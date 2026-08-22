import fs from 'node:fs';
import { randomUUID } from 'node:crypto';
import path from 'node:path';

import type { Command } from 'commander';
import * as yaml from 'js-yaml';

import {
  formatOpenApiInspectionJson,
  formatOpenApiInspectionText,
  generatePolicyCandidate,
  isPathWithinWorkspace,
  OpenApiAnalysisError,
  POLICY_CANDIDATE_PROFILES,
  type PolicyCandidateProfile,
  type PolicyObject,
} from '../../openapi';
import { inspectOpenApiForCli } from '../../openapi/inspect';

interface OpenApiInspectCliOptions {
  input: string;
  workspaceRoot: string;
  json?: boolean;
  out?: string;
  force?: boolean;
}

interface OpenApiPolicyCandidateCliOptions {
  input: string;
  workspaceRoot: string;
  profile: string;
  out: string;
  force?: boolean;
}

interface OpenApiCommandDependencies {
  pkgRoot: string;
  evaluatePolicyCapabilities: (policy: PolicyObject, policyPath: string, target: 'all') => {
    findings: unknown[];
  };
  validatePolicy: (options: { policy: PolicyObject; pkgRoot: string }) => {
    ok: boolean;
    errors: string[];
  };
}

type OpenApiInspectCliErrorCode =
  | 'OPENAPI_OUTPUT_EXISTS'
  | 'OPENAPI_OUTPUT_PARENT_NOT_FOUND'
  | 'OPENAPI_OUTPUT_OUTSIDE_ROOT'
  | 'OPENAPI_OUTPUT_PROTECTED'
  | 'OPENAPI_OUTPUT_REQUIRES_JSON'
  | 'OPENAPI_OUTPUT_WRITE_FAILED';

type OpenApiPolicyCandidateCliErrorCode =
  | 'OPENAPI_CANDIDATE_INVALID_PROFILE'
  | 'OPENAPI_CANDIDATE_INVALID_OUTPUT'
  | 'OPENAPI_CANDIDATE_OUTPUT_EXISTS'
  | 'OPENAPI_CANDIDATE_OUTPUT_PROTECTED'
  | 'OPENAPI_CANDIDATE_OUTPUT_WRITE_FAILED'
  | 'OPENAPI_CANDIDATE_POLICY_INVALID';

class OpenApiInspectCliError extends Error {
  constructor(readonly code: OpenApiInspectCliErrorCode, message: string) {
    super(message);
  }
}

class OpenApiPolicyCandidateCliError extends Error {
  constructor(readonly code: OpenApiPolicyCandidateCliErrorCode, message: string) {
    super(message);
  }
}

interface OutputTarget {
  basename: string;
  parent: string;
  parentDevice: number;
  parentInode: number;
  sourceFiles: Array<{ device: number; inode: number }>;
}

function sameFile(left: fs.Stats, right: { device: number; inode: number }): boolean {
  return left.dev === right.device && left.ino === right.inode;
}

function isSourceFile(
  candidate: fs.Stats,
  sourceFiles: ReadonlyArray<{ device: number; inode: number }>,
): boolean {
  return sourceFiles.some((source) => sameFile(candidate, source));
}

function outputPath(options: OpenApiInspectCliOptions, sourcePaths: readonly string[]): OutputTarget {
  if (!options.json) {
    throw new OpenApiInspectCliError(
      'OPENAPI_OUTPUT_REQUIRES_JSON',
      '--out requires --json.',
    );
  }
  const requestedWorkspaceRoot = path.resolve(options.workspaceRoot);
  let workspaceRoot: string;
  try {
    workspaceRoot = fs.realpathSync(options.workspaceRoot);
  } catch {
    throw new OpenApiInspectCliError(
      'OPENAPI_OUTPUT_PARENT_NOT_FOUND',
      'OpenAPI output parent directory was not found.',
    );
  }
  const lexicalOutput = path.isAbsolute(options.out as string)
    ? path.resolve(options.out as string)
    : path.resolve(workspaceRoot, options.out as string);
  const protectedDirectories = ['policy', 'dist'].map((directory) => (
    path.join(workspaceRoot, directory)
  ));
  const protectedRealDirectories = protectedDirectories.flatMap((directory) => {
    try {
      const resolved = fs.realpathSync(directory);
      return fs.statSync(resolved).isDirectory() ? [resolved] : [];
    } catch {
      return [];
    }
  });
  const input = path.isAbsolute(options.input)
    ? path.resolve(options.input)
    : path.resolve(workspaceRoot, options.input);
  if (!isPathWithinWorkspace(workspaceRoot, lexicalOutput)
    && !isPathWithinWorkspace(requestedWorkspaceRoot, lexicalOutput)) {
    throw new OpenApiInspectCliError(
      'OPENAPI_OUTPUT_OUTSIDE_ROOT',
      'OpenAPI output must be inside the workspace root.',
    );
  }
  if (lexicalOutput === input
    || protectedDirectories.some((directory) => isPathWithinWorkspace(directory, lexicalOutput))) {
    throw new OpenApiInspectCliError(
      'OPENAPI_OUTPUT_PROTECTED',
      'OpenAPI input, policy, and dist paths cannot be used as report output.',
    );
  }
  let parent: string;
  try {
    parent = fs.realpathSync(path.dirname(lexicalOutput));
  } catch {
    throw new OpenApiInspectCliError(
      'OPENAPI_OUTPUT_PARENT_NOT_FOUND',
      'OpenAPI output parent directory was not found.',
    );
  }
  const requested = path.join(parent, path.basename(lexicalOutput));
  if (!isPathWithinWorkspace(workspaceRoot, requested)) {
    throw new OpenApiInspectCliError(
      'OPENAPI_OUTPUT_OUTSIDE_ROOT',
      'OpenAPI output must be inside the workspace root.',
    );
  }
  const sourceRealPaths = sourcePaths.map((sourcePath) => fs.realpathSync(sourcePath));
  const sourceFiles = sourceRealPaths.map((sourcePath) => {
    const stats = fs.statSync(sourcePath);
    return { device: stats.dev, inode: stats.ino };
  });
  if (sourceRealPaths.includes(requested)
    || [...protectedDirectories, ...protectedRealDirectories]
      .some((directory) => isPathWithinWorkspace(directory, requested))) {
    throw new OpenApiInspectCliError(
      'OPENAPI_OUTPUT_PROTECTED',
      'OpenAPI input, policy, and dist paths cannot be used as report output.',
    );
  }
  if (fs.existsSync(requested)) {
    const existing = fs.lstatSync(requested);
    if (!options.force) {
      throw new OpenApiInspectCliError(
        'OPENAPI_OUTPUT_EXISTS',
        'OpenAPI output already exists. Use --force to overwrite it.',
      );
    }
    if (!existing.isFile() || existing.isSymbolicLink() || existing.nlink > 1
      || isSourceFile(existing, sourceFiles)) {
      throw new OpenApiInspectCliError(
        'OPENAPI_OUTPUT_PROTECTED',
        'OpenAPI output must be a regular file.',
      );
    }
  }
  const parentStats = fs.statSync(parent);
  return {
    basename: path.basename(requested),
    parent,
    parentDevice: parentStats.dev,
    parentInode: parentStats.ino,
    sourceFiles,
  };
}

function writeOutput(target: OutputTarget, content: string, force: boolean): void {
  let descriptor: number | undefined;
  const previousDirectory = process.cwd();
  try {
    process.chdir(target.parent);
    if (!sameFile(fs.statSync('.'), {
      device: target.parentDevice,
      inode: target.parentInode,
    })) {
      throw new OpenApiInspectCliError(
        'OPENAPI_OUTPUT_OUTSIDE_ROOT',
        'OpenAPI output parent changed before writing.',
      );
    }
    const exists = fs.existsSync(target.basename);
    if (exists && !force) {
      throw new OpenApiInspectCliError(
        'OPENAPI_OUTPUT_EXISTS',
        'OpenAPI output already exists. Use --force to overwrite it.',
      );
    }
    const beforeOpen = exists ? fs.lstatSync(target.basename) : undefined;
    if (beforeOpen && (!beforeOpen.isFile() || beforeOpen.isSymbolicLink()
      || beforeOpen.nlink > 1 || isSourceFile(beforeOpen, target.sourceFiles))) {
      throw new OpenApiInspectCliError(
        'OPENAPI_OUTPUT_PROTECTED',
        'OpenAPI output must be a regular single-link file.',
      );
    }
    descriptor = fs.openSync(
      target.basename,
      fs.constants.O_WRONLY | fs.constants.O_CREAT
        | (exists ? 0 : fs.constants.O_EXCL)
        | (fs.constants.O_NOFOLLOW ?? 0),
      0o666,
    );
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || opened.nlink > 1
      || isSourceFile(opened, target.sourceFiles)
      || (beforeOpen && !sameFile(opened, { device: beforeOpen.dev, inode: beforeOpen.ino }))) {
      throw new OpenApiInspectCliError(
        'OPENAPI_OUTPUT_PROTECTED',
        'OpenAPI output changed before writing.',
      );
    }
    fs.ftruncateSync(descriptor, 0);
    fs.writeFileSync(descriptor, content, 'utf8');
  } catch (error: unknown) {
    if (error instanceof OpenApiInspectCliError) throw error;
    throw new OpenApiInspectCliError(
      'OPENAPI_OUTPUT_WRITE_FAILED',
      'OpenAPI output could not be written.',
    );
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    process.chdir(previousDirectory);
  }
}

function run(options: OpenApiInspectCliOptions): void {
  if (options.force && !options.out) {
    throw new OpenApiInspectCliError('OPENAPI_OUTPUT_WRITE_FAILED', '--force requires --out.');
  }
  const inspection = inspectOpenApiForCli({
    inputPath: options.input,
    workspaceRoot: options.workspaceRoot,
  });
  const output = options.json
    ? formatOpenApiInspectionJson(inspection.report)
    : formatOpenApiInspectionText(inspection.report);
  if (options.out) {
    writeOutput(outputPath(options, inspection.sourcePaths), output, Boolean(options.force));
  }
  else process.stdout.write(output);
}

interface CandidateOutputPair {
  candidate: CandidateOutput;
  metadata: CandidateOutput;
  parent: string;
  parentDevice: number;
  parentInode: number;
}

interface CandidateOutput {
  basename: string;
  expected?: { device: number; inode: number };
}

function candidateOutputPair(
  options: OpenApiPolicyCandidateCliOptions,
  sourcePaths: readonly string[],
): CandidateOutputPair {
  let workspaceRoot: string;
  try {
    workspaceRoot = fs.realpathSync(options.workspaceRoot);
  } catch {
    throw new OpenApiPolicyCandidateCliError(
      'OPENAPI_CANDIDATE_INVALID_OUTPUT',
      'Workspace root was not found.',
    );
  }
  const lexicalCandidate = path.isAbsolute(options.out)
    ? path.resolve(options.out)
    : path.resolve(workspaceRoot, options.out);
  if (!/\.ya?ml$/i.test(lexicalCandidate)) {
    throw new OpenApiPolicyCandidateCliError(
      'OPENAPI_CANDIDATE_INVALID_OUTPUT',
      'Policy candidate output must use a .yml or .yaml extension.',
    );
  }
  let parent: string;
  try {
    parent = fs.realpathSync(path.dirname(lexicalCandidate));
  } catch {
    throw new OpenApiPolicyCandidateCliError(
      'OPENAPI_CANDIDATE_INVALID_OUTPUT',
      'Policy candidate output parent directory was not found.',
    );
  }
  const candidatePath = path.join(parent, path.basename(lexicalCandidate));
  const metadataPath = candidatePath.replace(/\.ya?ml$/i, '.meta.json');
  if (!isPathWithinWorkspace(workspaceRoot, candidatePath)) {
    throw new OpenApiPolicyCandidateCliError(
      'OPENAPI_CANDIDATE_OUTPUT_PROTECTED',
      'Policy candidate output must stay inside the workspace root.',
    );
  }
  const protectedPaths = [
    path.join(workspaceRoot, 'policy', 'security.yml'),
    path.join(workspaceRoot, 'policy', 'base.yml'),
  ];
  const protectedDirectories = [
    path.join(workspaceRoot, 'policy', 'profiles'),
    path.join(workspaceRoot, 'policy', 'archetypes'),
    path.join(workspaceRoot, 'dist'),
  ];
  const sourceStats = sourcePaths.map((sourcePath) => fs.statSync(fs.realpathSync(sourcePath)));
  const protectedStats = protectedPaths.flatMap((protectedPath) => {
    try { return [fs.statSync(protectedPath)]; } catch { return []; }
  });
  const outputs: CandidateOutput[] = [];
  for (const outputPath of [candidatePath, metadataPath]) {
    if (protectedPaths.some((protectedPath) => protectedPath.toLowerCase() === outputPath.toLowerCase())
      || protectedDirectories.some((directory) => isPathWithinWorkspace(directory, outputPath))
      || sourcePaths.map((sourcePath) => fs.realpathSync(sourcePath)).includes(outputPath)) {
      throw new OpenApiPolicyCandidateCliError(
        'OPENAPI_CANDIDATE_OUTPUT_PROTECTED',
        'Policy candidate output cannot replace active policy, profile, build, or source files.',
      );
    }
    let existing: fs.Stats;
    try {
      existing = fs.lstatSync(outputPath);
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
      throw error;
    }
    if (!options.force) {
      throw new OpenApiPolicyCandidateCliError(
        'OPENAPI_CANDIDATE_OUTPUT_EXISTS',
        'Policy candidate output already exists. Use --force to overwrite it.',
      );
    }
    if (!existing.isFile() || existing.isSymbolicLink() || existing.nlink > 1
      || [...sourceStats, ...protectedStats]
        .some((source) => sameFile(existing, { device: source.dev, inode: source.ino }))) {
      throw new OpenApiPolicyCandidateCliError(
        'OPENAPI_CANDIDATE_OUTPUT_PROTECTED',
        'Policy candidate output must be a regular single-link file.',
      );
    }
    outputs.push({ basename: path.basename(outputPath), expected: { device: existing.dev, inode: existing.ino } });
  }
  const [candidate, metadata] = [candidatePath, metadataPath].map((outputPath) => (
    outputs.find(({ basename }) => basename === path.basename(outputPath))
      ?? { basename: path.basename(outputPath) }
  ));
  const parentStats = fs.statSync(parent);
  return {
    candidate,
    metadata,
    parent,
    parentDevice: parentStats.dev,
    parentInode: parentStats.ino,
  };
}

function writeCandidatePair(pair: CandidateOutputPair, candidate: string, metadata: string): void {
  const nonce = randomUUID();
  const candidateTemp = `.${pair.candidate.basename}.${nonce}.tmp`;
  const metadataTemp = `.${pair.metadata.basename}.${nonce}.tmp`;
  const candidateBackup = `.${pair.candidate.basename}.${nonce}.bak`;
  const metadataBackup = `.${pair.metadata.basename}.${nonce}.bak`;
  const previousDirectory = process.cwd();
  let candidateBackedUp = false;
  let metadataBackedUp = false;
  let candidateInstalled = false;
  let metadataInstalled = false;
  try {
    process.chdir(pair.parent);
    if (!sameFile(fs.statSync('.'), { device: pair.parentDevice, inode: pair.parentInode })) {
      throw new Error('output parent changed');
    }
    fs.writeFileSync(candidateTemp, candidate, { encoding: 'utf8', flag: 'wx', mode: 0o666 });
    fs.writeFileSync(metadataTemp, metadata, { encoding: 'utf8', flag: 'wx', mode: 0o666 });

    const backup = (output: CandidateOutput, backupName: string): boolean => {
      let current: fs.Stats | undefined;
      try { current = fs.lstatSync(output.basename); } catch (error: unknown) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
      if (!output.expected) {
        if (current) throw new Error('output appeared after validation');
        return false;
      }
      if (!current || !sameFile(current, output.expected)
        || !current.isFile() || current.isSymbolicLink() || current.nlink > 1) {
        throw new Error('output changed after validation');
      }
      fs.renameSync(output.basename, backupName);
      return true;
    };

    candidateBackedUp = backup(pair.candidate, candidateBackup);
    metadataBackedUp = backup(pair.metadata, metadataBackup);
    fs.renameSync(candidateTemp, pair.candidate.basename);
    candidateInstalled = true;
    fs.renameSync(metadataTemp, pair.metadata.basename);
    metadataInstalled = true;
    if (candidateBackedUp) try { fs.unlinkSync(candidateBackup); } catch {}
    if (metadataBackedUp) try { fs.unlinkSync(metadataBackup); } catch {}
  } catch {
    if (candidateInstalled) try { fs.unlinkSync(pair.candidate.basename); } catch {}
    if (metadataInstalled) try { fs.unlinkSync(pair.metadata.basename); } catch {}
    if (candidateBackedUp) try { fs.renameSync(candidateBackup, pair.candidate.basename); } catch {}
    if (metadataBackedUp) try { fs.renameSync(metadataBackup, pair.metadata.basename); } catch {}
    throw new OpenApiPolicyCandidateCliError(
      'OPENAPI_CANDIDATE_OUTPUT_WRITE_FAILED',
      'Policy candidate output could not be written.',
    );
  } finally {
    for (const temporaryPath of [candidateTemp, metadataTemp]) {
      try { fs.unlinkSync(temporaryPath); } catch {}
    }
    process.chdir(previousDirectory);
  }
}

function runPolicyCandidate(
  options: OpenApiPolicyCandidateCliOptions,
  dependencies: OpenApiCommandDependencies,
): void {
  if (!POLICY_CANDIDATE_PROFILES.includes(options.profile as PolicyCandidateProfile)) {
    throw new OpenApiPolicyCandidateCliError(
      'OPENAPI_CANDIDATE_INVALID_PROFILE',
      'Invalid --profile. Use strict, balanced, or permissive.',
    );
  }
  const profile = options.profile as PolicyCandidateProfile;
  const inspection = inspectOpenApiForCli({
    inputPath: options.input,
    workspaceRoot: options.workspaceRoot,
  });
  const profilePath = path.join(dependencies.pkgRoot, 'policy', 'profiles', `${profile}.yml`);
  const profilePolicy = yaml.load(fs.readFileSync(profilePath, 'utf8')) as PolicyObject;
  const generated = generatePolicyCandidate(inspection.report.contract, {
    profile,
    profilePolicy,
    sourceDigest: inspection.report.analyzer.sourceDigest,
    evaluateCapabilities: (policy) => dependencies.evaluatePolicyCapabilities(policy, 'candidate', 'all'),
  });
  const validation = dependencies.validatePolicy({ policy: generated.policy, pkgRoot: dependencies.pkgRoot });
  if (!validation.ok) {
    throw new OpenApiPolicyCandidateCliError(
      'OPENAPI_CANDIDATE_POLICY_INVALID',
      'Generated policy candidate did not pass the current policy validator.',
    );
  }
  const outputs = candidateOutputPair(options, inspection.sourcePaths);
  const candidate = yaml.dump(generated.policy, {
    lineWidth: -1,
    noRefs: true,
  });
  const metadata = `${JSON.stringify(generated.metadata, null, 2)}\n`;
  writeCandidatePair(outputs, candidate, metadata);
  process.stdout.write('[SUCCESS] Created policy candidate and metadata sidecar.\n');
}

export function registerOpenApiInspectCommand(
  program: Command,
  dependencies: OpenApiCommandDependencies,
): void {
  const openApi = program
    .command('openapi')
    .description('Inspect OpenAPI contracts and generate review-only policy candidates');

  openApi
    .command('inspect')
    .description('Print canonical Security IR and analysis capabilities')
    .requiredOption('--input <path>', 'OpenAPI YAML or JSON file')
    .option('--workspace-root <path>', 'Workspace boundary for input and local refs', '.')
    .option('--json', 'Print deterministic JSON')
    .option('--out <path>', 'Write JSON to an existing directory inside the workspace')
    .option('--force', 'Overwrite an existing regular output file')
    .action((options: OpenApiInspectCliOptions) => {
      try {
        run(options);
      } catch (error: unknown) {
        if (error instanceof OpenApiAnalysisError || error instanceof OpenApiInspectCliError) {
          console.error(`[ERROR] ${error.code}: ${error.message}`);
        } else {
          console.error('[ERROR] OPENAPI_INSPECT_FAILED: OpenAPI inspection failed.');
        }
        process.exitCode = 1;
      }
    });

  openApi
    .command('generate-policy')
    .description('Generate a non-destructive policy candidate and metadata sidecar')
    .requiredOption('--input <path>', 'OpenAPI YAML or JSON file')
    .requiredOption('--profile <name>', 'Built-in profile: strict | balanced | permissive')
    .requiredOption('--out <path>', 'Write a new .yml or .yaml policy candidate inside the workspace')
    .option('--workspace-root <path>', 'Workspace boundary for input, local refs, and output', '.')
    .option('--force', 'Overwrite existing regular candidate and metadata files')
    .action((options: OpenApiPolicyCandidateCliOptions) => {
      try {
        runPolicyCandidate(options, dependencies);
      } catch (error: unknown) {
        if (error instanceof OpenApiAnalysisError
          || error instanceof OpenApiPolicyCandidateCliError) {
          console.error(`[ERROR] ${error.code}: ${error.message}`);
        } else {
          console.error('[ERROR] OPENAPI_CANDIDATE_FAILED: Policy candidate generation failed.');
        }
        process.exitCode = 1;
      }
    });
}
