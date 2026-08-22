import fs from 'node:fs';
import path from 'node:path';

import type { Command } from 'commander';

import {
  formatOpenApiInspectionJson,
  formatOpenApiInspectionText,
  isPathWithinWorkspace,
  OpenApiAnalysisError,
} from '../../openapi';
import { inspectOpenApiForCli } from '../../openapi/inspect';

interface OpenApiInspectCliOptions {
  input: string;
  workspaceRoot: string;
  json?: boolean;
  out?: string;
  force?: boolean;
}

type OpenApiInspectCliErrorCode =
  | 'OPENAPI_OUTPUT_EXISTS'
  | 'OPENAPI_OUTPUT_PARENT_NOT_FOUND'
  | 'OPENAPI_OUTPUT_OUTSIDE_ROOT'
  | 'OPENAPI_OUTPUT_PROTECTED'
  | 'OPENAPI_OUTPUT_REQUIRES_JSON'
  | 'OPENAPI_OUTPUT_WRITE_FAILED';

class OpenApiInspectCliError extends Error {
  constructor(readonly code: OpenApiInspectCliErrorCode, message: string) {
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
  if (!isPathWithinWorkspace(workspaceRoot, lexicalOutput)) {
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

export function registerOpenApiInspectCommand(program: Command): void {
  program
    .command('openapi')
    .description('Inspect OpenAPI security contracts without changing policy or build output')
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
}
