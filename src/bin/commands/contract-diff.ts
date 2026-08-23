import fs from 'node:fs';
import path from 'node:path';

import type { Command } from 'commander';

import {
  CONTRACT_DIFF_FAIL_ON,
  ContractDiffInputError,
  contractDiffExitCode,
  diffSecurityContractsForCli,
  formatContractDiffJson,
  formatContractDiffText,
  type ContractDiffFailOn,
} from '../../contract/contract-diff';
import { isPathWithinWorkspace, OpenApiAnalysisError } from '../../openapi';

interface ContractDiffCliOptions {
  openapi?: string;
  policy?: string;
  target?: string;
  exceptions?: string;
  currentDate?: string;
  format: string;
  out?: string;
  failOn: string;
  includeSuppressed?: boolean;
  workspaceRoot: string;
  force?: boolean;
}

class ContractDiffCliError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
  }
}

interface OutputTarget {
  basename: string;
  parent: string;
  parentDevice: number;
  parentInode: number;
  protectedDirectories: string[];
  sourceFiles: Array<{ device: number; inode: number }>;
  workspaceRoot: string;
  expected?: { device: number; inode: number };
}

function sameFile(left: fs.Stats, right: { device: number; inode: number }): boolean {
  return left.dev === right.device && left.ino === right.inode;
}

function outputTarget(
  options: ContractDiffCliOptions,
  sourceFiles: readonly { device: number; inode: number }[],
  workspace: { root: string; device: number; inode: number },
): OutputTarget {
  const root = workspace.root;
  try {
    if (!sameFile(fs.statSync(root), workspace)) throw new Error('workspace changed');
  } catch {
    throw new ContractDiffCliError('CONTRACT_DIFF_OUTPUT_INVALID', 'Workspace root changed after analysis.');
  }
  const lexical = path.resolve(root, options.out as string);
  let parent: string;
  try {
    parent = fs.realpathSync(path.dirname(lexical));
  } catch {
    throw new ContractDiffCliError('CONTRACT_DIFF_OUTPUT_INVALID', 'Report output parent was not found.');
  }
  const requested = path.join(parent, path.basename(lexical));
  const protectedDirectories = ['policy', 'dist'].flatMap((name) => {
    try { return [fs.realpathSync(path.join(root, name))]; } catch { return []; }
  });
  if (!isPathWithinWorkspace(root, requested)
    || protectedDirectories.some((directory) => isPathWithinWorkspace(directory, requested))) {
    throw new ContractDiffCliError('CONTRACT_DIFF_OUTPUT_PROTECTED', 'Report output cannot replace policy, dist, or input files.');
  }
  let existing: fs.Stats | undefined;
  try { existing = fs.lstatSync(requested); } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  if (existing && !options.force) {
    throw new ContractDiffCliError('CONTRACT_DIFF_OUTPUT_EXISTS', 'Report output already exists. Use --force to overwrite it.');
  }
  if (existing && (!existing.isFile() || existing.isSymbolicLink() || existing.nlink > 1
    || sourceFiles.some((source) => sameFile(existing as fs.Stats, source)))) {
    throw new ContractDiffCliError('CONTRACT_DIFF_OUTPUT_PROTECTED', 'Report output must be a regular single-link file.');
  }
  const parentStat = fs.statSync(parent);
  return {
    basename: path.basename(requested),
    parent,
    parentDevice: parentStat.dev,
    parentInode: parentStat.ino,
    protectedDirectories,
    sourceFiles: [...sourceFiles],
    workspaceRoot: root,
    expected: existing ? { device: existing.dev, inode: existing.ino } : undefined,
  };
}

function writeOutput(target: OutputTarget, content: string): void {
  let descriptor: number | undefined;
  const previousDirectory = process.cwd();
  try {
    process.chdir(target.parent);
    if (!sameFile(fs.statSync('.'), { device: target.parentDevice, inode: target.parentInode })) {
      throw new Error('parent changed');
    }
    descriptor = fs.openSync(
      target.basename,
      fs.constants.O_WRONLY | fs.constants.O_CREAT
        | (target.expected ? 0 : fs.constants.O_EXCL)
        | (fs.constants.O_NOFOLLOW ?? 0)
        | (fs.constants.O_NONBLOCK ?? 0),
      0o666,
    );
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || opened.nlink > 1
      || target.sourceFiles.some((source) => sameFile(opened, source))
      || (target.expected && !sameFile(opened, target.expected))) {
      throw new Error('output changed');
    }
    const currentOutput = path.join(fs.realpathSync('.'), target.basename);
    if (!isPathWithinWorkspace(target.workspaceRoot, currentOutput)
      || target.protectedDirectories.some((directory) => isPathWithinWorkspace(directory, currentOutput))) {
      if (!target.expected) {
        const created = fs.lstatSync(target.basename);
        if (sameFile(created, { device: opened.dev, inode: opened.ino })) fs.unlinkSync(target.basename);
      }
      throw new Error('parent moved');
    }
    fs.ftruncateSync(descriptor, 0);
    fs.writeFileSync(descriptor, content, 'utf8');
  } catch {
    throw new ContractDiffCliError('CONTRACT_DIFF_OUTPUT_WRITE_FAILED', 'Report output could not be written safely.');
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    process.chdir(previousDirectory);
  }
}

function required(value: string | undefined, name: string): string {
  if (!value) throw new ContractDiffCliError('CONTRACT_DIFF_ARGUMENT_REQUIRED', `${name} is required.`);
  return value;
}

function run(options: ContractDiffCliOptions): void {
  if (!['text', 'json'].includes(options.format)) {
    throw new ContractDiffCliError('CONTRACT_DIFF_FORMAT_INVALID', '--format must be text or json.');
  }
  if (!CONTRACT_DIFF_FAIL_ON.includes(options.failOn as ContractDiffFailOn)) {
    throw new ContractDiffCliError('CONTRACT_DIFF_FAIL_ON_INVALID', '--fail-on must be error, warning, or never.');
  }
  if (!['aws', 'cloudflare'].includes(options.target ?? '')) {
    throw new ContractDiffCliError('CONTRACT_DIFF_TARGET_INVALID', '--target must be aws or cloudflare.');
  }
  if (options.force && !options.out) {
    throw new ContractDiffCliError('CONTRACT_DIFF_OUTPUT_INVALID', '--force requires --out.');
  }
  if (options.currentDate && !options.exceptions) {
    throw new ContractDiffCliError('CONTRACT_DIFF_DATE_INVALID', '--current-date requires --exceptions.');
  }
  const execution = diffSecurityContractsForCli({
    openapiPath: required(options.openapi, '--openapi'),
    policyPath: required(options.policy, '--policy'),
    target: options.target as 'aws' | 'cloudflare',
    exceptionsPath: options.exceptions,
    currentDate: options.currentDate,
    includeSuppressed: options.includeSuppressed,
    workspaceRoot: options.workspaceRoot,
  });
  const output = options.format === 'json'
    ? formatContractDiffJson(execution.report)
    : formatContractDiffText(execution.report, {
      color: !options.out && Boolean(process.stdout.isTTY) && !('NO_COLOR' in process.env),
    });
  if (options.out) writeOutput(outputTarget(options, execution.sourceIdentities, execution.workspace), output);
  else process.stdout.write(output);
  process.exitCode = contractDiffExitCode(execution.report, options.failOn as ContractDiffFailOn);
}

export function registerContractDiffCommand(program: Command): void {
  const contract = program
    .command('contract')
    .description('Compare an OpenAPI contract with the effective CDN security policy');
  contract
    .command('diff')
    .description('Emit deterministic security contract drift findings')
    .exitOverride()
    .option('--openapi <path>', 'OpenAPI YAML or JSON file')
    .option('--policy <path>', 'CDN security policy YAML file')
    .option('--target <target>', 'Target platform: aws | cloudflare')
    .option('--exceptions <path>', 'Finding exceptions YAML file')
    .option('--current-date <date>', 'Exception evaluation date in YYYY-MM-DD')
    .option('--format <format>', 'Output format: text | json', 'text')
    .option('--out <path>', 'Write the report inside the workspace')
    .option('--fail-on <severity>', 'Failure threshold: error | warning | never', 'error')
    .option('--include-suppressed', 'Include suppressed findings in the report')
    .option('--workspace-root <path>', 'Workspace boundary for all inputs and output', '.')
    .option('--force', 'Overwrite an existing regular output file')
    .action((options: ContractDiffCliOptions) => {
      try {
        run(options);
      } catch (error: unknown) {
        if (error instanceof ContractDiffCliError || error instanceof ContractDiffInputError
          || error instanceof OpenApiAnalysisError) {
          console.error(`[ERROR] ${error.code}: ${error.message}`);
          process.exitCode = 2;
        } else {
          console.error('[ERROR] CONTRACT_DIFF_INTERNAL: Contract diff failed unexpectedly.');
          process.exitCode = 3;
        }
      }
    });
}
