import type { Command } from 'commander';

import { loadFindingExceptions, validateFindingExceptionSet } from '../../contract/finding-exceptions';
import type { ContractDiffFailOn } from '../../contract/contract-diff';

interface Options {
  workspaceRoot?: string;
  openapi?: string;
  policy?: string;
  target?: string;
  source?: string;
  sourceAuthConfig?: string;
  exceptions?: string;
  environment?: string;
  currentDate?: string;
  failOn: string;
  format: string;
}

class SourceDiffArgumentError extends Error {
  constructor(readonly code: string) { super(code); }
}

function required(value: string | undefined, name: string): string {
  if (!value) throw new SourceDiffArgumentError(`SOURCE_DIFF_${name}_REQUIRED`);
  return value;
}

function validate(options: Options) {
  const workspaceRoot = required(options.workspaceRoot, 'WORKSPACE_ROOT');
  const openapiPath = required(options.openapi, 'OPENAPI');
  const policyPath = required(options.policy, 'POLICY');
  const target = required(options.target, 'TARGET');
  const currentDate = required(options.currentDate, 'CURRENT_DATE');
  if (!['aws', 'cloudflare'].includes(target)) throw new SourceDiffArgumentError('SOURCE_DIFF_TARGET_INVALID');
  if (!['text', 'json', 'sarif', 'summary'].includes(options.format)) {
    throw new SourceDiffArgumentError('SOURCE_DIFF_FORMAT_INVALID');
  }
  if (!['error', 'warning', 'never'].includes(options.failOn)) {
    throw new SourceDiffArgumentError('SOURCE_DIFF_FAIL_ON_INVALID');
  }
  if (!validateFindingExceptionSet({ version: 1, exceptions: [] }, { currentDate }).valid) {
    throw new SourceDiffArgumentError('SOURCE_DIFF_DATE_INVALID');
  }
  if (options.source === '' || options.exceptions === ''
    || options.sourceAuthConfig === ''
    || (options.environment !== undefined && (options.environment.length > 128 || !options.environment.trim()))) {
    throw new SourceDiffArgumentError('SOURCE_DIFF_ARGUMENT_INVALID');
  }
  if (options.sourceAuthConfig !== undefined && !options.source) {
    throw new SourceDiffArgumentError('SOURCE_DIFF_AUTH_CONFIG_REQUIRES_SOURCE');
  }
  return { workspaceRoot, openapiPath, policyPath, target: target as 'aws' | 'cloudflare',
    currentDate, failOn: options.failOn as ContractDiffFailOn };
}

function writeStdout(output: string): Promise<void> {
  return new Promise((resolve, reject) => {
    let finished = false;
    const done = (error?: Error | null) => {
      if (finished) return;
      finished = true;
      process.stdout.off('error', done);
      if (error) reject(error);
      else resolve();
    };
    process.stdout.once('error', done);
    try { process.stdout.write(output, done); }
    catch (error) { done(error as Error); }
  });
}

async function run(options: Options): Promise<void> {
  let input: ReturnType<typeof validate>;
  try { input = validate(options); }
  catch (error) {
    const code = error instanceof SourceDiffArgumentError ? error.code : 'SOURCE_DIFF_ARGUMENT_INVALID';
    console.error(`[ERROR] ${code}: Invalid source-diff arguments.`);
    process.exitCode = 2;
    return;
  }

  let authConfig;
  if (options.sourceAuthConfig !== undefined) {
    let authLoader: typeof import('./source-auth-config');
    try { authLoader = await import('./source-auth-config'); }
    catch {
      console.error('[ERROR] SOURCE_DIFF_INTERNAL: Source-aware analysis failed unexpectedly.');
      process.exitCode = 3;
      return;
    }
    try {
      authConfig = authLoader.loadSourceAuthConfig({
        workspaceRoot: input.workspaceRoot, inputPath: options.sourceAuthConfig,
      }).config;
    } catch {
      console.error('[ERROR] SOURCE_DIFF_AUTH_CONFIG_INVALID: Source auth config input is invalid.');
      process.exitCode = 2;
      return;
    }
  }

  let exceptions;
  if (options.exceptions) {
    try {
      exceptions = loadFindingExceptions({ inputPath: options.exceptions,
        workspaceRoot: input.workspaceRoot, currentDate: input.currentDate });
    } catch {
      console.error('[ERROR] SOURCE_DIFF_EXCEPTIONS_INVALID: Finding exceptions input is invalid.');
      process.exitCode = 2;
      return;
    }
  }

  try {
    const [
      { analyzeSourceAwareWorkspace },
      { finalizeSourceAwareOutput },
      { formatSourceAwarePreviewJson, formatSourceAwarePreviewText },
      { renderSourceAwareSarif },
      { renderSourceAwareSummary },
    ] = await Promise.all([
      import('../../contract/source-aware-workspace'),
      import('../../contract/source-aware-output'),
      import('../../contract/source-aware-finalizer'),
      import('../../reporters/sarif'),
      import('../../reporters/source-aware-summary'),
    ]);
    const workspace = await analyzeSourceAwareWorkspace({
      workspaceRoot: input.workspaceRoot, openapiPath: input.openapiPath,
      policyPath: input.policyPath, target: input.target,
      ...(options.source ? { source: { tsconfigPath: options.source, ...(authConfig ? { authConfig } : {}) } } : {}),
    });
    const bundle = finalizeSourceAwareOutput(workspace, {
      currentDate: input.currentDate, failOn: input.failOn, environment: options.environment, exceptions,
    });
    if (bundle.finalizationError) {
      console.error(`[ERROR] ${bundle.finalizationError.code}: Source-aware finalization failed.`);
      process.exitCode = bundle.finalizationError.exitCode;
      return;
    }
    const final = bundle.finalized!;
    let output: string;
    try {
      output = options.format === 'sarif' ? `${JSON.stringify(renderSourceAwareSarif(bundle), null, 2)}\n`
        : options.format === 'summary' ? renderSourceAwareSummary(bundle)
          : options.format === 'json' ? formatSourceAwarePreviewJson(final)
            : formatSourceAwarePreviewText(final);
    } catch {
      console.error('[ERROR] SOURCE_DIFF_REPORTER_FAILED: Source-aware report could not be rendered.');
      process.exitCode = 3;
      return;
    }
    try { await writeStdout(output); }
    catch {
      console.error('[ERROR] SOURCE_DIFF_OUTPUT_FAILED: Source-aware report could not be written.');
      process.exitCode = 3;
      return;
    }
    process.exitCode = final.exitCode;
  } catch {
    console.error('[ERROR] SOURCE_DIFF_INTERNAL: Source-aware analysis failed unexpectedly.');
    process.exitCode = 3;
  }
}

export function registerSourceDiffCommand(contract: Command): void {
  contract.command('source-diff')
    .description('Experimental: compare one workspace with optional NestJS Source evidence')
    .configureOutput({ writeErr: () => {} })
    .exitOverride()
    .option('--workspace-root <dir>', 'Required single-workspace root')
    .option('--openapi <path>', 'OpenAPI document inside the workspace')
    .option('--policy <path>', 'Schema 2 Policy inside the workspace')
    .option('--target <target>', 'Target: aws | cloudflare')
    .option('--source <tsconfig-path>', 'Optional NestJS Source tsconfig (no auto-discovery)')
    .option('--source-auth-config <path>', 'Optional YAML/JSON NestJS auth data inside the workspace (requires --source)')
    .option('--exceptions <path>', 'Optional bounded Finding exceptions file')
    .option('--environment <name>', 'Exception environment context')
    .option('--current-date <date>', 'Required exception evaluation date: YYYY-MM-DD')
    .option('--fail-on <level>', 'Finding threshold: error | warning | never', 'error')
    .option('--format <format>', 'Output: text | json | sarif | summary', 'text')
    .action(run);
}
