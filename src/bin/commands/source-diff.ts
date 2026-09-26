import type { Command } from 'commander';

import { loadFindingExceptions, validateFindingExceptionSet } from '../../contract/finding-exceptions';
import type { ContractDiffFailOn } from '../../contract/contract-diff';

export interface SourceDiffOptions {
  workspaceRoot?: string;
  openapi?: string;
  policy?: string;
  target?: string;
  source?: string;
  sourceGlobalPrefix?: string;
  sourceVersioning?: string;
  sourceAuthConfig?: string;
  out?: string;
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

function validate(options: SourceDiffOptions) {
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
  if (options.sourceGlobalPrefix !== undefined && !options.source) {
    throw new SourceDiffArgumentError('SOURCE_DIFF_PREFIX_REQUIRES_SOURCE');
  }
  if (options.sourceVersioning !== undefined && !options.source) {
    throw new SourceDiffArgumentError('SOURCE_DIFF_VERSIONING_REQUIRES_SOURCE');
  }
  if (options.sourceVersioning !== undefined && options.sourceVersioning !== 'uri') {
    throw new SourceDiffArgumentError('SOURCE_DIFF_VERSIONING_INVALID');
  }
  if (options.out !== undefined && (!options.out || options.out === '-' || options.out.endsWith('/'))) {
    throw new SourceDiffArgumentError('SOURCE_DIFF_OUTPUT_INVALID');
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

type PreparedSourceDiff =
  | { ok: false; code: string; exitCode: 2 | 3; message: string }
  | { ok: true; bundle: import('../../contract/source-aware-output').SourceAwareOutputBundle;
      workspace: import('../../contract/source-aware-workspace').SourceAwareWorkspaceResult;
      outputGuard?: ReturnType<typeof import('./source-output').sourceOutputGuard> };

/** Internal shared analysis path for the CLI and the dev-only CI driver. */
export async function prepareSourceDiff(options: SourceDiffOptions): Promise<PreparedSourceDiff> {
  let input: ReturnType<typeof validate>;
  try { input = validate(options); }
  catch (error) {
    const code = error instanceof SourceDiffArgumentError ? error.code : 'SOURCE_DIFF_ARGUMENT_INVALID';
    return { ok: false, code, exitCode: 2, message: 'Invalid source-diff arguments.' };
  }

  let globalPrefix: string | undefined;
  if (options.sourceGlobalPrefix !== undefined) {
    try {
      const { normalizeSourceGlobalPrefix } = await import('../../contract/source-global-prefix');
      globalPrefix = normalizeSourceGlobalPrefix(options.sourceGlobalPrefix);
    } catch {
      return { ok: false, code: 'SOURCE_DIFF_PREFIX_INVALID', exitCode: 2,
        message: 'Source global prefix is invalid.' };
    }
  }

  let outputModule: typeof import('./source-output') | undefined;
  let outputGuard: ReturnType<typeof import('./source-output').sourceOutputGuard> | undefined;
  if (options.out !== undefined) {
    try {
      outputModule = await import('./source-output');
      outputGuard = outputModule.sourceOutputGuard(input.workspaceRoot);
      for (const candidate of [input.openapiPath, input.policyPath, options.source,
        options.exceptions, options.sourceAuthConfig]) {
        if (candidate) outputGuard.recordInputPath(candidate);
      }
    } catch (error) {
      const known = outputModule && error instanceof outputModule.SourceOutputError ? error : undefined;
      return { ok: false, code: known?.code ?? 'SOURCE_DIFF_INTERNAL',
        exitCode: known?.exitCode ?? 3, message: 'Source-aware output cannot be prepared.' };
    }
  }

  let authConfig;
  if (options.sourceAuthConfig !== undefined) {
    let authLoader: typeof import('./source-auth-config');
    try { authLoader = await import('./source-auth-config'); }
    catch {
      return { ok: false, code: 'SOURCE_DIFF_INTERNAL', exitCode: 3,
        message: 'Source-aware analysis failed unexpectedly.' };
    }
    try {
      authConfig = authLoader.loadSourceAuthConfig({
        workspaceRoot: input.workspaceRoot, inputPath: options.sourceAuthConfig,
      }).config;
    } catch {
      return { ok: false, code: 'SOURCE_DIFF_AUTH_CONFIG_INVALID', exitCode: 2,
        message: 'Source auth config input is invalid.' };
    }
  }

  let exceptions;
  if (options.exceptions) {
    try {
      exceptions = loadFindingExceptions({ inputPath: options.exceptions,
        workspaceRoot: input.workspaceRoot, currentDate: input.currentDate });
    } catch {
      return { ok: false, code: 'SOURCE_DIFF_EXCEPTIONS_INVALID', exitCode: 2,
        message: 'Finding exceptions input is invalid.' };
    }
  }

  try {
    const [
      { analyzeSourceAwareWorkspace },
      { finalizeSourceAwareOutput },
    ] = await Promise.all([
      import('../../contract/source-aware-workspace'),
      import('../../contract/source-aware-output'),
    ]);
    const workspace = await analyzeSourceAwareWorkspace({
      workspaceRoot: input.workspaceRoot, openapiPath: input.openapiPath,
      policyPath: input.policyPath, target: input.target,
      onInputPath: outputGuard?.recordInputPath,
      ...(options.source ? { source: { tsconfigPath: options.source, ...(authConfig ? { authConfig } : {}),
        ...(globalPrefix ? { globalPrefix } : {}),
        ...(options.sourceVersioning ? { versioning: 'uri' as const } : {}) } } : {}),
    });
    const bundle = finalizeSourceAwareOutput(workspace, {
      currentDate: input.currentDate, failOn: input.failOn, environment: options.environment, exceptions,
    });
    if (bundle.finalizationError) {
      return { ok: false, code: bundle.finalizationError.code,
        exitCode: bundle.finalizationError.exitCode, message: 'Source-aware finalization failed.' };
    }
    return { ok: true, bundle, workspace, outputGuard };
  } catch {
    return { ok: false, code: 'SOURCE_DIFF_INTERNAL', exitCode: 3,
      message: 'Source-aware analysis failed unexpectedly.' };
  }
}

async function run(options: SourceDiffOptions): Promise<void> {
  const prepared = await prepareSourceDiff(options);
  if (!prepared.ok) {
    console.error(`[ERROR] ${prepared.code}: ${prepared.message}`);
    process.exitCode = prepared.exitCode;
    return;
  }
  const { bundle, workspace, outputGuard } = prepared;
  const final = bundle.finalized!;
  try {
    const [{ formatSourceAwarePreviewJson, formatSourceAwarePreviewText },
      { renderSourceAwareSarif }, { renderSourceAwareSummary }] = await Promise.all([
      import('../../contract/source-aware-finalizer'),
      import('../../reporters/sarif'),
      import('../../reporters/source-aware-summary'),
    ]);
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
    if (outputGuard) {
      try { outputGuard.write(outputGuard.prepare(options.out!, workspace, final), output); }
      catch (error) {
        const { SourceOutputError } = await import('./source-output');
        const known = error instanceof SourceOutputError ? error : undefined;
        console.error(`[ERROR] ${known?.code ?? 'SOURCE_DIFF_OUTPUT_WRITE_FAILED'}: Source-aware report could not be saved.`);
        process.exitCode = known?.exitCode ?? 3;
        return;
      }
    } else {
      try { await writeStdout(output); }
      catch {
        console.error('[ERROR] SOURCE_DIFF_OUTPUT_FAILED: Source-aware report could not be written.');
        process.exitCode = 3;
        return;
      }
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
    .option('--source-global-prefix <path>', 'Explicit fixed Source comparison prefix (requires --source)')
    .option('--source-versioning <mode>', 'Explicit Source URI versioning with default v prefix (requires --source)')
    .option('--source-auth-config <path>', 'Optional YAML/JSON NestJS auth data inside the workspace (requires --source)')
    .option('--out <path>', 'Save the report to one new file inside the workspace')
    .option('--exceptions <path>', 'Optional bounded Finding exceptions file')
    .option('--environment <name>', 'Exception environment context')
    .option('--current-date <date>', 'Required exception evaluation date: YYYY-MM-DD')
    .option('--fail-on <level>', 'Finding threshold: error | warning | never', 'error')
    .option('--format <format>', 'Output: text | json | sarif | summary', 'text')
    .action(run);
}
