import fs from 'node:fs';
import path from 'node:path';

import {
  createSecurityContract,
  type SecurityContractInputV1,
  type SecurityContractV1,
} from '../contract/security-ir';

export const SOURCE_ANALYZER_CAPABILITY_NAMES = [
  'routePaths',
  'httpMethods',
  'routerPrefixes',
  'globalPrefixes',
  'authentication',
  'authorization',
  'requestContentTypes',
  'requestLimits',
  'sourceLocations',
  'inheritedMetadata',
  'dynamicExpressions',
] as const;

export const SOURCE_ANALYZER_CAPABILITY_STATUSES = ['supported', 'partial', 'unsupported'] as const;

export const SOURCE_ANALYZER_DIAGNOSTIC_CODES = [
  'SOURCE_ANALYZER_INVALID_PLUGIN',
  'SOURCE_ANALYZER_DUPLICATE',
  'SOURCE_ANALYZER_UNKNOWN',
  'SOURCE_ANALYZER_INVALID_LIMITS',
  'SOURCE_ANALYZER_INPUT_INVALID',
  'SOURCE_ANALYZER_INPUT_OUTSIDE_ROOT',
  'SOURCE_ANALYZER_FILE_LIMIT',
  'SOURCE_ANALYZER_TOTAL_BYTES_LIMIT',
  'SOURCE_ANALYZER_FILE_BYTES_LIMIT',
  'SOURCE_ANALYZER_AST_NODE_LIMIT',
  'SOURCE_ANALYZER_DIAGNOSTIC_LIMIT',
  'SOURCE_ANALYZER_OPERATION_LIMIT',
  'SOURCE_ANALYZER_DEPTH_LIMIT',
  'SOURCE_ANALYZER_DYNAMIC_ROUTE',
  'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR',
  'SOURCE_ANALYZER_CANCELLED',
  'SOURCE_ANALYZER_TIMEOUT',
  'SOURCE_ANALYZER_INVALID_RESULT',
  'SOURCE_ANALYZER_INTERNAL',
] as const;

const SOURCE_ANALYZER_RESULT_DIAGNOSTIC_CODES = [
  'SOURCE_ANALYZER_DYNAMIC_ROUTE',
  'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR',
] as const;

export type SourceAnalyzerCapabilityName = typeof SOURCE_ANALYZER_CAPABILITY_NAMES[number];
export type SourceAnalyzerCapabilityStatus = typeof SOURCE_ANALYZER_CAPABILITY_STATUSES[number];
export type SourceAnalyzerDiagnosticCode = typeof SOURCE_ANALYZER_DIAGNOSTIC_CODES[number];

export interface AnalyzerCapability {
  status: SourceAnalyzerCapabilityStatus;
  reason: string;
}

export type AnalyzerCapabilities = Readonly<Record<SourceAnalyzerCapabilityName, AnalyzerCapability>>;

export interface SourceAnalysisLimits {
  maxFiles: number;
  maxTotalSourceBytes: number;
  maxFileBytes: number;
  maxAstNodes: number;
  maxDiagnostics: number;
  maxOperations: number;
  maxAnalysisDepth: number;
  timeoutMs: number;
}

export interface SourceAnalysisMetrics {
  files: number;
  totalSourceBytes: number;
  largestFileBytes: number;
  astNodes: number;
  diagnostics: number;
  operations: number;
  maxDepth: number;
}

export interface AnalyzerDiagnostic {
  code: SourceAnalyzerDiagnosticCode;
  safeMessage: string;
  sourceUri?: string;
  line?: number;
  column?: number;
}

export const SOURCE_ANALYZER_LOG_CODES = [
  'SOURCE_ANALYZER_STARTED',
  'SOURCE_ANALYZER_COMPLETED',
  'SOURCE_ANALYZER_FAILED',
] as const;

export type SourceAnalyzerLogCode = typeof SOURCE_ANALYZER_LOG_CODES[number];

export interface SafeAnalyzerLogger {
  log(code: SourceAnalyzerLogCode): void | Promise<void>;
}

export interface SourceAnalysisContext {
  workspaceRoot: string;
  entrypoints: string[];
  limits: SourceAnalysisLimits;
  cancellationSignal?: AbortSignal;
  logger: SafeAnalyzerLogger;
}

export interface SourceAnalysisResult {
  contract: SecurityContractV1;
  diagnostics: AnalyzerDiagnostic[];
  metrics: SourceAnalysisMetrics;
}

export interface SourceAnalyzerPlugin {
  readonly id: string;
  readonly version: string;
  readonly languages: readonly string[];
  readonly frameworks: readonly string[];
  readonly capabilities: AnalyzerCapabilities;
  analyze(context: SourceAnalysisContext): Promise<SourceAnalysisResult>;
}

export type SourceAnalysisExecution =
  | { status: 'success'; result: SourceAnalysisResult }
  | { status: 'failed'; diagnostics: AnalyzerDiagnostic[] };

const SAFE_MESSAGES: Readonly<Record<SourceAnalyzerDiagnosticCode, string>> = Object.freeze({
  SOURCE_ANALYZER_INVALID_PLUGIN: 'Source analyzer plugin metadata is invalid.',
  SOURCE_ANALYZER_DUPLICATE: 'Source analyzer identity is already registered.',
  SOURCE_ANALYZER_UNKNOWN: 'Source analyzer identity is not registered.',
  SOURCE_ANALYZER_INVALID_LIMITS: 'Source analysis limits are invalid.',
  SOURCE_ANALYZER_INPUT_INVALID: 'Source analyzer input is invalid.',
  SOURCE_ANALYZER_INPUT_OUTSIDE_ROOT: 'Source analyzer input is outside the workspace root.',
  SOURCE_ANALYZER_FILE_LIMIT: 'Source analysis file limit was exceeded.',
  SOURCE_ANALYZER_TOTAL_BYTES_LIMIT: 'Source analysis total byte limit was exceeded.',
  SOURCE_ANALYZER_FILE_BYTES_LIMIT: 'Source analysis file byte limit was exceeded.',
  SOURCE_ANALYZER_AST_NODE_LIMIT: 'Source analysis AST node limit was exceeded.',
  SOURCE_ANALYZER_DIAGNOSTIC_LIMIT: 'Source analysis diagnostic limit was exceeded.',
  SOURCE_ANALYZER_OPERATION_LIMIT: 'Source analysis operation limit was exceeded.',
  SOURCE_ANALYZER_DEPTH_LIMIT: 'Source analysis depth limit was exceeded.',
  SOURCE_ANALYZER_DYNAMIC_ROUTE: 'A dynamic route expression could not be resolved statically.',
  SOURCE_ANALYZER_UNSUPPORTED_DECORATOR: 'A source decorator is not supported by this analyzer.',
  SOURCE_ANALYZER_CANCELLED: 'Source analysis was cancelled.',
  SOURCE_ANALYZER_TIMEOUT: 'Source analysis timed out.',
  SOURCE_ANALYZER_INVALID_RESULT: 'Source analyzer returned an invalid result.',
  SOURCE_ANALYZER_INTERNAL: 'Source analyzer failed unexpectedly.',
});

const LIMIT_RANGES: Readonly<Record<keyof SourceAnalysisLimits, Readonly<{ min: number; max: number }>>> = Object.freeze({
  maxFiles: Object.freeze({ min: 1, max: 100_000 }),
  maxTotalSourceBytes: Object.freeze({ min: 1, max: 1024 * 1024 * 1024 }),
  maxFileBytes: Object.freeze({ min: 1, max: 64 * 1024 * 1024 }),
  maxAstNodes: Object.freeze({ min: 1, max: 10_000_000 }),
  maxDiagnostics: Object.freeze({ min: 1, max: 100_000 }),
  maxOperations: Object.freeze({ min: 1, max: 100_000 }),
  maxAnalysisDepth: Object.freeze({ min: 1, max: 1_024 }),
  timeoutMs: Object.freeze({ min: 1, max: 300_000 }),
});

export const DEFAULT_SOURCE_ANALYSIS_LIMITS: Readonly<SourceAnalysisLimits> = Object.freeze({
  maxFiles: 10_000,
  maxTotalSourceBytes: 128 * 1024 * 1024,
  maxFileBytes: 4 * 1024 * 1024,
  maxAstNodes: 1_000_000,
  maxDiagnostics: 1_000,
  maxOperations: 10_000,
  maxAnalysisDepth: 128,
  timeoutMs: 10_000,
});

const LIMIT_NAMES = Object.freeze(Object.keys(LIMIT_RANGES) as Array<keyof SourceAnalysisLimits>);
const METRIC_NAMES = Object.freeze([
  'files', 'totalSourceBytes', 'largestFileBytes', 'astNodes',
  'diagnostics', 'operations', 'maxDepth',
] as const);
const COMPLETE_CAPABILITY_REQUIREMENTS = Object.freeze({
  routes: Object.freeze(['routePaths', 'httpMethods', 'routerPrefixes', 'globalPrefixes', 'dynamicExpressions'] as const),
  authentication: Object.freeze(['authentication', 'inheritedMetadata', 'dynamicExpressions'] as const),
});
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const SAFE_ID = /^[a-z][a-z0-9.-]{0,63}$/;
const SECRET_LIKE = /\b(?:Bearer|Basic)\s+\S+|\b(?:authorization|cookie|password|secret|client_secret|access_token|refresh_token|token|api[_-]?key)\s*[=:]\s*\S+/i;

export class SourceAnalyzerContractError extends Error {
  readonly safeMessage: string;

  constructor(readonly code: SourceAnalyzerDiagnosticCode) {
    super(SAFE_MESSAGES[code]);
    this.name = 'SourceAnalyzerContractError';
    this.safeMessage = SAFE_MESSAGES[code];
  }
}

function safeText(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 1_024 && value.trim().length > 0
    && !/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(value) && !SECRET_LIKE.test(value);
}

export function validateSourceAnalysisLimits(input: unknown): Readonly<SourceAnalysisLimits> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_LIMITS');
  }
  const record = input as Record<string, unknown>;
  if (Object.keys(record).length !== LIMIT_NAMES.length
    || Object.keys(record).some((name) => !LIMIT_NAMES.includes(name as keyof SourceAnalysisLimits))) {
    throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_LIMITS');
  }
  const output = {} as SourceAnalysisLimits;
  for (const name of LIMIT_NAMES) {
    const value = record[name];
    const range = LIMIT_RANGES[name];
    if (!Number.isInteger(value) || (value as number) < range.min || (value as number) > range.max) {
      throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_LIMITS');
    }
    output[name] = value as number;
  }
  return Object.freeze(output);
}

function validateStringSet(value: unknown): boolean {
  return Array.isArray(value) && value.length > 0 && value.length <= 128
    && value.every(safeText) && new Set(value).size === value.length;
}

function isSemanticVersion(value: string): boolean {
  const match = SEMVER.exec(value);
  return Boolean(match) && !(match?.[4]?.split('.').some((identifier) => (
    /^\d+$/.test(identifier) && identifier.length > 1 && identifier.startsWith('0')
  )));
}

export function validateSourceAnalyzerPlugin(input: unknown): SourceAnalyzerPlugin {
  if (!input || typeof input !== 'object') {
    throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_PLUGIN');
  }
  const plugin = input as Partial<SourceAnalyzerPlugin>;
  const capabilities = plugin.capabilities as unknown as Record<string, unknown> | undefined;
  if (!safeText(plugin.id) || !SAFE_ID.test(plugin.id)
    || !safeText(plugin.version) || !isSemanticVersion(plugin.version)
    || !validateStringSet(plugin.languages) || !validateStringSet(plugin.frameworks)
    || typeof plugin.analyze !== 'function' || !capabilities
    || Object.keys(capabilities).length !== SOURCE_ANALYZER_CAPABILITY_NAMES.length
    || Object.keys(capabilities).some((name) => !SOURCE_ANALYZER_CAPABILITY_NAMES.includes(name as SourceAnalyzerCapabilityName))) {
    throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_PLUGIN');
  }
  for (const name of SOURCE_ANALYZER_CAPABILITY_NAMES) {
    const capability = capabilities[name];
    if (!capability || typeof capability !== 'object') {
      throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_PLUGIN');
    }
    const { status, reason } = capability as Partial<AnalyzerCapability>;
    if (!SOURCE_ANALYZER_CAPABILITY_STATUSES.includes(status as SourceAnalyzerCapabilityStatus)
      || !safeText(reason)) {
      throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_PLUGIN');
    }
  }
  return input as SourceAnalyzerPlugin;
}

function diagnostic(code: SourceAnalyzerDiagnosticCode, options: {
  sourceUri?: string; line?: unknown; column?: unknown;
} = {}): AnalyzerDiagnostic {
  return {
    code,
    safeMessage: SAFE_MESSAGES[code],
    ...(options.sourceUri ? { sourceUri: options.sourceUri } : {}),
    ...(Number.isInteger(options.line) && (options.line as number) > 0 ? { line: options.line as number } : {}),
    ...(Number.isInteger(options.column) && (options.column as number) > 0 ? { column: options.column as number } : {}),
  };
}

function failed(code: SourceAnalyzerDiagnosticCode, options: { sourceUri?: string } = {}): SourceAnalysisExecution {
  return { status: 'failed', diagnostics: [diagnostic(code, options)] };
}

function relativeSourceUri(value: unknown, workspaceRoot: string): string | undefined {
  if (value === undefined) return undefined;
  if (!safeText(value)) throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
  const normalized = value.replace(/\\/g, '/');
  if (/[?#]/.test(normalized)) throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
  const candidate = path.isAbsolute(value) ? path.resolve(value) : path.resolve(workspaceRoot, value);
  let absolute: string;
  try { absolute = fs.realpathSync(candidate); } catch {
    throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
  }
  const relative = path.relative(workspaceRoot, absolute).replace(/\\/g, '/');
  if (!relative || relative === '..' || relative.startsWith('../') || path.isAbsolute(relative)) {
    throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
  }
  return relative;
}

function validateMetrics(input: unknown): SourceAnalysisMetrics {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
  }
  const record = input as Record<string, unknown>;
  if (Object.keys(record).length !== METRIC_NAMES.length
    || Object.keys(record).some((name) => !METRIC_NAMES.includes(name as typeof METRIC_NAMES[number]))) {
    throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
  }
  for (const name of METRIC_NAMES) {
    if (!Number.isInteger(record[name]) || (record[name] as number) < 0) {
      throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
    }
  }
  const metrics = record as unknown as SourceAnalysisMetrics;
  if (metrics.largestFileBytes > metrics.totalSourceBytes) {
    throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
  }
  return { ...metrics };
}

const METRIC_LIMITS: ReadonlyArray<readonly [keyof SourceAnalysisMetrics, keyof SourceAnalysisLimits, SourceAnalyzerDiagnosticCode]> = [
  ['files', 'maxFiles', 'SOURCE_ANALYZER_FILE_LIMIT'],
  ['totalSourceBytes', 'maxTotalSourceBytes', 'SOURCE_ANALYZER_TOTAL_BYTES_LIMIT'],
  ['largestFileBytes', 'maxFileBytes', 'SOURCE_ANALYZER_FILE_BYTES_LIMIT'],
  ['astNodes', 'maxAstNodes', 'SOURCE_ANALYZER_AST_NODE_LIMIT'],
  ['diagnostics', 'maxDiagnostics', 'SOURCE_ANALYZER_DIAGNOSTIC_LIMIT'],
  ['operations', 'maxOperations', 'SOURCE_ANALYZER_OPERATION_LIMIT'],
  ['maxDepth', 'maxAnalysisDepth', 'SOURCE_ANALYZER_DEPTH_LIMIT'],
];

function exceededMetric(input: unknown, limits: SourceAnalysisLimits): SourceAnalyzerDiagnosticCode | undefined {
  if (!input || typeof input !== 'object') return undefined;
  const metrics = input as Record<string, unknown>;
  for (const [metric, limit, code] of METRIC_LIMITS) {
    if (typeof metrics[metric] === 'number' && metrics[metric] > limits[limit]) return code;
  }
  return undefined;
}

function validateResult(
  input: unknown,
  workspaceRoot: string,
  analyzerIdentity: string,
  capabilityStatuses: Readonly<Record<SourceAnalyzerCapabilityName, SourceAnalyzerCapabilityStatus>>,
): SourceAnalysisResult {
  if (!input || typeof input !== 'object') {
    throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
  }
  const candidate = input as Partial<SourceAnalysisResult>;
  if (!Array.isArray(candidate.diagnostics)) {
    throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
  }
  const metrics = validateMetrics(candidate.metrics);
  let contract: SecurityContractV1;
  try {
    contract = createSecurityContract(candidate.contract as SecurityContractInputV1);
  } catch {
    throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
  }
  if (contract.source !== 'source-ast' || metrics.operations !== contract.operations.length
    || metrics.diagnostics !== candidate.diagnostics.length) {
    throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
  }
  if (contract.capabilities.parameters === 'complete' || contract.capabilities.requestBodies === 'complete'
    || Object.entries(COMPLETE_CAPABILITY_REQUIREMENTS).some(([name, requirements]) => (
      contract.capabilities[name as keyof typeof COMPLETE_CAPABILITY_REQUIREMENTS] === 'complete'
      && requirements.some((capability) => capabilityStatuses[capability] !== 'supported')
    ))) {
    throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
  }
  if (contract.operations.some(({ provenance }) => provenance.some((evidence) => (
    evidence.source !== 'source-ast'
    || evidence.analyzer !== analyzerIdentity
    || !SOURCE_ANALYZER_CAPABILITY_NAMES.includes(evidence.capability as SourceAnalyzerCapabilityName)
    || capabilityStatuses[evidence.capability as SourceAnalyzerCapabilityName] === 'unsupported'
    || relativeSourceUri(evidence.uri, workspaceRoot) !== evidence.uri
  )))) {
    throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
  }
  const diagnostics = candidate.diagnostics.map((value) => {
    if (!value || typeof value !== 'object') {
      throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
    }
    const item = value as Partial<AnalyzerDiagnostic>;
    if (!SOURCE_ANALYZER_RESULT_DIAGNOSTIC_CODES.includes(
      item.code as typeof SOURCE_ANALYZER_RESULT_DIAGNOSTIC_CODES[number],
    )) {
      throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
    }
    return diagnostic(item.code as SourceAnalyzerDiagnosticCode, {
      sourceUri: relativeSourceUri(item.sourceUri, workspaceRoot),
      line: item.line,
      column: item.column,
    });
  });
  return { contract, diagnostics, metrics };
}

function log(logger: SafeAnalyzerLogger, code: SourceAnalyzerLogCode): void {
  try {
    Promise.resolve(logger.log(code)).catch(() => {});
  } catch { /* Logging must not change analysis results. */ }
}

function preflight(context: SourceAnalysisContext, limits: SourceAnalysisLimits):
{ workspaceRoot: string; entrypoints: string[] } | SourceAnalysisExecution {
  if (!Array.isArray(context.entrypoints) || context.entrypoints.length === 0) {
    return failed('SOURCE_ANALYZER_INPUT_INVALID');
  }
  if (context.entrypoints.length > limits.maxFiles) return failed('SOURCE_ANALYZER_FILE_LIMIT');
  let workspaceRoot: string;
  try { workspaceRoot = fs.realpathSync(context.workspaceRoot); } catch { return failed('SOURCE_ANALYZER_INPUT_INVALID'); }
  let totalBytes = 0;
  const entrypoints: string[] = [];
  for (const entrypoint of context.entrypoints) {
    if (!safeText(entrypoint) || /[?#]/.test(entrypoint)) return failed('SOURCE_ANALYZER_INPUT_INVALID');
    const candidate = path.resolve(workspaceRoot, entrypoint);
    let realPath: string;
    let stat: fs.Stats;
    try {
      realPath = fs.realpathSync(candidate);
      stat = fs.statSync(realPath);
    } catch {
      return failed('SOURCE_ANALYZER_INPUT_INVALID');
    }
    const relative = path.relative(workspaceRoot, realPath).replace(/\\/g, '/');
    if (!relative || relative === '..' || relative.startsWith('../') || path.isAbsolute(relative)) {
      return failed('SOURCE_ANALYZER_INPUT_OUTSIDE_ROOT');
    }
    if (!stat.isFile()) return failed('SOURCE_ANALYZER_INPUT_INVALID');
    if (stat.size > limits.maxFileBytes) return failed('SOURCE_ANALYZER_FILE_BYTES_LIMIT', { sourceUri: relative });
    totalBytes += stat.size;
    if (totalBytes > limits.maxTotalSourceBytes) return failed('SOURCE_ANALYZER_TOTAL_BYTES_LIMIT');
    entrypoints.push(relative);
  }
  return { workspaceRoot, entrypoints: [...new Set(entrypoints)].sort() };
}

export async function runSourceAnalyzer(
  input: SourceAnalyzerPlugin,
  context: SourceAnalysisContext,
): Promise<SourceAnalysisExecution> {
  let plugin: SourceAnalyzerPlugin;
  let limits: Readonly<SourceAnalysisLimits>;
  try {
    plugin = validateSourceAnalyzerPlugin(input);
    limits = validateSourceAnalysisLimits(context.limits);
  } catch (error) {
    return failed(error instanceof SourceAnalyzerContractError ? error.code : 'SOURCE_ANALYZER_INTERNAL');
  }
  if (context.cancellationSignal?.aborted) return failed('SOURCE_ANALYZER_CANCELLED');
  const analyzerIdentity = `${plugin.id}@${plugin.version}`;
  const capabilityStatuses = Object.fromEntries(SOURCE_ANALYZER_CAPABILITY_NAMES.map((name) => (
    [name, plugin.capabilities[name].status]
  ))) as Record<SourceAnalyzerCapabilityName, SourceAnalyzerCapabilityStatus>;
  const prepared = preflight(context, limits);
  if ('status' in prepared) return prepared;

  const controller = new AbortController();
  let interrupted: 'SOURCE_ANALYZER_CANCELLED' | 'SOURCE_ANALYZER_TIMEOUT' | undefined;
  const interrupt = (code: typeof interrupted) => {
    if (!controller.signal.aborted) {
      interrupted = code;
      controller.abort();
    }
  };
  const onCancel = () => interrupt('SOURCE_ANALYZER_CANCELLED');
  context.cancellationSignal?.addEventListener('abort', onCancel, { once: true });
  const timeout = setTimeout(() => interrupt('SOURCE_ANALYZER_TIMEOUT'), limits.timeoutMs);
  const safeLogger: SafeAnalyzerLogger = {
    log() { /* Lifecycle events are emitted only by the wrapper. */ },
  };
  log(context.logger, 'SOURCE_ANALYZER_STARTED');
  const startedAt = performance.now();
  try {
    const aborted = new Promise<never>((_, reject) => {
      controller.signal.addEventListener('abort', () => reject(new Error('analysis interrupted')), { once: true });
    });
    const result = await Promise.race([
      Promise.resolve().then(() => plugin.analyze({
        workspaceRoot: prepared.workspaceRoot,
        entrypoints: prepared.entrypoints,
        limits: { ...limits },
        cancellationSignal: controller.signal,
        logger: safeLogger,
      })),
      aborted,
    ]);
    if (context.cancellationSignal?.aborted) {
      interrupted = 'SOURCE_ANALYZER_CANCELLED';
      throw new SourceAnalyzerContractError(interrupted);
    }
    if (performance.now() - startedAt >= limits.timeoutMs) {
      interrupted = 'SOURCE_ANALYZER_TIMEOUT';
      throw new SourceAnalyzerContractError(interrupted);
    }
    const limitCode = exceededMetric((result as Partial<SourceAnalysisResult>).metrics, limits);
    if (limitCode) throw new SourceAnalyzerContractError(limitCode);
    const validated = validateResult(result, prepared.workspaceRoot, analyzerIdentity, capabilityStatuses);
    log(context.logger, 'SOURCE_ANALYZER_COMPLETED');
    return { status: 'success', result: validated };
  } catch (error) {
    log(context.logger, 'SOURCE_ANALYZER_FAILED');
    return failed(interrupted
      ?? (error instanceof SourceAnalyzerContractError ? error.code : 'SOURCE_ANALYZER_INTERNAL'));
  } finally {
    clearTimeout(timeout);
    context.cancellationSignal?.removeEventListener('abort', onCancel);
  }
}

export class SourceAnalyzerRegistry {
  private readonly plugins = new Map<string, SourceAnalyzerPlugin>();

  constructor(plugins: readonly SourceAnalyzerPlugin[] = []) {
    for (const plugin of plugins) this.register(plugin);
  }

  register(input: SourceAnalyzerPlugin): void {
    const plugin = validateSourceAnalyzerPlugin(input);
    const key = `${plugin.id}@${plugin.version}`;
    if (this.plugins.has(key)) throw new SourceAnalyzerContractError('SOURCE_ANALYZER_DUPLICATE');
    this.plugins.set(key, plugin);
  }

  get(id: string, version: string): SourceAnalyzerPlugin {
    const plugin = this.plugins.get(`${id}@${version}`);
    if (!plugin) throw new SourceAnalyzerContractError('SOURCE_ANALYZER_UNKNOWN');
    return plugin;
  }

  list(): SourceAnalyzerPlugin[] {
    return [...this.plugins.values()].sort((left, right) => {
      const leftKey = `${left.id}@${left.version}`;
      const rightKey = `${right.id}@${right.version}`;
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    });
  }
}
