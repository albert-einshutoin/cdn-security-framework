import fs from 'node:fs';
import path from 'node:path';
import Ajv, { type ValidateFunction } from 'ajv';

import type { ContractDiffReportV1 } from '../contract/contract-diff';
import type { SecurityFindingV1 } from '../contract/finding';
import { sortFindings } from '../contract/finding-order';

export const JSON_REPORT_ERROR_CODES = [
  'JSON_REPORT_INPUT_INVALID',
  'JSON_REPORT_SCHEMA_INVALID',
  'JSON_REPORT_PRIVACY_VIOLATION',
  'JSON_REPORT_OUTPUT_LIMIT_EXCEEDED',
  'JSON_REPORT_SERIALIZATION_FAILED',
] as const;
export type JsonReportErrorCode = typeof JSON_REPORT_ERROR_CODES[number];

export class JsonReportError extends Error {
  constructor(readonly code: JsonReportErrorCode, message: string) {
    super(`[${code}] ${message}`);
    this.name = 'JsonReportError';
  }
}

export interface UnifiedContractDiffJsonOptions {
  pretty?: boolean;
  newline?: boolean;
  maxOutputBytes?: number;
}

const DEFAULT_MAX_OUTPUT_BYTES = 1_048_576;
const MAX_VALUE_NODES = 100_000;
const MAX_STRING_LENGTH = 16_384;
const MAX_ARRAY_LENGTH = 10_000;
const MAX_OBJECT_KEYS = 10_000;
const SENSITIVE_KEY_PATTERN = /(?:authorization|cookie|set[-_]?cookie|api[-_]?key|access[_-]?token|refresh[_-]?token|token|secret|password)/i;
const SECRET_VALUE_PATTERN = /\b(?:Bearer|Basic)\s+(?!\[REDACTED\])[\w._~+/=-]+|\b(?:authorization|cookie|set-cookie|x-api-key|api[-_]?key|access[-_]?token|refresh[-_]?token|token|password|secret)\s*[:=]\s*["']?(?!\[REDACTED\])[^\s,"'}]+/i;
const QUERY_VALUE_PATTERN = /[?&][^=\s&#]+=(?!\[REDACTED\])[^&#\s]*/;
const ABSOLUTE_URI_PATTERN = /^(?:[A-Za-z][A-Za-z0-9+.-]*:|[A-Za-z]:[\\/]|\/)/u;

const KEY_ORDERS: Record<string, readonly string[]> = {
  '/': [
    'schemaVersion', 'inputDigests', 'target', 'summary', 'findings',
    'suppressedFindings', 'exceptionDiagnostics', 'appliedExceptionIds',
    'analyzerCapabilities', 'analyzerDiagnostics', 'omittedComparisons',
  ],
  '/inputDigests': ['openapi', 'policy', 'exceptions'],
  '/summary': ['total', 'error', 'warning', 'info', 'suppressed', 'bySeverity', 'byConfidence', 'byCategory'],
  '/summary/bySeverity': ['error', 'warning', 'info'],
  '/summary/byConfidence': ['deterministic', 'high-confidence', 'heuristic'],
  '/summary/byCategory': [
    'inventory', 'exposure', 'authentication', 'authorization', 'resource-limit',
    'misconfiguration', 'governance', 'runtime-evidence',
  ],
  '/analyzerCapabilities': ['openapi', 'policy'],
  '/analyzerCapabilities/openapi': ['routes', 'parameters', 'requestBodies', 'authentication'],
  '/analyzerCapabilities/policy[]': ['id', 'status'],
  '/analyzerDiagnostic': ['code', 'level', 'message', 'capability', 'metric', 'used', 'limit'],
  '/finding': [
    'schemaVersion', 'ruleId', 'instanceId', 'severity', 'confidence', 'category',
    'title', 'message', 'route', 'expected', 'actual', 'evidence', 'remediation', 'tags',
  ],
  '/finding/route': ['method', 'path', 'operationId'],
  '/finding/evidence': ['source', 'uri', 'pointer', 'digest', 'analyzer', 'capability', 'complete'],
  '/finding/remediation': ['summary', 'safeAutoFix'],
};
const POLICY_CAPABILITY_ORDER = [
  'request.allow_methods', 'request.allowed_hosts', 'routes.request.allow_methods',
  'request.uri_query_limits', 'request.header_limits', 'request.content_type',
  'request.path_normalization', 'auth.route_gates', 'routes.response.cache_control',
  'response.security_headers', 'response.csp_nonce', 'request.graphql_guard',
  'response.response_dlp',
];

function policyCapabilityKey(id: string): string {
  const index = POLICY_CAPABILITY_ORDER.indexOf(id);
  const rank = index < 0 ? POLICY_CAPABILITY_ORDER.length : index;
  return `${rank.toString().padStart(3, '0')}\u0000${id}`;
}

function schemaPath(name: string): string {
  const compiled = path.join(__dirname, '..', 'schemas', name);
  return fs.existsSync(compiled) ? compiled : path.join(__dirname, '..', '..', 'schemas', name);
}

let validateReport: ValidateFunction | undefined;

function reportValidator(): ValidateFunction {
  if (validateReport) return validateReport;
  try {
    const reportSchema = JSON.parse(fs.readFileSync(
      schemaPath('contract-diff-report-v1.schema.json'), 'utf8',
    )) as object;
    const findingSchema = JSON.parse(fs.readFileSync(
      schemaPath('finding-v1.schema.json'), 'utf8',
    )) as object;
    const ajv = new Ajv({ allErrors: false, strict: false });
    ajv.addSchema(findingSchema);
    validateReport = ajv.compile(reportSchema);
    return validateReport;
  } catch {
    throw new JsonReportError('JSON_REPORT_SCHEMA_INVALID', 'Report schema is unavailable.');
  }
}

function orderedKeys(keys: readonly string[], pathName: string): string[] {
  const order = KEY_ORDERS[pathName] ?? [];
  const rank = new Map(order.map((key, index) => [key, index]));
  return [...keys].sort((left, right) => (
    (rank.get(left) ?? Number.MAX_SAFE_INTEGER) - (rank.get(right) ?? Number.MAX_SAFE_INTEGER)
    || (left < right ? -1 : left > right ? 1 : 0)
  ));
}

function itemPath(pathName: string): string {
  if (pathName === '/findings' || pathName === '/suppressedFindings' || pathName === '/exceptionDiagnostics') {
    return '/finding';
  }
  if (pathName === '/analyzerCapabilities/policy') return '/analyzerCapabilities/policy[]';
  if (pathName === '/analyzerDiagnostics') return '/analyzerDiagnostic';
  return pathName;
}

function stableArray(pathName: string, values: unknown[]): unknown[] {
  if (pathName === '/findings' || pathName === '/suppressedFindings' || pathName === '/exceptionDiagnostics') {
    return sortFindings(values as SecurityFindingV1[]);
  }
  if (pathName === '/analyzerCapabilities/policy' || pathName === '/analyzerDiagnostics') {
    return [...values].sort((left, right) => {
      const a = left as Record<string, unknown>;
      const b = right as Record<string, unknown>;
      const leftKey = pathName.endsWith('policy')
        ? `${policyCapabilityKey(String(a.id ?? ''))}\u0000${String(a.status ?? '')}`
        : [a.code, a.level, a.capability, a.metric, a.message, a.used, a.limit]
          .map((part) => String(part ?? '')).join('\u0000');
      const rightKey = pathName.endsWith('policy')
        ? `${policyCapabilityKey(String(b.id ?? ''))}\u0000${String(b.status ?? '')}`
        : [b.code, b.level, b.capability, b.metric, b.message, b.used, b.limit]
          .map((part) => String(part ?? '')).join('\u0000');
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    });
  }
  if (pathName === '/appliedExceptionIds' || pathName === '/omittedComparisons') {
    return [...values].sort((left, right) => {
      const a = String(left);
      const b = String(right);
      return a < b ? -1 : a > b ? 1 : 0;
    });
  }
  return values;
}

interface CanonicalState {
  ancestors: WeakSet<object>;
  nodes: number;
}

function canonicalize(value: unknown, pathName: string, state: CanonicalState): unknown {
  state.nodes += 1;
  if (state.nodes > MAX_VALUE_NODES) {
    throw new JsonReportError('JSON_REPORT_INPUT_INVALID', 'Report exceeds the value limit.');
  }
  if (value === null || typeof value === 'boolean' || typeof value === 'number') {
    if (typeof value === 'number' && !Number.isFinite(value)) {
      throw new JsonReportError('JSON_REPORT_INPUT_INVALID', 'Report contains a non-finite number.');
    }
    return value;
  }
  if (typeof value === 'string') {
    if (value.length > MAX_STRING_LENGTH) {
      throw new JsonReportError('JSON_REPORT_INPUT_INVALID', 'Report contains an oversized string.');
    }
    return value;
  }
  if (typeof value === 'bigint' || typeof value === 'function' || typeof value === 'symbol' || value === undefined) {
    throw new JsonReportError('JSON_REPORT_INPUT_INVALID', 'Report contains an unsupported value.');
  }
  if (typeof value !== 'object') {
    throw new JsonReportError('JSON_REPORT_INPUT_INVALID', 'Report contains an unsupported value.');
  }
  if (state.ancestors.has(value)) {
    throw new JsonReportError('JSON_REPORT_INPUT_INVALID', 'Report contains a cyclic value.');
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null && !Array.isArray(value)) {
    throw new JsonReportError('JSON_REPORT_INPUT_INVALID', 'Report contains a non-data object.');
  }
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw new JsonReportError('JSON_REPORT_INPUT_INVALID', 'Report contains symbol properties.');
  }
  state.ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (value.length > MAX_ARRAY_LENGTH) {
        throw new JsonReportError('JSON_REPORT_INPUT_INVALID', 'Report contains an oversized array.');
      }
      const output: unknown[] = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !('value' in descriptor)) {
          throw new JsonReportError('JSON_REPORT_INPUT_INVALID', 'Report contains an accessor or sparse array.');
        }
        output.push(canonicalize(descriptor.value, itemPath(pathName), state));
      }
      return stableArray(pathName, output);
    }

    const keys = Object.keys(value);
    if (keys.length > MAX_OBJECT_KEYS) {
      throw new JsonReportError('JSON_REPORT_INPUT_INVALID', 'Report contains too many object fields.');
    }
    const output: Record<string, unknown> = {};
    for (const key of orderedKeys(keys, pathName)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !('value' in descriptor)) {
        throw new JsonReportError('JSON_REPORT_INPUT_INVALID', 'Report contains an accessor property.');
      }
      const childPath = pathName === '/' && (key === 'findings' || key === 'suppressedFindings' || key === 'exceptionDiagnostics')
        ? `/${key}`
        : `${pathName === '/' ? '' : pathName}/${key}`;
      output[key] = canonicalize(descriptor.value, childPath, state);
    }
    return output;
  } finally {
    state.ancestors.delete(value);
  }
}

function privacyCheck(value: unknown, pathName = '/', state = new WeakSet<object>()): void {
  if (typeof value === 'string') {
    if (SECRET_VALUE_PATTERN.test(value)) {
      throw new JsonReportError('JSON_REPORT_PRIVACY_VIOLATION', 'Report contains sensitive text.');
    }
    if (QUERY_VALUE_PATTERN.test(value)) {
      throw new JsonReportError('JSON_REPORT_PRIVACY_VIOLATION', 'Report contains a raw query value.');
    }
    if (pathName.endsWith('/uri') && ABSOLUTE_URI_PATTERN.test(value)) {
      throw new JsonReportError('JSON_REPORT_PRIVACY_VIOLATION', 'Report contains an external URI.');
    }
    return;
  }
  if (value === null || typeof value !== 'object') return;
  if (state.has(value)) return;
  state.add(value);
  if (Array.isArray(value)) {
    value.forEach((item, index) => privacyCheck(item, `${pathName}/${index}`, state));
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (SENSITIVE_KEY_PATTERN.test(key) && typeof child === 'string' && child !== '[REDACTED]') {
      throw new JsonReportError('JSON_REPORT_PRIVACY_VIOLATION', 'Report contains a sensitive field.');
    }
    privacyCheck(child, `${pathName === '/' ? '' : pathName}/${key}`, state);
  }
}

function validateSchema(value: unknown): void {
  const validate = reportValidator();
  if (!validate(value)) throw new JsonReportError('JSON_REPORT_SCHEMA_INVALID', 'Report does not match the v1 schema.');
}

function optionLimit(value: number | undefined): number {
  if (value === undefined) return DEFAULT_MAX_OUTPUT_BYTES;
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new JsonReportError('JSON_REPORT_INPUT_INVALID', 'maxOutputBytes must be a positive safe integer.');
  }
  return value;
}

export function renderUnifiedContractDiffJson(
  report: ContractDiffReportV1,
  options: UnifiedContractDiffJsonOptions = {},
): string {
  if (!report || typeof report !== 'object') {
    throw new JsonReportError('JSON_REPORT_INPUT_INVALID', 'Report is required.');
  }
  if (!options || typeof options !== 'object') {
    throw new JsonReportError('JSON_REPORT_INPUT_INVALID', 'Options are invalid.');
  }
  if (options.pretty !== undefined && typeof options.pretty !== 'boolean') {
    throw new JsonReportError('JSON_REPORT_INPUT_INVALID', 'pretty must be a boolean.');
  }
  if (options.newline !== undefined && typeof options.newline !== 'boolean') {
    throw new JsonReportError('JSON_REPORT_INPUT_INVALID', 'newline must be a boolean.');
  }
  let canonical: unknown;
  try {
    canonical = canonicalize(report, '/', { ancestors: new WeakSet<object>(), nodes: 0 });
  } catch (error: unknown) {
    if (error instanceof JsonReportError) throw error;
    throw new JsonReportError('JSON_REPORT_INPUT_INVALID', 'Report could not be inspected safely.');
  }
  validateSchema(canonical);
  privacyCheck(canonical);

  let serialized: string;
  try {
    serialized = JSON.stringify(canonical, null, options.pretty === false ? undefined : 2);
  } catch {
    throw new JsonReportError('JSON_REPORT_SERIALIZATION_FAILED', 'Report could not be serialized.');
  }
  if (typeof serialized !== 'string') {
    throw new JsonReportError('JSON_REPORT_SERIALIZATION_FAILED', 'Report could not be serialized.');
  }
  const output = `${serialized}${options.newline === false ? '' : '\n'}`;
  const maxOutputBytes = optionLimit(options.maxOutputBytes);
  if (Buffer.byteLength(output, 'utf8') > maxOutputBytes) {
    throw new JsonReportError('JSON_REPORT_OUTPUT_LIMIT_EXCEEDED', 'Serialized report exceeds the output limit.');
  }
  try {
    const parsed = JSON.parse(output);
    validateSchema(parsed);
  } catch (error: unknown) {
    if (error instanceof JsonReportError) throw error;
    throw new JsonReportError('JSON_REPORT_SERIALIZATION_FAILED', 'Serialized report could not be validated.');
  }
  return output;
}
