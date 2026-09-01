import { createHash } from 'node:crypto';

import { redactSensitiveText, SENSITIVE_KEY_PATTERN } from './sensitive-text';

export const FINDING_SEVERITIES = ['error', 'warning', 'info'] as const;
export const FINDING_CONFIDENCES = ['deterministic', 'high-confidence', 'heuristic'] as const;
export const FINDING_CATEGORIES = [
  'inventory',
  'exposure',
  'authentication',
  'authorization',
  'resource-limit',
  'misconfiguration',
  'governance',
  'runtime-evidence',
] as const;
export const FINDING_EVIDENCE_SOURCES = [
  'openapi',
  'source-ast',
  'policy',
  'runtime',
  'generated-artifact',
] as const;

export type FindingSeverity = typeof FINDING_SEVERITIES[number];
export type FindingConfidence = typeof FINDING_CONFIDENCES[number];
export type FindingCategory = typeof FINDING_CATEGORIES[number];
export type FindingEvidenceSource = typeof FINDING_EVIDENCE_SOURCES[number];

export interface FindingRouteV1 {
  method?: string;
  path?: string;
  operationId?: string;
}

export interface FindingEvidenceV1 {
  source: FindingEvidenceSource;
  uri: string;
  pointer?: string;
  digest: string;
  analyzer: string;
  capability: string;
  complete: boolean;
}

export interface FindingRemediationV1 {
  summary: string;
  safeAutoFix: boolean;
}

export interface SecurityFindingV1 {
  schemaVersion: 1;
  ruleId: string;
  instanceId: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  category: FindingCategory;
  title: string;
  message: string;
  route?: FindingRouteV1;
  expected?: unknown;
  actual?: unknown;
  evidence: FindingEvidenceV1[];
  remediation?: FindingRemediationV1;
  tags?: string[];
}

export type FindingInputV1 = Omit<SecurityFindingV1, 'schemaVersion' | 'instanceId'>;

export interface FindingCreationOptions {
  workspaceRoot?: string;
}

const RULE_ID_PATTERN = /^SC-[A-Z][A-Z0-9]*-[0-9]{3}$/;
const MAX_REDACTION_DEPTH = 32;
const MAX_REDACTION_NODES = 10_000;
const MAX_REDACTED_STRING_LENGTH = 16_384;
const REDACTION_LOOKAHEAD = 256;

function redactString(value: string): string {
  const truncated = value.length > MAX_REDACTED_STRING_LENGTH;
  const bounded = value.slice(0, MAX_REDACTED_STRING_LENGTH + REDACTION_LOOKAHEAD);
  const redacted = redactSensitiveText(bounded);
  return `${redacted.slice(0, MAX_REDACTED_STRING_LENGTH)}${truncated ? '[TRUNCATED]' : ''}`;
}

interface RedactionState {
  seen: WeakSet<object>;
  nodes: number;
}

function redactValue(
  value: unknown,
  state: RedactionState = { seen: new WeakSet<object>(), nodes: 0 },
  depth = 0,
): unknown {
  if (state.nodes >= MAX_REDACTION_NODES) return '[REDACTED_NODE_LIMIT]';
  state.nodes += 1;
  if (typeof value === 'string') return redactString(value);
  if (typeof value === 'function' || typeof value === 'symbol') return '[REDACTED_UNSUPPORTED]';
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number' && !Number.isFinite(value)) return null;
  if (value === null || typeof value !== 'object') return value;
  if (depth >= MAX_REDACTION_DEPTH) return '[REDACTED_DEPTH_LIMIT]';
  if (state.seen.has(value)) return '[REDACTED_CIRCULAR]';
  state.seen.add(value);

  if (Array.isArray(value)) {
    const output: unknown[] = [];
    for (let index = 0; index < value.length && state.nodes < MAX_REDACTION_NODES; index += 1) {
      output.push(redactValue(value[index], state, depth + 1));
    }
    if (output.length < value.length) output.push('[REDACTED_NODE_LIMIT]');
    return output;
  }

  const output: Record<string, unknown> = {};
  let complete = true;
  for (const key in value) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
    if (state.nodes >= MAX_REDACTION_NODES) {
      complete = false;
      break;
    }
    const child = (value as Record<string, unknown>)[key];
    if (SENSITIVE_KEY_PATTERN.test(key)) {
      state.nodes += 1;
      output[key] = '[REDACTED]';
    } else {
      output[key] = redactValue(child, state, depth + 1);
    }
  }
  if (!complete) output.__truncated__ = '[REDACTED_NODE_LIMIT]';
  return output;
}

function normalizeRoute(route: FindingRouteV1 | undefined): FindingRouteV1 | undefined {
  if (!route) return undefined;
  const normalized: FindingRouteV1 = {};
  const method = route.method?.trim();
  const routePath = route.path?.trim();
  const operationId = route.operationId?.trim();
  if (method) normalized.method = redactString(method.toUpperCase());
  if (routePath) normalized.path = redactString(routePath.replace(/\\/g, '/'));
  if (operationId) normalized.operationId = redactString(operationId);
  return Object.keys(normalized).length > 0 ? normalized : undefined;
}

function normalizeEvidenceUri(uri: string, workspaceRoot?: string): string {
  const normalized = redactString(uri.trim().replace(/\\/g, '/'));
  if (/^file:/i.test(normalized)) {
    throw new Error('Finding file evidence uri is not supported');
  }
  const isWindowsAbsolute = /^[A-Za-z]:\//.test(normalized);
  const isPosixAbsolute = normalized.startsWith('/');
  if (!isWindowsAbsolute && !isPosixAbsolute) {
    if (normalized.split('/').includes('..')) throw new Error('Finding evidence uri escapes its root');
    return normalized.replace(/^\.\//, '');
  }
  if (!workspaceRoot) throw new Error('Finding absolute evidence uri requires workspaceRoot');

  const root = workspaceRoot.trim().replace(/\\/g, '/').replace(/\/$/, '');
  const comparableUri = isWindowsAbsolute ? normalized.toLowerCase() : normalized;
  const comparableRoot = isWindowsAbsolute ? root.toLowerCase() : root;
  if (!comparableUri.startsWith(`${comparableRoot}/`)) {
    throw new Error('Finding evidence uri is outside workspaceRoot');
  }
  const relative = normalized.slice(root.length + 1);
  if (!relative || relative.split('/').includes('..')) {
    throw new Error('Finding evidence uri is invalid');
  }
  return relative;
}

function sanitizeEvidence(
  evidence: FindingEvidenceV1,
  options: FindingCreationOptions,
): FindingEvidenceV1 {
  return {
    source: evidence.source,
    uri: normalizeEvidenceUri(evidence.uri, options.workspaceRoot),
    ...(evidence.pointer ? { pointer: redactString(evidence.pointer) } : {}),
    digest: redactString(evidence.digest),
    analyzer: redactString(evidence.analyzer),
    capability: redactString(evidence.capability),
    complete: evidence.complete,
  };
}

function stableSerialize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableSerialize).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => (
    `${JSON.stringify(key)}:${stableSerialize(record[key])}`
  )).join(',')}}`;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalEvidence(
  evidence: readonly FindingEvidenceV1[],
  options: FindingCreationOptions,
): unknown[] {
  return evidence.map((item) => sanitizeEvidence(item, options)).map(({
    source, uri, pointer, digest, analyzer, capability, complete,
  }) => ({
    source,
    uri,
    ...(pointer ? { pointer } : {}),
    ...(digest ? { digest } : {}),
    ...(analyzer ? { analyzer } : {}),
    capability,
    complete,
  })).sort((a, b) => compareText(stableSerialize(a), stableSerialize(b)));
}

export function computeFindingInstanceId(
  finding: FindingInputV1,
  options: FindingCreationOptions = {},
): string {
  const identity = {
    ruleId: finding.ruleId,
    route: normalizeRoute(finding.route) ?? null,
    evidence: canonicalEvidence(finding.evidence, options),
  };
  return createHash('sha256').update(stableSerialize(identity)).digest('hex');
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function assertValidInput(input: FindingInputV1): void {
  if (!RULE_ID_PATTERN.test(input.ruleId)) {
    throw new Error('invalid Finding ruleId');
  }
  if (!Array.isArray(input.evidence) || input.evidence.length === 0) {
    throw new Error('Finding evidence must contain at least one item');
  }
  if (!FINDING_SEVERITIES.includes(input.severity)
    || !FINDING_CONFIDENCES.includes(input.confidence)
    || !FINDING_CATEGORIES.includes(input.category)
    || !isNonEmptyString(input.title)
    || !isNonEmptyString(input.message)) {
    throw new Error('invalid Finding fields');
  }
  for (const evidence of input.evidence) {
    if (!FINDING_EVIDENCE_SOURCES.includes(evidence.source)
      || !isNonEmptyString(evidence.uri)
      || !isNonEmptyString(evidence.digest)
      || !isNonEmptyString(evidence.analyzer)
      || !isNonEmptyString(evidence.capability)
      || typeof evidence.complete !== 'boolean') {
      throw new Error('invalid Finding evidence');
    }
  }
  if (input.route && Object.values(input.route).some((value) => (
    value !== undefined && !isNonEmptyString(value)
  ))) {
    throw new Error('invalid Finding route');
  }
  if (input.remediation
    && (!isNonEmptyString(input.remediation.summary)
      || typeof input.remediation.safeAutoFix !== 'boolean')) {
    throw new Error('invalid Finding remediation');
  }
  if (input.tags && (!Array.isArray(input.tags) || input.tags.some((tag) => !isNonEmptyString(tag)))) {
    throw new Error('invalid Finding tags');
  }
}

export function createFinding(
  input: FindingInputV1,
  options: FindingCreationOptions = {},
): SecurityFindingV1 {
  assertValidInput(input);

  const evidence = input.evidence.map((item) => sanitizeEvidence(item, options));
  const route = normalizeRoute(input.route);
  return {
    schemaVersion: 1,
    ruleId: input.ruleId,
    instanceId: computeFindingInstanceId({ ...input, evidence, route }),
    severity: input.severity,
    confidence: input.confidence,
    category: input.category,
    title: redactString(input.title),
    message: redactString(input.message),
    ...(route ? { route } : {}),
    ...('expected' in input ? { expected: redactValue(input.expected) } : {}),
    ...('actual' in input ? { actual: redactValue(input.actual) } : {}),
    evidence,
    ...(input.remediation ? {
      remediation: {
        summary: redactString(input.remediation.summary),
        safeAutoFix: input.remediation.safeAutoFix,
      },
    } : {}),
    ...(input.tags ? { tags: [...new Set(input.tags.map(redactString))].sort() } : {}),
  };
}
