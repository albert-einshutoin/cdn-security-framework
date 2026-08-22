import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import Ajv, { type ErrorObject } from 'ajv';
import * as yaml from 'js-yaml';

import { createFinding, type FindingInputV1, type SecurityFindingV1 } from './finding';
import { sortFindings } from './finding-order';

export const WAIVABLE_FINDING_RULE_IDS = [
  'SC-AUTHN-001', 'SC-AUTHN-002', 'SC-AUTHN-003', 'SC-AUTHN-004',
  'SC-EXPOSURE-001', 'SC-EXPOSURE-002', 'SC-EXPOSURE-003', 'SC-INVENTORY-002',
  'SC-LIMIT-001', 'SC-LIMIT-002',
  'SC-REQUEST-001', 'SC-REQUEST-002', 'SC-REQUEST-003',
] as const;

export type FindingExceptionTarget = 'aws' | 'cloudflare';

export interface FindingExceptionSelectorV1 {
  instance_id?: string;
  method?: string;
  path?: string;
  target?: FindingExceptionTarget;
  environment?: string;
}

export interface FindingExceptionV1 {
  id: string;
  rule_id: string;
  selector: FindingExceptionSelectorV1;
  reason: string;
  owner: string;
  expires_at: string;
  ticket?: string;
  allow_broad?: boolean;
  broad_reason?: string;
}

export interface FindingExceptionSetV1 {
  version: 1;
  exceptions: FindingExceptionV1[];
}

export interface FindingExceptionContext {
  currentDate: string;
  target?: FindingExceptionTarget;
  environment?: string;
  sourceUri?: string;
}

export interface FindingExceptionValidationResult {
  valid: boolean;
  errors: string[];
}

export interface FindingExceptionReportV1 {
  findings: SecurityFindingV1[];
  suppressedFindings: SecurityFindingV1[];
  appliedExceptionIds: string[];
  summary: { before: number; after: number; suppressed: number; governance: number };
}

export interface LoadFindingExceptionsOptions {
  inputPath: string;
  workspaceRoot: string;
  currentDate: string;
}

const MAX_FILE_BYTES = 1_048_576;
const MAX_EXCEPTIONS = 10_000;
const MAX_APPLY_VISITS = 1_000_000;
const SENSITIVE_TEXT = /["']?(?:authorization|cookie|set-cookie|x-api-key|api[-_]?key|access[-_]?token|refresh[-_]?token|token|password|secret)["']?\s*[:=]\s*["']?[^\s,;}]+|\bBearer\s+\S+/i;
const NON_WAIVABLE_RULE = /^SC-(?:PARSER|SCHEMA|UNSAFE|GOV)-/;

function schemaPath(): string {
  const compiled = path.join(__dirname, '..', 'schemas', 'finding-exceptions-v1.schema.json');
  return fs.existsSync(compiled)
    ? compiled
    : path.join(__dirname, '..', '..', 'schemas', 'finding-exceptions-v1.schema.json');
}

const schema = JSON.parse(fs.readFileSync(schemaPath(), 'utf8')) as object;
const validateSchema = new Ajv({ allErrors: true, strict: true }).compile(schema);

function schemaErrors(errors: ErrorObject[] | null | undefined): string[] {
  return (errors ?? []).map((error) => {
    const extra = typeof error.params.additionalProperty === 'string'
      ? ` ${error.params.additionalProperty}` : '';
    return `${error.instancePath || '/'} ${error.message ?? 'is invalid'}${extra}`;
  });
}

function validDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(parsed.valueOf()) && parsed.toISOString().slice(0, 10) === value;
}

function isBroadSelector(selector: FindingExceptionSelectorV1): boolean {
  if (selector.instance_id) return false;
  return !selector.method || !selector.path || selector.method.includes('*') || selector.path.includes('*');
}

export function validateFindingExceptionSet(
  value: unknown,
  context: Pick<FindingExceptionContext, 'currentDate'>,
): FindingExceptionValidationResult {
  const errors: string[] = [];
  if (!context || !validDate(context.currentDate)) errors.push('currentDate must be an ISO date');
  if (value && typeof value === 'object' && Array.isArray((value as { exceptions?: unknown }).exceptions)
    && (value as { exceptions: unknown[] }).exceptions.length > MAX_EXCEPTIONS) {
    return { valid: false, errors: [`exceptions must contain at most ${MAX_EXCEPTIONS} items`] };
  }
  if (!validateSchema(value)) return { valid: false, errors: [...errors, ...schemaErrors(validateSchema.errors)] };

  const set = value as FindingExceptionSetV1;
  const ids = new Set<string>();
  for (const exception of set.exceptions) {
    if (ids.has(exception.id)) errors.push(`${exception.id}: duplicate exception id`);
    ids.add(exception.id);
    if (!(WAIVABLE_FINDING_RULE_IDS as readonly string[]).includes(exception.rule_id)
      || NON_WAIVABLE_RULE.test(exception.rule_id)) {
      errors.push(`${exception.id}: unknown rule or non-waivable rule`);
    }
    if (exception.reason.trim().length < 20) errors.push(`${exception.id}: reason is too short or blank`);
    if (!exception.owner.trim()) errors.push(`${exception.id}: owner must not be blank`);
    if (exception.ticket !== undefined && !exception.ticket.trim()) {
      errors.push(`${exception.id}: ticket must not be blank`);
    }
    if (!validDate(exception.expires_at)) errors.push(`${exception.id}: expires_at must be a valid ISO date`);
    if (exception.selector.method !== undefined && !exception.selector.method.trim()) {
      errors.push(`${exception.id}: selector method must not be blank`);
    }
    if (exception.selector.path !== undefined && !exception.selector.path.trim()) {
      errors.push(`${exception.id}: selector path must not be blank`);
    }
    if (exception.selector.environment !== undefined && !exception.selector.environment.trim()) {
      errors.push(`${exception.id}: selector environment must not be blank`);
    }
    if (exception.selector.instance_id && (exception.selector.method || exception.selector.path)) {
      errors.push(`${exception.id}: instance_id cannot be combined with method or path`);
    }
    if (isBroadSelector(exception.selector)
      && (exception.allow_broad !== true || (exception.broad_reason?.trim().length ?? 0) < 20)) {
      errors.push(`${exception.id}: broad selector requires allow_broad and broad_reason`);
    }
    if (SENSITIVE_TEXT.test(exception.reason) || SENSITIVE_TEXT.test(exception.broad_reason ?? '')) {
      errors.push(`${exception.id}: sensitive text is not allowed in exception rationale`);
    }
  }
  return { valid: errors.length === 0, errors: [...new Set(errors)].sort() };
}

function within(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative !== '' && !relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative);
}

function readBoundedRegularFile(filePath: string, root: string): string {
  let fd: number | undefined;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const opened = fs.fstatSync(fd);
    if (!opened.isFile()) throw new Error('Finding exception input must be a regular file');
    const verifiedPath = fs.realpathSync(filePath);
    if (!within(root, verifiedPath)) throw new Error('Finding exception file is outside workspace');
    const verified = fs.statSync(verifiedPath);
    if (opened.dev !== verified.dev || opened.ino !== verified.ino) {
      throw new Error('Finding exception file changed while opening');
    }

    const chunks: Buffer[] = [];
    let total = 0;
    while (total <= MAX_FILE_BYTES) {
      const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, MAX_FILE_BYTES + 1 - total));
      const read = fs.readSync(fd, chunk, 0, chunk.length, null);
      if (read === 0) break;
      chunks.push(chunk.subarray(0, read));
      total += read;
    }
    if (total > MAX_FILE_BYTES) throw new Error('Finding exception file is too large');
    return Buffer.concat(chunks, total).toString('utf8');
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

export function loadFindingExceptions(options: LoadFindingExceptionsOptions): FindingExceptionSetV1 {
  if (!options || typeof options.inputPath !== 'string' || typeof options.workspaceRoot !== 'string') {
    throw new Error('invalid Finding exception loader options');
  }
  const workspacePath = path.resolve(options.workspaceRoot);
  const candidate = path.resolve(workspacePath, options.inputPath);
  if (!within(workspacePath, candidate)) throw new Error('Finding exception file is outside workspace');
  const root = fs.realpathSync(workspacePath);

  let resolved: string;
  try {
    resolved = fs.realpathSync(candidate);
  } catch {
    throw new Error('Finding exception file was not found');
  }
  if (!within(root, resolved)) throw new Error('Finding exception file is outside workspace');

  let parsed: unknown;
  try {
    parsed = yaml.load(readBoundedRegularFile(resolved, root), {
      schema: yaml.JSON_SCHEMA, json: false, maxAliases: 50, maxDepth: 64,
    });
  } catch (error: unknown) {
    if (error instanceof Error && error.message.startsWith('Finding exception')) throw error;
    throw new Error('invalid Finding exception file');
  }
  const validation = validateFindingExceptionSet(parsed, { currentDate: options.currentDate });
  if (!validation.valid) throw new Error(`invalid Finding exception file: ${validation.errors.join('; ')}`);
  return parsed as FindingExceptionSetV1;
}

function globMatches(pattern: string, value: string): boolean {
  if (!pattern.includes('*')) return pattern === value;
  const parts = pattern.split('*');
  let cursor = 0;
  if (parts[0] && !value.startsWith(parts[0])) return false;
  for (const part of parts) {
    if (!part) continue;
    const found = value.indexOf(part, cursor);
    if (found < 0) return false;
    cursor = found + part.length;
  }
  return !parts.at(-1) || value.endsWith(parts.at(-1)!);
}

function matches(
  finding: SecurityFindingV1,
  exception: FindingExceptionV1,
  context: FindingExceptionContext,
): boolean {
  const selector = exception.selector;
  if (exception.rule_id !== finding.ruleId
    || (selector.target !== undefined && selector.target !== context.target)
    || (selector.environment !== undefined && selector.environment !== context.environment)) return false;
  if (selector.instance_id) return selector.instance_id === finding.instanceId;
  if (selector.method
    && (!finding.route?.method
      || !globMatches(selector.method.toUpperCase(), finding.route.method.toUpperCase()))) return false;
  if (selector.path && (!finding.route?.path || !globMatches(selector.path, finding.route.path))) return false;
  return true;
}

function specificity(exception: FindingExceptionV1): readonly number[] {
  const selector = exception.selector;
  const kind = selector.instance_id ? 3 : selector.method && selector.path ? 2 : 1;
  const routePatterns = [selector.method, selector.path].filter((value): value is string => Boolean(value));
  const literalLength = routePatterns.reduce((total, value) => total + value.replaceAll('*', '').length, 0);
  const wildcardCount = routePatterns.reduce((total, value) => total + (value.match(/\*/g)?.length ?? 0), 0);
  return [
    kind,
    Number(selector.method !== undefined && !selector.method.includes('*'))
      + Number(selector.path !== undefined && !selector.path.includes('*')),
    literalLength,
    -wildcardCount,
    Number(selector.target !== undefined) + Number(selector.environment !== undefined),
  ];
}

function compareSpecificity(left: FindingExceptionV1, right: FindingExceptionV1): number {
  const leftScore = specificity(left);
  const rightScore = specificity(right);
  for (let index = 0; index < leftScore.length; index += 1) {
    if (leftScore[index] !== rightScore[index]) return rightScore[index] - leftScore[index];
  }
  return left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
}

function exceptionDigest(set: FindingExceptionSetV1): string {
  return `sha256:${createHash('sha256').update(JSON.stringify(set)).digest('hex')}`;
}

function governanceFinding(
  ruleId: 'SC-GOV-001' | 'SC-GOV-002' | 'SC-GOV-003',
  severity: 'error' | 'warning',
  title: string,
  message: string,
  actual: Record<string, unknown>,
  set: FindingExceptionSetV1,
  context: FindingExceptionContext,
): SecurityFindingV1 {
  return createFinding({
    ruleId, severity, confidence: 'deterministic', category: 'governance', title, message, actual,
    evidence: [{
      source: 'policy', uri: context.sourceUri ?? 'finding-exceptions.yml',
      pointer: `/exceptions/${encodeURIComponent(String(
        actual.exceptionId ?? actual.findingInstanceId ?? ruleId,
      ))}`,
      digest: exceptionDigest(set), analyzer: 'finding-exceptions@1',
      capability: 'finding-exceptions-v1', complete: true,
    }],
    remediation: { summary: 'Update or remove the exception and retain the audit record.', safeAutoFix: false },
    tags: ['non-waivable'],
  });
}

function isNonWaivable(finding: SecurityFindingV1): boolean {
  return finding.category === 'governance' || NON_WAIVABLE_RULE.test(finding.ruleId)
    || finding.tags?.includes('non-waivable') === true;
}

function canonicalizeFindings(findings: readonly SecurityFindingV1[]): SecurityFindingV1[] {
  return findings.map((finding) => {
    if (finding.schemaVersion !== 1) throw new Error('invalid Finding exception input');
    const { schemaVersion: _schemaVersion, instanceId, ...input } = finding;
    const canonical = createFinding(input as FindingInputV1);
    if (canonical.instanceId !== instanceId) {
      throw new Error('Finding instanceId does not match its canonical identity');
    }
    return canonical;
  });
}

function assertDataFields(value: unknown, required: readonly string[], optional: readonly string[] = []): void {
  if (value === null || typeof value !== 'object') throw new Error('invalid Finding exception input');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error('invalid Finding exception input');
  }
  if (Object.getOwnPropertySymbols(value).length > 0) throw new Error('invalid Finding exception input');
  for (const key of [...required, ...optional]) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor) {
      if (required.includes(key) || key in value) throw new Error('invalid Finding exception input');
      continue;
    }
    if (!('value' in descriptor)) throw new Error('invalid Finding exception input');
  }
}

function dataField(value: object, key: string): unknown {
  return Object.getOwnPropertyDescriptor(value, key)?.value;
}

function assertFindingDataProperties(finding: SecurityFindingV1): void {
  assertDataFields(
    finding,
    ['schemaVersion', 'ruleId', 'instanceId', 'severity', 'confidence', 'category', 'title', 'message', 'evidence'],
    ['route', 'expected', 'actual', 'remediation', 'tags'],
  );
  const route = dataField(finding, 'route');
  if (route !== undefined) assertDataFields(route, [], ['method', 'path', 'operationId']);
  const evidenceItems = dataField(finding, 'evidence');
  if (!Array.isArray(evidenceItems)) throw new Error('invalid Finding exception input');
  for (const evidence of evidenceItems) {
    assertDataFields(evidence, ['source', 'uri', 'digest', 'analyzer', 'capability', 'complete'], ['pointer']);
  }
  const remediation = dataField(finding, 'remediation');
  if (remediation !== undefined) assertDataFields(remediation, ['summary', 'safeAutoFix']);
}

function consumeFindingNodes(value: unknown, state: { visits: number }): void {
  const pending: unknown[] = [value];
  const seen = new WeakSet<object>();
  while (pending.length > 0) {
    state.visits += 1;
    if (state.visits > MAX_APPLY_VISITS) {
      throw new Error('Finding exception application exceeds visit budget');
    }
    const current = pending.pop();
    if (current === null || typeof current !== 'object' || seen.has(current)) continue;
    seen.add(current);
    if (Array.isArray(current)) {
      if (current.length > MAX_APPLY_VISITS - state.visits) {
        throw new Error('Finding exception application exceeds visit budget');
      }
      state.visits += current.length;
      for (let index = 0; index < current.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(current, index);
        if (!descriptor) continue;
        if (!('value' in descriptor)) throw new Error('invalid Finding exception input');
        pending.push(descriptor.value);
      }
      continue;
    }
    for (const key in current) {
      if (!Object.prototype.hasOwnProperty.call(current, key)) continue;
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (!descriptor || !('value' in descriptor)) throw new Error('invalid Finding exception input');
      state.visits += 1;
      if (state.visits > MAX_APPLY_VISITS) {
        throw new Error('Finding exception application exceeds visit budget');
      }
      pending.push(descriptor.value);
    }
  }
}

export function applyFindingExceptions(
  findings: readonly SecurityFindingV1[],
  set: FindingExceptionSetV1,
  context: FindingExceptionContext,
): FindingExceptionReportV1 {
  const validation = validateFindingExceptionSet(set, context);
  if (!validation.valid) throw new Error(`invalid Finding exception set: ${validation.errors.join('; ')}`);
  const budget = { visits: set.exceptions.length };
  for (const finding of findings) {
    consumeFindingNodes(finding, budget);
    assertFindingDataProperties(finding);
  }
  const canonicalFindings = canonicalizeFindings(findings);

  const governance: SecurityFindingV1[] = [];
  const live = set.exceptions.filter((exception) => {
    if (exception.expires_at >= context.currentDate) return true;
    governance.push(governanceFinding(
      'SC-GOV-001', 'error', 'Finding exception has expired',
      'An expired exception does not suppress its matching Finding.',
      { exceptionId: exception.id, owner: exception.owner, expiresAt: exception.expires_at }, set, context,
    ));
    return false;
  });
  const matchedIds = new Set<string>();
  const appliedIds = new Set<string>();
  const active: SecurityFindingV1[] = [];
  const suppressed: SecurityFindingV1[] = [];
  const byRule = new Map<string, FindingExceptionV1[]>();
  for (const exception of live) {
    const rules = byRule.get(exception.rule_id) ?? [];
    rules.push(exception);
    byRule.set(exception.rule_id, rules);
  }
  let visits = budget.visits;

  for (const finding of canonicalFindings) {
    const ruleExceptions = isNonWaivable(finding) ? [] : (byRule.get(finding.ruleId) ?? []);
    if (ruleExceptions.length > MAX_APPLY_VISITS - visits) {
      throw new Error('Finding exception application exceeds visit budget');
    }
    visits += ruleExceptions.length;
    const candidates = ruleExceptions.filter((exception) => matches(finding, exception, context));
    for (const candidate of candidates) matchedIds.add(candidate.id);
    if (candidates.length === 0) {
      active.push(finding);
      continue;
    }
    candidates.sort(compareSpecificity);
    const selected = candidates[0];
    suppressed.push(finding);
    appliedIds.add(selected.id);
    if (candidates.length > 1) governance.push(governanceFinding(
      'SC-GOV-003', 'warning', 'Multiple exceptions match one Finding',
      'The most specific exception was applied; remove redundant matching exceptions.',
      { findingInstanceId: finding.instanceId, selectedExceptionId: selected.id, matchCount: candidates.length },
      set, context,
    ));
  }

  for (const exception of live) {
    if (!matchedIds.has(exception.id)) governance.push(governanceFinding(
      'SC-GOV-002', 'warning', 'Finding exception is unused',
      'No current Finding matches this live exception; remove it if the underlying issue is gone.',
      { exceptionId: exception.id, owner: exception.owner, expiresAt: exception.expires_at }, set, context,
    ));
  }
  return {
    findings: sortFindings([...active, ...governance]),
    suppressedFindings: sortFindings(suppressed),
    appliedExceptionIds: [...appliedIds].sort(),
    summary: {
      before: canonicalFindings.length,
      after: active.length,
      suppressed: suppressed.length,
      governance: governance.length,
    },
  };
}
