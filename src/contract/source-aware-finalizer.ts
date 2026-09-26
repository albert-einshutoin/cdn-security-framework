import { isDeepStrictEqual } from 'node:util';

import { OPENAPI_ANALYSIS_ERROR_CODES } from '../openapi/analysis-error';
import { SOURCE_ANALYZER_DIAGNOSTIC_CODES } from '../source-analysis';
import { contractDiffThresholdReached, type ContractDiffFailOn } from './contract-diff';
import { applyFindingExceptions, validateFindingExceptionSet, type FindingExceptionSetV1 } from './finding-exceptions';
import type { SecurityFindingV1 } from './finding';
import { sortFindings } from './finding-order';
import { redactEvidenceFilename, redactSensitiveText } from './sensitive-text';
import type { SourceAwareWorkspaceResult } from './source-aware-workspace';

export const SOURCE_AWARE_COMPARISONS = [
  'declaredAllowed', 'implementedDeclared', 'implementedAllowed',
] as const;
export type SourceAwareComparisonName = typeof SOURCE_AWARE_COMPARISONS[number];
type StageName = 'declared' | 'implemented' | 'allowed';
type Outcome = 'ok' | 'input-error' | 'internal-error';

type StageSummary = { status: 'complete' | 'partial' | 'omitted' | 'failed'; code?: string; diagnosticCodes: string[] };
type ComparisonSummary =
  | { status: 'complete' | 'partial'; count: number; active: number; suppressed: number }
  | { status: 'omitted' | 'failed'; code: string };

export interface SourceAwareFinalizedResult {
  target: 'aws' | 'cloudflare';
  routingAssumption?: { globalPrefix?: string; sourceVersioning?: 'uri'; versionPrefix?: 'v';
    digest: string; comparisonContractDigest?: string };
  sourceVersionMetadata?: SourceAwareWorkspaceResult['evidence']['sourceVersionMetadata'];
  stages: Record<StageName, StageSummary>;
  comparisons: Record<SourceAwareComparisonName, ComparisonSummary>;
  findings: SecurityFindingV1[];
  suppressedFindings: SecurityFindingV1[];
  exceptionDiagnostics: SecurityFindingV1[];
  appliedExceptionIds: string[];
  memberships: { instanceId: string; comparisons: SourceAwareComparisonName[] }[];
  summary: { unique: number; active: number; suppressed: number; governance: number };
  analysis: { status: 'complete' | 'partial' | 'failed'; outcome: Outcome; codes: string[] };
  threshold: { failOn: ContractDiffFailOn | 'invalid'; reached: boolean };
  exitCode: 0 | 1 | 2 | 3;
}

export interface SourceAwareFinalizerOptions {
  currentDate: string;
  failOn: ContractDiffFailOn;
  environment?: string;
  exceptions?: FindingExceptionSetV1;
}

export class SourceAwareFinalizationError extends Error {
  constructor(
    readonly code: 'SOURCE_FINDING_IDENTITY_CONFLICT' | 'SOURCE_FINDING_INPUT_INVALID'
      | 'SOURCE_EXCEPTION_APPLY_FAILED' | 'SOURCE_FINALIZER_OPTIONS_INVALID',
    readonly exitCode: 2 | 3 = 3,
  ) {
    super(code);
    this.name = 'SourceAwareFinalizationError';
  }
}

const EMPTY_EXCEPTIONS: FindingExceptionSetV1 = { version: 1, exceptions: [] };
const INPUT_CODES = new Set<string>([
  ...OPENAPI_ANALYSIS_ERROR_CODES,
  ...SOURCE_ANALYZER_DIAGNOSTIC_CODES.filter((code) => ![
    'SOURCE_ANALYZER_INTERNAL', 'SOURCE_ANALYZER_INVALID_RESULT', 'SOURCE_ANALYZER_UNKNOWN',
    'SOURCE_ANALYZER_CANCELLED',
  ].includes(code)),
  'CONTRACT_DIFF_WORKSPACE_INVALID', 'CONTRACT_DIFF_POLICY_OUTSIDE_ROOT',
  'CONTRACT_DIFF_POLICY_INVALID', 'CONTRACT_DIFF_POLICY_LIMIT', 'CONTRACT_DIFF_POLICY_CHANGED',
  'CONTRACT_DIFF_EXCEPTIONS_INVALID', 'CONTRACT_DIFF_FAIL_ON_INVALID',
]);
const KNOWN_CODES = new Set<string>([
  ...INPUT_CODES,
  ...SOURCE_ANALYZER_DIAGNOSTIC_CODES,
  'OPENAPI_CAPABILITY_PARTIAL', 'OPENAPI_CAPABILITY_UNSUPPORTED', 'OPENAPI_LIMIT_NEAR',
  'SOURCE_NOT_REQUESTED', 'SOURCE_EVIDENCE_MISSING', 'OPENAPI_EVIDENCE_MISSING',
  'POLICY_INPUT_FAILED', 'POLICY_PROJECTION_FAILED', 'OPENAPI_ANALYSIS_FAILED',
  'COMPARISON_FAILED', 'COMPARISON_RESOURCE_LIMIT', 'INPUT_FAILED',
  'SOURCE_COMPARISON_UNEXPECTED_OMISSION',
]);
export function isSourceAwareDiagnosticCode(value: unknown): value is string {
  return typeof value === 'string' && (KNOWN_CODES.has(value) || value === 'SOURCE_UNKNOWN_FAILURE');
}
const MAX_PREVIEW_FINDINGS = 40;
const MAX_PREVIEW_EXCEPTION_IDS = 40;
const MAX_PREVIEW_BYTES = 32_768;
const MAX_PREVIEW_FIELD = 256;

function safeCode(value: string | undefined): string {
  return typeof value === 'string' && KNOWN_CODES.has(value)
    ? value : 'SOURCE_UNKNOWN_FAILURE';
}

function copyStage(stage: SourceAwareWorkspaceResult['stages'][StageName]): StageSummary {
  return {
    status: stage.status,
    ...(stage.code ? { code: safeCode(stage.code) } : {}),
    diagnosticCodes: [...new Set(stage.diagnosticCodes.map(safeCode))].sort(),
  };
}

function failureCodes(
  stages: SourceAwareFinalizedResult['stages'],
  comparisons: SourceAwareFinalizedResult['comparisons'],
  exceptionInvalid: boolean,
): string[] {
  const codes = new Set<string>();
  for (const stage of Object.values(stages)) {
    if (stage.status === 'failed') codes.add(stage.code ?? 'SOURCE_UNKNOWN_FAILURE');
    for (const code of stage.diagnosticCodes) codes.add(code);
  }
  for (const comparison of Object.values(comparisons)) {
    if (comparison.status === 'failed') codes.add(comparison.code);
  }
  if (exceptionInvalid) codes.add('CONTRACT_DIFF_EXCEPTIONS_INVALID');
  return [...codes].sort();
}

// Internal/pre-Entry only. The adapter owns I/O and input evidence; this step only transforms its result.
export function finalizeSourceAwareWorkspace(
  input: SourceAwareWorkspaceResult,
  options: SourceAwareFinalizerOptions,
): SourceAwareFinalizedResult {
  if (!input || !['aws', 'cloudflare'].includes(input.target)
    || !options || !validateFindingExceptionSet(EMPTY_EXCEPTIONS, { currentDate: options.currentDate }).valid) {
    throw new SourceAwareFinalizationError('SOURCE_FINALIZER_OPTIONS_INVALID', 2);
  }
  const context = { currentDate: options.currentDate, target: input.target, environment: options.environment };
  let validExceptions = false;
  try {
    validExceptions = validateFindingExceptionSet(options.exceptions ?? EMPTY_EXCEPTIONS, context).valid;
  } catch { /* Invalid exception data must not be applied. */ }
  const exceptionInvalid = !validExceptions;
  const thresholdInvalid = !['error', 'warning', 'never'].includes(options.failOn);
  const stages = {
    declared: copyStage(input.stages.declared),
    implemented: copyStage(input.stages.implemented),
    allowed: copyStage(input.stages.allowed),
  };
  const memberships = new Map<string, SourceAwareComparisonName[]>();
  const comparisonIds = new Map<SourceAwareComparisonName, Set<string>>();
  const canonical: SecurityFindingV1[] = [];
  for (const name of SOURCE_AWARE_COMPARISONS) {
    const comparison = input.comparisons[name];
    if (comparison.status === 'omitted' || comparison.status === 'failed') continue;
    let findings: SecurityFindingV1[];
    try {
      if (!Array.isArray(comparison.findings)) throw new Error('invalid Finding input');
      findings = applyFindingExceptions(comparison.findings, EMPTY_EXCEPTIONS, context).findings;
    } catch {
      throw new SourceAwareFinalizationError('SOURCE_FINDING_INPUT_INVALID');
    }
    const ids = new Set<string>();
    for (const finding of findings) {
      canonical.push(finding);
      ids.add(finding.instanceId);
      const names = memberships.get(finding.instanceId) ?? [];
      if (!names.includes(name)) names.push(name);
      memberships.set(finding.instanceId, names);
    }
    comparisonIds.set(name, ids);
  }
  const unique = new Map<string, SecurityFindingV1>();
  for (const finding of canonical) {
    const previous = unique.get(finding.instanceId);
    if (previous && !isDeepStrictEqual(previous, finding)) {
      throw new SourceAwareFinalizationError('SOURCE_FINDING_IDENTITY_CONFLICT');
    }
    unique.set(finding.instanceId, finding);
  }
  const ordered = sortFindings([...unique.values()]);
  let applied;
  try {
    applied = applyFindingExceptions(ordered, exceptionInvalid ? EMPTY_EXCEPTIONS : options.exceptions ?? EMPTY_EXCEPTIONS, context);
  } catch {
    throw new SourceAwareFinalizationError('SOURCE_EXCEPTION_APPLY_FAILED');
  }
  const findings = applied.findings.filter(({ category }) => category !== 'governance');
  const exceptionDiagnostics = applied.findings.filter(({ category }) => category === 'governance');
  const suppressedFindings = applied.suppressedFindings;
  const activeIds = new Set(findings.map(({ instanceId }) => instanceId));
  const suppressedIds = new Set(suppressedFindings.map(({ instanceId }) => instanceId));
  const comparisons = {} as SourceAwareFinalizedResult['comparisons'];
  for (const name of SOURCE_AWARE_COMPARISONS) {
    const comparison = input.comparisons[name];
    if (comparison.status === 'omitted' || comparison.status === 'failed') {
      comparisons[name] = { status: comparison.status, code: safeCode(comparison.code) };
      continue;
    }
    const ids = comparisonIds.get(name) ?? new Set<string>();
    comparisons[name] = {
      status: comparison.status, count: ids.size,
      active: [...ids].filter((id) => activeIds.has(id)).length,
      suppressed: [...ids].filter((id) => suppressedIds.has(id)).length,
    };
  }
  const unexpectedOmission = (['declared', 'allowed'] as const).some((name) => stages[name].status === 'omitted')
    || SOURCE_AWARE_COMPARISONS.some((name) => {
      const comparison = comparisons[name];
      return comparison.status === 'omitted' && (
        name === 'declaredAllowed' || stages.implemented.status !== 'omitted'
        || stages.implemented.code !== 'SOURCE_NOT_REQUESTED'
        || comparison.code !== 'SOURCE_NOT_REQUESTED'
      );
    });
  const codes = failureCodes(stages, comparisons, exceptionInvalid);
  if (thresholdInvalid) codes.push('CONTRACT_DIFF_FAIL_ON_INVALID');
  if (unexpectedOmission) codes.push('SOURCE_COMPARISON_UNEXPECTED_OMISSION');
  codes.sort();
  const failures = [
    ...Object.values(stages).filter(({ status }) => status === 'failed').map(({ code }) => code ?? 'SOURCE_UNKNOWN_FAILURE'),
    ...SOURCE_AWARE_COMPARISONS.flatMap((name) => {
      const comparison = comparisons[name];
      return comparison.status === 'failed' ? [comparison.code] : [];
    }),
    ...(exceptionInvalid ? ['CONTRACT_DIFF_EXCEPTIONS_INVALID'] : []),
    ...(thresholdInvalid ? ['CONTRACT_DIFF_FAIL_ON_INVALID'] : []),
    ...(unexpectedOmission ? ['SOURCE_COMPARISON_UNEXPECTED_OMISSION'] : []),
  ];
  const outcome: Outcome = failures.length === 0 ? 'ok'
    : failures.every((code) => INPUT_CODES.has(code)) ? 'input-error' : 'internal-error';
  const status = outcome !== 'ok' ? 'failed'
    : [...Object.values(stages), ...Object.values(comparisons)].some((state) => state.status === 'partial')
      ? 'partial' : 'complete';
  const severity = [...findings, ...exceptionDiagnostics];
  const reached = exceptionInvalid || thresholdInvalid ? false : contractDiffThresholdReached({
    error: severity.filter(({ severity: level }) => level === 'error').length,
    warning: severity.filter(({ severity: level }) => level === 'warning').length,
  }, options.failOn);
  return {
    target: input.target, stages, comparisons,
    ...(input.evidence.routingAssumption ? { routingAssumption: input.evidence.routingAssumption } : {}),
    ...(input.evidence.sourceVersionMetadata ? { sourceVersionMetadata: input.evidence.sourceVersionMetadata } : {}),
    findings, suppressedFindings, exceptionDiagnostics,
    appliedExceptionIds: applied.appliedExceptionIds,
    memberships: ordered.map(({ instanceId }) => ({ instanceId, comparisons: memberships.get(instanceId) ?? [] })),
    summary: { unique: ordered.length, active: findings.length,
      suppressed: suppressedFindings.length, governance: exceptionDiagnostics.length },
    analysis: { status, outcome, codes },
    threshold: { failOn: thresholdInvalid ? 'invalid' : options.failOn, reached },
    exitCode: outcome === 'input-error' ? 2 : outcome === 'internal-error' ? 3 : reached ? 1 : 0,
  };
}

function field(value: string): string {
  return redactSensitiveText(value).slice(0, MAX_PREVIEW_FIELD);
}

function decodedPreviewPath(value: string): string | undefined {
  let decoded = value;
  for (let depth = 0; depth < 3; depth += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch { return undefined; }
  }
  return /%[0-9A-Fa-f]{2}|[?#]|:\/\/[^/]*@/.test(decoded) ? undefined : decoded;
}

function evidenceUri(uri: string): string {
  const plain = uri.split(/[?#]/, 1)[0];
  const decoded = decodedPreviewPath(plain);
  if (!decoded || /^(?:[A-Za-z][A-Za-z0-9+.-]*:|[A-Za-z]:[\\/]|\/)/.test(decoded)
    || /(?:^|\/)(?:[A-Za-z][A-Za-z0-9+.-]*:\/\/|[A-Za-z]:[\\/]|[^/]+:[^/]+@)/.test(decoded)
    || decoded.split('/').includes('..')) return '[REDACTED_URI]';
  return redactEvidenceFilename(field(plain));
}

function routePath(value: string): string {
  const decoded = decodedPreviewPath(value);
  return decoded && !decoded.split('/').includes('..')
    ? redactEvidenceFilename(field(value)) : '[REDACTED_ROUTE]';
}

// Shared safe projection for bounded displays; callers must pass the full finalized result independently.
export function previewFinding(finding: SecurityFindingV1, memberships: SourceAwareComparisonName[]) {
  return {
    instanceId: finding.instanceId,
    ruleId: finding.ruleId,
    severity: finding.severity,
    ...(finding.route ? { route: {
      ...(finding.route.method ? { method: /^[A-Z]+$/.test(finding.route.method)
        ? finding.route.method : '[REDACTED_METHOD]' } : {}),
      ...(finding.route.path ? { path: routePath(finding.route.path) } : {}),
    } } : {}),
    comparisons: memberships,
    evidence: finding.evidence.slice(0, 4).map(({ source, uri }) => ({ source, uri: evidenceUri(uri) })),
    omittedEvidence: Math.max(0, finding.evidence.length - 4),
  };
}

function renderText(preview: ReturnType<typeof previewData>): string {
  const lines = [
    'Source-aware internal preview (pre-Entry)',
    `target=${preview.target} analysis=${preview.analysis.status} outcome=${preview.analysis.outcome} exit=${preview.exitCode}`,
    `threshold=${preview.threshold.failOn} reached=${preview.threshold.reached}`,
    `unique=${preview.summary.unique} active=${preview.summary.active} suppressed=${preview.summary.suppressed} governance=${preview.summary.governance}`,
  ];
  if (preview.routingAssumption) {
    if (preview.routingAssumption.globalPrefix) {
      lines.push(`routing assumption explicit globalPrefix=${preview.routingAssumption.globalPrefix}`);
    }
    if (preview.routingAssumption.sourceVersioning) {
      lines.push('routing assumption explicit sourceVersioning=uri versionPrefix=v (not bootstrap-verified)');
    }
  }
  if (preview.sourceVersionMetadata) {
    lines.push(`source version metadata AST digest=${preview.sourceVersionMetadata.digest} total=${preview.sourceVersionMetadata.total}`);
    for (const route of preview.sourceVersionMetadata.routes) {
      lines.push(route.status === 'resolved'
        ? `  version ${route.method} ${route.localPath} ${route.version} ${route.origin} -> ${route.comparisonPath}`
        : `  version unresolved ${route.reason}`);
    }
  }
  for (const [name, stage] of Object.entries(preview.stages)) {
    lines.push(`stage ${name}=${stage.status}${stage.code ? ` code=${stage.code}` : ''}`);
  }
  for (const name of SOURCE_AWARE_COMPARISONS) {
    const comparison = preview.comparisons[name];
    lines.push(`comparison ${name}=${comparison.status}${'code' in comparison ? ` code=${comparison.code}`
      : ` count=${comparison.count} active=${comparison.active} suppressed=${comparison.suppressed}`}`);
  }
  if (preview.analysis.codes.length) lines.push(`codes=${preview.analysis.codes.join(',')}`);
  lines.push(`appliedExceptionIds=${preview.appliedExceptionIds.join(',')} omittedExceptionIds=${preview.omittedExceptionIds}`);
  for (const kind of ['active', 'suppressed', 'exceptionDiagnostics'] as const) {
    for (const finding of preview.findings[kind]) {
      lines.push(`${kind} ${finding.ruleId} ${finding.severity} ${finding.route?.method ?? '-'} ${finding.route?.path ?? '-'} ${finding.instanceId}`);
      for (const evidence of finding.evidence) lines.push(`  evidence ${evidence.source}:${evidence.uri}`);
      if (finding.omittedEvidence) lines.push(`  omittedEvidence=${finding.omittedEvidence}`);
    }
  }
  lines.push(`omitted=${preview.omittedFindings}`);
  return `${lines.join('\n')}\n`;
}

function previewData(result: SourceAwareFinalizedResult) {
  const byId = new Map(result.memberships.map(({ instanceId, comparisons }) => [instanceId, comparisons]));
  const groups = {
    active: result.findings,
    suppressed: result.suppressedFindings,
    exceptionDiagnostics: result.exceptionDiagnostics,
  };
  const selected = { active: [] as ReturnType<typeof previewFinding>[],
    suppressed: [] as ReturnType<typeof previewFinding>[],
    exceptionDiagnostics: [] as ReturnType<typeof previewFinding>[] };
  let remaining = MAX_PREVIEW_FINDINGS;
  for (const kind of ['active', 'suppressed', 'exceptionDiagnostics'] as const) {
    const take = groups[kind].slice(0, remaining);
    selected[kind] = take.map((finding) => previewFinding(finding, byId.get(finding.instanceId) ?? []));
    remaining -= take.length;
  }
  const total = result.findings.length + result.suppressedFindings.length + result.exceptionDiagnostics.length;
  const make = () => ({
    preview: 'source-aware-internal-pre-entry' as const,
    target: result.target, stages: result.stages, comparisons: result.comparisons,
    ...(result.routingAssumption ? { routingAssumption: {
      ...result.routingAssumption,
      ...(result.routingAssumption.globalPrefix ? {
        globalPrefix: routePath(result.routingAssumption.globalPrefix),
      } : {}),
    } } : {}),
    ...(result.sourceVersionMetadata ? { sourceVersionMetadata: {
      digest: result.sourceVersionMetadata.digest,
      total: result.sourceVersionMetadata.routes.length,
      omitted: Math.max(0, result.sourceVersionMetadata.routes.length - 20),
      routes: result.sourceVersionMetadata.routes.slice(0, 20).map((route) => route.status === 'resolved'
        ? { status: 'resolved' as const, sourceUri: evidenceUri(route.sourceUri), line: route.line,
          method: route.method, localPath: routePath(route.localPath!), version: route.version,
          origin: route.origin, comparisonPath: routePath(route.comparisonPath!) }
        : { status: 'unresolved' as const, sourceUri: evidenceUri(route.sourceUri), line: route.line,
          reason: route.reason }),
    } } : {}),
    summary: result.summary, analysis: result.analysis, threshold: result.threshold,
    exitCode: result.exitCode,
    appliedExceptionIds: result.appliedExceptionIds.slice(0, MAX_PREVIEW_EXCEPTION_IDS),
    omittedExceptionIds: Math.max(0, result.appliedExceptionIds.length - MAX_PREVIEW_EXCEPTION_IDS),
    findings: selected, omittedFindings: total - Object.values(selected).reduce((sum, items) => sum + items.length, 0),
  });
  let preview = make();
  while ((Buffer.byteLength(JSON.stringify(preview, null, 2)) + 1 > MAX_PREVIEW_BYTES
    || Buffer.byteLength(renderText(preview)) > MAX_PREVIEW_BYTES)
    && Object.values(selected).some((items) => items.length > 0)) {
    for (const kind of ['exceptionDiagnostics', 'suppressed', 'active'] as const) {
      if (selected[kind].length > 0) { selected[kind].pop(); break; }
    }
    preview = make();
  }
  return preview;
}

export function formatSourceAwarePreviewJson(result: SourceAwareFinalizedResult): string {
  return `${JSON.stringify(previewData(result), null, 2)}\n`;
}

export function formatSourceAwarePreviewText(result: SourceAwareFinalizedResult): string {
  return renderText(previewData(result));
}
