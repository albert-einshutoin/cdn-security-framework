import {
  contractDiffExitCode,
  type ContractDiffFailOn,
  type ContractDiffReportV1,
} from '../contract/contract-diff';
import type { SecurityFindingV1 } from '../contract/finding';
import { sortFindings } from '../contract/finding-order';

const TOP_FINDING_LIMIT = 10;

function cell(value: string): string {
  const normalized = value.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}|`]/gu, ' ').replace(/\s+/g, ' ').trim();
  return normalized.length > 120 ? `${normalized.slice(0, 117)}...` : normalized;
}

function route(finding: SecurityFindingV1): string {
  const method = cell(finding.route?.method ?? '');
  const path = cell((finding.route?.path ?? '').split(/[?#]/, 1)[0]);
  return method || path ? `\`${[method, path].filter(Boolean).join(' ')}\`` : '-';
}

export function renderContractDiffGitHubSummary(
  report: ContractDiffReportV1,
  options: { failOn?: ContractDiffFailOn } = {},
): string {
  const findings = sortFindings([...report.findings, ...report.exceptionDiagnostics]);
  const expired = report.exceptionDiagnostics.filter(({ ruleId }) => ruleId === 'SC-GOV-001').length;
  const categories = report.summary.byCategory;
  const top = findings.slice(0, TOP_FINDING_LIMIT);
  const remaining = findings.length - top.length;
  const lines = [
    '# CDN Security Contract Diff',
    '',
    contractDiffExitCode(report, options.failOn ?? 'error') === 1
      ? `**Gate: failing** (findings crossed the ${options.failOn ?? 'error'} threshold)`
      : '**Gate: passing**',
    ...(report.omittedComparisons.length > 0
      ? [`**Coverage warning:** ${report.omittedComparisons.length} comparison(s) omitted or unknown.`]
      : []),
    '',
    '| Error | Warning | Info | Suppressed | Expired exceptions |',
    '| ---: | ---: | ---: | ---: | ---: |',
    `| ${report.summary.error} | ${report.summary.warning} | ${report.summary.info} | ${report.summary.suppressed} | ${expired} |`,
    '',
    '## Change overview',
    '',
    '| Area | Findings |',
    '| --- | ---: |',
    `| New / removed routes | ${categories.inventory} |`,
    `| Extra / blocked methods | ${categories.exposure} |`,
    `| Authentication / authorization drift | ${categories.authentication + categories.authorization} |`,
    `| Limit / header / content-type drift | ${categories['resource-limit'] + categories.misconfiguration} |`,
    '',
    '## Top findings',
    '',
    '| Severity | Rule | Route | Finding |',
    '| --- | --- | --- | --- |',
    ...top.map((finding) => (
      `| ${finding.severity} | ${cell(finding.ruleId)} | ${route(finding)} | ${cell(finding.title)} |`
    )),
    '',
    ...(remaining > 0 ? [`${remaining} additional findings are available in the JSON and SARIF artifacts.`, ''] : []),
    'Full details: `contract-diff.json` and `cdn-security.sarif` artifacts.',
    '',
  ];
  return lines.join('\n');
}

export interface UnifiedGitHubSummaryOptions {
  maxFindings?: number;
  maxOutputBytes?: number;
}

export type UnifiedGitHubSummaryExecutionStatus = string | {
  status?: string;
  outcome?: string;
  kind?: string;
  result?: string;
  ok?: boolean;
  thresholdReached?: boolean;
  exitCode?: number;
  errorCode?: string;
  code?: string;
  phase?: string;
  safeMessage?: string;
  message?: string;
};

const UNIFIED_SUMMARY_DEFAULT_MAX_FINDINGS = 10;
const UNIFIED_SUMMARY_DEFAULT_MAX_OUTPUT_BYTES = 1_048_576;
const UNIFIED_SUMMARY_MAX_LIST_ITEMS = 32;
const UNIFIED_SUMMARY_SECRET_PATTERN = /\b(?:Bearer|Basic)\s+[^\s,;]+|\b(?:authorization|cookie|set-cookie|x-api-key|api[-_]?key|access[-_]?token|refresh[-_]?token|token|password|secret)\s*[:=]\s*["']?[^\s,"'}]+/gi;
const UNIFIED_SUMMARY_QUERY_PATTERN = /[?&][^=\s&#]+=[^&#\s]*/g;
const UNIFIED_SUMMARY_URI_PATTERN = /\b[A-Za-z][A-Za-z0-9+.-]*:[^\s|`<>()[\]]+/gi;
const UNIFIED_SUMMARY_ANY_ABSOLUTE_PATH_PATTERN = /(?:^|[\s(])\/[^\s|`<>()[\]]*/g;
const UNIFIED_SUMMARY_SYSTEM_PATH_PATTERN = /(?:^|[\s(])\/(?:Users|private|tmp|Volumes|home|etc|var|opt|usr|bin|sbin|root|workspace|workspaces|repo)(?:\/[^\s|`<>()[\]]*)?/gi;
const UNIFIED_SUMMARY_WINDOWS_PATH_PATTERN = /(?:^|[\s(])[A-Za-z]:[\\/][^\s|`<>()[\]]*/g;
const UNIFIED_SUMMARY_MARKDOWN_PATTERN = /[\\`*_{}()[\]<>#!|~]/gu;
const UNIFIED_SUMMARY_SOURCE_ORDER = ['source-ast', 'openapi', 'policy', 'generated-artifact', 'runtime'];

type UnifiedSummaryStatus = 'completed' | 'partial' | 'omitted' | 'failed';
type UnifiedSummaryResult = 'passed' | 'findings' | 'tool-error';

function unifiedSummaryCompareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function unifiedSummaryCell(value: unknown, maxLength = 160, allowApiPath = false): string {
  let normalized = typeof value === 'string' ? value : String(value ?? '');
  normalized = normalized
    .replace(UNIFIED_SUMMARY_QUERY_PATTERN, ' ')
    .replace(UNIFIED_SUMMARY_SECRET_PATTERN, ' [redacted] ')
    .replace(UNIFIED_SUMMARY_URI_PATTERN, ' [URI omitted] ')
    .replace(allowApiPath ? UNIFIED_SUMMARY_SYSTEM_PATH_PATTERN : UNIFIED_SUMMARY_ANY_ABSOLUTE_PATH_PATTERN, ' [path omitted] ')
    .replace(UNIFIED_SUMMARY_WINDOWS_PATH_PATTERN, ' [path omitted] ')
    .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, ' ')
    .replace(UNIFIED_SUMMARY_MARKDOWN_PATTERN, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return normalized.length > maxLength
    ? `${normalized.slice(0, Math.max(0, maxLength - 3))}...`
    : normalized;
}

function unifiedSummaryCode(value: unknown): string {
  const normalized = typeof value === 'string' ? value : String(value ?? '');
  return normalized.replace(/[^A-Za-z0-9_.:-]/gu, '').slice(0, 160) || 'UNSPECIFIED';
}

function unifiedSummaryCount(value: unknown): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function unifiedSummaryRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function unifiedSummaryStatus(value: unknown): UnifiedSummaryStatus | undefined {
  if (typeof value !== 'string') return undefined;
  const normalized = value.toLowerCase();
  if (normalized === 'completed' || normalized === 'complete' || normalized === 'success') return 'completed';
  if (normalized === 'partial' || normalized === 'unsupported' || normalized === 'warning-only') return 'partial';
  if (normalized === 'omitted' || normalized === 'not-requested' || normalized === 'not_evaluated'
    || normalized === 'not-evaluated' || normalized === 'unknown') return 'omitted';
  if (normalized === 'failed' || normalized === 'error') return 'failed';
  return undefined;
}

function unifiedSummaryNestedStatus(
  report: ContractDiffReportV1,
  containers: readonly string[],
  key: string,
): UnifiedSummaryStatus | undefined {
  const root = report as unknown as Record<string, unknown>;
  for (const containerName of containers) {
    const arrayContainer = root[containerName];
    if (Array.isArray(arrayContainer)) {
      for (const item of arrayContainer) {
        const record = unifiedSummaryRecord(item);
        if (!record) continue;
        const identity = record.kind ?? record.name ?? record.comparison;
        if (identity !== key) continue;
        const status = unifiedSummaryStatus(record.status);
        if (status) return status;
      }
      continue;
    }
    const container = unifiedSummaryRecord(root[containerName]);
    if (!container) continue;
    const entry = container[key] ?? container[key.replace(/-([a-z])/g, (_, letter: string) => letter.toUpperCase())];
    const status = unifiedSummaryStatus(typeof entry === 'string' ? entry : unifiedSummaryRecord(entry)?.status);
    if (status) return status;
  }
  return undefined;
}

function unifiedSummaryMarkerStatus(
  markers: readonly string[],
  terms: readonly string[],
): UnifiedSummaryStatus | undefined {
  const matching = markers.filter((item) => {
    const normalized = item.toLowerCase();
    return terms.some((term) => term === 'source'
      ? normalized.includes('source-ast') || /(?:^|[^a-z])source(?:$|[^a-z])/u.test(normalized)
      : normalized.includes(term));
  });
  if (matching.some((item) => /(?:failed|error)/u.test(item.toLowerCase()))) return 'failed';
  if (matching.some((item) => /(?:partial|unsupported|warning)/u.test(item.toLowerCase()))) return 'partial';
  if (matching.some((item) => /(?:omitted|unknown|not[-_ ]?(?:evaluated|requested))/u.test(item.toLowerCase()))) return 'omitted';
  return undefined;
}

function unifiedSummaryCapabilityStatus(values: readonly unknown[]): UnifiedSummaryStatus {
  if (values.length === 0) return 'omitted';
  const statuses = values.map(unifiedSummaryStatus).filter(
    (status): status is UnifiedSummaryStatus => status !== undefined,
  );
  if (statuses.includes('failed')) return 'failed';
  if (statuses.includes('partial')) return 'partial';
  if (statuses.length > 0 && statuses.every((status) => status === 'omitted')) return 'omitted';
  return 'completed';
}

function unifiedSummaryInputStatuses(report: ContractDiffReportV1): Record<string, UnifiedSummaryStatus> {
  const markers = report.omittedComparisons;
  const openapiCapabilities = Object.values(report.analyzerCapabilities.openapi);
  const policyCapabilities = report.analyzerCapabilities.policy.map(({ status }) => status);
  const sourceEvidence = [...report.findings, ...report.exceptionDiagnostics, ...report.suppressedFindings]
    .some((finding) => finding.evidence.some(({ source }) => source === 'source-ast'));
  const declared = unifiedSummaryNestedStatus(report, ['analyses', 'analysisStatus'], 'declared')
    ?? unifiedSummaryMarkerStatus(markers, ['declared', 'openapi'])
    ?? unifiedSummaryCapabilityStatus(openapiCapabilities);
  const implemented = unifiedSummaryNestedStatus(report, ['analyses', 'analysisStatus'], 'implemented')
    ?? unifiedSummaryMarkerStatus(markers, ['implemented', 'source'])
    ?? (sourceEvidence ? 'completed' : 'omitted');
  const allowed = unifiedSummaryNestedStatus(report, ['analyses', 'analysisStatus'], 'allowed')
    ?? unifiedSummaryMarkerStatus(markers, ['allowed', 'policy'])
    ?? unifiedSummaryCapabilityStatus(policyCapabilities);
  return { declared, implemented, allowed };
}

function unifiedSummaryComparisonStatuses(
  report: ContractDiffReportV1,
  inputs: Record<string, UnifiedSummaryStatus>,
): Record<string, UnifiedSummaryStatus> {
  const kinds = ['declared-vs-allowed', 'implemented-vs-declared', 'implemented-vs-allowed'];
  const statuses: Record<string, UnifiedSummaryStatus> = {};
  for (const kind of kinds) {
    const explicit = unifiedSummaryNestedStatus(report, ['comparisons', 'comparisonStatus'], kind);
    const marked = unifiedSummaryMarkerStatus(report.omittedComparisons, [kind]);
    if (explicit || marked) {
      statuses[kind] = explicit ?? marked!;
      continue;
    }
    if (kind === 'declared-vs-allowed') {
      statuses[kind] = inputs.declared === 'failed' || inputs.allowed === 'failed'
        ? 'failed'
        : inputs.declared === 'partial' || inputs.allowed === 'partial' ? 'partial' : 'completed';
    } else {
      statuses[kind] = inputs.implemented;
    }
  }
  return statuses;
}

function unifiedSummaryExecutionRecord(
  status: UnifiedGitHubSummaryExecutionStatus,
): Record<string, unknown> {
  return typeof status === 'string' ? { status } : unifiedSummaryRecord(status) ?? {};
}

function unifiedSummaryExecutionResult(status: UnifiedGitHubSummaryExecutionStatus): UnifiedSummaryResult {
  const record = unifiedSummaryExecutionRecord(status);
  const exitCode = record.exitCode;
  if (exitCode === 2 || exitCode === 3) return 'tool-error';
  if (exitCode === 1) return 'findings';
  if (record.ok === false) return 'tool-error';
  if (record.thresholdReached === true) return 'findings';
  const value = [record.status, record.outcome, record.kind, record.result]
    .filter((item): item is string => typeof item === 'string')
    .join(' ')
    .toLowerCase();
  if (/(?:threshold|finding|failing|gate[-_ ]?failed)/u.test(value)) return 'findings';
  if (/(?:tool|error|failed|failure|invalid|unsafe|internal|config|safety)/u.test(value)) return 'tool-error';
  return 'passed';
}

function unifiedSummaryExecutionDetail(status: UnifiedGitHubSummaryExecutionStatus): {
  code: string;
  phase?: string;
  message: string;
} {
  const record = unifiedSummaryExecutionRecord(status);
  const code = typeof record.errorCode === 'string'
    ? record.errorCode
    : typeof record.code === 'string' ? record.code : 'UNIFIED_ANALYSIS_FAILED';
  const phase = typeof record.phase === 'string' ? record.phase : undefined;
  const message = typeof record.safeMessage === 'string'
    ? record.safeMessage
    : typeof record.message === 'string' ? record.message : 'Analysis did not complete.';
  return { code, ...(phase ? { phase } : {}), message };
}

function unifiedSummarySourceKinds(finding: SecurityFindingV1): string {
  return [...new Set(finding.evidence.map(({ source }) => source))]
    .sort((left, right) => UNIFIED_SUMMARY_SOURCE_ORDER.indexOf(left) - UNIFIED_SUMMARY_SOURCE_ORDER.indexOf(right)
      || unifiedSummaryCompareText(left, right))
    .join(', ') || '-';
}

function unifiedSummaryComparisonKind(finding: SecurityFindingV1): string {
  const sources = new Set(finding.evidence.map(({ source }) => source));
  if (sources.has('source-ast') && sources.has('openapi') && sources.has('policy')) return 'three-way';
  if (sources.has('source-ast') && sources.has('openapi')) return 'implemented-vs-declared';
  if (sources.has('source-ast') && sources.has('policy')) return 'implemented-vs-allowed';
  if (sources.has('openapi') && sources.has('policy')) return 'declared-vs-allowed';
  return 'not classified';
}

function unifiedSummaryRoute(finding: SecurityFindingV1): string {
  const method = unifiedSummaryCell(finding.route?.method ?? '');
  const path = unifiedSummaryCell((finding.route?.path ?? '').split(/[?#]/, 1)[0], 160, true);
  return method || path ? `\`${[method, path].filter(Boolean).join(' ')}\`` : '-';
}

function unifiedSummaryInputDetail(name: string, status: UnifiedSummaryStatus): string {
  if (status === 'failed') return `${name} analysis failed`;
  if (status === 'partial') return `${name} analysis is partial`;
  if (status === 'omitted') return name === 'Source' ? 'Source analysis was not requested' : 'not requested';
  return `${name} contract analysis`;
}

function unifiedSummaryCapabilityLines(report: ContractDiffReportV1): string[] {
  const lines: string[] = [
    '## Capabilities and coverage',
    '',
    '| Analyzer | Capability | Status |',
    '| --- | --- | --- |',
  ];
  const entries: Array<[string, string, string]> = [
    ...Object.entries(report.analyzerCapabilities.openapi).map(([name, status]) => ['OpenAPI', name, status] as [string, string, string]),
    ...report.analyzerCapabilities.policy.map(({ id, status }) => ['Policy', id, status] as [string, string, string]),
  ].sort((left, right) => (
    unifiedSummaryCompareText(left[0], right[0])
      || unifiedSummaryCompareText(left[1], right[1])
      || unifiedSummaryCompareText(left[2], right[2])
  ));
  for (const [analyzer, name, status] of entries.slice(0, UNIFIED_SUMMARY_MAX_LIST_ITEMS)) {
    lines.push(`| ${unifiedSummaryCell(analyzer)} | ${unifiedSummaryCell(name)} | ${unifiedSummaryCell(status)} |`);
  }
  if (entries.length > UNIFIED_SUMMARY_MAX_LIST_ITEMS) {
    lines.push(`| ... | ${entries.length - UNIFIED_SUMMARY_MAX_LIST_ITEMS} more capability record(s) omitted | - |`);
  }
  if (entries.length === 0) lines.push('| - | No capability records | - |');
  lines.push('');
  const omitted = [...new Set(report.omittedComparisons)].sort();
  lines.push('Omitted or unknown comparisons: '
    + (omitted.length === 0 ? 'none.' : `${omitted.slice(0, UNIFIED_SUMMARY_MAX_LIST_ITEMS).map((item) => unifiedSummaryCell(item)).join(', ')}.`));
  if (omitted.length > UNIFIED_SUMMARY_MAX_LIST_ITEMS) {
    lines.push(`${omitted.length - UNIFIED_SUMMARY_MAX_LIST_ITEMS} additional comparison reason(s) omitted.`);
  }
  lines.push('');
  lines.push('Analyzer diagnostics:');
  const diagnostics = [...report.analyzerDiagnostics].sort((left, right) => (
    unifiedSummaryCompareText(unifiedSummaryCell(left.code), unifiedSummaryCell(right.code))
      || unifiedSummaryCompareText(unifiedSummaryCell(left.message), unifiedSummaryCell(right.message))
  ));
  if (diagnostics.length === 0) lines.push('- none');
  for (const diagnostic of diagnostics.slice(0, UNIFIED_SUMMARY_MAX_LIST_ITEMS)) {
    lines.push(`- ${unifiedSummaryCode(diagnostic.code)}: ${unifiedSummaryCell(diagnostic.message)}`);
  }
  if (diagnostics.length > UNIFIED_SUMMARY_MAX_LIST_ITEMS) {
    lines.push(`- ${diagnostics.length - UNIFIED_SUMMARY_MAX_LIST_ITEMS} additional diagnostic(s) omitted.`);
  }
  lines.push('');
  return lines;
}

function unifiedSummaryUtf8Prefix(value: string, maxBytes: number): string {
  const characters = Array.from(value);
  let low = 0;
  let high = characters.length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (Buffer.byteLength(characters.slice(0, middle).join(''), 'utf8') <= maxBytes) low = middle;
    else high = middle - 1;
  }
  return characters.slice(0, low).join('');
}

function unifiedSummaryBoundOutput(value: string, maxBytes: number): string {
  if (Buffer.byteLength(value, 'utf8') <= maxBytes) return value;
  const marker = '\n\n> Output truncated; see JSON and SARIF artifacts.\n';
  const markerBytes = Buffer.byteLength(marker, 'utf8');
  if (maxBytes <= markerBytes) return unifiedSummaryUtf8Prefix(marker, maxBytes);
  return `${unifiedSummaryUtf8Prefix(value, maxBytes - markerBytes)}${marker}`;
}

export function renderUnifiedGitHubSummary(
  report: ContractDiffReportV1 | null | undefined,
  executionStatus: UnifiedGitHubSummaryExecutionStatus = 'passed',
  options: UnifiedGitHubSummaryOptions = {},
): string {
  const maxFindings = options.maxFindings ?? UNIFIED_SUMMARY_DEFAULT_MAX_FINDINGS;
  const maxOutputBytes = options.maxOutputBytes ?? UNIFIED_SUMMARY_DEFAULT_MAX_OUTPUT_BYTES;
  if (!Number.isSafeInteger(maxFindings) || maxFindings < 0 || maxFindings > 1_000
    || !Number.isSafeInteger(maxOutputBytes) || maxOutputBytes <= 0) {
    throw new Error('GitHub summary limits are invalid.');
  }

  const executionResult = unifiedSummaryExecutionResult(executionStatus);
  if (executionResult === 'tool-error') {
    const detail = unifiedSummaryExecutionDetail(executionStatus);
    const lines = [
      '# CDN Security Contract Diff',
      '',
      '**Result: Tool Error**',
      '',
      '## Tool error',
      '',
      `- Code: \`${unifiedSummaryCode(detail.code)}\``,
      ...(detail.phase ? [`- Phase: ${unifiedSummaryCell(detail.phase)}`] : []),
      `- Message: ${unifiedSummaryCell(detail.message)}`,
      '',
      'No report was emitted because analysis did not complete.',
      '',
    ];
    return unifiedSummaryBoundOutput(lines.join('\n'), maxOutputBytes);
  }
  if (!report || typeof report !== 'object' || !report.summary
    || !report.analyzerCapabilities || !Array.isArray(report.findings)
    || !Array.isArray(report.suppressedFindings) || !Array.isArray(report.exceptionDiagnostics)
    || !Array.isArray(report.analyzerDiagnostics) || !Array.isArray(report.omittedComparisons)) {
    throw new Error('GitHub summary report is invalid.');
  }

  const inputs = unifiedSummaryInputStatuses(report);
  const comparisons = unifiedSummaryComparisonStatuses(report, inputs);
  const activeFindings = sortFindings([...report.findings, ...report.exceptionDiagnostics]);
  const top = activeFindings.slice(0, maxFindings);
  const remaining = activeFindings.length - top.length;
  const expired = report.exceptionDiagnostics.filter(({ ruleId }) => ruleId === 'SC-GOV-001').length;
  const categories = report.summary.byCategory;
  const resultLabel = executionResult === 'findings' ? 'Findings' : 'Passed';
  const inputRows: Array<[string, UnifiedSummaryStatus, string]> = [
    ['Declared (OpenAPI)', inputs.declared, unifiedSummaryInputDetail('OpenAPI', inputs.declared)],
    ['Implemented (Source)', inputs.implemented, unifiedSummaryInputDetail('Source', inputs.implemented)],
    ['Allowed (Policy)', inputs.allowed, unifiedSummaryInputDetail('Policy', inputs.allowed)],
  ];
  const comparisonRows: Array<[string, UnifiedSummaryStatus, string]> = [
    ['Declared vs Allowed', comparisons['declared-vs-allowed'], comparisons['declared-vs-allowed'] === 'omitted' ? 'not evaluated' : 'evaluated'],
    ['Implemented vs Declared', comparisons['implemented-vs-declared'], comparisons['implemented-vs-declared'] === 'omitted' ? 'not evaluated' : 'evaluated'],
    ['Implemented vs Allowed', comparisons['implemented-vs-allowed'], comparisons['implemented-vs-allowed'] === 'omitted' ? 'not evaluated' : 'evaluated'],
  ];
  const lines = [
    '# CDN Security Contract Diff',
    '',
    `**Result: ${resultLabel}**`,
    '',
    '## Analysis status',
    '',
    '| Input | Status | Details |',
    '| --- | --- | --- |',
    ...inputRows.map(([name, status, detail]) => `| ${name} | ${status} | ${detail} |`),
    '',
    '## Comparison status',
    '',
    '| Comparison | Status | Result |',
    '| --- | --- | --- |',
    ...comparisonRows.map(([name, status, detail]) => (
      `| ${name} | ${status} | ${status === 'partial' ? 'partial coverage' : status === 'failed' ? 'failed' : detail} |`
    )),
    '',
    '## Finding counts',
    '',
    '| Error | Warning | Info | Suppressed | Expired exceptions |',
    '| ---: | ---: | ---: | ---: | ---: |',
    `| ${unifiedSummaryCount(report.summary.error)} | ${unifiedSummaryCount(report.summary.warning)} | ${unifiedSummaryCount(report.summary.info)} | ${unifiedSummaryCount(report.summary.suppressed)} | ${expired} |`,
    '',
    '### By category',
    '',
    '| Area | Findings |',
    '| --- | ---: |',
    `| New / removed routes | ${unifiedSummaryCount(categories.inventory)} |`,
    `| Extra / blocked methods | ${unifiedSummaryCount(categories.exposure)} |`,
    `| Authentication / authorization drift | ${unifiedSummaryCount(categories.authentication) + unifiedSummaryCount(categories.authorization)} |`,
    `| Limit / header / content-type drift | ${unifiedSummaryCount(categories['resource-limit']) + unifiedSummaryCount(categories.misconfiguration)} |`,
    '',
    '## Top findings',
    '',
    '| Severity | Rule | Confidence | Comparison | Route | Finding | Evidence sources |',
    '| --- | --- | --- | --- | --- | --- | --- |',
    ...top.map((finding) => (
      `| ${unifiedSummaryCell(finding.severity)} | ${unifiedSummaryCell(finding.ruleId)} | ${unifiedSummaryCell(finding.confidence)} | ${unifiedSummaryCell(unifiedSummaryComparisonKind(finding))} | ${unifiedSummaryRoute(finding)} | ${unifiedSummaryCell(finding.title)} | ${unifiedSummaryCell(unifiedSummarySourceKinds(finding))} |`
    )),
    ...(top.length === 0 ? ['| - | - | - | - | - | No findings | - |'] : []),
    '',
    ...(remaining > 0 ? [`${remaining} additional findings are available in the JSON and SARIF artifacts.`, ''] : []),
    ...unifiedSummaryCapabilityLines(report),
    '## Exceptions',
    '',
    `- Suppressed findings: ${unifiedSummaryCount(report.summary.suppressed)}`,
    `- Expired exception diagnostics: ${expired}`,
    `- Applied exceptions: ${unifiedSummaryCount(report.appliedExceptionIds.length)}`,
    '',
    'Full details: `contract-diff.json` and `cdn-security.sarif` artifacts.',
    '',
  ];
  return unifiedSummaryBoundOutput(lines.join('\n'), maxOutputBytes);
}
