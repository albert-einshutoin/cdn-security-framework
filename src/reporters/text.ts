import type { AllowedCapabilityStatus } from '../contract/allowed-surface';
import type { ContractDiffReportV1 } from '../contract/contract-diff';
import type { FindingEvidenceV1, SecurityFindingV1 } from '../contract/finding';
import { sortFindings } from '../contract/finding-order';
import type { CapabilityLevelV1, SecurityContractCapabilitiesV1 } from '../contract/security-ir';

export interface UnifiedContractDiffTextOptions {
  color?: boolean;
  maxFindings?: number;
  includeSuppressed?: boolean;
  maxOutputBytes?: number;
}

const DEFAULT_MAX_OUTPUT_BYTES = 1_048_576;
const MAX_FIELD_LENGTH = 512;
const MAX_VALUE_DEPTH = 8;
const MAX_VALUE_NODES = 256;
const MAX_ARRAY_ITEMS = 32;
const MAX_OBJECT_KEYS = 32;
const SENSITIVE_KEY_PATTERN = /(?:authorization|cookie|set[-_]?cookie|api[-_]?key|access[_-]?token|refresh[_-]?token|token|secret|password)/i;

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function redactText(value: string): string {
  return value
    .replace(/([?&][^=\s&#]+)=([^&#\s]*)/g, '$1=[REDACTED]')
    .replace(/\b(authorization|cookie|set-cookie|x-api-key|api-key|access[_-]?token|refresh[_-]?token|token|password|secret)\s*[:=]\s*[^\r\n]*/gi, '$1=[REDACTED]')
    .replace(/\bBearer\s+[^\s,;]+/gi, 'Bearer [REDACTED]');
}

function terminalText(value: string): string {
  const boundedInput = value.slice(0, MAX_FIELD_LENGTH);
  const bounded = redactText(boundedInput).slice(0, MAX_FIELD_LENGTH);
  return `${bounded}${value.length > MAX_FIELD_LENGTH ? '[TRUNCATED]' : ''}`
    .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, (character) => (
      `\\u{${character.codePointAt(0)?.toString(16).padStart(4, '0')}}`
    ));
}

interface SafeValueState {
  nodes: number;
  seen: WeakSet<object>;
}

function safeValue(value: unknown, state: SafeValueState, depth: number): unknown {
  if (state.nodes >= MAX_VALUE_NODES) return '[REDACTED_NODE_LIMIT]';
  state.nodes += 1;
  if (typeof value === 'string') return terminalText(value);
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'function' || typeof value === 'symbol') return '[REDACTED_UNSUPPORTED]';
  if (typeof value === 'number' && !Number.isFinite(value)) return null;
  if (value === null || typeof value !== 'object') return value;
  if (depth >= MAX_VALUE_DEPTH) return '[REDACTED_DEPTH_LIMIT]';
  if (state.seen.has(value)) return '[REDACTED_CIRCULAR]';
  state.seen.add(value);

  if (Array.isArray(value)) {
    const output = value.slice(0, MAX_ARRAY_ITEMS).map((item) => safeValue(item, state, depth + 1));
    if (value.length > output.length) output.push('[REDACTED_ARRAY_LIMIT]');
    return output;
  }

  const output: Record<string, unknown> = {};
  let keys: string[];
  try {
    keys = Object.keys(value).sort(compareText);
  } catch {
    return '[REDACTED_UNREADABLE]';
  }
  for (const key of keys.slice(0, MAX_OBJECT_KEYS)) {
    if (SENSITIVE_KEY_PATTERN.test(key)) {
      output[terminalText(key)] = '[REDACTED]';
      continue;
    }
    try {
      output[terminalText(key)] = safeValue((value as Record<string, unknown>)[key], state, depth + 1);
    } catch {
      output[terminalText(key)] = '[REDACTED_UNREADABLE]';
    }
  }
  if (keys.length > MAX_OBJECT_KEYS) output.__truncated__ = '[REDACTED_OBJECT_LIMIT]';
  return output;
}

function safeValueText(value: unknown): string {
  try {
    return terminalText(JSON.stringify(safeValue(value, { nodes: 0, seen: new WeakSet<object>() }, 0)) ?? 'null');
  } catch {
    return '[REDACTED_UNSERIALIZABLE]';
  }
}

function positiveInteger(value: number | undefined, name: string, allowZero = false): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || (allowZero ? value < 0 : value <= 0)) {
    throw new Error(`${name} must be ${allowZero ? 'a non-negative' : 'a positive'} safe integer`);
  }
  return value;
}

function capabilityAggregate(
  capabilities: readonly (CapabilityLevelV1 | AllowedCapabilityStatus)[],
): 'complete' | 'partial' | 'unsupported' {
  if (capabilities.some((status) => status === 'unsupported')) return 'unsupported';
  if (capabilities.some((status) => status !== 'complete' && status !== 'supported')) return 'partial';
  return 'complete';
}

function capabilityCounts(capabilities: readonly string[]): string {
  const counts = { complete: 0, partial: 0, unsupported: 0, supported: 0, 'warning-only': 0 };
  for (const status of capabilities) if (status in counts) counts[status as keyof typeof counts] += 1;
  return Object.entries(counts)
    .filter(([, count]) => count > 0)
    .map(([status, count]) => `${status}=${count}`)
    .join(' ');
}

function* capabilityLines(report: ContractDiffReportV1): Generator<string> {
  const openapiEntries = Object.entries(report.analyzerCapabilities.openapi) as Array<
    [keyof SecurityContractCapabilitiesV1, CapabilityLevelV1]
  >;
  const policyEntries = [...report.analyzerCapabilities.policy]
    .sort((left, right) => compareText(left.id, right.id));
  const openapiStatus = capabilityAggregate(openapiEntries.map(([, status]) => status));
  const policyStatus = capabilityAggregate(policyEntries.map(({ status }) => status));
  yield 'Capabilities:';
  yield `  OpenAPI: ${openapiStatus} (${capabilityCounts(openapiEntries.map(([, status]) => status)) || 'none'})`;
  yield `  Policy: ${policyStatus} (${capabilityCounts(policyEntries.map(({ status }) => status)) || 'none'})`;
  for (const [name, status] of openapiEntries.sort(([left], [right]) => compareText(left, right))) {
    if (status === 'complete') continue;
    yield `    openapi.${name}: ${status} (${status === 'unsupported' ? 'not evaluated' : 'partial coverage'})`;
  }
  for (const { id, status } of policyEntries) {
    if (status === 'supported') continue;
    const reason = status === 'unsupported' ? 'not evaluated' : status === 'warning-only' ? 'warning-only' : 'partial coverage';
    yield `    policy.${terminalText(id)}: ${status} (${reason})`;
  }
}

function sortedDiagnostics(report: ContractDiffReportV1): ContractDiffReportV1['analyzerDiagnostics'] {
  return [...report.analyzerDiagnostics].sort((left, right) => compareText(
    [left.code, left.capability ?? '', left.metric ?? '', left.message].join('\u0000'),
    [right.code, right.capability ?? '', right.metric ?? '', right.message].join('\u0000'),
  ));
}

function diagnosticText(diagnostic: ContractDiffReportV1['analyzerDiagnostics'][number]): string {
  const scope = diagnostic.capability ?? diagnostic.metric ?? 'analysis';
  return `  ${terminalText(diagnostic.level.toUpperCase())} ${terminalText(diagnostic.code)} ${terminalText(scope)}: ${terminalText(diagnostic.message)}`;
}

function evidenceText(evidence: FindingEvidenceV1): string {
  const rawUri = evidence.uri.split(/[?#]/, 1)[0];
  const uri = /^(?:[A-Za-z][A-Za-z0-9+.-]*:|[A-Za-z]:[\\/]|\/)/u.test(rawUri)
    ? '[external]'
    : terminalText(rawUri);
  const pointer = evidence.pointer ? terminalText(evidence.pointer) : '';
  return `${uri}${pointer ? `#${pointer}` : ''}`;
}

function compareEvidence(left: FindingEvidenceV1, right: FindingEvidenceV1): number {
  return compareText(
    [left.source, left.uri, left.pointer ?? '', left.digest, left.analyzer, left.capability, String(left.complete)].join('\u0000'),
    [right.source, right.uri, right.pointer ?? '', right.digest, right.analyzer, right.capability, String(right.complete)].join('\u0000'),
  );
}

function boundedEvidence(evidence: readonly FindingEvidenceV1[]): FindingEvidenceV1[] {
  const selected: FindingEvidenceV1[] = [];
  for (const item of evidence) {
    let index = 0;
    while (index < selected.length && compareEvidence(selected[index], item) <= 0) index += 1;
    if (index >= MAX_ARRAY_ITEMS && selected.length >= MAX_ARRAY_ITEMS) continue;
    selected.splice(index, 0, item);
    if (selected.length > MAX_ARRAY_ITEMS) selected.pop();
  }
  return selected;
}

function routeText(finding: SecurityFindingV1): string {
  if (!finding.route) return '-';
  const method = terminalText(finding.route.method ?? '');
  const routePath = terminalText((finding.route.path ?? '').split(/[?#]/, 1)[0]);
  const operation = terminalText(finding.route.operationId ?? '');
  return [method, routePath].filter(Boolean).join(' ') || operation || '-';
}

function findingLines(finding: SecurityFindingV1, color: boolean): string[] {
  const labels = {
    error: '\u001b[31mERROR\u001b[0m',
    warning: '\u001b[33mWARNING\u001b[0m',
    info: '\u001b[36mINFO\u001b[0m',
  } as const;
  const label = color ? labels[finding.severity] : finding.severity.toUpperCase();
  return [
    `${label} ${terminalText(finding.ruleId)} [${terminalText(finding.confidence)}] ${routeText(finding)} ${terminalText(finding.title)}`,
    `  message=${terminalText(finding.message)}`,
    ...(finding.expected === undefined ? [] : [`  expected=${safeValueText(finding.expected)}`]),
    ...(finding.actual === undefined ? [] : [`  actual=${safeValueText(finding.actual)}`]),
    ...boundedEvidence(finding.evidence)
      .map((evidence) => `  evidence=${evidenceText(evidence)}`),
    ...(finding.evidence.length > MAX_ARRAY_ITEMS ? ['  evidence=[TRUNCATED]'] : []),
    ...(finding.remediation ? [`  remediation=${terminalText(finding.remediation.summary)}`] : []),
  ];
}

type AppendLine = (line: string) => boolean;

function appendFindingSection(
  appendLine: AppendLine,
  title: string,
  findings: readonly SecurityFindingV1[],
  color: boolean,
  maxFindings: number | undefined,
  includeTitle = true,
): boolean {
  if (includeTitle && !appendLine(title)) return false;
  const displayedCount = maxFindings === undefined ? findings.length : Math.min(findings.length, maxFindings);
  const omitted = findings.length - displayedCount;
  if (!appendLine(`  evaluated=${findings.length}${findings.length === 0 ? ' (no findings)' : ''}`)) return false;
  if (omitted > 0 && !appendLine(`  ${omitted} additional finding(s) omitted by maxFindings.`)) return false;
  for (let index = 0; index < displayedCount; index += 1) {
    for (const line of findingLines(findings[index], color)) {
      if (!appendLine(line)) return false;
    }
  }
  return displayedCount > 0 || appendLine('  (none)');
}

function byteLength(value: string): number {
  return Buffer.byteLength(value, 'utf8');
}

function truncateOutput(value: string, maxBytes: number): string {
  if (byteLength(value) <= maxBytes) return value;
  const marker = `\n[output truncated at ${maxBytes} bytes]\n`;
  const budget = Math.max(0, maxBytes - byteLength(marker));
  let bytes = 0;
  let prefix = '';
  for (let index = 0; index < value.length;) {
    const codePoint = value.codePointAt(index);
    if (codePoint === undefined) break;
    const character = String.fromCodePoint(codePoint);
    const size = byteLength(character);
    if (bytes + size > budget) break;
    prefix += character;
    bytes += size;
    index += character.length;
  }
  const output = `${prefix}${marker}`;
  if (byteLength(output) <= maxBytes) return output;
  return Buffer.from(output, 'utf8').subarray(0, maxBytes).toString('utf8');
}

function renderBoundedText(
  maxBytes: number,
  render: (appendLine: AppendLine) => void,
): string {
  const marker = `\n[output truncated at ${maxBytes} bytes]\n`;
  const budget = Math.max(0, maxBytes - byteLength(marker));
  const chunks: string[] = [];
  let bytes = 0;
  let truncated = false;
  const appendLine: AppendLine = (line) => {
    if (truncated) return false;
    const chunk = `${line}\n`;
    if (bytes + byteLength(chunk) > budget) {
      truncated = true;
      return false;
    }
    chunks.push(chunk);
    bytes += byteLength(chunk);
    return true;
  };
  render(appendLine);
  const output = chunks.join('');
  return truncated ? truncateOutput(`${output}${marker}`, maxBytes) : output;
}

export function renderUnifiedContractDiffText(
  report: ContractDiffReportV1,
  options: UnifiedContractDiffTextOptions = {},
): string {
  if (!report || typeof report !== 'object') throw new Error('Contract diff report is required.');
  const maxFindings = positiveInteger(options.maxFindings, 'maxFindings', true);
  const maxOutputBytes = positiveInteger(options.maxOutputBytes, 'maxOutputBytes') ?? DEFAULT_MAX_OUTPUT_BYTES;
  const color = options.color === true;
  const omittedComparisons = [...new Set(report.omittedComparisons)].sort(compareText);
  const activeFindings = sortFindings(report.findings);
  const diagnostics = sortFindings(report.exceptionDiagnostics);
  const analyzerDiagnostics = sortedDiagnostics(report);
  const includeSuppressed = options.includeSuppressed ?? report.suppressedFindings.length > 0;
  return renderBoundedText(maxOutputBytes, (appendLine) => {
    if (!appendLine(`Summary: total=${report.summary.total} error=${report.summary.error}`
      + ` warning=${report.summary.warning} info=${report.summary.info}`
      + ` suppressed=${report.summary.suppressed}`)) return;
    if (!appendLine(`Target: ${terminalText(report.target)}`)
      || !appendLine(`OpenAPI digest: ${terminalText(report.inputDigests.openapi)}`)
      || !appendLine(`Policy digest: ${terminalText(report.inputDigests.policy)}`)
      || !appendLine(`Exceptions digest: ${terminalText(report.inputDigests.exceptions ?? 'none')}`)
      || !appendLine(`Omitted/unknown comparisons: ${omittedComparisons.length || 'none'}`)) return;
    for (const comparison of omittedComparisons) if (!appendLine(`  ${terminalText(comparison)}`)) return;
    if (!appendLine('Input analysis:')
      || !appendLine('  declared: analyzed (OpenAPI)')
      || !appendLine('  implemented: not requested (source input is absent)')
      || !appendLine('  allowed: analyzed (Policy)')
      || !appendLine(`  Exception input: ${report.inputDigests.exceptions ? 'analyzed' : 'not requested'}`)
      || !appendLine('Comparison:')
      || !appendLine(`  status: ${omittedComparisons.length > 0 ? 'partial' : 'completed'}`)
      || !appendLine(`  evaluated findings: ${report.summary.total}`)
      || !appendLine(`  not evaluated: ${omittedComparisons.length > 0 ? `${omittedComparisons.length} comparison(s); absence of findings is not proof of no drift` : 'none'}`)) return;
    for (const line of capabilityLines(report)) if (!appendLine(line)) return;
    if (!appendLine('Analysis diagnostics:')) return;
    if (analyzerDiagnostics.length === 0) {
      if (!appendLine('  none')) return;
    } else {
      for (const diagnostic of analyzerDiagnostics) if (!appendLine(diagnosticText(diagnostic))) return;
    }
    if (!appendFindingSection(appendLine, 'Findings:', activeFindings, color, maxFindings)) return;
    if (includeSuppressed) {
      if (!appendLine('Suppressed findings:')
        || !appendFindingSection(appendLine, '', sortFindings(report.suppressedFindings), color, maxFindings, false)) return;
    }
    if (diagnostics.length > 0) {
      if (!appendLine('Exception/governance diagnostics:')
        || !appendFindingSection(appendLine, '', diagnostics, color, maxFindings, false)) return;
    }
    if (!appendLine('Limitations:')) return;
    if (omittedComparisons.length > 0 && !appendLine(`  ${omittedComparisons.length} comparison(s) were omitted or are unknown.`)) return;
    if (analyzerDiagnostics.length > 0 && !appendLine(`  ${analyzerDiagnostics.length} analyzer diagnostic(s) require attention.`)) return;
    if (omittedComparisons.length === 0 && analyzerDiagnostics.length === 0 && !appendLine('  none reported')) return;
  });
}
