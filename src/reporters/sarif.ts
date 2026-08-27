import type { ContractDiffReportV1 } from '../contract/contract-diff';
import type { FindingEvidenceV1, SecurityFindingV1 } from '../contract/finding';
import { compareFindings, sortFindings } from '../contract/finding-order';

export interface SarifLog {
  version: '2.1.0';
  $schema: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      informationUri: string;
      rules: SarifRule[];
      properties: {
        analyzers: string[];
        findingSchemaVersion: number;
        reportSchemaVersion: number;
        capabilities?: {
          openapi: Record<string, string>;
          policy: Array<{ id: string; status: string }>;
        };
        omittedComparisons?: string[];
        analyzerDiagnostics?: string[];
      };
    };
  };
  results: SarifResult[];
  invocations?: SarifInvocation[];
}

interface SarifInvocation {
  executionSuccessful: boolean;
  toolExecutionNotifications: Array<{
    descriptor: { id: string };
    message: { text: string };
  }>;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string; markdown: string };
  helpUri: string;
  defaultConfiguration: { level: SarifLevel };
  properties: {
    category: string;
    confidence: string;
    tags: string[];
    evidenceSources?: string[];
    capabilities?: string[];
  };
}

interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  partialFingerprints: { 'securityContractFinding/v1': string };
  locations?: SarifLocation[];
  relatedLocations?: SarifLocation[];
  suppressions?: Array<{ kind: 'external'; status: 'accepted' }>;
  properties: {
    category: string;
    confidence: string;
    tags: string[];
    evidenceSources?: string[];
    capabilities?: string[];
  };
}

interface SarifLocation {
  id?: number;
  message?: { text: string };
  physicalLocation: {
    artifactLocation: { uri: string; uriBaseId: '%SRCROOT%' };
    region?: { startLine: number; startColumn?: number };
    properties: { source: string; digest: string; analyzer: string; capability: string; complete: boolean };
  };
  logicalLocations?: Array<{ name: string; fullyQualifiedName: string; kind: 'jsonPointer' }>;
}

type SarifLevel = 'error' | 'warning' | 'note';

const LEVELS = { error: 'error', warning: 'warning', info: 'note' } as const;
const FINDING_REFERENCE = 'https://github.com/albert-einshutoin/cdn-security-framework/blob/main/docs/finding-reference.md';

export const SARIF_ERROR_CODES = [
  'SARIF_UNIFIED_REPORT_INVALID',
  'SARIF_LOCATION_INVALID',
  'SARIF_OUTPUT_LIMIT_EXCEEDED',
  'SARIF_PRIVACY_VIOLATION',
] as const;
export type SarifReportErrorCode = typeof SARIF_ERROR_CODES[number];

export class SarifReportError extends Error {
  constructor(readonly code: SarifReportErrorCode, message: string) {
    super(`[${code}] ${message}`);
    this.name = 'SarifReportError';
  }
}

export interface UnifiedContractDiffSarifOptions {
  maxRelatedLocations?: number;
  maxResults?: number;
  maxOutputBytes?: number;
}

const DEFAULT_MAX_RELATED_LOCATIONS = 32;
const DEFAULT_MAX_RESULTS = 10_000;
const DEFAULT_MAX_OUTPUT_BYTES = 1_048_576;
const SOURCE_PRIORITY: Record<FindingEvidenceV1['source'], number> = {
  'source-ast': 0,
  openapi: 1,
  policy: 2,
  'generated-artifact': 3,
  runtime: 4,
};
const PRIMARY_SOURCE_ORDER: Record<string, readonly FindingEvidenceV1['source'][]> = {
  'SC-AUTHN-001': ['openapi', 'policy', 'source-ast'],
  'SC-AUTHN-002': ['openapi', 'policy', 'source-ast'],
  'SC-AUTHN-003': ['openapi', 'policy', 'source-ast'],
  'SC-AUTHN-004': ['openapi', 'policy', 'source-ast'],
  'SC-AUTHN-005': ['openapi', 'source-ast', 'policy'],
  'SC-AUTHN-006': ['source-ast', 'policy'],
  'SC-AUTHZ-001': ['source-ast', 'openapi', 'policy'],
  'SC-AUTHZ-002': ['source-ast', 'policy'],
  'SC-EXPOSURE-001': ['openapi', 'policy', 'source-ast'],
  'SC-EXPOSURE-002': ['openapi', 'policy'],
  'SC-EXPOSURE-003': ['policy', 'openapi'],
  'SC-EXPOSURE-004': ['source-ast', 'policy'],
  'SC-EXPOSURE-005': ['policy', 'source-ast'],
  'SC-GOV-001': ['policy'],
  'SC-GOV-002': ['policy'],
  'SC-GOV-003': ['policy'],
  'SC-INVENTORY-001': ['source-ast', 'openapi', 'policy'],
  'SC-INVENTORY-002': ['policy', 'openapi'],
  'SC-INVENTORY-003': ['openapi', 'source-ast'],
  'SC-INVENTORY-004': ['openapi', 'source-ast', 'policy'],
  'SC-INVENTORY-005': ['policy', 'source-ast'],
  'SC-LIMIT-001': ['policy', 'openapi'],
  'SC-LIMIT-002': ['policy', 'openapi'],
  'SC-REQUEST-001': ['openapi', 'policy'],
  'SC-REQUEST-002': ['policy', 'openapi'],
  'SC-REQUEST-003': ['openapi', 'policy'],
};
const UNIFIED_SECRET_PATTERN = /\b(?:Bearer|Basic)\s+(?!\[REDACTED\](?=$|[\s,;}"'&#]))[^\s,;}"']+|\b(?:authorization|cookie|set-cookie|x-api-key|api[-_]?key|access[-_]?token|refresh[-_]?token|token|password|secret)\s*[:=]\s*["']?(?!\[REDACTED\](?=$|[\s,"'}&#]))[^\s,"'}]+/i;
const UNIFIED_QUERY_PATTERN = /[?&][^=\s&#]+=(?!\[REDACTED\](?=$|[\s&#,;}"']))[^&#\s}"']*/;

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function safeUri(uri: string): string {
  const normalized = uri.trim();
  if (!normalized || normalized !== uri || normalized.includes('\\') || normalized.startsWith('/')
    || normalized.includes('?') || normalized.includes('#') || /[\u0000-\u001f\u007f]/.test(normalized)
    || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(normalized)
    || normalized.split('/').includes('..')) {
    throw new Error('SARIF evidence URI must be workspace-relative');
  }
  try {
    return normalized.split('/').map((segment) => {
      if (segment.replace(/%2e/gi, '.') === '..' || /%(?:2f|5c)/i.test(segment)) {
        throw new Error('unsafe encoded path segment');
      }
      return segment.replace(/%[0-9A-Fa-f]{2}|./gu, (value) => (
        /^%[0-9A-Fa-f]{2}$/.test(value) ? value.toUpperCase() : encodeURIComponent(value)
      ));
    }).join('/');
  } catch {
    throw new Error('SARIF evidence URI must be workspace-relative');
  }
}

function evidenceKey(evidence: FindingEvidenceV1): string {
  return [evidence.uri, evidence.pointer ?? '', evidence.source, evidence.digest].join('\u0000');
}

function location(evidence: FindingEvidenceV1, id?: number): SarifLocation {
  const pointer = evidence.pointer?.trim();
  const sourcePosition = /^line:([1-9]\d*):column:([1-9]\d*)$/u.exec(pointer ?? '');
  const startLine = Number(sourcePosition?.[1]);
  const startColumn = Number(sourcePosition?.[2]);
  const physicalPosition = sourcePosition && Number.isSafeInteger(startLine) && Number.isSafeInteger(startColumn);
  return {
    ...(id === undefined ? {} : { id }),
    ...(id === undefined ? {} : { message: { text: `${evidence.source} evidence` } }),
    physicalLocation: {
      artifactLocation: { uri: safeUri(evidence.uri), uriBaseId: '%SRCROOT%' },
      ...(physicalPosition ? {
        region: {
          startLine,
          startColumn,
        },
      } : {}),
      properties: {
        source: evidence.source,
        digest: evidence.digest,
        analyzer: evidence.analyzer,
        capability: evidence.capability,
        complete: evidence.complete,
      },
    },
    ...(pointer && !physicalPosition ? {
      logicalLocations: [{ name: pointer, fullyQualifiedName: pointer, kind: 'jsonPointer' as const }],
    } : {}),
  };
}

function rule(finding: SecurityFindingV1): SarifRule {
  const help = finding.remediation?.summary ?? finding.message;
  return {
    id: finding.ruleId,
    name: finding.ruleId.replace(/-/g, '_'),
    shortDescription: { text: finding.title },
    fullDescription: { text: finding.message },
    help: { text: help, markdown: help },
    helpUri: FINDING_REFERENCE,
    defaultConfiguration: { level: LEVELS[finding.severity] },
    properties: {
      category: finding.category,
      confidence: finding.confidence,
      tags: [...new Set(finding.tags ?? [])].sort(compareText),
    },
  };
}

function result(finding: SecurityFindingV1, suppressed: boolean): SarifResult {
  const evidence = [...finding.evidence].sort((left, right) => compareText(evidenceKey(left), evidenceKey(right)));
  return {
    ruleId: finding.ruleId,
    level: LEVELS[finding.severity],
    message: { text: finding.message },
    partialFingerprints: { 'securityContractFinding/v1': finding.instanceId },
    ...(evidence.length > 0 ? { locations: [location(evidence[0])] } : {}),
    ...(evidence.length > 1 ? {
      relatedLocations: evidence.slice(1).map((item, index) => location(item, index + 1)),
    } : {}),
    // Exception approval is external to source, so SARIF records accepted/external suppression.
    ...(suppressed ? { suppressions: [{ kind: 'external' as const, status: 'accepted' as const }] } : {}),
    properties: {
      category: finding.category,
      confidence: finding.confidence,
      tags: [...new Set(finding.tags ?? [])].sort(compareText),
    },
  };
}

export function renderFindingsAsSarif(report: ContractDiffReportV1): SarifLog {
  const findings = sortFindings([
    ...report.findings,
    ...report.exceptionDiagnostics,
    ...report.suppressedFindings,
  ]);
  const suppressedIds = new Set(report.suppressedFindings.map(({ instanceId }) => instanceId));
  const rules = new Map<string, SecurityFindingV1>();
  for (const finding of findings) if (!rules.has(finding.ruleId)) rules.set(finding.ruleId, finding);
  const analyzers = [...new Set(findings.flatMap((finding) => (
    finding.evidence.map(({ analyzer }) => analyzer)
  )))].sort(compareText);
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'cdn-security-framework',
          informationUri: FINDING_REFERENCE,
          rules: [...rules.values()].sort((left, right) => compareText(left.ruleId, right.ruleId)).map(rule),
          properties: { analyzers, findingSchemaVersion: 1, reportSchemaVersion: report.schemaVersion },
        },
      },
      results: findings.map((finding) => result(finding, suppressedIds.has(finding.instanceId))),
    }],
  };
}

function unifiedText(value: string): string {
  if (UNIFIED_SECRET_PATTERN.test(value) || UNIFIED_QUERY_PATTERN.test(value)) {
    throw new SarifReportError('SARIF_PRIVACY_VIOLATION', 'Finding text contains sensitive data.');
  }
  return value.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, (character) => (
    `\\u{${character.codePointAt(0)?.toString(16).padStart(4, '0')}}`
  ));
}

function unifiedEvidenceKey(evidence: FindingEvidenceV1): string {
  return [
    SOURCE_PRIORITY[evidence.source], evidence.uri, evidence.pointer ?? '', evidence.source,
    evidence.digest, evidence.analyzer, evidence.capability, String(evidence.complete),
  ].join('\u0000');
}

function unifiedEvidenceIdentity(evidence: FindingEvidenceV1): string {
  return [evidence.uri, evidence.pointer ?? ''].join('\u0000');
}

function canonicalJson(value: unknown, ancestors = new WeakSet<object>()): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? String(value);
  if (ancestors.has(value)) return '[circular]';
  ancestors.add(value);
  try {
    if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item, ancestors)).join(',')}]`;
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort(compareText)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key], ancestors)}`).join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}

function unifiedFindingKey(finding: SecurityFindingV1): string {
  const { evidence, tags, ...fields } = finding;
  return `${canonicalJson({ ...fields, tags: tags ? [...tags].sort(compareText) : undefined })}\u0000${unifiedEvidence(evidence).map((item) => canonicalJson(item)).join('\u0000')}`;
}

function unifiedEvidence(evidence: readonly FindingEvidenceV1[]): FindingEvidenceV1[] {
  const sorted = [...evidence].sort((left, right) => compareText(unifiedEvidenceKey(left), unifiedEvidenceKey(right)));
  const seen = new Set<string>();
  return sorted.filter((item) => {
    const identity = unifiedEvidenceIdentity(item);
    if (seen.has(identity)) return false;
    seen.add(identity);
    return true;
  });
}

function primaryEvidence(finding: SecurityFindingV1, evidence: readonly FindingEvidenceV1[]): FindingEvidenceV1 | undefined {
  const order = PRIMARY_SOURCE_ORDER[finding.ruleId];
  if (!order) {
    throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Finding rule family has no primary-source mapping.');
  }
  return order.flatMap((source) => evidence.filter((item) => item.source === source))[0] ?? evidence[0];
}

function unifiedLocation(evidence: FindingEvidenceV1, id?: number): SarifLocation {
  let uri: string;
  try {
    uri = safeUri(evidence.uri);
  } catch {
    throw new SarifReportError('SARIF_LOCATION_INVALID', 'Finding evidence URI is not workspace-relative.');
  }
  try {
    return location({
      ...evidence,
      uri,
      source: unifiedText(evidence.source) as FindingEvidenceV1['source'],
      pointer: evidence.pointer === undefined ? undefined : unifiedText(evidence.pointer),
      digest: unifiedText(evidence.digest),
      analyzer: unifiedText(evidence.analyzer),
      capability: unifiedText(evidence.capability),
    }, id);
  } catch (error: unknown) {
    if (error instanceof SarifReportError) throw error;
    throw new SarifReportError('SARIF_LOCATION_INVALID', 'Finding evidence location is invalid.');
  }
}

function unifiedRule(finding: SecurityFindingV1): SarifRule {
  const help = finding.remediation?.summary ?? finding.message;
  return {
    id: unifiedText(finding.ruleId),
    name: unifiedText(finding.ruleId.replace(/-/g, '_')),
    shortDescription: { text: unifiedText(finding.title) },
    fullDescription: { text: unifiedText(finding.message) },
    help: { text: unifiedText(help), markdown: unifiedText(help) },
    helpUri: FINDING_REFERENCE,
    defaultConfiguration: { level: LEVELS[finding.severity] },
    properties: {
      category: unifiedText(finding.category),
      confidence: unifiedText(finding.confidence),
      tags: [...new Set((finding.tags ?? []).map(unifiedText))].sort(compareText),
    },
  };
}

function unifiedResult(
  finding: SecurityFindingV1,
  suppressed: boolean,
  maxRelatedLocations: number,
): SarifResult {
  const evidence = unifiedEvidence(finding.evidence);
  const primary = primaryEvidence(finding, evidence);
  const related = evidence.filter((item) => item !== primary).slice(0, maxRelatedLocations);
  const sources = [...new Set(evidence.map(({ source }) => unifiedText(source)))].sort(compareText);
  const capabilities = [...new Set(evidence.map(({ capability }) => unifiedText(capability)))].sort(compareText);
  return {
    ruleId: unifiedText(finding.ruleId),
    level: LEVELS[finding.severity],
    message: { text: unifiedText(finding.message) },
    partialFingerprints: { 'securityContractFinding/v1': unifiedText(finding.instanceId) },
    ...(primary ? { locations: [unifiedLocation(primary)] } : {}),
    ...(related.length > 0 ? {
      relatedLocations: related.map((item, index) => unifiedLocation(item, index + 1)),
    } : {}),
    ...(suppressed ? { suppressions: [{ kind: 'external' as const, status: 'accepted' as const }] } : {}),
    properties: {
      category: unifiedText(finding.category),
      confidence: unifiedText(finding.confidence),
      tags: [...new Set((finding.tags ?? []).map(unifiedText))].sort(compareText),
      ...(sources.length > 0 ? { evidenceSources: sources } : {}),
      ...(capabilities.length > 0 ? { capabilities } : {}),
    },
  };
}

function unifiedCapabilities(report: ContractDiffReportV1): {
  openapi: Record<string, string>;
  policy: Array<{ id: string; status: string }>;
} {
  const openapi = Object.fromEntries(Object.entries(report.analyzerCapabilities.openapi)
    .sort(([left], [right]) => compareText(left, right))
    .map(([name, status]) => [unifiedText(name), unifiedText(status)]));
  const policy = [...report.analyzerCapabilities.policy]
    .sort((left, right) => compareText(left.id, right.id) || compareText(left.status, right.status))
    .map(({ id, status }) => ({ id: unifiedText(id), status: unifiedText(status) }));
  return { openapi, policy };
}

function unifiedNotification(report: ContractDiffReportV1, truncated: boolean): SarifInvocation | undefined {
  const notifications: SarifInvocation['toolExecutionNotifications'] = [];
  const capabilityStatuses = [
    ...Object.values(report.analyzerCapabilities.openapi),
    ...report.analyzerCapabilities.policy.map(({ status }) => status),
  ];
  if (capabilityStatuses.some((status) => status === 'unsupported' || status === 'partial' || status === 'warning-only')) {
    const unsupported = capabilityStatuses.some((status) => status === 'unsupported');
    notifications.push({
      descriptor: { id: unsupported ? 'SARIF_CAPABILITY_UNSUPPORTED' : 'SARIF_CAPABILITY_PARTIAL' },
      message: { text: unsupported
        ? 'One or more analyzer capabilities are unsupported.'
        : 'One or more analyzer capabilities are partial.' },
    });
  }
  const omitted = [...new Set(report.omittedComparisons)].sort(compareText);
  if (omitted.length > 0) {
    const failed = omitted.some((item) => /(?:^|:)failed(?:$|:)/u.test(item));
    notifications.push({
      descriptor: { id: failed ? 'SARIF_COMPARISON_FAILED' : 'SARIF_COMPARISON_PARTIAL' },
      message: { text: unifiedText(`${omitted.length} comparison(s) were omitted or unknown.`) },
    });
  }
  for (const diagnostic of [...report.analyzerDiagnostics].sort((left, right) => compareText(
    [left.code, left.capability ?? '', left.metric ?? '', left.message, String(left.used ?? ''), String(left.limit ?? '')].join('\u0000'),
    [right.code, right.capability ?? '', right.metric ?? '', right.message, String(right.used ?? ''), String(right.limit ?? '')].join('\u0000'),
  ))) {
    notifications.push({
      descriptor: { id: 'SARIF_ANALYZER_DIAGNOSTIC' },
      message: { text: unifiedText(`${diagnostic.code}: ${diagnostic.message}`) },
    });
  }
  if (truncated) notifications.push({
    descriptor: { id: 'SARIF_OUTPUT_TRUNCATED' },
    message: { text: 'SARIF output was bounded by the configured result/location limit.' },
  });
  return notifications.length > 0 ? { executionSuccessful: true, toolExecutionNotifications: notifications } : undefined;
}

export function renderUnifiedContractDiffSarif(
  report: ContractDiffReportV1,
  options: UnifiedContractDiffSarifOptions = {},
): SarifLog {
  if (!report || typeof report !== 'object' || !Array.isArray(report.findings)
    || !Array.isArray(report.suppressedFindings) || !Array.isArray(report.exceptionDiagnostics)) {
    throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Unified report is invalid.');
  }
  if (!options || typeof options !== 'object') {
    throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'SARIF options are invalid.');
  }
  const maxRelatedLocations = options.maxRelatedLocations ?? DEFAULT_MAX_RELATED_LOCATIONS;
  const maxResults = options.maxResults ?? DEFAULT_MAX_RESULTS;
  const maxOutputBytes = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  if (![maxRelatedLocations, maxResults, maxOutputBytes].every((value) => Number.isSafeInteger(value) && value >= 0)
    || maxOutputBytes === 0) {
    throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'SARIF limits are invalid.');
  }
  try {
    const allFindings = [
      ...report.findings,
      ...report.exceptionDiagnostics,
      ...report.suppressedFindings,
    ].sort((left, right) => (
      compareFindings(left, right) || compareText(unifiedFindingKey(left), unifiedFindingKey(right))
    ));
    const findings = allFindings.slice(0, maxResults);
    const suppressedIds = new Set(report.suppressedFindings.map(({ instanceId }) => instanceId));
    const rules = new Map<string, SecurityFindingV1>();
    for (const finding of findings) {
      const existing = rules.get(finding.ruleId);
      if (!existing || unifiedFindingKey(finding) < unifiedFindingKey(existing)) rules.set(finding.ruleId, finding);
    }
    const analyzers = [...new Set(findings.flatMap((finding) => finding.evidence.map(({ analyzer }) => unifiedText(analyzer))))]
      .sort(compareText);
    const properties = {
      analyzers,
      findingSchemaVersion: 1,
      reportSchemaVersion: report.schemaVersion,
      capabilities: unifiedCapabilities(report),
      omittedComparisons: [...new Set(report.omittedComparisons)].sort(compareText).map(unifiedText),
      analyzerDiagnostics: [...new Set(report.analyzerDiagnostics.map(({ code }) => code))].sort(compareText).map(unifiedText),
    };
    const output: SarifLog = {
      version: '2.1.0',
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      runs: [{
        tool: {
          driver: {
            name: 'cdn-security-framework',
            informationUri: FINDING_REFERENCE,
            rules: [...rules.values()]
              .sort((left, right) => compareText(left.ruleId, right.ruleId))
              .map(unifiedRule),
            properties,
          },
        },
        results: findings.map((finding) => unifiedResult(
          finding, suppressedIds.has(finding.instanceId), maxRelatedLocations,
        )),
      }],
    };
    const truncated = findings.length < allFindings.length
      || allFindings.some((finding) => unifiedEvidence(finding.evidence).length > maxRelatedLocations + 1);
    const invocation = unifiedNotification(report, truncated);
    if (invocation) output.runs[0].invocations = [invocation];
    if (Buffer.byteLength(JSON.stringify(output), 'utf8') > maxOutputBytes) {
      throw new SarifReportError('SARIF_OUTPUT_LIMIT_EXCEEDED', 'SARIF output exceeds the configured byte limit.');
    }
    return output;
  } catch (error: unknown) {
    if (error instanceof SarifReportError) throw error;
    throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Unified report could not be rendered.');
  }
}
