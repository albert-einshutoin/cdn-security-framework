import { createHash } from 'node:crypto';

export type CloudflareEventClass = 'WAF_BLOCK_REPORTED' | 'HTTP_404_NOT_SERVED' | 'HTTP_200_REPORTED' | 'REVIEW_SENSITIVE_PATH_200' | 'UNKNOWN';
export type CloudflareRuleSource = 'custom-waf' | 'managed-waf' | 'rate-limit' | 'http' | 'unknown';
export type CloudflareEventAttribution = 'declared' | 'ambiguous' | 'unmatched' | 'unknown';
export interface CloudflareEventFixtureHeader {
  version: 1;
  scope: 'synthetic-cloudflare-events';
  sourceSha256: string | null;
  capturedAtMs: number | null;
  period: { fromMs: number | null; toMs: number | null };
  sampling: { kind: 'none' | 'sampled' | 'unknown'; rate: number | null };
  missing: Array<'events' | 'period' | 'sampling' | 'attribution' | 'rule-source'>;
}
export interface CloudflareEventFixtureRecord {
  observedAtMs: number | null;
  source: 'waf' | 'http' | 'unknown';
  action: 'block' | 'allow' | 'skip' | 'challenge' | 'log' | 'unknown';
  status: number | null;
  path: string | null;
  ruleSource: CloudflareRuleSource;
  ruleIdSha256: string | null;
  policyRouteSha256: string | null;
  attribution: CloudflareEventAttribution;
}
export interface CloudflareEventObservation {
  line: number;
  observed: Omit<CloudflareEventFixtureRecord, 'path'> & { pathSha256: string | null };
  inference: { classification: CloudflareEventClass; reasonCodes: string[]; content: 'UNKNOWN'; wafEffectiveness: 'UNKNOWN' };
}
export interface CloudflareEventReviewReport {
  version: 1;
  scope: 'synthetic-cloudflare-events';
  input: { sha256: string; bytes: number };
  provenance: CloudflareEventFixtureHeader | null;
  summary: {
    input: '[input]';
    inputStatus: 'complete' | 'partial' | 'unknown' | 'empty';
    eventCount: number;
    unknownEvents: number;
    requests: 'UNKNOWN';
    counts: Record<CloudflareEventClass, number>;
    reviewCandidates: number;
    omittedCandidates: number;
  };
  reasonCodes: string[];
  observations: CloudflareEventObservation[];
  candidates: Array<{ line: number; pathSha256: string; reason: 'SENSITIVE_PATH_200_REQUIRES_REVIEW'; content: 'UNKNOWN' }>;
  mode: 'review-only';
  automaticApply: false;
  securityVerdict: 'UNKNOWN';
}
export class CloudflareEventError extends Error {
  constructor(readonly code: string) { super(code); }
}
export const CLOUDFLARE_EVENT_MAX_BYTES = 1024 * 1024;
const classes: CloudflareEventClass[] = ['WAF_BLOCK_REPORTED', 'HTTP_404_NOT_SERVED', 'HTTP_200_REPORTED', 'REVIEW_SENSITIVE_PATH_200', 'UNKNOWN'];
const ruleSources: CloudflareRuleSource[] = ['custom-waf', 'managed-waf', 'rate-limit', 'http', 'unknown'];
const attributions: CloudflareEventAttribution[] = ['declared', 'ambiguous', 'unmatched', 'unknown'];
const missingFields: CloudflareEventFixtureHeader['missing'] = ['events', 'period', 'sampling', 'attribution', 'rule-source'];
const digest = (value: Uint8Array | string) => createHash('sha256').update(value).digest('hex');
const fail = (suffix: string): never => { throw new CloudflareEventError('ANALYZE_CLOUDFLARE_' + suffix); };
function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return fail('SHAPE_INVALID');
  return value as Record<string, unknown>;
}
function keys(value: Record<string, unknown>, expected: string[]): void {
  if (Object.keys(value).length !== expected.length || expected.some(key => !Object.prototype.hasOwnProperty.call(value, key))) fail('SHAPE_INVALID');
}
function timestamp(value: unknown): number | null {
  if (value === null) return null;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > 8_640_000_000_000_000) return fail('TIME_INVALID');
  return value;
}
function hash(value: unknown): string | null {
  if (value === null) return null;
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) return fail('IDENTITY_INVALID');
  return value;
}
function word(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-z][a-z-]{0,31}$/.test(value)) return fail('SHAPE_INVALID');
  return value;
}
function known<T extends string>(value: string, values: readonly T[], reasons: string[], reason: string): T | 'unknown' {
  if ((values as readonly string[]).includes(value)) return value as T;
  reasons.push(reason);
  return 'unknown';
}
function parse(text: string): unknown {
  try { return JSON.parse(text); } catch { return fail('JSON_INVALID'); }
}
function metadata(value: Record<string, unknown>, reasons: string[]): CloudflareEventFixtureHeader {
  keys(value, ['version', 'scope', 'sourceSha256', 'capturedAtMs', 'period', 'sampling', 'missing']);
  const period = object(value.period), sampling = object(value.sampling);
  keys(period, ['fromMs', 'toMs']); keys(sampling, ['kind', 'rate']);
  const sourceSha256 = hash(value.sourceSha256), capturedAtMs = timestamp(value.capturedAtMs);
  const fromMs = timestamp(period.fromMs), toMs = timestamp(period.toMs);
  if (fromMs !== null && toMs !== null && fromMs > toMs) fail('TIME_INVALID');
  if (capturedAtMs !== null && toMs !== null && capturedAtMs < toMs) fail('TIME_INVALID');
  const kind = known(word(sampling.kind), ['none', 'sampled', 'unknown'] as const, reasons, 'SAMPLING_UNSUPPORTED');
  const rate = sampling.rate;
  if (rate !== null && (typeof rate !== 'number' || !Number.isFinite(rate) || rate <= 0 || rate > 1)) fail('SAMPLING_INVALID');
  if (kind === 'none' && rate !== 1) fail('SAMPLING_INVALID');
  if (!Array.isArray(value.missing) || value.missing.length > missingFields.length || new Set(value.missing).size !== value.missing.length || value.missing.some(f => !missingFields.includes(f))) fail('SHAPE_INVALID');
  const missing = missingFields.filter(f => (value.missing as unknown[]).includes(f));
  if (sourceSha256 === null) reasons.push('SOURCE_MISSING');
  if (capturedAtMs === null) reasons.push('CAPTURE_TIME_MISSING');
  if (fromMs === null || toMs === null) reasons.push('PERIOD_MISSING');
  if (kind === 'unknown' || rate === null) reasons.push('SAMPLING_UNKNOWN');
  reasons.push(...missing.map(f => 'MISSING_' + f.toUpperCase().replace(/-/g, '_')));
  return { version: 1, scope: 'synthetic-cloudflare-events', sourceSha256, capturedAtMs, period: { fromMs, toMs }, sampling: { kind, rate: rate as number | null }, missing };
}
function observation(value: unknown, line: number, header: CloudflareEventFixtureHeader): CloudflareEventObservation {
  const row = object(value), reasons: string[] = [];
  keys(row, ['observedAtMs', 'source', 'action', 'status', 'path', 'ruleSource', 'ruleIdSha256', 'policyRouteSha256', 'attribution']);
  const observedAtMs = timestamp(row.observedAtMs), ruleIdSha256 = hash(row.ruleIdSha256), policyRouteSha256 = hash(row.policyRouteSha256);
  const source = known(word(row.source), ['waf', 'http', 'unknown'] as const, reasons, 'SOURCE_UNSUPPORTED');
  const action = known(word(row.action), ['block', 'allow', 'skip', 'challenge', 'log', 'unknown'] as const, reasons, 'ACTION_UNSUPPORTED');
  const ruleSource = known(word(row.ruleSource), ruleSources, reasons, 'RULE_SOURCE_UNSUPPORTED');
  const attribution = known(word(row.attribution), attributions, reasons, 'ATTRIBUTION_UNSUPPORTED');
  if (row.status !== null && (typeof row.status !== 'number' || !Number.isInteger(row.status) || row.status < 100 || row.status > 599)) fail('STATUS_INVALID');
  const status = row.status as number | null;
  let pathname: string | null = null;
  if (row.path !== null) {
    if (typeof row.path !== 'string' || !row.path.startsWith('/') || row.path.startsWith('//') || Buffer.byteLength(row.path) > 2048 || /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\\]/u.test(row.path)) fail('PATH_INVALID');
    pathname = (row.path as string).split(/[?#]/, 1)[0];
    if (!/^[\x21-\x7e]+$/.test(pathname) || /%|(?:^|\/)\.{1,2}(?:\/|$)|\/\//.test(pathname)) reasons.push('PATH_NORMALIZATION_UNKNOWN');
  }
  const pathSha256 = pathname === null ? null : digest(pathname);
  const period = header.period;
  if (observedAtMs === null || period.fromMs === null || period.toMs === null) reasons.push('EVENT_PERIOD_UNKNOWN');
  else if (observedAtMs < period.fromMs || observedAtMs > period.toMs) reasons.push('EVENT_OUTSIDE_PERIOD');
  if (attribution === 'declared') reasons.push('ATTRIBUTION_NOT_ATTESTED');
  if (attribution === 'ambiguous' || attribution === 'unknown') reasons.push('ATTRIBUTION_' + attribution.toUpperCase());
  if (attribution === 'declared' && (ruleIdSha256 === null || policyRouteSha256 === null)) reasons.push('ATTRIBUTION_INCOMPLETE');
  if (source === 'unknown') reasons.push('SOURCE_UNKNOWN');
  if (action === 'challenge' || action === 'unknown') reasons.push('ACTION_NOT_MODELED');
  if (status === null) reasons.push('STATUS_MISSING');
  if (pathname === null) reasons.push('PATH_MISSING');
  if (action === 'block' && source !== 'waf') reasons.push('ACTION_SOURCE_CONFLICT');
  let classification: CloudflareEventClass = 'UNKNOWN';
  const unsupported = reasons.some(r => r.endsWith('_UNSUPPORTED') || r === 'PATH_NORMALIZATION_UNKNOWN' || r.startsWith('EVENT_'));
  if (!unsupported && source === 'waf' && action === 'block') {
    if (!['custom-waf', 'managed-waf', 'rate-limit'].includes(ruleSource)) reasons.push('WAF_RULE_SOURCE_UNKNOWN');
    else if (status === 200) reasons.push('BLOCK_STATUS_CONFLICT');
    else { classification = 'WAF_BLOCK_REPORTED'; reasons.push('REPORTED_ACTION_NOT_EFFECT_PROOF'); }
  } else if (!unsupported && ['waf', 'http'].includes(source) && ['allow', 'skip', 'log'].includes(action)) {
    if (source === 'http' && ruleSource !== 'http' && ruleSource !== 'unknown') reasons.push('RULE_SOURCE_CONFLICT');
    else if (status === 404) { classification = 'HTTP_404_NOT_SERVED'; reasons.push('STATUS_NOT_WAF_PROOF'); }
    else if (status === 200 && pathname !== null) {
      // Only literal paths are classified; encoded/normalized routing needs separate evidence.
      const sensitive = /(?:^|\/)(?:\.git(?:\/|$)|(?:\.env|wp-config\.php|credentials|id_rsa)(?:[._~-][^/]*)?(?:\/|$))/i.test(pathname);
      classification = sensitive ? 'REVIEW_SENSITIVE_PATH_200' : 'HTTP_200_REPORTED';
      reasons.push('CONTENT_NOT_OBSERVED');
    }
  }
  if (classification === 'UNKNOWN') reasons.push('OBSERVATION_INSUFFICIENT');
  return { line, observed: { observedAtMs, source, action, status, pathSha256, ruleSource, ruleIdSha256, policyRouteSha256, attribution }, inference: { classification, reasonCodes: [...new Set(reasons)].sort(), content: 'UNKNOWN', wafEffectiveness: 'UNKNOWN' } };
}
export function reviewCloudflareEvents(input: Uint8Array, top = 20): CloudflareEventReviewReport {
  if (!Number.isSafeInteger(top) || top < 1 || top > 100) return fail('ARGUMENT_INVALID');
  if (!(input instanceof Uint8Array) || input.byteLength > CLOUDFLARE_EVENT_MAX_BYTES) return fail('SIZE_LIMIT');
  const bytes = Buffer.from(input);
  // Count raw bytes before UTF-8 decoding can remove a leading BOM.
  for (let start = 0; start <= bytes.length;) {
    const lf = bytes.indexOf(10, start);
    const end = lf === -1 ? bytes.length : lf;
    const contentEnd = lf !== -1 && end > start && bytes[end - 1] === 13 ? end - 1 : end;
    if (contentEnd - start > 8192) return fail('SIZE_LIMIT');
    if (lf === -1) break;
    start = lf + 1;
  }
  let text: string;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { return fail('UTF8_INVALID'); }
  const physicalLines = text.split(/\r?\n/);
  const lines = physicalLines.map((text, index) => ({ text, line: index + 1 })).filter(row => row.text.trim());
  if (lines.length > 1001) return fail('SIZE_LIMIT');
  const report: CloudflareEventReviewReport = {
    version: 1, scope: 'synthetic-cloudflare-events', input: { sha256: digest(bytes), bytes: bytes.length }, provenance: null,
    summary: { input: '[input]', inputStatus: 'empty', eventCount: Math.max(0, lines.length - 1), unknownEvents: 0, requests: 'UNKNOWN', counts: Object.fromEntries(classes.map(k => [k, 0])) as Record<CloudflareEventClass, number>, reviewCandidates: 0, omittedCandidates: 0 },
    reasonCodes: [], observations: [], candidates: [], mode: 'review-only', automaticApply: false, securityVerdict: 'UNKNOWN',
  };
  if (!lines.length) { report.reasonCodes.push('INPUT_EMPTY'); return report; }
  const first = object(parse(lines[0].text));
  if (first.scope !== 'synthetic-cloudflare-events') return fail('SCOPE_INVALID');
  if (typeof first.version !== 'number' || !Number.isSafeInteger(first.version) || first.version < 1) return fail('VERSION_INVALID');
  if (first.version !== 1) {
    report.summary.inputStatus = 'unknown'; report.summary.unknownEvents = report.summary.eventCount;
    report.summary.counts.UNKNOWN = report.summary.eventCount; report.reasonCodes.push('VERSION_UNSUPPORTED'); return report;
  }
  const header = metadata(first, report.reasonCodes); report.provenance = header;
  for (const row of lines.slice(1)) {
    const item = observation(parse(row.text), row.line, header);
    report.observations.push(item); report.summary.counts[item.inference.classification] += 1;
    if (item.inference.classification === 'REVIEW_SENSITIVE_PATH_200' && item.observed.pathSha256 !== null) {
      report.summary.reviewCandidates += 1;
      if (report.candidates.length < top) report.candidates.push({ line: item.line, pathSha256: item.observed.pathSha256, reason: 'SENSITIVE_PATH_200_REQUIRES_REVIEW', content: 'UNKNOWN' });
    }
  }
  report.summary.unknownEvents = report.summary.counts.UNKNOWN;
  report.summary.omittedCandidates = report.summary.reviewCandidates - report.candidates.length;
  report.summary.inputStatus = report.summary.eventCount === 0 ? 'empty'
    : report.summary.unknownEvents === report.summary.eventCount ? 'unknown'
      : report.reasonCodes.length || report.summary.unknownEvents ? 'partial' : 'complete';
  return report;
}

export function printCloudflareEventReview(report: CloudflareEventReviewReport): void {
  console.log(`[analyze] format=cloudflare-events input_status=${report.summary.inputStatus} mode=review-only`);
  console.log(`[analyze] events=${report.summary.eventCount} requests=UNKNOWN security=UNKNOWN`);
  console.log(`[analyze] counts=${JSON.stringify(report.summary.counts)} reasons=${JSON.stringify(report.reasonCodes)}`);
  const observationReasons = [...new Set(report.observations.flatMap(item => item.inference.reasonCodes))].sort();
  console.log(`[analyze] observation_reasons=${JSON.stringify(observationReasons)}`);
  console.log(`[analyze] review_candidates=${report.summary.reviewCandidates} omitted=${report.summary.omittedCandidates}`);
  for (const candidate of report.candidates) console.log(`- line=${candidate.line} path_sha256=${candidate.pathSha256} reason=${candidate.reason} content=UNKNOWN`);
}
