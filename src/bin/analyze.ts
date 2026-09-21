import fs from 'node:fs';
import path from 'node:path';
import { redactSensitiveText } from '../contract/sensitive-text';

type AnalyzeLogOptions = {
  input: string;
  minCount: number;
  top: number;
  json?: boolean;
};

type AnalyzeEvent = {
  target: string;
  policyRoute: string | null;
  method: string;
  uri: string | null;
  status: number;
  event: string;
  blockReason: string;
};

type AnalyzeCandidate = {
  policyRoute: string;
  blockReason: string;
  count: number;
  targets: string[];
  events: {
    method: string;
    status: number;
    uri: string;
    target: string;
  }[];
};

type AnalyzeSummary = {
  input: string;
  inputStatus: 'complete' | 'partial' | 'invalid' | 'empty';
  totalLines: number;
  parsedLines: number;
  unparseableLines: number;
  analyzedEvents: number;
  blockEvents: number;
  monitorEvents: number;
  lowFrequencyThreshold: number;
  top: number;
};

type AnalyzeReport = {
  summary: AnalyzeSummary;
  byBlockReason: Record<string, {
    count: number;
    targets: Record<string, number>;
    policyRoutes: Record<string, number>;
  }>;
  byPolicyRoute: Record<string, {
    count: number;
    blockReasons: Record<string, number>;
    targets: Record<string, number>;
  }>;
  candidates: AnalyzeCandidate[];
  diagnostics: { total: number; counts: Record<DiagnosticCode, number>; examples: { line: number; code: DiagnosticCode }[]; omitted: number };
};

function normalizeAnalyzeText(value: string, stripQueryHash = false): string {
  const normalized = value.trim();
  const withoutQueryHash = stripQueryHash ? normalized.split(/[?#]/, 1)[0] : normalized;
  return redactSensitiveText(withoutQueryHash)
    // Preserve escaped quotes until sensitive values have been removed.
    .replace(/\\/g, '/')
    .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, ' ')
    .trim();
}

function normalizeAnalyzeInput(cwd: string, inputPath: string): string {
  const relative = path.relative(cwd, inputPath).replace(/\\/g, '/');
  if (!relative || relative === '..' || relative.startsWith('../') || path.isAbsolute(relative)) {
    return '[external]';
  }
  return normalizeAnalyzeText(relative, true) || '[input]';
}

export const DIAGNOSTIC_CODES = [
  'ANALYZE_JSON_SYNTAX', 'ANALYZE_RECORD_TYPE', 'ANALYZE_EVENT_MISSING',
  'ANALYZE_EVENT_VALUE', 'ANALYZE_EVENT_UNKNOWN', 'ANALYZE_EVENT_ALIAS_CONFLICT',
  'ANALYZE_NESTED_MESSAGE', 'ANALYZE_FIELD_VALUE', 'ANALYZE_STATUS_VALUE',
] as const;
type DiagnosticCode = typeof DIAGNOSTIC_CODES[number];
type ParseResult = { ok: true; event: AnalyzeEvent } | { ok: false; code: DiagnosticCode };
const invalid = (code: DiagnosticCode): ParseResult => ({ ok: false, code });
const own = (value: object, key: string): boolean => Object.prototype.hasOwnProperty.call(value, key);
const isRecord = (value: unknown): value is Record<string, unknown> => (
  value !== null && typeof value === 'object' && !Array.isArray(value)
);
const EVENT_ALIASES = ['event', 'eventName', 'outcome'] as const;
const EVENTS: Readonly<Record<string, AnalyzeEvent['event']>> = Object.assign(Object.create(null), {
  allow: 'pass', pass: 'pass', passed: 'pass', block: 'block', blocked: 'block',
  monitor: 'monitor', monitoring: 'monitor', logged: 'monitor', audit: 'audit', error: 'error',
  challenge: 'challenge', challenge_report: 'challenge_report',
});
// Order is part of the diagnostic contract, independently of input key order.
const TEXT_FIELDS = {
  method: ['method', 'httpRequest.method', 'request.method'],
  uri: ['uri', 'path', 'request.uri', 'request.path', 'httpRequest.uri', 'httpRequest.path'],
  policyRoute: ['policy_route', 'policyRoute', 'route', 'request.route'],
  target: ['target', 'platform', 'provider', 'runtime'],
  blockReason: ['block_reason', 'blockReason', 'reason'],
} as const;
function field(record: Record<string, unknown>, alias: string): { value: unknown } | undefined {
  const [parent, child] = alias.split('.');
  if (!own(record, parent)) return undefined;
  if (!child) return { value: record[parent] };
  const container = record[parent];
  return isRecord(container) && own(container, child) ? { value: container[child] } : undefined;
}
function route(value: string | null): string | null {
  return value ? (value.startsWith('/') ? value : `/${value}`) : null;
}

// Internal parser boundary: never exports raw input in its result or diagnostics.
export function parseAnalyzeRecord(record: unknown): ParseResult {
  if (!isRecord(record)) return invalid('ANALYZE_RECORD_TYPE');
  const aliases = EVENT_ALIASES.filter(key => own(record, key));
  if (!aliases.length) return invalid('ANALYZE_EVENT_MISSING');
  const rawEvents = aliases.map(key => record[key]);
  if (rawEvents.some(value => typeof value !== 'string' || !value.trim())) return invalid('ANALYZE_EVENT_VALUE');
  const events = (rawEvents as string[]).map(value => EVENTS[value.trim().toLowerCase()]);
  if (events.some(value => value === undefined)) return invalid('ANALYZE_EVENT_UNKNOWN');
  if (events.some(value => value !== events[0])) return invalid('ANALYZE_EVENT_ALIAS_CONFLICT');
  for (const container of ['request', 'httpRequest']) {
    if (own(record, container) && !isRecord(record[container])) return invalid('ANALYZE_FIELD_VALUE');
  }
  const text: Record<keyof typeof TEXT_FIELDS, string | null> = {
    method: null, uri: null, policyRoute: null, target: null, blockReason: null,
  };
  let explicitPolicyRoute = false;
  for (const key of Object.keys(TEXT_FIELDS) as Array<keyof typeof TEXT_FIELDS>) {
    let selected = false;
    for (const alias of TEXT_FIELDS[key]) {
      const present = field(record, alias);
      if (!present) continue;
      if (typeof present.value !== 'string' || !present.value.trim()) return invalid('ANALYZE_FIELD_VALUE');
      if (!selected) {
        text[key] = normalizeAnalyzeText(present.value, true) || null;
        selected = true;
        if (key === 'policyRoute') explicitPolicyRoute = true;
      }
    }
  }
  let status = 0;
  let selectedStatus = false;
  for (const key of ['status', 'statusCode']) {
    if (!own(record, key)) continue;
    const value = record[key];
    const numeric = typeof value === 'number' ? value
      : typeof value === 'string' && /^[0-9]+$/.test(value.trim()) ? Number(value.trim()) : NaN;
    if (!Number.isSafeInteger(numeric) || (numeric !== 0 && (numeric < 100 || numeric > 599))) {
      return invalid('ANALYZE_STATUS_VALUE');
    }
    if (!selectedStatus) { status = numeric; selectedStatus = true; }
  }
  const uri = route(text.uri);
  return { ok: true, event: {
    event: events[0], method: text.method ?? 'UNKNOWN', uri,
    policyRoute: explicitPolicyRoute ? route(text.policyRoute) : uri, target: text.target ?? 'unknown',
    blockReason: text.blockReason ?? 'unclassified', status,
  } };
}

export function parseAnalyzeLine(line: string): ParseResult {
  let row: unknown;
  try { row = JSON.parse(line); } catch { return invalid('ANALYZE_JSON_SYNTAX'); }
  if (!isRecord(row)) return invalid('ANALYZE_RECORD_TYPE');
  if (EVENT_ALIASES.some(key => own(row, key))) return parseAnalyzeRecord(row);
  if (!own(row, 'message')) return invalid('ANALYZE_EVENT_MISSING');
  if (typeof row.message !== 'string') return invalid('ANALYZE_NESTED_MESSAGE');
  let nested: unknown;
  try { nested = JSON.parse(row.message); } catch { return invalid('ANALYZE_NESTED_MESSAGE'); }
  if (!isRecord(nested) || !EVENT_ALIASES.some(key => own(nested, key))) return invalid('ANALYZE_NESTED_MESSAGE');
  return parseAnalyzeRecord(nested);
}

export class AnalyzeError extends Error {
  constructor(readonly code: 'ANALYZE_ARGUMENT_INVALID' | 'ANALYZE_INPUT_NOT_FOUND' | 'ANALYZE_INPUT_READ_FAILED') {
    super(code);
  }
}

function buildEmptyAnalyzeReport(input: string, minCount: number, top: number): AnalyzeReport {
  return {
    summary: {
      input,
      inputStatus: 'empty',
      totalLines: 0,
      parsedLines: 0,
      unparseableLines: 0,
      analyzedEvents: 0,
      blockEvents: 0,
      monitorEvents: 0,
      lowFrequencyThreshold: minCount,
      top,
    },
    byBlockReason: Object.create(null),
    byPolicyRoute: Object.create(null),
    candidates: [],
    diagnostics: { total: 0, counts: Object.fromEntries(DIAGNOSTIC_CODES.map(code => [code, 0])) as Record<DiagnosticCode, number>, examples: [], omitted: 0 },
  };
}

function incrementCounter(map: Record<string, number>, key: string) {
  map[key] = (map[key] || 0) + 1;
}

export function runAnalyze(opts: AnalyzeLogOptions): AnalyzeReport {
  const cwd = process.cwd();
  const inputPath = opts.input
    ? path.isAbsolute(opts.input) ? opts.input : path.join(cwd, opts.input)
    : '';

  if (!inputPath) {
    throw new AnalyzeError('ANALYZE_ARGUMENT_INVALID');
  }
  if (!fs.existsSync(inputPath)) {
    throw new AnalyzeError('ANALYZE_INPUT_NOT_FOUND');
  }

  const minCount = Number(opts.minCount);
  const top = Number(opts.top);
  if (!Number.isFinite(minCount) || minCount < 1) {
    throw new AnalyzeError('ANALYZE_ARGUMENT_INVALID');
  }
  if (!Number.isFinite(top) || top < 1) {
    throw new AnalyzeError('ANALYZE_ARGUMENT_INVALID');
  }

  const report = buildEmptyAnalyzeReport(normalizeAnalyzeInput(cwd, inputPath), Math.floor(minCount), Math.floor(top));
  let text: string;
  try {
    text = fs.readFileSync(inputPath, 'utf8');
  } catch {
    throw new AnalyzeError('ANALYZE_INPUT_READ_FAILED');
  }
  const lines = text.split(/\r?\n/);
  const candidateMap: Record<string, {
    policyRoute: string;
    blockReason: string;
    count: number;
    targets: Record<string, boolean>;
    events: AnalyzeEvent[];
  }> = Object.create(null);

  for (const [index, rawLine] of lines.entries()) {
    if (!rawLine.trim()) {
      continue;
    }
    report.summary.totalLines += 1;
    const parsed = parseAnalyzeLine(rawLine);
    if (!parsed.ok) {
      report.diagnostics.total += 1;
      report.diagnostics.counts[parsed.code] += 1;
      if (report.diagnostics.examples.length < 20) report.diagnostics.examples.push({ line: index + 1, code: parsed.code });
      else report.diagnostics.omitted += 1;
      report.summary.unparseableLines += 1;
      continue;
    }
    const event = parsed.event;
    const policyRoute = event.policyRoute ?? 'unknown';
    report.summary.parsedLines += 1;
    report.summary.analyzedEvents += 1;

    const byReason = report.byBlockReason[event.blockReason] || {
      count: 0,
      targets: Object.create(null),
      policyRoutes: Object.create(null),
    };
    incrementCounter(byReason.targets, event.target);
    incrementCounter(byReason.policyRoutes, policyRoute);
    byReason.count += 1;
    report.byBlockReason[event.blockReason] = byReason;

    const byRoute = report.byPolicyRoute[policyRoute] || {
      count: 0,
      blockReasons: Object.create(null),
      targets: Object.create(null),
    };
    byRoute.count += 1;
    incrementCounter(byRoute.blockReasons, event.blockReason);
    incrementCounter(byRoute.targets, event.target);
    report.byPolicyRoute[policyRoute] = byRoute;

    const evt = event.event;
    if (evt === 'block') {
      report.summary.blockEvents += 1;
      if (event.policyRoute === null) continue;
      const key = JSON.stringify([event.blockReason, event.policyRoute]);
      const bucket = candidateMap[key] || {
        policyRoute: event.policyRoute,
        blockReason: event.blockReason,
        count: 0,
        targets: Object.create(null),
        events: [],
      };
      bucket.count += 1;
      bucket.targets[event.target] = true;
      if (bucket.events.length < report.summary.top) {
        bucket.events.push({
          method: event.method,
          status: event.status,
          uri: event.uri ?? 'unknown',
          target: event.target,
        } as AnalyzeEvent);
      }
      candidateMap[key] = bucket;
    }
    if (evt === 'monitor') {
      report.summary.monitorEvents += 1;
    }
  }

  const candidateKeys = Object.keys(candidateMap);
  report.candidates = candidateKeys
    .map((key) => {
      const bucket = candidateMap[key];
      return {
        policyRoute: bucket.policyRoute,
        blockReason: bucket.blockReason,
        count: bucket.count,
        targets: Object.keys(bucket.targets),
        events: bucket.events
          .slice(0, report.summary.top)
          .map((event: AnalyzeEvent) => ({
            method: event.method,
            status: event.status,
            uri: event.uri ?? 'unknown',
            target: event.target,
          })),
      };
    })
    .filter((entry) => entry.count <= report.summary.lowFrequencyThreshold)
    .sort((a, b) => a.count - b.count || a.policyRoute.localeCompare(b.policyRoute))
    .slice(0, report.summary.top);

  report.summary.inputStatus = report.summary.totalLines === 0 ? 'empty'
    : report.summary.parsedLines === 0 ? 'invalid'
      : report.summary.unparseableLines > 0 ? 'partial' : 'complete';
  return report;
}

export function printAnalyzeReport(report: AnalyzeReport) {
  console.log(`[analyze] input=${report.summary.input}`);
  console.log(`[analyze] input_status=${report.summary.inputStatus}`);
  console.log(`[analyze] diagnostics=${JSON.stringify(report.diagnostics)}`);
  console.log(`[analyze] total_lines=${report.summary.totalLines} parsed_lines=${report.summary.parsedLines} unparseable=${report.summary.unparseableLines}`);
  console.log(`[analyze] analyzed_events=${report.summary.analyzedEvents} block=${report.summary.blockEvents} monitor=${report.summary.monitorEvents}`);
  console.log('');

  const reasonEntries = Object.entries(report.byBlockReason)
    .map(([reason, value]) => ({ reason, count: value.count, routes: Object.entries(value.policyRoutes).length }))
    .sort((a, b) => b.count - a.count || a.reason.localeCompare(b.reason));
  const routeEntries = Object.entries(report.byPolicyRoute)
    .map(([policyRoute, value]) => ({ policyRoute, count: value.count, reasons: Object.entries(value.blockReasons).length }))
    .sort((a, b) => b.count - a.count || a.policyRoute.localeCompare(b.policyRoute));

  console.log('[analyze] Block reasons:');
  for (const item of reasonEntries) {
    console.log(`- ${item.reason}: ${item.count} events across ${item.routes} policy route(s)`);
  }
  if (reasonEntries.length === 0) {
    console.log('- none');
  }

  console.log('');
  console.log('[analyze] Top policy routes:');
  for (const item of routeEntries.slice(0, 20)) {
    console.log(`- ${item.policyRoute}: ${item.count} events (${item.reasons} block reason(s))`);
  }
  if (routeEntries.length === 0) {
    console.log('- none');
  }

  console.log('');
  if (report.candidates.length > 0) {
    console.log('[analyze] Low-frequency candidates:');
    for (const candidate of report.candidates) {
      console.log(`- route=${candidate.policyRoute} reason=${candidate.blockReason} count=${candidate.count} targets=${candidate.targets.join(',')}`);
      for (const evt of candidate.events) {
        console.log(`  sample: ${evt.method} ${evt.uri} status=${evt.status} target=${evt.target}`);
      }
    }
  } else {
    console.log('[analyze] Low-frequency candidates: none');
  }
}
