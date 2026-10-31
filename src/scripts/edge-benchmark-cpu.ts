import assert from 'node:assert/strict';
import crypto from 'node:crypto';

export const sha = (bytes: string | Buffer) => crypto.createHash('sha256').update(bytes).digest('hex');
export function summarize(values: number[]) {
  assert.ok(values.length && values.every(value => Number.isFinite(value) && value >= 0), 'Invalid measurement samples');
  const sorted = [...values].sort((a, b) => a - b);
  return { n: sorted.length, p50: sorted[Math.ceil(sorted.length * .5) - 1], p95: sorted[Math.ceil(sorted.length * .95) - 1], p99: sorted[Math.ceil(sorted.length * .99) - 1] };
}

export type ClientPoint = { id: string; colo: string; wallMs: number };
export type CpuBinding = { scriptName: string; versionId: string; from: number; to: number };
type RecordValue = Record<string, unknown>;
function object(value: unknown): RecordValue {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value), 'Invalid provider event object');
  return value as RecordValue;
}

/** Input is the API's individual events, never Analytics reservoir quantiles. */
export function joinProviderCpu(points: ClientPoint[], events: unknown[], binding: CpuBinding) {
  assert.ok(points.length && binding.scriptName && binding.versionId && Number.isFinite(binding.from) && Number.isFinite(binding.to) && binding.from <= binding.to, 'Invalid CPU population binding');
  const wanted = new Map(points.map(point => [point.id, point]));
  assert.equal(wanted.size, points.length, 'Duplicate client ID');
  for (const point of points) assert.ok(point.id && /^(?:[A-Z]{3}|unknown)$/.test(point.colo) && Number.isFinite(point.wallMs) && point.wallMs >= 0, 'Invalid client measurement');
  const rows = new Map<string, { id: string; colo: string; cpuMs: number; wallMs: number }>();
  const unknown: string[] = [], seen = new Set<string>();
  if (points.some(point => point.colo === 'unknown')) unknown.push('Client ingress PoP unavailable');
  for (const event of events) {
    const row = object(event), worker = object(row.$workers);
    assert.equal(object(row.$metadata).type, 'cf-worker-event', 'Provider invocation log type mismatch');
    if (worker.scriptName !== binding.scriptName) throw new Error('Provider Worker binding mismatch');
    const request = object(object(worker.event).request), headers = object(request.headers);
    const id = headers['x-csf-id'];
    assert.ok(typeof id === 'string' && wanted.has(id), 'Unexpected provider request ID');
    assert.ok(!seen.has(id), 'Duplicate CPU invocation for client ID'); seen.add(id);
    assert.equal(object(worker.scriptVersion).id, binding.versionId, 'Provider version mismatch');
    assert.ok(typeof row.timestamp === 'number' && row.timestamp >= binding.from && row.timestamp <= binding.to, 'Provider interval mismatch');
    assert.equal(worker.eventType, 'fetch', 'Provider event type mismatch');
    assert.equal(worker.outcome, 'ok', 'Provider invocation failure');
    if (worker.truncated !== false || typeof worker.cpuTimeMs !== 'number' || !Number.isFinite(worker.cpuTimeMs) || worker.cpuTimeMs < 0
      || typeof worker.wallTimeMs !== 'number' || !Number.isFinite(worker.wallTimeMs) || worker.wallTimeMs < 0) {
      unknown.push('Missing/truncated CPU or wall measurement'); continue;
    }
    const colo = request.cf && object(request.cf).colo;
    if (typeof colo !== 'string' || !/^[A-Z]{3}$/.test(colo) || colo !== wanted.get(id)!.colo) { unknown.push('PoP unavailable or mismatched'); continue; }
    rows.set(id, { id, colo, cpuMs: worker.cpuTimeMs, wallMs: worker.wallTimeMs });
  }
  const missing = points.filter(point => !rows.has(point.id)).length;
  const groups = [...new Set([...rows.values()].map(row => row.colo))].map(colo => {
    const selected = [...rows.values()].filter(row => row.colo === colo);
    return { colo, cpuMs: summarize(selected.map(row => row.cpuMs)), providerWallMs: summarize(selected.map(row => row.wallMs)) };
  });
  return { status: missing || unknown.length ? 'UNKNOWN' : 'CAPTURE_COMPLETE', qualification: 'INCONCLUSIVE', expected: points.length,
    captured: rows.size, missing, diagnostics: [...new Set(unknown)], precision: 'provider-reported ms; underlying precision unverified',
    population: 'Exact client-ID population; no extras, extrapolation or quantile subtraction', groups,
    rows: [...rows.values()].map(row => ({ ...row, scriptName: binding.scriptName, versionId: binding.versionId, outcome: 'ok' as const })) };
}

export function checkBudget(observedMs: number, baselineMs: number, relativeTolerance: number, absoluteToleranceMs: number): boolean {
  assert.ok([observedMs, baselineMs, relativeTolerance, absoluteToleranceMs].every(n => Number.isFinite(n) && n >= 0), 'Invalid performance budget');
  return observedMs <= baselineMs + Math.max(baselineMs * relativeTolerance, absoluteToleranceMs);
}

/** Distribution-free 95% order-statistic interval; serial correlation still requires repeated runs. */
export function quantileInterval(values: number[], percentile: number) {
  summarize(values);
  assert.ok(percentile > 0 && percentile < 1, 'Invalid percentile');
  const n = values.length, mode = Math.floor((n + 1) * percentile), mass = new Float64Array(n + 1);
  mass[mode] = 1;
  for (let k = mode; k > 0; k--) mass[k - 1] = mass[k] * k / (n - k + 1) * (1 - percentile) / percentile;
  for (let k = mode; k < n; k++) mass[k + 1] = mass[k] * (n - k) / (k + 1) * percentile / (1 - percentile);
  const total = mass.reduce((sum, value) => sum + value, 0);
  let cumulative = 0, lower = 0, upper = n + 1;
  for (let k = 0; k <= n; k++) {
    cumulative += mass[k] / total;
    if (cumulative < .025) lower = k + 1;
    if (cumulative >= .975) { upper = k + 1; break; }
  }
  const sorted = [...values].sort((a, b) => a - b);
  return { n, percentile, confidence: .95, lowerRank: lower, upperRank: upper,
    lowerMs: lower ? sorted[lower - 1] : null, upperMs: upper <= n ? sorted[upper - 1] : null };
}

/** Per-case, per-ingress-PoP A/A controls only; passing is readiness for baseline review, never an SLO. */
export type AaPair = { run: number; caseId: string; ingressPoP: string; comparison: string;
  targetA: { variant: string; identity: string }; targetB: { variant: string; identity: string }; a: number[]; b: number[] };
export function assessAaRepeatability(pairs: AaPair[], relativeTolerance: number, absoluteToleranceMs: number) {
  checkBudget(0, 0, relativeTolerance, absoluteToleranceMs);
  assert.ok(pairs.length && new Set(pairs.map(pair => pair.run)).size === pairs.length && pairs.every(pair => Number.isSafeInteger(pair.run) && pair.run >= 0), 'Invalid A/A runs');
  const diagnostics: string[] = [];
  const first = pairs[0];
  if (pairs.some(pair => pair.caseId !== first.caseId || !pair.caseId || pair.ingressPoP !== first.ingressPoP || !/^[A-Z]{3}$/.test(pair.ingressPoP))) diagnostics.push('A/A case or ingress PoP binding missing/mixed');
  if (pairs.some(pair => pair.comparison !== 'AA' || pair.targetA.variant !== 'bare' || pair.targetB.variant !== 'bare'
    || !pair.targetA.identity || pair.targetA.identity !== pair.targetB.identity || pair.targetA.identity !== first.targetA.identity)) diagnostics.push('Both A/A arms and all runs must use the identical no-op artifact and deployment');
  if (pairs.length < 3) diagnostics.push('At least three independent runs required');
  if (pairs.some(pair => pair.a.length < 1000 || pair.b.length < 1000)) diagnostics.push('At least 1000 samples per arm, run and ingress PoP required');
  const runs = pairs.map(pair => ({ run: pair.run, a: summarize(pair.a), b: summarize(pair.b),
    intervals: [.5, .95, .99].map(p => ({ percentile: p, a: quantileInterval(pair.a, p), b: quantileInterval(pair.b, p) })) }));
  for (const quantile of ['p50', 'p95'] as const) {
    const values = runs.flatMap(run => [run.a[quantile], run.b[quantile]]);
    if (!checkBudget(Math.max(...values), Math.min(...values), relativeTolerance, absoluteToleranceMs)) diagnostics.push(quantile + ' A/A or run drift exceeds tolerance');
    for (const run of runs) for (const arm of ['a', 'b'] as const) {
      const interval = run.intervals.find(item => item.percentile === (quantile === 'p50' ? .5 : .95))![arm];
      if (interval.lowerMs === null || interval.upperMs === null || !checkBudget(interval.upperMs, interval.lowerMs, relativeTolerance, absoluteToleranceMs)) diagnostics.push(quantile + ' interval too wide');
    }
  }
  return { status: diagnostics.length ? 'INCONCLUSIVE' : 'READY_FOR_BASELINE_REVIEW', diagnostics: [...new Set(diagnostics)],
    caseId: first.caseId, ingressPoP: first.ingressPoP, targetIdentity: first.targetA.identity,
    relativeTolerance, absoluteToleranceMs, p99: 'DESCRIPTIVE_ONLY: requires separate tail and correlation qualification', runs };
}
