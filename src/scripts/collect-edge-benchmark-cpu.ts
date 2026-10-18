#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { joinProviderCpu, sha, type ClientPoint, type CpuBinding } from './edge-benchmark-cpu';
import { benchmarkCases } from './edge-benchmark-fixture';

export type CpuCapture = { status: 'COMPLETE' | 'UNKNOWN'; events: unknown[]; pages: any[]; diagnostics: string[] };

/** Three bounded read queries. No deployment, retry, aggregate fallback, or credential output. */
export async function collectCpuEvents(accountId: string, token: string, binding: CpuBinding) {
  assert.match(accountId, /^[a-f0-9]{32}$/); assert.ok(token.length > 0, 'Provider credential required');
  assert.match(binding.scriptName, /^csf-1026-[a-f0-9]+-(basic|regex|graphql|hmac|rs256|bare|gateway|origin)$/);
  assert.ok(Number.isSafeInteger(binding.from) && Number.isSafeInteger(binding.to) && binding.from >= 0 && binding.from <= binding.to, 'Invalid provider query interval');
  const capture: CpuCapture = { status: 'UNKNOWN', events: [], pages: [], diagnostics: [] };
  let offset: string | undefined, total: number | undefined;
  const seen = new Set<string>();
  for (let page = 0; page < 3; page++) {
    const query = { queryId: 'csf-1026-cpu', timeframe: { from: binding.from, to: binding.to }, view: 'events', limit: 2000,
      ...(offset ? { offset, offsetDirection: 'next' } : {}), parameters: { datasets: ['cloudflare-workers'], filterCombination: 'and',
        filters: [{ key: '$metadata.service', operation: 'eq', type: 'string', value: binding.scriptName },
          { key: '$metadata.type', operation: 'eq', type: 'string', value: 'cf-worker-event' }] } };
    const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/observability/telemetry/query`, {
      method: 'POST', headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' },
      body: JSON.stringify(query), redirect: 'error', signal: AbortSignal.timeout(15000) });
    assert.ok(response.ok, 'Provider CPU query HTTP ' + response.status);
    const body = await response.json() as any;
    assert.ok(body.success === true && !body.errors?.length && Array.isArray(body.result?.events?.events), 'Invalid provider CPU response');
    const rows = body.result.events.events;
    assert.ok(rows.length <= 2000, 'Provider event page overflow');
    // Retain the query receipt: a short page alone says nothing about sampling or completion.
    capture.pages.push(body.result); capture.events.push(...rows);
    if (body.result.run?.status !== 'COMPLETED') capture.diagnostics.push('Provider query not completed');
    const count = body.result.events.count, abr = body.result.statistics?.abr_level;
    if (!Number.isSafeInteger(count) || count < rows.length) capture.diagnostics.push('Provider population count unavailable');
    if (abr !== 1) capture.diagnostics.push('Provider ABR sampling unknown or active');
    const buckets = Array.isArray(body.result.events.series) ? body.result.events.series.flatMap((series: any) => Array.isArray(series.data) ? series.data : []) : [];
    // Ingestion sampling is independent of query ABR; preserve both receipts.
    if (count > 0 && (!buckets.length || buckets.some((bucket: any) => bucket.sampleInterval !== 1))) capture.diagnostics.push('Provider ingestion sampling unknown or active');
    if (capture.diagnostics.length) return capture;
    if (total === undefined) total = count;
    assert.equal(count, total, 'Provider population changed during pagination');
    assert.ok(capture.events.length <= total!, 'Provider population overflow');
    if (capture.events.length === total) { capture.status = 'COMPLETE'; return capture; }
    if (!rows.length) { capture.diagnostics.push('Provider page ended before population was returned'); return capture; }
    const cursor = rows.at(-1)?.$metadata?.id;
    // Only pagination uses this cursor. Measurement identity is the strict client-ID join.
    assert.ok(typeof cursor === 'string' && cursor.length && !seen.has(cursor), 'Provider pagination did not advance');
    seen.add(cursor); offset = cursor;
  }
  capture.diagnostics.push('Provider CPU query page cap reached; narrow the measurement interval');
  return capture;
}

export function joinProviderCapture(points: ClientPoint[], capture: CpuCapture, binding: CpuBinding) {
  const joined = joinProviderCpu(points, capture.events, binding);
  return { ...joined, status: capture.status === 'COMPLETE' ? joined.status : 'UNKNOWN',
    diagnostics: [...new Set([...joined.diagnostics, ...capture.diagnostics])],
    query: { status: capture.status, pages: capture.pages.length, returned: capture.events.length } };
}

export function clientPopulation(bytes: Buffer, series: string, expected: number): ClientPoint[] {
  assert.ok(Number.isSafeInteger(expected) && expected > 0, 'Invalid client population size');
  const points = bytes.toString().trim().split('\n').map(line => JSON.parse(line))
    .filter(point => point.type === 'Point' && point.metric === 'csf_wall_ms');
  assert.equal(points.length, expected, 'Client population size mismatch');
  assert.ok(points.every(point => point.data?.tags?.series === series && typeof point.data.tags.request_id === 'string'
    && point.data.tags.request_id.startsWith(series + '-')), 'Client series binding mismatch');
  return points.map(point => ({ id: point.data.tags.request_id, colo: point.data.tags.colo, wallMs: point.data.value }));
}

export function bindCpuSeries(report: any, manifest: any, series: string, scriptName: string, versionId: string) {
  assert.ok(report.topology === 'direct' && manifest.topology === 'direct', 'CPU collection requires direct target topology');
  const rows = report.series.filter((item: any) => `r${item.run}-${item.id}-${item.variant}-${item.phase}` === series);
  assert.equal(rows.length, 1, 'Exactly one client series required');
  const row = rows[0], test = benchmarkCases.find(test => test.id === row.id);
  assert.ok(test && ['bare', 'generated'].includes(row.variant) && ['AA', 'AB'].includes(row.comparison), 'Invalid measured case/arm');
  assert.equal(row.targetVariant, row.comparison === 'AA' ? 'bare' : row.variant, 'Target arm binding mismatch');
  const role = row.targetVariant === 'bare' ? 'bare' : test.profile;
  const cloud = /^https:\/\/(csf-1026-[a-f0-9]+)-gateway\.([a-z0-9-]+\.workers\.dev)$/.exec(manifest.baseUrl);
  assert.ok(cloud && scriptName === `${cloud[1]}-${role}` && manifest.targetUrls?.[role] === `https://${scriptName}.${cloud[2]}`, 'Worker role/client endpoint binding mismatch');
  assert.ok(row.phase === 'measured' && row.actual === row.expected && row.valid === row.expected && row.invalid === 0 && row.dropped === 0 && row.exit === 0, 'Successful client measurement required');
  assert.ok(versionId.length > 0, 'Provider version required');
  return { row, binding: { scriptName, versionId, from: Date.parse(row.startedAt), to: Date.parse(row.endedAt) } };
}

async function main() {
  const args = process.argv.slice(2), required = ['--directory', '--series', '--worker', '--version'];
  assert.equal(args.length, required.length * 2, 'Exactly four named arguments required');
  const value = (flag: string) => { const at = args.indexOf(flag); assert.ok(at >= 0 && args[at + 1], flag + ' required'); return args[at + 1]; };
  const directory = path.resolve(value('--directory')), series = value('--series');
  assert.match(series, /^r[0-4]-[a-z0-9-]+-(bare|generated)-measured$/);
  const root = path.resolve(__dirname, '..'); assert.ok(directory.startsWith(path.join(root, 'reports') + path.sep), 'Benchmark report directory required');
  const report = JSON.parse(fs.readFileSync(path.join(directory, 'report.json'), 'utf8'));
  const identityBytes = fs.readFileSync(path.join(directory, 'identity.json'));
  assert.equal(sha(identityBytes), report.identitySha256, 'Measurement identity changed');
  const manifestBytes = fs.readFileSync(path.join(directory, 'client.json'));
  assert.equal(sha(manifestBytes), JSON.parse(identityBytes.toString()).clientSha256, 'Client manifest changed');
  const { row, binding } = bindCpuSeries(report, JSON.parse(manifestBytes.toString()), series, value('--worker'), value('--version'));
  const pointBytes = fs.readFileSync(path.join(directory, series + '-points.jsonl'));
  assert.equal(sha(pointBytes), row.pointsSha256, 'Client point binding changed');
  const points = clientPopulation(pointBytes, series, row.expected);
  const account = process.env.CLOUDFLARE_ACCOUNT_ID || '', token = process.env.CLOUDFLARE_API_TOKEN || '';
  const capture = await collectCpuEvents(account, token, binding);
  const raw = path.join(directory, series + '-provider-private.json');
  fs.writeFileSync(raw, JSON.stringify(capture), { mode: 0o600, flag: 'wx' });
  const result = { ...joinProviderCapture(points, capture, binding), clientPointsSha256: row.pointsSha256, providerEventsSha256: sha(fs.readFileSync(raw)),
    identitySha256: sha(identityBytes), collectorArtifactSha256: sha(fs.readFileSync(__filename)), cpuHelperArtifactSha256: sha(fs.readFileSync(path.join(__dirname, 'edge-benchmark-cpu.js'))) };
  fs.writeFileSync(path.join(directory, series + '-cpu.json'), JSON.stringify(result, null, 2), { mode: 0o600, flag: 'wx' });
  console.log(JSON.stringify({ status: result.status, captured: result.captured, missing: result.missing }));
  if (result.status !== 'CAPTURE_COMPLETE') process.exitCode = 2;
}
if (require.main === module) void main().catch(error => { console.error(error instanceof Error ? error.message : 'CPU collection failed'); process.exitCode = 1; });
