#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import vm from 'node:vm';
import { transformSync } from 'esbuild';
import { gateway, origin, createDirectTarget, readFixtureBody, type FixtureEnv, benchmarkCases } from './edge-benchmark-fixture';
import { joinProviderCpu, checkBudget, quantileInterval, assessAaRepeatability } from './edge-benchmark-cpu';
import { runK6Series, prepareBenchmark } from './benchmark-edge-k6';
import { collectCpuEvents, joinProviderCapture, clientPopulation, bindCpuSeries } from './collect-edge-benchmark-cpu';

async function main() {
  // Node lacks the Workers native stream. This test double models its byte
  // contract; the workerd integration run also exercises the real implementation.
  Object.assign(globalThis, { FixedLengthStream: class extends TransformStream<Uint8Array, Uint8Array> {
    constructor(length: number) {
      let received = 0;
      super({ transform(chunk, controller) {
        received += chunk.byteLength;
        if (received > length) throw new TypeError('Attempt to write too many bytes through a FixedLengthStream.');
        controller.enqueue(chunk);
      }, flush() {
        if (received !== length) throw new TypeError('FixedLengthStream did not see all expected bytes before close().');
      } });
    }
  } });
  let forwarded = 0;
  const service = { async fetch(request: Request) { forwarded++; return new Response(await request.arrayBuffer()); } };
  const env = { EXPIRES: String(Date.now() + 60000), PROBE_KEY: 'x'.repeat(32), ORIGIN: 'https://origin.example',
    BASIC: service, REGEX: service, GRAPHQL: service, HMAC: service, RS256: service, BARE: service } as FixtureEnv;
  const request = (body: BodyInit | null, target = '/hmac/bare', headers = {}) => new Request('https://gateway.example' + target, {
    method: 'POST', body, headers: { 'x-csf-key': env.PROBE_KEY, 'x-csf-id': 'test-1', ...headers }, duplex: 'half',
  } as RequestInit);
  const full = 'x'.repeat(1048576);
  assert.equal((await gateway.fetch(request(full), env)).status, 200);
  assert.equal(forwarded, 1);
  assert.equal(await (await gateway.fetch(request(full), env)).text(), full, 'Body bytes must survive gateway');
  for (const [body, status] of [[full + 'x', 413], [full.slice(1), 400], [null, 400]] as const) {
    const before: number = forwarded;
    assert.equal((await gateway.fetch(request(body), env)).status, status);
    assert.equal(forwarded, before, 'Invalid body must not reach target');
  }
  let cancelled = false, sent = 0;
  const oversized = new ReadableStream<Uint8Array>({ pull(controller) { sent++; controller.enqueue(new Uint8Array(65536)); }, cancel() { cancelled = true; } });
  assert.equal((await gateway.fetch(request(oversized), env)).status, 413);
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.ok(cancelled && sent < 25, 'Unknown-length overflow must cancel bounded input');
  assert.equal((await gateway.fetch(request(full, '/hmac/bare', { 'x-csf-key': 'wrong' }), env)).status, 403);
  assert.equal((await gateway.fetch(request(full), { ...env, EXPIRES: 'NaN' })).status, 410);
  assert.equal((await gateway.fetch(request(full), { ...env, EXPIRES: '0' })).status, 410);
  for (const target of ['/constructor/bare', '/hmac/generated/extra', '/hmac/bare?unknown=1']) assert.equal((await gateway.fetch(request(full, target), env)).status, 404);
  const chunks = new ReadableStream<Uint8Array>({ start(controller) { for (const text of ['ab', 'c', 'def']) controller.enqueue(new TextEncoder().encode(text)); controller.close(); } });
  assert.equal(new TextDecoder().decode(await readFixtureBody(request(chunks), 6)), 'abcdef');
  const inputFailure = new Error('Synthetic body transport failure');
  await assert.rejects(readFixtureBody(request(new ReadableStream({ start(controller) { controller.error(inputFailure); } })), 6), error => error === inputFailure);
  assert.equal(benchmarkCases.length, 9);
  const direct = createDirectTarget(service, 'hmac');
  const ingress = request(full, '/hmac/generated');
  Object.defineProperty(ingress, 'cf', { value: { colo: 'KIX' } });
  const directResponse = await direct.fetch(ingress, env);
  assert.equal(await directResponse.text(), full, 'Direct path must preserve the 1 MiB body');
  assert.equal(directResponse.headers.get('x-csf-ingress-colo'), 'KIX', 'PoP must come from the public invocation');
  assert.equal((await direct.fetch(request(full, '/hmac/generated'), { ...env, CSF_VERSION_METADATA: { id: 'provider-version' } })).headers.get('x-csf-version'), 'provider-version');
  const jwks = await origin.fetch(new Request('https://origin.example/jwks'), { ...env, PUBLIC_JWKS: '{"keys":[]}', CSF_VERSION_METADATA: { id: 'origin-version' } });
  assert.equal(jwks.headers.get('x-csf-version'), 'origin-version');
  const directBefore = forwarded;
  assert.equal((await direct.fetch(request(full, '/hmac/bare'), env)).status, 404);
  assert.equal((await direct.fetch(request(full, '/hmac/generated', { 'x-csf-key': 'wrong' }), env)).status, 403);
  assert.equal((await direct.fetch(request(full, '/hmac/generated'), { ...env, EXPIRES: '0' })).status, 410);
  assert.equal((await direct.fetch(request(full + 'x', '/hmac/generated'), env)).status, 413);
  assert.equal(forwarded, directBefore, 'Rejected direct requests must not invoke the generated handler');
  assert.throws(() => createDirectTarget(service, 'production'), /Unknown direct/);

  const points = [{ id: 'a', colo: 'KIX', wallMs: 20 }, { id: 'b', colo: 'PDX', wallMs: 130 }];
  const binding = { scriptName: 'fixture', versionId: 'version', from: 1, to: 100 };
  const event = (id: string, colo: string) => ({ timestamp: 10, $metadata: { type: 'cf-worker-event' }, $workers: { scriptName: 'fixture', scriptVersion: { id: 'version' },
    eventType: 'fetch', outcome: 'ok', truncated: false, cpuTimeMs: 2, wallTimeMs: 4, event: { request: { cf: { colo }, headers: { 'x-csf-id': id } } } } });
  const events = [event('a', 'KIX'), event('b', 'PDX')];
  const captured = joinProviderCpu(points, events, binding);
  assert.equal(captured.status, 'CAPTURE_COMPLETE'); assert.equal(captured.qualification, 'INCONCLUSIVE'); assert.equal(captured.groups.length, 2);
  assert.deepEqual(captured.rows.map(row => [row.id, row.colo, row.cpuMs, row.versionId, row.outcome]),
    [['a', 'KIX', 2, 'version', 'ok'], ['b', 'PDX', 2, 'version', 'ok']]);
  assert.equal(joinProviderCpu(points, events.slice(1), binding).status, 'UNKNOWN');
  assert.equal(joinProviderCpu(points, [], binding).missing, 2);
  const unknownPoP = [{ ...points[0], colo: 'unknown' }];
  assert.equal(joinProviderCpu(unknownPoP, [events[0]], binding).status, 'UNKNOWN');
  assert.equal(joinProviderCpu(unknownPoP, [event('a', 'unknown')], binding).captured, 0, 'Matching unknown sentinels are never captured PoP evidence');
  const noCpu: any = event('a', 'KIX'); delete noCpu.$workers.cpuTimeMs;
  assert.equal(joinProviderCpu(points, [noCpu], binding).status, 'UNKNOWN');
  assert.throws(() => joinProviderCpu(points, [noCpu, noCpu], binding), /Duplicate CPU/, 'Unknown rows must still reject duplicate invocations');
  assert.equal(joinProviderCpu(points, [event('a', 'PDX')], binding).status, 'UNKNOWN');
  assert.throws(() => joinProviderCpu(points, [events[0], events[0]], binding), /Duplicate CPU/);
  assert.throws(() => joinProviderCpu(points, events, { ...binding, versionId: 'other' }), /version mismatch/);
  assert.throws(() => joinProviderCpu(points, events, { ...binding, from: 20 }), /interval mismatch/);
  assert.throws(() => joinProviderCpu([...points, points[0]], events, binding), /Duplicate client/);
  assert.throws(() => joinProviderCpu(points, [...events, event('unexpected', 'KIX')], binding), /Unexpected provider request ID/,
    'A complete intersection must not hide extra invocations');
  const missingId = event('a', 'KIX'); delete (missingId.$workers.event.request.headers as any)['x-csf-id'];
  assert.throws(() => joinProviderCpu(points, [...events, missingId], binding), /Unexpected provider request ID/);
  assert.throws(() => joinProviderCpu(points, events, { ...binding, to: Infinity }), /Invalid CPU population/);
  const failed = event('a', 'KIX'); failed.$workers.outcome = 'exceededCpu';
  assert.throws(() => joinProviderCpu(points, [failed], binding), /invocation failure/);
  assert.ok(checkBudget(1.1, 1, .05, .2)); assert.ok(!checkBudget(1.3, 1, .05, .2));
  assert.throws(() => checkBudget(NaN, 1, .05, .2), /Invalid performance budget/);
  const ordered = Array.from({ length: 1000 }, (_, i) => i + 1), interval = quantileInterval(ordered, .95);
  assert.ok(interval.lowerRank > 925 && interval.lowerRank < 950 && interval.upperRank > 950 && interval.upperRank < 975);
  assert.equal(interval.lowerMs, interval.lowerRank); assert.equal(interval.upperMs, interval.upperRank);
  assert.equal(quantileInterval([1], .99).upperMs, null, 'Insufficient tail observations must not invent a confidence endpoint');
  const stablePairs = [0, 1, 2].map(run => ({ run, caseId: 'basic', ingressPoP: 'KIX', comparison: 'AA',
    targetA: { variant: 'bare', identity: 'synthetic-deployment' }, targetB: { variant: 'bare', identity: 'synthetic-deployment' }, a: Array(1000).fill(10), b: Array(1000).fill(10) }));
  assert.equal(assessAaRepeatability(stablePairs, .2, 5).status, 'READY_FOR_BASELINE_REVIEW');
  assert.equal(assessAaRepeatability(stablePairs.slice(1), .2, 5).status, 'INCONCLUSIVE');
  assert.equal(assessAaRepeatability(stablePairs.map(pair => ({ ...pair, b: Array(1000).fill(30) })), .2, 5).status, 'INCONCLUSIVE');
  for (const changed of [{ ingressPoP: 'PDX' }, { caseId: 'hmac' }, { comparison: 'AB' }, { targetB: { variant: 'generated', identity: 'synthetic-deployment' } }]) {
    assert.equal(assessAaRepeatability([stablePairs[0], { ...stablePairs[1], ...changed }, stablePairs[2]], .2, 5).status, 'INCONCLUSIVE');
  }
  const badTargets = Object.fromEntries(['bare', 'basic', 'graphql', 'hmac', 'regex', 'rs256'].map(role => [role, 'https://csf-1026-abcd-gateway.test.workers.dev']));
  assert.throws(() => prepareBenchmark('/nonexistent-csf-do-not-create', badTargets.bare, 'https://origin.example', badTargets), /Direct target must match/);
  const k6Source = transformSync(fs.readFileSync(path.resolve(__dirname, '../benchmarks/edge/k6.js'), 'utf8'), { format: 'cjs' }).code;
  const testManifest = { baseUrl: badTargets.bare, topology: 'direct', targetUrls: badTargets, cases: [benchmarkCases[0]] };
  const fakeMetric = class { add() {} };
  assert.throws(() => vm.runInNewContext(k6Source, { module: { exports: {} }, exports: {},
    require: (name: string) => name === 'k6/metrics' ? { Trend: fakeMetric, Counter: fakeMetric } : {}, open: () => JSON.stringify(testManifest),
    __ENV: { CSF_CASE: 'basic', CSF_VARIANT: 'generated', CSF_PHASE: 'measured', CSF_SERIES: 'test' } }), /Disposable direct target/);
  const clientSeries = 'r0-basic-bare-measured';
  const clientPoint = { type: 'Point', metric: 'csf_wall_ms', data: { value: 1, tags: { series: clientSeries, request_id: clientSeries + '-0', colo: 'KIX' } } };
  assert.equal(clientPopulation(Buffer.from(JSON.stringify(clientPoint)), clientSeries, 1).length, 1);
  assert.throws(() => clientPopulation(Buffer.from(JSON.stringify(clientPoint)), clientSeries, 2), /population size mismatch/);
  assert.throws(() => clientPopulation(Buffer.from(JSON.stringify(clientPoint)), 'r0-hmac-bare-measured', 1), /series binding mismatch/);
  assert.throws(() => clientPopulation(Buffer.from(JSON.stringify(clientPoint) + '\n{'), clientSeries, 1), SyntaxError);
  const cloudPrefix = 'csf-1026-abcd', baseUrl = `https://${cloudPrefix}-gateway.test.workers.dev`;
  const cloudManifest = { topology: 'direct', baseUrl, targetUrls: Object.fromEntries(['bare', 'basic', 'graphql', 'hmac'].map(role => [role, `https://${cloudPrefix}-${role}.test.workers.dev`])) };
  const clientRow = { run: 0, id: 'basic', variant: 'bare', targetVariant: 'bare', comparison: 'AB', phase: 'measured', actual: 1, expected: 1, valid: 1, invalid: 0, dropped: 0, exit: 0,
    startedAt: '2026-10-18T00:00:00Z', endedAt: '2026-10-18T00:00:01Z' };
  const cloudReport = { topology: 'direct', series: [clientRow] };
  assert.equal(bindCpuSeries(cloudReport, cloudManifest, clientSeries, cloudPrefix + '-bare', 'version').binding.scriptName, cloudPrefix + '-bare');
  for (const role of ['gateway', 'origin', 'basic', 'hmac']) assert.throws(() => bindCpuSeries(cloudReport, cloudManifest, clientSeries, cloudPrefix + '-' + role, 'version'), /Worker role/);
  const generatedSeries = 'r0-hmac-generated-measured', generatedRow = { ...clientRow, id: 'hmac', variant: 'generated', targetVariant: 'generated' };
  assert.equal(bindCpuSeries({ ...cloudReport, series: [generatedRow] }, cloudManifest, generatedSeries, cloudPrefix + '-hmac', 'version').binding.scriptName, cloudPrefix + '-hmac');
  assert.throws(() => bindCpuSeries({ ...cloudReport, series: [generatedRow] }, cloudManifest, generatedSeries, cloudPrefix + '-bare', 'version'), /Worker role/);
  assert.throws(() => bindCpuSeries({ ...cloudReport, topology: 'gateway' }, cloudManifest, clientSeries, cloudPrefix + '-bare', 'version'), /direct target/);
  assert.throws(() => bindCpuSeries({ ...cloudReport, series: [clientRow, clientRow] }, cloudManifest, clientSeries, cloudPrefix + '-bare', 'version'), /Exactly one/);
  for (const concurrency of ['1', '4', '0', '5', 'NaN']) {
    const module = { exports: {} as any };
    const evaluate = () => vm.runInNewContext(k6Source, { module, exports: module.exports,
      require: (name: string) => name === 'k6/metrics' ? { Trend: fakeMetric, Counter: fakeMetric } : {},
      open: () => JSON.stringify({ ...testManifest, baseUrl: 'http://127.0.0.1:1', topology: 'gateway' }),
      __ENV: { CSF_CASE: 'basic', CSF_VARIANT: 'bare', CSF_PHASE: 'measured', CSF_SERIES: 'test',
        CSF_MODEL: 'iterations', CSF_RATE: '1', CSF_SECONDS: '1', CSF_CONCURRENCY: concurrency } });
    if (['1', '4'].includes(concurrency)) { evaluate(); assert.equal(module.exports.options.scenarios.measured.vus, Number(concurrency)); }
    else assert.throws(evaluate, /Bounded concurrency/);
  }
  const realFetch = globalThis.fetch; let queries = 0;
  try {
    globalThis.fetch = async (_url, options) => {
      queries++; assert.equal(options?.redirect, 'error');
      const query = JSON.parse(options!.body as string); assert.equal(query.limit, 2000);
      assert.ok(query.parameters.filters.some((filter: any) => filter.key === '$metadata.type' && filter.value === 'cf-worker-event'));
      return Response.json({ success: true, result: { run: { status: 'COMPLETED' }, statistics: { abr_level: 1 }, events: { count: 0, events: [] } } });
    };
    const disposable = { ...binding, scriptName: 'csf-1026-abcd-hmac' };
    const emptyCapture: any = await collectCpuEvents('a'.repeat(32), 'synthetic-only', disposable);
    assert.equal(emptyCapture.status, 'COMPLETE', 'Provider query completion must be retained');
    assert.equal(emptyCapture.pages[0].events.count, 0, 'Provider population count must be retained');
    assert.equal(queries, 1);
    await assert.rejects(collectCpuEvents('a'.repeat(32), 'synthetic-only', { ...binding, scriptName: 'production' }));
    assert.equal(queries, 1, 'Production name must fail before API access');
    let page = 0;
    globalThis.fetch = async (_url, options) => {
      const query = JSON.parse(options!.body as string);
      if (page) { assert.equal(query.offset, 'cursor-b'); assert.equal(query.offsetDirection, 'next'); }
      const rows = (page++ ? [events[1]] : [events[0]]).map((row, index) => ({ ...row, $metadata: { ...row.$metadata, id: page === 1 ? 'cursor-b' : 'cursor-c' } }));
      return Response.json({ success: true, result: { run: { status: 'COMPLETED' }, statistics: { abr_level: 1 }, events: { count: 2, events: rows, series: [{ data: [{ count: 2, sampleInterval: 1 }] }] } } });
    };
    const paged = await collectCpuEvents('a'.repeat(32), 'synthetic-only', disposable);
    assert.equal(page, 2, 'A short page must not discard the rest of the provider population');
    assert.equal(paged.events.length, 2); assert.equal(paged.pages.length, 2); assert.equal(paged.status, 'COMPLETE');
    const completeEvents = (sampleInterval: number | undefined) => ({ success: true, result: { run: { status: 'COMPLETED' }, statistics: { abr_level: 1 },
      events: { count: 2, events: events.map(row => ({ ...row, $metadata: { ...row.$metadata, id: 'shared-cursor' } })),
        series: [{ data: [{ count: 2, sampleInterval }] }] } } });
    globalThis.fetch = async () => Response.json(completeEvents(1));
    const sharedCursor = await collectCpuEvents('a'.repeat(32), 'synthetic-only', disposable);
    assert.equal(sharedCursor.status, 'COMPLETE', 'Complete single-page events use client IDs, not pagination cursor uniqueness');
    assert.equal(joinProviderCapture(points, sharedCursor, binding).captured, 2);
    for (const sampleInterval of [2, undefined]) {
      globalThis.fetch = async () => Response.json(completeEvents(sampleInterval));
      const sampled = await collectCpuEvents('a'.repeat(32), 'synthetic-only', disposable);
      assert.equal(sampled.status, 'UNKNOWN', 'ABR=1 cannot prove ingestion sampling is disabled');
      assert.equal(joinProviderCapture(points, sampled, binding).status, 'UNKNOWN');
    }
    for (const [status, abr] of [['STARTED', 1], ['COMPLETED', 2], ['COMPLETED', undefined]] as const) {
      globalThis.fetch = async () => Response.json({ success: true, result: { run: { status }, statistics: { abr_level: abr }, events: { count: 2, events } } });
      const uncertain = await collectCpuEvents('a'.repeat(32), 'synthetic-only', disposable);
      assert.equal(uncertain.status, 'UNKNOWN'); assert.equal(uncertain.pages.length, 1);
      assert.equal(joinProviderCapture(points, uncertain, binding).status, 'UNKNOWN', 'Matching CPU rows cannot override sampled/incomplete query evidence');
    }
    globalThis.fetch = async () => new Response('', { status: 403 });
    await assert.rejects(collectCpuEvents('a'.repeat(32), 'synthetic-only', disposable), /HTTP 403/);
    globalThis.fetch = async () => new Response('{');
    await assert.rejects(collectCpuEvents('a'.repeat(32), 'synthetic-only', disposable), SyntaxError);
    globalThis.fetch = async () => { throw new DOMException('Synthetic timeout', 'TimeoutError'); };
    await assert.rejects(collectCpuEvents('a'.repeat(32), 'synthetic-only', disposable), /Synthetic timeout/);
    let repeated = 0;
    globalThis.fetch = async () => { repeated++; return Response.json({ success: true, result: { run: { status: 'COMPLETED' }, statistics: { abr_level: 1 },
      events: { count: 3, events: [{ ...events[0], $metadata: { type: 'cf-worker-event', id: 'stuck' } }], series: [{ data: [{ sampleInterval: 1 }] }] } } }); };
    await assert.rejects(collectCpuEvents('a'.repeat(32), 'synthetic-only', disposable), /pagination did not advance/);
    assert.equal(repeated, 2, 'Non-advancing pages must stop without a third query');
  } finally { globalThis.fetch = realFetch; }
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-k6-failure-'));
  const reportsDirectory = path.resolve(__dirname, '../reports');
  fs.mkdirSync(reportsDirectory, { recursive: true });
  const runtimeTemporary = fs.mkdtempSync(path.join(reportsDirectory, 'k6-spawn-failure-'));
  const failedRuntimeDirectory = path.join(runtimeTemporary, 'run');
  try {
    const fakeK6 = path.join(temporary, 'k6.cjs');
    fs.writeFileSync(fakeK6, `#!${process.execPath}
const fs=require('node:fs');
if(process.argv.includes('version')){console.log('failure-test');process.exit(0);}
fs.writeFileSync(process.env.CSF_SUMMARY,'{"metrics":');
fs.writeFileSync(process.argv[process.argv.indexOf('--out')+1].slice(5),JSON.stringify({type:'Point',metric:'csf_wall_ms',data:{value:1,tags:{request_id:'partial-0'}}})+'\\n{"type":');
process.exit(1);\n`, { mode: 0o700 });
    const partial: any = { series: [] };
    await assert.rejects(runK6Series(temporary, fakeK6, { selected: ['basic'], samples: 1, warmup: 1, rate: 1, runs: 1 }, partial, new AbortController().signal), /incomplete load/);
    const saved = JSON.parse(fs.readFileSync(path.join(temporary, 'report.json'), 'utf8'));
    assert.equal(saved.series.length, 1); assert.equal(saved.series[0].actual, 1); assert.equal(saved.series[0].exit, 1);
    assert.equal(saved.series[0].valid, null); assert.equal(saved.series[0].diagnostics.length, 2); assert.ok(saved.series[0].pointsSha256);
    const readyFile = path.join(temporary, 'child-ready.json');
    const stubbornK6 = path.join(temporary, 'stubborn-k6.cjs');
    fs.writeFileSync(stubbornK6, `#!${process.execPath}
const fs=require('node:fs');
process.on('SIGTERM',()=>{});
fs.writeFileSync(${JSON.stringify(readyFile)},JSON.stringify({pid:process.pid,concurrency:process.env.CSF_CONCURRENCY}));
setInterval(()=>{},1000);\n`, { mode: 0o700 });
    const controller = new AbortController(), aborted: any = { series: [] };
    const pending = assert.rejects(runK6Series(temporary, stubbornK6, { selected: ['basic'], samples: 1, warmup: 1, rate: 1, runs: 1, concurrency: 1 }, aborted, controller.signal), /incomplete load/);
    try {
      for (let n = 0; n < 200 && !fs.existsSync(readyFile); n++) await new Promise(resolve => setTimeout(resolve, 10));
      assert.ok(fs.existsSync(readyFile), 'Synthetic child readiness deadline');
    } finally { controller.abort(); }
    await pending;
    const child = JSON.parse(fs.readFileSync(readyFile, 'utf8'));
    assert.equal(child.concurrency, '1');
    assert.throws(() => process.kill(child.pid, 0), { code: 'ESRCH' }, 'SIGTERM-resistant child must be reaped');
    assert.equal(aborted.series.length, 1, 'Abort must stop before the next series');
    assert.equal(aborted.series[0].exit, null);
    assert.ok(aborted.series[0].childFailure);
    const preload = path.join(temporary, 'preload.cjs');
    fs.writeFileSync(preload, `const id=require.resolve('workerd',{paths:[${JSON.stringify(path.resolve(__dirname, '..'))}]});require.cache[id]={id,filename:id,loaded:true,exports:{default:'/nonexistent-csf-runtime'}};`);
    const failedRuntime = spawnSync(process.execPath, ['--require', preload, path.join(__dirname, 'benchmark-edge-k6.js'), '--output', failedRuntimeDirectory,
      '--k6', fakeK6, '--samples', '1', '--warmup', '1', '--rate', '1', '--runs', '1', '--only', 'basic'], { timeout: 15000, encoding: 'utf8' });
    assert.equal(failedRuntime.status, 1, 'Runtime spawn failure must reject promptly');
    const failedReport = JSON.parse(fs.readFileSync(path.join(failedRuntimeDirectory, 'report.json'), 'utf8'));
    assert.equal(failedReport.status, 'failed'); assert.equal(failedReport.cleanup.runtimeStopped, true);
    const identity = JSON.parse(fs.readFileSync(path.join(failedRuntimeDirectory, 'identity.json'), 'utf8'));
    for (const file of ['src/scripts/edge-benchmark-cpu.ts', 'src/scripts/collect-edge-benchmark-cpu.ts']) {
      assert.ok(identity.sourceFiles.some((row: any) => row.file === file && /^[a-f0-9]{64}$/.test(row.sha256)), 'Execution identity must bind CPU aggregation and collection sources');
    }
    assert.ok(identity.builtFiles.some((row: any) => row.file === 'scripts/edge-benchmark-cpu.js'));
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true }); fs.rmSync(runtimeTemporary, { recursive: true, force: true });
  }
  console.log('OK: gateway byte preservation, bounded/cancelled bodies, rejection before forwarding, expiry, exact provider populations, missing CPU, PoP/version binding, and budget regression detection');
  console.log('OK: truncated k6 artifacts preserve a failed series and spawn errors preserve the final report');
}
void main().catch(error => { console.error(error); process.exitCode = 1; });
