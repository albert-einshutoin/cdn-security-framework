#!/usr/bin/env node
/** Explicitly invoked benchmark harness; never deploys or contacts production. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { buildSync, transformSync } from 'esbuild';
import { benchmarkCases, compatibilityDate, fixtureSecret } from './edge-benchmark-fixture';
import { compileCloudflare } from './compile-cloudflare';
import { validatePolicy } from '../validator';
import type { CDNSecurityFrameworkPolicy } from '../types/policy';
import { sha, summarize } from './edge-benchmark-cpu';
export { sha } from './edge-benchmark-cpu';

const root = path.resolve(__dirname, '..');
const json = (file: string, data: unknown) => fs.writeFileSync(file, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });

export function readK6Artifacts(summaryFile: string, pointsFile: string) {
  const diagnostics: string[] = []; let summary: any, bytes: Buffer | undefined;
  const points: Array<{ data: { value: number; tags: Record<string, string> } }> = [];
  try { summary = JSON.parse(fs.readFileSync(summaryFile, 'utf8')); }
  catch { diagnostics.push('Summary missing, unreadable, or incomplete'); }
  try { bytes = fs.readFileSync(pointsFile); }
  catch { diagnostics.push('Points missing or unreadable'); }
  if (bytes) for (const line of bytes.toString().trim().split('\n')) {
    try {
      const point = JSON.parse(line);
      assert.ok(point && typeof point === 'object', 'Invalid point');
      if (point.type === 'Point' && point.metric === 'csf_wall_ms') {
        assert.ok(Number.isFinite(point.data?.value) && point.data.value >= 0 && typeof point.data.tags?.request_id === 'string', 'Invalid wall point');
        points.push(point);
      }
    } catch { diagnostics.push('Points incomplete or invalid; retained prefix only'); break; }
  }
  return { summary, points, diagnostics, pointsSha256: bytes ? sha(bytes) : null };
}

export function prepareBenchmark(directory: string, baseUrl: string, originUrl = 'https://origin.example', targetUrls?: Record<string, string>) {
  if (targetUrls) {
    assert.deepEqual(Object.keys(targetUrls).sort(), ['bare', 'basic', 'graphql', 'hmac', 'regex', 'rs256']);
    const cloud = /^https:\/\/(csf-1026-[a-f0-9]+)-gateway\.([a-z0-9-]+\.workers\.dev)$/.exec(baseUrl);
    for (const [role, url] of Object.entries(targetUrls)) assert.ok(
      /^http:\/\/127\.0\.0\.1:[0-9]+$/.test(baseUrl) ? /^http:\/\/127\.0\.0\.1:[0-9]+$/.test(url)
        : cloud && url === `https://${cloud[1]}-${role}.${cloud[2]}`, 'Direct target must match its disposable role and environment');
  }
  const probeKey = crypto.randomBytes(32).toString('hex'), key = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const claims = [JSON.stringify({ alg: 'RS256', kid: 'fixture' }), JSON.stringify({ iss: 'fixture', aud: 'fixture', exp: Math.floor(Date.now() / 1000) + 3600 })]
    .map(value => Buffer.from(value).toString('base64url')).join('.');
  const vars = { PROBE_KEY: probeKey, SECRET: fixtureSecret, EXPIRES: String(Date.now() + 900000), ORIGIN: originUrl,
    PUBLIC_JWKS: JSON.stringify({ keys: [{ ...key.publicKey.export({ format: 'jwk' }), kid: 'fixture', alg: 'RS256' }] }),
    RS_JWT: claims + '.' + crypto.sign('sha256', Buffer.from(claims), key.privateKey).toString('base64url') };
  const generated: Array<{ role: string; policySha256?: string; generatedSha256?: string; handlerSha256?: string; moduleSha256: string }> = [];
  for (const role of ['basic', 'regex', 'graphql', 'hmac', 'rs256', 'bare', 'origin', ...(targetUrls ? [] : ['gateway'])]) {
    let code: string, policy: CDNSecurityFrameworkPolicy | undefined, generatedSha256: string | undefined;
    if (['origin', 'gateway'].includes(role)) {
      code = buildSync({ stdin: { contents: `export { ${role} as default } from './src/scripts/edge-benchmark-fixture';`, resolveDir: root },
        bundle: true, write: false, format: 'esm', target: 'es2022', platform: 'browser' }).outputFiles[0].text;
    } else if (role === 'bare') code = 'export default {fetch(request){return fetch(request)}};';
    else {
      policy = { version: 2, defaults: { mode: 'enforce' }, request: { allow_methods: ['GET', 'POST'], allowed_hosts: [new URL(originUrl).hostname],
        limits: { max_uri_length: 8192, max_query_length: 4096, max_query_params: 32, max_header_count: 32, max_header_size: 8192 },
        block: { ua_contains: ['sqlmap'], header_missing: ['user-agent'] } },
        response_headers: { x_content_type_options: 'nosniff' }, routes: [], observability: { sample_rate: 0 } };
      if (role === 'regex') policy.request!.block!.path_patterns = { regex: Array.from({ length: 256 }, (_, i) => '/blocked-' + i + '/[a-z0-9]+$') };
      if (role === 'graphql') policy.request!.graphql_guard = { endpoint_paths: ['/graphql'], max_body_bytes: 65536, max_depth: 4, max_fields: 8 };
      if (role === 'hmac') policy.origin = { auth: { type: 'hmac_signature', secret_env: 'SECRET', include_body_hash: true } };
      if (role === 'rs256') {
        policy.routes = [{ name: 'jwt', match: { path_prefixes: ['/private'] }, auth_gate: { type: 'jwt', algorithm: 'RS256',
          jwks_url: originUrl + '/jwks', cache_ttl_sec: 3600, issuer: 'fixture', audience: 'fixture', clock_skew_sec: 0 } }];
        policy.firewall = { jwks: { allowed_hosts: [new URL(originUrl).hostname] } };
      }
      assert.ok(validatePolicy({ policy, pkgRoot: root, env: { SECRET: fixtureSecret } }).ok, 'Invalid benchmark policy');
      const output = path.join(directory, role);
      fs.mkdirSync(output);
      json(path.join(output, 'policy.json'), policy);
      const file = compileCloudflare(policy, { rootDir: root, outDir: output, logger: { log() {}, warn() {}, error() {} } });
      const source = fs.readFileSync(file, 'utf8'); generatedSha256 = sha(source);
      code = transformSync(source, { loader: 'ts', format: 'esm', target: 'es2022' }).code;
    }
    const handlerSha256 = sha(code);
    if (targetUrls && !['origin', 'gateway'].includes(role)) {
      fs.writeFileSync(path.join(directory, role + '-handler.mjs'), code, { mode: 0o600 });
      code = buildSync({ stdin: { contents: `import target from ${JSON.stringify(path.join(directory, role + '-handler.mjs'))};
import {createDirectTarget} from './src/scripts/edge-benchmark-fixture';export default createDirectTarget(target,${JSON.stringify(role)});`, resolveDir: root },
        bundle: true, write: false, format: 'esm', target: 'es2022', platform: 'browser' }).outputFiles[0].text;
    }
    fs.writeFileSync(path.join(directory, role + '.mjs'), code, { mode: 0o600 });
    generated.push({ role, ...(policy ? { policySha256: sha(JSON.stringify(policy)), generatedSha256 } : {}), handlerSha256, moduleSha256: sha(code) });
  }
  const cases = benchmarkCases.map(test => ({ ...test, bodyHash: sha(test.body || ''), pathHash: sha(test.path) }));
  const manifest = { schemaVersion: 2, topology: targetUrls ? 'direct' : 'gateway', baseUrl, targetUrls, probeKey, cases };
  json(path.join(directory, 'client.json'), manifest);
  const identity = { sourceHead: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(),
    sourceTree: execFileSync('git', ['rev-parse', 'HEAD^{tree}'], { cwd: root, encoding: 'utf8' }).trim(),
    sourceFiles: ['src/scripts/benchmark-edge-k6.ts', 'src/scripts/edge-benchmark-fixture.ts', 'src/scripts/edge-benchmark-cpu.ts', 'src/scripts/collect-edge-benchmark-cpu.ts', 'benchmarks/edge/k6.js']
      .map(file => ({ file, sha256: sha(fs.readFileSync(path.join(root, file))) })),
    builtFiles: ['benchmark-edge-k6.js', 'edge-benchmark-fixture.js', 'edge-benchmark-cpu.js', 'collect-edge-benchmark-cpu.js']
      .map(file => ({ file: 'scripts/' + file, sha256: sha(fs.readFileSync(path.join(__dirname, file))) })),
    generated, compatibilityDate, workerd: require('workerd/package.json').version,
    clientSha256: sha(fs.readFileSync(path.join(directory, 'client.json'))) };
  json(path.join(directory, 'identity.json'), identity);
  return { vars, identity, manifest };
}

export async function runK6Series(directory: string, k6: string, load: { selected: string[]; samples: number; warmup: number; rate: number; runs: number; concurrency?: number; model?: 'arrival' | 'iterations'; comparison?: 'AA' | 'AB' }, report: any, signal: AbortSignal) {
  const { selected, samples, warmup, rate, runs } = load;
  const concurrency = load.concurrency ?? 4;
  assert.ok(Number.isSafeInteger(concurrency) && concurrency >= 1 && concurrency <= 4, 'Invalid bounded concurrency');
  const model = load.model || 'arrival';
  const comparison = load.comparison || 'AB';
  assert.ok(['AA', 'AB'].includes(comparison), 'Unknown comparison');
  assert.ok(['arrival', 'iterations'].includes(model), 'Unknown load model');
  assert.ok(selected.length && new Set(selected).size === selected.length && selected.every(id => benchmarkCases.some(test => test.id === id)), 'Unknown or duplicate case');
  assert.ok([[samples, 2000], [warmup, 500], [rate, 50], [runs, 5]].every(([n, max]) => Number.isSafeInteger(n) && n >= 1 && n <= max)
    && samples % rate === 0 && warmup % rate === 0, 'Invalid bounded load');
  assert.ok(selected.length * 2 * runs * (samples + warmup) <= 20000, "20,000 request cap");
    for (let run = 0; run < runs; run++) for (const id of run % 2 ? [...selected].reverse() : selected) {
      for (const variant of run % 2 ? ['generated', 'bare'] : ['bare', 'generated']) for (const phase of ['warmup', 'measured']) {
        const count = phase === 'warmup' ? warmup : samples, series = `r${run}-${id}-${variant}-${phase}`;
        const summaryFile = path.join(directory, series + '-summary.json'), pointsFile = path.join(directory, series + '-points.jsonl');
        const startedAt = new Date().toISOString();
        let childFailure: string | null = null;
        signal.throwIfAborted();
        const code = await new Promise<number | null>(resolve => {
          const child = spawn(k6, ['run', '--quiet', '--no-usage-report', '--out', 'json=' + pointsFile, path.join(root, 'benchmarks/edge/k6.js')], {
            env: { PATH: process.env.PATH, HOME: process.env.HOME, CSF_MANIFEST: path.join(directory, 'client.json'), CSF_CASE: id,
              CSF_VARIANT: variant, CSF_COMPARISON: comparison, CSF_PHASE: phase, CSF_SERIES: series, CSF_SECONDS: String(count / rate), CSF_RATE: String(rate), CSF_CONCURRENCY: String(concurrency), CSF_MODEL: model, CSF_SUMMARY: summaryFile },
            signal: signal, stdio: ['ignore', 'pipe', 'pipe'] });
          child.stdout.resume(); child.stderr.resume();
          let forceKill: NodeJS.Timeout | undefined;
          const stop = () => { forceKill = setTimeout(() => child.kill('SIGKILL'), 2000); };
          signal.addEventListener('abort', stop, { once: true });
          if (signal.aborted) stop();
          child.once('error', () => { childFailure = 'k6 spawn failed or interrupted'; });
          child.once('close', code => { clearTimeout(forceKill); signal.removeEventListener('abort', stop); resolve(code); });
        });
        const { summary, points, diagnostics, pointsSha256 } = readK6Artifacts(summaryFile, pointsFile);
        const result = { run, id, variant, targetVariant: comparison === 'AA' ? 'bare' : variant, comparison, phase, model, startedAt, endedAt: new Date().toISOString(), expected: count, actual: points.length,
          exit: code, childFailure, diagnostics, valid: summary?.metrics?.csf_valid?.values?.count ?? null, invalid: summary?.metrics?.csf_invalid?.values?.count ?? null,
          dropped: summary?.metrics?.dropped_iterations?.values?.count ?? null, wallMs: points.length ? summarize(points.map(point => point.data.value)) : null, pointsSha256 };
        report.series.push(result); json(path.join(directory, 'report.json'), report);
        assert.ok(code === 0 && !childFailure && !diagnostics.length && result.actual === count && result.valid === count && result.invalid === 0 && result.dropped === 0
          && new Set(points.map(point => point.data.tags.request_id)).size === count, 'k6 incomplete load or oracle failure: ' + series);
        console.log(JSON.stringify({ run, id, variant, phase, samples: points.length }));
      }
    }
}

async function main() {
  const args = process.argv.slice(2), allowed = ['--output', '--k6', '--samples', '--warmup', '--rate', '--runs', '--concurrency', '--only', '--model', '--comparison', '--topology'];
  for (let at = 0; at < args.length; at += 2) assert.ok(allowed.includes(args[at]) && args[at + 1] && !args[at + 1].startsWith('--'), 'Invalid argument');
  const value = (flag: string, fallback?: string) => args.includes(flag) ? args[args.indexOf(flag) + 1] : fallback;
  const number = (flag: string, fallback: number, max: number) => {
    const n = Number(value(flag, String(fallback))); assert.ok(Number.isSafeInteger(n) && n >= 1 && n <= max, flag + ' out of bounds'); return n;
  };
  const samples = number('--samples', 100, 2000), warmup = number('--warmup', 20, 500), rate = number('--rate', 20, 50), runs = number('--runs', 3, 5);
  const concurrency = number('--concurrency', 4, 4);
  const model = value('--model', 'arrival') as 'arrival' | 'iterations';
  const comparison = value('--comparison', 'AB') as 'AA' | 'AB', topology = value('--topology', 'gateway')!;
  assert.ok(['AA', 'AB'].includes(comparison) && ['gateway', 'direct'].includes(topology), 'Unknown comparison/topology');
  assert.ok(['arrival', 'iterations'].includes(model), 'Unknown load model');
  assert.ok(samples % rate === 0 && warmup % rate === 0, 'samples and warmup must be divisible by rate');
  const selected = (value('--only') || benchmarkCases.map(test => test.id).join(',')).split(',');
  assert.ok(new Set(selected).size === selected.length && selected.every(id => benchmarkCases.some(test => test.id === id)), 'Unknown or duplicate case');
  assert.ok(3 + selected.length * 2 * runs * (samples + warmup) <= 20000, '20,000 request cap including preflight');
  assert.ok(value('--output') && value('--k6'), '--output and --k6 required');
  const directory = path.resolve(value('--output')!), k6 = path.resolve(value('--k6')!);
  assert.ok(directory.startsWith(path.join(root, 'reports') + path.sep), 'Output must be a new directory under reports/');
  fs.mkdirSync(directory, { mode: 0o700 });
  const report: any = { status: 'running', environment: 'local-workerd', metric: 'k6 HTTP sending + waiting + receiving; excludes connection setup and scheduling', quantiles: 'nearest rank from individual points',
    providerCpu: { status: 'UNKNOWN', reason: 'Local workerd does not provide managed Edge CPU samples' },
    topology, comparison, load: { model: model === 'arrival' ? 'constant-arrival-rate' : 'paced-shared-iterations', rate, concurrencyCap: concurrency, runs, samples, warmup }, series: [], cleanup: {} };
  const ports: Record<string, number> = {};
  for (const role of topology === 'direct' ? ['basic', 'regex', 'graphql', 'hmac', 'rs256', 'bare'] : ['gateway']) {
    const server = net.createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
    ports[role] = (server.address() as net.AddressInfo).port; await new Promise<void>(resolve => server.close(() => resolve()));
  }
  const port = ports.gateway || ports.bare;
  const targetUrls = topology === 'direct' ? Object.fromEntries(Object.entries(ports).filter(([role]) => role !== 'gateway').map(([role, port]) => [role, 'http://127.0.0.1:' + port])) : undefined;
  const prepared = prepareBenchmark(directory, 'http://127.0.0.1:' + port, undefined, targetUrls);
  report.identitySha256 = sha(fs.readFileSync(path.join(directory, 'identity.json')));
  report.k6 = execFileSync(k6, ['version'], { encoding: 'utf8' }).trim();
  const services = prepared.identity.generated.map(({ role }) => {
    const bindings = Object.entries(prepared.vars).map(([name, text]) => `(name=${JSON.stringify(name)},text=${JSON.stringify(text)})`);
    if (role === 'gateway') for (const name of ['basic', 'regex', 'graphql', 'hmac', 'rs256', 'bare']) bindings.push(`(name="${name.toUpperCase()}",service="${name}")`);
    return `(name="${role}",worker=(modules=[(name="${role}.mjs",esModule=embed "${role}.mjs")],compatibilityDate="${compatibilityDate}",bindings=[${bindings}],globalOutbound="origin"))`;
  });
  const sockets = Object.entries(ports).map(([role, port]) => `(name="${role}",address="127.0.0.1:${port}",http=(),service="${role}")`);
  fs.writeFileSync(path.join(directory, 'config.capnp'), `using Workerd=import "/workerd/workerd.capnp";const config:Workerd.Config=(services=[${services},(name="internet",network=(allow=[],deny=["0.0.0.0/0","::/0"]))],sockets=[${sockets}]);`, { mode: 0o600 });
  const controller = new AbortController(), abort = () => controller.abort(), timer = setTimeout(abort, 900000);
  process.once('SIGINT', abort); process.once('SIGTERM', abort);
  const runtime = spawn(require('workerd').default, ['serve', 'config.capnp'], { cwd: directory, env: { PATH: process.env.PATH }, stdio: ['ignore', 'pipe', 'pipe'] });
  runtime.stderr.resume(); runtime.stdout.resume();
  let startupFailed = false;
  const closed = new Promise<void>(resolve => {
    runtime.once('error', () => { startupFailed = true; });
    runtime.once('close', () => resolve());
  });
  try {
    let ready = false;
    for (let n = 0; n < 100 && !ready; n++) {
      if (startupFailed || runtime.exitCode !== null) throw new Error('workerd startup failed');
      ready = await new Promise<boolean>(resolve => { const socket = net.connect(port, '127.0.0.1'); socket.once('connect', () => { socket.destroy(); resolve(true); }); socket.once('error', () => resolve(false)); });
      if (!ready) await new Promise(resolve => setTimeout(resolve, 25));
    }
    assert.ok(ready, 'workerd readiness deadline');
    for (const [body, status] of [[null, 400], ['x', 400], ['x'.repeat(1048577), 413]] as const) {
      const response = await fetch((targetUrls?.hmac || 'http://127.0.0.1:' + port) + '/hmac/generated', { method: 'POST', body,
        headers: { 'x-csf-key': prepared.vars.PROBE_KEY, 'x-csf-id': 'preflight' }, signal: AbortSignal.timeout(5000) });
      assert.equal(response.status, status, 'Native gateway must reject invalid body before target'); await response.arrayBuffer();
    }
    await runK6Series(directory, k6, { selected, samples, warmup, rate, runs, concurrency, model, comparison }, report, controller.signal);
    report.status = 'local-passed';
  } catch (error) { report.status = 'failed'; throw error; }
  finally {
    runtime.kill('SIGTERM'); const kill = setTimeout(() => runtime.kill('SIGKILL'), 2000);
    try { await closed; report.cleanup.runtimeStopped = true; }
    finally {
      clearTimeout(kill); clearTimeout(timer); process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort);
      json(path.join(directory, 'report.json'), report);
    }
  }
}
if (require.main === module) void main().catch(error => { console.error(error instanceof Error ? error.message : 'Benchmark failed'); process.exitCode = 1; });
