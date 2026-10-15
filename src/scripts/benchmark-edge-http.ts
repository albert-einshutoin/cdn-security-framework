#!/usr/bin/env node
/** Bounded loopback-only measurement of generated code in native workerd. */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import crypto from 'node:crypto';
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { performance } from 'node:perf_hooks';
import { transformSync } from 'esbuild';

const arg = (name: string) => {
  const at = process.argv.indexOf(name);
  if (at < 0 || !process.argv[at + 1]) throw new Error(name + ' requires a path');
  return path.resolve(process.argv[at + 1]);
};
const root = arg('--root'), output = arg('--output');
const hotPaths = process.argv.includes('--hot-paths');
const prefixAt = process.argv.indexOf('--auth-prefix-count');
const prefixCount = prefixAt < 0 ? 0 : Number(process.argv[prefixAt + 1]);
if (prefixAt >= 0 && (!Number.isSafeInteger(prefixCount) || prefixCount < 1 || prefixCount > 5000)) {
  throw new Error('--auth-prefix-count must be an integer between 1 and 5000');
}
if (hotPaths && prefixAt >= 0) throw new Error('--hot-paths and --auth-prefix-count are separate workloads');
const sha = (value: string | Buffer) => crypto.createHash('sha256').update(value).digest('hex');
const secret = 'synthetic-loopback-only';
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-edge-http-bench-'));
const record: any = { environment: { node: process.version, workerd: require('workerd/package.json').version,
  platform: process.platform, arch: process.arch }, root, driverSha256: sha(fs.readFileSync(__filename)), results: [], cleanup: {} };
const agent = new http.Agent({ keepAlive: true });
let runtime: ChildProcess | undefined, runtimeClosed: Promise<unknown> | undefined;
let runtimeLog = '', originCalls = 0, originFailure: string | undefined;
let expectedHotPath = '', expectedHotBody = '';
const origin = http.createServer(async (req, res) => {
  try {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const body = Buffer.concat(chunks);
    if (hotPaths) {
      if (req.url !== expectedHotPath || body.toString('utf8') !== expectedHotBody
        || req.headers['x-edge-token'] !== secret || req.headers['x-edge-authenticated'] !== undefined) {
        throw new Error('hot-path origin URI/body/header mismatch');
      }
    } else if (prefixCount) {
      if (req.url !== `/private${prefixCount - 1}/child` || req.headers['x-edge-token'] !== secret) throw new Error('auth path/header mismatch');
    } else {
      const hash = crypto.createHash('sha256').update(body).digest('hex');
      const url = new URL(req.url!, 'http://edge.example');
      const query = Array.from(url.searchParams.entries()).sort(([ak, av], [bk, bv]) => ak < bk ? -1 : ak > bk ? 1 : av < bv ? -1 : av > bv ? 1 : 0)
        .map(([key, value]) => encodeURIComponent(key) + '=' + encodeURIComponent(value)).join('&');
      const canonical = [req.method, url.pathname, query, hash, req.headers['x-cdn-auth-timestamp'], req.headers['x-cdn-auth-nonce']].join('\n');
      if (req.headers['x-cdn-auth-body-sha256'] !== hash || req.headers['x-cdn-auth-signature'] !== crypto.createHmac('sha256', secret).update(canonical).digest('base64url')) throw new Error('origin body/signature mismatch');
      if (url.searchParams.has('utm_source')) throw new Error('query filter mismatch');
    }
    originCalls++;
    if (hotPaths) { res.sendDate = false; res.setHeader('Vary', 'Accept-Encoding'); res.setHeader('Cache-Control', 'public'); }
    res.end('ok');
  } catch (error) { originFailure = String(error); res.writeHead(500).end('origin validation failed'); }
});
async function send(port: number, target: string, body?: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path: target, method: body === undefined ? 'GET' : 'POST', agent,
      headers: { 'user-agent': 'local-benchmark', 'content-type': hotPaths ? 'application/graphql' : 'application/json',
        ...(prefixCount || hotPaths ? { 'x-edge-token': secret } : {}) }, timeout: 5000 }, res => {
      res.resume(); res.on('error', reject);
      res.on('end', () => {
        if (res.statusCode !== 200) return reject(new Error('HTTP ' + res.statusCode + ': ' + runtimeLog));
        if (hotPaths) {
          const protectedPath = target.startsWith('/private0/');
          if (res.headers.vary !== (protectedPath ? 'Accept-Encoding, Authorization, Cookie' : 'Accept-Encoding')
            || res.headers['cache-control'] !== (protectedPath ? 'no-store, no-cache, must-revalidate, private' : 'public')) {
            return reject(new Error('hot-path response cache/Vary mismatch'));
          }
        }
        resolve();
      });
    });
    req.on('timeout', () => req.destroy(new Error('HTTP deadline'))); req.on('error', reject); req.end(body);
  });
}
async function main() {
  try {
    origin.listen(0, '127.0.0.1'); await once(origin, 'listening');
    const originPort = (origin.address() as net.AddressInfo).port;
    const policy = { version: 2, defaults: { mode: 'enforce' }, request: { allow_methods: ['GET', 'POST'],
      limits: { max_query_params: 200, max_query_length: 32768 },
      ...(prefixCount ? {} : { graphql_guard: { endpoint_paths: ['/graphql'], max_body_bytes: 65536 } }) },
      response_headers: {}, routes: Array.from({ length: 500 }, (_, i) => ({ name: 'r' + i, match: { path_prefixes: ['/private' + i] },
        auth_gate: { type: 'static_token', token_env: 'SECRET' } })),
      ...(prefixCount ? {} : { origin: { auth: { type: 'hmac_signature', secret_env: 'SECRET', include_body_hash: true } } }),
      observability: { sample_rate: 0 } };
    if (hotPaths) {
      Object.assign(policy.request.limits, { max_uri_length: 8192 });
      Object.assign(policy.request, { graphql_guard: { endpoint_paths: ['/graphql'], max_body_bytes: 1048576, max_fields: 50000 } });
      delete policy.origin;
      policy.routes = [{ name: 'group', match: { path_prefixes: Array.from({ length: 64 }, (_, i) => '/private' + i) },
        auth_gate: { type: 'static_token', token_env: 'SECRET' } }];
    }
    if (prefixCount) policy.routes = [{ name: 'group',
      match: { path_prefixes: Array.from({ length: prefixCount }, (_, i) => '/private' + i) },
      auth_gate: { type: 'static_token', token_env: 'SECRET' } }];
    const input = path.join(temp, 'policy.json'); fs.writeFileSync(input, JSON.stringify(policy));
    execFileSync(process.execPath, [path.join(root, 'scripts/compile-cloudflare.js'), '--policy', input, '--out-dir', temp], { stdio: 'pipe', timeout: 15000 });
    const generated = fs.readFileSync(path.join(temp, 'edge/cloudflare/index.ts'), 'utf8');
    const code = transformSync(generated, { loader: 'ts', format: 'esm', target: 'es2022' }).code;
    fs.writeFileSync(path.join(temp, 'worker.mjs'), code);
    const socket = net.createServer(); socket.listen(0, '127.0.0.1'); await once(socket, 'listening');
    const port = (socket.address() as net.AddressInfo).port; await new Promise<void>(resolve => socket.close(() => resolve()));
    const config = `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
 services = [
  (name = "worker", worker = (modules = [(name = "worker.mjs", esModule = embed "worker.mjs")], compatibilityDate = "2026-07-20",
   bindings = [(name = "SECRET", text = "${secret}")], globalOutbound = "origin")),
  (name = "origin", external = (address = "127.0.0.1:${originPort}", http = ())),
  (name = "internet", network = (allow = [], deny = ["0.0.0.0/0", "::/0"]))
 ], sockets = [(name = "http", address = "127.0.0.1:${port}", http = (), service = "worker")]
);`;
    fs.writeFileSync(path.join(temp, 'config.capnp'), config);
    runtime = spawn(require('workerd').default, ['serve', 'config.capnp'], { cwd: temp, stdio: ['ignore', 'pipe', 'pipe'] });
    runtimeClosed = once(runtime, 'close');
    runtime.stdout!.on('data', chunk => { runtimeLog = (runtimeLog + chunk).slice(-32768); });
    runtime.stderr!.on('data', chunk => { runtimeLog = (runtimeLog + chunk).slice(-32768); });
    let ready = false;
    for (let i = 0; i < 100 && !ready; i++) {
      if (runtime.exitCode !== null) throw new Error('workerd startup failed: ' + runtimeLog);
      ready = await new Promise<boolean>(resolve => { const client = net.connect(port, '127.0.0.1');
        client.on('connect', () => { client.destroy(); resolve(true); }); client.on('error', () => resolve(false)); });
      if (!ready) await new Promise(resolve => setTimeout(resolve, 25));
    }
    if (!ready) throw new Error('workerd readiness deadline');
    record.policySha256 = sha(JSON.stringify(policy)); record.generatedSha256 = sha(generated); record.moduleSha256 = sha(code);
    const query = Array.from({ length: 100 }, (_, i) => 'key' + i + '=value%20' + i).join('&');
    const field = 'longField_012345678901234567890123456789 ';
    const workloads = prefixCount ? [
      [`single-gate-prefixes-${prefixCount}`, `/private${prefixCount - 1}/child`, undefined],
    ] as const : hotPaths ? [
      ['control-short', '/public/catalog/item', undefined],
      ['canonical-deep256', '/public/' + Array(256).fill('segment').join('/'), undefined],
      ['control-normalized', '/public//a;v/%61', undefined],
      ...[2048, 32768, 65536].map(bytes => [`graphql-${bytes}`, '/graphql',
        ('query Audit { ' + field.repeat(Math.floor((bytes - 15) / field.length))).padEnd(bytes - 1, ' ') + '}'] as const),
      ['response-index-short', '/private0/item', undefined],
      ['response-index-deep256', '/private0/' + Array(256).fill('segment').join('/'), undefined],
    ] as const : [
      ['routes-500', '/public', undefined], ['query-100', '/public?utm_source=x&' + query, undefined],
      ['graphql-hash-32768', '/graphql', JSON.stringify({ query: '{ viewer { id } }', padding: 'x'.repeat(32768) })],
    ] as const;
    const warmup = prefixCount || hotPaths ? 1000 : 10, count = prefixCount || hotPaths ? 1000 : 100;
    for (const [name, target, body] of workloads) {
      expectedHotPath = target === '/public//a;v/%61' ? '/public/a/a' : target;
      expectedHotBody = body || '';
      const first = performance.now();
      if (hotPaths) await send(port, target, body);
      const firstRequestMs = hotPaths ? performance.now() - first : undefined;
      for (let i = 0; i < warmup; i++) await send(port, target, body);
      const samples: number[] = [];
      for (let i = 0; i < count; i++) { const start = performance.now(); await send(port, target, body); samples.push(performance.now() - start); }
      record.results.push({ name, warmup, firstRequestMs, requestBodyBytes: Buffer.byteLength(body || ''), samplesMs: samples, status: 'passed' });
    }
    if (originFailure || originCalls !== workloads.length * (warmup + count + (hotPaths ? 1 : 0))) throw new Error(originFailure || 'origin arrival count mismatch');
    record.status = 'passed'; record.originCalls = originCalls;
  } catch (error) { record.status = 'failed'; record.error = String(error); process.exitCode = 1; }
  finally {
    agent.destroy();
    if (runtime && runtimeClosed) {
      runtime.kill('SIGTERM');
      const force = setTimeout(() => runtime?.kill('SIGKILL'), 3000);
      try { await runtimeClosed; } finally { clearTimeout(force); }
      record.cleanup.runtimeExited = runtime.exitCode !== null || runtime.signalCode !== null;
    }
    origin.closeAllConnections();
    if (origin.listening) await new Promise<void>((resolve, reject) => origin.close(error => error ? reject(error) : resolve()));
    record.cleanup.originClosed = !origin.listening;
    fs.rmSync(temp, { recursive: true, force: true }); record.cleanup.tempRemoved = !fs.existsSync(temp);
    fs.writeFileSync(output, JSON.stringify(record, null, 2));
  }
  console.log(JSON.stringify({ status: record.status, error: record.error, cleanup: record.cleanup }));
}
main().catch(error => { console.error(error); process.exitCode = 1; });
