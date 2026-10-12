#!/usr/bin/env node
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';

const repo = path.resolve(__dirname, '..');
const argv = process.argv.slice(2);
const reportIndex = argv.indexOf('--report');
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--report') { assert.ok(argv[++i] && !argv[i].startsWith('--'), '--report requires a path'); }
  else assert.ok(['--fail-after-start', '--fail-cleanup'].includes(argv[i]), 'Unknown argument');
}
const reportPath = path.resolve(reportIndex < 0 ? 'reports/cloudflare-http-e2e.json' : argv[reportIndex + 1]);
const workerdPath: string = require('workerd').default;
const digest = (bytes: string | Buffer) => crypto.createHash('sha256').update(bytes).digest('hex');
const timeoutMs = 5000;
const token = 'http-e2e-synthetic-admin';
const policy = `version: 2
project: http-e2e
defaults: { mode: enforce }
request:
  allow_methods: [GET, POST]
  limits: { max_uri_length: 200 }
  block:
    header_missing: [x-required]
    ua_contains: [sqlmap]
    path_patterns: { contains: ['/../'] }
  normalize:
    drop_query_keys: [utm_source]
routes:
  - name: admin
    match: { path_prefixes: [/admin] }
    auth_gate: { type: static_token, header: x-edge-token, token_env: EDGE_ADMIN_TOKEN }
    response: { cache_control: no-store }
response_headers:
  hsts: max-age=100
  x_content_type_options: nosniff
  referrer_policy: same-origin
observability: { log_format: json, correlation_id_header: x-e2e-id, sample_rate: 1 }
`;

type Receipt = { url: string; method: string; headers: http.IncomingHttpHeaders; body: string };
type HttpResult = { status: number; headers: http.IncomingHttpHeaders; body: string };
type Case = { id: string; target: string; method?: string; headers?: Record<string, string | undefined>; body?: string; status: number; forwarded?: string; reason?: string; protectedResponse?: boolean; publicResponse?: boolean };

// `path`, unlike a URL/fetch client, sends the supplied request-target verbatim.
function request(port: number, test: Case, signal: AbortSignal): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const headers = { 'user-agent': 'http-e2e', 'x-required': 'present', 'x-e2e-id': test.id, ...test.headers };
    Object.keys(headers).forEach(key => { if (headers[key as keyof typeof headers] === undefined) delete headers[key as keyof typeof headers]; });
    const req = http.request({ hostname: '127.0.0.1', port, path: test.target, method: test.method || 'GET', headers, agent: false, signal }, res => {
      let body = '';
      res.setTimeout(timeoutMs, () => res.destroy(new Error('HTTP response deadline')));
      res.on('data', chunk => { body += chunk; if (body.length > 65536) res.destroy(new Error('HTTP response too large')); });
      res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body }));
    });
    const timer = setTimeout(() => req.destroy(new Error('HTTP request deadline')), timeoutMs);
    req.once('close', () => clearTimeout(timer));
    req.on('error', reject);
    req.end(test.body);
  });
}

async function listen(server: net.Server, signal: AbortSignal): Promise<number> {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening', { signal });
  return (server.address() as net.AddressInfo).port;
}

async function connects(port: number): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1');
    const finish = (ok: boolean) => { socket.destroy(); resolve(ok); };
    socket.setTimeout(200, () => { socket.destroy(); reject(new Error('TCP probe deadline')); });
    socket.once('connect', () => finish(true));
    socket.once('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'ECONNREFUSED') finish(false);
      else { socket.destroy(); reject(error); }
    });
  });
}

async function deadline<T>(promise: Promise<T>, milliseconds: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout;
  try {
    return await Promise.race([promise, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(label)), milliseconds); })]);
  } finally { clearTimeout(timer!); }
}

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-http-e2e-'));
  const controller = new AbortController();
  const abort = () => controller.abort(new Error('HTTP E2E interrupted'));
  process.once('SIGINT', abort); process.once('SIGTERM', abort);
  const watchdog = setTimeout(abort, 60000);
  const receipts: Receipt[] = [];
  const cases: Array<Record<string, unknown>> = [];
  let runtime: ChildProcess | undefined;
  let closed: Promise<unknown> | undefined;
  let runtimeLog = '';
  const parseEvents = () => runtimeLog.split('\n').flatMap(line => {
    try { return [JSON.parse(line.slice(line.indexOf('{')))]; } catch { return []; }
  });
  let workerPort = 0;
  let originPort = 0;
  let failure: unknown;
  let identity: Record<string, unknown> = {};
  const origin = http.createServer(async (req, res) => {
    try {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const receipt = { url: req.url!, method: req.method!, headers: req.headers, body: Buffer.concat(chunks).toString() };
    receipts.push(receipt);
    if (req.url === '/origin-error') { res.writeHead(503, { 'content-type': 'text/plain' }); res.end('synthetic-origin-failure'); }
    else { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(receipt)); }
    } catch (error) {
      // An interrupted streamed POST must reject the run, not become an
      // unhandled async server callback that bypasses main's resource cleanup.
      controller.abort(error);
      res.destroy();
    }
  });
  origin.requestTimeout = timeoutMs;
  const cleanup = { runtimeExited: false, originClosed: false, tempRemoved: false, workerPortClosed: false, originPortClosed: false };
  try {
    originPort = await listen(origin, controller.signal);
    const reservation = net.createServer();
    workerPort = await listen(reservation, controller.signal);
    await new Promise<void>((resolve, reject) => reservation.close(error => error ? reject(error) : resolve()));
    const childEnv = { PATH: process.env.PATH, TMPDIR: tmp };
    const cli = path.join(repo, 'bin/cli.js');
    execFileSync(process.execPath, [cli, 'init', '--platform', 'cloudflare', '--profile', 'balanced'], { cwd: tmp, env: childEnv, timeout: 15000, stdio: 'pipe' });
    const wrangler = fs.readFileSync(path.join(tmp, 'wrangler.toml'), 'utf8');
    const date = /^compatibility_date\s*=\s*"(\d{4}-\d{2}-\d{2})"\s*$/m.exec(wrangler)?.[1];
    assert.ok(date, 'Generated Wrangler configuration must specify a compatibility date');
    const flagsLine = /^compatibility_flags\s*=\s*(\[[^\n]*\])\s*$/m.exec(wrangler);
    assert.ok(flagsLine || !/^compatibility_flags\s*=/m.test(wrangler), 'Unsupported compatibility flags syntax');
    const flags: string[] = flagsLine ? JSON.parse(flagsLine[1]) : [];
    assert.ok(Array.isArray(flags) && flags.every(f => typeof f === 'string'));
    fs.writeFileSync(path.join(tmp, 'policy/security.yml'), policy, { mode: 0o600 });
    execFileSync(process.execPath, [cli, 'build', '--policy', 'policy/security.yml', '--target', 'cloudflare', '--out-dir', 'dist'], { cwd: tmp, env: childEnv, timeout: 15000, stdio: 'pipe' });
    const generatedPath = path.join(tmp, 'dist/edge/cloudflare/index.ts');
    const generated = fs.readFileSync(generatedPath);
    // Same type erasure as deployment tooling; no replacement of fetch or Worker code.
    const { code } = require('esbuild').transformSync(generated.toString(), { loader: 'ts', format: 'esm', target: 'es2022' });
    fs.writeFileSync(path.join(tmp, 'worker.mjs'), code);
    const config = `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [
    (name = "worker", worker = (modules = [(name = "worker.mjs", esModule = embed "worker.mjs")],
      compatibilityDate = ${JSON.stringify(date)}, compatibilityFlags = ${JSON.stringify(flags)},
      bindings = [(name = "EDGE_ADMIN_TOKEN", text = ${JSON.stringify(token)})], globalOutbound = "origin")),
    (name = "origin", external = (address = "127.0.0.1:${originPort}", http = ())),
    (name = "internet", network = (allow = [], deny = ["0.0.0.0/0", "::/0"]))
  ],
  sockets = [(name = "http", address = "127.0.0.1:${workerPort}", http = (), service = "worker")]
);`;
    fs.writeFileSync(path.join(tmp, 'config.capnp'), config, { mode: 0o600 });
    identity = {
      source: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' }).trim(),
      node: process.version, platform: process.platform, arch: process.arch,
      workerd: require('workerd/package.json').version,
      runtimeVersion: execFileSync(workerdPath, ['--version'], { encoding: 'utf8', timeout: 5000 }).trim(),
      runtimeSha256: digest(fs.readFileSync(workerdPath)), compatibilityDate: date, compatibilityFlags: flags,
      policySha256: digest(policy), generatedWorkerSha256: digest(generated), moduleSha256: digest(code),
      harnessSha256: digest(fs.readFileSync(__filename)), packageLockSha256: digest(fs.readFileSync(path.join(repo, 'package-lock.json'))),
      configSha256: digest(config), compilerSha256: digest(fs.readFileSync(path.join(repo, 'scripts/compile-cloudflare.js'))),
      outbound: `127.0.0.1:${originPort}`, internet: 'deny-all', cfMetadataAutoFetch: false,
    };
    runtime = spawn(workerdPath, ['serve', 'config.capnp'], { cwd: tmp, env: childEnv, stdio: ['ignore', 'pipe', 'pipe'] });
    closed = new Promise(resolve => runtime!.once('close', resolve));
    let spawnError: Error | undefined;
    runtime.once('error', error => { spawnError = error; });
    runtime.stdout!.on('data', data => { runtimeLog += data; });
    runtime.stderr!.on('data', data => { runtimeLog += data; });
    const started = Date.now();
    while (!await connects(workerPort)) {
      controller.signal.throwIfAborted();
      if (spawnError) throw spawnError;
      assert.equal(runtime.exitCode, null, 'workerd exited before readiness: ' + runtimeLog);
      assert.ok(Date.now() - started < 10000, 'workerd readiness deadline: ' + runtimeLog);
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    if (argv.includes('--fail-after-start')) throw new Error('Injected cleanup check after workerd startup');

    const tests: Case[] = [
      { id: 'public', target: '/public?keep=1&utm_source=discard', status: 200, forwarded: '/public?keep=1' },
      { id: 'post', target: '/echo', method: 'POST', body: '{"synthetic":true}', headers: { 'content-type': 'application/json', 'x-forwarded-for': 'spoofed', 'x-edge-authenticated': 'spoofed' }, status: 200, forwarded: '/echo' },
      { id: 'admin-missing', target: '/admin', status: 401, reason: 'Unauthorized' },
      { id: 'admin-wrong', target: '/admin', headers: { 'x-edge-token': 'wrong-synthetic' }, status: 401, reason: 'Unauthorized' },
      { id: 'admin-valid', target: '/admin', headers: { 'x-edge-token': token }, status: 200, forwarded: '/admin' },
      { id: 'encoded-admin', target: '/%61dmin', status: 401, reason: 'Unauthorized' },
      { id: 'matrix-admin', target: '/admin;x=1', status: 401, reason: 'Unauthorized' },
      { id: 'slashes-admin', target: '//admin', status: 401, reason: 'Unauthorized' },
      { id: 'encoded-slash', target: '/admin%2fchild', status: 400, reason: 'Bad Request' },
      // workerd's Request URL removes dot segments before the Worker sees them.
      // The canonical protected destination must still reject unauthenticated access.
      { id: 'dot-admin', target: '/public/../admin', status: 401, reason: 'Unauthorized' },
      { id: 'method', target: '/public', method: 'DELETE', status: 405, reason: 'Method Not Allowed' },
      { id: 'uri-length', target: '/' + 'a'.repeat(210), status: 414, reason: 'URI Too Long' },
      { id: 'missing-header', target: '/public', headers: { 'x-required': undefined }, status: 400, reason: 'Missing x-required' },
      { id: 'user-agent', target: '/public', headers: { 'user-agent': 'sqlmap' }, status: 403, reason: 'Forbidden' },
      { id: 'origin-error', target: '/origin-error', status: 503, forwarded: '/origin-error' },
    ];
    // Literal destinations are the contract, not a copy of the normalizer.
    const matrixPaths = [
      ['raw-root', '/admin;x=1', '/admin'],
      ['encoded-root', '/admin%3bx=1', '/admin'],
      ['double-root', '/admin%253bx=1', '/admin'],
      ['raw-child', '/admin;x=1/child;y=2', '/admin/child'],
      ['encoded-child', '/admin%3bx=1/child%3by=2', '/admin/child'],
      ['double-child', '/admin%253bx=1/child%253by=2', '/admin/child'],
      ['triple-root', '/admin%25253bx=1', '/admin'],
    ];
    for (const [name, target, destination] of matrixPaths) {
      for (const auth of ['missing', 'wrong', 'valid']) {
        tests.push({ id: 'matrix-' + name + '-' + auth, target,
          headers: auth === 'missing' ? {} : { 'x-edge-token': auth === 'valid' ? token : 'wrong-synthetic' },
          status: auth === 'valid' ? 200 : 401,
          ...(auth === 'valid' ? { forwarded: destination, protectedResponse: true } : { reason: 'Unauthorized' }),
        });
      }
    }
    tests.push(
      { id: 'matrix-query-post', target: '/admin%253bx=1/child%253by=2?keep=1&utm_source=discard', method: 'POST', body: '{"synthetic":true}', headers: { 'content-type': 'application/json', 'x-edge-token': token }, status: 200, forwarded: '/admin/child?keep=1', protectedResponse: true },
      { id: 'prefix-boundary', target: '/administrator', status: 200, forwarded: '/administrator', publicResponse: true },
      { id: 'matrix-prefix-boundary', target: '/administrator%3bx=1', status: 200, forwarded: '/administrator', publicResponse: true },
      { id: 'matrix-invalid-encoding', target: '/admin%3bx=%ZZ', status: 400, reason: 'Bad Request' },
      { id: 'matrix-decode-overflow', target: '/admin%2525253bx=1', status: 400, reason: 'Bad Request' },
      { id: 'matrix-ambiguous-encoding', target: '/admin%3bx=1%2fchild', status: 400, reason: 'Bad Request' },
    );
    const caseErrors: unknown[] = [];
    for (const test of tests) {
      const before = receipts.length;
      const result = await request(workerPort, test, controller.signal);
      const observed = receipts.slice(before);
      cases.push({ id: test.id, requestTarget: test.target, method: test.method || 'GET', response: result, origin: observed, expectedStatus: test.status });
      try {
      assert.equal(result.status, test.status, test.id + ': status');
      assert.equal(observed.length, test.forwarded ? 1 : 0, test.id + ': origin arrivals');
      if (test.forwarded) {
        assert.equal(observed[0].url, test.forwarded, test.id + ': forwarded URL');
        assert.equal(observed[0].method, test.method || 'GET');
        assert.equal(observed[0].body, test.body || '');
        assert.equal(result.headers['strict-transport-security'], 'max-age=100');
        assert.equal(result.headers['x-content-type-options'], 'nosniff');
        assert.equal(result.headers['referrer-policy'], 'same-origin');
        if (test.id === 'post') {
          assert.equal(observed[0].headers['content-type'], 'application/json');
          assert.equal(observed[0].headers['x-forwarded-for'], undefined);
          assert.equal(observed[0].headers['x-edge-authenticated'], undefined);
        }
        if (test.id === 'origin-error') assert.equal(result.body, 'synthetic-origin-failure');
        else assert.deepEqual(JSON.parse(result.body), observed[0]);
        if (test.id === 'admin-valid' || test.protectedResponse) {
          assert.ok(String(result.headers['cache-control']).split(/,\s*/).includes('no-store'), test.id + ': no-store');
          assert.ok(String(result.headers.vary).toLowerCase().includes('authorization'), test.id + ': Vary Authorization');
        }
        if (test.publicResponse) assert.equal(result.headers['cache-control'], undefined, test.id + ': public path must not acquire auth cache protection');
      }
      console.log('OK:', test.id);
      } catch (error) { caseErrors.push(error); console.error('FAIL:', test.id, String(error)); }
    }
    if (caseErrors.length) throw new AggregateError(caseErrors, 'HTTP case expectations failed');
    // Prove policy rejection from the Worker's own log, not only an HTTP status.
    const logDeadline = Date.now() + timeoutMs;
    while (!tests.filter(t => !t.forwarded).every(t => parseEvents().some(e => e.correlation_id === t.id && e.event === 'block'))) {
      controller.signal.throwIfAborted();
      assert.ok(Date.now() < logDeadline, 'Worker rejection log deadline');
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    const events = parseEvents();
    for (const test of tests.filter(t => !t.forwarded)) {
      const event = events.find(e => e.correlation_id === test.id && e.event === 'block');
      assert.ok(event, test.id + ': missing Worker policy rejection event');
      assert.ok(String(event.block_reason).includes(test.reason!), test.id + ': block reason ' + event.block_reason);
      const evidence = cases.find(c => c.id === test.id)!;
      evidence.workerObservedUri = event.uri;
      evidence.workerBlockReason = event.block_reason;
      evidence.layer = 'worker-policy';
      if (test.id === 'dot-admin') assert.equal(event.uri, '/admin');
    }
    // Malformed HTTP is sent raw: it must be rejected before Worker/origin execution.
    const parserBefore = receipts.length;
    const parserResponse = await deadline(new Promise<string>((resolve, reject) => {
      const socket = net.connect(workerPort, '127.0.0.1'); let response = '';
      socket.setTimeout(timeoutMs, () => socket.destroy(new Error('Parser request deadline')));
      socket.on('error', reject); socket.on('data', data => { response += data; });
      socket.on('end', () => resolve(response));
      socket.on('connect', () => socket.end('GET /public HTTP/1.1\r\nHost: 127.0.0.1\r\nx-required: present\r\nx-e2e-id: parser-invalid\r\nx-bad: \x00\r\nConnection: close\r\n\r\n'));
    }), timeoutMs + 500, 'Parser response deadline');
    assert.match(parserResponse, /^HTTP\/1\.1 400 /);
    assert.equal(receipts.length, parserBefore);
    await new Promise(resolve => setTimeout(resolve, 50));
    assert.ok(!parseEvents().some(e => e.correlation_id === 'parser-invalid'), 'Parser rejection reached the Worker');
    cases.push({ id: 'parser-invalid', requestTarget: '/public', malformedHeader: 'NUL in x-bad', responseStatus: 400, layer: 'workerd-http-parser', originArrivals: 0 });
    origin.closeAllConnections();
    await new Promise<void>((resolve, reject) => origin.close(error => error ? reject(error) : resolve()));
    const beforeFailure = receipts.length;
    assert.equal(await connects(originPort), false, 'Origin must actually be unavailable');
    let upstreamFailure: Record<string, unknown>;
    try {
      const result = await request(workerPort, { id: 'origin-unreachable', target: '/unreachable', status: 500 }, controller.signal);
      assert.ok(result.status >= 500 && result.status <= 599, 'Connection failure must not become success');
      upstreamFailure = { response: result };
    } catch (error) {
      // workerd can terminate the downstream connection on an uncaught upstream
      // connect exception. Accept only that explicit transport failure, never a timeout.
      assert.equal((error as NodeJS.ErrnoException).code, 'ECONNRESET');
      upstreamFailure = { transportError: 'ECONNRESET' };
    }
    assert.equal(runtime.exitCode, null, 'Worker process crashed on origin failure');
    assert.equal(runtime.signalCode, null);
    assert.equal(await connects(workerPort), true);
    const failureLogDeadline = Date.now() + timeoutMs;
    while (!parseEvents().some(e => e.event === 'allow' && e.correlation_id === 'origin-unreachable')) {
      controller.signal.throwIfAborted();
      assert.ok(Date.now() < failureLogDeadline, 'Upstream failure did not reach the Worker');
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(receipts.length, beforeFailure);
    cases.push({ id: 'origin-unreachable', requestTarget: '/unreachable', ...upstreamFailure, originArrivals: 0, layer: 'workerd-upstream-error' });
    assert.equal(digest(fs.readFileSync(generatedPath)), identity.generatedWorkerSha256, 'Generated Worker was modified');
  } catch (error) { failure = error; }
  finally {
    clearTimeout(watchdog); process.off('SIGINT', abort); process.off('SIGTERM', abort);
    const cleanupErrors: unknown[] = [];
    // Every owned resource gets a cleanup attempt even if an earlier one fails.
    const attempt = async (action: () => unknown) => {
      try { await action(); } catch (error) { cleanupErrors.push(error); }
    };
    await attempt(async () => {
      if (runtime && closed) {
        runtime.kill('SIGTERM');
        try { await deadline(closed, 3000, 'workerd shutdown deadline'); }
        catch { runtime.kill('SIGKILL'); await deadline(closed, 3000, 'workerd kill deadline'); }
        cleanup.runtimeExited = runtime.exitCode !== null || runtime.signalCode !== null;
      } else cleanup.runtimeExited = true;
      if (argv.includes('--fail-cleanup')) throw new Error('Injected cleanup error after runtime shutdown');
    });
    await attempt(async () => {
      origin.closeAllConnections();
      if (origin.listening) await deadline(new Promise<void>((resolve, reject) => origin.close(error => error ? reject(error) : resolve())), 3000, 'Origin shutdown deadline');
      cleanup.originClosed = !origin.listening;
    });
    await attempt(async () => {
      cleanup.workerPortClosed = !workerPort || !await connects(workerPort);
    });
    await attempt(async () => {
      cleanup.originPortClosed = !originPort || !await connects(originPort);
    });
    await attempt(() => {
      fs.rmSync(tmp, { recursive: true, force: true }); cleanup.tempRemoved = !fs.existsSync(tmp);
    });
    await attempt(() => {
      assert.ok(Object.values(cleanup).every(Boolean), 'Incomplete cleanup');
      // Child close also waits for stdio close: delayed Worker output cannot
      // turn the parser's negative evidence into a false pass.
      assert.ok(!parseEvents().some(e => e.correlation_id === 'parser-invalid'), 'Parser request reached the Worker');
    });
    if (cleanupErrors.length) failure = new AggregateError([failure, ...cleanupErrors].filter(Boolean), 'HTTP E2E or cleanup failed');
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, JSON.stringify({ status: failure ? 'fail' : 'pass', identity, cases, receipts, cleanup, workerPid: runtime?.pid, tempDirectory: tmp, runtimeLog, error: failure ? String(failure) : null }, null, 2));
  }
  if (failure) throw failure;
  console.log('Cloudflare HTTP E2E passed; report:', reportPath);
}
main().catch(error => { console.error(error); process.exitCode = 1; });
