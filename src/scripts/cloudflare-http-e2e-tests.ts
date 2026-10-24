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
import { HTTP_FIXTURE_CASES, HTTP_FIXTURE_POLICY, HTTP_FIXTURE_HEADERS } from './fixtures/cloudflare-http-cases';
import { createHttpArtifactContract, captureHttpArtifactSnapshot, captureHttpArtifactObservation, verifyHttpArtifact, createHttpArtifactBundle, replayHttpArtifact, type HttpArtifactCase, type HttpArtifactSnapshot, type HttpArtifactRawObservation } from '../contract/verification/artifact-http';

const repo = fs.realpathSync(path.resolve(__dirname, '..'));
const argv = process.argv.slice(2);
const reportIndex = argv.indexOf('--report');
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--report') { assert.ok(argv[++i] && !argv[i].startsWith('--'), '--report requires a path'); }
  else assert.ok(['--fail-after-start', '--fail-cleanup', '--jwks-before'].includes(argv[i]), 'Unknown argument');
}
const reportPath = path.resolve(reportIndex < 0 ? 'reports/cloudflare-http-e2e.json' : argv[reportIndex + 1]);
const workerdPath: string = fs.realpathSync(require('workerd').default);
const digest = (bytes: string | Buffer) => crypto.createHash('sha256').update(bytes).digest('hex');
const timeoutMs = 5000;
const token = 'http-e2e-synthetic-admin';
const policy = HTTP_FIXTURE_POLICY;
const expectedContract = createHttpArtifactContract(policy, HTTP_FIXTURE_CASES.filter(test => test.artifact));

type Receipt = { url: string; method: string; headers: http.IncomingHttpHeaders; body: string };
type HttpResult = { status: number; headers: http.IncomingHttpHeaders; body: string; request: HttpArtifactRawObservation['request'] };
type Case = HttpArtifactCase;

// `path`, unlike a URL/fetch client, sends the supplied request-target verbatim.
function request(port: number, test: Case, signal: AbortSignal): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const headers:Record<string,string|undefined> = { ...HTTP_FIXTURE_HEADERS, 'x-e2e-id': test.id, ...(test.credential==='valid'?{'x-edge-token':token}:test.credential==='wrong'?{'x-edge-token':'wrong-synthetic'}:{}), ...test.headers };
    Object.keys(headers).forEach(key => { if (headers[key as keyof typeof headers] === undefined) delete headers[key as keyof typeof headers]; });
    const req = http.request({ hostname: '127.0.0.1', port, path: test.target, method: test.method || 'GET', headers, agent: false, signal }, res => {
      const destinationHost=res.socket.remoteAddress,destinationPort=res.socket.remotePort;
      if(destinationHost!=='127.0.0.1'||typeof destinationPort!=='number'||destinationPort!==port){reject(new Error('HTTP destination binding mismatch'));res.destroy();return;}
      let body = '';
      res.setTimeout(timeoutMs, () => res.destroy(new Error('HTTP response deadline')));
      res.on('data', chunk => { body += chunk; if (body.length > 65536) res.destroy(new Error('HTTP response too large')); });
      res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body, request:{target:test.target,method:test.method??'GET',body:test.body??'',headers:{...headers},destination:{host:destinationHost,port:destinationPort}} }));
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
  const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'csf-http-e2e-')));
  const controller = new AbortController();
  const abort = () => controller.abort(new Error('HTTP E2E interrupted'));
  process.once('SIGINT', abort); process.once('SIGTERM', abort);
  const watchdog = setTimeout(abort, 120000);
  const receipts: Receipt[] = [];
  const cases: Array<Record<string, unknown>> = [];
  const jwksReceipts: Array<{ endpoint: string; at: number; mode: string; kids: string[] }> = [];
  const jwksCases: Array<Record<string, unknown>> = [];
  // Private keys and complete tokens remain in memory and never enter reports.
  const keyA = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const keyB = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicA = { ...keyA.publicKey.export({ format: 'jwk' }), kid: 'key-a', alg: 'RS256' };
  const publicB = { ...keyB.publicKey.export({ format: 'jwk' }), kid: 'key-b', alg: 'RS256' };
  const endpoints = new Map(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'].map(name => [name, { mode: 'ok', keys: [publicA], delay: 20 }]));
  function jwt(kid: string, signingKey = keyA.privateKey, claims: Record<string, unknown> = {}) {
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const data = encode({ alg: 'RS256', kid }) + '.' + encode({ iss: 'synthetic', aud: 'synthetic', exp: Math.floor(Date.now() / 1000) + 3600, ...claims });
    return data + '.' + crypto.sign('sha256', Buffer.from(data), signingKey).toString('base64url');
  }
  let runtime: ChildProcess | undefined;
  let closed: Promise<unknown> | undefined;
  let runtimeLog = '';
  const parseEvents = () => runtimeLog.split('\n').flatMap(line => {
    try { return [JSON.parse(line.slice(line.indexOf('{')))]; } catch { return []; }
  });
  let workerPort = 0, negativePort = 0;
  const runStartedAt = Date.now();
  const artifactInputs:Array<{variant:'normal'|'weakened-policy';caseId:string;correlationId:string;recordedAtMs:number;response:HttpResult;origins:HttpArtifactRawObservation['origins']}>=[];
  let normalSnapshot:HttpArtifactSnapshot|undefined, negativeSnapshot:HttpArtifactSnapshot|undefined;
  const caseErrors:unknown[]=[];
  let artifactVerification:Record<string,unknown> = {state:'Error',code:'EXECUTION_INCOMPLETE'};
  let originPort = 0;
  let failure: unknown;
  let identity: Record<string, unknown> = {};
  const origin = http.createServer(async (req, res) => {
    try {
    if (req.url?.startsWith('/jwks/')) {
      const name = req.url.slice('/jwks/'.length);
      const endpoint = endpoints.get(name);
      assert.ok(endpoint, 'Unexpected JWKS endpoint');
      jwksReceipts.push({ endpoint: name, at: Date.now(), mode: endpoint.mode, kids: endpoint.keys.map(key => key.kid) });
      if (endpoint.mode === 'hang') return;
      if (endpoint.mode === 'body-hang') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.flushHeaders(); res.write('{"keys":'); return;
      }
      await new Promise(resolve => setTimeout(resolve, endpoint.delay));
      if (endpoint.mode === 'redirect') {
        res.writeHead(302, { location: 'http://169.254.169.254/metadata' }); res.end(); return;
      }
      res.writeHead(endpoint.mode === '5xx' ? 503 : 200, { 'content-type': 'application/json' });
      res.end(endpoint.mode === 'bad-json' ? '{' : JSON.stringify({ keys: endpoint.keys }));
      return;
    }
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const receipt = { url: req.url!, method: req.method!, headers: { ...req.headers, ...(req.headers.authorization ? { authorization: '[redacted synthetic JWT]' } : {}) }, body: Buffer.concat(chunks).toString() };
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
  const cleanup = { runtimeExited: false, originClosed: false, tempRemoved: false, workerPortClosed: false, originPortClosed: false, negativePortClosed:false };
  try {
    originPort = await listen(origin, controller.signal);
    const reservation = net.createServer();
    workerPort = await listen(reservation, controller.signal);
    await new Promise<void>((resolve, reject) => reservation.close(error => error ? reject(error) : resolve()));
    const negativeReservation=net.createServer();
    negativePort=await listen(negativeReservation,controller.signal);
    await new Promise<void>((resolve,reject)=>negativeReservation.close(error=>error?reject(error):resolve()));
    const childEnv = { PATH: process.env.PATH, TMPDIR: tmp };
    // Observe the actual compiler reads and CJS modules; do not scan unrelated repo modules.
    const preloadPath=path.join(tmp,'compiler-receipt.cjs');
    const preload=`const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const read=fs.readFileSync,root=${JSON.stringify(repo)},fixture=${JSON.stringify(tmp)},files=new Map();
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function observe(name,bytes){if(typeof name!=='string')return;const absolute=path.resolve(name);let logical;
if(absolute.startsWith(root+path.sep)&&!absolute.includes(path.sep+'node_modules'+path.sep))logical='repo/'+path.relative(root,absolute);
else if(absolute===path.resolve(process.env.CSF_ACTUAL_POLICY))logical='fixture/'+path.relative(fixture,absolute);else return;
const digest=sha(bytes);if(files.has(logical)&&files.get(logical).sha256!==digest)throw Error('COMPILER_INPUT_CHANGED');files.set(logical,{name:logical,sha256:digest,bytes:Buffer.byteLength(bytes)});}
fs.readFileSync=function(name,...args){const bytes=read.call(fs,name,...args);observe(name,bytes);return bytes;};
process.on('exit',()=>{for(const name of Object.keys(require.cache))if(name.startsWith(root+path.sep)&&!name.includes(path.sep+'node_modules'+path.sep))observe(name,read.call(fs,name));
fs.writeFileSync(process.env.CSF_COMPILER_RECEIPT,JSON.stringify({entry:'repo/'+path.relative(root,process.argv[1]),files:[...files.values()].sort((a,b)=>a.name.localeCompare(b.name,'en'))}));});`;
    fs.writeFileSync(preloadPath,preload,{mode:0o600});
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
    function compile(policyFile:string,outDir:string,variant:string) {
      const receipt=path.join(tmp,variant+'-compiler.json');
      execFileSync(process.execPath,['--require',preloadPath,cli,'build','--policy',policyFile,'--target','cloudflare','--out-dir',outDir],{cwd:tmp,env:{...childEnv,CSF_COMPILER_RECEIPT:receipt,CSF_ACTUAL_POLICY:path.join(tmp,policyFile)},timeout:15000,stdio:'pipe'});
      const recorded=JSON.parse(fs.readFileSync(receipt,'utf8')) as {entry:string;files:Array<{name:string;sha256:string;bytes:number}>};
      assert.equal(recorded.entry,'repo/bin/cli.js');assert.ok(recorded.files.length>0&&recorded.files.length<=200);
      assert.ok(recorded.files.some(f=>f.name==='fixture/'+policyFile&&f.sha256===digest(fs.readFileSync(path.join(tmp,policyFile)))),'Compiler must actually read its declared Policy');
      return recorded.files;
    }
    const compilerFiles=compile('policy/security.yml','dist','normal');
    const authLine='    auth_gate: { type: static_token, header: x-edge-token, token_env: EDGE_ADMIN_TOKEN }';
    assert.equal(policy.split(authLine).length,2);
    const weakPolicy=policy.replace(authLine,'    # Verification negative: admin auth gate deliberately omitted');
    fs.writeFileSync(path.join(tmp,'policy/weak-security.yml'),weakPolicy,{mode:0o600});
    const negativeCompilerFiles=compile('policy/weak-security.yml','weak-dist','negative');
    const generatedPath = path.join(tmp, 'dist/edge/cloudflare/index.ts');
    const generated = fs.readFileSync(generatedPath);
    // Same type erasure as deployment tooling; no replacement of fetch or Worker code.
    const { code } = require('esbuild').transformSync(generated.toString(), { loader: 'ts', format: 'esm', target: 'es2022' });
    fs.writeFileSync(path.join(tmp, 'worker.mjs'), code);
    const negativeGeneratedPath=path.join(tmp,'weak-dist/edge/cloudflare/index.ts'),negativeGenerated=fs.readFileSync(negativeGeneratedPath);
    const negativeCode=require('esbuild').transformSync(negativeGenerated.toString(),{loader:'ts',format:'esm',target:'es2022'}).code as string;
    fs.writeFileSync(path.join(tmp,'weak-worker.mjs'),negativeCode);
    const config = `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [
    (name = "worker", worker = (modules = [(name = "worker.mjs", esModule = embed "worker.mjs")],
      compatibilityDate = ${JSON.stringify(date)}, compatibilityFlags = ${JSON.stringify(flags)},
      bindings = [(name = "EDGE_ADMIN_TOKEN", text = ${JSON.stringify(token)})], globalOutbound = "origin")),
    (name = "weak-worker", worker = (modules = [(name = "weak-worker.mjs", esModule = embed "weak-worker.mjs")],
      compatibilityDate = ${JSON.stringify(date)}, compatibilityFlags = ${JSON.stringify(flags)},
      bindings = [(name = "EDGE_ADMIN_TOKEN", text = ${JSON.stringify(token)})], globalOutbound = "origin")),
    (name = "origin", external = (address = "127.0.0.1:${originPort}", http = ())),
    (name = "internet", network = (allow = [], deny = ["0.0.0.0/0", "::/0"]))
  ],
  sockets = [(name = "http", address = "127.0.0.1:${workerPort}", http = (), service = "worker"), (name = "negative-http", address = "127.0.0.1:${negativePort}", http = (), service = "weak-worker")]
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
    const sourcePaths=[
      ...Object.keys(require.cache).filter(p=>p.startsWith(repo+path.sep)&&!p.includes(path.sep+'node_modules'+path.sep)).map(absolute=>({name:path.relative(repo,absolute),absolute})),
      ...['src/scripts/cloudflare-http-e2e-tests.ts','src/scripts/fixtures/cloudflare-http-cases.ts','src/contract/verification/artifact-http.ts'].map(name=>({name,absolute:path.join(repo,name)})),
      {name:'dependencies/esbuild-main.js',absolute:require.resolve('esbuild')},
      {name:'dependencies/workerd-wrapper.js',absolute:require.resolve('workerd')},
    ].map(p=>({...p,sha256:digest(fs.readFileSync(p.absolute))}));
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
    assert.equal(await connects(negativePort),true,'Negative service must share the native runtime');
    if (argv.includes('--fail-after-start')) throw new Error('Injected cleanup check after workerd startup');

    const wait = async (milliseconds: number) => {
      await new Promise(resolve => setTimeout(resolve, milliseconds));
      controller.signal.throwIfAborted();
    };
    async function jwtGroup(id: string, endpoint: string, tokens: string[], expectedStatus: number, parallel = false, maxFetches = 0) {
      const startedAt = Date.now();
      const beforeJwks = jwksReceipts.length;
      const beforeApp = receipts.length;
      const send = (signed: string, i: number) => request(workerPort, { id: id + '-' + i, target: '/jwt-' + endpoint, headers: { authorization: 'Bearer ' + signed }, status: expectedStatus }, controller.signal);
      const responses: HttpResult[] = [];
      if (parallel) responses.push(...await Promise.all(tokens.map(send)));
      else for (let i = 0; i < tokens.length; i++) responses.push(await send(tokens[i], i));
      const observed = { id, endpoint, startedAt, endedAt: Date.now(), requests: tokens.length, parallel, responses: responses.map(r => r.status), jwksArrivals: jwksReceipts.slice(beforeJwks), appArrivals: receipts.slice(beforeApp).filter(r => String(r.headers['x-e2e-id']).startsWith(id + '-')).length, maxFetches };
      jwksCases.push(observed);
      assert.ok(responses.every(r => r.status === expectedStatus), id + ': JWT status');
      assert.equal(observed.appArrivals, expectedStatus === 200 ? tokens.length : 0, id + ': app arrivals');
      assert.ok(observed.jwksArrivals.length <= maxFetches, id + ': JWKS amplification (' + observed.jwksArrivals.length + ')');
      if (expectedStatus === 200) assert.ok(responses.every(r => String(r.headers['cache-control']).includes('no-store')), id + ': protected response');
      return observed;
    }
    const first = await jwtGroup('unknown-32', 'a', Array.from({ length: 32 }, (_, i) => jwt('unknown-' + i)), 401, false, 2);
    assert.ok(first.endedAt - first.startedAt < 5000, 'Burst must remain in one fixed window');
    if (argv.includes('--jwks-before')) throw new Error('Before reproduction unexpectedly passed');
    const larger = await jwtGroup('unknown-128', 'a', Array.from({ length: 128 }, (_, i) => jwt('larger-' + i)), 401);
    assert.ok(larger.endedAt - first.startedAt < 5000, 'Both bursts must share one window');
    await jwtGroup('known-fresh', 'a', [jwt('key-a')], 200);
    await jwtGroup('wrong-signature', 'a', [jwt('key-a', keyB.privateKey)], 401);
    await jwtGroup('wrong-claims', 'a', [jwt('key-a', keyA.privateKey, { iss: 'wrong' }), jwt('key-a', keyA.privateKey, { aud: 'wrong' })], 401);
    await jwtGroup('cold-parallel', 'b', Array.from({ length: 32 }, (_, i) => jwt('cold-' + i)), 401, true, 2);
    await jwtGroup('fresh-parallel-repeat', 'b', Array.from({ length: 32 }, () => jwt('cold-0')), 401, true);
    // The same kid used on A must not couple B's keys or failure state.
    await jwtGroup('endpoint-b-known', 'b', [jwt('key-a')], 200);
    await jwtGroup('expiry-seed', 'c', [jwt('key-a')], 200, false, 1);
    await wait(1100);
    await jwtGroup('expired-parallel', 'c', Array.from({ length: 32 }, (_, i) => jwt('expired-' + i)), 401, true, 1);
    await jwtGroup('expired-known', 'c', [jwt('key-a')], 200);
    await jwtGroup('rotation-before', 'a', [jwt('key-b', keyB.privateKey)], 401);
    endpoints.get('a')!.keys.push(publicB);
    jwksCases.push({ id: 'rotation-key-update', at: Date.now(), endpoint: 'a', kids: ['key-a', 'key-b'] });
    // Continue misses until a fixed original boundary, without rewriting the Worker clock.
    while (Date.now() < first.startedAt + 4800) {
      await jwtGroup('rotation-attack-' + jwksCases.length, 'a', [jwt('continued-' + jwksCases.length)], 401);
      await wait(250);
    }
    await wait(Math.max(0, first.startedAt + 5100 - Date.now()));
    await jwtGroup('rotation-parallel', 'a', Array.from({ length: 16 }, () => jwt('key-b', keyB.privateKey)), 200, true, 1);
    await jwtGroup('rotation-fresh', 'a', [jwt('key-b', keyB.privateKey)], 200);
    await jwtGroup('endpoint-key-isolation', 'b', [jwt('key-b', keyB.privateKey)], 401, false, 1);

    const faultSeed = await jwtGroup('fault-seed', 'd', [jwt('key-a')], 200, false, 1);
    endpoints.get('d')!.mode = '5xx';
    await wait(1100);
    await jwtGroup('5xx-stale-parallel', 'd', Array.from({ length: 16 }, () => jwt('key-a')), 200, true, 1);
    await jwtGroup('5xx-unknown-negative', 'd', [jwt('unknown-fault')], 401);
    await jwtGroup('endpoint-b-during-d-fault', 'b', [jwt('key-a')], 200);
    await wait(2100);
    await jwtGroup('stale-expired-throttled', 'd', [jwt('key-a')], 401);
    await wait(Math.max(0, faultSeed.startedAt + 5100 - Date.now()));
    endpoints.get('d')!.mode = 'bad-json';
    await jwtGroup('bad-json-parallel', 'd', Array.from({ length: 16 }, () => jwt('key-a')), 401, true, 1);
    await jwtGroup('bad-json-negative', 'd', [jwt('key-a')], 401);
    endpoints.get('d')!.mode = 'ok';
    await wait(1100);
    await jwtGroup('failure-recovery', 'd', [jwt('key-a')], 200, false, 1);
    endpoints.get('f')!.mode = 'hang';
    const fetchDeadline = await jwtGroup('fetch-deadline', 'f', [jwt('key-a')], 401, false, 1);
    assert.ok(fetchDeadline.endedAt - fetchDeadline.startedAt >= 1800 && fetchDeadline.endedAt - fetchDeadline.startedAt < 4000, 'Fetch deadline timing');
    endpoints.get('f')!.mode = 'ok';
    await wait(1100);
    await jwtGroup('deadline-recovery', 'f', [jwt('key-a')], 200, false, 1);
    endpoints.get('g')!.mode = 'redirect';
    await jwtGroup('redirect-rejected', 'g', [jwt('key-a')], 401, false, 1);
    await jwtGroup('redirect-negative', 'g', [jwt('key-a')], 401);
    endpoints.get('i')!.mode = 'body-hang';
    const bodyDeadline = await jwtGroup('body-deadline', 'i', [jwt('key-a')], 401, false, 1);
    assert.ok(bodyDeadline.endedAt - bodyDeadline.startedAt >= 1800 && bodyDeadline.endedAt - bodyDeadline.startedAt < 4000, 'Body deadline timing');
    endpoints.get('i')!.mode = 'ok';
    await wait(1100);
    await jwtGroup('body-deadline-recovery', 'i', [jwt('key-a')], 200, false, 1);
    await jwtGroup('shared-ttl-seed', 'h', [jwt('key-a')], 200, false, 1);
    endpoints.get('h')!.mode = '5xx';
    endpoints.get('h')!.delay = 200;
    await wait(4100);
    const long = jwtGroup('shared-ttl-long', 'h', [jwt('key-a')], 200, false, 1);
    // Receipt proves the long caller's network fetch is pending before short joins.
    const pendingDeadline = Date.now() + timeoutMs;
    while (!jwksReceipts.some(r => r.endpoint === 'h' && r.mode === '5xx')) {
      assert.ok(Date.now() < pendingDeadline, 'Shared TTL fetch did not start'); await wait(5);
    }
    const short = jwtGroup('shared-ttl-short', 'short', [jwt('key-a')], 401);
    await Promise.all([long, short]);
    origin.closeAllConnections();
    await new Promise<void>((resolve, reject) => origin.close(error => error ? reject(error) : resolve()));
    await jwtGroup('connection-refused', 'e', [jwt('key-a')], 401);
    origin.listen(originPort, '127.0.0.1');
    await once(origin, 'listening', { signal: controller.signal });
    await jwtGroup('connection-negative', 'e', [jwt('key-a')], 401);
    await wait(1100);
    await jwtGroup('connection-recovery', 'e', [jwt('key-a')], 200, false, 1);

    const tests = HTTP_FIXTURE_CASES;
    for (const test of tests) {
      const before = receipts.length;
      const startedAt = performance.now();
      const result = await request(workerPort, test, controller.signal);
      const elapsedMs = performance.now() - startedAt;
      const observed = receipts.slice(before);
      if(test.artifact)artifactInputs.push({variant:'normal',caseId:test.id,correlationId:test.id,recordedAtMs:Date.now(),response:result,origins:observed.map((receipt,i)=>({arrival:before+i,receipt}))});
      cases.push({ id: test.id, requestTarget: test.target, method: test.method || 'GET', elapsedMs, response: result, origin: observed, expectedStatus: test.status });
      try {
      if(!test.artifact){
      assert.equal(result.status, test.status, test.id + ': status');
      assert.equal(observed.length, test.forwarded ? 1 : 0, test.id + ': origin arrivals');
      if (test.forwarded) {
        assert.equal(observed[0].url, test.forwarded, test.id + ': forwarded URL');
        assert.equal(observed[0].method, test.method || 'GET');
        assert.equal(observed[0].body, test.body || '');
      }
      }
      if(test.forwarded&&observed.length===1){
        assert.equal(result.headers['strict-transport-security'], 'max-age=100');
        assert.equal(result.headers['x-content-type-options'], 'nosniff');
        assert.equal(result.headers['referrer-policy'], 'same-origin');
        if (test.id === 'post') {
          assert.equal(observed[0].headers['content-type'], 'application/json');
          assert.equal(observed[0].headers['x-forwarded-for'], undefined);
          assert.equal(observed[0].headers['x-edge-authenticated'], undefined);
        }
        if(!test.artifact){
          if (test.id === 'origin-error') assert.equal(result.body, 'synthetic-origin-failure');
          else assert.deepEqual(JSON.parse(result.body), observed[0]);
        }
      }
      console.log(test.artifact?'OBSERVED:':'OK:', test.id);
      } catch (error) { caseErrors.push(error); console.error('FAIL:', test.id, String(error)); }
    }
    // Prove policy rejection from the Worker's own log, not only an HTTP status.
    const logDeadline = Date.now() + timeoutMs;
    while (!tests.filter(t => !t.forwarded&&!t.artifact).every(t => parseEvents().some(e => e.correlation_id === t.id && e.event === 'block'))) {
      controller.signal.throwIfAborted();
      assert.ok(Date.now() < logDeadline, 'Worker rejection log deadline');
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    const negativeTests=['admin-missing','admin-wrong','admin-valid','prefix-boundary'].map(id=>tests.find(t=>t.id===id)!);
    for(const test of negativeTests){
      const before=receipts.length,correlationId='negative-'+test.id;
      const response=await request(negativePort,{...test,id:correlationId},controller.signal);
      artifactInputs.push({variant:'weakened-policy',caseId:test.id,correlationId,recordedAtMs:Date.now(),response,origins:receipts.slice(before).map((receipt,i)=>({arrival:before+i,receipt}))});
    }
    const events = parseEvents();
    for (const test of tests.filter(t => !t.forwarded&&!t.artifact)) {
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
    const runtimeBinary=fs.readFileSync(workerdPath),finishedAtMs=Date.now();
    const file=(role:string,name:string,bytes:Buffer,expectedSha256:string)=>({role,name,bytes,expectedSha256});
    const common=[
      file('lock','package-lock.json',fs.readFileSync(path.join(repo,'package-lock.json')),String(identity.packageLockSha256)),
      file('runtime-binary','workerd',runtimeBinary,String(identity.runtimeSha256)),
      file('runtime-config','config.capnp',fs.readFileSync(path.join(tmp,'config.capnp')),String(identity.configSha256)),
      file('source-module','generated/wrangler.toml',fs.readFileSync(path.join(tmp,'wrangler.toml')),digest(wrangler)),
      file('source-module','compiler-receipt.cjs',fs.readFileSync(preloadPath),digest(preload)),
      ...sourcePaths.map(p=>file('source-module',p.name,fs.readFileSync(p.absolute),p.sha256)),
    ];
    function snapshot(variant:'normal'|'weakened-policy') {
      const negative=variant==='weakened-policy';
      const actualPolicy=negative?'policy/weak-security.yml':'policy/security.yml';
      const compiler=(negative?negativeCompilerFiles:compilerFiles).map(f=>{
        const absolute=f.name.startsWith('repo/')?path.join(repo,f.name.slice(5)):path.join(tmp,f.name.slice(8));
        return file('compiler-module',f.name,fs.readFileSync(absolute),f.sha256);
      });
      return captureHttpArtifactSnapshot(expectedContract,{
        variant,
        files:[
          ...common,
          file('policy',actualPolicy,fs.readFileSync(path.join(tmp,actualPolicy)),digest(negative?weakPolicy:policy)),
          file('generated-ts','worker.ts',fs.readFileSync(negative?negativeGeneratedPath:generatedPath),digest(negative?negativeGenerated:generated)),
          file('module','worker.mjs',fs.readFileSync(path.join(tmp,negative?'weak-worker.mjs':'worker.mjs')),digest(negative?negativeCode:code)),
          ...compiler,
        ],
        runtime:{
          version:String(identity.runtimeVersion),packageVersion:String(identity.workerd),
          compatibilityDate:date,compatibilityFlags:flags,network:'deny-all-loopback-origin',
        },
        metadata:{
          runId:variant+'-'+digest(config).slice(0,16),sourceCommit:String(identity.source),
          startedAtMs:runStartedAt,finishedAtMs,originPort,workerPort:negative?negativePort:workerPort,
          service:negative?'weak-worker':'worker',esbuildVersion:require('esbuild').version,
          policyDerivation:negative
            ? {operation:'remove-admin-static-token-gate',parentPolicySha256:digest(policy),actualPolicySha256:digest(weakPolicy)}
            : {operation:'unchanged-policy',actualPolicySha256:digest(policy)},
          workingTree:execFileSync('git',['status','--porcelain=v2','--untracked-files=all'],{cwd:repo,encoding:'utf8'}),
        },
        credentials:{valid:token,wrong:'wrong-synthetic'},
      });
    }
    assert.equal(runtime.spawnfile,workerdPath);assert.deepEqual(runtime.spawnargs,[workerdPath,'serve','config.capnp']);
    identity.nativeProcess={executablePathSha256:digest(workerdPath),executableSha256:digest(runtimeBinary),arguments:['serve','config.capnp'],configSha256:identity.configSha256};
    normalSnapshot=snapshot('normal');negativeSnapshot=snapshot('weakened-policy');
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
    await attempt(async () => {cleanup.negativePortClosed=!negativePort||!await connects(negativePort);});
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
    try {
      if(failure||!normalSnapshot||!negativeSnapshot)throw new Error('HTTP_EXECUTION_FAILED: '+String(failure??'snapshot missing'));
      const evaluate=(variant:'normal'|'weakened-policy',snapshot:HttpArtifactSnapshot)=>{
        const observed=artifactInputs.filter(i=>i.variant===variant).map(i=>captureHttpArtifactObservation(snapshot,{caseId:i.caseId,correlationId:i.correlationId,recordedAtMs:i.recordedAtMs,request:i.response.request,response:i.response,origins:i.origins,events:parseEvents().filter(e=>e.correlation_id===i.correlationId)}));
        const result=verifyHttpArtifact(expectedContract,snapshot,observed),bundle=createHttpArtifactBundle(expectedContract,snapshot,observed);
        assert.equal(replayHttpArtifact(expectedContract,JSON.parse(JSON.stringify(bundle)),bundle.digest).semanticDigest,result.semanticDigest);
        return {result,bundle,trustedBundleDigest:bundle.digest};
      };
      const normal=evaluate('normal',normalSnapshot),negative=evaluate('weakened-policy',negativeSnapshot);
      artifactVerification={state:'complete',normal,negative};
      assert.equal(normal.result.semantic.verdict,'VERIFIED','Normal generated artifact must meet the entire fixed fixture');
      assert.equal(negative.result.semantic.verdict,'VIOLATED','Weakened artifact must be detected without weakening the oracle');
      console.log('OK: fixed artifact fixture VERIFIED; weakened artifact VIOLATED');
      console.log('Artifact bundle digests:',JSON.stringify({normal:normal.bundle.digest,negative:negative.bundle.digest}));
      if(caseErrors.length)throw new AggregateError(caseErrors,'Existing HTTP regression expectations failed');
    } catch(error){if(artifactVerification.state!=='complete')artifactVerification={state:'Error',code:'HTTP_EXECUTION_FAILED',error:String(error)};failure=failure??error;}
    identity.runtimeLogSha256=digest(runtimeLog);
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, JSON.stringify({ status: failure ? 'fail' : 'pass', artifactVerification, identity, jwksCases, jwksReceipts, cases, receipts, cleanup, workerPid: runtime?.pid, tempDirectory: tmp, runtimeLog, error: failure ? String(failure) : null }, (_key,value)=>typeof value==='string'?value.replaceAll(token,'[credential:valid]').replaceAll('wrong-synthetic','[credential:wrong]'):value, 2));
  }
  if (failure) throw failure;
  console.log('Cloudflare HTTP E2E passed; report:', reportPath);
}
main().catch(error => { console.error(error); process.exitCode = 1; });
