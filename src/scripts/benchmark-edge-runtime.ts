#!/usr/bin/env node
/** Local generated-code comparison. No production traffic; origins are in-process stubs. */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { transformSync } from 'esbuild';

const arg = (name: string): string => {
  const at = process.argv.indexOf(name);
  if (at < 0 || !process.argv[at + 1]) throw new Error(`${name} requires a path`);
  return path.resolve(process.argv[at + 1]);
};
const filterIndex = process.argv.indexOf('--only');
const only = filterIndex < 0 ? undefined : process.argv[filterIndex + 1];
if (filterIndex >= 0 && !only) throw new Error('--only requires a workload prefix');
const root = arg('--root'), output = arg('--output'), fixture = arg('--fixture');
const sha = (value: string | Buffer): string => crypto.createHash('sha256').update(value).digest('hex');
const secret = 'synthetic-benchmark-not-for-deploy';
if (!fs.existsSync(fixture)) {
  const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  fs.writeFileSync(fixture, JSON.stringify({ publicJwk: keys.publicKey.export({ format: 'jwk' }),
    privateKey: keys.privateKey.export({ type: 'pkcs8', format: 'pem' }) }), { flag: 'wx', mode: 0o600 });
}
const keys = JSON.parse(fs.readFileSync(fixture, 'utf8'));
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-edge-benchmark-'));
const quiet = { log() {}, error() {} };
const results: any[] = [], generated: any[] = [];
let generation = 0;
function base(): any {
  return { version: 2, defaults: { mode: 'enforce' }, request: { allow_methods: ['GET', 'POST'],
    limits: { max_query_params: 200, max_query_length: 32768 } }, response_headers: {}, observability: { sample_rate: 0 } };
}
function build(policy: any, target: 'aws' | 'cf'): string {
  const folder = path.join(scratch, `generated-${generation++}`); fs.mkdirSync(folder);
  if (target === 'cf') {
    const input = path.join(folder, 'policy.json'); fs.writeFileSync(input, JSON.stringify(policy));
    execFileSync(process.execPath, [path.join(root, 'scripts/compile-cloudflare.js'), '--policy', input, '--out-dir', folder], { stdio: 'pipe' });
  } else require(path.join(root, 'scripts/lib/compile-core')).build(policy,
    { rootDir: root, outDir: folder, optimize: true, env: { EDGE_ADMIN_TOKEN: secret } });
  const source = fs.readFileSync(path.join(folder, target === 'cf' ? 'edge/cloudflare/index.ts' : 'edge/viewer-request.js'), 'utf8');
  generated.push({ target, policySha256: sha(JSON.stringify(policy)), sourceSha256: sha(source), bytes: Buffer.byteLength(source) });
  return source;
}
async function measure(name: string, create: () => Promise<any> | any, count = 100, warmup = 30): Promise<void> {
  if (only && !name.startsWith(only)) return;
  const record: any = { name, countPerBatch: count, warmup, batches: 5 };
  try {
    const scenario = await create(), start = performance.now();
    const cold = await scenario.call(); record.firstRequestMs = performance.now() - start;
    record.outcomeSha256 = sha(JSON.stringify(cold));
    for (let i = 0; i < warmup; i++) await scenario.call();
    record.batchMeansMs = [];
    for (let batch = 0; batch < 5; batch++) {
      const began = performance.now();
      for (let i = 0; i < count; i++) await scenario.call();
      record.batchMeansMs.push((performance.now() - began) / count);
    }
    record.importKeyCalls = scenario.imports?.(); record.status = 'passed';
  } catch (error: any) { record.status = 'failed'; record.error = String(error?.message || error); }
  results.push(record); console.log(JSON.stringify({ name, status: record.status, error: record.error }));
}
function worker(policy: any, request: () => Request, responseBody = 'origin-ok', env: any = {}, jwk?: any): any {
  const source = build(policy, 'cf'); let imports = 0, jwksCalls = 0;
  const subtle = new Proxy(crypto.webcrypto.subtle, { get(target, key) {
    const member = Reflect.get(target, key, target);
    if (key === 'importKey') return (...args: any[]) => { imports++; return Reflect.apply(member, target, args); };
    return typeof member === 'function' ? member.bind(target) : member;
  } });
  const module: any = { exports: {} };
  const origin = async (input: any): Promise<Response> => {
    if (typeof input === 'string') { jwksCalls++; return new Response(JSON.stringify({ keys: [jwk] })); }
    const body = Buffer.from(await input.arrayBuffer());
    if (policy.origin?.auth?.type === 'hmac_signature') {
      const hash = crypto.createHash('sha256').update(body).digest('hex');
      const url = new URL(input.url);
      const components = policy.origin.auth.signed_components || ['method', 'path', 'query', 'body', 'timestamp', 'nonce'];
      const query = Array.from(url.searchParams.entries()).sort(([ak, av], [bk, bv]) => ak < bk ? -1 : ak > bk ? 1 : av < bv ? -1 : av > bv ? 1 : 0)
        .map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v)).join('&');
      const values: any = { method: input.method, path: url.pathname, query,
        body: policy.origin.auth.include_body_hash ? hash : '', timestamp: input.headers.get('x-cdn-auth-timestamp'), nonce: input.headers.get('x-cdn-auth-nonce') };
      const canonical = components.map((component: string) => values[component] || '').join('\n');
      if ((policy.origin.auth.include_body_hash && input.headers.get('x-cdn-auth-body-sha256') !== hash)
        || input.headers.get('x-cdn-auth-signature') !== crypto.createHmac('sha256', secret).update(canonical).digest('base64url')) throw new Error('origin signature/bytes mismatch');
    }
    return new Response(responseBody, { headers: { 'content-type': 'text/plain' } });
  };
  Function('module', 'exports', 'fetch', 'console', 'crypto', transformSync(source, { loader: 'ts', format: 'cjs' }).code)
    (module, module.exports, origin, quiet, { subtle, getRandomValues: crypto.webcrypto.getRandomValues.bind(crypto.webcrypto) });
  return { imports: () => ({ imports, jwksCalls }), call: async () => {
    const response = await module.exports.default.fetch(request(), env);
    const text = await response.text();
    if (response.status !== 200) throw new Error('unexpected status ' + response.status + ': ' + text);
    return { status: response.status, text };
  } };
}
const headers = { 'user-agent': 'local-benchmark' };
async function main(): Promise<void> {
  try {
    for (const count of [0, 500]) await measure(`followup-cf-routes-${count}`, () => {
      const policy = base(); policy.routes = Array.from({ length: count }, (_, i) => ({ name: `r${i}`, match: { path_prefixes: [`/private${i}`] }, auth_gate: { type: 'static_token', token_env: 'TOKEN' } }));
      return worker(policy, () => new Request('https://edge.example/public', { headers }));
    }, 500);
    await measure('followup-cf-headers-64', () => {
      const policy = base(); policy.request.limits.max_header_count = 100; policy.request.limits.max_header_size = 32768;
      const many = { ...headers, ...Object.fromEntries(Array.from({ length: 64 }, (_, i) => ['x-header-' + i, 'value'])) };
      return worker(policy, () => new Request('https://edge.example/public', { headers: many }));
    }, 500);
    const manyQuery = Array.from({ length: 100 }, (_, i) => `key${i}=value%20${i}`).join('&');
    await measure('followup-cf-query-100', () => worker(base(), () => new Request('https://edge.example/public?' + manyQuery, { headers })), 500);
    await measure('followup-cf-query-100-signed-without-query', () => {
      const policy = base(); policy.origin = { auth: { type: 'hmac_signature', secret_env: 'SECRET',
        signed_components: ['method', 'path', 'timestamp', 'nonce'] } };
      return worker(policy, () => new Request('https://edge.example/public?' + manyQuery, { headers }), undefined, { SECRET: secret });
    }, 300);
    await measure('followup-cf-graphql-hash-32768', () => {
      const policy = base(); policy.request.graphql_guard = { endpoint_paths: ['/graphql'], max_body_bytes: 65536 };
      policy.origin = { auth: { type: 'hmac_signature', secret_env: 'SECRET', include_body_hash: true } };
      const body = JSON.stringify({ query: '{ viewer { id } }', padding: 'x'.repeat(32768) });
      return worker(policy, () => new Request('https://edge.example/graphql', { method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body }), undefined, { SECRET: secret });
    }, 200);
    await measure('followup-aws-query-100', () => {
      const handler = Function('console', build(base(), 'aws') + '\nreturn handler;')(quiet);
      const query = Object.fromEntries(Array.from({ length: 100 }, (_, i) => [`key${i}`, { multiValue: [{ value: 'a b' }, { value: '日本語' }] }]));
      return { call() { const result = handler({ request: { method: 'GET', uri: '/public', headers: { 'user-agent': { value: 'local' } }, querystring: query } });
        if (Object.keys(result.querystring).length !== 100 || result.querystring.key99.multiValue[1].value !== '日本語') throw new Error('query changed'); return result; } };
    }, 1000);
    for (const target of ['aws', 'cloudflare']) await measure(`followup-emitter-${target}`, () => {
      const input = path.join(scratch, 'emitter-policy.json'); fs.writeFileSync(input, JSON.stringify(base()));
      const { compileArtifacts } = require(path.join(root, 'emitter'));
      return { call() { const result = compileArtifacts({ policyPath: input, outDir: path.join(scratch, 'emitter-' + target), target, pkgRoot: root, env: {} });
        if (!result.ok) throw new Error(result.errors.join('\n')); return { ok: result.ok, edgeFiles: result.edgeFiles.length, infraFiles: result.infraFiles.length }; } };
    }, 5, 2);
    for (const count of [0, 1, 3, 10]) await measure(`aws-routes-${count}`, () => {
      const policy = base(); policy.routes = Array.from({ length: count }, (_, i) => ({ name: `r${i}`, match: { path_prefixes: [`/PRIVATE${i}`] }, auth_gate: { type: 'static_token', token_env: 'EDGE_ADMIN_TOKEN' } }));
      const handler = Function('console', build(policy, 'aws') + '\nreturn handler;')(quiet);
      return { call() { const result = handler({ request: { method: 'GET', uri: '/public', headers: { 'user-agent': { value: 'local' } }, querystring: {} } }); if (result.uri !== '/public') throw new Error('AWS rejected'); return result; } };
    }, 2000);
    for (const count of [0, 100]) await measure(`aws-query-${count}`, () => {
      const handler = Function('console', build(base(), 'aws') + '\nreturn handler;')(quiet);
      const query = Object.fromEntries(Array.from({ length: count }, (_, i) => [`key${i}`, { value: 'value with spaces' }]));
      return { call() { const result = handler({ request: { method: 'GET', uri: '/public', headers: { 'user-agent': { value: 'local' } }, querystring: query } }); if (Object.keys(result.querystring).length !== count) throw new Error('query changed'); return result; } };
    }, 1000);
    for (const count of [0, 100, 500]) {
      const policy = base(); policy.routes = Array.from({ length: count }, (_, i) => ({ name: `r${i}`, match: { path_prefixes: [`/PRIVATE${i}`] }, auth_gate: { type: 'static_token', token_env: 'EDGE_ADMIN_TOKEN' } }));
      await measure(`cf-routes-${count}-public`, () => worker(policy, () => new Request('https://edge.example/public', { headers })));
      if (count) await measure(`cf-routes-${count}-last-auth`, () => worker(policy, () => new Request(`https://edge.example/private${count - 1}`, { headers: { ...headers, 'x-edge-token': secret } }), undefined, { EDGE_ADMIN_TOKEN: secret }));
    }
    for (const algorithm of ['HS256', 'RS256']) await measure(`cf-jwt-${algorithm}`, () => {
      const policy = base(); policy.routes = [{ name: 'jwt', match: { path_prefixes: ['/private'] }, auth_gate: { type: 'jwt', algorithm, ...(algorithm === 'HS256' ? { secret_env: 'SECRET' } : { jwks_url: 'https://id.example/jwks' }) } }];
      policy.firewall = { jwks: { allowed_hosts: ['id.example'] } };
      const data = Buffer.from(JSON.stringify({ alg: algorithm, kid: 'fixed' })).toString('base64url') + '.' + Buffer.from(JSON.stringify({ exp: 4102444800 })).toString('base64url');
      const signature = algorithm === 'HS256' ? crypto.createHmac('sha256', secret).update(data).digest('base64url') : crypto.sign('sha256', Buffer.from(data), keys.privateKey).toString('base64url');
      return worker(policy, () => new Request('https://edge.example/private', { headers: { ...headers, authorization: 'Bearer ' + data + '.' + signature } }), undefined, { SECRET: secret }, { ...keys.publicJwk, kid: 'fixed', alg: 'RS256' });
    });
    for (const bytes of [1024, 32768]) await measure(`cf-graphql-${bytes}`, () => {
      const policy = base(); policy.request.graphql_guard = { endpoint_paths: ['/graphql'], max_body_bytes: 65536 };
      const body = JSON.stringify({ query: '{ viewer { id } }', padding: 'x'.repeat(bytes) });
      return worker(policy, () => new Request('https://edge.example/graphql', { method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body }));
    });
    for (const action of ['report_only', 'mask']) for (const bytes of [4096, 65536]) await measure(`cf-dlp-${action}-${bytes}`, () => {
      const policy = base(); policy.response_dlp = { enabled: true, action, body: { max_bytes: 131072, content_types: ['text/plain'] } };
      return worker(policy, () => new Request('https://edge.example/public', { headers }), 'sk-live-abcdefghijklmnop '.repeat(Math.ceil(bytes / 25)).slice(0, bytes));
    });
    await measure('cf-dlp-custom-65536', () => {
      const policy = base(); policy.response_dlp = { enabled: true, action: 'mask', detectors: { custom_regex: [{ name: 'custom', pattern: 'TOKEN_[A-Z]{8}' }] }, body: { max_bytes: 131072, content_types: ['text/plain'] } };
      return worker(policy, () => new Request('https://edge.example/public', { headers }), 'TOKEN_ABCDEFGH '.repeat(5000).slice(0, 65536));
    });
    for (const bytes of [0, 1048576]) await measure(`cf-origin-body-hash-${bytes}`, () => {
      const policy = base(); policy.origin = { auth: { type: 'hmac_signature', secret_env: 'SECRET', include_body_hash: true } };
      const body = 'x'.repeat(bytes);
      return worker(policy, () => new Request('https://edge.example/upload', { method: 'POST', headers, body }), undefined, { SECRET: secret });
    });
    await measure('tooling-validate-policy', () => {
      const { validatePolicy } = require(path.join(root, 'validator'));
      return { call() { const result = validatePolicy({ policy: base(), pkgRoot: root, env: {} }); if (!result.ok) throw new Error(result.errors.join('\n')); return result; } };
    }, 10);
    const sourceRoot = path.join(scratch, 'sources'); fs.mkdirSync(sourceRoot);
    fs.writeFileSync(path.join(sourceRoot, 'tsconfig.json'), JSON.stringify({ compilerOptions: { noLib: true, types: [] }, files: ['input.ts'] }));
    fs.writeFileSync(path.join(sourceRoot, 'input.ts'), Array.from({ length: 5000 }, (_, i) => `export const value${i} = ${i};`).join('\n'));
    await measure('tooling-project-load-cached', () => {
      const { loadTypeScriptProject, TypeScriptAnalysisCache } = require(path.join(root, 'source/typescript/project-loader'));
      const { DEFAULT_SOURCE_ANALYSIS_LIMITS } = require(path.join(root, 'source-analysis'));
      const cache = new TypeScriptAnalysisCache();
      return { async call() { const result = await loadTypeScriptProject({ workspaceRoot: sourceRoot, tsconfigPath: 'tsconfig.json', cache, limits: DEFAULT_SOURCE_ANALYSIS_LIMITS }); return { nodes: result.metrics.astNodes, depth: result.metrics.maxDepth, diagnostics: result.diagnostics }; } };
    }, 3, 5);
    const log = path.join(scratch, 'events.jsonl'); fs.writeFileSync(log, (JSON.stringify({ event: 'block', status: 403, uri: '/日本語', block_reason: 'synthetic' }) + '\n').repeat(20000));
    await measure('tooling-analyze-log-20000', () => {
      const { runAnalyze } = require(path.join(root, 'bin/analyze'));
      return { call() { const report = runAnalyze({ input: log, minCount: 10, top: 3 }); return { ...report, summary: { ...report.summary, input: 'fixture.jsonl' } }; } };
    }, 3, 5);
    for (const controllers of [10, 100]) await measure(`tooling-wrapper-aliases-${controllers}`, () => {
      const workload = path.join(scratch, 'aliases');
      require(path.join(root, 'scripts/benchmark-source-analysis')).generateSourceAnalysisWorkload(workload, controllers);
      for (let i = 0; i < controllers; i++) {
        const file = path.join(workload, 'src', 'controller-' + i + '.ts');
        const aliases = ["const holder = { Auth: UseGuards(BenchGuard) };", "const wrapper = { holder };"];
        for (let j = 0; j < 12; j++) aliases.push('const alias' + j + ' = ' + (j ? 'alias' + (j - 1) : 'wrapper') + ';');
        fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace('@HttpController(', aliases.join('\n') + '\n@HttpController(').replace(/@Read/g, '@holder.Auth @Read'));
      }
      const { runSourceAnalyzer, DEFAULT_SOURCE_ANALYSIS_LIMITS } = require(path.join(root, 'source-analysis'));
      const { createNestJsSourceAnalyzer } = require(path.join(root, 'source/nestjs'));
      const analyzer = createNestJsSourceAnalyzer({ public_decorators: [], roles_decorators: [], guard_mappings: { BenchGuard: { auth_kind: 'bearer' } } });
      return { async call() {
        const result = await runSourceAnalyzer(analyzer, { workspaceRoot: workload, entrypoints: ['tsconfig.json'], limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, timeoutMs: 60000, maxDiagnostics: 10000 }, logger: quiet });
        if (result.status !== 'success' || result.result.contract.operations.length !== controllers * 9) throw new Error('wrapper fixture contract');
        return { contract: result.result.contract, diagnostics: result.result.diagnostics };
      } };
    }, 1, 2);
    await measure('tooling-contract-drift-100', () => {
      const { createSecurityContract, projectPolicyToAllowedSurface, compareSecurityContracts } = require(path.join(root, 'contract'));
      const provenance = [{ source: 'openapi', uri: 'fixed.json', pointer: '/', digest: 'sha256:' + 'a'.repeat(64), analyzer: 'benchmark', capability: 'openapi-operations-v1', complete: true }];
      const declared = createSecurityContract({ source: 'openapi', capabilities: { routes: 'complete', parameters: 'complete', requestBodies: 'complete', authentication: 'complete' }, operations: Array.from({ length: 100 }, (_, i) => ({ method: 'GET', path: `/private${i}`, exposure: 'public', auth: { mode: 'none', alternatives: [] }, request: { contentTypes: [], requiredHeaders: [], queryParameters: [], pathParameters: [], headerParameters: [], cookieParameters: [] }, provenance })) });
      const policy = base(); policy.routes = Array.from({ length: 100 }, (_, i) => ({ name: `r${i}`, match: { path_prefixes: [`/private${i}`] }, auth_gate: { type: 'static_token', token_env: 'TOKEN' } }));
      const allowed = projectPolicyToAllowedSurface(policy, { policyDigest: 'sha256:' + 'b'.repeat(64), sourceUri: 'policy/fixed.yml' });
      return { call() { return compareSecurityContracts({ declared, allowed, target: 'cloudflare' }); } };
    }, 3, 5);
    if (only && results.length === 0) throw new Error('unknown workload prefix');
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
    fs.writeFileSync(output, JSON.stringify({ environment: { node: process.version, platform: process.platform, arch: process.arch }, driverSha256: sha(fs.readFileSync(__filename)), fixtureSha256: sha(fs.readFileSync(fixture)), root, results, generated }, null, 2));
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
