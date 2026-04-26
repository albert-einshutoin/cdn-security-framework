#!/usr/bin/env node
"use strict";
// @ts-nocheck
// @ts-nocheck
// @ts-nocheck
/**
 * Cloudflare Worker integration harness.
 *
 * Compiles a policy → TypeScript Worker, transpiles to JS via esbuild, and
 * invokes `fetch()` with real `Request` / `Response` globals (Node ≥ 18).
 * This is deliberately Node-native instead of miniflare: our runtime needs
 * are small (no KV, no Durable Objects), and avoiding the extra dep keeps
 * CI fast and deterministic.
 *
 * Coverage goal: ≥ 6 distinct request/response shapes per issue #27
 *   1. allowed GET on non-protected path
 *   2. blocked path-traversal payload → 400
 *   3. blocked disallowed method → 405
 *   4. blocked URI length → 414
 *   5. blocked UA on deny list → 403
 *   6. admin without token → 401
 *   7. admin with correct static_token → passes gate
 *   8. structured JSON log shape on a block
 */
Object.defineProperty(exports, "__esModule", { value: true });
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const { execFileSync } = require('child_process');
const repoRoot = path.join(__dirname, '..');
function test(name, fn) {
    return Promise.resolve()
        .then(fn)
        .then(() => console.log('OK:', name))
        .catch((e) => {
        console.error('FAIL:', name);
        console.error(e && e.stack ? e.stack : e);
        process.exitCode = 1;
    });
}
function compileWorker(policyYaml, { env = {} } = {}) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-integ-'));
    const policyPath = path.join(tmpDir, 'policy.yml');
    const outDir = path.join(tmpDir, 'out');
    fs.writeFileSync(policyPath, policyYaml, 'utf8');
    execFileSync(process.execPath, [path.join(repoRoot, 'scripts', 'compile-cloudflare.js'), '--policy', policyPath, '--out-dir', outDir], { cwd: repoRoot, stdio: 'pipe', env: { ...process.env, ...env } });
    const tsPath = path.join(outDir, 'edge', 'cloudflare', 'index.ts');
    const tsSource = fs.readFileSync(tsPath, 'utf8');
    fs.rmSync(tmpDir, { recursive: true, force: true });
    return tsSource;
}
function transpileToJs(tsSource) {
    // Strip types, preserve source-equivalent semantics. `format: 'cjs'` so the
    // `export default` binding becomes `module.exports.default`, which we then
    // reach into from the sandbox.
    let esbuild;
    try {
        esbuild = require('esbuild');
    }
    catch (_e) {
        console.error('Cloudflare integration tests require esbuild. Install it with `npm install --save-dev esbuild`\n' +
            'then re-run `npm run test:cloudflare-integration`.');
        process.exit(2);
    }
    const { code } = esbuild.transformSync(tsSource, {
        loader: 'ts',
        format: 'cjs',
        target: 'es2020',
    });
    return code;
}
function loadWorker(jsCode, { env = {}, fetchStub } = {}) {
    // Expose the Node-native web fetch primitives inside the sandbox. Node 18+
    // ships all of these on globalThis, so just pass them straight through.
    const logs = [];
    const defaultFetch = async () => new Response('stub-origin', { status: 200, headers: { 'content-type': 'text/plain' } });
    const sandbox = {
        console: {
            log: (...args) => logs.push(args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')),
            error: (...args) => logs.push('[stderr] ' + args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')),
            warn: (...args) => logs.push('[stderr] ' + args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')),
        },
        crypto: globalThis.crypto,
        Request: globalThis.Request,
        Response: globalThis.Response,
        Headers: globalThis.Headers,
        URL: globalThis.URL,
        URLSearchParams: globalThis.URLSearchParams,
        TextEncoder: globalThis.TextEncoder,
        TextDecoder: globalThis.TextDecoder,
        atob: globalThis.atob,
        btoa: globalThis.btoa,
        // Per-worker fetch stub — captured inside the sandbox so the module
        // closes over _this_ reference rather than the host's live `globalThis.fetch`.
        // Tests that care about pass-through can pass their own stub; the default
        // returns a canned 200 so the worker's forward path doesn't hit the network.
        fetch: typeof fetchStub === 'function' ? fetchStub : defaultFetch,
        setTimeout,
        clearTimeout,
        Date,
        module: { exports: {} },
        exports: {},
        require,
        __env: env,
    };
    sandbox.global = sandbox;
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(jsCode, sandbox);
    const worker = sandbox.module.exports.default || sandbox.module.exports;
    if (!worker || typeof worker.fetch !== 'function') {
        throw new Error('Compiled worker has no default export with fetch()');
    }
    return { worker, logs, env: sandbox.__env };
}
async function dispatch(worker, url, init = {}, env = {}) {
    const req = new Request(url, init);
    // Cloudflare passes env as the 2nd arg. ctx (3rd) is unused here.
    const res = await worker.fetch(req, env, { waitUntil() { }, passThroughOnException() { } });
    return res;
}
const BASE_POLICY = `
version: 1
project: cf-integ
defaults: { mode: enforce }
request:
  allow_methods: [GET, HEAD]
  limits:
    max_uri_length: 128
    max_query_length: 64
    max_query_params: 10
  block:
    ua_contains: [sqlmap, nikto]
    path_patterns:
      contains: ['/../', '%2e%2e']
response_headers:
  hsts: "max-age=31536000"
routes:
  - name: admin
    match:
      path_prefixes: ["/admin"]
    auth_gate:
      type: static_token
      header: x-edge-token
      token_env: EDGE_ADMIN_TOKEN
`;
async function runAll() {
    const ts = compileWorker(BASE_POLICY, { env: { EDGE_ADMIN_TOKEN: 'integration-test-token' } });
    const js = transpileToJs(ts);
    await test('allowed GET on non-protected path returns a non-block response', async () => {
        const { worker } = loadWorker(js, {
            env: { EDGE_ADMIN_TOKEN: 'integration-test-token' },
            fetchStub: async () => new Response('ok', { status: 200, headers: { 'content-type': 'text/plain' } }),
        });
        const res = await dispatch(worker, 'https://example.com/hello', {
            method: 'GET',
            headers: { 'user-agent': 'Mozilla/5.0' },
        }, { EDGE_ADMIN_TOKEN: 'integration-test-token' });
        assert.ok(res.status < 400, `expected a non-error response; got ${res.status}`);
    });
    await test('path traversal payload is blocked with 400', async () => {
        // WHATWG URL normalizes `/a/../b` to `/b`, so we send the percent-encoded
        // form that survives parsing and still trips the contains check.
        const { worker } = loadWorker(js, { env: { EDGE_ADMIN_TOKEN: 'integration-test-token' } });
        const res = await dispatch(worker, 'https://example.com/a/%2e%2e%2fb', {
            method: 'GET',
            headers: { 'user-agent': 'Mozilla/5.0' },
        });
        assert.strictEqual(res.status, 400);
    });
    await test('disallowed method is blocked with 405', async () => {
        const { worker } = loadWorker(js, { env: { EDGE_ADMIN_TOKEN: 'integration-test-token' } });
        const res = await dispatch(worker, 'https://example.com/', {
            method: 'DELETE',
            headers: { 'user-agent': 'Mozilla/5.0' },
        });
        assert.strictEqual(res.status, 405);
    });
    await test('oversized URI is blocked with 414', async () => {
        const { worker } = loadWorker(js, { env: { EDGE_ADMIN_TOKEN: 'integration-test-token' } });
        const longPath = '/' + 'a'.repeat(200);
        const res = await dispatch(worker, 'https://example.com' + longPath, {
            method: 'GET',
            headers: { 'user-agent': 'Mozilla/5.0' },
        });
        assert.strictEqual(res.status, 414);
    });
    await test('UA on deny list is blocked with 403', async () => {
        const { worker } = loadWorker(js, { env: { EDGE_ADMIN_TOKEN: 'integration-test-token' } });
        const res = await dispatch(worker, 'https://example.com/', {
            method: 'GET',
            headers: { 'user-agent': 'sqlmap/1.0' },
        });
        assert.strictEqual(res.status, 403);
    });
    await test('admin request without static token is blocked with 401', async () => {
        const { worker } = loadWorker(js, { env: { EDGE_ADMIN_TOKEN: 'integration-test-token' } });
        const res = await dispatch(worker, 'https://example.com/admin/dashboard', {
            method: 'GET',
            headers: { 'user-agent': 'Mozilla/5.0' },
        }, { EDGE_ADMIN_TOKEN: 'integration-test-token' });
        assert.strictEqual(res.status, 401);
    });
    await test('admin request with correct static token is NOT blocked by auth', async () => {
        const { worker } = loadWorker(js, {
            env: { EDGE_ADMIN_TOKEN: 'integration-test-token' },
            fetchStub: async () => new Response('admin', { status: 200, headers: { 'content-type': 'text/html' } }),
        });
        const res = await dispatch(worker, 'https://example.com/admin/dashboard', {
            method: 'GET',
            headers: { 'user-agent': 'Mozilla/5.0', 'x-edge-token': 'integration-test-token' },
        }, { EDGE_ADMIN_TOKEN: 'integration-test-token' });
        assert.notStrictEqual(res.status, 401);
        assert.ok(res.status < 500, `expected non-5xx; got ${res.status}`);
    });
    await test('blocked request emits structured JSON log with status/block_reason/uri', async () => {
        const { worker, logs } = loadWorker(js, { env: { EDGE_ADMIN_TOKEN: 'integration-test-token' } });
        await dispatch(worker, 'https://example.com/a/%2e%2e%2fb', {
            method: 'GET',
            headers: { 'user-agent': 'Mozilla/5.0' },
        });
        const jsonLine = logs.find((l) => l.includes('"event":"block"'));
        assert.ok(jsonLine, 'expected a structured block log; got:\n' + logs.join('\n'));
        const parsed = JSON.parse(jsonLine);
        assert.strictEqual(parsed.event, 'block');
        assert.strictEqual(parsed.status, 400);
        assert.strictEqual(parsed.method, 'GET');
        assert.ok(typeof parsed.uri === 'string' && parsed.uri.length > 0);
        assert.ok(typeof parsed.ts === 'number');
    });
    if (process.exitCode)
        process.exit(process.exitCode);
    console.log('Cloudflare integration tests passed.');
}
runAll().catch((e) => {
    console.error('Test harness crashed:', e && e.stack ? e.stack : e);
    process.exit(1);
});
