#!/usr/bin/env node
"use strict";
/**
 * Pseudo Edge container attack tests.
 *
 * These tests start short-lived local HTTP servers that wrap generated edge
 * artifacts. Incoming HTTP requests are translated into the platform event
 * contracts, executed through the generated runtime, and converted back to an
 * HTTP response. This gives CI a black-box layer above direct handler tests.
 */
Object.defineProperty(exports, "__esModule", { value: true });
const assert = require('assert');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const vm = require('vm');
const { execFileSync } = require('child_process');
const repoRoot = path.join(__dirname, '..');
const EDGE_TOKEN = 'edge-container-test-token';
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
function runNode(script, args, env = {}) {
    execFileSync(process.execPath, [path.join(repoRoot, script), ...args], {
        cwd: repoRoot,
        stdio: 'pipe',
        env: { ...process.env, EDGE_ADMIN_TOKEN: EDGE_TOKEN, ...env },
    });
}
let awsArtifactsCompiled = false;
function ensureAwsArtifactsCompiled() {
    if (awsArtifactsCompiled)
        return;
    runNode('scripts/compile.js', []);
    awsArtifactsCompiled = true;
}
function loadAwsViewerHandler() {
    ensureAwsArtifactsCompiled();
    const code = fs.readFileSync(path.join(repoRoot, 'dist', 'edge', 'viewer-request.js'), 'utf8');
    const sandbox = {
        exports: {},
        console,
        Buffer,
        setTimeout,
        clearTimeout,
    };
    sandbox.global = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(`${code}\nexports.handler = handler;`, sandbox);
    if (typeof sandbox.exports.handler !== 'function') {
        throw new Error('AWS viewer artifact did not expose handler');
    }
    return sandbox.exports.handler;
}
function loadAwsOriginHandler() {
    ensureAwsArtifactsCompiled();
    const code = fs.readFileSync(path.join(repoRoot, 'dist', 'edge', 'origin-request.js'), 'utf8');
    const sandbox = {
        exports: {},
        require,
        console,
        Buffer,
        process: { env: { EDGE_ADMIN_TOKEN: EDGE_TOKEN } },
        setTimeout,
        clearTimeout,
    };
    sandbox.global = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(code, sandbox);
    if (typeof sandbox.exports.handler !== 'function') {
        throw new Error('AWS origin artifact did not expose exports.handler');
    }
    return sandbox.exports.handler;
}
function cfHeadersFromNode(headers) {
    const out = {};
    for (const [name, value] of Object.entries(headers || {})) {
        if (value === undefined)
            continue;
        const v = Array.isArray(value) ? value.join(', ') : String(value);
        out[name.toLowerCase()] = { value: v };
    }
    return out;
}
function lambdaHeadersFromCff(headers) {
    const out = {};
    for (const [name, entry] of Object.entries(headers || {})) {
        const headerEntry = entry;
        const value = headerEntry && headerEntry.value !== undefined ? String(headerEntry.value) : '';
        out[name.toLowerCase()] = [{ key: name, value }];
    }
    return out;
}
function splitUrl(reqUrl) {
    const url = new URL(reqUrl, 'https://edge.test');
    return {
        uri: url.pathname,
        querystring: url.search ? url.search.slice(1) : '',
    };
}
function cffEventFromHttp(req) {
    const { uri, querystring } = splitUrl(req.url);
    return {
        request: {
            method: req.method || 'GET',
            uri,
            querystring,
            headers: cfHeadersFromNode(req.headers),
        },
    };
}
function lambdaEventFromCffRequest(request) {
    return {
        Records: [{
                cf: {
                    request: {
                        method: request.method || 'GET',
                        uri: request.uri || '/',
                        querystring: request.querystring || '',
                        headers: lambdaHeadersFromCff(request.headers),
                    },
                },
            }],
    };
}
function lambdaStatusToHttp(result) {
    if (!result || !result.status)
        return null;
    return Number(result.status);
}
function cffStatusToHttp(result) {
    if (!result || !result.statusCode)
        return null;
    return Number(result.statusCode);
}
function hasHeader(headers, name) {
    return Boolean(headers && headers[name.toLowerCase()]);
}
async function startAwsEdgeHarness() {
    const viewerHandler = loadAwsViewerHandler();
    const originHandler = loadAwsOriginHandler();
    const server = http.createServer(async (req, res) => {
        try {
            const viewerResult = viewerHandler(cffEventFromHttp(req));
            const viewerStatus = cffStatusToHttp(viewerResult);
            if (viewerStatus) {
                res.writeHead(viewerStatus, { 'content-type': 'text/plain' });
                res.end(String(viewerResult.body || viewerResult.statusDescription || 'blocked'));
                return;
            }
            const originResult = await originHandler(lambdaEventFromCffRequest(viewerResult));
            const originStatus = lambdaStatusToHttp(originResult);
            if (originStatus) {
                res.writeHead(originStatus, { 'content-type': 'text/plain' });
                res.end(String(originResult.body || originResult.statusDescription || 'blocked'));
                return;
            }
            const smugglingStripped = ![
                'transfer-encoding',
                'connection',
                'keep-alive',
                'te',
                'upgrade',
                'proxy-connection',
                'trailer',
            ].some((name) => hasHeader(originResult.headers, name));
            const xffStripped = !hasHeader(originResult.headers, 'x-forwarded-for');
            const edgeAuthStripped = !hasHeader(originResult.headers, 'x-edge-authenticated');
            res.writeHead(200, {
                'content-type': 'text/plain',
                'x-harness-smuggling-stripped': String(smugglingStripped),
                'x-harness-xff-stripped': String(xffStripped),
                'x-harness-edge-auth-stripped': String(edgeAuthStripped),
            });
            res.end('origin-ok');
        }
        catch (e) {
            res.writeHead(500, { 'content-type': 'text/plain' });
            res.end(e && e.stack ? e.stack : String(e));
        }
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    return server;
}
function cloudflarePolicy() {
    return `
version: 1
project: edge-container-cf
defaults: { mode: enforce }
request:
  allow_methods: [GET, HEAD]
  limits:
    max_uri_length: 128
    max_query_length: 64
    max_query_params: 10
    max_header_count: 64
  block:
    ua_contains: [sqlmap, nikto]
    path_patterns:
      contains: ['/../', '%2e%2e']
response_headers:
  hsts: "max-age=31536000"
firewall:
  geo:
    block_countries: [RU]
routes:
  - name: admin
    match:
      path_prefixes: ["/admin"]
    auth_gate:
      type: static_token
      header: x-edge-token
      token_env: EDGE_ADMIN_TOKEN
`;
}
function compileCloudflareWorker() {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edge-cf-'));
    try {
        const policyPath = path.join(tmpDir, 'policy.yml');
        const outDir = path.join(tmpDir, 'out');
        fs.writeFileSync(policyPath, cloudflarePolicy(), 'utf8');
        runNode('scripts/compile-cloudflare.js', ['--policy', policyPath, '--out-dir', outDir]);
        const tsSource = fs.readFileSync(path.join(outDir, 'edge', 'cloudflare', 'index.ts'), 'utf8');
        let esbuild;
        try {
            esbuild = require('esbuild');
        }
        catch (_e) {
            console.error('Edge container tests require esbuild. Run npm install first.');
            process.exit(2);
        }
        return esbuild.transformSync(tsSource, {
            loader: 'ts',
            format: 'cjs',
            target: 'es2020',
        }).code;
    }
    finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
}
const REQUIRED_WORKER_GLOBALS = ['crypto', 'Request', 'Response', 'Headers', 'TextEncoder', 'TextDecoder'];
for (const name of REQUIRED_WORKER_GLOBALS) {
    if (typeof globalThis[name] === 'undefined') {
        console.error(`Edge container tests require globalThis.${name} (Node >= 20).`);
        process.exit(2);
    }
}
function loadCloudflareWorker() {
    const logs = [];
    const sandbox = {
        console: {
            log: (...args) => logs.push(['log', args.join(' ')]),
            warn: (...args) => logs.push(['warn', args.join(' ')]),
            error: (...args) => logs.push(['error', args.join(' ')]),
        },
        crypto: globalThis.crypto,
        Request: globalThis.Request,
        Response: globalThis.Response,
        Headers: globalThis.Headers,
        URL: globalThis.URL,
        URLSearchParams: globalThis.URLSearchParams,
        TextEncoder: globalThis.TextEncoder,
        TextDecoder: globalThis.TextDecoder,
        AbortController: globalThis.AbortController,
        AbortSignal: globalThis.AbortSignal,
        atob: globalThis.atob,
        btoa: globalThis.btoa,
        structuredClone: globalThis.structuredClone,
        queueMicrotask: globalThis.queueMicrotask,
        fetch: async () => new Response('origin-ok', { status: 200 }),
        setTimeout,
        clearTimeout,
        Date,
        module: { exports: {} },
        exports: {},
    };
    sandbox.global = sandbox;
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    try {
        vm.runInContext(compileCloudflareWorker(), sandbox);
    }
    catch (e) {
        if (logs.length) {
            console.error('[cloudflare-worker-sandbox] captured logs before crash:');
            for (const [level, msg] of logs)
                console.error(`  ${level}: ${msg}`);
        }
        throw e;
    }
    const worker = sandbox.module.exports.default || sandbox.module.exports;
    if (!worker || typeof worker.fetch !== 'function') {
        throw new Error('Cloudflare artifact did not expose default.fetch');
    }
    return worker;
}
async function startCloudflareEdgeHarness() {
    const worker = loadCloudflareWorker();
    const server = http.createServer(async (req, res) => {
        try {
            const origin = `http://edge.test${req.url}`;
            const headers = new Headers();
            for (const [name, value] of Object.entries(req.headers)) {
                if (name === 'x-harness-cf-country')
                    continue;
                if (Array.isArray(value)) {
                    for (const v of value)
                        headers.append(name, v);
                }
                else if (value !== undefined) {
                    headers.set(name, String(value));
                }
            }
            const request = new Request(origin, { method: req.method || 'GET', headers });
            const country = req.headers['x-harness-cf-country'];
            if (country) {
                Object.defineProperty(request, 'cf', {
                    value: { country: Array.isArray(country) ? country[0] : String(country) },
                });
            }
            const workerRes = await worker.fetch(request, { EDGE_ADMIN_TOKEN: EDGE_TOKEN }, { waitUntil() { }, passThroughOnException() { } });
            const body = await workerRes.text();
            res.writeHead(workerRes.status, Object.fromEntries(workerRes.headers.entries()));
            res.end(body);
        }
        catch (e) {
            res.writeHead(500, { 'content-type': 'text/plain' });
            res.end(e && e.stack ? e.stack : String(e));
        }
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    return server;
}
function portOf(server) {
    return server.address().port;
}
function request(server, method, target, headers = {}) {
    return new Promise((resolve, reject) => {
        const req = http.request({
            host: '127.0.0.1',
            port: portOf(server),
            method,
            path: target,
            headers,
        }, (res) => {
            let body = '';
            res.setEncoding('utf8');
            res.on('data', (chunk) => { body += chunk; });
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
        });
        req.on('error', reject);
        req.end();
    });
}
function fillerHeaders(count) {
    const headers = { 'user-agent': 'Mozilla/5.0' };
    for (let i = 0; i < count - 1; i++)
        headers[`x-filler-${i}`] = 'v';
    return headers;
}
async function runAwsAttackTests() {
    const server = await startAwsEdgeHarness();
    try {
        const cases = [
            ['aws pseudo-edge allows benign request', 'GET', '/', { 'user-agent': 'Mozilla/5.0' }, 200],
            ['aws pseudo-edge blocks missing user-agent', 'GET', '/', {}, 400],
            ['aws pseudo-edge blocks disallowed method', 'DELETE', '/', { 'user-agent': 'Mozilla/5.0' }, 405],
            ['aws pseudo-edge blocks encoded traversal', 'GET', '/a/%2e%2e%2fb', { 'user-agent': 'Mozilla/5.0' }, 400],
            ['aws pseudo-edge blocks scanner user-agent', 'GET', '/', { 'user-agent': 'sqlmap/1.0' }, 403],
            ['aws pseudo-edge blocks admin without token', 'GET', '/admin', { 'user-agent': 'Mozilla/5.0' }, 401],
            ['aws pseudo-edge accepts admin with static token', 'GET', '/admin', { 'user-agent': 'Mozilla/5.0', 'x-edge-token': EDGE_TOKEN }, 200],
            ['aws pseudo-edge blocks header flood', 'GET', '/', fillerHeaders(65), 431],
            ['aws pseudo-edge ignores spoofed auth marker', 'GET', '/admin', { 'user-agent': 'Mozilla/5.0', 'x-edge-authenticated': '1' }, 401],
        ];
        for (const [name, method, target, headers, expected] of cases) {
            await test(name, async () => {
                const res = await request(server, method, target, headers);
                assert.strictEqual(res.status, expected, res.body);
            });
        }
        await test('aws pseudo-edge strips forwarding and smuggling headers before origin', async () => {
            const res = await request(server, 'GET', '/not-protected', {
                'user-agent': 'Mozilla/5.0',
                'x-forwarded-for': '127.0.0.1',
                'x-edge-authenticated': '1',
                connection: 'upgrade',
                te: 'trailers',
                'proxy-connection': 'keep-alive',
            });
            assert.strictEqual(res.status, 200, res.body);
            assert.strictEqual(res.headers['x-harness-smuggling-stripped'], 'true');
            assert.strictEqual(res.headers['x-harness-xff-stripped'], 'true');
            assert.strictEqual(res.headers['x-harness-edge-auth-stripped'], 'true');
        });
    }
    finally {
        if (typeof server.closeAllConnections === 'function')
            server.closeAllConnections();
        await new Promise((resolve) => server.close(resolve));
    }
}
async function runCloudflareAttackTests() {
    const server = await startCloudflareEdgeHarness();
    try {
        const cases = [
            ['cloudflare pseudo-edge allows benign request', 'GET', '/', { 'user-agent': 'Mozilla/5.0' }, 200],
            ['cloudflare pseudo-edge blocks disallowed method', 'DELETE', '/', { 'user-agent': 'Mozilla/5.0' }, 405],
            ['cloudflare pseudo-edge blocks encoded traversal', 'GET', '/a/%2e%2e%2fb', { 'user-agent': 'Mozilla/5.0' }, 400],
            ['cloudflare pseudo-edge blocks scanner user-agent', 'GET', '/', { 'user-agent': 'nikto' }, 403],
            ['cloudflare pseudo-edge blocks oversized URI', 'GET', '/' + 'a'.repeat(200), { 'user-agent': 'Mozilla/5.0' }, 414],
            ['cloudflare pseudo-edge blocks header flood', 'GET', '/', fillerHeaders(65), 431],
            ['cloudflare pseudo-edge blocks admin without token', 'GET', '/admin', { 'user-agent': 'Mozilla/5.0' }, 401],
            ['cloudflare pseudo-edge accepts admin with static token', 'GET', '/admin', { 'user-agent': 'Mozilla/5.0', 'x-edge-token': EDGE_TOKEN }, 200],
            ['cloudflare pseudo-edge blocks configured geo country', 'GET', '/', { 'user-agent': 'Mozilla/5.0', 'x-harness-cf-country': 'RU' }, 403],
        ];
        for (const [name, method, target, headers, expected] of cases) {
            await test(name, async () => {
                const res = await request(server, method, target, headers);
                assert.strictEqual(res.status, expected, res.body);
            });
        }
    }
    finally {
        if (typeof server.closeAllConnections === 'function')
            server.closeAllConnections();
        await new Promise((resolve) => server.close(resolve));
    }
}
async function main() {
    await runAwsAttackTests();
    await runCloudflareAttackTests();
    if (process.exitCode)
        process.exit(process.exitCode);
    console.log('Edge container attack tests passed.');
}
main().catch((e) => {
    console.error('Edge container test harness crashed:', e && e.stack ? e.stack : e);
    process.exit(1);
});
