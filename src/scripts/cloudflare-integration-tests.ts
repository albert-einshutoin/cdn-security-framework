#!/usr/bin/env node
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

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const { execFileSync } = require('child_process');

const repoRoot = path.join(__dirname, '..');

function createHS256Jwt(payload: Record<string, unknown>, secret: string) {
  const enc = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const data = enc({ alg: 'HS256', typ: 'JWT' }) + '.' + enc(payload);
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  return data + '.' + sig;
}

function createSignedUrlQuery(pathname: string, params: Array<[string, string]>, secret: string) {
  const canonical = params
    .slice()
    .sort((a, b) => a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0]))
    .map(([key, value]) => encodeURIComponent(key) + '=' + encodeURIComponent(value))
    .join('&');
  const payload = canonical ? pathname + '?' + canonical : pathname;
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  return canonical + '&sig=' + sig;
}

function canonicalQuery(params: URLSearchParams) {
  const pairs: Array<[string, string]> = [];
  params.forEach((value, key) => pairs.push([key, value]));
  return pairs
    .sort((a, b) => a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0]))
    .map(([key, value]) => encodeURIComponent(key) + '=' + encodeURIComponent(value))
    .join('&');
}

function challengeUaHash(ua: string) {
  return crypto.createHash('sha256').update(ua || '').digest('hex').slice(0, 16);
}

function findChallengeNonce(seed: string, difficulty: number) {
  const prefix = '0'.repeat(difficulty);
  for (let i = 0; i < 2000000; i++) {
    const nonce = i.toString(16);
    const digest = crypto.createHash('sha256').update(seed + ':' + nonce).digest('hex');
    if (digest.startsWith(prefix)) return nonce;
  }
  throw new Error('could not solve test challenge');
}

function createChallengeSolutionQuery(seed: string, exp: number, ua: string, secret: string, difficulty: number) {
  const sig = crypto.createHmac('sha256', secret)
    .update(seed + ':' + String(exp) + ':' + challengeUaHash(ua))
    .digest('base64url');
  const nonce = findChallengeNonce(seed, difficulty);
  return new URLSearchParams({
    __cdn_challenge_seed: seed,
    __cdn_challenge_exp: String(exp),
    __cdn_challenge_nonce: nonce,
    __cdn_challenge_sig: sig,
  }).toString();
}

function createChallengeCookie(exp: number, ua: string, secret: string) {
  const sig = crypto.createHmac('sha256', secret)
    .update(String(exp) + ':' + challengeUaHash(ua))
    .digest('base64url');
  return `${exp}.${sig}`;
}

function test(name: string, fn: () => unknown | Promise<unknown>) {
  return Promise.resolve()
    .then(fn)
    .then(() => console.log('OK:', name))
    .catch((e: any) => {
      console.error('FAIL:', name);
      console.error(e && e.stack ? e.stack : e);
      process.exitCode = 1;
    });
}

function compileWorker(policyYaml: string, { env = {} }: { env?: Record<string, string> } = {}): string {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-integ-'));
  const policyPath = path.join(tmpDir, 'policy.yml');
  const outDir = path.join(tmpDir, 'out');
  fs.writeFileSync(policyPath, policyYaml, 'utf8');
  execFileSync(
    process.execPath,
    [path.join(repoRoot, 'scripts', 'compile-cloudflare.js'), '--policy', policyPath, '--out-dir', outDir],
    { cwd: repoRoot, stdio: 'pipe', env: { ...process.env, ...env } },
  );
  const tsPath = path.join(outDir, 'edge', 'cloudflare', 'index.ts');
  const tsSource = fs.readFileSync(tsPath, 'utf8');
  fs.rmSync(tmpDir, { recursive: true, force: true });
  return tsSource;
}

function transpileToJs(tsSource: string): string {
  // Strip types, preserve source-equivalent semantics. `format: 'cjs'` so the
  // `export default` binding becomes `module.exports.default`, which we then
  // reach into from the sandbox.
  let esbuild;
  try {
    esbuild = require('esbuild');
  } catch (_e) {
    console.error(
      'Cloudflare integration tests require esbuild. Install it with `npm install --save-dev esbuild`\n' +
      'then re-run `npm run test:cloudflare-integration`.',
    );
    process.exit(2);
  }
  const { code } = esbuild.transformSync(tsSource, {
    loader: 'ts',
    format: 'cjs',
    target: 'es2020',
  });
  return code;
}

function loadWorker(jsCode: string, { env = {}, fetchStub }: any = {}) {
  // Expose the Node-native web fetch primitives inside the sandbox. Node 18+
  // ships all of these on globalThis, so just pass them straight through.
  const logs: string[] = [];
  const defaultFetch = async () =>
    new Response('stub-origin', { status: 200, headers: { 'content-type': 'text/plain' } });
  const sandbox: any = {
    console: {
      log: (...args: unknown[]) => logs.push(args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')),
      error: (...args: unknown[]) => logs.push('[stderr] ' + args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')),
      warn: (...args: unknown[]) => logs.push('[stderr] ' + args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')),
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

async function dispatch(worker: any, url: string, init: RequestInit = {}, env: Record<string, string> = {}) {
  const req = new Request(url, init);
  // Cloudflare passes env as the 2nd arg. ctx (3rd) is unused here.
  const res = await worker.fetch(req, env, { waitUntil() {}, passThroughOnException() {} });
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

  await test('origin auth missing secret fails closed with 503', async () => {
    const originAuthPolicy = BASE_POLICY + `
origin:
  auth:
    type: custom_header
    header: X-Origin-Verify
    secret_env: ORIGIN_SECRET_FOR_MISSING_TEST
`;
    const originJs = transpileToJs(compileWorker(originAuthPolicy, { env: { EDGE_ADMIN_TOKEN: 'integration-test-token' } }));
    let fetched = false;
    const { worker } = loadWorker(originJs, {
      env: { EDGE_ADMIN_TOKEN: 'integration-test-token' },
      fetchStub: async () => {
        fetched = true;
        return new Response('origin', { status: 200 });
      },
    });
    const res = await dispatch(worker, 'https://example.com/hello', {
      method: 'GET',
      headers: { 'user-agent': 'Mozilla/5.0' },
    }, { EDGE_ADMIN_TOKEN: 'integration-test-token' });
    assert.strictEqual(res.status, 503);
    assert.strictEqual(fetched, false, 'origin fetch must not run when origin auth secret is missing');
  });

  await test('origin auth hmac signs upstream request with canonical query', async () => {
    const originAuthPolicy = BASE_POLICY + `
origin:
  auth:
    type: hmac_signature
    secret_env: ORIGIN_HMAC_SECRET
    header_prefix: X-CDN-Auth
    timestamp_tolerance_seconds: 300
    include_body_hash: false
    signed_components: [method, path, query, body, timestamp, nonce]
`;
    const secret = 'cf-origin-hmac-secret';
    const originJs = transpileToJs(compileWorker(originAuthPolicy, { env: { EDGE_ADMIN_TOKEN: 'integration-test-token' } }));
    let forwarded: Request | null = null;
    const { worker } = loadWorker(originJs, {
      env: { EDGE_ADMIN_TOKEN: 'integration-test-token' },
      fetchStub: async (req: Request) => {
        forwarded = req;
        return new Response('origin', { status: 200 });
      },
    });
    const res = await dispatch(worker, 'https://example.com/hello?b=2&a=1', {
      method: 'GET',
      headers: { 'user-agent': 'Mozilla/5.0' },
    }, {
      EDGE_ADMIN_TOKEN: 'integration-test-token',
      ORIGIN_HMAC_SECRET: secret,
    });
    assert.strictEqual(res.status, 200);
    assert.ok(forwarded, 'origin fetch should receive a signed request');
    const ts = forwarded!.headers.get('X-CDN-Auth-Timestamp') || '';
    const nonce = forwarded!.headers.get('X-CDN-Auth-Nonce') || '';
    const sig = forwarded!.headers.get('X-CDN-Auth-Signature') || '';
    const url = new URL(forwarded!.url);
    const canonical = ['GET', '/hello', canonicalQuery(url.searchParams), '', ts, nonce].join('\n');
    const expected = crypto.createHmac('sha256', secret).update(canonical).digest('base64url');
    assert.ok(Math.abs(Math.floor(Date.now() / 1000) - Number(ts)) <= 5, 'timestamp should be fresh');
    assert.ok(/^[0-9a-f]{32}$/.test(nonce), 'nonce should be 16 random bytes as hex');
    assert.strictEqual(sig, expected);
    assert.strictEqual(forwarded!.headers.get('X-CDN-Auth-Body-SHA256'), null);
  });

  await test('JWT missing exp is rejected by Cloudflare worker with 401', async () => {
    const jwtPolicy = BASE_POLICY + `
  - name: api-jwt
    match:
      path_prefixes: ["/api"]
    auth_gate:
      type: jwt
      algorithm: HS256
      secret_env: JWT_SECRET
      issuer: test-issuer
      audience: test-audience
`;
    const jwtJs = transpileToJs(compileWorker(jwtPolicy, {
      env: {
        EDGE_ADMIN_TOKEN: 'integration-test-token',
        JWT_SECRET: 'integration-jwt-secret',
      },
    }));
    const { worker } = loadWorker(jwtJs);
    const token = createHS256Jwt({
      sub: 'user1',
      iss: 'test-issuer',
      aud: 'test-audience',
    }, 'integration-jwt-secret');
    const res = await dispatch(worker, 'https://example.com/api/data', {
      method: 'GET',
      headers: {
        'user-agent': 'Mozilla/5.0',
        authorization: 'Bearer ' + token,
      },
    }, {
      EDGE_ADMIN_TOKEN: 'integration-test-token',
      JWT_SECRET: 'integration-jwt-secret',
    });
    assert.strictEqual(res.status, 401);
    assert.strictEqual(await res.text(), 'Unauthorized');
  });

  await test('signed URL rejects unsigned query selector changes with generic 403', async () => {
    const signedPolicy = BASE_POLICY.replace('max_query_length: 64', 'max_query_length: 256') + `
  - name: assets-signed
    match:
      path_prefixes: ["/assets"]
    auth_gate:
      type: signed_url
      secret_env: URL_SIGNING_SECRET
      expires_param: exp
      signature_param: sig
`;
    const signedJs = transpileToJs(compileWorker(signedPolicy, {
      env: {
        EDGE_ADMIN_TOKEN: 'integration-test-token',
        URL_SIGNING_SECRET: 'integration-url-secret',
      },
    }));
    const { worker } = loadWorker(signedJs);
    const exp = String(Math.floor(Date.now() / 1000) + 3600);
    const signedQuery = createSignedUrlQuery('/assets/file.png', [['exp', exp]], 'integration-url-secret');
    const res = await dispatch(worker, 'https://example.com/assets/file.png?' + signedQuery + '&file=other.png', {
      method: 'GET',
      headers: { 'user-agent': 'Mozilla/5.0' },
    }, {
      EDGE_ADMIN_TOKEN: 'integration-test-token',
      URL_SIGNING_SECRET: 'integration-url-secret',
    });
    assert.strictEqual(res.status, 403);
    assert.strictEqual(await res.text(), 'Forbidden');
  });

  await test('experimental JS challenge returns HTML for matching suspicious path', async () => {
    const challengePolicy = BASE_POLICY.replace('max_query_length: 64', 'max_query_length: 512') + `
firewall:
  challenge:
    enabled: true
    mode: challenge
    path_prefixes: ["/guarded"]
    ua_contains: ["headless-test"]
    difficulty: 1
    ttl_sec: 120
    secret_env: CHALLENGE_SECRET
`;
    const challengeJs = transpileToJs(compileWorker(challengePolicy));
    const { worker } = loadWorker(challengeJs);
    const res = await dispatch(worker, 'https://example.com/guarded/page', {
      method: 'GET',
      headers: { 'user-agent': 'Mozilla/5.0' },
    }, {
      EDGE_ADMIN_TOKEN: 'integration-test-token',
      CHALLENGE_SECRET: 'integration-challenge-secret',
    });
    assert.strictEqual(res.status, 403);
    assert.match(res.headers.get('content-type') || '', /text\/html/);
    assert.match(await res.text(), /Security check/);
  });

  await test('experimental JS challenge accepts solved proof and then solved cookie', async () => {
    const challengePolicy = BASE_POLICY.replace('max_query_length: 64', 'max_query_length: 512') + `
firewall:
  challenge:
    enabled: true
    mode: challenge
    path_prefixes: ["/guarded"]
    difficulty: 1
    ttl_sec: 120
    secret_env: CHALLENGE_SECRET
`;
    const challengeJs = transpileToJs(compileWorker(challengePolicy));
    const { worker } = loadWorker(challengeJs, {
      fetchStub: async () => new Response('guarded ok', { status: 200 }),
    });
    const ua = 'Mozilla/5.0';
    const secret = 'integration-challenge-secret';
    const exp = Math.floor(Date.now() / 1000) + 120;
    const query = createChallengeSolutionQuery('abcdefghijklmnop', exp, ua, secret, 1);
    const solved = await dispatch(worker, 'https://example.com/guarded/page?' + query, {
      method: 'GET',
      headers: { 'user-agent': ua },
    }, {
      EDGE_ADMIN_TOKEN: 'integration-test-token',
      CHALLENGE_SECRET: secret,
    });
    assert.strictEqual(solved.status, 302);
    const setCookie = solved.headers.get('set-cookie') || '';
    assert.match(setCookie, /__cdn_challenge=/);

    const cookieValue = /__cdn_challenge=([^;]+)/.exec(setCookie)?.[1] || '';
    const passed = await dispatch(worker, 'https://example.com/guarded/page', {
      method: 'GET',
      headers: { 'user-agent': ua, cookie: '__cdn_challenge=' + cookieValue },
    }, {
      EDGE_ADMIN_TOKEN: 'integration-test-token',
      CHALLENGE_SECRET: secret,
    });
    assert.strictEqual(passed.status, 200);
    assert.strictEqual(await passed.text(), 'guarded ok');
  });

  await test('experimental JS challenge re-challenges expired or invalid cookies', async () => {
    const challengePolicy = BASE_POLICY.replace('max_query_length: 64', 'max_query_length: 512') + `
firewall:
  challenge:
    enabled: true
    mode: challenge
    path_prefixes: ["/guarded"]
    difficulty: 1
    ttl_sec: 120
    secret_env: CHALLENGE_SECRET
`;
    const challengeJs = transpileToJs(compileWorker(challengePolicy));
    const { worker } = loadWorker(challengeJs);
    const ua = 'Mozilla/5.0';
    const secret = 'integration-challenge-secret';
    const expired = createChallengeCookie(Math.floor(Date.now() / 1000) - 10, ua, secret);
    const res = await dispatch(worker, 'https://example.com/guarded/page', {
      method: 'GET',
      headers: { 'user-agent': ua, cookie: '__cdn_challenge=' + expired },
    }, {
      EDGE_ADMIN_TOKEN: 'integration-test-token',
      CHALLENGE_SECRET: secret,
    });
    assert.strictEqual(res.status, 403);
    assert.match(await res.text(), /Security check/);

    const invalid = await dispatch(worker, 'https://example.com/guarded/page', {
      method: 'GET',
      headers: { 'user-agent': ua, cookie: '__cdn_challenge=9999999999.invalid' },
    }, {
      EDGE_ADMIN_TOKEN: 'integration-test-token',
      CHALLENGE_SECRET: secret,
    });
    assert.strictEqual(invalid.status, 403);
    assert.match(await invalid.text(), /Security check/);
  });

  await test('blocked request emits structured JSON log with status/block_reason/uri', async () => {
    const { worker, logs } = loadWorker(js, { env: { EDGE_ADMIN_TOKEN: 'integration-test-token' } });
    await dispatch(worker, 'https://example.com/a/%2e%2e%2fb', {
      method: 'GET',
      headers: { 'user-agent': 'Mozilla/5.0' },
    });
    const jsonLine = logs.find((l) => l.includes('"event":"block"'));
    assert.ok(jsonLine, 'expected a structured block log; got:\n' + logs.join('\n'));
    const parsed = JSON.parse(jsonLine as string);
    assert.strictEqual(parsed.event, 'block');
    assert.strictEqual(parsed.status, 400);
    assert.strictEqual(parsed.method, 'GET');
    assert.ok(typeof parsed.uri === 'string' && parsed.uri.length > 0);
    assert.ok(typeof parsed.ts === 'number');
  });

  if (process.exitCode) process.exit(process.exitCode);
  console.log('Cloudflare integration tests passed.');
}

runAll().catch((e) => {
  console.error('Test harness crashed:', e && e.stack ? e.stack : e);
  process.exit(1);
});
