#!/usr/bin/env node

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');
const esbuild = require('esbuild');

const tests: Array<{ name: string; fn: () => void | Promise<void> }> = [];

function test(name: string, fn: () => void | Promise<void>) {
  tests.push({ name, fn });
}

async function runTests() {
  for (const t of tests) {
  try {
      await t.fn();
      console.log('OK:', t.name);
  } catch (e: any) {
      console.error('FAIL:', t.name);
    console.error(e && e.stack ? e.stack : e);
    process.exitCode = 1;
  }
  }
}

const repoRoot = path.join(__dirname, '..');

function compileCloudflare(policyContent: string): string {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-runtime-'));
  const policyPath = path.join(tempDir, 'policy.yml');
  const outDir = path.join(tempDir, 'out');

  fs.writeFileSync(policyPath, policyContent, 'utf8');
  execFileSync(process.execPath, [path.join(repoRoot, 'scripts', 'compile-cloudflare.js'), '--policy', policyPath, '--out-dir', outDir], {
    cwd: repoRoot,
    stdio: 'pipe',
  });

  const generatedPath = path.join(outDir, 'edge', 'cloudflare', 'index.ts');
  const generated = fs.readFileSync(generatedPath, 'utf8');

  fs.rmSync(tempDir, { recursive: true, force: true });
  return generated;
}

function compileAws(policyContent: string): { status: number | null; stderr: string } {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aws-runtime-'));
  const policyPath = path.join(tempDir, 'policy.yml');
  const outDir = path.join(tempDir, 'out');

  fs.writeFileSync(policyPath, policyContent, 'utf8');
  const result = spawnSync(process.execPath, [path.join(repoRoot, 'scripts', 'compile.js'), '--policy', policyPath, '--out-dir', outDir, '--allow-placeholder-token'], {
    cwd: repoRoot,
    encoding: 'utf8',
  });

  fs.rmSync(tempDir, { recursive: true, force: true });
  return { status: result.status, stderr: result.stderr || '' };
}

async function runGeneratedWorker(generated: string, query: string, options: any = {}) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-worker-'));
  const modPath = path.join(tempDir, 'worker.cjs');
  const compiled = esbuild.transformSync(generated, {
    loader: 'ts',
    format: 'cjs',
    target: 'es2022',
  }).code;

  const previousFetch = globalThis.fetch;
  const fetchCalls: any[] = [];
  (globalThis as any).fetch = async (input: any) => {
    fetchCalls.push(input);
    return new Response(options.originBody || 'origin-ok', {
      status: options.originStatus || 200,
      headers: options.originHeaders || {},
    });
  };

  try {
    fs.writeFileSync(modPath, compiled, 'utf8');
    delete require.cache[modPath];
    const worker = require(modPath).default;
    const body = options.rawBody || JSON.stringify({ query });
    const req = new Request(options.url || 'https://edge.example.com/graphql', {
      method: 'POST',
      headers: {
        'user-agent': 'runtime-test',
        'content-type': options.contentType || 'application/json',
      },
      body,
    });
    const res = await worker.fetch(req, {});
    return { res, fetchCalls };
  } finally {
    (globalThis as any).fetch = previousFetch;
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

async function runGeneratedWorkerRequest(generated: string, request: any, options: any = {}) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-worker-'));
  const modPath = path.join(tempDir, 'worker.cjs');
  const compiled = esbuild.transformSync(generated, {
    loader: 'ts',
    format: 'cjs',
    target: 'es2022',
  }).code;

  const previousFetch = globalThis.fetch;
  const fetchCalls: any[] = [];
  (globalThis as any).fetch = async (input: any) => {
    fetchCalls.push(input);
    return new Response(options.originBody || 'origin-ok', {
      status: options.originStatus || 200,
      headers: options.originHeaders || {},
    });
  };

  try {
    fs.writeFileSync(modPath, compiled, 'utf8');
    delete require.cache[modPath];
    const worker = require(modPath).default;
    const res = await worker.fetch(request, options.env || {});
    return { res, fetchCalls };
  } finally {
    (globalThis as any).fetch = previousFetch;
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

test('cloudflare compile injects jwt, signed_url, and origin auth config', () => {
  const generated = compileCloudflare(`
version: 1
project: cloudflare-auth-test
request:
  allow_methods: ["GET", "HEAD"]
response_headers:
  hsts: "max-age=31536000"
routes:
  - name: api-jwt
    match:
      path_prefixes: ["/api"]
    auth_gate:
      type: jwt
      algorithm: HS256
      secret_env: JWT_SECRET
      issuer: issuer
      audience: audience
  - name: assets-signed
    match:
      path_prefixes: ["/assets"]
    auth_gate:
      type: signed_url
      secret_env: URL_SIGNING_SECRET
      expires_param: exp
      signature_param: sig
origin:
  auth:
    type: custom_header
    header: X-Origin-Verify
    secret_env: ORIGIN_SECRET
`);

  assert.ok(generated.includes('"type":"jwt"'));
  assert.ok(generated.includes('"type":"signed_url"'));
  assert.ok(/originAuth:\s*\{"type":"custom_header"/.test(generated));
});

test('cloudflare template contains auth enforcement logic', () => {
  const templatePath = path.join(repoRoot, 'templates', 'cloudflare', 'index.ts');
  const template = fs.readFileSync(templatePath, 'utf8');

  assert.ok(template.includes('async function verifyJwt'));
  assert.ok(template.includes('async function verifySignedUrl'));
  assert.ok(template.includes('if (gate.type === \'jwt\')'));
  assert.ok(template.includes('if (gate.type === \'signed_url\')'));
  assert.ok(template.includes('CFG.originAuth'));
  assert.ok(template.includes('forwardHeaders.set(headerName, secret)'));
  assert.ok(template.includes('async function handleChallenge'), 'challenge handler missing');
  assert.ok(template.includes('verifyChallengeCookie'), 'challenge cookie verifier missing');
  assert.ok(template.includes('verifyChallengeSolution'), 'challenge proof verifier missing');
  // Auth/crypto hardening fixtures
  assert.ok(template.includes('isJwtAlgAllowed'), 'JWT alg whitelist helper missing');
  assert.ok(template.includes('isHostAllowed'), 'Host allowlist helper missing');
  assert.ok(template.includes("forwardHeaders.delete('x-forwarded-for')"),
    'XFF strip missing from forward path');
  assert.ok(template.includes('Missing exp claim'), 'JWT exp-required guard missing');
  assert.ok(/nowSec\s*>=\s*Number\(payload\.exp\)\s*\+\s*skewSec/.test(template),
    'JWT clock skew tolerance missing');
  assert.ok(template.includes('function shouldBlockAuth'), 'auth fail-closed helper missing');
});

test('cloudflare blocks raw traversal before dot-segment normalization', async () => {
  const generated = compileCloudflare(`
version: 1
project: cf-raw-path-test
request:
  allow_methods: ["GET"]
  limits:
    max_query_length: 1024
    max_query_params: 30
    max_uri_length: 2048
  block:
    path_patterns:
      contains:
        - "/../"
  normalize:
    path:
      collapse_slashes: true
      remove_dot_segments: true
response_headers:
  hsts: "max-age=31536000"
`);

  const headers = new Headers({ 'user-agent': 'runtime-test' });
  const request = {
    url: 'https://edge.example.com/public/../private',
    method: 'GET',
    headers,
    body: null,
    redirect: 'manual',
    clone: () => new Request('https://edge.example.com/private', { method: 'GET', headers }),
  };

  const { res, fetchCalls } = await runGeneratedWorkerRequest(generated, request);
  assert.strictEqual(res.status, 400);
  assert.strictEqual(fetchCalls.length, 0, 'raw traversal should block before origin fetch');
});

test('cloudflare compile emits experimental challenge config', () => {
  const generated = compileCloudflare(`
version: 1
project: cf-challenge-test
request:
  allow_methods: ["GET"]
response_headers:
  hsts: "max-age=31536000"
firewall:
  challenge:
    enabled: true
    mode: challenge
    path_prefixes: ["/guarded"]
    ua_contains: ["HeadlessChrome"]
    difficulty: 2
    ttl_sec: 600
    secret_env: CHALLENGE_SECRET
`);

  assert.ok(generated.includes('challenge: {"enabled":true'));
  assert.ok(generated.includes('"pathPrefixes":["/guarded"]'));
  assert.ok(generated.includes('"uaContains":["headlesschrome"]'));
  assert.ok(generated.includes('"difficulty":2'));
  assert.ok(generated.includes('"ttlSec":600'));
});

test('cloudflare compile emits allowedHosts, trustForwardedFor, and JWT alg/skew fields', () => {
  const generated = compileCloudflare(`
version: 1
project: cf-hardening-test
request:
  allow_methods: ["GET"]
  allowed_hosts: ["API.example.com", "*.edge.example.com"]
  trust_forwarded_for: false
response_headers:
  hsts: "max-age=31536000"
routes:
  - name: api-jwt
    match:
      path_prefixes: ["/api"]
    auth_gate:
      type: jwt
      algorithm: RS256
      jwks_url: https://example.com/jwks.json
      issuer: test
      audience: test
      allowed_algorithms: ["RS256", "none"]
      clock_skew_sec: 60
`);

  assert.ok(generated.includes('allowedHosts: ["api.example.com","*.edge.example.com"]'),
    'allowedHosts emitted lowercased;\n' + (generated.match(/allowedHosts: .*/)?.[0] || ''));
  assert.ok(/trustForwardedFor:\s*false/.test(generated));
  assert.ok(generated.includes('"allowed_algorithms":["RS256"]'),
    'allowed_algorithms emitted without "none" or cross-alg entries');
  assert.ok(generated.includes('"clock_skew_sec":60'));
});

test('cloudflare graphql guard allows normal GraphQL POST', async () => {
  const generated = compileCloudflare(`
version: 1
project: cf-graphql-test
request:
  allow_methods: ["POST"]
  graphql_guard:
    endpoint_paths: ["/graphql"]
    max_depth: 4
    max_aliases: 2
    max_fields: 8
response_headers:
  hsts: "max-age=31536000"
`);

  const { res, fetchCalls } = await runGeneratedWorker(generated, 'query { viewer { id name } }');
  assert.strictEqual(res.status, 200);
  assert.strictEqual(fetchCalls.length, 1, 'normal GraphQL query should reach origin');
});

test('cloudflare graphql guard blocks deep GraphQL POST', async () => {
  const generated = compileCloudflare(`
version: 1
project: cf-graphql-test
request:
  allow_methods: ["POST"]
  graphql_guard:
    endpoint_paths: ["/graphql"]
    max_depth: 2
    max_aliases: 10
    max_fields: 20
response_headers:
  hsts: "max-age=31536000"
`);

  const { res, fetchCalls } = await runGeneratedWorker(generated, 'query { a { b { c } } }');
  assert.strictEqual(res.status, 400);
  assert.strictEqual(fetchCalls.length, 0, 'deep GraphQL query should not reach origin');
});

test('cloudflare graphql guard blocks excessive aliases and repeated fields', async () => {
  const generated = compileCloudflare(`
version: 1
project: cf-graphql-test
request:
  allow_methods: ["POST"]
  graphql_guard:
    endpoint_paths: ["/graphql"]
    max_depth: 4
    max_aliases: 1
    max_fields: 3
response_headers:
  hsts: "max-age=31536000"
`);

  const aliased = await runGeneratedWorker(generated, 'query { a: viewer { id } b: viewer { id } }');
  assert.strictEqual(aliased.res.status, 400);
  assert.strictEqual(aliased.fetchCalls.length, 0);

  const fields = await runGeneratedWorker(generated, 'query { viewer { id name email createdAt } }');
  assert.strictEqual(fields.res.status, 400);
  assert.strictEqual(fields.fetchCalls.length, 0);
});

test('cloudflare graphql guard blocks malformed GraphQL body', async () => {
  const generated = compileCloudflare(`
version: 1
project: cf-graphql-test
request:
  allow_methods: ["POST"]
  graphql_guard:
    endpoint_paths: ["/graphql"]
    max_depth: 4
response_headers:
  hsts: "max-age=31536000"
`);

  const { res, fetchCalls } = await runGeneratedWorker(generated, 'query { viewer { id }', {
    rawBody: JSON.stringify({ query: 'query { viewer { id }' }),
  });
  assert.strictEqual(res.status, 400);
  assert.strictEqual(fetchCalls.length, 0);
});

test('cloudflare graphql guard report mode logs and forwards violations', async () => {
  const generated = compileCloudflare(`
version: 1
project: cf-graphql-test
request:
  allow_methods: ["POST"]
  graphql_guard:
    endpoint_paths: ["/graphql"]
    max_depth: 1
    mode: report
response_headers:
  hsts: "max-age=31536000"
`);

  const { res, fetchCalls } = await runGeneratedWorker(generated, 'query { viewer { id } }');
  assert.strictEqual(res.status, 200);
  assert.strictEqual(fetchCalls.length, 1, 'report mode should forward GraphQL violations');
});

test('cloudflare compile fails when allowed_algorithms includes an alg the verifier cannot validate', () => {
  let caught: any;
  try {
    compileCloudflare(`
version: 1
project: cf-hardening-test
request:
  allow_methods: ["GET"]
response_headers:
  hsts: "max-age=31536000"
routes:
  - name: api-jwt
    match:
      path_prefixes: ["/api"]
    auth_gate:
      type: jwt
      algorithm: RS256
      jwks_url: https://example.com/jwks.json
      issuer: test
      audience: test
      allowed_algorithms: ["HS256"]
`);
  } catch (e: any) {
    caught = e;
  }
  assert.ok(caught, 'expected compile-cloudflare to fail validation');
  const stderr = String(caught && caught.stderr ? caught.stderr : '');
  assert.ok(/allowed_algorithms/.test(stderr) && /RS256/.test(stderr),
    'stderr should mention allowed_algorithms and the verifier alg; got:\n' + stderr);
});

test('cloudflare response DLP masks response body and headers', async () => {
  const generated = compileCloudflare(`
version: 1
project: cf-dlp-mask-test
request:
  allow_methods: ["POST"]
response_headers:
  hsts: "max-age=31536000"
response_dlp:
  enabled: true
  action: mask
  mask: "[MASKED]"
  body:
    max_bytes: 4096
    content_types: ["application/json"]
  headers:
    names: ["x-api-key"]
`);

  const { res } = await runGeneratedWorker(generated, 'query { viewer { id } }', {
    originBody: '{"secret":"sk-live-abcdefghijklmnop","card":"4111 1111 1111 1111"}',
    originHeaders: {
      'content-type': 'application/json',
      'x-api-key': 'ghp_abcdefghijklmnop',
    },
  });
  const body = await res.text();
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.headers.get('x-edge-dlp'), 'mask');
  assert.strictEqual(res.headers.get('x-api-key'), '[MASKED]');
  assert.ok(!body.includes('sk-live-abcdefghijklmnop'), body);
  assert.ok(!body.includes('4111 1111 1111 1111'), body);
  assert.ok(body.includes('[MASKED]'), body);
});

test('cloudflare response DLP blocks response body findings', async () => {
  const generated = compileCloudflare(`
version: 1
project: cf-dlp-block-test
request:
  allow_methods: ["POST"]
response_headers:
  hsts: "max-age=31536000"
response_dlp:
  enabled: true
  action: block
  block_status: 451
`);

  const { res } = await runGeneratedWorker(generated, 'query { viewer { id } }', {
    originBody: 'token ghp_abcdefghijklmnop',
    originHeaders: { 'content-type': 'text/plain' },
  });
  assert.strictEqual(res.status, 451);
  assert.strictEqual(res.headers.get('x-edge-dlp'), 'block');
  assert.match(await res.text(), /Response blocked by edge DLP/);
});

test('cloudflare response DLP report-only logs but leaves response unchanged', async () => {
  const generated = compileCloudflare(`
version: 1
project: cf-dlp-report-test
request:
  allow_methods: ["POST"]
response_headers:
  hsts: "max-age=31536000"
response_dlp:
  enabled: true
  action: report_only
`);

  const { res } = await runGeneratedWorker(generated, 'query { viewer { id } }', {
    originBody: 'token ghp_abcdefghijklmnop',
    originHeaders: { 'content-type': 'text/plain' },
  });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.headers.get('x-edge-dlp'), 'report_only');
  assert.strictEqual(await res.text(), 'token ghp_abcdefghijklmnop');
});

test('cloudflare compile rejects unsafe response DLP custom regex', () => {
  let caught: any;
  try {
    compileCloudflare(`
version: 1
project: cf-dlp-redos-test
request:
  allow_methods: ["GET"]
response_headers:
  hsts: "max-age=31536000"
response_dlp:
  enabled: true
  detectors:
    custom_regex:
      - name: bad
        pattern: "^(a+)+$"
`);
  } catch (e: any) {
    caught = e;
  }
  assert.ok(caught, 'expected compile-cloudflare to reject nested quantifier custom regex');
  const stderr = String(caught && caught.stderr ? caught.stderr : '');
  assert.ok(/response_dlp/.test(stderr) && /ReDoS/.test(stderr), 'stderr should mention response_dlp ReDoS guard; got:\n' + stderr);
});

test('aws compile warns response DLP is unsupported for CloudFront Functions', () => {
  const result = compileAws(`
version: 1
project: aws-dlp-unsupported-test
request:
  allow_methods: ["GET"]
response_headers:
  hsts: "max-age=31536000"
response_dlp:
  enabled: true
  action: block
`);

  assert.strictEqual(result.status, 0);
  assert.ok(/response_dlp is enabled/.test(result.stderr), result.stderr);
  assert.ok(/CloudFront Functions cannot inspect response bodies/.test(result.stderr), result.stderr);
});

runTests().then(() => {
  if (process.exitCode) {
    process.exit(process.exitCode);
  }
  console.log('Cloudflare runtime tests passed.');
});
