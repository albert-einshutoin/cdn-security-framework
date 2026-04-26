#!/usr/bin/env node
// @ts-nocheck
// @ts-nocheck
// @ts-nocheck

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

function test(name, fn) {
  try {
    fn();
    console.log('OK:', name);
  } catch (e) {
    console.error('FAIL:', name);
    console.error(e && e.stack ? e.stack : e);
    process.exitCode = 1;
  }
}

const repoRoot = path.join(__dirname, '..');

function compileCloudflare(policyContent) {
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
  // Auth/crypto hardening fixtures
  assert.ok(template.includes('isJwtAlgAllowed'), 'JWT alg whitelist helper missing');
  assert.ok(template.includes('isHostAllowed'), 'Host allowlist helper missing');
  assert.ok(template.includes("forwardHeaders.delete('x-forwarded-for')"),
    'XFF strip missing from forward path');
  assert.ok(/payload\.exp\s*&&\s*nowSec\s*>=\s*payload\.exp\s*\+\s*skewSec/.test(template),
    'JWT clock skew tolerance missing');
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

test('cloudflare compile fails when allowed_algorithms includes an alg the verifier cannot validate', () => {
  let caught;
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
  } catch (e) {
    caught = e;
  }
  assert.ok(caught, 'expected compile-cloudflare to fail validation');
  const stderr = String(caught && caught.stderr ? caught.stderr : '');
  assert.ok(/allowed_algorithms/.test(stderr) && /RS256/.test(stderr),
    'stderr should mention allowed_algorithms and the verifier alg; got:\n' + stderr);
});

if (process.exitCode) {
  process.exit(process.exitCode);
}

console.log('Cloudflare runtime tests passed.');
