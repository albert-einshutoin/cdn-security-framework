#!/usr/bin/env node

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
});

if (process.exitCode) {
  process.exit(process.exitCode);
}

console.log('Cloudflare runtime tests passed.');
