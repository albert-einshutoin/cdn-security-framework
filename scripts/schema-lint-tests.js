#!/usr/bin/env node
/**
 * Schema lint tests: exercise `policy-lint.js` against temporary policy files
 * with numeric values that are inside/outside the bounds declared in
 * policy/schema.json. Fails if the lint gate accepts an out-of-range value or
 * rejects an in-range value.
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');

const repoRoot = path.join(__dirname, '..');
const lintScript = path.join(repoRoot, 'scripts', 'policy-lint.js');

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

function writeTempPolicy(policyYaml) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'schema-lint-'));
  const file = path.join(dir, 'policy.yml');
  fs.writeFileSync(file, policyYaml, 'utf8');
  return { dir, file };
}

function runLint(policyPath) {
  return spawnSync(process.execPath, [lintScript, policyPath], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
}

function basePolicy(overrides) {
  return `
version: 1
project: schema-lint-test
request:
  allow_methods: ["GET", "HEAD"]
  limits:
    max_query_length: ${overrides.max_query_length ?? 1024}
    max_query_params: ${overrides.max_query_params ?? 30}
    max_uri_length: ${overrides.max_uri_length ?? 2048}
    max_header_size: ${overrides.max_header_size ?? 8192}
response_headers:
  hsts: "max-age=31536000"
${overrides.extra || ''}
`;
}

test('lint accepts in-range request.limits', () => {
  const { dir, file } = writeTempPolicy(basePolicy({}));
  try {
    const result = runLint(file);
    assert.strictEqual(result.status, 0, `stderr:\n${result.stderr}\nstdout:\n${result.stdout}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lint rejects max_query_length below minimum', () => {
  const { dir, file } = writeTempPolicy(basePolicy({ max_query_length: 0 }));
  try {
    const result = runLint(file);
    assert.notStrictEqual(result.status, 0, 'expected lint to fail');
    assert.match(result.stderr + result.stdout, /max_query_length|>=\s*1|minimum/i);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lint rejects max_query_length above maximum', () => {
  const { dir, file } = writeTempPolicy(basePolicy({ max_query_length: 99999999 }));
  try {
    const result = runLint(file);
    assert.notStrictEqual(result.status, 0, 'expected lint to fail');
    assert.match(result.stderr + result.stdout, /max_query_length|maximum|<=\s*65536/i);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lint rejects max_query_params out of range', () => {
  const { dir, file } = writeTempPolicy(basePolicy({ max_query_params: 5000 }));
  try {
    const result = runLint(file);
    assert.notStrictEqual(result.status, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lint rejects max_uri_length below minimum', () => {
  const { dir, file } = writeTempPolicy(basePolicy({ max_uri_length: 0 }));
  try {
    const result = runLint(file);
    assert.notStrictEqual(result.status, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lint rejects firewall.waf.rate_limit below WAF minimum (100)', () => {
  const yaml = basePolicy({
    extra: `firewall:
  waf:
    rate_limit: 50
    scope: CLOUDFRONT
`,
  });
  const { dir, file } = writeTempPolicy(yaml);
  try {
    const result = runLint(file);
    assert.notStrictEqual(result.status, 0, 'expected lint to fail for rate_limit < 100');
    assert.match(result.stderr + result.stdout, /rate_limit|minimum|>=\s*100/i);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lint accepts firewall.waf.rate_limit at AWS WAF ceiling', () => {
  const yaml = basePolicy({
    extra: `firewall:
  waf:
    rate_limit: 2000000000
    scope: CLOUDFRONT
`,
  });
  const { dir, file } = writeTempPolicy(yaml);
  try {
    const result = runLint(file);
    assert.strictEqual(result.status, 0, `stderr:\n${result.stderr}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lint rejects cors.max_age beyond 86400', () => {
  const yaml = basePolicy({
    extra: `response_headers:
  hsts: "max-age=31536000"
  cors:
    allow_origins: ["https://example.com"]
    max_age: 999999
`,
  });
  const { dir, file } = writeTempPolicy(yaml);
  try {
    const result = runLint(file);
    assert.notStrictEqual(result.status, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lint rejects origin.timeout.read above 60', () => {
  const yaml = basePolicy({
    extra: `origin:
  timeout:
    connect: 5
    read: 120
`,
  });
  const { dir, file } = writeTempPolicy(yaml);
  try {
    const result = runLint(file);
    assert.notStrictEqual(result.status, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lint rejects negative origin.timeout.connect', () => {
  const yaml = basePolicy({
    extra: `origin:
  timeout:
    connect: 0
`,
  });
  const { dir, file } = writeTempPolicy(yaml);
  try {
    const result = runLint(file);
    assert.notStrictEqual(result.status, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lint rejects auth_gate.cache_ttl_sec above 1 day', () => {
  const yaml = basePolicy({
    extra: `routes:
  - name: api-jwt
    match:
      path_prefixes: ["/api"]
    auth_gate:
      type: jwt
      algorithm: RS256
      jwks_url: https://example.com/jwks.json
      issuer: iss
      audience: aud
      cache_ttl_sec: 999999
`,
  });
  const { dir, file } = writeTempPolicy(yaml);
  try {
    const result = runLint(file);
    assert.notStrictEqual(result.status, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lint rejects unknown key at top level (additionalProperties:false)', () => {
  const yaml = basePolicy({}) + '\ntypo_top_level: whatever\n';
  const { dir, file } = writeTempPolicy(yaml);
  try {
    const result = runLint(file);
    assert.notStrictEqual(result.status, 0, 'expected lint to fail');
    assert.match(result.stderr + result.stdout, /additionalProperty|typo_top_level|additional properties/i);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lint rejects unknown key under request.limits', () => {
  const yaml = `
version: 1
project: schema-lint-test
request:
  allow_methods: ["GET"]
  limits:
    max_query_length: 1024
    ratelimit: 100
response_headers:
  hsts: "max-age=31536000"
`;
  const { dir, file } = writeTempPolicy(yaml);
  try {
    const result = runLint(file);
    assert.notStrictEqual(result.status, 0, 'expected lint to fail');
    assert.match(result.stderr + result.stdout, /additional|ratelimit/i);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lint rejects unknown key under firewall.waf', () => {
  const yaml = basePolicy({
    extra: `firewall:
  waf:
    scope: CLOUDFRONT
    rate_limite: 500
`,
  });
  const { dir, file } = writeTempPolicy(yaml);
  try {
    const result = runLint(file);
    assert.notStrictEqual(result.status, 0, 'expected lint to fail');
    assert.match(result.stderr + result.stdout, /additional|rate_limite/i);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lint rejects unknown key inside routes[]', () => {
  const yaml = basePolicy({
    extra: `routes:
  - name: a
    match:
      path_prefixes: ["/a"]
    cache_control: "no-store"
`,
  });
  const { dir, file } = writeTempPolicy(yaml);
  try {
    const result = runLint(file);
    assert.notStrictEqual(result.status, 0, 'expected lint to fail');
    assert.match(result.stderr + result.stdout, /additional|cache_control/i);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lint rejects origin.auth custom_header missing secret_env', () => {
  const yaml = basePolicy({
    extra: `origin:
  auth:
    type: custom_header
    header: X-Origin-Verify
`,
  });
  const { dir, file } = writeTempPolicy(yaml);
  try {
    const result = runLint(file);
    assert.notStrictEqual(result.status, 0, 'expected lint to fail');
    assert.match(result.stderr + result.stdout, /secret_env|required/i);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lint rejects origin.auth.secret_env not matching env-var convention', () => {
  const yaml = basePolicy({
    extra: `origin:
  auth:
    type: custom_header
    header: X-Origin-Verify
    secret_env: "lowercase name"
`,
  });
  const { dir, file } = writeTempPolicy(yaml);
  try {
    const result = runLint(file);
    assert.notStrictEqual(result.status, 0, 'expected lint to fail');
    assert.match(result.stderr + result.stdout, /pattern|secret_env/i);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lint rejects origin.auth.custom_header missing header', () => {
  const yaml = basePolicy({
    extra: `origin:
  auth:
    type: custom_header
    secret_env: ORIGIN_SECRET
`,
  });
  const { dir, file } = writeTempPolicy(yaml);
  try {
    const result = runLint(file);
    assert.notStrictEqual(result.status, 0, 'expected lint to fail');
    assert.match(result.stderr + result.stdout, /header|required/i);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lint accepts complete origin.auth.custom_header', () => {
  const yaml = basePolicy({
    extra: `origin:
  auth:
    type: custom_header
    header: X-Origin-Verify
    secret_env: ORIGIN_SECRET
`,
  });
  const { dir, file } = writeTempPolicy(yaml);
  try {
    const result = runLint(file);
    assert.strictEqual(result.status, 0, `stderr:\n${result.stderr}\nstdout:\n${result.stdout}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

if (process.exitCode) {
  process.exit(process.exitCode);
}

console.log('Schema lint tests passed.');
