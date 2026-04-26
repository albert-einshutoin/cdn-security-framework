#!/usr/bin/env node
// @ts-nocheck
// @ts-nocheck
// @ts-nocheck

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  runDoctor,
  collectReferencedEnvVars,
  checkNodeVersion,
  checkPolicyExists,
  checkPolicyParses,
  checkSchemaVersion,
  checkEnvVars,
  checkDistWritable,
  checkDependencies,
  tryParsePolicy,
  resolvePolicyPath,
  MIN_NODE_MAJOR,
  MIN_NODE_VERSION,
  SCHEMA_CURRENT_VERSION,
} = require('./cli-doctor.js');

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

function mktmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix || 'doctor-unit-'));
}

const repoRoot = path.join(__dirname, '..');

// ---- collectReferencedEnvVars --------------------------------------------

test('collectReferencedEnvVars: returns [] for policy without env refs', () => {
  const doc = {
    version: 1,
    request: { allow_methods: ['GET'] },
    response_headers: {},
  };
  assert.deepStrictEqual(collectReferencedEnvVars(doc), []);
});

test('collectReferencedEnvVars: picks token_env, credentials_env, secret_env across routes', () => {
  const doc = {
    routes: [
      { name: 'admin', match: { path_prefixes: ['/admin'] }, auth_gate: { type: 'static_token', token_env: 'EDGE_ADMIN_TOKEN' } },
      { name: 'basic', match: { path_prefixes: ['/b'] }, auth_gate: { type: 'basic_auth', credentials_env: 'BASIC_AUTH_CREDS' } },
      { name: 'jwt', match: { path_prefixes: ['/api'] }, auth_gate: { type: 'jwt', algorithm: 'HS256', secret_env: 'JWT_SECRET' } },
      { name: 'signed', match: { path_prefixes: ['/d'] }, auth_gate: { type: 'signed_url', secret_env: 'URL_SIGNING_SECRET' } },
    ],
  };
  assert.deepStrictEqual(
    collectReferencedEnvVars(doc),
    ['BASIC_AUTH_CREDS', 'EDGE_ADMIN_TOKEN', 'JWT_SECRET', 'URL_SIGNING_SECRET']
  );
});

test('collectReferencedEnvVars: picks origin.auth.secret_env', () => {
  const doc = { origin: { auth: { type: 'custom_header', header: 'X-Edge-Secret', secret_env: 'ORIGIN_SECRET' } } };
  assert.deepStrictEqual(collectReferencedEnvVars(doc), ['ORIGIN_SECRET']);
});

test('collectReferencedEnvVars: dedups repeated env names', () => {
  const doc = {
    routes: [
      { name: 'a', match: {}, auth_gate: { type: 'jwt', algorithm: 'HS256', secret_env: 'JWT_SECRET' } },
      { name: 'b', match: {}, auth_gate: { type: 'jwt', algorithm: 'HS256', secret_env: 'JWT_SECRET' } },
    ],
    origin: { auth: { type: 'custom_header', header: 'X', secret_env: 'JWT_SECRET' } },
  };
  assert.deepStrictEqual(collectReferencedEnvVars(doc), ['JWT_SECRET']);
});

test('collectReferencedEnvVars: ignores empty string env names', () => {
  const doc = {
    routes: [
      { name: 'a', match: {}, auth_gate: { type: 'static_token', token_env: '' } },
    ],
  };
  assert.deepStrictEqual(collectReferencedEnvVars(doc), []);
});

// ---- checkNodeVersion ----------------------------------------------------

test('checkNodeVersion: pass at >= MIN_NODE_VERSION', () => {
  const r = checkNodeVersion(`v${MIN_NODE_VERSION}`);
  assert.strictEqual(r.status, 'pass');
});

test('checkNodeVersion: minimum version matches package.json engines.node', () => {
  const pkg = require(path.join(repoRoot, 'package.json'));
  const match = /^>=\s*(\d+\.\d+\.\d+)/.exec(pkg.engines.node);
  assert.ok(match, `unexpected engines.node format: ${pkg.engines.node}`);
  assert.strictEqual(MIN_NODE_VERSION, match[1]);
});

test('checkNodeVersion: fail below required major version', () => {
  const r = checkNodeVersion(`v${MIN_NODE_MAJOR - 2}.5.0`);
  assert.strictEqual(r.status, 'fail');
  assert.strictEqual(r.found, `v${MIN_NODE_MAJOR - 2}.5.0`);
});

test('checkNodeVersion: fail below required minor version', () => {
  const r = checkNodeVersion('v20.11.1');
  assert.strictEqual(r.status, 'fail');
  assert.strictEqual(r.required, `>=${MIN_NODE_VERSION}`);
});

test('checkNodeVersion: fail on unparseable version', () => {
  const r = checkNodeVersion('not-a-version');
  assert.strictEqual(r.status, 'fail');
});

// ---- checkPolicyExists ---------------------------------------------------

test('checkPolicyExists: pass when file exists', () => {
  const tmp = mktmp();
  const p = path.join(tmp, 'p.yml');
  fs.writeFileSync(p, 'version: 1\n');
  try {
    assert.strictEqual(checkPolicyExists(p).status, 'pass');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('checkPolicyExists: fail when file missing', () => {
  const tmp = mktmp();
  try {
    assert.strictEqual(checkPolicyExists(path.join(tmp, 'nope.yml')).status, 'fail');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---- tryParsePolicy + checkPolicyParses ----------------------------------

test('checkPolicyParses: pass on valid yaml object', () => {
  const tmp = mktmp();
  const p = path.join(tmp, 'p.yml');
  fs.writeFileSync(p, 'version: 1\nrequest:\n  allow_methods: [GET]\n');
  try {
    const parsed = tryParsePolicy(p);
    assert.ok(parsed.ok);
    assert.strictEqual(checkPolicyParses(parsed).status, 'pass');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('checkPolicyParses: fail on yaml syntax error', () => {
  const tmp = mktmp();
  const p = path.join(tmp, 'p.yml');
  fs.writeFileSync(p, '::: not yaml :\n  - [unclosed\n');
  try {
    const parsed = tryParsePolicy(p);
    assert.strictEqual(parsed.ok, false);
    assert.strictEqual(checkPolicyParses(parsed).status, 'fail');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('checkPolicyParses: fail on non-object top-level value', () => {
  const r = checkPolicyParses({ ok: true, doc: 'just a string' });
  assert.strictEqual(r.status, 'fail');
});

// ---- checkSchemaVersion --------------------------------------------------

test('checkSchemaVersion: pass when matches current', () => {
  assert.strictEqual(checkSchemaVersion({ version: SCHEMA_CURRENT_VERSION }).status, 'pass');
});

test('checkSchemaVersion: fail when version missing', () => {
  assert.strictEqual(checkSchemaVersion({}).status, 'fail');
});

test('checkSchemaVersion: fail when version mismatched', () => {
  const r = checkSchemaVersion({ version: SCHEMA_CURRENT_VERSION + 1 });
  assert.strictEqual(r.status, 'fail');
  assert.strictEqual(r.found, SCHEMA_CURRENT_VERSION + 1);
  assert.strictEqual(r.expected, SCHEMA_CURRENT_VERSION);
});

test('checkSchemaVersion: skip on null policyDoc', () => {
  assert.strictEqual(checkSchemaVersion(null).status, 'skip');
});

// ---- checkEnvVars --------------------------------------------------------

test('checkEnvVars: pass when policy references no env vars', () => {
  const env = () => undefined;
  const r = checkEnvVars({ routes: [] }, env);
  assert.strictEqual(r.status, 'pass');
});

test('checkEnvVars: fail when referenced env is missing', () => {
  const doc = {
    routes: [{ name: 'a', match: {}, auth_gate: { type: 'static_token', token_env: 'EDGE_ADMIN_TOKEN' } }],
  };
  const r = checkEnvVars(doc, () => undefined);
  assert.strictEqual(r.status, 'fail');
  assert.deepStrictEqual(r.missing, ['EDGE_ADMIN_TOKEN']);
});

test('checkEnvVars: fail when referenced env is empty string', () => {
  const doc = {
    routes: [{ name: 'a', match: {}, auth_gate: { type: 'static_token', token_env: 'EDGE_ADMIN_TOKEN' } }],
  };
  const r = checkEnvVars(doc, (name) => (name === 'EDGE_ADMIN_TOKEN' ? '' : undefined));
  assert.strictEqual(r.status, 'fail');
});

test('checkEnvVars: pass when all referenced env vars are set', () => {
  const doc = {
    routes: [{ name: 'a', match: {}, auth_gate: { type: 'jwt', algorithm: 'HS256', secret_env: 'JWT_SECRET' } }],
    origin: { auth: { type: 'custom_header', header: 'X', secret_env: 'ORIGIN_SECRET' } },
  };
  const env = (name) => ({ JWT_SECRET: 'x', ORIGIN_SECRET: 'y' }[name]);
  const r = checkEnvVars(doc, env);
  assert.strictEqual(r.status, 'pass');
  assert.deepStrictEqual(r.missing, []);
});

test('checkEnvVars: skip when policyDoc is null', () => {
  assert.strictEqual(checkEnvVars(null, () => 'x').status, 'skip');
});

// ---- checkDistWritable ---------------------------------------------------

test('checkDistWritable: pass when cwd is writable', () => {
  const tmp = mktmp();
  try {
    assert.strictEqual(checkDistWritable(tmp).status, 'pass');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// Skip read-only test on platforms where we cannot enforce it reliably.

// ---- checkDependencies ---------------------------------------------------

test('checkDependencies: pass when npm ls has no problems', () => {
  const fakeSpawn = () => ({ stdout: JSON.stringify({ problems: [] }) });
  assert.strictEqual(checkDependencies('/tmp', fakeSpawn).status, 'pass');
});

test('checkDependencies: fail when npm ls reports problems', () => {
  const fakeSpawn = () => ({
    stdout: JSON.stringify({ problems: ['missing: ajv@^8.0.0, required by cdn-security-framework@1.0.0'] }),
  });
  assert.strictEqual(checkDependencies('/tmp', fakeSpawn).status, 'fail');
});

test('checkDependencies: warn when npm is absent / empty stdout', () => {
  const fakeSpawn = () => ({ stdout: '' });
  assert.strictEqual(checkDependencies('/tmp', fakeSpawn).status, 'warn');
});

test('checkDependencies: warn when npm output is not valid JSON', () => {
  const fakeSpawn = () => ({ stdout: 'not json' });
  assert.strictEqual(checkDependencies('/tmp', fakeSpawn).status, 'warn');
});

// ---- resolvePolicyPath ---------------------------------------------------

test('resolvePolicyPath: honours explicit relative path', () => {
  const tmp = mktmp();
  const resolved = resolvePolicyPath(tmp, 'policy/x.yml');
  assert.strictEqual(resolved, path.join(tmp, 'policy/x.yml'));
});

test('resolvePolicyPath: honours explicit absolute path', () => {
  const tmp = mktmp();
  const abs = path.join(tmp, 'some', 'abs.yml');
  assert.strictEqual(resolvePolicyPath('/cwd', abs), abs);
});

test('resolvePolicyPath: prefers security.yml over base.yml', () => {
  const tmp = mktmp();
  fs.mkdirSync(path.join(tmp, 'policy'));
  fs.writeFileSync(path.join(tmp, 'policy', 'security.yml'), 'version: 1');
  fs.writeFileSync(path.join(tmp, 'policy', 'base.yml'), 'version: 1');
  try {
    assert.strictEqual(resolvePolicyPath(tmp), path.join(tmp, 'policy', 'security.yml'));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('resolvePolicyPath: falls back to base.yml when only base exists', () => {
  const tmp = mktmp();
  fs.mkdirSync(path.join(tmp, 'policy'));
  fs.writeFileSync(path.join(tmp, 'policy', 'base.yml'), 'version: 1');
  try {
    assert.strictEqual(resolvePolicyPath(tmp), path.join(tmp, 'policy', 'base.yml'));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---- runDoctor end-to-end ------------------------------------------------

test('runDoctor: clean pass with valid policy + env vars set, writes report', () => {
  const tmp = mktmp();
  const policyDir = path.join(tmp, 'policy');
  fs.mkdirSync(policyDir);
  const policyPath = path.join(policyDir, 'security.yml');
  fs.writeFileSync(policyPath, `
version: 1
request:
  allow_methods: [GET]
response_headers:
  hsts: "max-age=1"
routes:
  - name: admin
    match: { path_prefixes: ["/admin"] }
    auth_gate: { type: static_token, header: "X-Admin-Token", token_env: "ADMIN_TOKEN_FOR_TEST" }
`);
  const result = runDoctor({
    cwd: tmp,
    pkgRoot: repoRoot,
    envProvider: (n) => (n === 'ADMIN_TOKEN_FOR_TEST' ? 'ci-test' : undefined),
    spawnSync: () => ({ stdout: JSON.stringify({ problems: [] }) }),
    log: false,
    reportPath: 'doctor-report.json',
  });
  try {
    assert.strictEqual(result.exitCode, 0);
    const envCheck = result.report.checks.find((c) => c.name === 'env_vars_referenced_by_policy');
    assert.strictEqual(envCheck.status, 'pass');
    const written = JSON.parse(fs.readFileSync(path.join(tmp, 'doctor-report.json'), 'utf8'));
    assert.strictEqual(written.exitCode, 0);
    assert.ok(Array.isArray(written.checks));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('runDoctor: fails when referenced env var is missing', () => {
  const tmp = mktmp();
  fs.mkdirSync(path.join(tmp, 'policy'));
  fs.writeFileSync(path.join(tmp, 'policy', 'security.yml'), `
version: 1
request:
  allow_methods: [GET]
response_headers: {}
routes:
  - name: api
    match: { path_prefixes: ["/api"] }
    auth_gate: { type: jwt, algorithm: HS256, secret_env: MISSING_JWT_SECRET_XYZ }
`);
  const result = runDoctor({
    cwd: tmp,
    pkgRoot: repoRoot,
    envProvider: () => undefined,
    spawnSync: () => ({ stdout: JSON.stringify({ problems: [] }) }),
    log: false,
    reportPath: null,
  });
  try {
    assert.strictEqual(result.exitCode, 1);
    const envCheck = result.report.checks.find((c) => c.name === 'env_vars_referenced_by_policy');
    assert.strictEqual(envCheck.status, 'fail');
    assert.deepStrictEqual(envCheck.missing, ['MISSING_JWT_SECRET_XYZ']);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('runDoctor: fails when policy is missing', () => {
  const tmp = mktmp();
  const result = runDoctor({
    cwd: tmp,
    pkgRoot: repoRoot,
    envProvider: () => undefined,
    spawnSync: () => ({ stdout: JSON.stringify({ problems: [] }) }),
    log: false,
    reportPath: null,
  });
  try {
    assert.strictEqual(result.exitCode, 1);
    const existsCheck = result.report.checks.find((c) => c.name === 'policy_exists');
    assert.strictEqual(existsCheck.status, 'fail');
    const parseCheck = result.report.checks.find((c) => c.name === 'policy_parses');
    assert.strictEqual(parseCheck.status, 'skip');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('runDoctor: reportPath: null skips file write', () => {
  const tmp = mktmp();
  fs.mkdirSync(path.join(tmp, 'policy'));
  fs.writeFileSync(path.join(tmp, 'policy', 'security.yml'), 'version: 1\nrequest:\n  allow_methods: [GET]\nresponse_headers: {}\n');
  const result = runDoctor({
    cwd: tmp,
    pkgRoot: repoRoot,
    envProvider: () => undefined,
    spawnSync: () => ({ stdout: JSON.stringify({ problems: [] }) }),
    log: false,
    reportPath: null,
  });
  try {
    // checkDistWritable legitimately creates dist/edge as a side effect; only
    // assert that no JSON report file appears when reportPath is null.
    const files = fs.readdirSync(tmp);
    assert.ok(!files.includes('doctor-report.json'), 'report file should not be written');
    assert.strictEqual(result.exitCode, 0);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

if (process.exitCode) {
  process.exit(process.exitCode);
}
