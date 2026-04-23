#!/usr/bin/env node

/**
 * emit-waf subcommand integration: spawn `bin/cli.js emit-waf` in a fresh tmp
 * repo and assert it drops only infra/*.tf.json (no edge/*.js), supports each
 * --target + --rule-group-only + stubbed --format rejections.
 *
 * We use ci-build-token-not-for-deploy for ORIGIN_SECRET so archetypes /
 * policies that reference env vars through schema still lint cleanly (policy
 * lint reads env at build time for origin.auth). The cli-doctor env check is
 * NOT exercised here — that's covered by doctor-unit-tests.js.
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

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
const cliPath = path.join(repoRoot, 'bin', 'cli.js');

const BASIC_AWS_POLICY = `
version: 1
project: emit-waf-test
request:
  allow_methods: [GET, POST]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    scope: CLOUDFRONT
    rate_limit: 1000
    managed_rules:
      - AWSManagedRulesCommonRuleSet
`;

const BASIC_CF_POLICY = `
version: 1
project: emit-waf-cf-test
request:
  allow_methods: [GET]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    scope: CLOUDFRONT
    rate_limit: 1000
`;

function runEmitWaf(policyYaml, extraArgs) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'emit-waf-'));
  const policyDir = path.join(tmp, 'policy');
  fs.mkdirSync(policyDir);
  const policyPath = path.join(policyDir, 'security.yml');
  fs.writeFileSync(policyPath, policyYaml, 'utf8');

  const outDir = path.join(tmp, 'dist');
  const args = ['emit-waf', '-p', policyPath, '-o', outDir].concat(extraArgs || []);

  const result = spawnSync(process.execPath, [cliPath].concat(args), {
    cwd: tmp,
    encoding: 'utf8',
    env: Object.assign({}, process.env, {
      EDGE_ADMIN_TOKEN: 'ci-build-token-not-for-deploy',
      ORIGIN_SECRET: 'ci-origin-secret-not-for-deploy',
    }),
  });

  return {
    tmp,
    outDir,
    policyPath,
    status: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    cleanup() { fs.rmSync(tmp, { recursive: true, force: true }); },
  };
}

test('emit-waf --target aws writes infra/*.tf.json and no edge/', () => {
  const ctx = runEmitWaf(BASIC_AWS_POLICY, ['--target', 'aws']);
  try {
    assert.strictEqual(ctx.status, 0, `emit-waf failed: ${ctx.stderr}`);
    const wafPath = path.join(ctx.outDir, 'infra', 'waf-rules.tf.json');
    assert.ok(fs.existsSync(wafPath), `expected ${wafPath} to exist`);
    const waf = JSON.parse(fs.readFileSync(wafPath, 'utf8'));
    assert.ok(waf.resource && waf.resource.aws_wafv2_rule_group, 'expected AWS WAF rule group');
    // MUST NOT emit edge code — that's the whole point of emit-waf.
    const edgeDir = path.join(ctx.outDir, 'edge');
    assert.ok(!fs.existsSync(edgeDir), `emit-waf must not create dist/edge/, found ${edgeDir}`);
  } finally {
    ctx.cleanup();
  }
});

test('emit-waf --target aws --rule-group-only suppresses web ACL emission', () => {
  const ctx = runEmitWaf(BASIC_AWS_POLICY, ['--target', 'aws', '--rule-group-only']);
  try {
    assert.strictEqual(ctx.status, 0, `emit-waf failed: ${ctx.stderr}`);
    const waf = JSON.parse(fs.readFileSync(path.join(ctx.outDir, 'infra', 'waf-rules.tf.json'), 'utf8'));
    // With --rule-group-only, aws_wafv2_web_acl MUST NOT appear as an output —
    // existing Terraform owns the ACL and attaches this rule group to it.
    assert.ok(!(waf.resource && waf.resource.aws_wafv2_web_acl), 'web ACL must be suppressed in rule-group-only mode');
    assert.ok(waf.resource && waf.resource.aws_wafv2_rule_group, 'rule group must still be emitted');
  } finally {
    ctx.cleanup();
  }
});

test('emit-waf --target cloudflare writes cloudflare-waf.tf.json', () => {
  const ctx = runEmitWaf(BASIC_CF_POLICY, ['--target', 'cloudflare']);
  try {
    assert.strictEqual(ctx.status, 0, `emit-waf failed: ${ctx.stderr}`);
    const cfPath = path.join(ctx.outDir, 'infra', 'cloudflare-waf.tf.json');
    assert.ok(fs.existsSync(cfPath), `expected ${cfPath} to exist`);
    const doc = JSON.parse(fs.readFileSync(cfPath, 'utf8'));
    assert.ok(doc.resource || doc.variable, 'expected Terraform resource/variable block in CF WAF output');
    const edgeDir = path.join(ctx.outDir, 'edge');
    assert.ok(!fs.existsSync(edgeDir), 'emit-waf cloudflare must not emit edge code');
  } finally {
    ctx.cleanup();
  }
});

test('emit-waf --format cloudformation exits 2 with clear message (stubbed)', () => {
  const ctx = runEmitWaf(BASIC_AWS_POLICY, ['--target', 'aws', '--format', 'cloudformation']);
  try {
    assert.strictEqual(ctx.status, 2, 'cloudformation stub must exit 2 so pipelines fail loudly');
    assert.ok(/not yet implemented/i.test(ctx.stderr), `expected "not yet implemented" in stderr, got: ${ctx.stderr}`);
    assert.ok(!fs.existsSync(path.join(ctx.outDir, 'infra')), 'stub must not produce any infra output');
  } finally {
    ctx.cleanup();
  }
});

test('emit-waf --format cdk exits 2 with clear message (stubbed)', () => {
  const ctx = runEmitWaf(BASIC_AWS_POLICY, ['--target', 'aws', '--format', 'cdk']);
  try {
    assert.strictEqual(ctx.status, 2);
    assert.ok(/not yet implemented/i.test(ctx.stderr));
  } finally {
    ctx.cleanup();
  }
});

test('emit-waf rejects unknown --target', () => {
  const ctx = runEmitWaf(BASIC_AWS_POLICY, ['--target', 'gcp']);
  try {
    assert.notStrictEqual(ctx.status, 0);
    assert.ok(/Unknown target/i.test(ctx.stderr));
  } finally {
    ctx.cleanup();
  }
});

test('emit-waf rejects unknown --format', () => {
  const ctx = runEmitWaf(BASIC_AWS_POLICY, ['--target', 'aws', '--format', 'pulumi']);
  try {
    assert.notStrictEqual(ctx.status, 0);
    assert.ok(/Unknown --format/i.test(ctx.stderr));
  } finally {
    ctx.cleanup();
  }
});

test('emit-waf fails when policy file does not exist', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'emit-waf-missing-'));
  try {
    const result = spawnSync(process.execPath, [cliPath, 'emit-waf', '-p', path.join(tmp, 'missing.yml')], {
      cwd: tmp,
      encoding: 'utf8',
      env: process.env,
    });
    assert.notStrictEqual(result.status, 0);
    assert.ok(/Policy file not found/i.test(result.stderr || ''));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('build still emits both edge/ and infra/ (emit-waf does not replace build)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'build-compat-'));
  const policyDir = path.join(tmp, 'policy');
  fs.mkdirSync(policyDir);
  fs.writeFileSync(path.join(policyDir, 'security.yml'), BASIC_AWS_POLICY, 'utf8');
  const outDir = path.join(tmp, 'dist');
  const result = spawnSync(process.execPath, [cliPath, 'build', '-p', path.join(policyDir, 'security.yml'), '-o', outDir], {
    cwd: tmp,
    encoding: 'utf8',
    env: Object.assign({}, process.env, {
      EDGE_ADMIN_TOKEN: 'ci-build-token-not-for-deploy',
      ORIGIN_SECRET: 'ci-origin-secret-not-for-deploy',
    }),
  });
  try {
    assert.strictEqual(result.status, 0, `build failed: ${result.stderr}`);
    assert.ok(fs.existsSync(path.join(outDir, 'edge', 'viewer-request.js')), 'build must still emit edge code');
    assert.ok(fs.existsSync(path.join(outDir, 'infra', 'waf-rules.tf.json')), 'build must still emit infra config');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

if (process.exitCode) {
  process.exit(process.exitCode);
}
