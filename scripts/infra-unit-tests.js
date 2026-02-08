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

function runCompileInfra(policyContent) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'infra-unit-'));
  const policyPath = path.join(tempDir, 'policy.yml');
  const outDir = path.join(tempDir, 'out');
  fs.writeFileSync(policyPath, policyContent, 'utf8');

  execFileSync(process.execPath, [path.join(repoRoot, 'scripts', 'compile-infra.js'), '--policy', policyPath, '--out-dir', outDir], {
    cwd: repoRoot,
    stdio: 'pipe',
  });

  return {
    tempDir,
    read(rel) {
      return JSON.parse(fs.readFileSync(path.join(outDir, rel), 'utf8'));
    },
    cleanup() {
      fs.rmSync(tempDir, { recursive: true, force: true });
    },
  };
}

test('compile-infra emits JA3 block rules when configured', () => {
  const ctx = runCompileInfra(`
version: 1
project: ja3-test
request:
  allow_methods: ["GET"]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    scope: CLOUDFRONT
    ja3_fingerprints:
      - "0123456789abcdef0123456789abcdef"
      - "fedcba9876543210fedcba9876543210"
`);

  try {
    const waf = ctx.read('infra/waf-rules.tf.json');
    const group = waf.resource.aws_wafv2_rule_group['ja3-test-rate-limit'];
    assert.ok(group);
    assert.ok(Array.isArray(group.rule));

    const ja3Rules = group.rule.filter((r) => r.statement && r.statement.byte_match_statement);
    assert.strictEqual(ja3Rules.length, 2);
    assert.strictEqual(ja3Rules[0].statement.byte_match_statement.field_to_match.ja3_fingerprint.constructor, Object);
    assert.strictEqual(ja3Rules[0].statement.byte_match_statement.positional_constraint, 'EXACTLY');
  } finally {
    ctx.cleanup();
  }
});

test('compile-infra emits JA4 count rules when configured', () => {
  const ctx = runCompileInfra(`
version: 1
project: ja4-test
request:
  allow_methods: ["GET"]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    fingerprint_action: count
    ja4_fingerprints:
      - "t13d1516h2_8daaf6152771_02713d6af862"
`);

  try {
    const waf = ctx.read('infra/waf-rules.tf.json');
    const group = waf.resource.aws_wafv2_rule_group['ja4-test-rate-limit'];
    const ja4Rules = group.rule.filter((r) =>
      r.statement &&
      r.statement.byte_match_statement &&
      r.statement.byte_match_statement.field_to_match &&
      r.statement.byte_match_statement.field_to_match.ja4_fingerprint
    );
    assert.strictEqual(ja4Rules.length, 1);
    assert.ok(ja4Rules[0].action.count);
    assert.strictEqual(ja4Rules[0].statement.byte_match_statement.positional_constraint, 'EXACTLY');
  } finally {
    ctx.cleanup();
  }
});

test('compile-infra still emits managed rules and rate limits', () => {
  const ctx = runCompileInfra(`
version: 1
project: waf-test
request:
  allow_methods: ["GET"]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    rate_limit: 1500
    managed_rules:
      - "AWSManagedRulesCommonRuleSet"
`);

  try {
    const waf = ctx.read('infra/waf-rules.tf.json');
    const group = waf.resource.aws_wafv2_rule_group['waf-test-rate-limit'];
    assert.ok(group.rule.some((r) => r.statement && r.statement.rate_based_statement));

    const acl = waf.resource.aws_wafv2_web_acl['waf-test-waf-acl'];
    assert.ok(acl.rule.length === 1);
    assert.strictEqual(acl.rule[0].statement.managed_rule_group_statement.name, 'AWSManagedRulesCommonRuleSet');
  } finally {
    ctx.cleanup();
  }
});

if (process.exitCode) {
  process.exit(process.exitCode);
}
