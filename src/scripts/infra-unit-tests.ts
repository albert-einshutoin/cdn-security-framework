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

function runCompileInfra(policyContent, options = {}) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'infra-unit-'));
  const policyPath = path.join(tempDir, 'policy.yml');
  const outDir = path.join(tempDir, 'out');
  fs.writeFileSync(policyPath, policyContent, 'utf8');

  const args = [path.join(repoRoot, 'scripts', 'compile-infra.js'), '--policy', policyPath, '--out-dir', outDir];
  if (options.outputMode) args.push('--output-mode', options.outputMode);
  if (options.ruleGroupOnly) args.push('--rule-group-only');

  execFileSync(process.execPath, args, {
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

test('compile-infra supports --rule-group-only for existing web ACL users', () => {
  const ctx = runCompileInfra(`
version: 1
project: rg-only-test
request:
  allow_methods: ["GET"]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    rate_limit: 1200
    managed_rules:
      - "AWSManagedRulesCommonRuleSet"
`, { ruleGroupOnly: true });

  try {
    const waf = ctx.read('infra/waf-rules.tf.json');
    assert.ok(waf.resource.aws_wafv2_rule_group['rg-only-test-rate-limit']);
    assert.ok(!waf.resource.aws_wafv2_web_acl);
  } finally {
    ctx.cleanup();
  }
});

test('compile-infra supports --output-mode rule-group for existing web ACL users', () => {
  const ctx = runCompileInfra(`
version: 1
project: outmode-test
request:
  allow_methods: ["GET"]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    managed_rules:
      - "AWSManagedRulesCommonRuleSet"
`, { outputMode: 'rule-group' });

  try {
    const waf = ctx.read('infra/waf-rules.tf.json');
    assert.ok(waf.resource.aws_wafv2_rule_group['outmode-test-rate-limit']);
    assert.ok(!waf.resource.aws_wafv2_web_acl);
  } finally {
    ctx.cleanup();
  }
});

test('compile-infra emits rate_limit_rules[] with scope_down_statement and custom priority', () => {
  const ctx = runCompileInfra(`
version: 1
project: rlr-test
request:
  allow_methods: ["GET"]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    scope: CLOUDFRONT
    rate_limit_rules:
      - name: "global"
        limit: 2000
        aggregate_key_type: "IP"
        action: "block"
        priority: 1
      - name: "login-tight"
        limit: 50
        aggregate_key_type: "IP"
        action: "count"
        priority: 2
        scope_down_statement:
          byte_match_statement:
            field_to_match: { uri_path: {} }
            positional_constraint: "STARTS_WITH"
            search_string: "/login"
            text_transformation: [{ priority: 0, type: "LOWERCASE" }]
`);

  try {
    const waf = ctx.read('infra/waf-rules.tf.json');
    const group = waf.resource.aws_wafv2_rule_group['rlr-test-rate-limit'];
    const rateRules = group.rule.filter((r) => r.statement && r.statement.rate_based_statement);
    assert.strictEqual(rateRules.length, 2);
    assert.strictEqual(rateRules[0].name, 'global');
    assert.strictEqual(rateRules[0].priority, 1);
    assert.ok(rateRules[0].action.block);
    assert.strictEqual(rateRules[1].name, 'login-tight');
    assert.ok(rateRules[1].action.count);
    assert.ok(rateRules[1].statement.rate_based_statement.scope_down_statement.byte_match_statement);
  } finally {
    ctx.cleanup();
  }
});

test('compile-infra emits block_response custom_response_body on rule group + references it', () => {
  const ctx = runCompileInfra(`
version: 1
project: br-test
request:
  allow_methods: ["GET"]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    scope: CLOUDFRONT
    rate_limit: 2000
    managed_rules:
      - "AWSManagedRulesCommonRuleSet"
    block_response:
      status_code: 451
      body: "unavailable for legal reasons"
      content_type: "TEXT_PLAIN"
`);

  try {
    const waf = ctx.read('infra/waf-rules.tf.json');
    const group = waf.resource.aws_wafv2_rule_group['br-test-rate-limit'];
    assert.ok(Array.isArray(group.custom_response_body));
    assert.strictEqual(group.custom_response_body[0].key, 'cdn_sec_block');
    assert.strictEqual(group.custom_response_body[0].content, 'unavailable for legal reasons');

    const rateRule = group.rule.find((r) => r.statement.rate_based_statement);
    assert.strictEqual(rateRule.action.block.custom_response.response_code, 451);
    assert.strictEqual(rateRule.action.block.custom_response.custom_response_body_key, 'cdn_sec_block');

    const acl = waf.resource.aws_wafv2_web_acl['br-test-waf-acl'];
    assert.ok(Array.isArray(acl.custom_response_body));
    assert.strictEqual(acl.custom_response_body[0].key, 'cdn_sec_block');
  } finally {
    ctx.cleanup();
  }
});

test('compile-infra emits aws_wafv2_logging_configuration when logging.enabled', () => {
  const ctx = runCompileInfra(`
version: 1
project: log-test
request:
  allow_methods: ["GET"]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    scope: CLOUDFRONT
    managed_rules:
      - "AWSManagedRulesCommonRuleSet"
    logging:
      enabled: true
      destination_arn_env: "WAF_LOG_DESTINATION_ARN"
      redacted_fields:
        - "authorization"
        - "cookie"
`);

  try {
    const waf = ctx.read('infra/waf-rules.tf.json');
    const logging = waf.resource.aws_wafv2_logging_configuration['log-test-waf-acl-logging'];
    assert.ok(logging);
    assert.strictEqual(logging.log_destination_configs[0], '${var.waf_log_destination_arn}');
    assert.strictEqual(logging.resource_arn, '${aws_wafv2_web_acl.log-test-waf-acl.arn}');
    assert.strictEqual(logging.redacted_fields[0].single_header.name, 'authorization');
    assert.strictEqual(logging.redacted_fields[1].single_header.name, 'cookie');
    assert.ok(waf.variable && waf.variable.waf_log_destination_arn);
  } finally {
    ctx.cleanup();
  }
});

test('compile-infra: logging is NOT emitted when logging.enabled is false/missing', () => {
  const ctx = runCompileInfra(`
version: 1
project: nolog-test
request:
  allow_methods: ["GET"]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    scope: CLOUDFRONT
    managed_rules:
      - "AWSManagedRulesCommonRuleSet"
`);

  try {
    const waf = ctx.read('infra/waf-rules.tf.json');
    assert.ok(!waf.resource.aws_wafv2_logging_configuration);
  } finally {
    ctx.cleanup();
  }
});

if (process.exitCode) {
  process.exit(process.exitCode);
}
