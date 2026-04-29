#!/usr/bin/env node
/**
 * Unit tests for the Cloudflare WAF parity system (issue #68).
 *
 * Exercises:
 *   - scripts/lib/cloudflare-waf-parity.js    — classification + warning format
 *   - scripts/compile-cloudflare-waf.js       — stderr warnings, --fail-on-waf-approximation flag
 *   - scripts/generate-parity-doc.js          — rendered doc is stable + contains expected keys
 *   - drift: committed docs/ cloudflare-waf-parity.*.md matches generator output
 *
 * Kept self-contained (no Jest/Mocha) to match the existing test harness.
 */
'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const repoRoot = path.join(__dirname, '..');
const parityLib = require(path.join(repoRoot, 'scripts', 'lib', 'cloudflare-waf-parity'));
const generator = require(path.join(repoRoot, 'scripts', 'generate-parity-doc'));
const compilerPath = path.join(repoRoot, 'scripts', 'compile-cloudflare-waf.js');
function test(name, fn) {
    try {
        fn();
        console.log('OK:', name);
    }
    catch (e) {
        console.error('FAIL:', name);
        console.error(e && e.stack ? e.stack : e);
        process.exitCode = 1;
    }
}
function tmpProject(policy) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-parity-'));
    const policyPath = path.join(dir, 'policy.yml');
    fs.writeFileSync(policyPath, policy, 'utf8');
    return {
        dir,
        policyPath,
        cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
    };
}
function runCompiler(policyPath, outDir, extraArgs = []) {
    return spawnSync(process.execPath, [compilerPath, '--policy', policyPath, '--out-dir', outDir, ...extraArgs], { encoding: 'utf8' });
}
// ---- classifyManagedRule ----
test('classifyManagedRule: known rule returns the registered entry', () => {
    const entry = parityLib.classifyManagedRule('AWSManagedRulesCommonRuleSet');
    assert.strictEqual(entry.status, 'equivalent');
    assert.ok(entry.cloudflare.rulesetId);
});
test('classifyManagedRule: approximate rule keeps its rationale', () => {
    const entry = parityLib.classifyManagedRule('AWSManagedRulesSQLiRuleSet');
    assert.strictEqual(entry.status, 'approximate');
    assert.ok(/OWASP/i.test(entry.rationale));
});
test('classifyManagedRule: unsupported rule emits null rulesetId', () => {
    const entry = parityLib.classifyManagedRule('AWSManagedRulesATPRuleSet');
    assert.strictEqual(entry.status, 'unsupported');
    assert.strictEqual(entry.cloudflare.rulesetId, null);
});
test('classifyManagedRule: unknown rule degrades to unsupported', () => {
    const entry = parityLib.classifyManagedRule('AWSManagedRulesTotallyMadeUp');
    assert.strictEqual(entry.status, 'unsupported');
    assert.strictEqual(entry.cloudflare.rulesetId, null);
    assert.ok(/no parity entry/i.test(entry.rationale));
});
test('formatManagedRuleWarning: equivalent returns null (no warning)', () => {
    const entry = parityLib.classifyManagedRule('AWSManagedRulesCommonRuleSet');
    assert.strictEqual(parityLib.formatManagedRuleWarning(entry), null);
});
test('formatManagedRuleWarning: approximate includes rule name and rationale', () => {
    const entry = parityLib.classifyManagedRule('AWSManagedRulesSQLiRuleSet');
    const msg = parityLib.formatManagedRuleWarning(entry);
    assert.ok(/APPROXIMATE/.test(msg));
    assert.ok(/AWSManagedRulesSQLiRuleSet/.test(msg));
    assert.ok(/OWASP/i.test(msg));
});
test('formatManagedRuleWarning: unsupported flags enabled: false in message', () => {
    const entry = parityLib.classifyManagedRule('AWSManagedRulesATPRuleSet');
    const msg = parityLib.formatManagedRuleWarning(entry);
    assert.ok(/UNSUPPORTED/.test(msg));
    assert.ok(/enabled: false/.test(msg));
});
// ---- compiler stderr warnings ----
const POLICY_EQUIVALENT = `
version: 1
project: parity-unit
request:
  allow_methods: [GET]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    scope: CLOUDFRONT
    managed_rules:
      - AWSManagedRulesCommonRuleSet
`;
const POLICY_APPROXIMATE = `
version: 1
project: parity-unit
request:
  allow_methods: [GET]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    scope: CLOUDFRONT
    managed_rules:
      - AWSManagedRulesSQLiRuleSet
`;
const POLICY_UNSUPPORTED = `
version: 1
project: parity-unit
request:
  allow_methods: [GET]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    scope: CLOUDFRONT
    managed_rules:
      - AWSManagedRulesATPRuleSet
`;
const POLICY_SCOPE_DOWN_UNTRANSLATED = `
version: 1
project: parity-unit
request:
  allow_methods: [GET]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    scope: CLOUDFRONT
    rate_limit_rules:
      - name: exact-match
        aggregate_key_type: IP
        limit: 100
        scope_down_statement:
          byte_match_statement:
            field_to_match: { uri_path: {} }
            positional_constraint: EXACTLY
            search_string: "/login"
`;
test('compiler: equivalent-only policy emits no parity warning', () => {
    const ctx = tmpProject(POLICY_EQUIVALENT);
    try {
        const r = runCompiler(ctx.policyPath, ctx.dir);
        assert.strictEqual(r.status, 0);
        assert.ok(!/APPROXIMATE|UNSUPPORTED/.test(r.stderr), `unexpected stderr: ${r.stderr}`);
    }
    finally {
        ctx.cleanup();
    }
});
test('compiler: approximate rule emits APPROXIMATE stderr warning, exit 0 by default', () => {
    const ctx = tmpProject(POLICY_APPROXIMATE);
    try {
        const r = runCompiler(ctx.policyPath, ctx.dir);
        assert.strictEqual(r.status, 0);
        assert.ok(/APPROXIMATE/.test(r.stderr));
        assert.ok(/AWSManagedRulesSQLiRuleSet/.test(r.stderr));
    }
    finally {
        ctx.cleanup();
    }
});
test('compiler: --fail-on-waf-approximation exits non-zero on approximate', () => {
    const ctx = tmpProject(POLICY_APPROXIMATE);
    try {
        const r = runCompiler(ctx.policyPath, ctx.dir, ['--fail-on-waf-approximation']);
        assert.strictEqual(r.status, 1);
        assert.ok(/--fail-on-waf-approximation/.test(r.stderr));
    }
    finally {
        ctx.cleanup();
    }
});
test('compiler: --fail-on-waf-approximation exits non-zero on unsupported', () => {
    const ctx = tmpProject(POLICY_UNSUPPORTED);
    try {
        const r = runCompiler(ctx.policyPath, ctx.dir, ['--fail-on-waf-approximation']);
        assert.strictEqual(r.status, 1);
        assert.ok(/UNSUPPORTED/.test(r.stderr));
    }
    finally {
        ctx.cleanup();
    }
});
test('compiler: unknown AWS managed rule treated as unsupported (disabled, warned)', () => {
    const policy = POLICY_UNSUPPORTED.replace('AWSManagedRulesATPRuleSet', 'AWSManagedRulesTotallyFake');
    const ctx = tmpProject(policy);
    try {
        const r = runCompiler(ctx.policyPath, ctx.dir);
        assert.strictEqual(r.status, 0);
        assert.ok(/UNSUPPORTED: AWSManagedRulesTotallyFake/.test(r.stderr));
        const tf = JSON.parse(fs.readFileSync(path.join(ctx.dir, 'infra', 'cloudflare-waf.tf.json'), 'utf8'));
        const managed = tf.resource.cloudflare_ruleset['parity-unit_managed'];
        const rule = managed.rules.find((r) => /Fake/.test(r.description));
        assert.ok(rule, 'expected managed rule emitted');
        assert.strictEqual(rule.enabled, false);
    }
    finally {
        ctx.cleanup();
    }
});
test('compiler: untranslated scope_down emits parity warning and degrades expression', () => {
    const ctx = tmpProject(POLICY_SCOPE_DOWN_UNTRANSLATED);
    try {
        const r = runCompiler(ctx.policyPath, ctx.dir);
        assert.strictEqual(r.status, 0);
        assert.ok(/scope_down_statement/i.test(r.stderr));
        assert.ok(/match-all/.test(r.stderr));
        const tf = JSON.parse(fs.readFileSync(path.join(ctx.dir, 'infra', 'cloudflare-waf.tf.json'), 'utf8'));
        const rl = tf.resource.cloudflare_ruleset['parity-unit_ratelimit'];
        const rule = rl.rules.find((r) => r.description === 'exact-match');
        assert.strictEqual(rule.expression, 'true');
    }
    finally {
        ctx.cleanup();
    }
});
test('compiler: expression_cloudflare override suppresses the scope_down warning', () => {
    const policy = `${POLICY_SCOPE_DOWN_UNTRANSLATED}        expression_cloudflare: 'http.request.uri.path eq "/login"'
`;
    const ctx = tmpProject(policy);
    try {
        const r = runCompiler(ctx.policyPath, ctx.dir);
        assert.strictEqual(r.status, 0);
        assert.ok(!/scope_down_statement.*match-all/.test(r.stderr), `unexpected warning: ${r.stderr}`);
        const tf = JSON.parse(fs.readFileSync(path.join(ctx.dir, 'infra', 'cloudflare-waf.tf.json'), 'utf8'));
        const rl = tf.resource.cloudflare_ruleset['parity-unit_ratelimit'];
        const rule = rl.rules.find((r) => r.description === 'exact-match');
        assert.strictEqual(rule.expression, 'http.request.uri.path eq "/login"');
    }
    finally {
        ctx.cleanup();
    }
});
test('compiler: custom Cloudflare rules include geo, IP, UA, fingerprint, rate limit, and logging resources', () => {
    const policy = `
version: 1
project: cf-custom-test
request:
  allow_methods: [GET]
  block:
    ua_contains: ["BadBot"]
response_headers:
  hsts: "max-age=1"
firewall:
  geo:
    block_countries: ["RU"]
    allow_countries: ["JP", "US"]
  ip:
    blocklist: ["203.0.113.0/24"]
    allowlist: ["198.51.100.10/32"]
  waf:
    scope: CLOUDFRONT
    rate_limit: 1234
    fingerprint_action: count
    ja3_fingerprints:
      - "0123456789abcdef0123456789abcdef"
    ja4_fingerprints:
      - "t13d1516h2_8daaf6152771_02713d6af862"
    block_response:
      status_code: 429
      body: "slow down"
      content_type: APPLICATION_JSON
    rate_limit_rules:
      - name: login-starts-with
        aggregate_key_type: CUSTOM_KEYS
        cloudflare_characteristics: ["ip.src", "http.request.headers[\\"x-api-key\\"]"]
        limit: 25
        action: count
        scope_down_statement:
          byte_match_statement:
            field_to_match: { uri_path: {} }
            positional_constraint: STARTS_WITH
            search_string: "/login"
    logging:
      enabled: true
      destination_arn_env: CLOUDFLARE_LOG_DEST
`;
    const ctx = tmpProject(policy);
    try {
        const r = runCompiler(ctx.policyPath, ctx.dir);
        assert.strictEqual(r.status, 0, r.stderr);
        const tf = JSON.parse(fs.readFileSync(path.join(ctx.dir, 'infra', 'cloudflare-waf.tf.json'), 'utf8'));
        const lists = tf.resource.cloudflare_list;
        assert.strictEqual(lists['cf-custom-test_ip_blocklist'].item[0].value.ip, '203.0.113.0/24');
        assert.strictEqual(lists['cf-custom-test_ip_allowlist'].item[0].value.ip, '198.51.100.10/32');
        const custom = tf.resource.cloudflare_ruleset['cf-custom-test_custom'];
        assert.ok(custom.rules.some((rule) => /Geo blocklist/.test(rule.description) && /"RU"/.test(rule.expression)));
        assert.ok(custom.rules.some((rule) => /Geo allowlist/.test(rule.description) && /not/.test(rule.expression)));
        assert.ok(custom.rules.some((rule) => /IP blocklist/.test(rule.description) && /\$cf-custom-test_ip_blocklist/.test(rule.expression)));
        assert.ok(custom.rules.some((rule) => /User-Agent/.test(rule.description) && /badbot/.test(rule.expression)));
        assert.ok(custom.rules.some((rule) => /JA3 fingerprint log/.test(rule.description) && rule.action === 'log'));
        assert.ok(custom.rules.some((rule) => /JA4 fingerprint log/.test(rule.description) && rule.action === 'log'));
        const blockedRule = custom.rules.find((rule) => /Geo blocklist/.test(rule.description));
        assert.strictEqual(blockedRule.action_parameters.response.status_code, 429);
        assert.strictEqual(blockedRule.action_parameters.response.content_type, 'application/json');
        const rateRules = tf.resource.cloudflare_ruleset['cf-custom-test_ratelimit'].rules;
        const globalRate = rateRules.find((rule) => /legacy/.test(rule.description));
        assert.strictEqual(globalRate.ratelimit.requests_per_period, 1234);
        const scopedRate = rateRules.find((rule) => rule.description === 'login-starts-with');
        assert.strictEqual(scopedRate.action, 'log');
        assert.strictEqual(scopedRate.expression, 'starts_with(http.request.uri.path, "/login")');
        assert.deepStrictEqual(scopedRate.ratelimit.characteristics, ['ip.src', 'http.request.headers["x-api-key"]']);
        assert.ok(tf.variable.cloudflare_log_dest);
        const logpush = tf.resource.cloudflare_logpush_job['cf-custom-test_waf_logs'];
        assert.strictEqual(logpush.destination_conf, '${var.cloudflare_log_dest}');
    }
    finally {
        ctx.cleanup();
    }
});
test('compiler: BotControl managed rule emits approximation warning and bot fight setting', () => {
    const policy = `
version: 1
project: cf-bots-test
request:
  allow_methods: [GET]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    managed_rules:
      - AWSManagedRulesBotControlRuleSet
`;
    const ctx = tmpProject(policy);
    try {
        const r = runCompiler(ctx.policyPath, ctx.dir);
        assert.strictEqual(r.status, 0, r.stderr);
        assert.ok(/APPROXIMATE: AWSManagedRulesBotControlRuleSet/.test(r.stderr));
        const tf = JSON.parse(fs.readFileSync(path.join(ctx.dir, 'infra', 'cloudflare-waf.tf.json'), 'utf8'));
        const managed = tf.resource.cloudflare_ruleset['cf-bots-test_managed'];
        assert.strictEqual(managed.rules[0].enabled, false);
        assert.strictEqual(tf.resource.cloudflare_zone_settings_override['cf-bots-test_bots'].settings.bot_fight_mode, 'on');
    }
    finally {
        ctx.cleanup();
    }
});
// ---- generator ----
test('generator: EN render includes every managed rule entry', () => {
    const out = generator.renderEn();
    for (const e of parityLib.MANAGED_RULES) {
        assert.ok(out.includes(`\`${e.aws}\``), `missing ${e.aws} in EN doc`);
    }
    assert.ok(/--fail-on-waf-approximation/.test(out));
});
test('generator: JA render includes every managed rule entry', () => {
    const out = generator.renderJa();
    for (const e of parityLib.MANAGED_RULES) {
        assert.ok(out.includes(`\`${e.aws}\``), `missing ${e.aws} in JA doc`);
    }
    assert.ok(/--fail-on-waf-approximation/.test(out));
});
test('generator: render is deterministic (stable across calls)', () => {
    assert.strictEqual(generator.renderEn(), generator.renderEn());
    assert.strictEqual(generator.renderJa(), generator.renderJa());
});
test('drift: committed docs/cloudflare-waf-parity.md matches generator output', () => {
    const committed = fs.readFileSync(path.join(repoRoot, 'docs', 'cloudflare-waf-parity.md'), 'utf8');
    assert.strictEqual(committed, generator.renderEn(), 'run `node scripts/generate-parity-doc.js --write` to regenerate');
});
test('drift: committed docs/cloudflare-waf-parity.ja.md matches generator output', () => {
    const committed = fs.readFileSync(path.join(repoRoot, 'docs', 'cloudflare-waf-parity.ja.md'), 'utf8');
    assert.strictEqual(committed, generator.renderJa(), 'run `node scripts/generate-parity-doc.js --write --lang=ja` to regenerate');
});
