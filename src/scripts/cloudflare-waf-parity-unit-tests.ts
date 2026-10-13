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

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const repoRoot = path.join(__dirname, '..');
const parityLib = require(path.join(repoRoot, 'scripts', 'lib', 'cloudflare-waf-parity'));
const generator = require(path.join(repoRoot, 'scripts', 'generate-parity-doc'));
const compilerPath = path.join(repoRoot, 'scripts', 'compile-cloudflare-waf.js');

function test(name: string, fn: () => void) {
  try {
    fn();
    console.log('OK:', name);
  } catch (e: unknown) {
    console.error('FAIL:', name);
    console.error(e instanceof Error && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  }
}

function tmpProject(policy: string) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-parity-'));
  const policyPath = path.join(dir, 'policy.yml');
  fs.writeFileSync(policyPath, policy, 'utf8');
  return {
    dir,
    policyPath,
    cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}

function runCompiler(policyPath: string, outDir: string, extraArgs: string[] = []) {
  return spawnSync(
    process.execPath,
    [compilerPath, '--policy', policyPath, '--out-dir', outDir, ...extraArgs],
    { encoding: 'utf8' },
  );
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
version: 2
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
version: 2
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
version: 2
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
version: 2
project: parity-unit
request:
  allow_methods: [GET]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    scope: CLOUDFRONT
    cloudflare_rate_limit_plan: business
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
  } finally {
    ctx.cleanup();
  }
});

test('compiler: approximate rule fails closed by default', () => {
  const ctx = tmpProject(POLICY_APPROXIMATE);
  try {
    const r = runCompiler(ctx.policyPath, ctx.dir);
    assert.strictEqual(r.status, 1);
    assert.ok(/APPROXIMATE/.test(r.stderr));
    assert.ok(/AWSManagedRulesSQLiRuleSet/.test(r.stderr));
    assert.ok(/allow-waf-approximation/.test(r.stderr));
  } finally {
    ctx.cleanup();
  }
});

test('compiler: --allow-waf-approximation warns and exits 0 on approximate', () => {
  const ctx = tmpProject(POLICY_APPROXIMATE);
  try {
    const r = runCompiler(ctx.policyPath, ctx.dir, ['--allow-waf-approximation']);
    assert.strictEqual(r.status, 0);
    assert.ok(/APPROXIMATE/.test(r.stderr));
  } finally {
    ctx.cleanup();
  }
});

test('compiler: unsupported mappings fail closed by default', () => {
  const ctx = tmpProject(POLICY_UNSUPPORTED);
  try {
    const r = runCompiler(ctx.policyPath, ctx.dir);
    assert.strictEqual(r.status, 1);
    assert.ok(/UNSUPPORTED/.test(r.stderr));
  } finally {
    ctx.cleanup();
  }
});

test('compiler: unknown AWS managed rule treated as unsupported (disabled, warned)', () => {
  const policy = POLICY_UNSUPPORTED.replace('AWSManagedRulesATPRuleSet', 'AWSManagedRulesTotallyFake');
  const ctx = tmpProject(policy);
  try {
    const r = runCompiler(ctx.policyPath, ctx.dir, ['--allow-waf-approximation']);
    assert.strictEqual(r.status, 0);
    assert.ok(/UNSUPPORTED: AWSManagedRulesTotallyFake/.test(r.stderr));
    const tf = JSON.parse(fs.readFileSync(path.join(ctx.dir, 'infra', 'cloudflare-waf.tf.json'), 'utf8'));
    const managed = tf.resource.cloudflare_ruleset['parity-unit_managed'];
    const rule = managed.rules.find((r: any) => /Fake/.test(r.description));
    assert.ok(rule, 'expected managed rule emitted');
    assert.strictEqual(rule.enabled, false);
  } finally {
    ctx.cleanup();
  }
});

test('compiler: untranslated scope_down rejects before output even with approximation opt-out', () => {
  const ctx = tmpProject(POLICY_SCOPE_DOWN_UNTRANSLATED);
  try {
    for (const args of [[], ['--allow-waf-approximation']]) {
      const r = runCompiler(ctx.policyPath, ctx.dir, args);
      assert.strictEqual(r.status, 1);
      assert.match(r.stderr, /CLOUDFLARE_RATE_LIMIT_INVALID.*scope_down_statement/);
      assert.ok(!fs.existsSync(path.join(ctx.dir, 'infra', 'cloudflare-waf.tf.json')));
    }
  } finally { ctx.cleanup(); }
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
    const rule = rl.rules.find((r: any) => r.description === 'exact-match');
    assert.strictEqual(rule.expression, 'http.request.uri.path eq "/login"');
  } finally {
    ctx.cleanup();
  }
});

test('compiler: custom Cloudflare rules include geo, IP, UA, fingerprint, rate limit, and logging resources', () => {
  const policy = `
version: 2
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
    cloudflare_rate_limit_plan: business
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
        aggregate_key_type: IP
        cloudflare_characteristics: ["ip.src"]
        limit: 100
        action: block
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
    assert.ok(custom.rules.some((rule: any) => /Geo blocklist/.test(rule.description) && /"RU"/.test(rule.expression)));
    assert.ok(custom.rules.some((rule: any) => /Geo allowlist/.test(rule.description) && /not/.test(rule.expression)));
    assert.ok(custom.rules.some((rule: any) => /IP blocklist/.test(rule.description) && /\$cf-custom-test_ip_blocklist/.test(rule.expression)));
    assert.ok(custom.rules.some((rule: any) => /User-Agent/.test(rule.description) && /badbot/.test(rule.expression)));
    assert.ok(custom.rules.some((rule: any) => /JA3 fingerprint log/.test(rule.description) && rule.action === 'log'));
    assert.ok(custom.rules.some((rule: any) => /JA4 fingerprint log/.test(rule.description) && rule.action === 'log'));
    const blockedRule = custom.rules.find((rule: any) => /Geo blocklist/.test(rule.description));
    assert.strictEqual(blockedRule.action_parameters.response.status_code, 429);
    assert.strictEqual(blockedRule.action_parameters.response.content_type, 'application/json');

    const rateRules = tf.resource.cloudflare_ruleset['cf-custom-test_ratelimit'].rules;
    const globalRate = rateRules.find((rule: any) => rule.description === 'Global IP rate limit');
    assert.strictEqual(globalRate.ratelimit.requests_per_period, 1234);
    const scopedRate = rateRules.find((rule: any) => rule.description === 'login-starts-with');
    assert.strictEqual(scopedRate.action, 'block');
    assert.strictEqual(scopedRate.expression, 'starts_with(http.request.uri.path, "/login")');
    assert.deepStrictEqual(scopedRate.ratelimit.characteristics, ['cf.colo.id', 'ip.src']);
    assert.strictEqual(scopedRate.ratelimit.mitigation_timeout, 10);
    assert.strictEqual(globalRate.ratelimit.mitigation_timeout, 10);

    assert.ok(tf.variable.cloudflare_log_dest);
    const logpush = tf.resource.cloudflare_logpush_job['cf-custom-test_waf_logs'];
    assert.strictEqual(logpush.destination_conf, '${var.cloudflare_log_dest}');
  } finally {
    ctx.cleanup();
  }
});

test('compiler: BotControl managed rule emits approximation warning and bot fight setting', () => {
  const policy = `
version: 2
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
    const r = runCompiler(ctx.policyPath, ctx.dir, ['--allow-waf-approximation']);
    assert.strictEqual(r.status, 0, r.stderr);
    assert.ok(/APPROXIMATE: AWSManagedRulesBotControlRuleSet/.test(r.stderr));
    const tf = JSON.parse(fs.readFileSync(path.join(ctx.dir, 'infra', 'cloudflare-waf.tf.json'), 'utf8'));
    const managed = tf.resource.cloudflare_ruleset['cf-bots-test_managed'];
    assert.strictEqual(managed.rules[0].enabled, false);
    assert.strictEqual(tf.resource.cloudflare_zone_settings_override['cf-bots-test_bots'].settings.bot_fight_mode, 'on');
  } finally {
    ctx.cleanup();
  }
});

// ---- generator ----

test('generator: EN render includes every managed rule entry', () => {
  const out = generator.renderEn();
  for (const e of parityLib.MANAGED_RULES) {
    assert.ok(out.includes(`\`${e.aws}\``), `missing ${e.aws} in EN doc`);
  }
  assert.ok(/--allow-waf-approximation/.test(out));
});

test('generator: JA render includes every managed rule entry', () => {
  const out = generator.renderJa();
  for (const e of parityLib.MANAGED_RULES) {
    assert.ok(out.includes(`\`${e.aws}\``), `missing ${e.aws} in JA doc`);
  }
  assert.ok(/--allow-waf-approximation/.test(out));
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

test('explicit Free rate limit preserves the chosen 2000 requests per 10 seconds', () => {
  const ctx = tmpProject(`version: 2
project: free-rate
firewall:
  waf:
    cloudflare_rate_limit_plan: free
    cloudflare_rate_limit_period: 10
    rate_limit: 2000
`);
  try {
    const r = runCompiler(ctx.policyPath, ctx.dir);
    assert.strictEqual(r.status, 0, r.stderr);
    const tf = JSON.parse(fs.readFileSync(path.join(ctx.dir, 'infra/cloudflare-waf.tf.json'), 'utf8'));
    const rate = tf.resource.cloudflare_ruleset['free-rate_ratelimit'].rules[0].ratelimit;
    assert.strictEqual(rate.period, 10);
    assert.strictEqual(rate.requests_per_period, 2000);
    assert.deepStrictEqual(rate.characteristics, ['cf.colo.id', 'ip.src']);
  } finally { fs.rmSync(ctx.dir, { recursive: true, force: true }); }
});

test('Free plus 300 seconds fails before writing even with approximation opt-out', () => {
  const ctx = tmpProject(`version: 2
firewall:
  waf:
    cloudflare_rate_limit_plan: free
    cloudflare_rate_limit_period: 300
    rate_limit: 2000
`);
  try {
    const r = runCompiler(ctx.policyPath, ctx.dir, ['--allow-waf-approximation']);
    assert.notStrictEqual(r.status, 0);
    assert.ok(!fs.existsSync(path.join(ctx.dir, 'infra/cloudflare-waf.tf.json')));
  } finally { fs.rmSync(ctx.dir, { recursive: true, force: true }); }
});

const { buildCloudflareRateRules } = require('./lib/cloudflare-rate-limit');
const freeRate = { cloudflare_rate_limit_plan: 'free', cloudflare_rate_limit_period: 10, rate_limit: 200 };
test('rate profiles preserve explicit thresholds and the Business 5-minute window', () => {
  assert.strictEqual(buildCloudflareRateRules({ cloudflare_rate_limit_plan: 'business', rate_limit: 2000 })[0].ratelimit.period, 300);
  const rules = buildCloudflareRateRules({ cloudflare_rate_limit_plan: 'free', cloudflare_rate_limit_period: 10, rate_limit_rules: [
    { name: 'login', limit: 100, expression_cloudflare: 'lower(http.request.uri.path) eq "/login"' },
  ] });
  assert.strictEqual(rules.length, 1);
  assert.strictEqual(rules[0].expression, 'lower(http.request.uri.path) eq "/login"');
  assert.deepStrictEqual(rules[0].ratelimit, { characteristics: ['cf.colo.id', 'ip.src'], period: 10, requests_per_period: 100, mitigation_timeout: 10 });
  const business = buildCloudflareRateRules({ cloudflare_rate_limit_plan: 'business', rate_limit: 2000,
    rate_limit_rules: Array.from({ length: 4 }, (_, i) => ({ name: 'route-' + i, limit: 100 + i })) });
  assert.strictEqual(business.length, 5);
  assert.strictEqual(business[4].ratelimit.requests_per_period, 103);
  assert.deepStrictEqual(buildCloudflareRateRules({}), []);
});

for (const [name, config] of Object.entries({
  'non-object configuration': [],
  'missing plan': { rate_limit: 2000 },
  'missing Free period': { cloudflare_rate_limit_plan: 'free', rate_limit: 2000 },
  'unknown plan': { ...freeRate, cloudflare_rate_limit_plan: 'pro' },
  'Free 300 seconds': { ...freeRate, cloudflare_rate_limit_period: 300 },
  'unsupported discrete period 15': { ...freeRate, cloudflare_rate_limit_plan: 'business', cloudflare_rate_limit_period: 15 },
  'Free block throttling zero': { ...freeRate, rate_limit_mitigation_timeout: 0 },
  'Business block throttling zero': { ...freeRate, cloudflare_rate_limit_plan: 'business', rate_limit_mitigation_timeout: 0 },
  'Free 60-second mitigation': { ...freeRate, rate_limit_mitigation_timeout: 60 },
  'unsupported discrete mitigation 30': { ...freeRate, cloudflare_rate_limit_plan: 'business', rate_limit_mitigation_timeout: 30 },
  'zero threshold': { ...freeRate, rate_limit: 0 },
  'fractional threshold': { ...freeRate, rate_limit: 200.5 },
  'string threshold': { ...freeRate, rate_limit: '200' },
  'Free global plus individual': { ...freeRate, rate_limit_rules: [{ name: 'login', limit: 100 }] },
  'Free two individual': { ...freeRate, rate_limit: undefined, rate_limit_rules: [{ name: 'a', limit: 100 }, { name: 'b', limit: 100 }] },
  'Business six total': { ...freeRate, cloudflare_rate_limit_plan: 'business', rate_limit_rules: Array.from({ length: 5 }, (_, i) => ({ name: 'r-' + i, limit: 100 })) },
  'header characteristic': { ...freeRate, rate_limit: undefined, rate_limit_rules: [{ name: 'login', limit: 100, cloudflare_characteristics: ['ip.src', 'http.request.headers["x-api-key"]'] }] },
  'characteristics without IP': { ...freeRate, rate_limit: undefined, rate_limit_rules: [{ name: 'login', limit: 100, cloudflare_characteristics: ['cf.colo.id'] }] },
  'custom keys': { ...freeRate, rate_limit: undefined, rate_limit_rules: [{ name: 'login', limit: 100, custom_keys: [] }] },
  'missing individual threshold': { ...freeRate, rate_limit: undefined, rate_limit_rules: [{ name: 'login' }] },
  'count action': { ...freeRate, rate_limit: undefined, rate_limit_rules: [{ name: 'login', limit: 100, action: 'count' }] },
  'captcha action': { ...freeRate, rate_limit: undefined, rate_limit_rules: [{ name: 'login', limit: 100, action: 'captcha' }] },
  'forwarded IP': { ...freeRate, rate_limit: undefined, rate_limit_rules: [{ name: 'login', limit: 100, aggregate_key_type: 'FORWARDED_IP' }] },
  'complex expression': { ...freeRate, rate_limit: undefined, rate_limit_rules: [{ name: 'login', limit: 100, expression_cloudflare: 'http.request.uri.path eq "/login" or true' }] },
  'regex expression': { ...freeRate, rate_limit: undefined, rate_limit_rules: [{ name: 'login', limit: 100, expression_cloudflare: 'http.request.uri.path matches "^/"' }] },
  'unknown rule field': { ...freeRate, rate_limit: undefined, rate_limit_rules: [{ name: 'login', limit: 100, custom_count: true }] },
  'non-error block response': { ...freeRate, block_response: { status_code: 200 } },
})) {
  test('rate profiles reject ' + name, () => assert.throws(() => buildCloudflareRateRules(config), /CLOUDFLARE_RATE_LIMIT_INVALID/));
}
