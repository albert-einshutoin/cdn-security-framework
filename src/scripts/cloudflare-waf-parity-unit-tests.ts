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
    assert.strictEqual(lists['cf-custom-test_ip_blocklist'].account_id, '${var.cloudflare_account_id}');

    const custom = tf.resource.cloudflare_ruleset['cf-custom-test_custom'];
    assert.strictEqual(custom.zone_id, '${var.cloudflare_zone_id}');
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

const { assessCloudflareFreeWaf } = require('./lib/cloudflare-rate-limit');
const freeCustomResources = (count: number) => ({ cloudflare_ruleset: { custom: {
  kind: 'zone', phase: 'http_request_firewall_custom', rules: Array.from({ length: count }, (_, i) => ({
    enabled: i % 2 === 0, expression: '(ip.geoip.country in {"CN"})', action: 'block',
    action_parameters: { response: null },
  })),
} } });
const freeInventory = (changes: Record<string, unknown> = {}) => JSON.stringify({
  version: 1, scope: 'saved-cloudflare-free-inventory', capturedAtMs: 0, complete: true,
  plan: 'free', existingCustomRules: 1, existingRateRules: 0, ...changes,
});

test('Free preflight counts every generated rule plus existing zone consumption', () => {
  const result = assessCloudflareFreeWaf(freeCustomResources(5), freeInventory(), 0);
  assert.strictEqual(result.savedCapacity, 'exceeded');
  assert.ok(result.reasons.includes('CUSTOM_RULE_CAPACITY_EXCEEDED'));
  assert.strictEqual(result.liveDeployment, 'unknown');
});

test('Free preflight never infers an empty account inventory', () => {
  const result = assessCloudflareFreeWaf(freeCustomResources(1), undefined, 0);
  assert.strictEqual(result.localGeneration, 'supported');
  assert.strictEqual(result.savedCapacity, 'unknown');
  assert.ok(result.reasons.includes('INVENTORY_MISSING'));
  assert.strictEqual(result.liveDeployment, 'unknown');
});

test('explicit Free compilation rejects Log before creating an artifact', () => {
  const ctx = tmpProject(`version: 2
project: free-log
request:
  allow_methods: [GET]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    fingerprint_action: count
    ja3_fingerprints: [d41d8cd98f00b204e9800998ecf8427e]
`);
  try {
    const result = runCompiler(ctx.policyPath, ctx.dir, ['--cloudflare-free']);
    assert.notStrictEqual(result.status, 0);
    assert.match(result.stderr, /LOG_ACTION_NOT_FREE/);
    assert.ok(!fs.existsSync(path.join(ctx.dir, 'infra/cloudflare-waf.tf.json')));
  } finally { ctx.cleanup(); }
});

test('Free capacity boundaries include disabled rules and both independent quotas', () => {
  for (const count of [0, 1, 5, 6]) {
    const result = assessCloudflareFreeWaf(freeCustomResources(count), freeInventory({ existingCustomRules: 0 }), 0);
    assert.strictEqual(result.generated.customRules, count);
    assert.strictEqual(result.localGeneration, count <= 5 ? 'supported' : 'unsupported');
    assert.strictEqual(result.savedCapacity, count <= 5 ? 'fits' : 'exceeded');
  }
  for (const count of [0, 1, 2]) {
    const resources = { cloudflare_ruleset: { rate: { kind: 'zone', phase: 'http_ratelimit',
      rules: Array.from({ length: count }, () => buildCloudflareRateRules(freeRate)[0]),
    } } };
    const empty = assessCloudflareFreeWaf(resources, freeInventory({ existingCustomRules: 0, existingRateRules: 0 }), 0);
    assert.strictEqual(empty.savedCapacity, count <= 1 ? 'fits' : 'exceeded');
    const used = assessCloudflareFreeWaf(resources, freeInventory({ existingRateRules: 1 }), 0);
    assert.strictEqual(used.savedCapacity, count === 0 ? 'fits' : 'exceeded');
  }
});

test('Free inventory cannot assert capacity from partial, stale, unknown-plan/count/version data', () => {
  for (const changes of [{ complete: false }, { plan: null }, { existingCustomRules: null }, { existingRateRules: null }, { version: 2 }]) {
    const result = assessCloudflareFreeWaf(freeCustomResources(1), freeInventory(changes), 0);
    assert.strictEqual(result.savedCapacity, 'unknown');
    assert.strictEqual(result.liveDeployment, 'unknown');
  }
  assert.strictEqual(assessCloudflareFreeWaf(freeCustomResources(1), freeInventory(), 86400000).savedCapacity, 'fits');
  assert.strictEqual(assessCloudflareFreeWaf(freeCustomResources(1), freeInventory({ existingCustomRules: 5 }), 86400001).savedCapacity, 'unknown');
  assert.strictEqual(assessCloudflareFreeWaf(freeCustomResources(1), freeInventory({ existingCustomRules: 5, complete: false }), 0).savedCapacity, 'unknown');
});

test('Free inventory rejects malformed/oversized/foreign data without echoing raw input', () => {
  const invalid = [
    'not-json-private-token', '[]', freeInventory({ version: 0 }), freeInventory({ version: 1.5 }),
    freeInventory({ scope: 'private-token' }), freeInventory({ capturedAtMs: 1 }), freeInventory({ capturedAtMs: -1 }),
    freeInventory({ complete: 'false' }), freeInventory({ plan: 'business' }), freeInventory({ secret: 'private-token' }),
    freeInventory({ existingCustomRules: -1 }), freeInventory({ existingRateRules: 1.5 }),
    freeInventory({ existingCustomRules: 10001 }), freeInventory({ existingRateRules: Number.MAX_SAFE_INTEGER + 1 }),
  ];
  for (const text of invalid) assert.throws(() => assessCloudflareFreeWaf({}, text, 0), (error: Error) =>
    error.message.startsWith('CLOUDFLARE_FREE_INVALID:') && !error.message.includes('private-token'));
  const text = freeInventory();
  assert.strictEqual(assessCloudflareFreeWaf({}, text.padEnd(8192, ' '), 0).savedCapacity, 'fits');
  assert.throws(() => assessCloudflareFreeWaf({}, text.padEnd(8193, ' '), 0), /INVENTORY_BYTES/);
  assert.throws(() => assessCloudflareFreeWaf({}, undefined, -1), /INPUT/);
});

test('Free feature checks parse whole supported shapes and ignore keywords inside quoted UA data', () => {
  const rule = freeCustomResources(1).cloudflare_ruleset.custom.rules[0];
  const withRule = (changes: Record<string, unknown>) => ({ cloudflare_ruleset: { custom: {
    kind: 'zone', phase: 'http_request_firewall_custom', rules: [{ ...rule, ...changes }],
  } } });
  const benign = assessCloudflareFreeWaf(withRule({ expression: '(lower(http.user_agent) contains "matches cf.bot_management.ja3_hash")' }), undefined, 0);
  assert.strictEqual(benign.localGeneration, 'supported');
  for (const [changes, reason] of [
    [{ action: 'log' }, 'LOG_ACTION_NOT_FREE'],
    [{ expression: 'http.user_agent matches "bot"' }, 'REGEX_NOT_FREE'],
    [{ expression: '(cf.bot_management.ja3_hash in {"x"})' }, 'BOT_MANAGEMENT_NOT_FREE'],
    [{ expression: '(lower(http.user_agent) contains "ok") or true' }, 'EXPRESSION_NOT_SUPPORTED'],
    [{ expression: '(lower(http.user_agent) contains "bad\\n")' }, 'EXPRESSION_NOT_SUPPORTED'],
    [{ expression: 'lower(http.host) eq "example.invalid"' }, 'EXPRESSION_NOT_SUPPORTED'],
    [{ action: 'skip' }, 'ACTION_NOT_SUPPORTED'],
    [{ action_parameters: { response: { status_code: 403, content: 'x' } } }, 'ACTION_PARAMETERS_NOT_SUPPORTED'],
    [{ unexpected: true }, 'RULE_FIELD_NOT_SUPPORTED'],
  ] as [Record<string, unknown>, string][]) {
    const result = assessCloudflareFreeWaf(withRule(changes), undefined, 0);
    assert.notStrictEqual(result.localGeneration, 'supported');
    assert.ok(result.reasons.includes(reason), reason);
  }
  assert.ok(assessCloudflareFreeWaf({ cloudflare_logpush_job: { logs: {} } }, undefined, 0).reasons.includes('METERED_RESOURCE_NOT_ALLOWED'));
  assert.strictEqual(assessCloudflareFreeWaf({ cloudflare_list: { list: {} } }, undefined, 0).localGeneration, 'unknown');
  assert.strictEqual(assessCloudflareFreeWaf({ cloudflare_ruleset: { managed: {
    kind: 'zone', phase: 'http_request_firewall_managed', rules: [],
  } } }, undefined, 0).localGeneration, 'unknown');
});

const POLICY_FREE_PREFLIGHT = `version: 2
project: free-preflight
request:
  allow_methods: [GET]
  block:
    ua_contains: [bot]
response_headers:
  hsts: "max-age=1"
firewall:
  geo:
    block_countries: [CN]
`;

test('Free CLI emits the same local artifact and reports unknown live applicability', () => {
  const ctx = tmpProject(POLICY_FREE_PREFLIGHT);
  try {
    const legacy = runCompiler(ctx.policyPath, path.join(ctx.dir, 'legacy'));
    assert.strictEqual(legacy.status, 0, legacy.stderr);
    const free = runCompiler(ctx.policyPath, path.join(ctx.dir, 'free'), ['--cloudflare-free']);
    assert.strictEqual(free.status, 0, free.stderr);
    const line = free.stderr.split('\n').find((line: string) => line.startsWith('Cloudflare Free preflight: '));
    const report = JSON.parse(line.slice('Cloudflare Free preflight: '.length));
    assert.strictEqual(report.savedCapacity, 'unknown');
    assert.strictEqual(report.liveDeployment, 'unknown');
    assert.deepStrictEqual(report.generated, { customRules: 2, rateRules: 0 });
    assert.deepStrictEqual(fs.readFileSync(path.join(ctx.dir, 'legacy/infra/cloudflare-waf.tf.json')),
      fs.readFileSync(path.join(ctx.dir, 'free/infra/cloudflare-waf.tf.json')));
  } finally { ctx.cleanup(); }
});

test('Free CLI binds saved capacity and never overwrites an existing artifact on rejection', () => {
  const ctx = tmpProject(POLICY_FREE_PREFLIGHT);
  try {
    const inventory = path.join(ctx.dir, 'inventory.json');
    fs.writeFileSync(inventory, freeInventory({ capturedAtMs: Date.now(), existingCustomRules: 3 }));
    const args = ['--cloudflare-free', '--cloudflare-free-inventory', inventory];
    const first = runCompiler(ctx.policyPath, ctx.dir, args);
    assert.strictEqual(first.status, 0, first.stderr);
    assert.match(first.stderr, /"savedCapacity":"fits"/);
    const output = path.join(ctx.dir, 'infra/cloudflare-waf.tf.json');
    fs.writeFileSync(output, 'preserve-existing-output');
    fs.writeFileSync(inventory, freeInventory({ capturedAtMs: Date.now(), existingCustomRules: 4 }));
    const rejected = runCompiler(ctx.policyPath, ctx.dir, [...args, '--allow-waf-approximation']);
    assert.notStrictEqual(rejected.status, 0);
    assert.match(rejected.stderr, /CUSTOM_RULE_CAPACITY_EXCEEDED/);
    assert.strictEqual(fs.readFileSync(output, 'utf8'), 'preserve-existing-output');
  } finally { ctx.cleanup(); }
});

test('Free CLI rejects ambiguous flags and invalid UTF8/oversized inventory files', () => {
  const ctx = tmpProject(POLICY_FREE_PREFLIGHT);
  try {
    const file = path.join(ctx.dir, 'private-token-inventory.json');
    for (const flags of [
      ['--cloudflare-free', '--cloudflare-free'], ['--cloudflare-free-inventory', file],
      ['--cloudflare-free=false'], ['--cloudflare-free-inventory=' + file],
      ['--cloudflare-free', '--cloudflare-free-inventory'],
      ['--cloudflare-free', '--cloudflare-free-inventory', file, '--cloudflare-free-inventory', file],
    ]) {
      const result = runCompiler(ctx.policyPath, ctx.dir, flags);
      assert.notStrictEqual(result.status, 0);
      assert.match(result.stderr, /CLOUDFLARE_FREE_INVALID: ARGUMENTS/);
    }
    for (const bytes of [Buffer.from([0xc3, 0x28]), Buffer.alloc(8193, 32)]) {
      fs.writeFileSync(file, bytes);
      const result = runCompiler(ctx.policyPath, ctx.dir, ['--cloudflare-free', '--cloudflare-free-inventory', file]);
      assert.notStrictEqual(result.status, 0);
      assert.match(result.stderr, /CLOUDFLARE_FREE_INVALID: INVENTORY_FILE/);
      assert.ok(!result.stderr.includes('private-token'));
    }
    assert.ok(!fs.existsSync(path.join(ctx.dir, 'infra/cloudflare-waf.tf.json')));
  } finally { ctx.cleanup(); }
});

test('Free CLI reuses the explicit rate profile and rejects a Business window before writing', () => {
  for (const plan of ['free', 'business']) {
    const ctx = tmpProject(POLICY_FREE_PREFLIGHT + `  waf:
    cloudflare_rate_limit_plan: ${plan}
    cloudflare_rate_limit_period: ${plan === 'free' ? 10 : 300}
    rate_limit: 200
`);
    try {
      const result = runCompiler(ctx.policyPath, ctx.dir, ['--cloudflare-free']);
      assert.strictEqual(result.status, plan === 'free' ? 0 : 1, result.stderr);
      if (plan === 'free') assert.match(result.stderr, /"generated":\{"customRules":2,"rateRules":1\}/);
      else {
        assert.match(result.stderr, /RATE_WINDOW_NOT_FREE/);
        assert.ok(!fs.existsSync(path.join(ctx.dir, 'infra/cloudflare-waf.tf.json')));
      }
    } finally { ctx.cleanup(); }
  }
});

test('Free inventory rejects a non-regular file without waiting on its contents', () => {
  const ctx = tmpProject(POLICY_FREE_PREFLIGHT);
  try {
    let file = ctx.dir;
    if (process.platform !== 'win32') {
      file = path.join(ctx.dir, 'inventory.fifo');
      const created = spawnSync('mkfifo', [file], { encoding: 'utf8' });
      assert.strictEqual(created.status, 0, created.stderr);
    }
    const result = spawnSync(process.execPath, [compilerPath, '--policy', ctx.policyPath, '--out-dir', ctx.dir,
      '--cloudflare-free', '--cloudflare-free-inventory', file], { encoding: 'utf8', timeout: 3000 });
    assert.strictEqual(result.error, undefined);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /CLOUDFLARE_FREE_INVALID: INVENTORY_FILE/);
    assert.ok(!fs.existsSync(path.join(ctx.dir, 'infra/cloudflare-waf.tf.json')));
  } finally { ctx.cleanup(); }
});

test('Free expression shape matching cannot mistake a raw marker for a JSON literal', () => {
  const source = freeCustomResources(1);
  for (const expression of ['(ip.geoip.country in {#})', '(lower(http.user_agent) contains #)',
    '(ip.geoip.country in {# "CN"})']) {
    source.cloudflare_ruleset.custom.rules[0].expression = expression;
    const result = assessCloudflareFreeWaf(source, undefined, 0);
    assert.strictEqual(result.localGeneration, 'unknown', expression);
    assert.ok(result.reasons.includes('EXPRESSION_NOT_SUPPORTED'));
  }
  source.cloudflare_ruleset.custom.rules[0].expression = '(lower(http.user_agent) contains "# matches")';
  assert.strictEqual(assessCloudflareFreeWaf(source, undefined, 0).localGeneration, 'supported');
});

test('UA compilation in both modes refuses Unicode folding that Cloudflare lower cannot provide', () => {
  const source = freeCustomResources(1);
  source.cloudflare_ruleset.custom.rules[0].expression = '(lower(http.user_agent) contains "évil")';
  const assessment = assessCloudflareFreeWaf(source, undefined, 0);
  assert.strictEqual(assessment.localGeneration, 'unknown');
  assert.ok(assessment.reasons.includes('UA_UNICODE_CASE_UNSUPPORTED'));
  const ctx = tmpProject(POLICY_FREE_PREFLIGHT.replace('ua_contains: [bot]', 'ua_contains: ["ÉVIL"]'));
  try {
    const free = runCompiler(ctx.policyPath, ctx.dir, ['--cloudflare-free']);
    assert.strictEqual(free.status, 1);
    assert.match(free.stderr, /UA_UNICODE_CASE_UNSUPPORTED/);
    assert.ok(!fs.existsSync(path.join(ctx.dir, 'infra/cloudflare-waf.tf.json')));
    const normal = runCompiler(ctx.policyPath, ctx.dir);
    assert.strictEqual(normal.status, 1);
    assert.match(normal.stderr, /UA_UNICODE_CASE_UNSUPPORTED/);
    assert.ok(!fs.existsSync(path.join(ctx.dir, 'infra/cloudflare-waf.tf.json')));
  } finally { ctx.cleanup(); }
});

test('Free UA input domain is checked before Unicode-to-ASCII conversion and Terraform templates', () => {
  for (const [literal, reason] of [['K', 'UA_UNICODE_CASE_UNSUPPORTED'],
    ['${var.ua}', 'EXPRESSION_TEMPLATE_UNSUPPORTED'], ['%{if true}', 'EXPRESSION_TEMPLATE_UNSUPPORTED']]) {
    const ctx = tmpProject(POLICY_FREE_PREFLIGHT.replace('ua_contains: [bot]', 'ua_contains: [' + JSON.stringify(literal) + ']'));
    try {
      const result = runCompiler(ctx.policyPath, ctx.dir, ['--cloudflare-free']);
      assert.strictEqual(result.status, 1, literal);
      assert.match(result.stderr, new RegExp(reason));
      assert.ok(!fs.existsSync(path.join(ctx.dir, 'infra/cloudflare-waf.tf.json')));
    } finally { ctx.cleanup(); }
  }
});

test('UA unsupported literals preserve absent and existing outputs in both modes,even with approximation allowed', () => {
  for (const [literal, reason] of [['K', 'UA_UNICODE_CASE_UNSUPPORTED'], ['İ', 'UA_UNICODE_CASE_UNSUPPORTED'],
    ['Σ', 'UA_UNICODE_CASE_UNSUPPORTED'], ['a\nb', 'UA_LITERAL_ENCODING_UNSUPPORTED'],
    ['a\tb', 'UA_LITERAL_ENCODING_UNSUPPORTED'], ['a\u007fb', 'UA_LITERAL_ENCODING_UNSUPPORTED']]) {
    for (const extra of [[], ['--cloudflare-free']]) {
      const ctx = tmpProject(POLICY_FREE_PREFLIGHT.replace('ua_contains: [bot]', () => 'ua_contains: [' + JSON.stringify(literal) + ']'));
      const output = path.join(ctx.dir, 'infra/cloudflare-waf.tf.json');
      try {
        for (const existing of [false, true]) {
          if (existing) { fs.mkdirSync(path.dirname(output), { recursive: true }); fs.writeFileSync(output, 'preserve-existing-ua-output'); }
          const result = runCompiler(ctx.policyPath, ctx.dir, [...extra, '--allow-waf-approximation']);
          assert.strictEqual(result.status, 1, JSON.stringify({ literal, extra, stderr: result.stderr }));
          assert.match(result.stderr, new RegExp('CLOUDFLARE_WAF_UNKNOWN: ' + reason));
          assert.ok(!result.stderr.includes(literal), 'diagnostic must not echo the literal');
          if (existing) assert.strictEqual(fs.readFileSync(output, 'utf8'), 'preserve-existing-ua-output');
          else assert.ok(!fs.existsSync(output));
        }
      } finally { ctx.cleanup(); }
    }
  }
});

for (const [literal, expression] of [
  ['BadBot', '(lower(http.user_agent) contains "badbot")'],
  ['A\\B', String.raw`(lower(http.user_agent) contains "a\\b")`],
  ['A\\"B', String.raw`(lower(http.user_agent) contains "a\\\"b")`],
  [String.raw`A\nB`, String.raw`(lower(http.user_agent) contains "a\\nb")`],
  ['A" or true or "B', String.raw`(lower(http.user_agent) contains "a\" or true or \"b")`],
]) {
  test('UA supported literal has the independent expected wire in both modes: ' + JSON.stringify(literal), () => {
    for (const extra of [[], ['--cloudflare-free']]) {
      const ctx = tmpProject(POLICY_FREE_PREFLIGHT.replace('ua_contains: [bot]', () => 'ua_contains: [' + JSON.stringify(literal) + ']'));
      try {
        const result = runCompiler(ctx.policyPath, ctx.dir, extra);
        assert.strictEqual(result.status, 0, result.stderr);
        const artifact = JSON.parse(fs.readFileSync(path.join(ctx.dir, 'infra/cloudflare-waf.tf.json'), 'utf8'));
        const ua = artifact.resource.cloudflare_ruleset['free-preflight_custom'].rules.find((r: any) => r.description === 'User-Agent blocklist');
        assert.strictEqual(ua.expression, expression);
      } finally { ctx.cleanup(); }
    }
  });
}

test('UA programmatic boundary rejects non-string items without coercion in both modes', () => {
  const { compileCloudflareWaf } = require(compilerPath);
  for (const literal of [1, null, {}, []]) {
    for (const free of [false, true]) {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-ua-invalid-'));
      try {
        assert.throws(() => compileCloudflareWaf({ version: 2, request: { block: { ua_contains: [literal] } } }, {
          outDir: dir, logger: { log() {}, error() {} }, ...(free ? { cloudflareFree: {} } : {}),
        }), /^Error: CLOUDFLARE_WAF_INVALID: UA_LITERAL_TYPE$/);
        assert.ok(!fs.existsSync(path.join(dir, 'infra')));
      } finally { fs.rmSync(dir, { recursive: true, force: true }); }
    }
  }
});


test('Free emitted-expression boundary rejects Terraform templates across custom and rate rules', () => {
  for (const literal of ['${1+1}', '%{if true}', '$${1+1}', '%%{if true}']) {
    for (const expression of ['(lower(http.user_agent) contains ' + JSON.stringify(literal) + ')',
      '(ip.geoip.country in {' + JSON.stringify(literal) + '})']) {
      const resources = freeCustomResources(1);
      resources.cloudflare_ruleset.custom.rules[0].expression = expression;
      const report = assessCloudflareFreeWaf(resources, undefined, 0);
      assert.strictEqual(report.localGeneration, 'unknown', expression);
      assert.ok(report.reasons.includes('EXPRESSION_TEMPLATE_UNSUPPORTED'));
    }
    const rules = buildCloudflareRateRules({ ...freeRate, rate_limit: undefined,
      rate_limit_rules: [{ name: 'path', limit: 100, expression_cloudflare: 'http.request.uri.path eq ' + JSON.stringify('/' + literal) }] });
    const report = assessCloudflareFreeWaf({ cloudflare_ruleset: { rate: { kind: 'zone', phase: 'http_ratelimit', rules } } }, undefined, 0);
    assert.strictEqual(report.localGeneration, 'unknown', literal);
    assert.ok(report.reasons.includes('EXPRESSION_TEMPLATE_UNSUPPORTED'));
  }
});

test('Free CLI refuses direct and scope-down rate templates before creating or replacing WAF output', () => {
  for (const literal of ['/${1+1}', '/%{if true}']) {
    for (const field of ['expression_cloudflare: ' + JSON.stringify('http.request.uri.path eq ' + JSON.stringify(literal)),
      'scope_down_statement: {byte_match_statement: {positional_constraint: STARTS_WITH, field_to_match: {uri_path: {}}, search_string: ' + JSON.stringify(literal) + '}}']) {
      const ctx = tmpProject(POLICY_FREE_PREFLIGHT + `  waf:
    cloudflare_rate_limit_plan: free
    cloudflare_rate_limit_period: 10
    rate_limit_rules:
      - name: path
        limit: 100
        ${field}
`);
      try {
        const output = path.join(ctx.dir, 'infra/cloudflare-waf.tf.json');
        for (const existing of [false, true]) {
          if (existing) { fs.mkdirSync(path.dirname(output), { recursive: true }); fs.writeFileSync(output, 'preserve-existing-output'); }
          const result = runCompiler(ctx.policyPath, ctx.dir, ['--cloudflare-free', '--allow-waf-approximation']);
          assert.strictEqual(result.status, 1, result.stderr);
          assert.match(result.stderr, /EXPRESSION_TEMPLATE_UNSUPPORTED/);
          if (existing) assert.strictEqual(fs.readFileSync(output, 'utf8'), 'preserve-existing-output');
          else assert.ok(!fs.existsSync(output));
        }
      } finally { ctx.cleanup(); }
    }
  }
});


for (const [name, literal, encoded, directive, encodedDirective] of [
  ['template markers', '${1+1}', '$${1+1}', '%{if true}end%{endif}', '%%{if true}end%%{endif}'],
  ['authored escape-like data', '$${1+1}', '$$${1+1}', '%%{if true}end%%{endif}', '%%%{if true}end%%%{endif}'],
]) {
  test('compiler: ruleset literals preserve ' + name + ' through Terraform JSON representation', () => {
    const policy = POLICY_FREE_PREFLIGHT.replace('ua_contains: [bot]', () => 'ua_contains: [' + JSON.stringify(literal) + ']') + `  waf:
    cloudflare_rate_limit_plan: business
    cloudflare_rate_limit_period: 10
    block_response:
      status_code: 403
      body: ${JSON.stringify('日本語 ' + literal + ' ' + directive)}
      content_type: TEXT_PLAIN
    rate_limit_rules:
      - name: direct
        limit: 100
        expression_cloudflare: ${JSON.stringify('http.request.uri.path eq ' + JSON.stringify('/' + literal))}
      - name: scoped
        limit: 100
        scope_down_statement:
          byte_match_statement:
            positional_constraint: STARTS_WITH
            field_to_match: {uri_path: {}}
            search_string: ${JSON.stringify('/' + literal)}
`;
    const ctx = tmpProject(policy);
    try {
      const result = runCompiler(ctx.policyPath, ctx.dir);
      assert.strictEqual(result.status, 0, result.stderr);
      const artifact = JSON.parse(fs.readFileSync(path.join(ctx.dir, 'infra/cloudflare-waf.tf.json'), 'utf8'));
      const custom = artifact.resource.cloudflare_ruleset['free-preflight_custom'];
      const ua = custom.rules.find((rule: any) => rule.description === 'User-Agent blocklist');
      assert.strictEqual(ua.expression, '(lower(http.user_agent) contains "' + encoded + '")');
      const rate = artifact.resource.cloudflare_ruleset['free-preflight_ratelimit'];
      assert.strictEqual(rate.rules.find((rule: any) => rule.description === 'direct').expression,
        'http.request.uri.path eq "/' + encoded + '"');
      assert.strictEqual(rate.rules.find((rule: any) => rule.description === 'scoped').expression,
        'starts_with(http.request.uri.path, "/' + encoded + '")');
      for (const set of [custom, rate]) {
        assert.strictEqual(set.zone_id, '${var.cloudflare_zone_id}');
        for (const rule of set.rules) assert.strictEqual(rule.action_parameters.response.content,
          '日本語 ' + encoded + ' ' + encodedDirective);
      }
    } finally { ctx.cleanup(); }
  });
}

// Independent requirements for the explicit WAF-only archetype; not Worker/WAF runtime parity.
const staticArchetypePath = path.join(repoRoot, 'policy/archetypes/cloudflare-free-static-site.yml');
const staticArchetypePolicy = () => fs.readFileSync(staticArchetypePath, 'utf8');
test('static Free archetype emits independent path method port blocks and no Worker', () => {
  const proj = tmpProject(staticArchetypePolicy());
  try {
    const result = runCompiler(proj.policyPath, proj.dir, ['--cloudflare-free']);
    assert.strictEqual(result.status, 0, result.stderr);
    const resource = JSON.parse(fs.readFileSync(path.join(proj.dir, 'infra/cloudflare-waf.tf.json'), 'utf8')).resource;
    assert.deepStrictEqual(Object.keys(resource), ['cloudflare_ruleset']);
    const sets = Object.values(resource.cloudflare_ruleset) as any[];
    assert.strictEqual(sets.length, 1);
    const rules = sets[0].rules;
    assert.strictEqual(rules.length, 4);
    assert.ok(rules.every((rule: any) => rule.enabled && rule.action === 'block' && rule.action_parameters.response === null));
    assert.strictEqual(rules.find((rule: any) => rule.description === 'Static site method allowlist').expression, 'not (http.request.method in {"GET" "HEAD"})');
    assert.strictEqual(rules.find((rule: any) => rule.description === 'Static site edge port allowlist').expression, 'not (cf.edge.server_port in {80 443})');
    assert.strictEqual(fs.existsSync(path.join(proj.dir, 'edge')), false);
    assert.match(result.stderr, /"generated":\{"customRules":4,"rateRules":0\}/);
  } finally { proj.cleanup(); }
});
test('static Free archetype requires explicit Free admission even with approximation allowed', () => {
  const proj = tmpProject(staticArchetypePolicy());
  try {
    const result = runCompiler(proj.policyPath, proj.dir, ['--allow-waf-approximation']);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /CLOUDFLARE_STATIC_INVALID: FREE_PROFILE_REQUIRED/);
    assert.strictEqual(fs.existsSync(path.join(proj.dir, 'infra')), false);
  } finally { proj.cleanup(); }
});
for (const entry of ['compile.js', 'compile-cloudflare.js', 'compile-infra.js']) {
  test('static WAF-only profile rejects wrong target ' + entry + ' before output', () => {
    const proj = tmpProject(staticArchetypePolicy());
    try {
      const result = spawnSync(process.execPath, [path.join(repoRoot, 'scripts', entry), '--policy', proj.policyPath, '--out-dir', path.join(proj.dir, 'out'), '--allow-placeholder-token'], { encoding: 'utf8' });
      assert.strictEqual(result.status, 1, result.stderr);
      assert.match(result.stderr, /CLOUDFLARE_STATIC_INVALID: WAF_ONLY_PROFILE/);
      assert.strictEqual(fs.existsSync(path.join(proj.dir, 'out')), false);
    } finally { proj.cleanup(); }
  });
}
test('static WAF profile rejects mixed Worker path requirements instead of ignoring them', () => {
  const text = staticArchetypePolicy().replace('    ua_contains:', "    path_patterns: { contains: ['/.hidden'] }\n    ua_contains:");
  const proj = tmpProject(text);
  try {
    const result = runCompiler(proj.policyPath, proj.dir, ['--cloudflare-free']);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /CLOUDFLARE_STATIC_UNKNOWN: WORKER_REQUIREMENTS/);
    assert.strictEqual(fs.existsSync(path.join(proj.dir, 'infra')), false);
  } finally { proj.cleanup(); }
});

const staticFieldPolicy = () => ({
  version: 2, project: 'static-fields', defaults: { mode: 'enforce' },
  request: { allow_methods: ['GET', 'HEAD'], block: { ua_contains: ['sqlmap'] } }, response_headers: {},
  firewall: { waf: { cloudflare_static_site: {
    allow_ports: [80, 443],
    block_paths: { exact: ['/.env', '/phpinfo.php'], prefix: ['/.git/', '/wp-admin/'], exceptions: ['/wp-admin/status'] },
    method_exceptions: [{ path: '/api/required.php', methods: ['POST'] }],
  } } },
});
const STATIC_PATH_WIRE = '((lower(http.request.uri.path) in {"/.env" "/phpinfo.php"} or starts_with(lower(http.request.uri.path), "/.git/") or starts_with(lower(http.request.uri.path), "/wp-admin/")) and not (lower(http.request.uri.path) in {"/wp-admin/status"}))';
const STATIC_METHOD_WIRE = 'not (http.request.method in {"GET" "HEAD"} or (http.request.method in {"POST"} and lower(http.request.uri.path) eq "/api/required.php"))';
const STATIC_PORT_WIRE = 'not (cf.edge.server_port in {80 443})';
test('static field fixtures preserve normal resources and keep exceptions within their own block', () => {
  const proj = tmpProject(JSON.stringify(staticFieldPolicy()));
  try {
    const result = runCompiler(proj.policyPath, proj.dir, ['--cloudflare-free']);
    assert.strictEqual(result.status, 0, result.stderr);
    const resource = JSON.parse(fs.readFileSync(path.join(proj.dir, 'infra/cloudflare-waf.tf.json'), 'utf8')).resource;
    const rules = (Object.values(resource.cloudflare_ruleset) as any[])[0].rules;
    // Four literal expressions and their independent requirement truth table.
    // This is a finite wire-format oracle, not a Rules-language/WAF interpreter.
    type Fields = { uri: string; method: string; edgePort: number; ua: string };
    const asciiLower = (text: string) => text.replace(/[A-Z]/g, c => c.toLowerCase());
    const requirements = new Map<string, (f: Fields) => boolean>([
      ['(lower(http.user_agent) contains "sqlmap")', f => asciiLower(f.ua).includes('sqlmap')],
      [STATIC_PATH_WIRE, f => {
        const p = asciiLower(f.uri);
        return (p === '/.env' || p === '/phpinfo.php' || p.startsWith('/.git/') || p.startsWith('/wp-admin/')) && p !== '/wp-admin/status';
      }],
      [STATIC_METHOD_WIRE, f => !(['GET', 'HEAD'].includes(f.method) || (f.method === 'POST' && asciiLower(f.uri) === '/api/required.php'))],
      [STATIC_PORT_WIRE, f => f.edgePort !== 80 && f.edgePort !== 443],
    ]);
    assert.strictEqual(rules.length, 4);
    assert.deepStrictEqual(new Set(rules.map((rule: any) => rule.expression)), new Set(requirements.keys()));
    assert.ok(rules.every((rule: any) => rule.enabled && rule.action === 'block' && rule.action_parameters.response === null));
    const httpCases = require('./fixtures/cloudflare-http-cases').HTTP_FIXTURE_CASES as Array<{ id: string; target: string; method?: string }>;
    const selected: Array<[string, boolean]> = [
      ['probe-env', true], ['probe-phpinfo', true], ['probe-git', true], ['probe-wp-admin-child', true],
      ['site-root', false], ['site-normal', false], ['site-en', false], ['site-ja', false], ['site-ja-encoded', false],
      ['site-well-known', false], ['site-cdn-cgi', false], ['site-js', false], ['site-wasm', false], ['site-required-php', false],
      ['site-wp-static', false], ['site-env-boundary', false], ['site-git-boundary', false], ['site-php-boundary', false], ['site-wp-boundary', false],
      ['site-head', false], ['site-post', false], ['method', true],
    ];
    // Reuse input literals only. These are supplied synthetic URI field values;
    // do not infer Cloudflare normalization from raw HTTP targets or Worker status.
    const cases = selected.map(([id, blocked]) => {
      const request = httpCases.find(c => c.id === id)!;
      return { id, fields: { uri: request.target, method: request.method || 'GET', edgePort: 443, ua: 'synthetic-browser' }, blocked };
    });
    cases.push(
      { id: 'ASCII-case', fields: { uri: '/.ENV', method: 'GET', edgePort: 443, ua: 'synthetic-browser' }, blocked: true },
      { id: 'path-exception', fields: { uri: '/wp-admin/status', method: 'GET', edgePort: 443, ua: 'synthetic-browser' }, blocked: false },
      { id: 'path-exception-method-block', fields: { uri: '/wp-admin/status', method: 'DELETE', edgePort: 443, ua: 'synthetic-browser' }, blocked: true },
      { id: 'path-exception-port-block', fields: { uri: '/wp-admin/status', method: 'GET', edgePort: 8443, ua: 'synthetic-browser' }, blocked: true },
      { id: 'path-exception-UA-block', fields: { uri: '/wp-admin/status', method: 'GET', edgePort: 443, ua: 'sqlmap' }, blocked: true },
      { id: 'method-exception-port-block', fields: { uri: '/api/required.php', method: 'POST', edgePort: 8443, ua: 'synthetic-browser' }, blocked: true },
      { id: 'method-exception-other-path', fields: { uri: '/about', method: 'POST', edgePort: 443, ua: 'synthetic-browser' }, blocked: true },
    );
    for (const c of cases) assert.strictEqual(rules.some((rule: any) => requirements.get(rule.expression)!(c.fields)), c.blocked, c.id);
    console.log('Static synthetic field subset: ' + cases.length + ' fixed cases; actual WAF/normalization/runtime UNKNOWN');
  } finally { proj.cleanup(); }
});

test('static Free quota includes new conditions and other generated custom rules', () => {
  const policy = staticFieldPolicy() as any;
  policy.firewall.geo = { block_countries: ['CN'], allow_countries: ['JP'] };
  const proj = tmpProject(JSON.stringify(policy));
  try {
    const result = runCompiler(proj.policyPath, proj.dir, ['--cloudflare-free']);
    assert.strictEqual(result.status, 1);
    assert.match(result.stderr, /CUSTOM_RULE_LIMIT_EXCEEDED/);
    assert.match(result.stderr, /"customRules":6/);
    assert.strictEqual(fs.existsSync(path.join(proj.dir, 'infra')), false);
  } finally { proj.cleanup(); }
});

test('static Free admission cannot reuse paid or unrecognized shape through literal stripping', () => {
  const allowed = [STATIC_PATH_WIRE, STATIC_METHOD_WIRE, STATIC_PORT_WIRE];
  for (const expression of allowed) {
    const resource = freeCustomResources(1) as any;
    resource.cloudflare_ruleset.custom.rules[0].expression = expression;
    assert.strictEqual(assessCloudflareFreeWaf(resource, undefined, 0).localGeneration, 'supported', expression);
    for (const suffix of [' or true', ' and http.host eq "example.invalid"']) {
      resource.cloudflare_ruleset.custom.rules[0].expression = expression + suffix;
      assert.strictEqual(assessCloudflareFreeWaf(resource, undefined, 0).localGeneration, 'unknown');
    }
  }
  for (const expression of ['not (cf.edge.server_port in {0})', 'not (cf.edge.server_port in {65536})', 'not (cf.edge.server_port in {1e3})', 'not (cf.edge.server_port in {"443"})']) {
    const resource = freeCustomResources(1) as any;
    resource.cloudflare_ruleset.custom.rules[0].expression = expression;
    assert.strictEqual(assessCloudflareFreeWaf(resource, undefined, 0).localGeneration, 'unknown');
  }
});

const staticInvalid: Array<[string, (p: any) => void]> = [
  ['empty paths', p => { p.firewall.waf.cloudflare_static_site.block_paths = { exact: [], prefix: [] }; }],
  ['regex', p => { p.firewall.waf.cloudflare_static_site.block_paths.regex = ['.*']; }],
  ['unknown field', p => { p.firewall.waf.cloudflare_static_site.skip = true; }],
  ['port type', p => { p.firewall.waf.cloudflare_static_site.allow_ports = ['443']; }],
  ['port zero', p => { p.firewall.waf.cloudflare_static_site.allow_ports = [0]; }],
  ['port overflow', p => { p.firewall.waf.cloudflare_static_site.allow_ports = [65536]; }],
  ['duplicate ports', p => { p.firewall.waf.cloudflare_static_site.allow_ports = [443, 443]; }],
  ['path trailing newline', p => { p.firewall.waf.cloudflare_static_site.block_paths.exact = ['/.env\n']; }],
  ['method trailing newline', p => { p.request.allow_methods = ['GET\n']; }],
  ['Unicode path', p => { p.firewall.waf.cloudflare_static_site.block_paths.exact = ['/private-K']; }],
  ['encoded path literal', p => { p.firewall.waf.cloudflare_static_site.block_paths.exact = ['/%2eenv']; }],
  ['query literal', p => { p.firewall.waf.cloudflare_static_site.block_paths.exact = ['/.env?private-token']; }],
  ['template literal', p => { p.firewall.waf.cloudflare_static_site.block_paths.exact = ['/${private-token}']; }],
  ['duplicate exception paths', p => { p.firewall.waf.cloudflare_static_site.method_exceptions.push({ path: '/api/required.php', methods: ['PUT'] }); }],
  ['method type', p => { p.request.allow_methods = [null]; }],
  ['empty methods', p => { p.request.allow_methods = []; }],
  ['monitor', p => { p.defaults.mode = 'monitor'; }],
  ['Worker route', p => { p.routes = [{ name: 'protected', match: { path_prefixes: ['/admin'] }, auth_gate: { type: 'static_token' } }]; }],
  ['Worker headers', p => { p.response_headers.hsts = 'max-age=100'; }],
  ['Worker normalize', p => { p.request.normalize = { drop_query_keys: ['utm_source'] }; }],
  ['AWS scope', p => { p.firewall.waf.scope = 'REGIONAL'; }],
];
for (const [name, alter] of staticInvalid) {
  test('static direct compiler rejects ' + name + ' before output', () => {
    const policy = staticFieldPolicy(); alter(policy);
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-static-invalid-'));
    try {
      assert.throws(() => require('./compile-cloudflare-waf').compileCloudflareWaf(policy, { outDir: path.join(out, 'generated'), cloudflareFree: {}, logger: { log() {}, error() {} } }), /CLOUDFLARE_STATIC_(?:INVALID|UNKNOWN):/);
      assert.strictEqual(fs.existsSync(path.join(out, 'generated')), false);
    } finally { fs.rmSync(out, { recursive: true, force: true }); }
  });
}
test('static expression size and sparse programmatic ports fail before output', () => {
  for (const sparse of [true, false]) {
    const policy = staticFieldPolicy() as any;
    if (sparse) policy.firewall.waf.cloudflare_static_site.allow_ports = Array(1);
    else policy.firewall.waf.cloudflare_static_site.block_paths.prefix = Array.from({ length: 32 }, (_, i) => '/' + String(i) + 'a'.repeat(250));
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-static-bound-'));
    try {
      assert.throws(() => require('./compile-cloudflare-waf').compileCloudflareWaf(policy, { outDir: path.join(out, 'generated'), cloudflareFree: {}, logger: { log() {}, error() {} } }), /CLOUDFLARE_STATIC_INVALID: (POLICY_SCHEMA|EXPRESSION_LIMIT)/);
      assert.strictEqual(fs.existsSync(path.join(out, 'generated')), false);
    } finally { fs.rmSync(out, { recursive: true, force: true }); }
  }
});

for (const [name, compile] of [
  ['AWS Worker', (p: any, o: any) => require('./lib/compile-core').build(p, o)],
  ['Cloudflare Worker', (p: any, o: any) => require('./compile-cloudflare').compileCloudflare(p, o)],
  ['AWS Infra', (p: any, o: any) => require('./compile-infra').compileInfra(p, o)],
] as const) {
  test('programmatic ' + name + ' rejects WAF-only profile before output', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-static-target-'));
    try {
      const outDir = path.join(dir, 'out');
      assert.throws(() => compile(staticFieldPolicy(), { outDir }), /CLOUDFLARE_STATIC_INVALID: WAF_ONLY_PROFILE/);
      assert.strictEqual(fs.existsSync(outDir), false);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
}

for (const target of ['aws', 'cloudflare']) {
  test('readiness rejects WAF-only profile for unsupported ' + target + ' build target', () => {
    const proj = tmpProject(staticArchetypePolicy());
    try {
      const result = spawnSync(process.execPath, [path.join(repoRoot, 'bin/cli.js'), 'readiness', '--policy', proj.policyPath, '--target', target, '--json'], { encoding: 'utf8', timeout: 15000 });
      assert.strictEqual(result.status, 1, result.stderr);
      const report = JSON.parse(result.stdout);
      assert.ok(report.findings.some((finding: any) => finding.id === 'firewall.waf.cloudflare_static_site.waf_only' && finding.severity === 'fail'));
    } finally { proj.cleanup(); }
  });
}

test('static resource placeholders cannot manufacture supported fields', () => {
  for (const expression of ['(S)', '(P)', 'not (M)', 'not (M or (M and E))']) {
    const resource = freeCustomResources(1) as any;
    resource.cloudflare_ruleset.custom.rules[0].expression = expression;
    assert.strictEqual(assessCloudflareFreeWaf(resource, undefined, 0).localGeneration, 'unknown', expression);
  }
});
