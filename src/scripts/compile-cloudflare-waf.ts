#!/usr/bin/env node
// @ts-nocheck
// @ts-nocheck
// @ts-nocheck
/**
 * Compile Cloudflare WAF: security.yml の firewall セクションを読み、
 * dist/infra/cloudflare-waf.tf.json に `cloudflare_ruleset` / `cloudflare_list`
 * を出力する。Cloudflare ターゲットで `firewall.waf.*` が silently ignored される
 * 問題（issue #16）を解消する。
 *
 * Emitted resources:
 *   - cloudflare_ruleset   (http_request_firewall_custom) — Geo / IP / UA / path blocks
 *   - cloudflare_ruleset   (http_ratelimit)               — rate_limit + rate_limit_rules
 *   - cloudflare_ruleset   (http_request_firewall_managed) — managed rulesets (OWASP, etc.)
 *   - cloudflare_list      (ip_list)                      — optional IP block/allowlists
 *   - variable             cloudflare_zone_id             — the zone the ruleset attaches to
 *
 * Usage: node scripts/compile-cloudflare-waf.js [--policy path] [--out-dir dir]
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const parity = require('./lib/cloudflare-waf-parity');

const repoRoot = path.join(__dirname, '..');
const argv = process.argv.slice(2);
const securityPath = path.join(repoRoot, 'policy', 'security.yml');
const basePath = path.join(repoRoot, 'policy', 'base.yml');
let policyPath = fs.existsSync(securityPath) ? securityPath : basePath;
let outDir = path.join(repoRoot, 'dist');
let failOnApproximation = false;
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--policy' && argv[i + 1]) { policyPath = argv[++i]; continue; }
  if (argv[i] === '--out-dir' && argv[i + 1]) { outDir = argv[++i]; continue; }
  if (argv[i] === '--fail-on-waf-approximation') { failOnApproximation = true; continue; }
  if (!argv[i].startsWith('--')) { policyPath = argv[i]; }
}

// Parity warnings collected during emission — surfaced once at the end so
// the order is stable (managed rules first, then scope-down notes).
const parityWarnings = [];
let sawApproximationOrUnsupported = false;
function recordParity(entry) {
  const msg = parity.formatManagedRuleWarning(entry);
  if (!msg) return;
  parityWarnings.push(msg);
  sawApproximationOrUnsupported = true;
}

let policy;
try {
  policy = yaml.load(fs.readFileSync(policyPath, 'utf8'));
} catch (e) {
  if (e.code === 'ENOENT') {
    console.error('Error: policy file not found:', policyPath);
    process.exit(1);
  }
  console.error('Error: failed to parse policy YAML:', e.message);
  process.exit(1);
}

const firewall = policy.firewall || {};
const waf = firewall.waf || {};
const geo = firewall.geo || {};
const ip = firewall.ip || {};
const projectName = (policy.project || 'cdn-security').replace(/[^a-z0-9-]/gi, '-').toLowerCase();

const distDir = path.join(outDir, 'infra');
fs.mkdirSync(distDir, { recursive: true });

const tfJson = {
  variable: {
    cloudflare_zone_id: {
      description: 'Cloudflare zone ID to attach rulesets to. Sourced from $CLOUDFLARE_ZONE_ID or equivalent in CI.',
      type: 'string',
    },
    cloudflare_account_id: {
      description: 'Cloudflare account ID. Required when attaching account-scoped rulesets / lists. Sourced from $CLOUDFLARE_ACCOUNT_ID.',
      type: 'string',
    },
  },
  resource: {},
};

// 1. IP lists (optional) — cloudflare_list with IPs. Rules below reference by id.
const ipBlocklistEntries = Array.isArray(ip.blocklist) ? ip.blocklist.filter(Boolean) : [];
const ipAllowlistEntries = Array.isArray(ip.allowlist) ? ip.allowlist.filter(Boolean) : [];
if (ipBlocklistEntries.length > 0) {
  tfJson.resource.cloudflare_list = tfJson.resource.cloudflare_list || {};
  tfJson.resource.cloudflare_list[projectName + '_ip_blocklist'] = {
    account_id: '${var.cloudflare_account_id}',
    name: projectName + '_ip_blocklist',
    description: 'CDN Security Framework: IP blocklist',
    kind: 'ip',
    item: ipBlocklistEntries.map((addr) => ({
      value: { ip: String(addr) },
      comment: 'policy blocklist',
    })),
  };
}
if (ipAllowlistEntries.length > 0) {
  tfJson.resource.cloudflare_list = tfJson.resource.cloudflare_list || {};
  tfJson.resource.cloudflare_list[projectName + '_ip_allowlist'] = {
    account_id: '${var.cloudflare_account_id}',
    name: projectName + '_ip_allowlist',
    description: 'CDN Security Framework: IP allowlist',
    kind: 'ip',
    item: ipAllowlistEntries.map((addr) => ({
      value: { ip: String(addr) },
      comment: 'policy allowlist',
    })),
  };
}

// 2. Custom firewall ruleset (geo + IP + UA + path)
const customRules = [];
let customPriority = 1;

function makeBlockAction() {
  // block_response: Cloudflare ruleset block actions support a custom response
  // via `action_parameters { response { status_code, content, content_type } }`.
  const br = waf.block_response;
  if (br && (br.body || br.status_code)) {
    return {
      action: 'block',
      action_parameters: {
        response: {
          status_code: Number(br.status_code) || 403,
          content: String(br.body || 'blocked'),
          content_type: (br.content_type === 'TEXT_HTML' ? 'text/html'
            : br.content_type === 'APPLICATION_JSON' ? 'application/json'
            : 'text/plain'),
        },
      },
    };
  }
  return { action: 'block', action_parameters: { response: null } };
}

// Geo block / allow
const geoBlockCountries = Array.isArray(geo.block_countries) ? geo.block_countries.filter(Boolean) : [];
const geoAllowCountries = Array.isArray(geo.allow_countries) ? geo.allow_countries.filter(Boolean) : [];
if (geoBlockCountries.length > 0) {
  const expr = `(ip.geoip.country in {${geoBlockCountries.map((c) => `"${c}"`).join(' ')}})`;
  customRules.push(Object.assign({
    description: 'Geo blocklist',
    enabled: true,
    expression: expr,
  }, makeBlockAction()));
}
if (geoAllowCountries.length > 0) {
  const expr = `not (ip.geoip.country in {${geoAllowCountries.map((c) => `"${c}"`).join(' ')}})`;
  customRules.push(Object.assign({
    description: 'Geo allowlist (reject anything outside)',
    enabled: true,
    expression: expr,
  }, makeBlockAction()));
}

// IP block via cloudflare_list
if (ipBlocklistEntries.length > 0) {
  customRules.push(Object.assign({
    description: 'IP blocklist',
    enabled: true,
    expression: `(ip.src in $${projectName}_ip_blocklist)`,
  }, makeBlockAction()));
}

// UA deny (subset — keep the heavy lifting on edge template; this is a WAF safety net)
const uaDeny = Array.isArray((policy.request || {}).block?.ua_contains)
  ? policy.request.block.ua_contains
  : [];
if (uaDeny.length > 0) {
  const uaExprs = uaDeny.map((s) => `lower(http.user_agent) contains "${String(s).toLowerCase().replace(/"/g, '\\"')}"`);
  customRules.push(Object.assign({
    description: 'User-Agent blocklist',
    enabled: true,
    expression: `(${uaExprs.join(' or ')})`,
  }, makeBlockAction()));
}

// JA3/JA4 fingerprint rules
const fpAction = waf.fingerprint_action === 'count' ? 'log' : 'block';
const ja3List = Array.isArray(waf.ja3_fingerprints) ? waf.ja3_fingerprints.filter(Boolean) : [];
const ja4List = Array.isArray(waf.ja4_fingerprints) ? waf.ja4_fingerprints.filter(Boolean) : [];
if (ja3List.length > 0) {
  const expr = `(cf.bot_management.ja3_hash in {${ja3List.map((h) => `"${h}"`).join(' ')}})`;
  customRules.push({
    description: 'JA3 fingerprint ' + fpAction,
    enabled: true,
    expression: expr,
    action: fpAction,
    action_parameters: fpAction === 'block' ? makeBlockAction().action_parameters : {},
  });
}
if (ja4List.length > 0) {
  const expr = `(cf.bot_management.ja4 in {${ja4List.map((h) => `"${h}"`).join(' ')}})`;
  customRules.push({
    description: 'JA4 fingerprint ' + fpAction,
    enabled: true,
    expression: expr,
    action: fpAction,
    action_parameters: fpAction === 'block' ? makeBlockAction().action_parameters : {},
  });
}

if (customRules.length > 0) {
  tfJson.resource.cloudflare_ruleset = tfJson.resource.cloudflare_ruleset || {};
  tfJson.resource.cloudflare_ruleset[projectName + '_custom'] = {
    zone_id: '${var.cloudflare_zone_id}',
    name: projectName + '-custom',
    description: 'CDN Security Framework: custom firewall rules (geo/IP/UA/fingerprint)',
    kind: 'zone',
    phase: 'http_request_firewall_custom',
    rules: customRules.map((r, idx) => Object.assign({ ref: `rule_${idx + 1}` }, r)),
  };
}

// 3. Rate-limit ruleset — rate_limit (legacy global) + rate_limit_rules[]
const rateRules = [];
if (waf.rate_limit) {
  rateRules.push({
    description: 'Global IP rate limit (legacy)',
    enabled: true,
    expression: 'true',
    action: 'block',
    action_parameters: makeBlockAction().action_parameters,
    ratelimit: {
      characteristics: ['ip.src'],
      period: 300,
      requests_per_period: Number(waf.rate_limit) || 2000,
      mitigation_timeout: 600,
    },
  });
}
if (Array.isArray(waf.rate_limit_rules)) {
  for (const rule of waf.rate_limit_rules) {
    if (!rule || !rule.name || !rule.limit) continue;
    const action = rule.action === 'count' ? 'log' : 'block';
    // scope_down_statement is AWS-shaped; not portable. Cloudflare uses the
    // `expression` field for scoping. We translate a minimal subset of well-
    // known scope-downs (URI starts-with) when recognized; otherwise require
    // `expression_cloudflare` to be set by the user. Unknown shapes degrade
    // to a `true` expression (global).
    let expression = 'true';
    let translatedShape = null;
    const sd = rule.scope_down_statement || {};
    const bm = sd.byte_match_statement;
    if (bm && bm.field_to_match && bm.field_to_match.uri_path && bm.positional_constraint === 'STARTS_WITH' && typeof bm.search_string === 'string') {
      expression = `starts_with(http.request.uri.path, "${String(bm.search_string).replace(/"/g, '\\"')}")`;
      translatedShape = 'byte_match_statement(uri_path, STARTS_WITH)';
    }
    if (typeof rule.expression_cloudflare === 'string' && rule.expression_cloudflare.trim()) {
      expression = rule.expression_cloudflare;
      translatedShape = 'expression_cloudflare override';
    }
    // Warn if a scope_down_statement was declared but not auto-translated and
    // no explicit expression_cloudflare override is present. This is the
    // silent-match-all class of drift the parity policy exists to prevent.
    if (Object.keys(sd).length > 0 && translatedShape === null) {
      parityWarnings.push(
        `[cloudflare-waf-parity] APPROXIMATE: rate_limit rule "${rule.name}" has scope_down_statement that this compiler does not auto-translate to a Cloudflare expression (shape: ${Object.keys(sd).join(', ')}). Rule degraded to expression: "true" (match-all). Set rule.expression_cloudflare on the policy to provide the exact scope. See docs/cloudflare-waf-parity.md#scope_down_statement-shapes.`,
      );
      sawApproximationOrUnsupported = true;
    }
    const characteristicsMap = {
      IP: ['ip.src'],
      FORWARDED_IP: ['http.x_forwarded_for'],
      CUSTOM_KEYS: Array.isArray(rule.cloudflare_characteristics) && rule.cloudflare_characteristics.length > 0
        ? rule.cloudflare_characteristics
        : ['ip.src'],
    };
    rateRules.push({
      description: rule.name,
      enabled: true,
      expression,
      action,
      action_parameters: action === 'block' ? makeBlockAction().action_parameters : {},
      ratelimit: {
        characteristics: characteristicsMap[rule.aggregate_key_type || 'IP'] || ['ip.src'],
        period: 300,
        requests_per_period: Number(rule.limit),
        mitigation_timeout: 600,
      },
    });
  }
}
if (rateRules.length > 0) {
  tfJson.resource.cloudflare_ruleset = tfJson.resource.cloudflare_ruleset || {};
  tfJson.resource.cloudflare_ruleset[projectName + '_ratelimit'] = {
    zone_id: '${var.cloudflare_zone_id}',
    name: projectName + '-ratelimit',
    description: 'CDN Security Framework: rate limits',
    kind: 'zone',
    phase: 'http_ratelimit',
    rules: rateRules.map((r, idx) => Object.assign({ ref: `rate_${idx + 1}` }, r)),
  };
}

// 4. Managed rulesets — consult cloudflare-waf-parity.js for every AWS entry
// so the compiler emits warnings for anything that is not `equivalent`. The
// compiler never silently swaps an AWS ruleset for a semantically-different
// Cloudflare one without surfacing the mismatch.
const managedEntries = Array.isArray(waf.managed_rules) ? waf.managed_rules : [];
if (managedEntries.length > 0) {
  const managedRules = [];
  for (const name of managedEntries) {
    const entry = parity.classifyManagedRule(name);
    recordParity(entry);
    const cfId = entry.cloudflare && entry.cloudflare.rulesetId;
    if (cfId) {
      managedRules.push({
        description:
          entry.status === 'equivalent'
            ? `AWS ${name} → Cloudflare ${entry.cloudflare.rulesetName} (equivalent)`
            : `AWS ${name} → Cloudflare ${entry.cloudflare.rulesetName} (APPROXIMATE — see docs/cloudflare-waf-parity.md)`,
        enabled: true,
        expression: 'true',
        action: 'execute',
        action_parameters: { id: cfId },
      });
    } else {
      managedRules.push({
        description: `UNSUPPORTED AWS managed rule: ${name}. No Cloudflare mapping — emitted disabled. See docs/cloudflare-waf-parity.md.`,
        enabled: false,
        expression: 'true',
        action: 'log',
        action_parameters: {},
      });
    }
  }
  tfJson.resource.cloudflare_ruleset = tfJson.resource.cloudflare_ruleset || {};
  tfJson.resource.cloudflare_ruleset[projectName + '_managed'] = {
    zone_id: '${var.cloudflare_zone_id}',
    name: projectName + '-managed',
    description: 'CDN Security Framework: managed ruleset bindings',
    kind: 'zone',
    phase: 'http_request_firewall_managed',
    rules: managedRules.map((r, idx) => Object.assign({ ref: `managed_${idx + 1}` }, r)),
  };
}

// 5. Bot Fight Mode — expressed as a zone setting; emit a one-line hint when
// BotControl appears in managed_rules but cannot be mapped one-to-one.
if (managedEntries.some((n) => n === 'AWSManagedRulesBotControlRuleSet' || n === 'AWSManagedRulesATPRuleSet')) {
  tfJson.resource.cloudflare_zone_settings_override = tfJson.resource.cloudflare_zone_settings_override || {};
  tfJson.resource.cloudflare_zone_settings_override[projectName + '_bots'] = {
    zone_id: '${var.cloudflare_zone_id}',
    settings: {
      bot_fight_mode: 'on',
    },
  };
}

// 6. Logging — Cloudflare Logpush for WAF events
const logging = waf.logging || {};
if (logging.enabled) {
  const destEnv = logging.destination_arn_env || 'CLOUDFLARE_LOGPUSH_DESTINATION';
  const destVarName = destEnv.toLowerCase();
  tfJson.variable[destVarName] = {
    description: `Logpush destination URI (e.g. s3://... or r2://...). Sourced from $${destEnv}.`,
    type: 'string',
  };
  tfJson.resource.cloudflare_logpush_job = tfJson.resource.cloudflare_logpush_job || {};
  tfJson.resource.cloudflare_logpush_job[projectName + '_waf_logs'] = {
    zone_id: '${var.cloudflare_zone_id}',
    name: projectName + '-waf-logs',
    enabled: true,
    dataset: 'firewall_events',
    destination_conf: '${var.' + destVarName + '}',
    output_options: {
      field_names: ['Action', 'ClientIP', 'ClientCountry', 'RuleID', 'RayID', 'Source'],
    },
  };
}

// Write file (always — empty WAF config still produces a file with just variables, so
// downstream tooling can `terraform plan` without a missing-file error).
const outPath = path.join(distDir, 'cloudflare-waf.tf.json');
fs.writeFileSync(outPath, JSON.stringify(tfJson, null, 2), 'utf8');
console.log('Build complete:', outPath);

// Emit parity warnings AFTER the file write so a failing exit still leaves a
// diffable artifact for the operator to inspect. stderr stream only — stdout
// reserved for the Terraform consumer / CI log.
for (const msg of parityWarnings) {
  console.error(msg);
}

if (failOnApproximation && sawApproximationOrUnsupported) {
  console.error('[cloudflare-waf-parity] --fail-on-waf-approximation set; exiting non-zero because the policy relies on approximate or unsupported Cloudflare mappings.');
  process.exit(1);
}
