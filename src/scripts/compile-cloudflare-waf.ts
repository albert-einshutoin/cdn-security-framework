#!/usr/bin/env node
import { assertSupportedNode } from '../lib/node-engine';
assertSupportedNode(require.main === module);

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

import { runCompilerCli, type CompilerOptions } from './lib/compiler-entry';
const fs = require('fs');
const path = require('path');
const { numberOr } = require('./lib/value-normalize');

const parity = require('./lib/cloudflare-waf-parity');
const { buildCloudflareRateRules } = require('./lib/cloudflare-rate-limit');

export function compileCloudflareWaf(policy: any, options: CompilerOptions): void {
const outDir = options.outDir;
const console = options.logger || globalThis.console;
const failOnApproximation = options.failOnWafApproximation !== false;

// Parity warnings collected during emission — surfaced once at the end so
// the order is stable (managed rules first, then scope-down notes).
const parityWarnings: string[] = [];
let sawApproximationOrUnsupported = false;
function recordParity(entry: any) {
  const msg = parity.formatManagedRuleWarning(entry);
  if (!msg) return;
  parityWarnings.push(msg);
  sawApproximationOrUnsupported = true;
}

const firewall = policy.firewall || {};
const waf = firewall.waf || {};
const geo = firewall.geo || {};
const ip = firewall.ip || {};
const projectName = (policy.project || 'cdn-security').replace(/[^a-z0-9-]/gi, '-').toLowerCase();
let rateRules: any[];
rateRules = buildCloudflareRateRules(waf);
if (rateRules!.length) console.error('Cloudflare rate-limit profile: ' + waf.cloudflare_rate_limit_plan + '; local configuration only, account entitlement and remaining rule slots are unverified.');

const distDir = path.join(outDir, 'infra');
fs.mkdirSync(distDir, { recursive: true });

const tfJson: any = {
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
const ipBlocklistEntries = Array.isArray(ip.blocklist) ? ip.blocklist.filter((entry: unknown) => Boolean(entry)) : [];
const ipAllowlistEntries = Array.isArray(ip.allowlist) ? ip.allowlist.filter((entry: unknown) => Boolean(entry)) : [];
if (ipBlocklistEntries.length > 0) {
  tfJson.resource.cloudflare_list = tfJson.resource.cloudflare_list || {};
  tfJson.resource.cloudflare_list[projectName + '_ip_blocklist'] = {
    account_id: '${var.cloudflare_account_id}',
    name: projectName + '_ip_blocklist',
    description: 'CDN Security Framework: IP blocklist',
    kind: 'ip',
    item: ipBlocklistEntries.map((addr: unknown) => ({
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
    item: ipAllowlistEntries.map((addr: unknown) => ({
      value: { ip: String(addr) },
      comment: 'policy allowlist',
    })),
  };
}

// 2. Custom firewall ruleset (geo + IP + UA + path)
const customRules: any[] = [];
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
          status_code: numberOr(br.status_code, 403),
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
const geoBlockCountries = Array.isArray(geo.block_countries) ? geo.block_countries.filter((c: unknown) => Boolean(c)) : [];
const geoAllowCountries = Array.isArray(geo.allow_countries) ? geo.allow_countries.filter((c: unknown) => Boolean(c)) : [];
if (geoBlockCountries.length > 0) {
  const expr = `(ip.geoip.country in {${geoBlockCountries.map((c: unknown) => `"${c}"`).join(' ')}})`;
  customRules.push(Object.assign({
    description: 'Geo blocklist',
    enabled: true,
    expression: expr,
  }, makeBlockAction()));
}
if (geoAllowCountries.length > 0) {
  const expr = `not (ip.geoip.country in {${geoAllowCountries.map((c: unknown) => `"${c}"`).join(' ')}})`;
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
  const uaExprs = uaDeny.map((s: unknown) => `lower(http.user_agent) contains "${String(s).toLowerCase().replace(/"/g, '\\"')}"`);
  customRules.push(Object.assign({
    description: 'User-Agent blocklist',
    enabled: true,
    expression: `(${uaExprs.join(' or ')})`,
  }, makeBlockAction()));
}

// JA3/JA4 fingerprint rules
const fpAction = waf.fingerprint_action === 'count' ? 'log' : 'block';
const ja3List = Array.isArray(waf.ja3_fingerprints) ? waf.ja3_fingerprints.filter((h: unknown) => Boolean(h)) : [];
const ja4List = Array.isArray(waf.ja4_fingerprints) ? waf.ja4_fingerprints.filter((h: unknown) => Boolean(h)) : [];
if (ja3List.length > 0) {
  const expr = `(cf.bot_management.ja3_hash in {${ja3List.map((h: unknown) => `"${h}"`).join(' ')}})`;
  customRules.push({
    description: 'JA3 fingerprint ' + fpAction,
    enabled: true,
    expression: expr,
    action: fpAction,
    action_parameters: fpAction === 'block' ? makeBlockAction().action_parameters : {},
  });
}
if (ja4List.length > 0) {
  const expr = `(cf.bot_management.ja4 in {${ja4List.map((h: unknown) => `"${h}"`).join(' ')}})`;
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
    rules: customRules.map((r: any, idx: number) => Object.assign({ ref: `rule_${idx + 1}` }, r)),
  };
}

// 3. Shared, prevalidated rate-limit rules. No plan guessing or threshold rescaling.
if (rateRules.length > 0) {
  tfJson.resource.cloudflare_ruleset = tfJson.resource.cloudflare_ruleset || {};
  tfJson.resource.cloudflare_ruleset[projectName + '_ratelimit'] = {
    zone_id: '${var.cloudflare_zone_id}',
    name: projectName + '-ratelimit',
    description: 'CDN Security Framework: rate limits',
    kind: 'zone',
    phase: 'http_ratelimit',
    rules: rateRules.map((r: any, idx: number) => Object.assign({ ref: `rate_${idx + 1}` }, r)),
  };
}

// 4. Managed rulesets — consult cloudflare-waf-parity.js for every AWS entry
// so the compiler emits warnings for anything that is not `equivalent`. The
// compiler never silently swaps an AWS ruleset for a semantically-different
// Cloudflare one without surfacing the mismatch.
const managedEntries = Array.isArray(waf.managed_rules) ? waf.managed_rules : [];
if (managedEntries.length > 0) {
  const managedRules: any[] = [];
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
    rules: managedRules.map((r: any, idx: number) => Object.assign({ ref: `managed_${idx + 1}` }, r)),
  };
}

// 5. Bot Fight Mode — expressed as a zone setting; emit a one-line hint when
// BotControl appears in managed_rules but cannot be mapped one-to-one.
if (managedEntries.some((n: unknown) => n === 'AWSManagedRulesBotControlRuleSet' || n === 'AWSManagedRulesATPRuleSet')) {
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
  console.error('[cloudflare-waf-parity] approximate or unsupported Cloudflare WAF mappings detected (default fail-closed). Pass --allow-waf-approximation to warn-only.');
  throw new Error('Cloudflare WAF parity rejected');
}

}

if (require.main === module) runCompilerCli(compileCloudflareWaf);
