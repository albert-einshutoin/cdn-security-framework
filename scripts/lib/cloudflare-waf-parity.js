// @ts-nocheck
/**
 * Cloudflare WAF parity metadata.
 *
 * Single source of truth for how AWS-shaped WAF policy concepts map onto
 * Cloudflare. Consumed by:
 *   - scripts/compile-cloudflare-waf.js  (emits warnings + resolves ruleset ids)
 *   - scripts/generate-parity-doc.js     (renders docs/cloudflare-waf-parity.md)
 *   - scripts/check-drift.js             (ensures the committed doc matches)
 *
 * Classifications:
 *   equivalent  — CF has a 1:1 resource. Compiler emits normally, no warning.
 *   approximate — CF has something close but not identical. Compiler emits
 *                 a stderr warning naming the rule, the CF target, and the
 *                 caveat. `--fail-on-waf-approximation` makes these fatal.
 *   unsupported — CF has no reasonable mapping today. Compiler emits the
 *                 rule as `enabled: false` + stderr warning. Also gated
 *                 by `--fail-on-waf-approximation`.
 *
 * Every entry has a `lastVerified` date. The drift test lives in
 * scripts/check-drift.js — when entries change, the generated doc is
 * re-rendered; the committed copy must match.
 */
'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
const MANAGED_RULES = [
    {
        aws: 'AWSManagedRulesCommonRuleSet',
        status: 'equivalent',
        cloudflare: {
            rulesetId: 'efb7b8c949ac4650a09736fc376e9aee',
            rulesetName: 'Cloudflare Managed Ruleset',
            docUrl: 'https://developers.cloudflare.com/waf/managed-rules/reference/cloudflare-managed-ruleset/',
        },
        rationale: 'Cloudflare Managed Ruleset covers the same baseline injection / traversal / scanner signatures as AWS Common Rule Set. Field names differ but blocked traffic class is equivalent.',
        lastVerified: '2026-04-24',
    },
    {
        aws: 'AWSManagedRulesKnownBadInputsRuleSet',
        status: 'approximate',
        cloudflare: {
            rulesetId: '4814384a9e5d4991b9815dcfc25d2f1f',
            rulesetName: 'Cloudflare OWASP Core Ruleset',
            docUrl: 'https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/',
        },
        rationale: 'OWASP Core Ruleset overlaps with Known Bad Inputs for scanner / exploit probes but is broader: enabling it also triggers the SQLi / XSS / LFI rule families. Tune the paranoia level and sensitivity after adopting.',
        lastVerified: '2026-04-24',
    },
    {
        aws: 'AWSManagedRulesSQLiRuleSet',
        status: 'approximate',
        cloudflare: {
            rulesetId: '4814384a9e5d4991b9815dcfc25d2f1f',
            rulesetName: 'Cloudflare OWASP Core Ruleset',
            docUrl: 'https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/',
        },
        rationale: 'Cloudflare does not ship a standalone SQLi ruleset. The OWASP Core Ruleset covers SQLi via its 942xxx rule family, but declaring it means accepting the full OWASP bundle. If you only want SQLi today, map the individual OWASP rule IDs instead.',
        lastVerified: '2026-04-24',
    },
    {
        aws: 'AWSManagedRulesIPReputationList',
        status: 'approximate',
        cloudflare: {
            rulesetId: 'c2e184081120413c86c3ab7e14069605',
            rulesetName: 'Cloudflare Exposed Credentials Check Managed Ruleset',
            docUrl: 'https://developers.cloudflare.com/waf/managed-rules/reference/exposed-credentials-check/',
        },
        rationale: 'Cloudflare does not expose its IP reputation list via Ruleset Engine the way AWS does. Closest adjacent Cloudflare feature is Exposed Credentials Check (threat intel against credential-stuffing). If you need IP reputation specifically, enable Cloudflare Security Level (zone-scoped) outside this policy or use IP Lists against known-bad feeds.',
        lastVerified: '2026-04-24',
    },
    {
        aws: 'AWSManagedRulesBotControlRuleSet',
        status: 'approximate',
        cloudflare: {
            rulesetId: null,
            rulesetName: 'Bot Fight Mode (zone setting) / Bot Management (paid)',
            docUrl: 'https://developers.cloudflare.com/bots/',
        },
        rationale: 'Cloudflare bot mitigation is not a ruleset — it is a zone-scoped feature (Bot Fight Mode on free; Bot Management on enterprise). The compiler sets `bot_fight_mode: on` via cloudflare_zone_settings_override, which is only a coarse approximation of AWS Bot Control.',
        lastVerified: '2026-04-24',
    },
    {
        aws: 'AWSManagedRulesAnonymousIpList',
        status: 'approximate',
        cloudflare: {
            rulesetId: null,
            rulesetName: 'Cloudflare Security Level (zone setting) + IP Lists (manual feeds)',
            docUrl: 'https://developers.cloudflare.com/waf/tools/security-level/',
        },
        rationale: 'Cloudflare does not expose a managed anonymous-IP / VPN / Tor list as a Ruleset. Approximate coverage is available via the zone-level Security Level setting (blocks threat-scored traffic including known anonymizers) and Tor-exit custom IP Lists seeded from public feeds. Neither is a drop-in replacement for the AWS AnonymousIpList; the compiler emits the rule disabled so operators choose explicitly.',
        lastVerified: '2026-04-24',
    },
    {
        aws: 'AWSManagedRulesATPRuleSet',
        status: 'unsupported',
        cloudflare: {
            rulesetId: null,
            rulesetName: null,
            docUrl: 'https://developers.cloudflare.com/bots/concepts/bot-score/',
        },
        rationale: 'AWS ATP (Account Takeover Prevention) runs credential-stuffing detection at the edge with stateful scoring. Cloudflare does not expose an equivalent via Ruleset Engine. Closest features (Bot Management, Super Bot Fight Mode) are not policy-portable. Declare ATP only on the AWS side for now.',
        lastVerified: '2026-04-24',
    },
];
const SCOPE_DOWN_TRANSLATIONS = [
    {
        shape: 'byte_match_statement(uri_path, STARTS_WITH)',
        status: 'equivalent',
        cloudflareExpression: 'starts_with(http.request.uri.path, "<value>")',
        rationale: 'Direct translation — Cloudflare expression language has starts_with/ends_with/contains helpers.',
    },
    {
        shape: 'byte_match_statement(uri_path, EXACTLY)',
        status: 'approximate',
        cloudflareExpression: 'http.request.uri.path eq "<value>"',
        rationale: 'Not yet auto-translated by the compiler. Set rule.expression_cloudflare to override. Will be promoted to equivalent once the translator is extended.',
    },
    {
        shape: 'byte_match_statement(uri_path, CONTAINS)',
        status: 'approximate',
        cloudflareExpression: 'http.request.uri.path contains "<value>"',
        rationale: 'Not yet auto-translated. Set rule.expression_cloudflare. Will be promoted once the translator is extended.',
    },
    {
        shape: 'regex_match_statement',
        status: 'approximate',
        cloudflareExpression: 'http.request.uri.path matches "<regex>"',
        rationale: 'Cloudflare supports regex via the `matches` operator but differs in flavor (RE2 vs AWS regex). Auto-translation would risk silent re-interpretation of edge cases. Require explicit expression_cloudflare.',
    },
    {
        shape: 'label_match_statement / size_constraint_statement / geo_match_statement (inside scope-down)',
        status: 'unsupported',
        cloudflareExpression: null,
        rationale: 'These AWS scope-down shapes have no direct expression counterpart. Either flatten the scope-down into a separate Cloudflare rule, or provide expression_cloudflare explicitly on the rate_limit rule.',
    },
];
const IP_REPUTATION_FEATURES = [
    {
        feature: 'AWS WAF IP reputation list (managed)',
        status: 'approximate',
        cloudflareSurface: 'Exposed Credentials Check / Zone Security Level',
        rationale: 'Cloudflare does not expose IP reputation via Ruleset Engine. Use Security Level (zone setting) plus custom IP Lists seeded from a threat feed for comparable coverage.',
        lastVerified: '2026-04-24',
    },
    {
        feature: 'Custom IP block / allowlists',
        status: 'equivalent',
        cloudflareSurface: 'cloudflare_list (ip kind) + custom firewall rule',
        rationale: 'Direct translation. The compiler emits cloudflare_list + ruleset rule referencing $<name>_ip_blocklist.',
        lastVerified: '2026-04-24',
    },
];
const LOGGING_FEATURES = [
    {
        feature: 'AWS WAF logging destination (Kinesis / CloudWatch / S3)',
        status: 'approximate',
        cloudflareSurface: 'cloudflare_logpush_job (dataset: firewall_events)',
        rationale: 'Cloudflare Logpush streams firewall_events to S3/R2/GCS. Field names and event shape differ from AWS WAF logs — downstream log queries must be adapted.',
        lastVerified: '2026-04-24',
    },
];
const MANAGED_RULES_INDEX = Object.fromEntries(MANAGED_RULES.map((e) => [e.aws, e]));
function classifyManagedRule(awsRuleName) {
    if (Object.prototype.hasOwnProperty.call(MANAGED_RULES_INDEX, awsRuleName)) {
        return MANAGED_RULES_INDEX[awsRuleName];
    }
    return {
        aws: awsRuleName,
        status: 'unsupported',
        cloudflare: { rulesetId: null, rulesetName: null, docUrl: null },
        rationale: 'No parity entry for this AWS managed rule. Treated as unsupported — compiler emits rule with enabled: false so Terraform apply does not silently attach a random ruleset. Add an entry to cloudflare-waf-parity.js when a mapping is decided.',
        lastVerified: null,
    };
}
function formatManagedRuleWarning(entry) {
    const target = entry.cloudflare.rulesetName
        ? `${entry.cloudflare.rulesetName}${entry.cloudflare.rulesetId ? ` (id: ${entry.cloudflare.rulesetId})` : ''}`
        : '(no Cloudflare target)';
    const docTail = entry.cloudflare.docUrl ? ` See ${entry.cloudflare.docUrl}` : '';
    if (entry.status === 'equivalent')
        return null;
    const prefix = entry.status === 'approximate'
        ? `[cloudflare-waf-parity] APPROXIMATE: ${entry.aws} → ${target}.`
        : `[cloudflare-waf-parity] UNSUPPORTED: ${entry.aws} has no mapping; rule emitted with enabled: false.`;
    return `${prefix} ${entry.rationale}${docTail}`;
}
module.exports = {
    MANAGED_RULES,
    SCOPE_DOWN_TRANSLATIONS,
    IP_REPUTATION_FEATURES,
    LOGGING_FEATURES,
    classifyManagedRule,
    formatManagedRuleWarning,
};
