# Cloudflare WAF parity

> **Languages:** English · [日本語](./cloudflare-waf-parity.ja.md)

This document is **generated** from `scripts/lib/cloudflare-waf-parity.js`. Do not edit by hand — run `node scripts/generate-parity-doc.js --write` after changing the metadata. The drift test in `scripts/check-drift.js` fails CI if this file falls out of sync.

The dual-target story ("one YAML, both CloudFront and Cloudflare") depends on users knowing which parts are 1:1 equivalents, which are approximations, and which simply do not exist on Cloudflare. Silent degradation would undermine the whole value proposition — so the compiler emits stderr warnings for every non-equivalent entry, and `--fail-on-waf-approximation` promotes those to a non-zero exit for production CI.

## Legend

| Status | Meaning |
| --- | --- |
| `EQUIVALENT` | Cloudflare has a direct 1:1 resource. No warning. |
| `APPROXIMATE` | Close but not identical. Compiler warns; `--fail-on-waf-approximation` exits non-zero. |
| `UNSUPPORTED` | No reasonable Cloudflare mapping today. Rule emitted with `enabled: false`. Compiler warns; `--fail-on-waf-approximation` exits non-zero. |

## AWS managed rule sets

| AWS rule | Status | Cloudflare target | Last verified |
| --- | --- | --- | --- |
| `AWSManagedRulesCommonRuleSet` | `EQUIVALENT` | Cloudflare Managed Ruleset (`efb7b8c949ac4650a09736fc376e9aee`) | 2026-04-24 |
| `AWSManagedRulesKnownBadInputsRuleSet` | `APPROXIMATE` | Cloudflare OWASP Core Ruleset (`4814384a9e5d4991b9815dcfc25d2f1f`) | 2026-04-24 |
| `AWSManagedRulesSQLiRuleSet` | `APPROXIMATE` | Cloudflare OWASP Core Ruleset (`4814384a9e5d4991b9815dcfc25d2f1f`) | 2026-04-24 |
| `AWSManagedRulesIPReputationList` | `APPROXIMATE` | Cloudflare Exposed Credentials Check Managed Ruleset (`c2e184081120413c86c3ab7e14069605`) | 2026-04-24 |
| `AWSManagedRulesBotControlRuleSet` | `APPROXIMATE` | Bot Fight Mode (zone setting) / Bot Management (paid) | 2026-04-24 |
| `AWSManagedRulesAnonymousIpList` | `APPROXIMATE` | Cloudflare Security Level (zone setting) + IP Lists (manual feeds) | 2026-04-24 |
| `AWSManagedRulesATPRuleSet` | `UNSUPPORTED` | — | 2026-04-24 |

### `AWSManagedRulesCommonRuleSet`

- **Status:** `EQUIVALENT`
- **Cloudflare target:** Cloudflare Managed Ruleset (id `efb7b8c949ac4650a09736fc376e9aee`)
- **Docs:** https://developers.cloudflare.com/waf/managed-rules/reference/cloudflare-managed-ruleset/
- **Last verified:** 2026-04-24

Cloudflare Managed Ruleset covers the same baseline injection / traversal / scanner signatures as AWS Common Rule Set. Field names differ but blocked traffic class is equivalent.

### `AWSManagedRulesKnownBadInputsRuleSet`

- **Status:** `APPROXIMATE`
- **Cloudflare target:** Cloudflare OWASP Core Ruleset (id `4814384a9e5d4991b9815dcfc25d2f1f`)
- **Docs:** https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/
- **Last verified:** 2026-04-24

OWASP Core Ruleset overlaps with Known Bad Inputs for scanner / exploit probes but is broader: enabling it also triggers the SQLi / XSS / LFI rule families. Tune the paranoia level and sensitivity after adopting.

### `AWSManagedRulesSQLiRuleSet`

- **Status:** `APPROXIMATE`
- **Cloudflare target:** Cloudflare OWASP Core Ruleset (id `4814384a9e5d4991b9815dcfc25d2f1f`)
- **Docs:** https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/
- **Last verified:** 2026-04-24

Cloudflare does not ship a standalone SQLi ruleset. The OWASP Core Ruleset covers SQLi via its 942xxx rule family, but declaring it means accepting the full OWASP bundle. If you only want SQLi today, map the individual OWASP rule IDs instead.

### `AWSManagedRulesIPReputationList`

- **Status:** `APPROXIMATE`
- **Cloudflare target:** Cloudflare Exposed Credentials Check Managed Ruleset (id `c2e184081120413c86c3ab7e14069605`)
- **Docs:** https://developers.cloudflare.com/waf/managed-rules/reference/exposed-credentials-check/
- **Last verified:** 2026-04-24

Cloudflare does not expose its IP reputation list via Ruleset Engine the way AWS does. Closest adjacent Cloudflare feature is Exposed Credentials Check (threat intel against credential-stuffing). If you need IP reputation specifically, enable Cloudflare Security Level (zone-scoped) outside this policy or use IP Lists against known-bad feeds.

### `AWSManagedRulesBotControlRuleSet`

- **Status:** `APPROXIMATE`
- **Cloudflare target:** Bot Fight Mode (zone setting) / Bot Management (paid)
- **Docs:** https://developers.cloudflare.com/bots/
- **Last verified:** 2026-04-24

Cloudflare bot mitigation is not a ruleset — it is a zone-scoped feature (Bot Fight Mode on free; Bot Management on enterprise). The compiler sets `bot_fight_mode: on` via cloudflare_zone_settings_override, which is only a coarse approximation of AWS Bot Control.

### `AWSManagedRulesAnonymousIpList`

- **Status:** `APPROXIMATE`
- **Cloudflare target:** Cloudflare Security Level (zone setting) + IP Lists (manual feeds)
- **Docs:** https://developers.cloudflare.com/waf/tools/security-level/
- **Last verified:** 2026-04-24

Cloudflare does not expose a managed anonymous-IP / VPN / Tor list as a Ruleset. Approximate coverage is available via the zone-level Security Level setting (blocks threat-scored traffic including known anonymizers) and Tor-exit custom IP Lists seeded from public feeds. Neither is a drop-in replacement for the AWS AnonymousIpList; the compiler emits the rule disabled so operators choose explicitly.

### `AWSManagedRulesATPRuleSet`

- **Status:** `UNSUPPORTED`
- **Cloudflare target:** none
- **Docs:** https://developers.cloudflare.com/bots/concepts/bot-score/
- **Last verified:** 2026-04-24

AWS ATP (Account Takeover Prevention) runs credential-stuffing detection at the edge with stateful scoring. Cloudflare does not expose an equivalent via Ruleset Engine. Closest features (Bot Management, Super Bot Fight Mode) are not policy-portable. Declare ATP only on the AWS side for now.

## `scope_down_statement` shapes

AWS `rate_limit_rules[].scope_down_statement` is a structured AST. Cloudflare rate limits scope via the free-form `expression` field. The compiler translates a small set of shapes automatically; anything else must be expressed with `rule.expression_cloudflare` on the policy.

| Shape | Status | Cloudflare expression | Notes |
| --- | --- | --- | --- |
| `byte_match_statement(uri_path, STARTS_WITH)` | `EQUIVALENT` | `starts_with(http.request.uri.path, "<value>")` | Direct translation — Cloudflare expression language has starts_with/ends_with/contains helpers. |
| `byte_match_statement(uri_path, EXACTLY)` | `APPROXIMATE` | `http.request.uri.path eq "<value>"` | Not yet auto-translated by the compiler. Set rule.expression_cloudflare to override. Will be promoted to equivalent once the translator is extended. |
| `byte_match_statement(uri_path, CONTAINS)` | `APPROXIMATE` | `http.request.uri.path contains "<value>"` | Not yet auto-translated. Set rule.expression_cloudflare. Will be promoted once the translator is extended. |
| `regex_match_statement` | `APPROXIMATE` | `http.request.uri.path matches "<regex>"` | Cloudflare supports regex via the `matches` operator but differs in flavor (RE2 vs AWS regex). Auto-translation would risk silent re-interpretation of edge cases. Require explicit expression_cloudflare. |
| `label_match_statement / size_constraint_statement / geo_match_statement (inside scope-down)` | `UNSUPPORTED` | — | These AWS scope-down shapes have no direct expression counterpart. Either flatten the scope-down into a separate Cloudflare rule, or provide expression_cloudflare explicitly on the rate_limit rule. |

## IP reputation and lists

| Feature | Status | Cloudflare surface | Last verified |
| --- | --- | --- | --- |
| AWS WAF IP reputation list (managed) | `APPROXIMATE` | Exposed Credentials Check / Zone Security Level | 2026-04-24 |
| Custom IP block / allowlists | `EQUIVALENT` | cloudflare_list (ip kind) + custom firewall rule | 2026-04-24 |

- **AWS WAF IP reputation list (managed)** — Cloudflare does not expose IP reputation via Ruleset Engine. Use Security Level (zone setting) plus custom IP Lists seeded from a threat feed for comparable coverage.
- **Custom IP block / allowlists** — Direct translation. The compiler emits cloudflare_list + ruleset rule referencing $<name>_ip_blocklist.

## Logging

| Feature | Status | Cloudflare surface | Last verified |
| --- | --- | --- | --- |
| AWS WAF logging destination (Kinesis / CloudWatch / S3) | `APPROXIMATE` | cloudflare_logpush_job (dataset: firewall_events) | 2026-04-24 |

- **AWS WAF logging destination (Kinesis / CloudWatch / S3)** — Cloudflare Logpush streams firewall_events to S3/R2/GCS. Field names and event shape differ from AWS WAF logs — downstream log queries must be adapted.

## Production CI gate

```bash
npx cdn-security build --target cloudflare --fail-on-waf-approximation
```

Exits non-zero when any `APPROXIMATE` or `UNSUPPORTED` entry is touched by the compiled policy. Use this gate in `main`-branch pipelines; keep the default (warn-only) for development branches.

## Updating this document

1. Edit `scripts/lib/cloudflare-waf-parity.js`.
2. Bump `lastVerified` to today.
3. Run `node scripts/generate-parity-doc.js --write` and `node scripts/generate-parity-doc.js --write --lang=ja`.
4. Commit both the metadata change and the regenerated docs in the same PR.

