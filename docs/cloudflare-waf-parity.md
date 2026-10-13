# Cloudflare WAF parity

> **Languages:** English · [日本語](./cloudflare-waf-parity.ja.md)

This document is **generated** from `scripts/lib/cloudflare-waf-parity.js`. Do not edit by hand — run `node scripts/generate-parity-doc.js --write` after changing the metadata. The drift test in `scripts/check-drift.js` fails CI if this file falls out of sync.

The dual-target story ("one YAML, both CloudFront and Cloudflare") depends on users knowing which parts are 1:1 equivalents, which are approximations, and which simply do not exist on Cloudflare. Silent degradation would undermine the whole value proposition — so the compiler emits stderr warnings for every non-equivalent entry and **fails closed by default**. Pass `--allow-waf-approximation` for warn-only local exploration. `--fail-on-waf-approximation` remains as an explicit alias of the default.

## Legend

| Status | Meaning |
| --- | --- |
| `EQUIVALENT` | Cloudflare has a direct 1:1 resource. No warning. |
| `APPROXIMATE` | Close but not identical. Compiler warns and exits non-zero by default; `--allow-waf-approximation` keeps warn-only. |
| `UNSUPPORTED` | No reasonable Cloudflare mapping today. Rule emitted with `enabled: false`. Compiler warns and exits non-zero by default; `--allow-waf-approximation` keeps warn-only. |

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

## Cloudflare rate-limit configuration profiles

Checked 2026-10-13 against [Availability](https://developers.cloudflare.com/waf/rate-limiting-rules/#availability) and [Rate limiting parameters](https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/). This compiler supports a conservative subset: explicit `free` or `business`, IP plus mandatory `cf.colo.id`, and block actions. There is no inferred or default paid plan. This is local configuration validation, not account entitlement, remaining rule slots, permission, API acceptance, or overall Free WAF support.

- `free`: explicitly choose period **10 seconds** and a threshold, mitigation 10, at most **one total** global + individual rule.
- `business`: the existing 300-second window when period is omitted; supported discrete periods 10/60/120/300/600 and mitigation 10/60/120/300/600/3600/86400 (default 10), at most **five total** rules. Pro/Enterprise are not supported profiles. Mitigation 0 means block throttling, which is Enterprise-only; it is rejected for both profiles.
- Thresholds are integers 100..2,000,000,000. A 2000/300 configuration is never rescaled or silently converted to 2000/10. AWS keeps its 300-second window and aggregation/action support.
- Expressions are `true` or one URI-path `eq`/`starts_with`, optionally `lower(path)`. Only URI-path STARTS_WITH with absent/NONE/LOWERCASE priority-0 transformation is automatically translated. Complex expressions, custom/header/forwarded keys, count/captcha actions, and unsupported scope-downs are rejected; approximation flags cannot bypass this. Individual priority is unique, ascending (omitted = array position); the global rule is first. Custom block responses require 400..499, supported plain/HTML/JSON MIME, and at most 30,000 UTF-8 bytes.

Explicit Free example (choose the threshold for this 10-second window):

```yaml
firewall:
  waf:
    cloudflare_rate_limit_plan: free
    cloudflare_rate_limit_period: 10
    rate_limit: 200
```

Changing that example to `cloudflare_rate_limit_period: 300` fails before writing artifacts. To preserve an existing 2000/300 contract, explicitly set `cloudflare_rate_limit_plan: business` with `rate_limit: 2000`; leave period omitted or set 300. This requires Business and is not a recommendation to buy a plan. Shipped 5-minute samples declare this prerequisite. Guided Cloudflare init requires explicit `--cloudflare-rate-limit-plan business`; Free users should author the explicit policy above.

Counters are per Cloudflare location and may have enforcement delay; this does not promise a precise global/origin ceiling. Local workerd HTTP tests exercise the Worker/build only, not managed WAF counting, 429 enforcement, or live Free applicability.


## `scope_down_statement` shapes

AWS `rate_limit_rules[].scope_down_statement` is a structured AST. Cloudflare rate limits scope via the free-form `expression` field. The compiler translates a small set of shapes automatically; other shapes require a supported explicit path expression or are rejected even with approximation allowed.

| Shape | Status | Cloudflare expression | Notes |
| --- | --- | --- | --- |
| `byte_match_statement(uri_path, STARTS_WITH)` | `EQUIVALENT` | `starts_with(http.request.uri.path, "<value>")` | Direct URI-path STARTS_WITH translation, with only absent/NONE/LOWERCASE priority-0 transformation. |
| `byte_match_statement(uri_path, EXACTLY)` | `APPROXIMATE` | `http.request.uri.path eq "<value>"` | Not auto-translated. An explicit single path eq expression is supported. Otherwise rejected, even with approximation allowed. |
| `byte_match_statement(uri_path, CONTAINS)` | `APPROXIMATE` | `http.request.uri.path contains "<value>"` | Not supported by the local rate-limit profiles; rejected, even with approximation allowed. |
| `regex_match_statement` | `APPROXIMATE` | `http.request.uri.path matches "<regex>"` | Regex is outside the local rate-limit expression subset and is rejected, even with approximation allowed. |
| `label_match_statement / size_constraint_statement / geo_match_statement (inside scope-down)` | `UNSUPPORTED` | — | These AWS scope-down shapes have no direct expression counterpart. Use a supported explicit single path expression if it captures the intended scope; otherwise rejected, even with approximation allowed. |

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
npx cdn-security build --target cloudflare
# warn-only local exploration:
npx cdn-security build --target cloudflare --allow-waf-approximation
```

Exits non-zero by default when any `APPROXIMATE` or `UNSUPPORTED` entry is touched by the compiled policy. Pass `--allow-waf-approximation` only when you intentionally accept the parity gaps.

## Updating this document

1. Edit `scripts/lib/cloudflare-waf-parity.js`.
2. Bump `lastVerified` to today.
3. Run `node scripts/generate-parity-doc.js --write` and `node scripts/generate-parity-doc.js --write --lang=ja`.
4. Commit both the metadata change and the regenerated docs in the same PR.

