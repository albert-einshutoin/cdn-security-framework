# Cloudflare WAF パリティ

> **Languages:** [English](./cloudflare-waf-parity.md) · 日本語

このドキュメントは `scripts/lib/cloudflare-waf-parity.js` から **自動生成** されます。手で編集せず、メタデータ更新後に `node scripts/generate-parity-doc.js --write --lang=ja` を実行してください。`scripts/check-drift.js` がズレを検知すると CI が落ちます。

「1 つの YAML で CloudFront と Cloudflare 両方」という前提は、**どこが 1:1 等価で、どこが近似で、どこが未対応か** を利用者が把握していてはじめて成立します。黙って劣化させるのはアーキテクチャ上の罪なので、コンパイラは equivalent 以外の全てで stderr 警告を出し、`--fail-on-waf-approximation` を付けると本番 CI で非ゼロ終了します。

## 凡例

| ステータス | 意味 |
| --- | --- |
| `EQUIVALENT` | Cloudflare に 1:1 のリソースあり。警告なし。 |
| `APPROXIMATE` | 近いが同一ではない。警告あり。`--fail-on-waf-approximation` で非ゼロ終了。 |
| `UNSUPPORTED` | 現状 Cloudflare に対応物なし。ルールは `enabled: false` で出力。警告あり、`--fail-on-waf-approximation` で非ゼロ終了。 |

## AWS マネージドルール

| AWS ルール | ステータス | Cloudflare ターゲット | 最終確認日 |
| --- | --- | --- | --- |
| `AWSManagedRulesCommonRuleSet` | `EQUIVALENT` | Cloudflare Managed Ruleset (`efb7b8c949ac4650a09736fc376e9aee`) | 2026-04-24 |
| `AWSManagedRulesKnownBadInputsRuleSet` | `APPROXIMATE` | Cloudflare OWASP Core Ruleset (`4814384a9e5d4991b9815dcfc25d2f1f`) | 2026-04-24 |
| `AWSManagedRulesSQLiRuleSet` | `APPROXIMATE` | Cloudflare OWASP Core Ruleset (`4814384a9e5d4991b9815dcfc25d2f1f`) | 2026-04-24 |
| `AWSManagedRulesIPReputationList` | `APPROXIMATE` | Cloudflare Exposed Credentials Check Managed Ruleset (`c2e184081120413c86c3ab7e14069605`) | 2026-04-24 |
| `AWSManagedRulesBotControlRuleSet` | `APPROXIMATE` | Bot Fight Mode (zone setting) / Bot Management (paid) | 2026-04-24 |
| `AWSManagedRulesAnonymousIpList` | `APPROXIMATE` | Cloudflare Security Level (zone setting) + IP Lists (manual feeds) | 2026-04-24 |
| `AWSManagedRulesATPRuleSet` | `UNSUPPORTED` | — | 2026-04-24 |

### `AWSManagedRulesCommonRuleSet`

- **ステータス:** `EQUIVALENT`
- **Cloudflare ターゲット:** Cloudflare Managed Ruleset（id `efb7b8c949ac4650a09736fc376e9aee`）
- **ドキュメント:** https://developers.cloudflare.com/waf/managed-rules/reference/cloudflare-managed-ruleset/
- **最終確認日:** 2026-04-24

Cloudflare Managed Ruleset covers the same baseline injection / traversal / scanner signatures as AWS Common Rule Set. Field names differ but blocked traffic class is equivalent.

### `AWSManagedRulesKnownBadInputsRuleSet`

- **ステータス:** `APPROXIMATE`
- **Cloudflare ターゲット:** Cloudflare OWASP Core Ruleset（id `4814384a9e5d4991b9815dcfc25d2f1f`）
- **ドキュメント:** https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/
- **最終確認日:** 2026-04-24

OWASP Core Ruleset overlaps with Known Bad Inputs for scanner / exploit probes but is broader: enabling it also triggers the SQLi / XSS / LFI rule families. Tune the paranoia level and sensitivity after adopting.

### `AWSManagedRulesSQLiRuleSet`

- **ステータス:** `APPROXIMATE`
- **Cloudflare ターゲット:** Cloudflare OWASP Core Ruleset（id `4814384a9e5d4991b9815dcfc25d2f1f`）
- **ドキュメント:** https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/
- **最終確認日:** 2026-04-24

Cloudflare does not ship a standalone SQLi ruleset. The OWASP Core Ruleset covers SQLi via its 942xxx rule family, but declaring it means accepting the full OWASP bundle. If you only want SQLi today, map the individual OWASP rule IDs instead.

### `AWSManagedRulesIPReputationList`

- **ステータス:** `APPROXIMATE`
- **Cloudflare ターゲット:** Cloudflare Exposed Credentials Check Managed Ruleset（id `c2e184081120413c86c3ab7e14069605`）
- **ドキュメント:** https://developers.cloudflare.com/waf/managed-rules/reference/exposed-credentials-check/
- **最終確認日:** 2026-04-24

Cloudflare does not expose its IP reputation list via Ruleset Engine the way AWS does. Closest adjacent Cloudflare feature is Exposed Credentials Check (threat intel against credential-stuffing). If you need IP reputation specifically, enable Cloudflare Security Level (zone-scoped) outside this policy or use IP Lists against known-bad feeds.

### `AWSManagedRulesBotControlRuleSet`

- **ステータス:** `APPROXIMATE`
- **Cloudflare ターゲット:** Bot Fight Mode (zone setting) / Bot Management (paid)
- **ドキュメント:** https://developers.cloudflare.com/bots/
- **最終確認日:** 2026-04-24

Cloudflare bot mitigation is not a ruleset — it is a zone-scoped feature (Bot Fight Mode on free; Bot Management on enterprise). The compiler sets `bot_fight_mode: on` via cloudflare_zone_settings_override, which is only a coarse approximation of AWS Bot Control.

### `AWSManagedRulesAnonymousIpList`

- **ステータス:** `APPROXIMATE`
- **Cloudflare ターゲット:** Cloudflare Security Level (zone setting) + IP Lists (manual feeds)
- **ドキュメント:** https://developers.cloudflare.com/waf/tools/security-level/
- **最終確認日:** 2026-04-24

Cloudflare does not expose a managed anonymous-IP / VPN / Tor list as a Ruleset. Approximate coverage is available via the zone-level Security Level setting (blocks threat-scored traffic including known anonymizers) and Tor-exit custom IP Lists seeded from public feeds. Neither is a drop-in replacement for the AWS AnonymousIpList; the compiler emits the rule disabled so operators choose explicitly.

### `AWSManagedRulesATPRuleSet`

- **ステータス:** `UNSUPPORTED`
- **Cloudflare ターゲット:** なし
- **ドキュメント:** https://developers.cloudflare.com/bots/concepts/bot-score/
- **最終確認日:** 2026-04-24

AWS ATP (Account Takeover Prevention) runs credential-stuffing detection at the edge with stateful scoring. Cloudflare does not expose an equivalent via Ruleset Engine. Closest features (Bot Management, Super Bot Fight Mode) are not policy-portable. Declare ATP only on the AWS side for now.

## `scope_down_statement` 形状

AWS の `rate_limit_rules[].scope_down_statement` は構造化 AST ですが、Cloudflare のレートリミットは自由形式 `expression` でスコープを指定します。コンパイラは限られた形状だけ自動変換し、それ以外は policy 側で `rule.expression_cloudflare` を明示してもらう方針です。

| 形状 | ステータス | Cloudflare expression | 備考 |
| --- | --- | --- | --- |
| `byte_match_statement(uri_path, STARTS_WITH)` | `EQUIVALENT` | `starts_with(http.request.uri.path, "<value>")` | Direct translation — Cloudflare expression language has starts_with/ends_with/contains helpers. |
| `byte_match_statement(uri_path, EXACTLY)` | `APPROXIMATE` | `http.request.uri.path eq "<value>"` | Not yet auto-translated by the compiler. Set rule.expression_cloudflare to override. Will be promoted to equivalent once the translator is extended. |
| `byte_match_statement(uri_path, CONTAINS)` | `APPROXIMATE` | `http.request.uri.path contains "<value>"` | Not yet auto-translated. Set rule.expression_cloudflare. Will be promoted once the translator is extended. |
| `regex_match_statement` | `APPROXIMATE` | `http.request.uri.path matches "<regex>"` | Cloudflare supports regex via the `matches` operator but differs in flavor (RE2 vs AWS regex). Auto-translation would risk silent re-interpretation of edge cases. Require explicit expression_cloudflare. |
| `label_match_statement / size_constraint_statement / geo_match_statement (inside scope-down)` | `UNSUPPORTED` | — | These AWS scope-down shapes have no direct expression counterpart. Either flatten the scope-down into a separate Cloudflare rule, or provide expression_cloudflare explicitly on the rate_limit rule. |

## IP レピュテーション / リスト

| 機能 | ステータス | Cloudflare 対応面 | 最終確認日 |
| --- | --- | --- | --- |
| AWS WAF IP reputation list (managed) | `APPROXIMATE` | Exposed Credentials Check / Zone Security Level | 2026-04-24 |
| Custom IP block / allowlists | `EQUIVALENT` | cloudflare_list (ip kind) + custom firewall rule | 2026-04-24 |

- **AWS WAF IP reputation list (managed)** — Cloudflare does not expose IP reputation via Ruleset Engine. Use Security Level (zone setting) plus custom IP Lists seeded from a threat feed for comparable coverage.
- **Custom IP block / allowlists** — Direct translation. The compiler emits cloudflare_list + ruleset rule referencing $<name>_ip_blocklist.

## ロギング

| 機能 | ステータス | Cloudflare 対応面 | 最終確認日 |
| --- | --- | --- | --- |
| AWS WAF logging destination (Kinesis / CloudWatch / S3) | `APPROXIMATE` | cloudflare_logpush_job (dataset: firewall_events) | 2026-04-24 |

- **AWS WAF logging destination (Kinesis / CloudWatch / S3)** — Cloudflare Logpush streams firewall_events to S3/R2/GCS. Field names and event shape differ from AWS WAF logs — downstream log queries must be adapted.

## 本番 CI ゲート

```bash
npx cdn-security build --target cloudflare --fail-on-waf-approximation
```

コンパイル対象のポリシーが `APPROXIMATE` か `UNSUPPORTED` に触れていると非ゼロで終了します。`main` ブランチのパイプラインではこのゲートを有効化し、開発ブランチではデフォルト（警告のみ）のままで運用するのが推奨です。

## 更新手順

1. `scripts/lib/cloudflare-waf-parity.js` を編集する。
2. `lastVerified` を今日の日付に更新する。
3. `node scripts/generate-parity-doc.js --write` と `node scripts/generate-parity-doc.js --write --lang=ja` を実行する。
4. メタデータ変更と再生成ドキュメントを同じ PR でコミットする。

