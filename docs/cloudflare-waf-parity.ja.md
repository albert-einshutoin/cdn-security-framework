# Cloudflare WAF パリティ

> **Languages:** [English](./cloudflare-waf-parity.md) · 日本語

このドキュメントは `scripts/lib/cloudflare-waf-parity.js` から **自動生成** されます。手で編集せず、メタデータ更新後に `node scripts/generate-parity-doc.js --write --lang=ja` を実行してください。`scripts/check-drift.js` がズレを検知すると CI が落ちます。

「1 つの YAML で CloudFront と Cloudflare 両方」という前提は、**どこが 1:1 等価で、どこが近似で、どこが未対応か** を利用者が把握していてはじめて成立します。黙って劣化させるのはアーキテクチャ上の罪なので、コンパイラは equivalent 以外の全てで stderr 警告を出し、**既定で非ゼロ終了**します。調査用途では `--allow-waf-approximation` で警告のみにできます。`--fail-on-waf-approximation` は既定動作の明示エイリアスとして残しています。

## 凡例

| ステータス | 意味 |
| --- | --- |
| `EQUIVALENT` | Cloudflare に 1:1 のリソースあり。警告なし。 |
| `APPROXIMATE` | 近いが同一ではない。警告あり。既定で非ゼロ終了。`--allow-waf-approximation` で警告のみ。 |
| `UNSUPPORTED` | 現状 Cloudflare に対応物なし。ルールは `enabled: false` で出力。警告あり、既定で非ゼロ終了。`--allow-waf-approximation` で警告のみ。 |

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

## Cloudflare rate-limit の設定プロファイル

2026-10-13に[Availability](https://developers.cloudflare.com/waf/rate-limiting-rules/#availability)と[Rate limiting parameters](https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/)を確認。対応範囲は明示した`free`または`business`、IPと必須`cf.colo.id`、block actionに限定します。有料プランの推定や既定指定はありません。ローカルの設定検証であり、実アカウントの契約・残りルール枠・権限・API受理・WAF全体のFree対応の証拠ではありません。

- `free`: **10秒**と閾値を明示、mitigationは10秒、globalと個別の**合計1ルール**まで。
- `business`: 期間省略時は既存の300秒契約を保持。離散期間10/60/120/300/600秒、mitigation 10/60/120/300/600/3600/86400秒（既定10）、**合計5ルール**まで。Pro/Enterpriseは未対応です。mitigation 0はblockのthrottlingでEnterprise限定のため、両profileで拒否します。
- 閾値は整数100..2,000,000,000。2000回/300秒を比例換算したり2000回/10秒へ黙って変更したりしません。AWSの300秒契約と集約/action対応は維持します。
- 式は`true`またはURI pathの単一`eq`/`starts_with`（`lower(path)`可）だけ。自動変換はURI pathのSTARTS_WITHと、省略/NONE/LOWERCASEのpriority 0変換に限定します。複雑な式、custom/header/forwarded key、count/captcha、未対応scope-downは近似許可でも拒否します。個別priorityは一意の昇順（省略時は配列位置）、globalは先頭。custom block responseは400..499、plain/HTML/JSON MIME、UTF-8で30,000 bytes以内です。

明示的なFree例（10秒窓に適した閾値を利用者が選択）:

```yaml
firewall:
  waf:
    cloudflare_rate_limit_plan: free
    cloudflare_rate_limit_period: 10
    rate_limit: 200
```

この例を`cloudflare_rate_limit_period: 300`に変えると、成果物を書き込む前に失敗します。既存の2000回/300秒を保持するには、`cloudflare_rate_limit_plan: business`と`rate_limit: 2000`を明示し、期間を省略または300に指定します。Businessが前提であり、契約を推奨するものではありません。同梱の5分sampleはこの前提を宣言します。Cloudflare guided initは`--cloudflare-rate-limit-plan business`の明示指定が必要です。Free利用者は上記の明示policyを作成してください。

計数はCloudflare locationごとで反映遅延があり、厳密な全体/origin上限を保証しません。ローカルworkerd HTTPテストはWorker/buildの検証であり、管理WAFの計数・429・実Free適用の証拠ではありません。


## `scope_down_statement` 形状

AWS の `rate_limit_rules[].scope_down_statement` は構造化 AST ですが、Cloudflare のレートリミットは自由形式 `expression` でスコープを指定します。コンパイラは限られた形状だけ自動変換し、それ以外は対応する単一path式を明示するか、近似許可でも拒否します。

| 形状 | ステータス | Cloudflare expression | 備考 |
| --- | --- | --- | --- |
| `byte_match_statement(uri_path, STARTS_WITH)` | `EQUIVALENT` | `starts_with(http.request.uri.path, "<value>")` | Direct URI-path STARTS_WITH translation, with only absent/NONE/LOWERCASE priority-0 transformation. |
| `byte_match_statement(uri_path, EXACTLY)` | `APPROXIMATE` | `http.request.uri.path eq "<value>"` | Not auto-translated. An explicit single path eq expression is supported. Otherwise rejected, even with approximation allowed. |
| `byte_match_statement(uri_path, CONTAINS)` | `APPROXIMATE` | `http.request.uri.path contains "<value>"` | Not supported by the local rate-limit profiles; rejected, even with approximation allowed. |
| `regex_match_statement` | `APPROXIMATE` | `http.request.uri.path matches "<regex>"` | Regex is outside the local rate-limit expression subset and is rejected, even with approximation allowed. |
| `label_match_statement / size_constraint_statement / geo_match_statement (inside scope-down)` | `UNSUPPORTED` | — | These AWS scope-down shapes have no direct expression counterpart. Use a supported explicit single path expression if it captures the intended scope; otherwise rejected, even with approximation allowed. |

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
npx cdn-security build --target cloudflare
# 調査用途（警告のみ）:
npx cdn-security build --target cloudflare --allow-waf-approximation
```

コンパイル対象のポリシーが `APPROXIMATE` か `UNSUPPORTED` に触れていると、既定で非ゼロ終了します。パリティギャップを意図的に受け入れるときだけ `--allow-waf-approximation` を付けてください。

## 更新手順

1. `scripts/lib/cloudflare-waf-parity.js` を編集する。
2. `lastVerified` を今日の日付に更新する。
3. `node scripts/generate-parity-doc.js --write` と `node scripts/generate-parity-doc.js --write --lang=ja` を実行する。
4. メタデータ変更と再生成ドキュメントを同じ PR でコミットする。

