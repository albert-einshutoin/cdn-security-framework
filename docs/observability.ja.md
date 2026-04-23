# 観測とメトリクス

このドキュメントでは、Edge セキュリティレイヤー（CloudFront Functions / Lambda@Edge / Cloudflare Workers）で **ログとメトリクス** をどう取るかを推奨仕様として示します。ブロック件数や理由を把握し、トラフィックを分析できるようにするためです。

---

## スコープ

* **Edge セキュリティレイヤー** は、WAF や Origin に届く前にリクエストをブロックまたは正規化します。安全に運用するには、以下を把握することが望ましいです：
  * ブロックされたリクエスト数とその理由（メソッド、パストラバーサル、UA、クエリ、管理ゲート）。
  * レスポンスにセキュリティヘッダーが付与されているか。
* ここでは **推奨** するログフィールドとメトリクス次元を定義します。ランタイム側または CDN のログ（CloudFront アクセスログ、Workers 分析など）で実装してください。

---

## 推奨ログフィールド（ブロック時）

Edge セキュリティレイヤーが 4xx（400, 401, 403, 405, 414）を返したときに、少なくとも以下をログすることを推奨します。

| フィールド | 説明 | 例 |
|------------|------|-----|
| `block_reason` | ブロック理由 | `method_not_allowed`, `path_traversal`, `ua_denied`, `query_limit`, `admin_unauthorized` |
| `status_code` | 返した HTTP ステータス | `400`, `401`, `403`, `405`, `414` |
| `method` | リクエストメソッド | `GET`, `OPTIONS` |
| `uri` または `path` | リクエスト URI（サニタイズ推奨；クエリがセンシティブな場合は全文を出さない） | `/admin`, `/foo/../bar` |
| `user_agent` | User-Agent（任意；長い・センシティブな場合は省略やハッシュ化） | 厳格な環境では切り詰めやハッシュ |

任意: `request_id`, `timestamp`, `region` / `edge_location`（CDN が提供する場合）。

---

## ブロック理由の対応表

| ポリシー / ランタイムのチェック | 推奨 `block_reason` | ステータス |
|--------------------------------|---------------------|------------|
| 許可メソッド外 | `method_not_allowed` | 405 |
| パストラバーサル（`../`, `%2e%2e` 等） | `path_traversal` | 400 |
| UA 拒否リスト該当または UA 欠落 | `ua_denied` | 403 または 400 |
| クエリ長・パラメータ数超過 | `query_limit` | 414 または 400 |
| 管理パスでトークン不正・欠落 | `admin_unauthorized` | 401 |

---

## メトリクス（推奨次元）

メトリクスを集約する場合（CloudWatch、Datadog、Cloudflare Analytics など）、次のような次元を推奨します。

| メトリクス / 次元 | 説明 |
|-------------------|------|
| `edge_security_block_count` | Edge セキュリティレイヤーでブロックしたリクエスト数（カウンタ）。 |
| `block_reason` | 次元: `method_not_allowed`, `path_traversal`, `ua_denied`, `query_limit`, `admin_unauthorized`。 |
| `status_code` | 次元: 400, 401, 403, 405, 414。 |

例: `edge_security_block_count{block_reason="ua_denied", status_code="403"}`。

---

## 実装上の注意

* **CloudFront Functions**: ログ API はない。CloudFront アクセスログを利用するか、レスポンスにデバッグ用ヘッダー（例: `x-edge-block-reason`）を付与する。本番でセンシティブな場合は本番では外す。同一 Behavior で Lambda@Edge を使う場合はそちらでログ送信も可。
* **Lambda@Edge**: `console.log`（または自前ロガー）で `block_reason` と `status_code` を含む JSON を出力し、CloudWatch Logs に送り、メトリクスフィルタで集計する。
* **Cloudflare Workers**: `console.log` または Workers 分析 / カスタムメトリクスを利用。デバッグ用に `x-edge-block-reason` ヘッダーを付与する場合は任意。

---

## セキュリティヘッダー（レスポンス）

Edge セキュリティレイヤーを通過したレスポンスには、フレームワークで定義したセキュリティヘッダー（HSTS, X-Content-Type-Options, CSP など）が付与されます。本番で確認するには：

* レスポンスをサンプリングし、期待するヘッダーが付いているかを確認する。
* ランタイムでオーバーヘッドが許容できる場合は、パスプレフィックス（例: `/`, `/admin`）ごとに `edge_security_headers_applied_count` のようなメトリクスを出すことも可能。

---

## 関連

* [アーキテクチャ](architecture.ja.md) — Edge / WAF / Origin の責務。
* [脅威モデル](threat-model.ja.md) — エッジで扱う脅威。

---

## WAF ロギング（AWS）

`firewall.waf.logging` は Web ACL と同じファイルに `aws_wafv2_logging_configuration` を出力する。宛先 ARN 自体はポリシーに書かずシークレットマネージャ / CI から渡せるよう、コンパイラは Terraform 変数を自動生成する。

```yaml
firewall:
  waf:
    scope: CLOUDFRONT
    logging:
      enabled: true
      destination_arn_env: "WAF_LOG_DESTINATION_ARN"
      redacted_fields:
        - "authorization"
        - "cookie"
        - "x-api-key"
```

### 宛先の選び方

- **Kinesis Firehose → S3**: 定番。>10k rec/s かつクロスリージョン配送可。PCI / SOC2 で 30 日超の保持要件があるならこれ。
- **CloudWatch Logs**: 既に CW Insights で照会しているなら最安。ロググループ毎のレート制限に注意。
- **S3 直送**: ストリーム再生不要で結果整合を受容できる場合のみ。

宛先名は `aws_wafv2_logging_configuration` の規約に従う必要がある——Kinesis Firehose 名は `aws-waf-logs-` 始まり必須。

### レッダクション

`redacted_fields` は指定したリクエストフィールドを WAF 内部でログレコードから落とす。許可値: `authorization`, `cookie`, `set-cookie`, `x-api-key`, `x-csrf-token`。WAF の中で落とすので下流パイプラインに生値は流れない。認証トラフィックを扱うなら最低 `cookie` + `authorization` は推奨。

### Lint 警告

`npm run lint:policy` は `defaults.mode == enforce` かつ `firewall.waf.scope == CLOUDFRONT` でロギングが無効のとき、非致命的な警告を出す:

```
Policy lint warnings: policy/security.yml
  - firewall.waf.logging is not enabled while scope=CLOUDFRONT. PCI-DSS / SOC2 require WAF log retention — set logging.enabled: true and supply destination_arn_env.
```

REGIONAL スコープでは ALB アクセスログで代替可能なケースが多いので警告しない。

### マネージドルール網羅 Lint

同じ Lint パスで、enforce モードなのに BotControl / ATP / IPReputationList / AnonymousIpList が一つも無い設定には警告を出す。この 4 つは「WAF でなぜ止められなかった？」の原因になりやすい群。警告のみでビルドは止めない。

### カスタムブロックレスポンス

`firewall.waf.block_response` で既定の WAF 403 ページ（ベンダー情報が漏れる）をブランド済みページに差し替える。ルールグループと Web ACL の双方に `custom_response_bodies` を出力するので、どのブロックルールからも `custom_response_body_key: cdn_sec_block` で参照できる。

```yaml
firewall:
  waf:
    block_response:
      status_code: 403
      body: "Access denied. Reference: {RID}"
      content_type: "TEXT_PLAIN"
```

---

## フィンガープリント運用（JA3/JA4）

JA3/JA4 は段階的に運用してください。

1. `firewall.waf.fingerprint_action: count` で開始
2. WAF ログから候補を抽出
3. 誤検知レビュー後に `block` へ昇格

候補抽出ヘルパー:

```bash
node scripts/fingerprint-candidates.js --input waf-logs.jsonl --min-count 20 --top 50
```

出力内容:

- 出現頻度上位の JA3/JA4 候補
- レビュー用の policy 差分スニペット（`recommended_policy_patch`）
