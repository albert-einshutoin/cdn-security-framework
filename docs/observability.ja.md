# 観測とメトリクス

このドキュメントでは、Edge セキュリティレイヤー（CloudFront Functions / Lambda@Edge / Cloudflare Workers）で **ログとメトリクス** をどう取るかを推奨仕様として示します。ブロック件数や理由を把握し、トラフィックを分析できるようにするためです。

---

## スコープ

* **Edge セキュリティレイヤー** は、WAF や Origin に届く前にリクエストをブロックまたは正規化します。安全に運用するには、以下を把握することが望ましいです：
  * ブロックされたリクエスト数とその理由（メソッド、パストラバーサル、UA、クエリ、管理ゲート）。
  * レスポンスにセキュリティヘッダーが付与されているか。
* ここでは **推奨** するログフィールドとメトリクス次元を定義します。ランタイム側または CDN のログ（CloudFront アクセスログ、Workers 分析など）で実装してください。

---

## 構造化 JSON ログ（生成ランタイム）

`observability.log_format: json`（既定）を指定すると、生成された viewer-request / origin-request / Cloudflare Worker は判定 1 件につき 1 行の JSON を `console.log` に出力します。フィールド:

| フィールド | 説明 | 例 |
|------------|------|-----|
| `ts` | ISO-8601 タイムスタンプ | `2026-04-23T12:34:56.789Z` |
| `level` | block/monitor/audit は `info`、実行エラーは `error` | `info` |
| `event` | `block` / `monitor`（monitor モード）/ `audit` / `error` | `block` |
| `status` | 返した HTTP ステータス | `405` |
| `block_reason` | ブロック理由（下表参照） | `method_not_allowed` |
| `method` | リクエストメソッド | `POST` |
| `uri` | URI パス（既定ではクエリを除く） | `/admin` |
| `correlation_id` | 設定した相関ヘッダーの値（無ければ origin で採番） | `00-4bf9...-01` |

監査イベント（`audit_log_auth: true`）は追加で:

| フィールド | 説明 |
|------------|------|
| `auth_event` | JWT / 署名 URL 検証成功で `auth_pass` |
| `gate_type` | `jwt` / `signed_url` / `static_token` |
| `gate_name` | ポリシーの route `name:` |
| `sub` | JWT の `sub`。`audit_hash_sub: true` のとき SHA-256 先頭 16 hex |

ブロックイベント例:

```json
{"ts":"2026-04-23T12:34:56.789Z","level":"info","event":"block","status":405,"block_reason":"method_not_allowed","method":"POST","uri":"/anything","correlation_id":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
```

### ポリシー

```yaml
observability:
  log_format: "json"               # "json"（既定）または "text"
  correlation_id_header: "traceparent"  # もしくは "x-request-id"
  sample_rate: 1                   # 0..1（現状は advisory — block/audit は常時出力）
  audit_log_auth: true             # 認証ゲート成功時に audit イベントを出す
  audit_hash_sub: true             # sub を SHA-256 先頭 16 hex にハッシュ（PII 対策）
```

### 相関 ID 伝播

Lambda@Edge / Worker は受信リクエストに `correlation_id_header` が無いとき自動採番（`crypto.randomUUID` / `crypto.getRandomValues`）して origin への転送ヘッダに付与します。これにより Edge / WAF / Origin のログを同一 ID で串刺しできます。

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
