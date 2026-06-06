# レスポンス DLP

> **言語:** [English](./response-dlp.md) - 日本語

`response_dlp` は、レスポンスヘッダーとサイズ上限内のテキスト系レスポンスボディを検査する opt-in のデータ漏えい防止ガードです。現時点で enforcement する target は Cloudflare Workers です。

```yaml
response_dlp:
  enabled: true
  action: report_only       # report_only | mask | block
  mask: "[REDACTED]"
  block_status: 451
  block_body: "Response blocked by edge DLP"
  body:
    enabled: true
    max_bytes: 32768
    content_types:
      - "text/"
      - "application/json"
  headers:
    enabled: true
    names:
      - "set-cookie"
      - "authorization"
      - "x-api-key"
  detectors:
    built_in:
      - "api_key"
      - "credit_card"
    custom_regex:
      - name: "internal_token"
        pattern: "internal_[A-Za-z0-9]{16,}"
```

## 対応 target

Cloudflare Workers は、設定されたレスポンスヘッダーと、テキスト系レスポンスボディの clone を検査できます。有効化すると、compiler は DLP 設定と detector regex を `dist/edge/cloudflare/index.ts` に注入します。

CloudFront Functions はレスポンス body を検査できません。AWS target で `response_dlp.enabled: true` の場合は unsupported warning を出し、レスポンス DLP の mask/block は enforcement しません。AWS 配備では Cloudflare Workers、Lambda/origin 側の制御、またはアプリケーション層の DLP を使ってください。

## action

| Action | 動作 |
|--------|------|
| `report_only` | DLP finding をログに出し、`X-Edge-DLP: report_only` を付け、レスポンス本体は変更しません。 |
| `mask` | 検出値を `mask` に置換し、body 書き換え時は `content-length` を削除し、`X-Edge-DLP: mask` を付けます。 |
| `block` | `block_status`、`block_body`、`Cache-Control: no-store`、`X-Edge-DLP: block` を持つ合成レスポンスを返します。 |

最初は `report_only` で開始し、本番に近い traffic に対して detector を調整してから mask/block に切り替えてください。

## detector

built-in detector は高信頼なものに限定しています。

- `api_key`: `sk-live-`、`sk_test_`、`ghp_` などの一般的な key prefix。
- `credit_card`: Luhn 検証に通る 13-19 桁の card-like 値。

custom regex detector は build 時に compile され、最大 10 件、1 pattern 256 文字までに制限されます。既知の nested quantifier 系 ReDoS 形状は拒否されます。custom detector は狭くし、anchor や prefix を使った pattern を優先してください。

## body の制限

body inspection は `body.enabled` が false ではなく、レスポンス `Content-Type` が設定された `content_types` のいずれかの部分文字列を含む場合だけ実行されます。既定値は text / JSON / XML 系レスポンスを対象にします。

`body.max_bytes` の既定は `32768`、上限は `131072` です。`Content-Length` が上限を超える場合、または clone した body を読んだ結果が上限を超える場合、Worker はレスポンスを変更せず通します。これにより edge の CPU とメモリコストを bounded に保ちます。

## header の制限

header inspection は `headers.names` に限定されます。未設定の場合の既定値は `set-cookie`、`authorization`、`x-api-key` です。レスポンス DLP は Cookie を意味的に parse せず、設定された header value を文字列として scan します。

## 運用メモ

- response DLP を secret 保護の唯一の手段にしないでください。可能な限り origin response に sensitive value を出さない設計を優先します。
- まず `report_only` を使い、`event` が `monitor`、`block_reason` が `response_dlp_report_only` の DLP finding を確認してから `mask` または `block` に切り替えてください。
- `max_bytes` は、実際に検査したい最大レスポンスサイズに近い値にしてください。
- 広いテキストに曖昧な wildcard を当てる custom regex は避けてください。build-time guard は一般的な ReDoS 形状を拒否しますが、狭い pattern の方が安全で高速です。
- 圧縮または暗号化された payload は、runtime が readable decoded body として露出しない限り decode しません。
