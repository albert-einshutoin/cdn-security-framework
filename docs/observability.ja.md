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
