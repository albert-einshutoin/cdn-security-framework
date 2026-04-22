# ポリシーとランタイムの同期

このドキュメントでは、**ポリシー**（`policy/security.yml` または `policy/base.yml`）と **ランタイム**（CloudFront Functions / Lambda@Edge / Cloudflare Workers）の同期のしかたを説明します。

---

## 現状

* **ポリシー** が唯一の正です。YAML を編集して以下を変更します：
  * 許可メソッド、クエリ/URI 制限
  * ブロックルール（パスパターン、UA 拒否リスト、必須ヘッダー欠落）
  * 正規化（例: `drop_query_keys`）
  * ルート（例: `/admin`, `/docs`）と認証ゲート
  * レスポンスヘッダー（HSTS、CSP など）

* **CloudFront Functions（viewer-request / viewer-response）** と **Lambda@Edge（origin-request）** は CLI コンパイラ（`npx cdn-security build`）で **自動生成** され、`dist/edge/*.js` に出力されます。
* **Cloudflare Workers** は Cloudflare ターゲットコンパイラ（`npx cdn-security build --target cloudflare`）で **自動生成** され、`dist/edge/cloudflare/index.ts` に出力されます。
* 生成対象では `CFG` やランタイム設定の手動同期は不要です。

---

## ポリシーを変更したときの手順

1. `policy/security.yml`（または `policy/base.yml`）を編集する。
2. ビルド（ポリシー検証と Edge コード生成）を実行する：
   ```bash
   npx cdn-security build
   ```
3. 生成された **`dist/edge/`** 内のファイルを CDN にデプロイする（例: Terraform の `file("dist/edge/viewer-request.js")`、CDK、コンソール）。
4. `dist/edge/` の生成物を各ランタイム（CloudFront Functions / Lambda@Edge / Cloudflare Workers）へデプロイする。

---

## ポリシーコンパイラ（実装済み）

**ポリシーコンパイラ**（CLI: `npx cdn-security build`）は次のことを行います。

* `policy/security.yml` または `policy/base.yml`（および `--policy` でパス指定可能）を読み込む。
* ポリシーを検証（Lint）する。
* AWS 向けは `dist/edge/*.js`、Cloudflare 向けは `dist/edge/cloudflare/index.ts` に **Edge Runtime** コードを生成する。

ポリシーから生成コードへのマッピングは `scripts/compile.js`、`scripts/compile-cloudflare.js` と `templates/` 内のテンプレートで実装されています。

---

## マッピングの参照先

| ポリシー側               | CloudFront Functions   | Lambda@Edge        | Cloudflare Workers   |
| ------------------------ | ---------------------- | ------------------- | -------------------- |
| `request.allow_methods`  | `CFG.allowMethods`     | 同様                | `CFG.allowMethods`   |
| `request.limits`         | `CFG.maxQueryLength` 等 | 同様                | 同様                 |
| `request.block.*`        | `CFG.blockPathContains`, `CFG.blockPathRegexes`, `CFG.uaDenyContains` | 同様 | 同様                 |
| `request.normalize.drop_query_keys` | `CFG.dropQueryKeys` | 同様                | `CFG.dropQueryKeys`  |
| `routes[].auth_gate`     | `CFG.authGates` (static_token / Basic) | JWT / 署名付き URL の検証 | `CFG.authGates` (static token / Basic / JWT / 署名付き URL) |
| `response_headers`       | `viewer-response.js`   | Origin response     | レスポンスヘッダー設定 |
| `origin.auth`            | —                      | カスタムヘッダー注入 | upstream fetch にカスタムヘッダー注入 |

関連: [アーキテクチャ](architecture.ja.md)、[判断マトリクス](decision-matrix.ja.md)、[観測とメトリクス](observability.ja.md)。
