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

* **CloudFront Functions (viewer-request)** は CLI コンパイラで **自動生成** されます。ポリシーを編集したあと `npx cdn-security build` を実行すると、ポリシーが検証され、**Edge Runtime** コードが `dist/edge/*.js`（例: `dist/edge/viewer-request.js`）に出力されます。このターゲットでは `CFG` やランタイム設定の手動同期は不要です。

* **Lambda@Edge** と **Cloudflare Workers** はまだコンパイラで生成されません。それらのランタイムは、コード生成が実装されるまでポリシーに合わせて手動で更新してください。

---

## ポリシーを変更したときの手順

1. `policy/security.yml`（または `policy/base.yml`）を編集する。
2. ビルド（ポリシー検証と Edge コード生成）を実行する：
   ```bash
   npx cdn-security build
   ```
3. 生成された **`dist/edge/`** 内のファイルを CDN にデプロイする（例: Terraform の `file("dist/edge/viewer-request.js")`、CDK、コンソール）。
4. Lambda@Edge / Cloudflare Workers（未生成の場合）: 該当ランタイムをポリシーに合わせて手動で更新し、デプロイする。

---

## ポリシーコンパイラ（実装済み）

**ポリシーコンパイラ**（CLI: `npx cdn-security build`）は次のことを行います。

* `policy/security.yml` または `policy/base.yml`（および `--policy` でパス指定可能）を読み込む。
* ポリシーを検証（Lint）する。
* 選択したターゲット（例: AWS CloudFront Functions）向けの **Edge Runtime** コードを `dist/edge/*.js` に生成する。

ポリシーから生成コードへのマッピングは `scripts/compile.js` と `templates/` 内のテンプレートで実装されています。

---

## マッピングの参照先

| ポリシー側               | CloudFront Functions   | Lambda@Edge        | Cloudflare Workers   |
| ------------------------ | ---------------------- | ------------------- | -------------------- |
| `request.allow_methods`  | `CFG.allowMethods`     | 同様                | `CFG.allowMethods`   |
| `request.limits`         | `CFG.maxQueryLength` 等 | 同様                | 同様                 |
| `request.block.*`        | `CFG.blockPathMarks`, `CFG.uaDenyContains` | 同様 | 同様                 |
| `request.normalize.drop_query_keys` | `CFG.dropQueryKeys` | 同様                | `CFG.dropQueryKeys`  |
| `routes[].auth_gate`     | `CFG.adminGate`        | 同様                | `env.EDGE_ADMIN_TOKEN` + プレフィックス |
| `response_headers`       | `viewer-response.js`   | Origin response     | レスポンスヘッダー設定 |

関連: [アーキテクチャ](architecture.ja.md)、[判断マトリクス](decision-matrix.ja.md)、[観測とメトリクス](observability.ja.md)。
