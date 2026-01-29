# ポリシーとランタイムの同期

このドキュメントでは、**ポリシー**（`policy/base.yml` および `policy/profiles/*.yml`）と **ランタイム**（CloudFront Functions / Lambda@Edge / Cloudflare Workers）を、現状どう同期するかと、今後の方針を説明します。

---

## 現状

* **ポリシー** が人間が読める正です。YAML を編集して以下を変更します：
  * 許可メソッド、クエリ/URI 制限
  * ブロックルール（パスパターン、UA 拒否リスト、必須ヘッダー欠落）
  * 正規化（例: `drop_query_keys`）
  * ルート（例: `/admin`, `/docs`）と認証ゲート
  * レスポンスヘッダー（HSTS、CSP など）

* **ランタイム** は **ポリシーファイルを読みません**。各ランタイムはコード内の設定（例: `viewer-request.js` の `CFG`、Workers の `env`）を持ちます。ポリシーを変更したら、**各ランタイムを手動で更新**し、挙動がポリシーと一致するようにしてください。

---

## ポリシーを変更したときの手順

1. `policy/base.yml`（または使用しているプロファイル）を編集する。
2. ポリシー Lint を実行する（任意だが推奨）：
   ```bash
   node scripts/policy-lint.js policy/base.yml
   ```
3. 使用している各ランタイムを更新する：
   * **CloudFront Functions**: `runtimes/aws-cloudfront-functions/viewer-request.js` と `viewer-response.js` — `CFG` とヘッダー処理をポリシーに合わせる。
   * **Lambda@Edge**: `runtimes/aws-lambda-edge/origin-request.js`（および必要なら response）— 同様。
   * **Cloudflare Workers**: `runtimes/cloudflare-workers/src/index.ts` — 設定とヘッダー処理をポリシーに合わせる。
4. ランタイムのテストがあれば実行する（例: ランタイムまたは `scripts/` で `npm test`）。
5. 更新したランタイムを CDN にデプロイする。

---

## 今後の方針：ポリシーコンパイラ

**ポリシーコンパイラ** の導入を予定しています。想定している動きは次のとおりです。

* `policy/base.yml`（および任意でプロファイルの上書き）を読み込む。
* 各ターゲット（CloudFront Functions / Lambda@Edge / Cloudflare Workers）向けのランタイムコードを **生成** または **検証** する。

コンパイラができるまでは、ポリシーとランタイムを **手動で整合** させ、ランタイムの README とこのドキュメントでマッピングを明示します。

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
