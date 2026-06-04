# クイックスタート（日本語）

## 目的

このフレームワークを最短で動かす手順です: インストール → 初期化 → ポリシー編集 → ビルド → デプロイ。

## 1. インストールと初期化

```bash
npm install --save-dev cdn-security-framework
npx cdn-security init
```

プラットフォーム（AWS CloudFront / Cloudflare Workers）と、プロファイル（Strict / Balanced / Permissive）またはアーキタイプ（SPA / REST API / 管理画面 / マイクロサービス）を選ぶと、`policy/security.yml` と `policy/profiles/` または `policy/archetypes/` 配下の参照コピーが作成されます。

非対話: `npx cdn-security init --platform aws --profile balanced --force`
最初の推奨ルート: `npx cdn-security init --platform aws --archetype spa-static-site --force`

Cognito JWT API、署名付き download、Cloudflare GraphQL など用途別の
copyable snippet が必要な場合は [ポリシーレシピ](./recipes.ja.md) を参照してください。

## 2. ポリシー編集とビルド

`policy/security.yml` を必要に応じて編集し（allow_methods、block ルール、routes など）、次を実行します。

```bash
# policy に static_token 認証ゲートがある場合は、参照先の build-time secret を
# 先に設定します。組み込みの base/admin 例は EDGE_ADMIN_TOKEN を使います。
export EDGE_ADMIN_TOKEN=replace-with-a-deploy-secret

npx cdn-security build

# Cloudflare Workers
npx cdn-security build --target cloudflare
```

ポリシーが検証され、**Edge Runtime** コードが `dist/edge/` に生成されます（AWS: `viewer-request.js` / `viewer-response.js` / `origin-request.js`、Cloudflare: `cloudflare/index.ts`）。`CFG` やランタイム設定の手動編集は不要です。

## 3. 管理用トークン

`/admin`、`/docs`、`/swagger` の保護用:

- 環境変数や CDN のシークレット管理（Terraform、Wrangler など）で `EDGE_ADMIN_TOKEN` を設定してください。
- ビルド時に変数が設定されていれば注入されます。local fixture build のみ、`npx cdn-security build --allow-placeholder-token` で明示的な insecure placeholder と警告を出せます。placeholder artifact は絶対にデプロイしないでください。

`viewer-request.js` を手で編集する必要はありません。トークンはポリシー（routes.auth_gate.token_env）と環境変数で制御されます。

## 4. テスト

```bash
export EDGE_ADMIN_TOKEN=ci-build-token-not-for-deploy
export ORIGIN_SECRET=ci-origin-secret-not-for-deploy

npm run test:runtime
npm run test:unit
npm run test:drift
npm run test:security-baseline
```

CI と同じ runtime / unit / drift / security-baseline チェックを実行します。

## 5. デプロイ

生成された **`dist/edge/`** 内のファイルを Terraform / CDK や CDN コンソールでデプロイします。

- AWS: CloudFront Function / Lambda@Edge の設定で `dist/edge/viewer-request.js`（および viewer-response.js が生成されていればそれも）を参照。
- Cloudflare: `dist/edge/cloudflare/index.ts` を Workers としてデプロイ。

## 6. 動作確認

- `/admin` がトークン無しで 401
- トークン付きで通る
- Path traversal / 異常 UA / 過剰クエリが弾かれる
