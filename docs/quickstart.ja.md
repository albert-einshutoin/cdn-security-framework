# クイックスタート（日本語）

## 目的

このフレームワークを最短で動かす手順です: インストール → 初期化 → ポリシー編集 → ビルド → デプロイ。

## 1. インストールと初期化

```bash
npm install --save-dev cdn-security-framework
npx cdn-security init
```

プラットフォーム（AWS CloudFront / Cloudflare Workers）とプロファイル（Strict / Balanced / Permissive）を選ぶと、`policy/security.yml` と `policy/profiles/<profile>.yml` が作成されます。

非対話: `npx cdn-security init --platform aws --profile balanced --force`

## 2. ポリシー編集とビルド

`policy/security.yml` を必要に応じて編集し（allow_methods、block ルール、routes など）、次を実行します。

```bash
npx cdn-security build
```

ポリシーが検証され、**Edge Runtime** コードが `dist/edge/` に生成されます（例: AWS CloudFront Functions 用 `dist/edge/viewer-request.js`）。`CFG` やランタイム設定の手動編集は不要です。

## 3. 管理用トークン

`/admin`、`/docs`、`/swagger` の保護用:

- 環境変数や CDN のシークレット管理（Terraform、Wrangler など）で `EDGE_ADMIN_TOKEN` を設定してください。
- ビルド時に変数が設定されていれば注入され、未設定の場合はプレースホルダーが入り、デプロイパイプラインで差し替え可能です。

`viewer-request.js` を手で編集する必要はありません。トークンはポリシー（routes.auth_gate.token_env）と環境変数で制御されます。

## 4. デプロイ

生成された **`dist/edge/`** 内のファイルを Terraform / CDK や CDN コンソールでデプロイします。

- AWS: CloudFront Function / Lambda@Edge の設定で `dist/edge/viewer-request.js`（および viewer-response.js が生成されていればそれも）を参照。
- Cloudflare: Cloudflare ターゲット実装後は `dist/edge/` の Workers コードを使用。

## 5. 動作確認

- `/admin` がトークン無しで 401
- トークン付きで通る
- Path traversal / 異常 UA / 過剰クエリが弾かれる
