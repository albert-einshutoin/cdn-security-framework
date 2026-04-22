# AWS CloudFront Functions Runtime

このディレクトリは **レガシー・参照用** です。**デプロイ用コード** は CLI が **`dist/edge/`** に生成します。

## 生成コードからデプロイする

1. **`policy/security.yml`**（または `policy/base.yml`）を編集する。
2. **`npx cdn-security build`** を実行する。
3. **`dist/edge/`** 内のファイル（`dist/edge/viewer-request.js` と `dist/edge/viewer-response.js`）を CloudFront Functions にデプロイする（Terraform の `file()`、CDK、コンソール）。

このディレクトリの `viewer-request.js` は手で編集しないでください。デプロイ対象は生成された `dist/edge/viewer-request.js` です。CLI がポリシーを読み、テンプレートに設定（許可メソッド、ブロックルール、admin gate など）を注入します。

## 何を守る？

- 入口で「攻撃面を削る」（不要メソッド / traversal / 異常 UA / 過剰クエリ）
- クエリ正規化（utm 等を落としてキャッシュキー汚染を防ぐ）
- セキュリティヘッダーを CDN で強制（複数オリジンでも統一）

## どこにアタッチする？

- `dist/edge/viewer-request.js` → **Viewer Request**
- `dist/edge/viewer-response.js` → **Viewer Response**（ポリシーの `response_headers` と `routes` から生成）

## 管理用トークン

`npm run build` を実行する前に、環境変数やシークレットで `EDGE_ADMIN_TOKEN` を設定してください。CloudFront Functions は実行時に環境変数を読めないため、トークンはビルド時に `dist/edge/viewer-request.js` の `CFG.authGates[].token` へ埋め込まれます。`static_token` を利用する場合、生成物自体がシークレットに準ずるため取り扱いに注意してください。

トークンを持たない開発用ビルドでは `--allow-placeholder-token` を渡してください。プレースホルダー (`INSECURE_PLACEHOLDER__REBUILD_WITH_REAL_TOKEN`) が埋め込まれ、ビルド時に明示的な警告が出力されます。

## 動作確認（例）

```bash
curl -i https://YOUR_DOMAIN/admin
curl -i -H "x-edge-token: YOUR_TOKEN" https://YOUR_DOMAIN/admin
curl -i "https://YOUR_DOMAIN/?utm_source=x&foo=1"
```

## 他にできること

- `/api/*` 用に別 Behavior を作り、ポリシーの `allow_methods` を拡張する（PUT / DELETE 等）。
- 露骨な攻撃だけ Functions で落とし、レート制限や OWASP は AWS WAF へ。
