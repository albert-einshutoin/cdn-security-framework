# AWS CloudFront Functions Runtime

このディレクトリは **レガシー・参照用** です。**デプロイ用コード** は CLI が **`dist/edge/`** に生成します。

## 生成コードからデプロイする

1. **`policy/security.yml`**（または `policy/base.yml`）を編集する。
2. **`npx cdn-security build`** を実行する。
3. **`dist/edge/`** 内のファイル（例: `dist/edge/viewer-request.js`）を CloudFront Functions にデプロイする（Terraform の `file()`、CDK、コンソール）。

このディレクトリの `viewer-request.js` は手で編集しないでください。デプロイ対象は生成された `dist/edge/viewer-request.js` です。CLI がポリシーを読み、テンプレートに設定（許可メソッド、ブロックルール、admin gate など）を注入します。

## 何を守る？

- 入口で「攻撃面を削る」（不要メソッド / traversal / 異常 UA / 過剰クエリ）
- クエリ正規化（utm 等を落としてキャッシュキー汚染を防ぐ）
- セキュリティヘッダーを CDN で強制（複数オリジンでも統一）

## どこにアタッチする？

- `dist/edge/viewer-request.js` → **Viewer Request**
- `dist/edge/viewer-response.js` → **Viewer Response**（生成される場合）

## 管理用トークン

環境変数やシークレットで `EDGE_ADMIN_TOKEN` を設定してください。ビルド時に変数が設定されていれば注入されます。コード内の `CFG.adminGate.token` を手で置換する必要はありません。

## 動作確認（例）

```bash
curl -i https://YOUR_DOMAIN/admin
curl -i -H "x-edge-token: YOUR_TOKEN" https://YOUR_DOMAIN/admin
curl -i "https://YOUR_DOMAIN/?utm_source=x&foo=1"
```

## 他にできること

- `/api/*` 用に別 Behavior を作り、ポリシーの `allow_methods` を拡張する（PUT / DELETE 等）。
- 露骨な攻撃だけ Functions で落とし、レート制限や OWASP は AWS WAF へ。
