# E2E 例

これらの例では **cdn-security-framework** を devDependency として使い、init → ポリシー編集 → build → 生成された **`dist/edge/`** のデプロイを行います。

| 例 | プラットフォーム | 流れ |
|----|------------------|------|
| [aws-cloudfront/](aws-cloudfront/) | AWS CloudFront Functions | `npm install` → `npm run init` → `npm run build` → `dist/edge/viewer-request.js` をデプロイ |
| [cloudflare/](cloudflare/) | Cloudflare Workers | cloudflare の README 参照（Workers コード生成は予定） |

AWS の例は `examples/aws-cloudfront/` で実行してください。リポジトリルート（`file:../..`）からフレームワークがインストールされます。公開済みパッケージを使う場合は、プロジェクトの `package.json` に `"cdn-security-framework": "^1.0.0"` を入れ、そのプロジェクトで `npm install` してください。
