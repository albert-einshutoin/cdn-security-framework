# E2E 例

これらの例では **cdn-security-framework** を devDependency として使い、init → ポリシー編集 → build → 生成された **`dist/edge/`** のデプロイを行います。

| 例 | プラットフォーム | 流れ |
|----|------------------|------|
| [aws-cloudfront/](aws-cloudfront/) | AWS CloudFront Functions | `npm install` → `npm run init` → `npm run build` → `dist/edge/viewer-request.js` と `viewer-response.js` をデプロイ |
| [cloudflare/](cloudflare/) | Cloudflare Workers | `npm install` → `npm run init` → `npm run build` → `dist/edge/cloudflare/index.ts` をデプロイ |

AWS の例は `examples/aws-cloudfront/` で実行してください。リポジトリルート（`file:../..`）からフレームワークがインストールされます。公開済みパッケージを使う場合は、プロジェクトの `package.json` に `"cdn-security-framework": "^1.0.0"` を入れ、そのプロジェクトで `npm install` してください。
