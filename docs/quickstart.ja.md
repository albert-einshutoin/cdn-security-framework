# クイックスタート（日本語）

## 目的
このテンプレを「最短で動かす」手順です。

## 1. ランタイムの選択
- **AWS CloudFront** → `runtimes/aws-cloudfront-functions`
- **Cloudflare** → `runtimes/cloudflare-workers`
- **高度検証（JWT/署名）** → `runtimes/aws-lambda-edge` 併用

## 2. /admin の簡易ゲート
### CloudFront Functions
`viewer-request.js` の `CFG.adminGate.token` を置換。

### Cloudflare Workers
```bash
wrangler secret put EDGE_ADMIN_TOKEN
```

## 3. 動作確認
- `/admin` がトークン無しで 401
- トークン付きで通る
- traversal / 異常UA / 過剰クエリが弾かれる
