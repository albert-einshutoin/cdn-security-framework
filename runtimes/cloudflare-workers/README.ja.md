# Cloudflare Workers Runtime

このディレクトリは **レガシー・参照用** です。**デプロイ用コード** は CLI が **`dist/edge/cloudflare/`** に生成します。

## 生成コードからデプロイする

1. **`policy/security.yml`**（または `policy/base.yml`）を編集する。
2. **`npx cdn-security build --target cloudflare`** を実行する。
3. 生成された **`dist/edge/cloudflare/index.ts`** を Cloudflare Workers にデプロイする（例: Worker プロジェクトにコピーして `wrangler deploy`）。

ポリシー駆動の設定用に、このディレクトリの `src/index.ts` を手で編集しないでください。CLI がポリシーを読み、テンプレートに設定（許可メソッド・ブロックルール・admin gate・レスポンスヘッダー）を注入します。

## 何を守る？

- CloudFront Functions と同様の「入口遮断・正規化・ヘッダー付与」。
- Workers は KV / Durable Objects と組み合わせて状態を持てる（レート制限などに拡張可能）。

## セットアップ（生成 Worker 用）

```bash
# プロジェクト（または examples/cloudflare/）で:
npm install --save-dev cdn-security-framework
npx cdn-security init --platform cloudflare --profile balanced --force
npx cdn-security build --target cloudflare
```

その後、Worker で `dist/edge/cloudflare/index.ts` を使い:

```bash
wrangler secret put EDGE_ADMIN_TOKEN
wrangler deploy
```

## 動作確認

```bash
curl -i https://YOUR_WORKER_DOMAIN/admin
curl -i -H "x-edge-token: YOUR_TOKEN" https://YOUR_WORKER_DOMAIN/admin
```

## 何が他にできる？

- KV / Durable Objects で IP 単位レート制限（Functions では難しい）。
- Bot 判定の高度化（WAF 機能と競合させない設計が重要）。
