# Cloudflare Workers Runtime

このディレクトリは Cloudflare Workers 用のランタイムです。

## 何を守る？
- CloudFront Functions と同様の「入口遮断・正規化・ヘッダー付与」
- さらに Workers は KV / Durable Objects と組み合わせれば “状態” を持てる（レート制限等に拡張可）

## セットアップ
```bash
cd runtimes/cloudflare-workers
npm i -g wrangler
wrangler login
```

## シークレット設定（管理画面ゲート）
```bash
wrangler secret put EDGE_ADMIN_TOKEN
```

## デプロイ
```bash
wrangler deploy
```

## 動作確認
```bash
curl -i https://YOUR_WORKER_DOMAIN/admin
curl -i -H "x-edge-token: YOUR_TOKEN" https://YOUR_WORKER_DOMAIN/admin
```

## 何が他にできる？

KV / Durable Objects で IP 単位レート制限（Functionsでは難しい）

Bot判定の高度化（ただしWAF機能と競合させない設計が重要）