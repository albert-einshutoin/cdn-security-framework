# 例: Cloudflare Workers

この例では **Cloudflare Workers** で Edge セキュリティランタイムをデプロイする手順を示します。

---

## 前提条件

- Cloudflare アカウント
- Wrangler CLI（`npm i -g wrangler`）と `wrangler login` 済み

---

## 手順

### 1. ランタイムを使う

リポジトリルートから:

```bash
cd runtimes/cloudflare-workers
```

または `runtimes/cloudflare-workers/` の内容をあなたの Worker プロジェクトにコピーしてください。

### 2. インストールとビルド（必要な場合）

```bash
npm install
npm run build   # ビルドステップがある場合
```

### 3. 管理用トークンのシークレットを設定

```bash
wrangler secret put EDGE_ADMIN_TOKEN
```

プロンプトで秘密トークンを入力します。

### 4. デプロイ

```bash
wrangler deploy
```

Worker は Cloudflare ダッシュボードまたは `wrangler.toml` の routes でルート（例: `*\.yourdomain.com/*`）に紐付けてください。

### 5. 動作確認

```bash
# トークンなし: 401
curl -i https://YOUR_WORKER_DOMAIN/admin

# トークン付き: 許可
curl -i -H "x-edge-token: YOUR_TOKEN" https://YOUR_WORKER_DOMAIN/admin

# トラバーサル / 異常 UA / 過剰クエリ: ブロック
curl -i "https://YOUR_WORKER_DOMAIN/foo/../bar"
```

---

## ポリシーとの対応

ランタイムの挙動は `policy/base.yml`（または `policy/profiles/balanced.yml`）と対応しています。ポリシーコンパイラ導入後は、ポリシーから Worker コードを生成できます。

---

## 関連リンク

- [Cloudflare Workers ランタイム](../../runtimes/cloudflare-workers/README.ja.md)
- [クイックスタート](../../docs/quickstart.ja.md)
- [アーキテクチャ](../../docs/architecture.ja.md)
