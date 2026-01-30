# 例: Cloudflare Workers（E2E）

この例では **cdn-security-framework** を devDependency として使い、init → ポリシー編集 → `--target cloudflare` でビルド → 生成された **`dist/edge/cloudflare/index.ts`** を Cloudflare Workers にデプロイします。

---

## 前提条件

- Node.js 18+
- Cloudflare アカウント
- Wrangler CLI（`npm i -g wrangler` または `npx wrangler`）と `wrangler login`

---

## 手順

### 1. インストールと初期化

このディレクトリ（`examples/cloudflare/`）で:

```bash
npm install
npm run init
```

リポジトリルート（`file:../..`）からフレームワークがインストールされ、`policy/security.yml` と `policy/profiles/balanced.yml` が作成されます。公開済みパッケージを使う場合は、プロジェクトの `package.json` に `"cdn-security-framework": "^1.0.0"` を指定してください。

### 2. ポリシー編集（任意）

`policy/security.yml` を編集し、許可メソッド・ブロックルール・ルート・レスポンスヘッダーなどを調整します。

### 3. ビルド

```bash
npm run build
```

`npx cdn-security build --target cloudflare` が実行され、ポリシーが検証され **`dist/edge/cloudflare/index.ts`** が生成されます。この生成ファイルをデプロイするか、Worker プロジェクトにコピーしてください。Wrangler はデプロイ時に TypeScript をコンパイルします。

### 4. 管理用トークンのシークレット設定

```bash
wrangler secret put EDGE_ADMIN_TOKEN
```

プロンプトで秘密トークンを入力します。Worker は `env.EDGE_ADMIN_TOKEN` から読みます。

### 5. デプロイ

生成された Worker を Wrangler プロジェクトにコピーまたはリンクしてデプロイします。

- **方法 A**: 生成ファイルを使う Worker プロジェクトを作成する。例: `src/index.ts` で `dist/edge/cloudflare/index.ts` を re-export するか、Worker の `src/` にコピーし、次を実行:

  ```bash
  wrangler deploy
  ```

- **方法 B**: フレームワークのリポジトリルートから、生成ファイルを指すように `wrangler.toml` の `main` を設定し、`wrangler deploy` を実行する。

Worker がルート（例: `*\.yourdomain.com/*`）にアタッチされていることを、Cloudflare ダッシュボードまたは `wrangler.toml` の routes で確認してください。

### 6. 動作確認

```bash
# トークンなし: 401
curl -i https://YOUR_WORKER_DOMAIN/admin

# トークン付き: 許可
curl -i -H "x-edge-token: YOUR_TOKEN" https://YOUR_WORKER_DOMAIN/admin

# トラバーサル / 異常 UA / 過剰クエリ: ブロック
curl -i "https://YOUR_WORKER_DOMAIN/foo/../bar"
```

---

## まとめ

| ステップ | コマンド / 操作 |
|----------|------------------|
| インストール | `npm install`（リポジトリまたは npm の cdn-security-framework を使用） |
| 初期化     | `npm run init` → `policy/security.yml` 作成 |
| ビルド     | `npm run build` → `dist/edge/cloudflare/index.ts` 生成 |
| デプロイ   | `dist/edge/cloudflare/index.ts` を Worker プロジェクトで使い `wrangler deploy` |

---

## 関連リンク

- [Cloudflare Workers ランタイム](../../runtimes/cloudflare-workers/README.ja.md)
- [クイックスタート](../../docs/quickstart.ja.md)
- [ポリシーとランタイムの同期](../../docs/policy-runtime-sync.ja.md)
