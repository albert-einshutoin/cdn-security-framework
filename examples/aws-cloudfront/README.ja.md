# 例: AWS CloudFront（E2E）

この例では **cdn-security-framework** を devDependency として使い、init → ポリシー編集 → build の流れで生成された **`dist/edge/`** のコードを CloudFront Functions にデプロイします。

---

## 前提条件

- Node.js 18+
- CloudFront および CloudFront Functions が利用可能な AWS アカウント
- オリジン（S3 バケットまたはカスタムオリジン）の準備済み

---

## 手順

### 1. インストールと初期化

このディレクトリ（`examples/aws-cloudfront/`）で:

```bash
npm install
npm run init
```

リポジトリルート（`file:../..`）からフレームワークがインストールされ、`policy/security.yml` と `policy/profiles/balanced.yml` が作成されます。公開済みパッケージを使う場合は、devDependency を `"cdn-security-framework": "^1.0.0"` にし、そのプロジェクトで `npm install` を実行してください。

### 2. ポリシー編集（任意）

`policy/security.yml` を編集し、許可メソッド・ブロックルール・ルートなどを調整します。

### 3. ビルド

```bash
npm run build
```

`npx cdn-security build` が実行され、ポリシーが検証され **`dist/edge/viewer-request.js`**（および他 Edge コードが実装されていればそれら）が生成されます。デプロイするのは **この生成ファイル** であり、フレームワークの `runtimes/` ソースではありません。

### 4. 管理用トークン

環境変数やシークレットで `EDGE_ADMIN_TOKEN` を設定してください。ビルド時に変数が設定されていれば注入されます。生成された JS を手で編集する必要はありません。

### 5. CloudFront Functions の作成と関連付け

1. CloudFront → Functions → Create function。
2. **Viewer Request**: 関数を作成し **`dist/edge/viewer-request.js`** の内容を貼り付けて Publish。
3. （生成されている場合）**Viewer Response**: 同様に `dist/edge/viewer-response.js`。
4. ディストリビューション → Behaviors → 対象の behavior を編集 → **Viewer request**: Function type = CloudFront Functions、Viewer Request 関数を選択。**Viewer response** も同様に設定。保存しデプロイ完了を待ちます。

### 6. 動作確認

```bash
# トークンなし: 401
curl -i https://YOUR_DISTRIBUTION_DOMAIN/admin

# トークン付き: 許可
curl -i -H "x-edge-token: YOUR_TOKEN" https://YOUR_DISTRIBUTION_DOMAIN/admin

# トラバーサル / 異常 UA / 過剰クエリ: ブロック
curl -i "https://YOUR_DISTRIBUTION_DOMAIN/foo/../bar"
```

---

## まとめ

| ステップ | コマンド / 操作 |
|----------|------------------|
| インストール | `npm install`（リポジトリまたは npm の cdn-security-framework を使用） |
| 初期化     | `npm run init` → `policy/security.yml` 作成 |
| ビルド     | `npm run build` → `dist/edge/viewer-request.js` 生成 |
| デプロイ   | `dist/edge/*.js` を CloudFront Functions（コンソール / Terraform / CDK）で使用 |

---

## 関連リンク

- [CloudFront Functions ランタイム](../../runtimes/aws-cloudfront-functions/README.ja.md)
- [クイックスタート](../../docs/quickstart.ja.md)
- [ポリシーとランタイムの同期](../../docs/policy-runtime-sync.ja.md)
