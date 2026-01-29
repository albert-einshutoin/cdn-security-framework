# 例: AWS CloudFront

この例では **AWS CloudFront** と **CloudFront Functions** で Edge セキュリティランタイムをデプロイする手順を示します。

---

## 前提条件

- CloudFront および CloudFront Functions が利用可能な AWS アカウント
- オリジン（S3 バケットまたはカスタムオリジン）の準備済み

---

## 手順

### 1. ランタイムを使う

フレームワークのランタイムをコピーまたは参照します。

- **Viewer Request**: `../../runtimes/aws-cloudfront-functions/viewer-request.js`
- **Viewer Response**: `../../runtimes/aws-cloudfront-functions/viewer-response.js`

または、フレームワークの `runtimes/aws-cloudfront-functions/` をそのまま Functions のソースとしてデプロイしてください。

### 2. 管理用トークンを設定

`viewer-request.js` 内の次の行を、あなたの秘密トークンに置き換えます（または環境変数から注入するビルドステップを使用）。

```js
token: "REPLACE_ME_WITH_EDGE_ADMIN_TOKEN",
```

### 3. コンソールで CloudFront Functions を作成

1. CloudFront → Functions → Create function。
2. **Viewer Request** 用の関数を作成: `viewer-request.js` の内容を貼り付けて Publish。
3. **Viewer Response** 用の関数を作成: `viewer-response.js` の内容を貼り付けて Publish。

### 4. ディストリビューションに関連付け

1. ディストリビューション → Behaviors → デフォルト（または対象の behavior）を編集。
2. **Viewer request**: Function type = CloudFront Functions、Viewer Request 関数を選択。
3. **Viewer response**: Function type = CloudFront Functions、Viewer Response 関数を選択。
4. 保存し、デプロイ完了を待ちます。

### 5. 動作確認

```bash
# トークンなし: 401
curl -i https://YOUR_DISTRIBUTION_DOMAIN/admin

# トークン付き: 許可
curl -i -H "x-edge-token: YOUR_TOKEN" https://YOUR_DISTRIBUTION_DOMAIN/admin

# トラバーサル / 異常 UA / 過剰クエリ: ブロック
curl -i "https://YOUR_DISTRIBUTION_DOMAIN/foo/../bar"
```

---

## ポリシーとの対応

ランタイムの挙動は `policy/base.yml`（または `policy/profiles/balanced.yml`）と対応しています。ポリシーコンパイラ導入後は、ポリシーから Functions を生成できます。

---

## 関連リンク

- [CloudFront Functions ランタイム](../../runtimes/aws-cloudfront-functions/README.ja.md)
- [クイックスタート](../../docs/quickstart.ja.md)
- [アーキテクチャ](../../docs/architecture.ja.md)
