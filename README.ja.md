# CDN セキュリティフレームワーク

## 概要

**CDN Security Framework** は、CloudFront / CloudFront Functions / Lambda@Edge / Cloudflare Workers など、
主要 CDN のエッジ実行環境で共通に使える **セキュリティ設計・実装フレームワーク**です。

目的はシンプルです。

> **「CDN セキュリティを“設計思想ごと”再利用可能にし、
> 世界中の誰でも短時間で安全な初期構成を作れるようにする」**

---

## なぜこのフレームワークが必要か

多くの CDN セキュリティは、以下のような問題を抱えがちです。

* 各プロジェクトで **同じような Edge ルールを毎回手書き**している
* CloudFront / Cloudflare ごとに **設計が分断**されている
* 「WAF と Edge Functions の責務分離」が曖昧
* 人によって **セキュリティの初期品質に差**が出る

本フレームワークは、これらを **"ポリシー駆動" + "ランタイム分離"** で解決します。

---

## 設計思想（重要）

### 1. Edge は「侵入させない最前線」

* Origin やアプリに到達する前に **攻撃面を削る**
* 明らかな異常は **即時ブロック**
* 正規化・不要要素除去で **事故を防ぐ**

### 2. ルールは「宣言的（Policy）」に書く

* CDN 固有コードを直接編集しない
* まず **人が読めるポリシー**を書く
* それを各 CDN ランタイムに変換する

### 3. WAF と競合しない

* **Functions / Workers**

  * 正規化、軽量遮断、ヘッダー付与
* **WAF**

  * レート制限、OWASP、Bot、CAPTCHA

> Edge Functions は「前段フィルタ」、WAF は「本命防御」

---

## 対応 CDN / Edge ランタイム

| プラットフォーム             | 対応内容                      |
| -------------------- | ------------------------- |
| AWS CloudFront       | Behavior / Policy 設計      |
| CloudFront Functions | Viewer Request / Response |
| AWS Lambda@Edge      | Origin Request / Response |
| Cloudflare           | CDN / Security Rules      |
| Cloudflare Workers   | Fetch Handler             |

---

## リポジトリ構成

```
  README.md
  docs/
    architecture.md
    quickstart.md
    threat-model.md
    decision-matrix.md
    policy-runtime-sync.md
    observability.md
  policy/
    base.yml
    README.md
    profiles/
      balanced.yml
      strict.yml
      permissive.yml
  scripts/
    policy-lint.js
    runtime-tests.js
  runtimes/
    aws-cloudfront-functions/
    aws-lambda-edge/
    cloudflare-workers/
  examples/
    aws-cloudfront/
    cloudflare/
```

---

## ポリシーとランタイム（現状）

* **ポリシー**（`policy/base.yml` および `policy/profiles/*.yml`）がセキュリティルールの **正** です。ブロック条件・ヘッダー・ルート保護を変えるときはポリシーを編集します。
* **ランタイム**（CloudFront Functions / Lambda@Edge / Cloudflare Workers）は **いまはポリシーファイルを読みません**。設定は各ランタイムのコード内（例: `viewer-request.js` の `CFG`）にあります。ポリシーを変更したら、**各ランタイムの設定を手動で合わせて**ください。
* **ポリシーコンパイラ**（ポリシー → ランタイムコード生成）は **予定** されていますが未実装です。それまではルール変更時にポリシーとランタイムを手動で同期してください。手順と今後の方針は [ポリシーとランタイムの同期](docs/policy-runtime-sync.ja.md) を参照してください。

---

## クイックスタート（5分）

### 1. ポリシープロファイルを選ぶ

`policy/profiles/` からプロファイル（`balanced` / `strict` / `permissive` など）を選び、`base.yml` にコピーします。選び方は [ポリシープロファイル](policy/README.ja.md) を参照してください。

```bash
cp policy/profiles/balanced.yml policy/base.yml
```

### 2. 管理画面用トークンを設定

```bash
export EDGE_ADMIN_TOKEN=your-secret-token
```

### 3. CDN別ランタイムをデプロイ

* AWS: `examples/aws-cloudfront/` または `runtimes/aws-cloudfront-functions/`
* Cloudflare: `examples/cloudflare/` または `runtimes/cloudflare-workers/`

---

## このフレームでできること

* 不要メソッド遮断
* Path Traversal 早期遮断
* UA / クエリ異常検知
* /admin /docs の簡易 Edge 認証
* セキュリティヘッダー強制
* キャッシュ汚染防止
* WAF と衝突しない設計

---

## できないこと（意図的に）

* 高度な Bot 行動解析（WAF / Bot Management の責務）
* DB 内部の不正
* 業務ロジック破壊

---

## 想定ユースケース

* 新規 Web / API サービスの初期セキュリティ
* 複数 CDN を使うグローバルサービス
* OSS / SaaS の「安全なテンプレ」提供
* 社内セキュリティ基盤の標準化

---

## ライセンス

MIT License

---
