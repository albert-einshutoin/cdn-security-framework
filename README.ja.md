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
  bin/
    cli.js                 # CLI エントリ (npx cdn-security)
  docs/
    quickstart.md
    policy-runtime-sync.md
    VISION.md
  policy/
    security.yml / base.yml
    profiles/
  scripts/
    compile.js
    policy-lint.js
    runtime-tests.js
  templates/               # 内部用: build が dist/edge/ を生成する際に参照
    aws/
  dist/
    edge/                  # 生成物: ここをデプロイ (viewer-request.js 等)
  runtimes/                # レガシー・参照用。デプロイは dist/edge/ から
  examples/
```

---

## ポリシーとランタイム

* **ポリシー**（`policy/security.yml` または `policy/base.yml`）が **唯一の正** です。ブロック条件・ヘッダー・ルート保護を変えるときはポリシーを編集します。
* **ビルド**で CLI コンパイラを実行: `npx cdn-security build` がポリシーを読み検証し、**Edge Runtime** コードを `dist/edge/*.js` に生成します。`CFG` やランタイム設定の手動同期は不要です。
* 詳細と IaC 連携は [ポリシーとランタイムの同期](docs/policy-runtime-sync.ja.md) を参照してください。

---

## クイックスタート（5分）

### 1. インストール

```bash
npm install --save-dev cdn-security-framework
```

### 2. 初期化（ポリシーの雛形生成）

```bash
npx cdn-security init
```

対話でプラットフォーム（AWS / Cloudflare）とプロファイル（Strict / Balanced / Permissive）を選ぶと、`policy/security.yml` と `policy/profiles/<profile>.yml` が作成されます。

非対話: `npx cdn-security init --platform aws --profile balanced --force`

### 3. 編集とビルド

`policy/security.yml` を編集し、次を実行します。

```bash
npx cdn-security build
```

ポリシーが検証され、`dist/edge/viewer-request.js` などが生成されます。

### 4. デプロイ

生成された `dist/edge/` を Terraform / CDK や CDN コンソールでデプロイしてください。管理ルート用に `EDGE_ADMIN_TOKEN` を環境変数やシークレットで設定します。

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

## メンテナ向け（npm 公開）

* **package-lock.json**: コミットしておく（CI で `npm ci` するため）。
* **dist/**: CI で「dist ドリフト」を検知する場合は、`npm run build` を実行し `dist/edge/`（および将来の `dist/infra/`）をコミットしてリポジトリと一致させる。
* **公開**: リポジトリルートで `npm publish`（npm 認証が必要）。`package.json` のバージョン更新と `CHANGELOG.md` の記載を済ませた状態で公開すること。スコープ付きパッケージ（例: `@your-org/cdn-security-framework`）は初回公開時に `--access public` が必要。

---

## ライセンス

MIT License

---
