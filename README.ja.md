# CDN セキュリティフレームワーク

> **言語:** [English](./README.md) · 日本語

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
  policy/
    security.yml / base.yml
    profiles/
  scripts/
    compile.js
    compile-cloudflare.js
    compile-infra.js
    policy-lint.js
    runtime-tests.js
    cloudflare-runtime-tests.js
    compile-unit-tests.js
    infra-unit-tests.js
    check-drift.js
  templates/               # 内部用: build が dist/edge/ を生成する際に参照
    aws/
  dist/
    edge/                  # 生成物: ここをデプロイ (viewer-request.js, viewer-response.js, origin-request.js)
    infra/                 # ポリシーに firewall がある場合に生成: waf-rules.tf.json (Terraform)
  runtimes/                # レガシー・参照用。デプロイは dist/edge/ から
  examples/
```

Terraform / CDK / WAF の利用例は [IaC 連携](docs/iac.ja.md) を参照。

### 運用ドキュメント
- [CLI リファレンス](docs/cli.ja.md) — `init` / `build` / `emit-waf` / `doctor` / `migrate`
- [プログラマティック API](docs/programmatic-api.ja.md) — `require('cdn-security-framework')` で CI / IaC から直接呼び出し
- [アーキタイプ](docs/archetypes.ja.md) — アプリ形状別プリセット（SPA / REST API / 管理画面 / マイクロサービス）
- [シークレットローテーション runbook](docs/runbooks/secret-rotation.ja.md) — JWT / JWKS / 署名付き URL / 管理トークン / origin シークレット
- [スキーママイグレーション](docs/schema-migration.ja.md) — `policy/schema.json` のバージョン契約と `migrate` CLI
- [サプライチェーン](docs/supply-chain.ja.md) — SLSA v1 provenance と `npm audit signatures`

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

### 4. テスト

```bash
npm run test:runtime
npm run test:unit
npm run test:drift
npm run test:security-baseline
```

CI と同じ runtime / unit / drift / security-baseline チェックを実行します。

### 4.5 環境診断（初回デプロイ前の任意実行、推奨）

```bash
npx cdn-security doctor
```

Node バージョン、ポリシーのパース/スキーマバージョン、認証ゲートが参照する全環境変数（`EDGE_ADMIN_TOKEN`・`JWT_SECRET`・`ORIGIN_SECRET` など）、`dist/edge/` の書き込み可否、`npm ls` の健全性を一括で pass/fail 判定します。CI でアーティファクト化できる `doctor-report.json` も書き出します。詳細は [CLI リファレンス](docs/cli.ja.md)。

### 5. デプロイ

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
* **dist/**: `.gitignore` で無視。ユーザーは `npm run build` で `dist/edge/` と `dist/infra/` を生成する。CI でドリフト検知する場合は CI 内で `npm run build` を実行しポリシーと比較する（`dist/` はコミットしない）。
* **CI ワークフロー**:
  * `.github/workflows/policy-lint.yml`: push/PR の品質ゲート（lint/build/runtime/unit/drift/security-baseline + `npm pack --dry-run`）
  * `.github/workflows/release-npm.yml`: タグ起点の npm 公開ワークフロー
* **タグで公開する手順**:
  1. `package.json` の version を更新（例: `1.0.1`）
  2. `main` へコミット/プッシュ
  3. `v1.0.1` タグを作成して push
  4. GitHub Actions が公開前チェックを実行し、全て成功時のみ npm へ公開
* **npm 認証**:
  * 推奨: npm Trusted Publishing（OIDC, `npm publish --provenance`）
  * フォールバック: リポジトリシークレット `NPM_TOKEN` を設定してトークン公開

---

## ライセンス

MIT License

---
