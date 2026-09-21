# CDN セキュリティフレームワーク

> **言語:** [English](./README.md) · 日本語

現行の Release Train、互換性 gate、Implemented / Experimental / Planned の境界は
[version roadmap](./docs/ROADMAP.ja.md) を参照してください。

## 概要

**CDN Security Framework** は、CloudFront / CloudFront Functions / Lambda@Edge / Cloudflare Workers など、
主要 CDN のエッジ実行環境で共通に使える **セキュリティ設計・実装フレームワーク**です。

目的はシンプルです。

> **「CDN セキュリティを“設計思想ごと”再利用可能にし、
> 世界中の誰でも短時間で安全な初期構成を作れるようにする」**

**初回導入:** [候補tarballのQuickstart](docs/quickstart.ja.md)を空consumerで実行してください。公開1.4.0と未公開schema2候補をSHA/digestで区別し、既存入力を上書きしません。

## プロダクト境界とリリース状態

**CDN Security Framework** は **Application-aware Edge Security Compiler** です。
アプリケーションが宣言した意図とレビュー済みの security policy を、provider
別の Edge / WAF artifact に変換します。CDN、WAF、bot-management service、
アプリケーションの認証認可層そのものを再実装するものではありません。

プロダクトの流れは **Generate → Diff → Review → Apply** です。対応済み入力では
deterministic finding を優先し、未対応または比較不能な部分は推測せず報告します。
OpenAPI、source analysis、policy、runtime evidence は別々の Truth であり、どれか
1つが他の証明になるわけではありません。

### Capability status

| Capability | Status | Interface | Limit |
| --- | --- | --- | --- |
| OpenAPI inspect | Implemented | CLI/API | local refs only |
| OpenAPI policy candidate | Implemented | CLI/API | review-only; never auto-applied |
| OpenAPI↔Policy drift | Implemented | CLI/JSON/SARIF/GHA | no source needed |
| NestJS Source Analyzer core | Experimental/Implemented core | Programmatic | no app execution; metadata is not enforcement proof |
| Source-aware contract diff CLI | Planned v1.6 | — | — |
| Runtime Evidence v1 | Planned v1.8 | — | — |
| Policy Composition | Planned v1.9 | — | — |
| LSP/VS Code | Planned v2.1 | — | — |

実行可能な導入手順は [OpenAPI 導入ガイド](docs/openapi-integration.ja.md)、
[NestJS Source Analysis](docs/source-analysis-nestjs.ja.md)、
[CLI リファレンス](docs/cli.ja.md)、[プログラマティック API](docs/programmatic-api.ja.md)
を参照してください。[Version roadmap](docs/ROADMAP.ja.md) が release status の正本です。

生成 artifact が完全に安全であること、Guard や Analyzer の結果が runtime の
enforcement を証明すること、未対応 provider の control が利用できることは主張しません。
candidate と provider capability finding は適用前にレビューしてください。

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
  src/
    bin/cli.ts             # CLI の TypeScript ソース
    scripts/               # compiler / test / tool の TypeScript ソース
    lib/                   # public library API の TypeScript ソース
  bin/                    # 生成 package artifact。編集・commitしない
    cli.js                 # 生成 CLI エントリ (npx cdn-security)
  docs/
    quickstart.md
    policy-runtime-sync.md
  policy/
    security.yml / base.yml
    profiles/
  scripts/                # src/scripts/*.ts から生成。編集・commitしない
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
    infra/                 # 生成 WAF IaC: Terraform JSON と任意の CloudFormation
  runtimes/                # レガシー・参照用。デプロイは dist/edge/ から
  examples/
```

package code の正となるソースは `src/**/*.ts` です。root 配下の JavaScript と `.d.ts` は CI と npm package 作成時に `npm run build:ts` が生成する artifact で、編集・commit 対象のソースではありません。`templates/` 配下の runtime template は手書きで、deploy 可能な `dist/edge/` 出力を生成するために使われます。

Terraform / CloudFormation / CDK / WAF の利用例は [IaC 連携](docs/iac.ja.md) を参照。

### 運用ドキュメント
- [クイックスタート](docs/quickstart.ja.md) — install、policy build、contract review、デプロイ境界
- [OpenAPI導入ガイド](docs/openapi-integration.ja.md) — API contractのinspect、review専用Policy Candidate生成、安全上の制約
- [NestJS Source Analysis](docs/source-analysis-nestjs.ja.md) — appを実行しないexperimentalなprogrammatic source metadata
- [CLI リファレンス](docs/cli.ja.md) — `init` / `build` / `emit-waf` / `doctor` / `readiness` / `capabilities` / `explain` / `diff` / `migrate`
- [プログラマティック API](docs/programmatic-api.ja.md) — `require('cdn-security-framework')` で CI / IaC から直接呼び出し
- [Package/API manifest](docs/api-manifest.json) — entrypoint、schema、bin、package file contract の機械可読 inventory
- [Compiler strictness](docs/compiler-strictness.ja.md) — phase contract、strict check、残る dynamic area
- [アーキタイプ](docs/archetypes.ja.md) — アプリ形状別プリセット（SPA / REST API / 管理画面 / マイクロサービス）
- [ポリシーレシピ](docs/recipes.ja.md) — Cognito API、SPA、管理画面、署名付き download、Cloudflare GraphQL の copyable snippet
- [レスポンス DLP](docs/response-dlp.ja.md) — Cloudflare Workers で高信頼の漏えい値を mask/block する設定
- [シークレットローテーション runbook](docs/runbooks/secret-rotation.ja.md) — JWT / JWKS / 署名付き URL / 管理トークン / origin シークレット
- [スキーママイグレーション](docs/schema-migration.ja.md) — `policy/schema.json` のバージョン契約と `migrate` CLI
- [サプライチェーン](docs/supply-chain.ja.md) — SLSA v1 provenance と `npm audit signatures`
- [テンプレート注入契約](docs/template-injection-contract.ja.md) — marker-safe かつ parse-checked な runtime config 注入
- [テスト戦略](docs/test-strategy.ja.md) — Vitest 移行方針と release gate の test workflow
- [選択的CIテスト](docs/selective-testing.ja.md) — 変更影響分析、安全なfallback、shadow比較の運用
- [ADR 0001: Plugin-safe emitter path](docs/adr/0001-plugin-safe-emitter-path.ja.md) — bundler-backed prototype と移行条件

- [Origin認証](docs/origin-auth.ja.md)
- [署名URL（Cloudflare）](docs/signed-urls.ja.md)
- [脅威モデル](docs/threat-model.ja.md)
- [判断表](docs/decision-matrix.ja.md)
- [観測](docs/observability.ja.md)
- [Changelog](CHANGELOG.md)

---

## ポリシーとランタイム

* **ポリシー**（`policy/security.yml` または `policy/base.yml`）が **唯一の正** です。ブロック条件・ヘッダー・ルート保護を変えるときはポリシーを編集します。
* **ビルド**で CLI コンパイラを実行: `./node_modules/.bin/cdn-security build` がポリシーを読み検証し、**Edge Runtime** コードを `dist/edge/*.js` に生成します。`CFG` やランタイム設定の手動同期は不要です。
* 詳細と IaC 連携は [ポリシーとランタイムの同期](docs/policy-runtime-sync.ja.md) を参照してください。

---

## クイックスタート

[完全な手順・fixture・期待結果](docs/quickstart.ja.md)に従い、提供された候補tarballのSHA/digestを照合します。公開後の2.0.0導入と未公開候補の導入を混同しません。

```bash
# Set this to the verified tarball supplied with the candidate SHA and SHA-256.
export CANDIDATE_TARBALL=/path/to/verified-candidate.tgz
shasum -a 256 "$CANDIDATE_TARBALL"
mkdir consumer
cd consumer
npm init -y
npm install --save-dev "$CANDIDATE_TARBALL"
./node_modules/.bin/cdn-security --help
```

### Init・lint・build

```bash
./node_modules/.bin/cdn-security init --platform aws --profile balanced
export EDGE_ADMIN_TOKEN=docs-fixture-token-not-for-deploy
node node_modules/cdn-security-framework/scripts/policy-lint.js policy/security.yml
./node_modules/.bin/cdn-security build --policy policy/security.yml --target aws --out-dir dist/aws
```

`init --guided`のCloudflare JWT例、認証env付きPOST JSON playground、OpenAPI inspect→review-only candidate→contract diff、migration preview/save/backup/rollbackもQuickstartに記載しています。JWT/signed_urlをAWSの成功例として扱いません。

### 5. デプロイ境界

この例の`--out-dir dist/aws`では`dist/aws/edge/`がruntime、`dist/aws/infra/`がIaC断片です。このoptionを省略した既定の出力先は`dist/edge/`と`dist/infra/`です。[IaC手順](docs/iac.ja.md)を確認し、operatorのTerraform/CDK/CDN workflowへreview後に引き渡します。build自体はdeployしません。synthetic token/placeholder artifactを本番利用せず、適用前に本番用secretで別途build・reviewしてください。

## Product Core と生成 Security Control

### Product core

* レビュー可能な policy と schema validation
* OpenAPI inspect、review 専用 policy candidate、OpenAPI↔Policy drift finding
* CI / IaC から利用する programmatic API
* deterministic な provider capability 診断と生成 artifact の diff

### 生成 security control（maintenance surface）

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
* **dist/**: `.gitignore` で無視。consumerは `./node_modules/.bin/cdn-security build` で `dist/edge/` と `dist/infra/` を生成する。CI でドリフト検知する場合は CI 内で `npm run build` を実行しポリシーと比較する（`dist/` はコミットしない）。
* **CI ワークフロー**:
  * `.github/workflows/policy-lint.yml`: PRの選択的検証と必須shadow比較、`main`・`release/**`・手動・日次の完全検証
  * `.github/workflows/release-npm.yml`: タグ起点の npm 公開ワークフロー
  * [Release compatibility matrix](docs/release-matrix.ja.md): Node 20.17.0 / 22 / 24 の証拠と cross-version digest 比較
  * [Deterministic output audit](docs/determinism-audit.ja.md): contract/report/golden の反復検証と privacy 境界
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
