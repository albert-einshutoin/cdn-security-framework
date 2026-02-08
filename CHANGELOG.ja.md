# 変更履歴

このプロジェクトの主な変更をこのファイルに記録します。

形式は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/) に基づき、
バージョン付け後は [Semantic Versioning](https://semver.org/lang/ja/) に従います。

---

## [Unreleased]

### 追加

- Edge と WAF の切り分けのための脅威モデル（`docs/threat-model.md`）と判断マトリクス（`docs/decision-matrix.md`）。
- ポリシープロファイル `policy/profiles/balanced.yml`。クイックスタートでは `cp policy/profiles/balanced.yml policy/base.yml` を使用。
- デプロイ例: `examples/aws-cloudfront/`, `examples/cloudflare/` と README（英語 + 日本語）。
- CONTRIBUTING.md, CODE_OF_CONDUCT.md、および `.github` の Issue/PR テンプレート。
- OSS 公開準備の監査: `docs/OSS-READINESS-AUDIT.ja.md`（日本語）。
- Lambda@Edge origin-request のランタイム対応を追加（JWT 認証: RS256/HS256、署名付き URL 検証、origin auth 注入）。
- `scripts/compile.js` の主要ロジック（`pathPatternsToMarks`, `getAuthGates`, `getAdminGate`, `validateAuthGates`）に単体テストを追加。
- Cloudflare Workers で JWT（`HS256`/`RS256`）・署名付き URL・origin custom header 認証をポリシー生成で利用可能にした。
- コミット済み golden 生成物（`tests/golden/base/*`）とのドリフト検知（`npm run test:drift`）を追加し、CI に統合。
- `firewall.waf.ja3_fingerprints` から JA3 フィンガープリント WAF ブロックルールを生成する機能を追加。
- `firewall.waf.ja4_fingerprints` と `firewall.waf.fingerprint_action`（`count`/`block`）による JA4 対応と段階導入モードを追加。
- `scripts/fingerprint-candidates.js` を追加（WAF JSONL ログから JA3/JA4 候補を抽出）。
- `scripts/security-baseline-check.js` を追加し、`npm run test:security-baseline` として CI に統合。

### 変更

- README のリポジトリ構成を実態に合わせて更新（`base.yml`, `profiles/`, `docs/quickstart.md`, `examples/`）。
- クイックスタートの手順を既存パスに統一: `policy/base.yml`, `policy/profiles/balanced.yml`、デプロイは `runtimes/` または `examples/` を参照。
- 全ランタイムのコード・コメント（CloudFront Functions, Lambda@Edge, Cloudflare Workers）を英語に統一。
- ポリシー `policy/base.yml` のコメントおよび `.ja` ファイル: `.ja` ファイルにのみ日本語；それ以外のファイルとコードは英語のみ。
- CI の品質ゲートにコンパイラ単体テストを追加（policy lint / build / runtime test に加えて実行）。
- ランタイムテストに Cloudflare ターゲット検証を追加し、CI ゲートを runtime + unit + drift に拡張。

### 修正

- README から存在しないファイル（`base.yaml`, `threat-model.md`, `decision-matrix.md`、空の `examples/`）への参照を削除・修正。
- `package.json` のリポジトリ情報（`repository`, `homepage`, `bugs`）を実際の GitHub リポジトリに修正。

---

## [0.1.0] – 初回（テンプレート）

- CloudFront Functions: Viewer Request / Viewer Response。
- Lambda@Edge: Origin Request（テンプレート；JWT/署名は TODO）。
- Cloudflare Workers: 入口遮断・正規化・ヘッダー付与の fetch ハンドラ。
- ポリシー: `policy/base.yml`（人間が読める形式；コンパイラ導入まではランタイムは手動同期）。
- ドキュメント: README, architecture, quick start（英語 + 日本語）；SECURITY（英語 + 日本語）。

---

[Unreleased]: https://github.com/YOUR_ORG/YOUR_REPO/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/YOUR_ORG/YOUR_REPO/releases/tag/v0.1.0
