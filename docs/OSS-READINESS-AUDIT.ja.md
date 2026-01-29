# OSS・公開リポジトリ向け 不足点・ドキュメント徹底調査

本ドキュメントは、本フレームワークを OSS / 公開リポジトリとして提供するにあたり、
**不足している点** と **ドキュメントの有無** を整理した監査結果です。

---

## 1. README との齟齬（存在しないファイル・ディレクトリ）

README / README.ja.md の「リポジトリ構成」およびクイックスタートで参照しているが、**実体が存在しない**項目です。

| 参照箇所 | 期待されるパス | 現状 |
|----------|----------------|------|
| リポジトリ構成 | `docs/threat-model.md` | **なし** |
| リポジトリ構成 | `docs/decision-matrix.md` | **なし** |
| リポジトリ構成 | `policy/base.yaml` | 実ファイルは `policy/base.yml`（拡張子不一致） |
| リポジトリ構成 | `policy/profiles/` | **なし**（ディレクトリ自体がない） |
| クイックスタート | `policy/profiles/balanced.yaml` | **なし**（profiles がないため） |
| クイックスタート | `examples/aws-cloudfront/` | **なし**（examples/ は空） |
| クイックスタート | `examples/cloudflare/` | **なし**（examples/ は空） |

**影響**: 新規ユーザーが README の手順どおりに進めると、コピー・デプロイのステップで失敗する。

---

## 2. ドキュメントの有無

### 2.1 存在するドキュメント

| パス | 内容 |
|------|------|
| `README.md` / `README.ja.md` | 概要・設計思想・対応ランタイム・クイックスタート |
| `docs/architecture.md` / `docs/architecture.ja.md` | アーキテクチャ概要・レイヤー責務・ポリシー駆動・Next Steps |
| `docs/quickstart.md` / `docs/quickstart.ja.md` | ランタイム選択・/admin ゲート・動作確認（README と一部重複） |
| `SECURITY.md` / `SECURITY.ja.md` | 脆弱性報告ポリシー |
| `LICENSE` | MIT |
| 各ランタイム `README.md` / `README.ja.md` | セットアップ・検証例・補足 |

### 2.2 存在しないが README/architecture で言及されているドキュメント

| パス | 言及元 | 想定される内容 |
|------|--------|----------------|
| `docs/threat-model.md` | README 構成・architecture.md「Next Steps」 | 脅威の整理・攻撃シナリオ |
| `docs/decision-matrix.md` | README 構成・architecture.md「Next Steps」 | Edge / WAF の判断基準・責務分離の判断表 |

---

## 3. ポリシーとランタイムの関係

- **`policy/base.yml`**: 人間が読めるポリシー（YAML）として存在し、内容は各ランタイムの CFG と対応している。
- **ランタイム**: CloudFront Functions / Cloudflare Workers / Lambda@Edge は **いずれもポリシーファイルを読み込んでいない**。  
  - 設定は各ランタイム内の `CFG` 等に **ハードコード**。
  - README（CloudFront Functions）には「compiler を入れると `policy/base.yml` から自動生成できる」とあるが、**コンパイラは未実装**。

**影響**: 「ポリシー駆動」を謳っているが、現状はポリシーとランタイムが手動で同期する設計。ポリシー変更時に全ランタイムを手で書き換える必要がある。

---

## 4. サンプル・デプロイ（examples/）

- **現状**: `examples/` ディレクトリは **空**。
- **README**: 「AWS: `examples/aws-cloudfront/`」「Cloudflare: `examples/cloudflare/`」でデプロイと記載。

**影響**: 初見ユーザーが「どこをどうデプロイするか」の具体例がなく、runtimes をそのままデプロイする手順も README に明示されていない。

---

## 5. OSS 運用で一般的に期待されるが未整備の項目

| 項目 | 現状 |
|------|------|
| **CONTRIBUTING.md** | なし（コントリビューション手順・PR の流れ・コードスタイル等の記載なし） |
| **CHANGELOG.md** | なし（バージョン・変更履歴なし） |
| **CODE_OF_CONDUCT.md** | なし |
| **.github/** | ディレクトリなし（Issue テンプレート・PR テンプレート・CI ワークフローなし） |
| **テスト** | ランタイム・ポリシーともにテストコード・テスト実行手順なし |
| **ビルド・CI** | ルートの `package.json` なし。Cloudflare Workers 用のビルドは `wrangler.toml` のみ。Lint/Test の CI なし |
| **バージョン・タグ** | バージョン番号の定義（package.json / タグ）なし |

---

## 6. その他の不整合・注意点

- **リポジトリ名**: 実フォルダは `edgeComputeSecurity`。README の構成図では `cdn-security-framework/` と表記。リポジトリ名と README のどちらを正とするか整理されていない。
- **クイックスタートの二重化**: README 内の「クイックスタート（5分）」と `docs/quickstart.*.md` が類似しており、ポリシー選択・examples 参照など README 側が「未実装の手順」を含む。
- **Lambda@Edge**: `origin-request.js` のみ存在。JWT/署名検証は TODO コメントで「テンプレ」と明記。Origin Response 用のサンプルはなし。
- **SECURITY.md**: 連絡手段が「yourdomain.com」等のプレースホルダのまま。公開前に差し替えが必要。

---

## 7. 優先度付き推奨対応（サマリ）

### 必須（README と矛盾しないようにする）

1. **README の修正**  
   - リポジトリ構成を実態に合わせる（`base.yml`・`profiles/` の有無・`examples/` の有無）。  
   - クイックスタートを「今あるものだけ」で動くようにする（例: `policy/base.yml` を参照、デプロイは `runtimes/` を指定する手順に変更）。
2. **ポリシー拡張子の統一**  
   - README で `base.yaml` と書くなら `policy/base.yml` を `base.yaml` にリネームするか、README を `base.yml` に合わせる。
3. **profiles の扱い**  
   - `policy/profiles/` と `balanced.yaml` を作成するか、README から「ポリシーを選ぶ」手順を削除/変更する。

### 強く推奨（OSS としての信頼性・参加のしやすさ）

4. **CONTRIBUTING.md** の追加（PR の流れ・ブランチ・最低限のチェックリスト）。
5. **examples/ の整備**  
   - `examples/aws-cloudfront/` と `examples/cloudflare/` の少なくとも「デプロイ手順＋必要最小限の設定」を記載した README、または runtimes へのリンク＋デプロイコマンド例。
6. **docs/threat-model.md** と **docs/decision-matrix.md** の追加（architecture の Next Steps と README 構成を満たす）。

### あるとよい

7. **.github/** の整備（Issue/PR テンプレート、必要なら CI の骨子）。
8. **CHANGELOG.md**（バージョンが付いた時点で運用開始で可）。
9. **ポリシー ↔ ランタイム** の同期方針の明文化（現状は手動であることを README または architecture に記載し、将来 compiler を入れる場合の方針を 1 行でも書く）。

---

## 8. ドキュメント「存在」一覧（参照用）

```
存在する:
  README.md, README.ja.md
  LICENSE
  SECURITY.md, SECURITY.ja.md
  docs/architecture.md, docs/architecture.ja.md
  docs/quickstart.md, docs/quickstart.ja.md
  policy/base.yml
  runtimes/*/README.md, runtimes/*/README.ja.md

存在しない:
  docs/threat-model.md
  docs/decision-matrix.md
  policy/base.yaml（※ base.yml は存在）
  policy/profiles/
  policy/profiles/balanced.yaml
  examples/aws-cloudfront/
  examples/cloudflare/
  CONTRIBUTING.md
  CHANGELOG.md
  CODE_OF_CONDUCT.md
  .github/
  ルートの package.json
  テスト・CI の仕組み
```

---

*本監査は、OSS・公開リポジトリとしての提供を前提に、README と実リポジトリの齟齬および一般的な OSS 期待項目を中心に実施したものです。*
