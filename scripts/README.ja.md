# スクリプト

CDN セキュリティフレームワーク用のヘルパースクリプトです。ポリシー Lint とランタイムテストは外部依存なし（Node.js のみ）で動作します。

---

## スクリプト一覧

| スクリプト | 用途 |
|------------|------|
| `policy-lint.js` | ポリシー YAML の構造を検証（必須キー、バージョン）。デプロイ前に `policy/base.yml` または任意のプロファイルに対して実行。 |
| `runtime-tests.js` | CloudFront Functions の viewer-request ハンドラに対して、リクエスト→期待ステータスのテストを実行。 |

---

## 使い方

### ポリシー Lint

```bash
node scripts/policy-lint.js policy/base.yml
node scripts/policy-lint.js policy/profiles/balanced.yml
```

終了コード 0: 正常。非 0: 検証エラー。

### ランタイムテスト

```bash
node scripts/runtime-tests.js
```

テストケース（メソッドブロック、パストラバーサル、UA ブロック、管理ゲート、クエリ制限）を実行。終了コード 0: 全件成功。

---

## CI

GitHub Actions ワークフロー `.github/workflows/policy-lint.yml` は、`main` への push/PR 時に、`policy/`・`scripts/`・viewer-request ランタイムが変更された場合に、全ポリシーファイルの Lint とランタイムテストを実行します。

---

## 関連

* [ポリシーとランタイムの同期](../docs/policy-runtime-sync.ja.md)
* [ポリシープロファイル](../policy/README.ja.md)
