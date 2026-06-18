# スクリプト

CDN Security Framework の補助スクリプト一覧です。

このディレクトリ配下のランタイム成果物は `src/scripts/*.ts` から生成されます。
本ドキュメント（`scripts/README.md`）と `scripts/README.ja.md` は、直接編集して
更新するガイドです。ランタイム実装を変更したら `src/scripts/` 側で編集し、
`npm run build:ts` で成果物を再生成してください。

---

## スクリプト一覧

| スクリプト | 用途 |
|------------|------|
| `policy-lint.js` | ポリシー YAML の構造・必須キー・auth gate 制約を検証。 |
| `compile.js` | AWS 向け Edge 生成物（`dist/edge/viewer-request.js` / `viewer-response.js` / `origin-request.js`）を生成。 |
| `compile-cloudflare.js` | Cloudflare Workers 生成物（`dist/edge/cloudflare/index.ts`）を生成。 |
| `compile-cloudflare-waf.js` | Cloudflare 向け WAF パリティ検証用生成物を作成。 |
| `compile-infra.js` | Terraform 向け infra 生成物（`dist/infra/*.tf.json`）を生成。 |
| `runtime-tests.js` | AWS viewer/origin テンプレートのランタイム挙動テスト。 |
| `cloudflare-runtime-tests.js` | Cloudflare の compile/template 挙動テスト（JWT/署名付き URL/origin auth フロー）。 |
| `api-contract-tests.js` | パッケージ smoke で使う API 契約チェック。 |
| `compile-unit-tests.js` | コンパイラコアの単体テスト。 |
| `infra-unit-tests.js` | infra コンパイラ出力の単体テスト（JA3/JA4 ルール含む）。 |
| `policy-io-unit-tests.js` | policy IO 周りの単体テスト。 |
| `check-drift.js` | 生成物とコミット済み golden のドリフト検知。 |
| `security-baseline-check.js` | OWASP ベースライン参照と CI ガードレールの必須項目を検証。 |
| `fingerprint-candidates.js` | WAF JSONL ログから JA3/JA4 候補を抽出（段階導入向け）。 |
| `package-smoke-tests.js` | パッケージを pack/install して smoke を行う。 |
| `benchmark-compiler.js` | コンパイラ基準性能計測と optional なインストール計測。 |
| `fingerprint-candidates-unit-tests.js` | 指紋候補抽出ヘルパーの単体テスト。 |
| `schema-lint-tests.js` | schema とテンプレートメタデータの静的チェック。 |

## 使い方

### ビルド

```bash
npm run build:ts
node scripts/compile.js
node scripts/compile-cloudflare.js
node scripts/compile-infra.js
node scripts/compile-infra.js --rule-group-only
```

### Lint

```bash
node scripts/policy-lint.js policy/base.yml
node scripts/policy-lint.js policy/profiles/balanced.yml
```

### テスト

```bash
npm run test:ci

# 局所確認
npm run test:runtime
npm run test:unit
npm run test:drift
npm run test:security-baseline
npm run test:package
```

### フィンガープリント候補抽出

```bash
npm run fingerprints:candidates -- --input waf-logs.jsonl --min-count 20 --top 50
```

### コンパイラ計測

```bash
npm run benchmark:compiler -- --iterations 8 --warmup 1 --policy policy/base.yml
npm run benchmark:compiler -- --measure-install --iterations 5 --policy policy/base.yml
```

---

## CI

`.github/workflows/policy-lint.yml` は `main` / `develop` への push・PR 時に品質ゲートを実行します。

1. policy lint（base + 全プロファイル）
2. build（AWS + Cloudflare）
3. 生成物存在チェック（`npm run test:dist-exists`）
4. runtime テスト（`npm run test:runtime`）
5. unit テスト（`npm run test:unit`）
6. drift チェック（`npm run test:drift`）
7. security baseline チェック（`npm run test:security-baseline`）
8. coverage（`npm run test:coverage`）
9. package smoke（`npm run test:package`）

ローカル同等ゲートは `npm run test:ci`。Workflow では Node マトリックス（`20.17.0`, `22`, `24`）で package smoke も実行します。

---

## 関連

- [ポリシーとランタイムの同期](../docs/policy-runtime-sync.ja.md)
- [ポリシープロファイル](../policy/README.ja.md)
