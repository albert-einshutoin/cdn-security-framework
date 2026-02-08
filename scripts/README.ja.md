# スクリプト

CDN Security Framework の補助スクリプト一覧です。

---

## スクリプト一覧

| スクリプト | 用途 |
|------------|------|
| `policy-lint.js` | ポリシー YAML の構造・必須キー・auth gate 制約を検証。 |
| `compile.js` | AWS 向け Edge 生成物（`dist/edge/viewer-request.js` / `viewer-response.js` / `origin-request.js`）を生成。 |
| `compile-cloudflare.js` | Cloudflare Workers 生成物（`dist/edge/cloudflare/index.ts`）を生成。 |
| `compile-infra.js` | Terraform 向け infra 生成物（`dist/infra/*.tf.json`）を生成。 |
| `runtime-tests.js` | AWS viewer/origin テンプレートのランタイム挙動テスト。 |
| `cloudflare-runtime-tests.js` | Cloudflare の compile/template 挙動テスト（JWT/署名付き URL/origin auth 経路）。 |
| `compile-unit-tests.js` | コンパイラコアの単体テスト。 |
| `infra-unit-tests.js` | infra コンパイラ出力の単体テスト（JA3 ルール含む）。 |
| `check-drift.js` | 生成物とコミット済み golden のドリフト検知。 |

---

## 使い方

### ビルド

```bash
node scripts/compile.js
node scripts/compile-cloudflare.js
node scripts/compile-infra.js
```

### Lint

```bash
node scripts/policy-lint.js policy/base.yml
node scripts/policy-lint.js policy/profiles/balanced.yml
```

### テスト

```bash
npm run test:runtime
npm run test:unit
npm run test:drift
```

---

## CI

GitHub Actions の `.github/workflows/policy-lint.yml` では、`main` への push/PR で `policy/`、`scripts/`、`templates/`、`bin/` が変更された場合、次の品質ゲートを実行します。

1. policy lint（base + 全プロファイル）
2. build（AWS + Cloudflare）
3. 生成物存在チェック
4. runtime テスト（`npm run test:runtime`）
5. unit テスト（`npm run test:unit`）
6. drift チェック（`npm run test:drift`）

---

## 関連

- [ポリシーとランタイムの同期](../docs/policy-runtime-sync.ja.md)
- [ポリシープロファイル](../policy/README.ja.md)
