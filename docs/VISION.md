# 目指すゴール (The North Star)

## 入出力

| 項目 | 内容 |
|------|------|
| **入力** | 単一の `security.yml`（すべてのセキュリティ定義の「正」） |
| **処理** | `npx cdn-security build`（CLI コンパイラ） |
| **出力** | **Edge Runtime**: `dist/edge/*.js`（Functions / Workers 用コード）<br>**Infra Config**: `dist/infra/*.tf.json`（Terraform / WAF 用設定・Phase 3） |

## リポジトリ構成（ツール化後）

| パス | 現状 (Before) | 未来 (After) |
|------|----------------|---------------|
| **templates/** | （なし） | **テンプレート置き場**。CLI の内部資産。ユーザーは直接触らない。 |
| **runtimes/** | ユーザーが編集・デプロイするコード | 廃止または templates/ へ移行済み。参照は `templates/`。 |
| **scripts/** | 補助ツール (policy-lint.js 等) | CLI のソース。コンパイルロジックの本体。 |
| **policy/** | サンプル設定 | init 用テンプレート。init 時にユーザーの手元にコピーされる。 |
| **examples/** | デプロイ例 | E2E テスト用プロジェクト。ツールでデプロイを検証する場。 |
| **dist/** | （なし or 旧 dist/aws/） | **自動生成物の出力先**。Edge: `dist/edge/*.js`、Infra: `dist/infra/*.tf.json`。`.gitignore` で無視。ユーザーは `npm run build` で生成。CI で検証する場合は CI 内で build して diff チェック。 |

## 実装フェーズ

- **Phase 1（完了）**: Edge Runtime の自動化 — `security.yml` → `dist/edge/*.js`
- **Phase 2（完了）**: エクスペリエンス向上 — init の充実、IaC 連携ドキュメント（docs/iac.md）
- **Phase 3（完了）**: インフラ設定 (WAF) — YAML に `firewall.waf` セクション追加 → `dist/infra/waf-rules.tf.json`

## 達成済み（Phase 1〜3）

- [x] templates/ をルートに用意し、AWS / Cloudflare テンプレートを参照
- [x] CLI: `init` / `build`（`--target aws|cloudflare`）、`dist/edge/` と `dist/infra/` 出力
- [x] IaC 連携ドキュメント（Terraform / CDK / WAF）
- [x] Phase 3: `firewall.waf` → `dist/infra/waf-rules.tf.json`

次のステップ: npm 公開（README の「For maintainers」参照）、または WAF/Lambda@Edge の拡張。
