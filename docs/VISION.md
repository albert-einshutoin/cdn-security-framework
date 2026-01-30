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
| **dist/** | （なし or 旧 dist/aws/） | **自動生成物の出力先**。Edge: `dist/edge/*.js`、Infra: `dist/infra/*.tf.json`。.gitignore またはコミットしてドリフト検知。 |

## 実装フェーズ

- **Phase 1（完了）**: Edge Runtime の自動化 — `security.yml` → `dist/edge/*.js`
- **Phase 2**: エクスペリエンス向上 — init の充実、IaC 連携ドキュメント
- **Phase 3**: インフラ設定 (WAF) — YAML に `firewall` セクション追加 → `dist/infra/*.tf.json`

## 今日のタスク（Phase 1 突破）

- [x] templates/ をルートに用意し、`templates/aws/viewer-request.js` を参照
- [x] package.json に bin を設定し、js-yaml / commander を利用
- [x] コンパイラ: `scripts/compile.js` で YAML を読んで JS を吐く
- [x] 動作確認: `npm run build` で `dist/edge/viewer-request.js` が生成され、CFG が YAML 通りになること

これが **「B ティア脱却」** の第一歩です。
