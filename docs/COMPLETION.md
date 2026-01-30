# 目標パッケージの完成度

目標（North Star・VISION・TODO）に対する現在の完成度と、100% にするために必要な項目をまとめます。

---

## 現在の完成度: **おおよそ 95%**（npm 公開以外は実施済み）

### 完了している領域（約 75% 分）

| 領域 | 状態 | 備考 |
|------|------|------|
| **入力** | ✅ 100% | 単一の `security.yml`（または `policy/base.yml`）を正とする |
| **CLI 骨格** | ✅ 100% | `npx cdn-security init` / `npx cdn-security build`、commander・inquirer |
| **Edge Runtime（AWS）** | ✅ 100% | viewer-request.js / viewer-response.js を policy から自動生成、`dist/edge/` に出力 |
| **Edge Runtime（Cloudflare）** | ✅ 100% | index.ts を policy から自動生成、`dist/edge/cloudflare/` に出力 |
| **テンプレート・コンパイラ** | ✅ 100% | templates/aws, templates/cloudflare、scripts/compile.js, compile-cloudflare.js |
| **init 用テンプレート** | ✅ 100% | policy/profiles/ を init 時にユーザー側にコピー |
| **E2E 例** | ✅ 100% | examples/aws-cloudfront, examples/cloudflare（package.json + init/build 手順） |
| **ドキュメント** | ✅ 95% | README, quickstart, policy-runtime-sync, OSS-READINESS-AUDIT を新フローに更新 |
| **CI** | ✅ 100% | policy lint, build, dist drift チェック, runtime tests |
| **npm パッケージ形態** | ✅ 100% | package.json (bin, files), 公開手順は README に記載 |

### 未実装・不足（約 25% 分）

| 領域 | 状態 | 備考 |
|------|------|------|
| **Infra Config（Phase 3）** | ✅ 100% | `policy.firewall.waf` から `dist/infra/waf-rules.tf.json` を出力。`scripts/compile-infra.js`。 |
| **Lambda@Edge** | ✅ 100% | `dist/edge/origin-request.js` を policy から生成（最小 CFG、パススルー）。 |
| **IaC 連携の詳細** | ✅ 100% | `docs/iac.md` / `docs/iac.ja.md` に Terraform（file, WAF）、CDK の例を記載。 |
| **実際の npm 公開** | − | 手順はあるが未実施（運用タスク）。 |

---

## 100% にするために必要なこと（npm 公開以外は実施済み）

### 実施済み

1. **Phase 3: Infra Config** — `policy.firewall.waf` から `dist/infra/waf-rules.tf.json` を出力。`scripts/compile-infra.js`。build（aws）時に自動実行。
2. **IaC 連携ドキュメント** — `docs/iac.md` / `docs/iac.ja.md` に Terraform（file, WAF）、CDK の例を記載。
3. **Lambda@Edge (origin-request.js)** — `templates/aws/origin-request.js` と `scripts/compile.js` で `dist/edge/origin-request.js` を生成。

### 残り（運用タスク）

4. **npm レジストリへの公開**
   - README の「For maintainers」に従い、`npm publish` を実行（スコープ付きの場合は `--access public` 等）。
   - 必要に応じて CHANGELOG 更新・タグ付け。

---

## まとめ

| 項目 | 現在 | 100% に必要なこと |
|------|------|-------------------|
| **完成度** | **約 70〜75%** | Phase 3 + IaC 詳細 +（必要なら）Lambda@Edge + npm 公開 |
| **North Star の「出力」** | Edge のみ | **Infra Config（dist/infra/*.tf.json）の実装** |
| **ユーザー体験** | Install → Init → Build → Deploy（Edge）は可能 | WAF まで含めた一貫したストーリーと IaC サンプル |

**結論**: npm 公開以外は目標どおり実装済み（Edge Runtime、Infra Config、IaC ドキュメント、Lambda@Edge）。残りは **npm レジストリへの公開** のみ。
