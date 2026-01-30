# やることリスト（コンパイラ + npm パッケージ化）

## 目指すゴール (North Star)

- **入力**: 単一の `security.yml`（すべてのセキュリティ定義の「正」）
- **処理**: `npx cdn-security build`
- **出力**: **Edge Runtime** `dist/edge/*.js`（Functions / Workers 用）、**Infra Config** `dist/infra/*.tf.json`（Phase 3）

## 目指すユーザー体験

- **Install**: `npm i -D cdn-security-framework`
- **Init**: `npx cdn-security init` （対話で `policy/security.yml` 雛形が生成される）
- **Build**: `npx cdn-security build` （security.yml から `dist/edge/*.js` に生成される）
- **Deploy**: 生成された `dist/edge/` を Terraform / CDK 等でデプロイ

---

## 1. 提供形態：npm パッケージ

- [x] **package.json を npm パッケージ用に整える**（済）
  - `"bin": { "cdn-security": "./bin/cli.js" }` を追加。
  - `dependencies`: `js-yaml`, `commander`, `inquirer`。
  - `files`: `bin/`, `scripts/`, `templates/`, `policy/profiles/`。

- [x] **bin/cli.js を用意する**（済）
  - shebang と commander で `cdn-security` コマンドを定義。サブコマンド: `init`, `build`。

- [x] **npm レジストリに公開する**（手順は README に記載済み）
  - README「For maintainers (publishing to npm)」に package-lock.json / dist/ のコミットと `npm publish` の条件を記載。ユーザーは `npm install --save-dev cdn-security-framework` で導入可能。

---

## 2. ユーザー体験：YAML 作成〜コンパイル

### Step 1: 初期化 (Scaffolding)

- [x] **`npx cdn-security init` を実装する**（済）
  - **挙動**: 対話形式で質問し、最適な `policy/security.yml` と `policy/profiles/<profile>.yml` を生成する。
  - **質問例**: `Which platform are you using?` → AWS / Cloudflare。`Choose a security profile:` → Strict / Balanced / Permissive。
  - **非対話**: `--platform aws --profile balanced --force` で CI/スクリプトから実行可能。
  - 成功メッセージ: `[SUCCESS] Created policy/base.yml`, `[SUCCESS] Created policy/profiles/balanced.yml` 等。

### Step 2: 編集とコンパイル (Build)

- [x] **`npx cdn-security build` を実装する**（済）
  - **挙動**: `policy/base.yml` を読み込み → Lint → 指定プラットフォーム向け JS を `dist/` に出力。
  - **出力例**: `[INFO] Validating policy... OK`, `[INFO] Target: AWS CloudFront Functions`, `[SUCCESS] Generated dist/edge/viewer-request.js`。
  - **オプション**: `--policy <path>`, `--out-dir <dir>`, `--target aws|cloudflare`（Cloudflare は未実装）。

---

## 3. リポジトリ内の役割変更（改造計画）

| ディレクトリ | 現在の役割 | 未来の役割（npm パッケージ化後） |
|-------------|------------|----------------------------------|
| **templates/** | （なし → runtimes/templates/ から移行） | **テンプレート置き場（内部アセット）**。CLI の build がここから dist/edge/*.js を生成する。 |
| **runtimes/** | ユーザーが編集・デプロイするコード | 廃止または templates/ へ移行済み。参照は `templates/`。 |
| **scripts/** | 開発用スクリプト（compile.js, policy-lint.js 等） | **CLI のソース**。init / build の実装。 |
| **policy/** | サンプルポリシー | **初期化用テンプレート**。`init` 時に `policy/security.yml` 等をユーザー側にコピー。 |
| **examples/** | デプロイ例 | **E2E テスト用プロジェクト**。ツールで init → build → デプロイを検証する場。 |
| **dist/** | （なし or 旧 dist/aws/） | **自動生成物**。`dist/edge/*.js`（Edge Runtime）、`dist/infra/*.tf.json`（Phase 3）。 |

- [x] **runtimes/** を「レガシー・参照」と明記する**（済）
  - runtimes/aws-cloudfront-functions/README に「デプロイは dist/edge/。runtimes/ はレガシー・参照用」と記載。

- [x] **scripts/ と CLI の関係を整理する**（済）
  - `bin/cli.js` から `scripts/compile.js` および `scripts/policy-lint.js` を呼ぶ形で実装済み。

- [x] **policy/** を init 用テンプレートとして扱う**（済）
  - `init` は `policy/profiles/<profile>.yml` をユーザーの `policy/security.yml` にコピー。`--force` で上書き可能。

- [x] **examples/** を E2E 用に整える**（済）
  - `examples/aws-cloudfront/` に package.json（devDependency: cdn-security-framework from repo）、init/build スクリプト、README（init → build → dist/edge/ デプロイ手順）を追加。`examples/README.md` で E2E 例の案内を記載。

---

## 4. 必須（CI・運用を成立させる）

- [x] **dist/ を初回コミットする**（手順は README に記載済み）  
  CI で「Check for changes (dist drift)」を使う場合は `npm run build` 後に `dist/edge/` をコミットする。README「For maintainers」に記載。

- [x] **package-lock.json をコミットする**（手順は README に記載済み）  
  CI で `npm ci` を使うため。README「For maintainers」に記載。

---

## 5. ドキュメント更新（新しいフローに合わせる）

- [x] **README.md / README.ja.md**（済）
  - 導入・クイックスタートを新フロー（init → build → dist/edge/）に更新。「手動で CFG を更新」を削除。

- [x] **docs/quickstart.md / docs/quickstart.ja.md**（済）
  - 「policy 編集 → npx cdn-security build」に変更。デプロイ対象は `dist/edge/`。

- [x] **docs/policy-runtime-sync.md / docs/policy-runtime-sync.ja.md**（済）
  - CloudFront Functions 向けコードは `cdn-security build` で policy から自動生成される旨を記載。

- [x] **docs/OSS-READINESS-AUDIT*.md**（済）
  - 「コンパイラ未実装」を「実装済み（CLI: init / build）」に更新。

---

## 6. 運用・案内の整理

- [x] **runtimes/aws-cloudfront-functions/README（.ja 含む）**（済）
  - デプロイ用は `dist/edge/`。runtimes/ はレガシー・参照用である旨を記載。

---

## 7. 将来・拡張

- [ ] **Lambda@Edge (origin-request.js)**  
  必要ならテンプレートと build 対象に追加。

- [ ] **Cloudflare Workers (index.ts)**  
  必要なら `runtimes/templates/cloudflare/` と build で生成する。

- [ ] **viewer-response.js の自動生成**  
  policy の `response_headers` 等から生成する。
