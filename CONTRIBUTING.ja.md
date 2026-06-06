# CDN Security Framework へのコントリビューション

コントリビューションに興味を持っていただきありがとうございます。変更の提案方法と、こちらが期待する内容をまとめています。

---

## コントリビューションの方法

### バグ報告・機能提案

- [Issue](https://github.com/albert-einshutoin/cdn-security-framework/issues) を立て、タイトルと説明を明確に記載してください。
- バグ: 再現手順、期待する動作と実際の動作、環境（CDN・ランタイム）を含めてください。
- 機能: ユースケースと、フレームワークのスコープ（Edge セキュリティ、ポリシー駆動、WAF と補完）にどう合うかを記載してください。

### コード・ドキュメント

1. リポジトリを **Fork** し、`develop` からブランチを作成（例: `fix/admin-gate`, `docs/quickstart`）。
2. **変更**は小さく分けたコミットで行ってください。`.ja` が付かないファイルとコード内コメントは **英語**、`.ja` ファイルには **日本語** のみ記載してください。
3. **手動でテスト**: 変更したランタイム（CloudFront Functions のコンソール、Workers の `wrangler dev` など）で動作確認してください。
4. **Pull Request** を `develop` 向けに作成し、短い説明と、あれば Issue へのリンクを書いてください。

---

## レビューで見るポイント

- **設計との整合**: Edge を「最前線」とする、可能な範囲でポリシー駆動、WAF の責務（レート制限、OWASP、Bot）と重複しないこと。
- **後方互換**: 既存のポリシー・ランタイムの挙動を壊す変更は、移行パスを明示した上で行ってください。
- **ドキュメント**: 機能追加・セットアップ変更時は README や docs を更新してください。`.ja` 以外のファイルは英語で記載してください。

---

## CI 品質ゲート

PR 作成前に、次のチェックがローカルで通ることを確認してください。

1. `npm run lint:policy -- policy/base.yml`
2. `npm run build`
3. `node scripts/compile-cloudflare.js`
4. `npm run test:runtime`
5. `npm run test:unit`
6. `npm run test:drift`
7. `npm run test:security-baseline`

GitHub Actions でも、`develop` への push/PR で同じゲートを実行します。

リリースはタグで自動化しています:

1. `package.json` の version を更新
2. リリースブランチへコミット/プッシュ
3. `vX.Y.Z` タグを push
4. `.github/workflows/release-npm.yml` が品質ゲートを実行し、成功時のみ npm 公開

---

## サプライチェーンポリシー

- **GitHub Actions は SHA でピン留め**してください。40文字のコミット SHA とタグコメントを併記する形式です。例:
  `uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4`
  Dependabot が毎週更新 PR を作成します。差分を確認してからマージしてください。
- **`uses: <action>@<tag>` のみの記法は使用しない**でください。Lint 追加後は CI で弾きます。
- **npm 依存**は `.github/dependabot.yml` で追跡。`npm audit` の HIGH/CRITICAL はマージをブロックします。
- **セキュリティに影響する経路**（スキーマ、コンパイラ、テンプレート、ワークフロー）は CODEOWNERS によるレビューを必須化（`.github/CODEOWNERS`）。
- **リリース整合性**: タグ駆動リリースは、`NPM_TOKEN` が未設定の場合 `npm publish --provenance` で公開します。

---

## リポジトリ構成

- `src/` - TypeScript ソース。CLI、コンパイラ、ライブラリ、テストのロジックはここを編集します。
- `bin/`, `lib/`, `scripts/`, `parser/`, `validator/`, `emitter/` - `npm run build:ts` が出力する compiled JavaScript と `.d.ts` の package artifact。直接編集しないでください。
- `docs/` – アーキテクチャ、脅威モデル、判断マトリクス、クイックスタート（英語 + `.ja`）。
- `policy/` – YAML ポリシー。`profiles/` にプロファイル（例: `balanced.yml`）を配置。
- `templates/` - compiler が deploy 可能な edge code を生成するために使う runtime template。
- `tests/golden/` - 生成された drift fixture。手編集ではなく drift workflow で更新します。
- `runtimes/` – CloudFront Functions、Lambda@Edge、Cloudflare Workers。コード・コメントは **英語**。
- `examples/` – AWS CloudFront / Cloudflare のデプロイ例。

---

## ソースと生成物

正となる実装ソースは `src/**/*.ts`、`templates/` 配下の runtime template、policy/docs です。root 配下の JavaScript は、npm 利用者が TypeScript build なしで package を実行できるようにするため、また checkout 直後の CLI smoke test を成立させるために commit しています。

TypeScript ソースを変更するときは:

1. 対応する `src/` 配下のファイルを編集します。
2. `npm run build:ts` を実行します。
3. package surface に含まれる artifact が変わる場合は、`src/**/*.ts` と生成された artifact（`scripts/*.js`, `lib/*.js` など）の両方を commit します。

生成済み JavaScript や `.d.ts` を直接編集しないでください。`.gitattributes` では package artifact、golden fixture、coverage output、生成型定義を generated として扱い、GitHub の言語統計が手書きソースをより正確に表すようにしています。

---

## コードと言語

- **`.ja` が付かないファイル**（`.js`, `.ts`, `.yml`, `.md` 等）: **英語のみ**（コメント・ドキュメント・PR のコミットメッセージ）。
- **`.ja` が付くファイル**（例: `README.ja.md`, `docs/quickstart.ja.md`）: ユーザー向け文面は **日本語のみ**。

---

## ライセンス

コントリビューションいただいた内容は、本プロジェクトと同じライセンス（MIT）で提供されることにご同意いただいたものとみなします。

---

## 質問

不明点があれば、Issue を「question」ラベルで立てるか、機密にしたい場合は [SECURITY.md](SECURITY.md) の連絡手段をご利用ください。
