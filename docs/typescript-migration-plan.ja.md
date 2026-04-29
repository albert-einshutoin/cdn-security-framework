# TypeScript 移行プラン

## 目的

実装ソースを TypeScript 化し、既存の CLI、programmatic API、テスト実行方法、npm package の利用パスを維持する。

## 方針

- 実装ソースは `src/` 配下の `.ts` に集約する。
- `tsc` は CommonJS の `.js` を既存の `bin/`, `lib/`, `scripts/` に生成する。
- package の公開面は維持する。
  - `bin.cdn-security`: `bin/cli.js`
  - `main`: `lib/index.js`
  - 既存テスト: `node scripts/*-tests.js`
- CloudFront Functions 向けの runtime template と golden fixture は生成・配布対象なので、移行対象から除外する。
- 型安全性は段階的に強める。移行完了後は `strict: true` を有効にし、既存JS由来の大きな整理が必要な項目だけ明示的に緩和する。

## 実装ステップ

1. TypeScript ビルド基盤を追加する。
   - `typescript`, `@types/node`, `@types/js-yaml`
   - `tsconfig.json`
   - `npm run build:ts`
   - `npm run typecheck`
2. 互換性保護テストを追加する。
   - programmatic API の export contract
   - CLI entrypoint の存在
   - 代表的な structured result の shape
3. `bin/`, `lib/`, `scripts/` の実装ソースを `src/` 配下へ移す。
4. `tsc` 生成後の JS で既存テストを実行する。
5. `test:all` に `build:ts` を組み込み、CI が TS 生成物を検証する状態にする。

## 完了条件

- `src/` 配下の実装・テストソースから `@ts-nocheck` を撤去し、TypeScript の型検査対象にする。
- `npm run typecheck` が成功する。
- `npm run test:api-contract` が成功する。
- `EDGE_ADMIN_TOKEN=ci-build-token-not-for-deploy ORIGIN_SECRET=ci-origin-secret-not-for-deploy npm run test:all` が成功する。
- `bin/`, `lib/`, `scripts/` の手書き実装ソースは `src/` 配下の TypeScript になる。
- `strict: true` と `useUnknownInCatchVariables: true` を有効にする。暗黙 any と strict null の完全整理は後続フェーズで行う。
