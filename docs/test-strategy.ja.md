# テスト戦略

> **Languages:** [English](./test-strategy.md) · 日本語

このプロジェクトでは、セキュリティ上重要な smoke / integration test は
独立した Node script として維持しつつ、compiler contract のような絞り込んだ
テストには Vitest を導入します。

## runner の選定

- focused unit / contract test の移行先は Vitest を標準とします。TypeScript の
  test file、watch mode、test name filter、CI 向け structured report を扱いやすいためです。
- Jest も候補ですが、この repository では transform 設定と CommonJS/ESM 境界の
  複雑さが増えます。
- 既存の script harness は、package smoke、drift check、ReDoS fuzzing、
  edge-container attack test のように process-level の挙動が重要なテストで維持します。

## local workflow

- generated artifact や release gate 系チェックを実行する前に、CI と同じ用途の
  fixture secret を設定します。

  ```bash
  export EDGE_ADMIN_TOKEN=ci-build-token-not-for-deploy
  export ORIGIN_SECRET=ci-origin-secret-not-for-deploy
  ```

- Vitest の focused check: `npm run test:vitest`
- 既存 unit suite: `npm run test:unit`
- release gate 全体: `npm run test:all`

`EDGE_ADMIN_TOKEN` は `static_token` 認証ゲートを含む CloudFront Functions artifact
に焼き込まれます。`ORIGIN_SECRET` は drift / release gate で使う origin-auth fixture
向けです。これらの値は local / CI 検証専用であり、production build では deploy 用の
secret を使ってください。

`CI=true` の場合、Vitest は `reports/vitest-junit.xml` に JUnit output を出します。

## 移行方針

focused run、watch mode、明瞭な assertion structure の恩恵があるテストは Vitest
へ移行します。CLI process behavior、package install、generated artifact drift、
fuzzing、container-style attack flow を検証するものは standalone script として残します。
