# Compiler Strictness

> **Languages:** [English](./compiler-strictness.md) · 日本語

compiler strictness check は repository の TypeScript gate 経由で実行し、
parser、validator、emitter、target compile entry point を対象にしています。

```sh
npm run typecheck
```

この gate は `npm run test:all` に含まれます。

## 型付けされた境界

- `parser` は schema 由来の `CDNSecurityFrameworkPolicy` から
  `Partial<CDNSecurityFrameworkPolicy> | null` を返します。
- `validator` は同じ policy draft shape を受け取り、明示的な
  `ValidatePolicyResult` を返します。
- `emitter` は diagnostics と artifact list を型付けした
  `CompileArtifactsResult` を返します。

## 残る dynamic area

一部の dynamic typing は意図的に残しています。

- YAML parse の入力は untrusted data です。parser は policy draft まで狭め、
  schema enforcement は validator が担当します。
- 現時点の `origin.auth` は schema 上 extensible な形なので、validator は閉じた
  object shape と断定せず、必要な string field だけを narrow helper で読みます。
- emitter は CLI と生成物の互換性を維持するため、compiler phase split が安定するまで
  target script を `spawnSync` 経由で呼び出します。

これらは policy schema が discriminated union 化され、target emitter の in-process 化が
進むにつれて縮小できます。
