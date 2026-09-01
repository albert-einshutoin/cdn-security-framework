# プログラマティック API

> **Languages:** [English](./programmatic-api.md) · 日本語

`cdn-security-framework` は Node.js から直接呼び出せる安定 API を公開しています。CI パイプライン・IaC ツール・独自ラッパーから CLI をシェル起動せずにコンパイラを駆動できます。CLI サブコマンドと同じ機能を提供しますが、`process.exit` を呼ばず構造化された結果を返します。

```js
const { compile, emitWaf, lintPolicy, migratePolicy, runDoctor } = require('cdn-security-framework');
```

## 存在理由

以前は CLI 経由でしか統合できませんでした。CI は stderr を取り込み文字列一致で失敗分類し、終了コード 1 / 2 の違いを慣習で扱い、出力ファイル一覧を取得する安定手段もありませんでした。プログラマティック API はこれを以下に置き換えます。

- 統一された `{ ok, errors, warnings, ... }` の形
- 明示的な `edgeFiles` / `infraFiles` 配列（絶対パス）
- `formatNotImplemented` / `reservedExit2` といった機械可読フラグ（stderr 文字列一致に依存しない）
- `process.exit` を呼ばないためプロセス全体への副作用なし

CLI（`bin/cli.js`）もこれらの関数に委譲しています。CLI で再現するバグは API でも再現し、逆もまた然りです。

## Package contract と stability

機械可読な [Package/API manifest](api-manifest.json) が entrypoint、declaration、schema、
bin、必須 example の inventory の正本です。既存の root / phase API と CLI は **stable**、
Contract / OpenAPI / recommendation entrypoint は **stable additive** です。
`source-analysis` と `source/nestjs` は **experimental** で、minor release で変更される
可能性があります。どちらも programmatic / static 専用で application runtime の
enforcement を証明しません。`bin/commands/`、`reporters/`、`scripts/` は tarball に
含まれていても package internal です。

API module の import は side-effect free でなければなりません。policy の読込、出力の書込、
stdout/stderr への表示、process 終了を import 時に行いません。明示的な
Generate → Diff → Review → Apply は CLI を使ってください。

## スコープ

compiler は parser / validator / emitter の phase module に分かれています。`lintPolicy()` は parser + validator を完全 in-process で実行します。`compile()` もこの phase 境界を使い、emitter phase は生成物の互換性を保つため必要な箇所で既存ターゲットスクリプトへ委譲します。

## リファレンス

### `compile(opts)`

ポリシーを検証し、エッジランタイムコード + インフラ設定を生成します。

**入力**

| フィールド | 型 | 備考 |
| --- | --- | --- |
| `policyPath` | `string` | 必須。絶対または `cwd` からの相対。 |
| `outDir` | `string` | 必須。絶対または `cwd` からの相対。 |
| `target` | `'aws' \| 'cloudflare'` | デフォルト `'aws'`。 |
| `outputMode` | `'full' \| 'rule-group'` | AWS のみ。デフォルト `'full'`。 |
| `ruleGroupOnly` | `boolean` | AWS のみ。`aws_wafv2_web_acl` を出さず rule group のみ。 |
| `failOnPermissive` | `boolean` | `metadata.risk_level === 'permissive'` を失敗扱い。 |
| `cwd` | `string` | デフォルト `process.cwd()`。 |
| `pkgRoot` | `string` | インストール済みパッケージルート。 |
| `env` | `NodeJS.ProcessEnv` | デフォルト `process.env`。 |

**出力**

```ts
interface CompileResult {
  ok: boolean;
  errors: string[];
  warnings: string[];
  edgeFiles: string[];   // 絶対パス
  infraFiles: string[];  // 絶対パス
  policyPath: string;    // 解決済み
  outDir: string;        // 解決済み
  target: 'aws' | 'cloudflare';
}
```

**例**

```js
const { compile } = require('cdn-security-framework');

const result = compile({
  policyPath: 'policy/security.yml',
  outDir: 'dist',
  target: 'aws',
});

if (!result.ok) {
  for (const err of result.errors) console.error(err);
  process.exit(1);
}

for (const warn of result.warnings) console.warn(warn);
for (const file of result.edgeFiles) console.log('edge:', file);
for (const file of result.infraFiles) console.log('infra:', file);
```

### `emitWaf(opts)`

インフラ/WAF 設定のみを生成します。`edgeFiles` は常に `[]`。

`compile` と同じ入力に加えて `format: 'terraform' | 'cloudformation' | 'cdk'`（デフォルト `'terraform'`）。

`terraform` は AWS / Cloudflare に対応しています。`cloudformation` は AWS に対応し、`dist/infra/waf-cloudformation.json` を出力します。`cdk` は `{ ok: false, formatNotImplemented: true, errors: [...] }` を返します。CLI は `formatNotImplemented: true` を終了コード 2 に翻訳するので、パイプラインは「未実装」と「実装が失敗」を区別できます。

```js
const { emitWaf } = require('cdn-security-framework');

const result = emitWaf({
  policyPath: 'policy/security.yml',
  outDir: 'dist',
  target: 'aws',
  format: 'cloudformation',
});
```

### `lintPolicy(opts)`

完全 in-process のポリシー検証（スキーマ、パスパターン、auth gate、WAF 健全性、env 参照）。

**入力**

| フィールド | 型 | 備考 |
| --- | --- | --- |
| `policyPath` | `string` | 必須。 |
| `pkgRoot` | `string` | スキーマ/プロファイル解決用ルート。 |
| `env` | `NodeJS.ProcessEnv` | ポリシーが参照する env 変数確認用。 |

**出力**

```ts
interface LintResult {
  ok: boolean;
  errors: string[];
  warnings: string[];
  policy: unknown;  // ok === true のとき YAML パース結果
}
```

### `migratePolicy(opts)`

ポリシーをスキーマバージョン間で移行します。現状 v1 のみリリース済みなので、v1 → v1 は no-op（`{ ok: true, noop: true }`）。

**出力**

```ts
interface MigrateResult {
  ok: boolean;
  errors: string[];
  warnings: string[];
  fromVersion?: number | string;
  toVersion?: number | string;
  migrated?: unknown;
  noop?: boolean;
  reservedExit2?: boolean;  // CLI は終了コード 2 に翻訳
}
```

### `runDoctor(opts)`

環境診断を実行します。`{ exitCode: number, report: {...} }` を返します。`strict: true` を渡すと `cdn-security doctor --strict` と同じく warn チェックも exit code `1` の失敗扱いにします。

## エラー意味論

API は `process.exit` を呼びません。全ての失敗は `{ ok: false, errors: [...] }` として表面化します。プロセス終了コードへの翻訳は CLI レイヤだけが行います。

| ケース | CLI 終了コード | API フラグ |
| --- | --- | --- |
| 成功 | `0` | `ok: true` |
| 一般的な失敗 | `1` | `ok: false` |
| 予約/未実装（例: `emit-waf --format cdk`） | `2` | `formatNotImplemented: true` または `reservedExit2: true` |

独自ラッパーを書くときは stderr をパースせず、構造化フラグを参照してください。

## 後方互換性

- `bin/cli.js` のサブコマンド・オプション・終了コードは従来どおり。
- stderr メッセージは既存の大文字/ハイフンを保持（`Unknown --format:`, `Unknown target:`）。grep しているスクリプトはそのまま動きます。
- `process.exit` を呼ぶのは CLI のみ。

## 関連ドキュメント

- [CLI リファレンス](./cli.ja.md)
- [スキーマ移行](./schema-migration.ja.md)
- [テンプレート注入契約](./template-injection-contract.ja.md)
