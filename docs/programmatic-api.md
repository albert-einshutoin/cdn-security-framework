# Programmatic API

> **Languages:** English · [日本語](./programmatic-api.ja.md)

`cdn-security-framework` exposes a stable Node.js API so CI pipelines, IaC tools, and custom wrappers can drive the compiler without shelling out to the CLI. The API mirrors the CLI subcommands but returns structured results instead of calling `process.exit`.

```js
const { compile, emitWaf, lintPolicy, migratePolicy, runDoctor } = require('cdn-security-framework');
```

## Why this exists

Before 1.2.0, the only integration path was the CLI. CI systems had to capture stderr to classify failures, parse exit codes (1 vs 2) by convention, and had no stable way to enumerate emitted files. The programmatic API replaces that with:

- Uniform `{ ok, errors, warnings, ... }` shape
- Explicit `edgeFiles` / `infraFiles` arrays (absolute paths)
- Machine-readable flags (e.g. `formatNotImplemented`, `reservedExit2`) instead of string-matching stderr
- No process-wide side effects — never calls `process.exit`

The CLI (`bin/cli.js`) now delegates to these same functions. If a bug shows up in the CLI, the API sees it too — and vice versa.

## Scope note

`compile()` and `emitWaf()` currently invoke the existing compiler scripts in a subprocess via `spawnSync`. The API contract (inputs, outputs, error semantics) is stable; the subprocess boundary is an implementation detail that will move in-process under issue #69 without changing the surface. `lintPolicy()` and `migratePolicy()` already run fully in-process.

## Reference

### `compile(opts)`

Validate a policy, compile edge runtime code, and emit infra config.

**Input**

| Field | Type | Notes |
| --- | --- | --- |
| `policyPath` | `string` | Required. Absolute or relative to `cwd`. |
| `outDir` | `string` | Required. Absolute or relative to `cwd`. |
| `target` | `'aws' \| 'cloudflare'` | Defaults to `'aws'`. |
| `outputMode` | `'full' \| 'rule-group'` | AWS only. Defaults to `'full'`. |
| `ruleGroupOnly` | `boolean` | AWS only. Emit rule groups without `aws_wafv2_web_acl`. |
| `failOnPermissive` | `boolean` | Non-zero-equivalent when `metadata.risk_level === 'permissive'`. |
| `cwd` | `string` | Defaults to `process.cwd()`. |
| `pkgRoot` | `string` | Defaults to the installed package root. |
| `env` | `NodeJS.ProcessEnv` | Defaults to `process.env`. |

**Output**

```ts
interface CompileResult {
  ok: boolean;
  errors: string[];
  warnings: string[];
  edgeFiles: string[];   // absolute paths
  infraFiles: string[];  // absolute paths
  policyPath: string;    // resolved
  outDir: string;        // resolved
  target: 'aws' | 'cloudflare';
}
```

**Example**

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

Emit only the infra/WAF config. `edgeFiles` is always `[]`.

Same input shape as `compile` plus `format: 'terraform' | 'cloudformation' | 'cdk'` (defaults to `'terraform'`).

Only `terraform` is generated today. `cloudformation` and `cdk` return `{ ok: false, formatNotImplemented: true, errors: [...] }`. The CLI translates `formatNotImplemented: true` to exit code 2 so pipelines can distinguish "not implemented" from "implementation failed".

```js
const { emitWaf } = require('cdn-security-framework');

const result = emitWaf({
  policyPath: 'policy/security.yml',
  outDir: 'dist',
  target: 'aws',
  format: 'terraform',
});
```

### `lintPolicy(opts)`

Fully in-process policy validation (schema, path patterns, auth gates, WAF hygiene, env references).

**Input**

| Field | Type | Notes |
| --- | --- | --- |
| `policyPath` | `string` | Required. |
| `pkgRoot` | `string` | Schema/profiles resolution root. |
| `env` | `NodeJS.ProcessEnv` | For env-var referenced by policy. |

**Output**

```ts
interface LintResult {
  ok: boolean;
  errors: string[];
  warnings: string[];
  policy: unknown;  // parsed YAML when ok === true
}
```

### `migratePolicy(opts)`

Migrate a policy file between schema versions. v1 is the only shipped version today; a v1 → v1 call is a no-op with `{ ok: true, noop: true }`.

**Output**

```ts
interface MigrateResult {
  ok: boolean;
  errors: string[];
  warnings: string[];
  fromVersion?: number | string;
  toVersion?: number | string;
  migrated?: unknown;
  noop?: boolean;
  reservedExit2?: boolean;  // CLI translates to exit 2
}
```

### `runDoctor(opts)`

Run environment diagnostics. Returns `{ exitCode: number, report: {...} }`. Unlike the other functions, `runDoctor` already pre-dates this surface and is re-exported unchanged.

## Error semantics

The API never calls `process.exit`. All failure modes surface as `{ ok: false, errors: [...] }`. The CLI layer is the only caller that translates to process exit codes:

| Case | CLI exit | API flag |
| --- | --- | --- |
| Success | `0` | `ok: true` |
| Generic failure | `1` | `ok: false` |
| Reserved / not-implemented (e.g. `emit-waf --format cdk`) | `2` | `formatNotImplemented: true` or `reservedExit2: true` |

When building your own wrapper, prefer inspecting the structured flags rather than parsing stderr.

## Backwards compatibility

- `bin/cli.js` still uses the same subcommands, options, and exit codes as before.
- Stderr messages preserve existing capitalization (`Unknown --format:`, `Unknown target:`) so scripts grepping for them continue to work.
- The CLI is the only place `process.exit` is called.

## See also

- [CLI reference](./cli.md)
- [Schema migration](./schema-migration.md)
- Roadmap item #69 (in-process compile) in [ROADMAP.md](./ROADMAP.md)
