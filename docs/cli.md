# CLI Reference

> **Languages:** English · [日本語](./cli.ja.md)

`cdn-security` is the single entry point that scaffolds policy, compiles it to edge runtime code, emits infra config, and runs diagnostics.

```bash
npx cdn-security <subcommand> [options]
```

| Subcommand | Purpose |
| --- | --- |
| `init` | Scaffold `policy/security.yml` from a profile or archetype. |
| `build` | Validate policy, compile edge runtime + infra config. |
| `emit-waf` | Emit infra config only (no edge code). For redeploying firewall rules without touching edge. |
| `doctor` | One-shot environment diagnostics. Exits non-zero on any failing check. |
| `migrate` | Migrate a policy file between schema versions (stub — v1 is the only shipped version today). |

---

## `init`

```bash
npx cdn-security init                                      # interactive
npx cdn-security init --platform aws --profile balanced    # non-interactive
npx cdn-security init --platform aws --archetype rest-api  # archetype
```

- `--profile` and `--archetype` are mutually exclusive — a starter is either a security posture (profile) or an app shape (archetype).
- `--force` overwrites existing `policy/security.yml`.

## `build`

```bash
npx cdn-security build                        # AWS (default)
npx cdn-security build --target cloudflare    # Cloudflare Workers
npx cdn-security build --rule-group-only      # AWS: skip web ACL, emit rule group only
npx cdn-security build --fail-on-permissive   # Exit non-zero if metadata.risk_level == permissive
```

Outputs:

- `dist/edge/viewer-request.js`, `dist/edge/viewer-response.js`, `dist/edge/origin-request.js` (AWS)
- `dist/edge/cloudflare/index.ts` (Cloudflare)
- `dist/infra/*.tf.json` — WAF, geo, IP sets, CloudFront settings, origin timeouts

## `emit-waf`

```bash
npx cdn-security emit-waf                               # AWS WAF terraform
npx cdn-security emit-waf --target cloudflare           # Cloudflare WAF terraform
npx cdn-security emit-waf --target aws --rule-group-only
```

Use when the edge code is already deployed and you only need to refresh firewall rules — saves a full `build`. `build` still emits both edge and infra by default, so nothing about the existing flow changes.

Flags:

- `-p, --policy <path>` — policy file (default `policy/security.yml` → `policy/base.yml`)
- `-o, --out-dir <dir>` — output directory (default `dist`)
- `-t, --target <aws|cloudflare>` — target platform
- `--output-mode <full|rule-group>` — AWS only
- `--rule-group-only` — AWS only; generate rule groups without `aws_wafv2_web_acl`
- `--format <terraform|cloudformation|cdk>` — only `terraform` is generated today; `cloudformation` and `cdk` are reserved stubs that exit 2 so pipelines fail loudly rather than silently fall back.

## `doctor`

```bash
npx cdn-security doctor                               # prints pass/fail report, writes doctor-report.json
npx cdn-security doctor --policy policy/security.yml
npx cdn-security doctor --no-report                   # skip the JSON report
```

Checks run, in order:

| Check | Fails when |
| --- | --- |
| `node_version` | Node < 20.12.0. |
| `policy_exists` | Neither `policy/security.yml` nor `policy/base.yml` is found. |
| `policy_parses` | YAML parse error or non-object top-level value. |
| `policy_schema_version` | `version` field missing, or does not match the CLI's supported schema (currently v1). |
| `env_vars_referenced_by_policy` | Any env var referenced by `routes[].auth_gate.{token_env,credentials_env,secret_env}` or `origin.auth.secret_env` is unset or empty. CloudFront Functions cannot read env at runtime, so these are baked into the build artifact — missing values produce a silent auth bypass. |
| `dist_edge_writable` | Cannot create or write files under `dist/edge/`. |
| `npm_dependencies` | `npm ls --depth=0 --json` reports `problems[]` (missing / invalid peer / unmet dep). `warn` (not fail) when npm is absent. |

Exit code is `0` when no check has status `fail`, else `1`. Report is written to `doctor-report.json` by default — useful for CI capture.

### Example CI usage

```yaml
- name: Environment diagnostics
  run: |
    npx cdn-security doctor
- name: Upload doctor report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: doctor-report
    path: doctor-report.json
```

## `migrate`

```bash
npx cdn-security migrate              # dry-run inspection
npx cdn-security migrate --to 1       # no-op on v1
```

See [schema-migration.md](./schema-migration.md) for the schema SemVer contract and deprecation window.
