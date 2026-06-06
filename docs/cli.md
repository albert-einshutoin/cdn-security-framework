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
| `readiness` | Production release gate that combines diagnostics and policy posture findings. |
| `capabilities` | Print target support matrix and optionally evaluate policy controls against a target. |
| `deploy-template` | Generate GitHub Actions workflow templates for AWS and Cloudflare artifact deployment. |
| `explain` | Print a concise policy posture summary for review and onboarding. |
| `diff` | Compare generated output against the current `dist/` tree and fail on drift. |
| `migrate` | Migrate a policy file between schema versions (stub — v1 is the only shipped version today). |

---

## `init`

```bash
npx cdn-security init                                      # interactive
npx cdn-security init --platform aws --profile balanced    # non-interactive
npx cdn-security init --platform aws --archetype rest-api  # archetype
npx cdn-security init --guided --platform cloudflare --app-shape rest-api --auth jwt --cors-origins https://app.example.com
```

- `--profile` and `--archetype` are mutually exclusive — a starter is either a security posture (profile) or an app shape (archetype).
- `--guided` asks about app shape, CDN target, auth mode, protected paths, CORS origins, WAF posture, geo/IP constraints, and deployment intent.
- Guided setup also has CI-friendly flags: `--app-shape`, `--auth`, `--admin-paths`, `--cors-origins`, `--waf`, `--geo-block`, `--ip-allowlist`, `--deployment`, and `--project`.
- Generated guided policies include comments pointing to secret-management docs. Secret values are never written; only env var names such as `EDGE_ADMIN_TOKEN`, `BASIC_AUTH_CREDS`, `URL_SIGNING_SECRET`, or `WAF_LOG_DESTINATION_ARN` are referenced.
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
npx cdn-security emit-waf --format cloudformation       # AWS WAFv2 CloudFormation JSON
npx cdn-security emit-waf --target aws --rule-group-only
```

Use when the edge code is already deployed and you only need to refresh firewall rules — saves a full `build`. `build` still emits both edge and infra by default, so nothing about the existing flow changes.

Flags:

- `-p, --policy <path>` — policy file (default `policy/security.yml` → `policy/base.yml`)
- `-o, --out-dir <dir>` — output directory (default `dist`)
- `-t, --target <aws|cloudflare>` — target platform
- `--output-mode <full|rule-group>` — AWS only
- `--rule-group-only` — AWS only; generate rule groups without `aws_wafv2_web_acl`
- `--format <terraform|cloudformation|cdk>` — `terraform` is supported for AWS and Cloudflare. `cloudformation` is supported for AWS and writes `dist/infra/waf-cloudformation.json`. `cdk` remains reserved and exits 2.

## `doctor`

```bash
npx cdn-security doctor                               # prints pass/fail report, writes doctor-report.json
npx cdn-security doctor --policy policy/security.yml
npx cdn-security doctor --strict                      # fail on warn checks too
npx cdn-security doctor --no-report                   # skip the JSON report
```

Checks run, in order:

| Check | Fails when |
| --- | --- |
| `node_version` | Node < 20.17.0. |
| `policy_exists` | Neither `policy/security.yml` nor `policy/base.yml` is found. |
| `policy_parses` | YAML parse error or non-object top-level value. |
| `policy_schema_version` | `version` field missing, or does not match the CLI's supported schema (currently v1). |
| `env_vars_referenced_by_policy` | Any env var referenced by `routes[].auth_gate.{token_env,credentials_env,secret_env}` or `origin.auth.secret_env` is unset or empty. CloudFront Functions cannot read env at runtime, so these are baked into the build artifact — missing values produce a silent auth bypass. |
| `dist_edge_writable` | Cannot create or write files under `dist/edge/`. |
| `npm_dependencies` | `npm ls --depth=0 --json` reports `problems[]` (missing / invalid peer / unmet dep). `warn` (not fail) when npm is absent. |

Exit code is `0` when no check has status `fail`, else `1`. With `--strict`, warning checks also fail the command. Report is written to `doctor-report.json` by default — useful for CI capture.

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

## `readiness`

```bash
npx cdn-security readiness
npx cdn-security readiness --target cloudflare
npx cdn-security readiness --strict
npx cdn-security readiness --json
npx cdn-security readiness --report readiness-report.json
```

Runs a production-oriented release gate over the selected policy. It reuses environment diagnostics and policy validation, then adds production posture checks for risk level, enforce mode, method restrictions, response headers, WAF rate limits, managed-rule coverage, and target-specific unsupported controls.

Exit code is `1` when any finding has severity `fail`. With `--strict`, warning findings also fail the command. Use `--json` for stdout JSON, or `--report <path>` to write the same machine-readable report while keeping the human summary on stdout/stderr.

## `capabilities`

```bash
npx cdn-security capabilities
npx cdn-security capabilities --json
npx cdn-security capabilities --policy policy/security.yml --target aws
npx cdn-security capabilities --policy policy/security.yml --target cloudflare --json
```

Prints the target support matrix for AWS CloudFront Functions, AWS Lambda@Edge, Cloudflare Workers, and Terraform-backed WAF controls. Status values are `supported`, `partial`, `unsupported`, and `warning-only`.

When `--policy` is provided, the command detects configured controls and reports target-specific findings for controls that are partial, unsupported, or warning-only. The command is read-only and does not fail the process for findings; use `--json` and inspect `policyEvaluation.findings` in automation.

## `deploy-template`

```bash
npx cdn-security deploy-template
npx cdn-security deploy-template --target aws
npx cdn-security deploy-template --target cloudflare
npx cdn-security deploy-template --out-dir .github/workflows --force
```

Writes starter GitHub Actions workflows for generated edge and infra artifacts. The AWS template builds and uploads `dist/edge/` and `dist/infra/` for a downstream Terraform/CDK/CloudFront release. The Cloudflare template builds the Worker, passes configured runtime secrets through `wrangler deploy --secrets-file`, and uploads generated artifacts.

The templates reference GitHub Secrets such as `EDGE_ADMIN_TOKEN`, `BASIC_AUTH_CREDS`, `URL_SIGNING_SECRET`, `JWT_SECRET`, `ORIGIN_SECRET`, `CHALLENGE_SECRET`, `CLOUDFLARE_API_TOKEN`, and `CLOUDFLARE_ACCOUNT_ID`; they never include secret values. For Cloudflare, extend `CDN_SECURITY_WORKER_SECRET_NAMES` when your policy uses additional `*_env` names. Existing files are not overwritten unless `--force` is provided.

## `explain`

```bash
npx cdn-security explain
npx cdn-security explain --policy policy/security.yml
```

Prints the policy's schema, mode, allowed methods, request limits, host and route posture, auth gates, WAF settings, and response headers. It is read-only and intended for code review, runbooks, and issue triage.

## `diff`

```bash
npx cdn-security diff
npx cdn-security diff --target cloudflare
npx cdn-security diff --out-dir dist
```

Compiles the selected policy to a temporary directory and compares it with the current output tree. It prints `MISSING`, `EXTRA`, and `CHANGED` entries and exits `1` when generated artifacts are out of date.

## `migrate`

```bash
npx cdn-security migrate              # dry-run inspection
npx cdn-security migrate --to 1       # no-op on v1
```

See [schema-migration.md](./schema-migration.md) for the schema SemVer contract and deprecation window.
