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
| `playground` | Compile policy locally and run sample request fixtures against edge runtimes (AWS + Cloudflare). |
| `analyze` | Aggregate block/monitor JSONL logs and surface low-frequency candidates. |
| `emit-waf` | Emit infra config only (no edge code). For redeploying firewall rules without touching edge. |
| `doctor` | One-shot environment diagnostics. Exits non-zero on any failing check. |
| `readiness` | Production release gate that combines diagnostics and policy posture findings. |
| `capabilities` | Print target support matrix and optionally evaluate policy controls against a target. |
| `deploy-template` | Generate GitHub Actions workflow templates for AWS and Cloudflare artifact deployment. |
| `explain` | Print a concise policy posture summary for review and onboarding. |
| `visualize` | Render a deterministic policy control map in Mermaid or static HTML, including supported/monitor/unsupported/target-specific status. |
| `diff` | Compare generated output drift or semantic policy posture changes between policies. |
| `migrate` | Preview or explicitly save a validated v1→v2 migration with an original-policy backup. |
| `openapi inspect` | Inspect local OpenAPI security contracts as deterministic text or JSON without changing policy or build output. |
| `openapi generate-policy` | Generate a non-destructive, review-only policy candidate and metadata sidecar. |
| `contract diff` | Compare OpenAPI declarations with the effective policy and emit security findings. |

---

## `contract diff`

```bash
npx cdn-security contract diff \
  --openapi openapi.yaml --policy policy/security.yml --target aws
npx cdn-security contract diff \
  --openapi openapi.yaml --policy policy/security.yml --target cloudflare \
  --exceptions policy/finding-exceptions.yml --format json \
  --out reports/contract-diff.json --fail-on warning
npx cdn-security contract diff \
  --openapi openapi.yaml --policy policy/security.yml --target aws \
  --format sarif --out reports/cdn-security.sarif --fail-on never
```

- `--openapi`, `--policy`, and `--target aws|cloudflare` are required. All inputs and local references must stay inside `--workspace-root`.
- `--format text|json|sarif` defaults to text. JSON follows [`contract-diff-report-v1.schema.json`](../schemas/contract-diff-report-v1.schema.json). SARIF emits deterministic SARIF 2.1.0 for CI consumers. Both machine formats exclude timestamps, absolute paths, raw specifications, and secrets.
- `--exceptions` applies the existing Finding Exception contract. Pass `--environment <name>` when exceptions use `selector.environment`. Suppressed findings are counted but omitted unless `--include-suppressed` is set; in SARIF they are encoded as accepted external suppressions. Use `--current-date YYYY-MM-DD` to pin expiry evaluation for reproducible CI reports.
- `--fail-on error|warning|never` defaults to `error`. Exit codes are `0` below threshold, `1` at or above threshold, `2` for input/configuration/safety errors, and `3` for unexpected internal errors.
- `--out` writes only to an existing directory inside the workspace. Existing regular files require `--force`; policy, build output, and analyzed source files are protected. Run the command with exclusive control of the writable workspace: a same-user process with rename permission can relocate an already-open directory inode after validation.
- Text starts with the summary and contains rule, route, expected/actual evidence, and remediation. Color is used only on a TTY and is disabled by `NO_COLOR`.

The command is read-only except for an explicit report output. Unsupported and partial analyzer capabilities are reported as omitted comparisons rather than guessed.

To retain SARIF as a GitHub Actions artifact without granting Code Scanning upload permissions:

```yaml
- run: >-
    npx cdn-security contract diff --openapi openapi.yaml
    --policy policy/security.yml --target aws --format sarif
    --out reports/cdn-security.sarif --fail-on never
- name: Upload CDN security SARIF artifact
  uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
  with:
    name: cdn-security-sarif
    path: reports/cdn-security.sarif
```

This only stores the artifact; automatic Code Scanning upload is outside this command.

---

## `openapi inspect`

```bash
npx cdn-security openapi inspect --input openapi.yaml --workspace-root .
npx cdn-security openapi inspect --input openapi.yaml --workspace-root . --json
npx cdn-security openapi inspect --input openapi.yaml --workspace-root . --json --out reports/openapi-contract.json
```

- `--input <path>` is required and accepts OpenAPI 3.0/3.1 YAML or JSON inside `--workspace-root`.
- Local `$ref` files must stay inside the workspace. Remote and `file:` references remain disabled.
- Text output summarizes version, digest, operation exposure/auth, content types, parameters, capabilities, and limit warnings.
- `--json` emits deterministic Security IR plus safe analyzer metadata and diagnostics. It contains no timestamp, absolute path, or raw OpenAPI document.
- `--out` requires `--json`, an existing parent directory, and a path inside the workspace. Existing files require `--force`.
- OpenAPI input, `policy/`, and `dist/` are protected output locations. Inspection never generates or deploys policy.
- Parse, reference, and resource-limit failures use stable `OPENAPI_*` codes and safe messages on stderr.

The JSON output follows [`openapi-inspection-v1.schema.json`](../schemas/openapi-inspection-v1.schema.json). Unsupported or partial analysis remains explicit; it is never treated as public access.

## `openapi generate-policy`

```bash
npx cdn-security openapi generate-policy \
  --input openapi.yaml \
  --workspace-root . \
  --profile balanced \
  --out policy/openapi.candidate.yml
```

- `--input`, `--profile strict|balanced|permissive`, and `--out` are required.
- `--workspace-root` bounds the input, local `$ref`s, and both output files.
- Existing regular candidate and sidecar files require `--force`.
- The command writes a schema-valid YAML candidate plus a deterministic
  `.meta.json` sidecar. It never merges with the active policy or deploys it.
- Authentication details and unsupported controls are reported as omitted,
  never guessed or approximated.

See the [OpenAPI integration guide](openapi-integration.md) for the runnable
example, limits, review workflow, and troubleshooting.

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

Build supports inheritance via top-level `extends`:

- `policy` can point to another policy file and reuse defaults across services.
- `extends` path is resolved relative to the selected policy file.
- Merge behavior is deep-merge for objects and append for arrays:
  - object key collisions are resolved by child
  - arrays from parent then child
  - scalar replacement replaces the parent subtree
- Inheritance is transitive (supports `child` -> `parent` -> `grandparent`).

## `playground`

```bash
npx cdn-security playground                                      # local fixtures against built-in examples (AWS + Cloudflare)
npx cdn-security playground --target aws --json                   # machine-readable output
npx cdn-security playground --policy policy/security.yml -f cases.json
npx cdn-security playground --allow-placeholder-token --target all  # allow INSECURE_PLACEHOLDER__REBUILD_WITH_REAL_TOKEN
```

`playground` builds the selected policy to a temporary directory and executes synthetic requests through the generated runtime. It reports `pass|block`, HTTP `status`, and `block_reason` for each fixture and includes the runtime target (`aws` or `cloudflare`).

Input format options:

- `--fixture <path>` accepts one of:
  - `{ "fixtures": [ ... ] }`
  - `[ ... ]`
  - `{ "request": { ... } }`
- each fixture item accepts:
  - `method`
  - `path`
  - `query` (string or object map)
  - `headers`
  - `body`

Example fixture:

```json
{
  "fixtures": [
    { "name": "GET /", "request": { "method": "GET", "path": "/" } },
    { "name": "PATCH blocked", "request": { "method": "PATCH", "path": "/" } },
    { "name": "admin missing auth", "request": { "method": "GET", "path": "/admin", "headers": { "x-edge-token": "INSECURE_PLACEHOLDER__REBUILD_WITH_REAL_TOKEN" } } }
  ]
}
```

When `--json` is set, output is:

```json
{
  "policyPath": "/path/to/policy/security.yml",
  "targets": [
    {
      "target": "aws",
      "fixtures": [
        {
          "name": "GET /",
          "decision": "pass",
          "status": 200,
          "block_reason": "",
          "path": "/",
          "method": "GET",
          "query": ""
        }
      ]
    }
  ]
}
```

## `analyze`

```bash
npx cdn-security analyze --input /path/to/monitor.jsonl
npx cdn-security analyze --input /path/to/monitor.jsonl --min-count 3 --top 10 --json
```

`analyze` reads JSONL without modifying the input. It groups valid records by route/reason and surfaces low-frequency block candidates; it does not decide whether a policy is safe or apply changes.

- `--input`: required JSONL file path.
- `--min-count`: inclusive upper count threshold for block candidates (default `5`, rounded down).
- `--top`: maximum candidates and samples per candidate (default `20`, rounded down).
- `--json`: one JSON document with a final newline on stdout; otherwise a text report.

Each nonblank line must be an object with an explicit own `event`, `eventName`, or `outcome`. Values are trimmed and case-insensitive: `allow`/`pass`/`passed` → `pass`, `block`/`blocked` → `block`, `monitor`/`monitoring`/`logged` → `monitor`; `audit`, `error`, `challenge`, and `challenge_report` retain their meaning. Every supplied event alias must be valid and agree. Status alone never implies an event, and a challenge with status 403 is not a block.

If any outer event alias exists, the outer record is selected even when its value is invalid. Otherwise, an own `message` must contain a JSON string encoding an object with an event alias. Only one layer is decoded; outer metadata is not merged and there is no fallback to another record.

Supplied auxiliary string fields must be nonempty strings before privacy normalization. All supplied aliases are validated, then the first is selected in this order:

| Field | Alias priority |
| --- | --- |
| method | `method`, `httpRequest.method`, `request.method` |
| URI | `uri`, `path`, `request.uri`, `request.path`, `httpRequest.uri`, `httpRequest.path` |
| policy route | `policy_route`, `policyRoute`, `route`, `request.route`; URI only when all are absent |
| target | `target`, `platform`, `provider`, `runtime` |
| reason | `block_reason`, `blockReason`, `reason` |

Present `request`/`httpRequest` containers must be objects, not arrays or null. Both `status` and `statusCode` are validated before selecting the first: a safe integer number, or a trimmed decimal-digit string, representing 0 or 100–599. Explicit 0 does not fall back. Missing method/status/target/reason display as `UNKNOWN`/0/`unknown`/`unclassified`. Missing URI/route, including a selected value made empty by privacy normalization, stays distinct internally and displays as `unknown`. An explicit `unknown` route becomes `/unknown`. Blocks with no real route count in the summary but cannot become route candidates.

All valid events contribute to route/reason groups. Only explicit canonical block/monitor events increment their respective counters. Candidates contain block events with a real route and `count <= --min-count`, sorted by count then route, preserving input order for ties. Credentials, URL userinfo, query/fragment and unsafe path text are normalized before grouping; diagnostics contain no raw records or argument values.

| `summary.inputStatus` | Meaning | Exit | stderr (one line) |
| --- | --- | --- | --- |
| `complete` | All nonblank records valid | 0 | empty |
| `partial` | Valid and invalid records mixed; report contains the valid portion | 1 | `[WARN] ANALYZE_INPUT_PARTIAL` |
| `invalid` | Nonblank records exist, none valid | 1 | `[ERROR] ANALYZE_INPUT_INVALID` |
| `empty` | No nonblank records | 1 | `[WARN] ANALYZE_INPUT_EMPTY` |

Exit 0 means input processing completed; it is not a security approval. Nonzero input status still emits a complete report. `totalLines = parsedLines + unparseableLines` counts nonblank lines; `analyzedEvents = parsedLines` counts valid records. JSON includes `diagnostics` and text includes `input_status` and a `diagnostics` JSON line. Diagnostics contain `total`, `counts` (all codes below, in this order, including zero), the first 20 `{line, code}` examples using physical 1-based line numbers (blank lines included), and `omitted`.

1. `ANALYZE_JSON_SYNTAX`: invalid outer JSON.
2. `ANALYZE_RECORD_TYPE`: outer value is not an object.
3. `ANALYZE_EVENT_MISSING`: no event alias or message.
4. `ANALYZE_EVENT_VALUE`: event alias is not a nonempty string.
5. `ANALYZE_EVENT_UNKNOWN`: unrecognized event value.
6. `ANALYZE_EVENT_ALIAS_CONFLICT`: aliases disagree.
7. `ANALYZE_NESTED_MESSAGE`: invalid one-layer message envelope.
8. `ANALYZE_FIELD_VALUE`: invalid auxiliary field/container.
9. `ANALYZE_STATUS_VALUE`: invalid status.

Each rejected line produces one diagnostic: JSON/object and record selection first, then event type/known value/agreement, containers (`request`, then `httpRequest`), string fields in the table order, and status. Fatal errors emit no report (stdout empty), exit 1, and a fixed stderr line: `[ERROR] ANALYZE_INPUT_NOT_FOUND`, `[ERROR] ANALYZE_INPUT_READ_FAILED`, or `[ERROR] ANALYZE_ARGUMENT_INVALID` (including missing/unknown options). `analyze --help` retains normal help and exit 0.

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
npx cdn-security readiness --fail-on-weak-waf-baseline
npx cdn-security readiness --json
npx cdn-security readiness --report readiness-report.json
```

Runs a production-oriented release gate over the selected policy. It reuses environment diagnostics and policy validation, then adds production posture checks for risk level, enforce mode, method restrictions, response headers, WAF rate limits, managed-rule coverage, and target-specific unsupported controls.

Exit code is `1` when any finding has severity `fail`. With `--strict`, warning findings also fail the command. Use `--json` for stdout JSON, or `--report <path>` to write the same machine-readable report while keeping the human summary on stdout/stderr.

Use `--fail-on-weak-waf-baseline` for production CI when starter policies should remain usable locally but weak WAF posture must stop a release. The flag promotes WAF baseline findings to `fail`, including missing WAF config, missing rate limits, missing AWS managed-rule signal coverage, and missing CloudFront WAF logging when `firewall.waf.scope: CLOUDFRONT`.

Readiness reports also include read-only `wafRecommendations`. The engine infers `spa-static-site`, `rest-api`, `admin-panel`, or `microservice-origin` posture from the policy and suggests managed WAF rule groups plus related settings with rationale, cost notes, false-positive notes, and AWS/Cloudflare target support. It never mutates the policy; apply recommendations manually in a follow-up change.

`--report` protects the selected input policy by file identity, including relative/absolute aliases, symlinks and hardlinks. Collisions and existing non-regular, symlink or multi-link output files are rejected before writing with exit 1, empty stdout and `[ERROR] READINESS_OUTPUT_PROTECTED`. I/O failures or detected identity/directory changes emit `[ERROR] READINESS_OUTPUT_WRITE_FAILED` with exit 1 and empty stdout, without raw errors or paths. An unrelated regular report can still be overwritten, including outside cwd; its parent directory must already exist.

An absent policy or a directory policy can still produce the usual evaluation failure report at a safe, separate destination. An absent input must remain absent until writing; a newly appearing input is rejected. A missing input reached through an unresolved leaf symlink is rejected because its destination cannot be established safely.

Report writing reuses the contract-diff writer: open without truncation, validate the descriptor and pinned parent, then write. The selected policy remains unchanged on rejection or write failure. This is not a transactional report replacement: a write failure after truncation may leave an unrelated output report empty or partial. No temporary file is used. Keep the writable directories under exclusive control while running: concurrent same-user rename/hardlink operations after the final checks are outside the guarantee. POSIX local filesystem behavior is tested; Windows and network filesystem race behavior are not verified. This protection covers the selected policy file, not an additional audit of its inheritance graph. Evaluation findings, report schema and normal readiness exit criteria are unchanged.

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

Writes starter GitHub Actions workflows. The AWS template builds edge code inside the trusted job but uploads only infra and readiness evidence because AWS edge code can contain baked credentials; deploy the edge code from the same job. The Cloudflare template deploys with a pinned Wrangler version and uploads generated artifacts.

The templates reference GitHub Secrets such as `EDGE_ADMIN_TOKEN`, `BASIC_AUTH_CREDS`, `URL_SIGNING_SECRET`, `JWT_SECRET`, `ORIGIN_SECRET`, `CHALLENGE_SECRET`, `CLOUDFLARE_API_TOKEN`, and `CLOUDFLARE_ACCOUNT_ID`; they never include secret values. For Cloudflare, extend `CDN_SECURITY_WORKER_SECRET_NAMES` when your policy uses additional `*_env` names. Existing files are not overwritten unless `--force` is provided.

Flags:

- `-o, --out-dir <dir>` — workflow output directory (default `.github/workflows`)
- `-t, --target <aws|cloudflare|all>` — which templates to emit (default `all`)
- `-f, --force` — overwrite existing workflow files

Outputs:

- `<out-dir>/cdn-security-aws.yml` when `--target` is `aws` or `all`
- `<out-dir>/cdn-security-cloudflare.yml` when `--target` is `cloudflare` or `all`
- `[SUCCESS] Generated <path>` per written file

Exit code is `0` on success. Invalid `--target`, or an existing target file without `--force`, exits `1`. When overwrite is refused, no partial writes occur.

## `explain`

```bash
npx cdn-security explain
npx cdn-security explain --policy policy/security.yml
```

Prints the policy's schema, mode, allowed methods, request limits, host and route posture, auth gates, WAF settings, and response headers. It is read-only and intended for code review, runbooks, and issue triage.

## `visualize`

```bash
npx cdn-security visualize
npx cdn-security visualize --policy policy/security.yml --target aws
npx cdn-security visualize --policy policy/security.yml --target all --format mermaid
npx cdn-security visualize --policy policy/security.yml --target cloudflare --format html --out policy-coverage.html
```

Generates a deterministic policy control visualization by policy section and control matrix, grouped by policy layer:

- Layer nodes for Edge, WAF, Origin, and Response
- Route coverage and auth gate summaries
- Control coverage status at the selected target(s): enforce / monitor / target-specific / unsupported

`--format mermaid` prints Mermaid flowchart text to stdout, which is CI-friendly because it requires no browser runtime. Use `--format html` to generate a static HTML artifact that renders the same Mermaid diagram when opened in a browser.

Flags:

- `-p, --policy <path>` — policy file (default `policy/security.yml` → `policy/base.yml`)
- `-t, --target <aws|cloudflare|all>` — control behavior scope (default `all`)
- `--format <mermaid|html>` — output format (default `mermaid`)
- `-o, --out <path>` — write rendered output to file instead of stdout

Outputs:

- Without `--out`: prints Mermaid or HTML to stdout
- With `--out`: writes the artifact to the given path and prints `[SUCCESS] Wrote visualization to <path>`

Exit code is `0` on success. Invalid `--target` or `--format`, a missing policy file, or a render error exits `1`.

## `diff`

```bash
npx cdn-security diff
npx cdn-security diff --target cloudflare
npx cdn-security diff --out-dir dist
npx cdn-security diff --semantic --baseline policy/security.previous.yml --policy policy/security.yml --target aws
```

Compiles the selected policy to a temporary directory and compares it with the current output tree. It prints `MISSING`, `EXTRA`, and `CHANGED` entries and exits `1` when generated artifacts are out of date.

With `--semantic`, `diff` compares two policy files and reports posture changes instead of file-level drift. The command is useful for PR review: it can detect removed auth gates, added permissive methods, CSP risk changes, WAF rule changes, and target-specific capability support shifts.

- `--policy` sets the candidate policy path (default: `policy/security.yml` or fallback `policy/base.yml`).
- `--baseline` sets the baseline policy path. If omitted, `policy/base.yml` is used.
- `--target` accepts `aws`, `cloudflare`, or `all` to check target-specific capability support.
- `--json` emits semantic findings as machine-readable JSON.
- `--semantic` switches from drift mode to security-posture mode.

## `migrate`

```bash
./node_modules/.bin/cdn-security migrate --policy policy/security.yml
./node_modules/.bin/cdn-security migrate --policy policy/security.yml --target cloudflare --write
```

Use the executable from the unpublished candidate tarball. Default `--to 2` previews a validated v1→v2 conversion without writing files. `--target aws|cloudflare` is required for provider-sensitive settings; migration does not assume build's AWS default. `--write` saves in place only after validation, requiring an absent `<policy>.v1.bak` sibling that retains the original bytes. Valid same-version input is a read-only noop even with --write.

CLI stdout contains a fixed preview/saved/noop summary. Failure diagnostics are fixed and go to stderr; no policy contents, secret values or unnecessary paths are printed. Exit 0 means success/noop, 1 input/I/O/downgrade error, and 2 unsupported version or explicit human decision required. No difficulty clamping or auth/nonce disabling occurs.

See [schema migration](./schema-migration.md) for exact preservation, save failure, filesystem and rollback boundaries. Published 1.4.0 remains v1; the candidate package version alone does not identify its v2 contract.
