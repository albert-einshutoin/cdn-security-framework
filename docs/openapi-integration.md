# OpenAPI integration

Use the OpenAPI commands to turn an untrusted local OpenAPI 3.0/3.1 document
into review evidence and a non-destructive policy candidate. They help expose
differences between an API declaration and an edge-policy baseline; they do not
prove that the application is secure.

## Scope: four independent truths

| Truth | Evidence | What it does not prove |
| --- | --- | --- |
| Declared API | OpenAPI document | That a route is implemented, reachable, or allowed |
| Implemented API | Source AST | Runtime reachability or unrecognized framework behavior |
| Allowed API | Edge/WAF policy | That an allowed route is declared, implemented, or safe in the application |
| Observed API | Runtime events | That an unobserved route is unused or safe to remove |

This Phase 1 workflow prepares the Declared API and a candidate for the Allowed
API. It does not yet compare them in CI. See
[ADR 0003](adr/0003-security-contract-trust-model.md) for the complete trust
model.

## Ten-minute quickstart

Run these commands from a clone of this repository. For a consuming project,
install with `npm install --save-dev cdn-security-framework` and use the same
`npx cdn-security` commands.

### 1. Install and prepare output directories

```bash
npm ci
mkdir -p reports
```

### 2. Inspect the declared contract

```bash
npx cdn-security openapi inspect \
  --input examples/openapi/openapi.yaml \
  --workspace-root . \
  --json \
  --out reports/openapi-contract.json
```

Read the text form first by omitting `--json` and `--out` if preferred. The
JSON report is deterministic and contains the normalized Security IR,
capabilities, and safe diagnostics.

### 3. Generate a policy candidate

```bash
npx cdn-security openapi generate-policy \
  --input examples/openapi/openapi.yaml \
  --workspace-root . \
  --profile balanced \
  --out policy/openapi.candidate.yml
```

This writes `policy/openapi.candidate.yml` and
`policy/openapi.candidate.meta.json`. It does not read, merge, or overwrite
`policy/security.yml`, and it never applies or deploys a policy. Existing
outputs require `--force`; review their paths before using it.

### 4. Review the candidate and omissions

```bash
git diff --no-index policy/profiles/balanced.yml policy/openapi.candidate.yml
node -e "const m=require('./policy/openapi.candidate.meta.json'); console.log(m.omittedRecommendations)"
```

`git diff --no-index` exits `1` when differences exist; that is expected. Check
every added global method/header and every `omittedRecommendations` entry.
Typical omissions are route-specific matches, authentication, content types,
body limits, and parameter constraints that the current policy schema cannot
represent faithfully.

For this fixture, one reviewed diff is the global method set:

```diff
-  allow_methods: ["GET", "HEAD", "POST"]
+  allow_methods:
+    - GET
+    - POST
```

This shows what changed; it is not automatic approval to adopt the candidate.

### 5. Validate and build locally

```bash
npm run lint:policy -- policy/openapi.candidate.yml
npx cdn-security build \
  --policy policy/openapi.candidate.yml \
  --out-dir dist/openapi-candidate
```

Build only proves that the candidate compiles. The generated files remain
local artifacts and are not deployed.

## Input boundary and resource limits

- `--workspace-root` is the filesystem boundary for the input, local `$ref`
  documents, and output. Use the repository root or a narrower trusted root.
- Relative local `$ref`s are resolved after lexical and real-path containment
  checks. Absolute paths, `file:` URLs, workspace escapes, and symlink escapes
  are rejected.
- Remote `http:` and `https:` references are disabled by default. Enabling
  network resolution during analysis would add SSRF, nondeterminism, mutable
  inputs, credential exposure, and CI availability risks.
- Document bytes, graph bytes, resolved documents, reference/schema depth,
  nodes, operations, parameters, security schemes, YAML aliases, strings, and
  related traversal work have explicit limits. `timeoutMs` is only a deadline
  contract for an external supervisor; it does not interrupt the synchronous
  CLI/loader. Run untrusted analysis under a Worker or child-process supervisor
  that enforces that deadline. See the
  [OpenAPI threat model](openapi-threat-model.md) for current defaults.

Treat OpenAPI and every referenced file as untrusted input. Inspection errors
use stable `OPENAPI_*` codes and do not include raw input, credentials, absolute
paths, request bodies, cookies, or query values.

## Interpret findings and recommendations

`security: []` makes an operation explicitly public. Missing or unsupported
security information is `unknown`, not public. A bearer or OAuth declaration
shows an authentication expectation but cannot safely supply JWT issuer,
audience, JWKS, algorithms, environment variable names, or secrets. Those
values are never inferred into a candidate.

Recommendation estimates mean:

| Kind | Meaning | Candidate treatment |
| --- | --- | --- |
| `exact` | Exact for the analyzed declared inputs | Apply only when the policy mapping is also faithful |
| `upper-bound` | Finite safe bound for the analyzed declared inputs | Apply only when the policy mapping is also faithful |
| `partial` | Some contributing input is not fully bounded | Keep the profile baseline and review manually |
| `unknown` | A safe bound cannot be established | Keep the profile baseline and review manually |

OpenAPI does not prohibit undeclared query parameters, so query and URI limit
recommendations remain omitted even when the declared parameters have an exact
or upper-bound estimate. Multipart upload size in the example is unknown.

Review `capabilityFindings` as target support evidence, not as proof that an
unsupported control is enforced. Review rules and stable IDs are documented in
the [Finding reference](finding-reference.md). Performance envelopes and their
limits are in the [OpenAPI benchmark](benchmarks/openapi-analysis.md).

## Review checklist

- Confirm that each operation intended to be public has explicit `security: []`.
- Treat absent, unresolved, or unsupported authentication as unknown.
- Verify global allowed methods and required headers against every operation.
- Review each omitted recommendation; do not approximate route, auth, body, or
  content-type constraints with a broader policy control.
- Supply JWT and secret settings only from reviewed application/deployment
  configuration.
- Confirm target capability findings before adopting a setting.
- Copy only approved fields into the active policy and review that separate
  change. Never deploy the candidate directly by automation.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| `OPENAPI_REMOTE_REF_DISABLED` | Replace the remote `$ref` with a reviewed local file inside `--workspace-root`. |
| Workspace/path error | Use a relative input/output under the real workspace root; remove absolute, `file:`, traversal, or symlink-escape paths. |
| Resource-limit error | Reduce/split the specification. Raise limits only with benchmark evidence and a trusted input boundary. |
| Output exists | Review both candidate files, then use `--force` only for those regular files. |
| Candidate validation fails | Keep the active policy unchanged and inspect the stable error plus metadata omissions. |
| Auth appears unknown | Add explicit OpenAPI security declarations, but configure JWT/secrets separately; they are intentionally not inferred. |
| Multipart/body limit is unknown | Set a reviewed application/edge limit manually where the selected target supports it. |

## CI adoption

Do not make Phase 1 `inspect` or candidate generation a required drift check.
The Phase 2 `contract diff` command will provide stable comparison rules, exit
codes, exceptions, and reports before CI gating is introduced. Until then,
store review evidence if useful, but keep adoption and deployment manual.

Related references: [policy candidate mapping](openapi-policy-candidates.md),
[threat model](openapi-threat-model.md), [Finding reference](finding-reference.md),
and [benchmark](benchmarks/openapi-analysis.md).
