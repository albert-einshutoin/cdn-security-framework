## Architecture Overview

The [version roadmap](./ROADMAP.md) is the canonical source for release scope
and capability status.

This framework is designed with a three-layer structure: **"Policy → Compile → Runtime"**.

## Product Boundary and Evidence

The product is an **Application-aware Edge Security Compiler**. It compiles
declared application intent and reviewed policy into provider-specific edge and
WAF artifacts; it does not reimplement CDN/WAF behavior or application
authorization. The operating loop is **Generate → Diff → Review → Apply**.

Four independent truths are kept separate:

| Truth | Evidence | What it can establish |
| --- | --- | --- |
| Declared | OpenAPI | What the contract says is exposed |
| Implemented | Source AST / Source IR | What supported source syntax declares |
| Allowed | Policy and CDN/WAF configuration | What the security policy permits |
| Observed | Runtime evidence | What a deployed system actually emitted or accepted |

No truth is treated as proof of another. Unsupported or partial analysis is
reported as a finding for review rather than filled in by an assumption.

Published: **1.4.0 / Policy schema 1**. The technical baseline checked on 2026-10-26 at main `31975ebcf9862ba040905c1a693fe17714b5a5fd` is **unpublished 2.0.0-rc.0 / Policy schema 2**, with explicit migration. [Candidate evidence](https://github.com/albert-einshutoin/cdn-security-framework/issues/1024). H01 EN/JA is not performed; RC GO and publication remain pending.

### Capability status

| Capability | Status | Interface | Limit |
| --- | --- | --- | --- |
| OpenAPI inspect | Implemented | CLI/API | local refs only |
| OpenAPI policy candidate | Implemented | CLI/API | review-only; never auto-applied |
| OpenAPI↔Policy drift | Implemented | CLI/JSON/SARIF/GHA | no source needed |
| NestJS Source Analyzer core | Experimental/Implemented core | Programmatic | no app execution; metadata is not enforcement proof |
| Source-aware contract diff CLI | Planned v2.1 | — | — |
| Auth/cache model verification (#1119) | Implemented bounded core | Internal harness | model-only; no deployed authentication proof |
| Cloudflare artifact HTTP verification (#1123) | Implemented local MVP | Internal native HTTP harness | bound artifact/runtime; no live Cloud or AWS cache proof |
| Runtime / Deployment Evidence (#534) | Planned beyond the local MVP | — | Phase B; release version not adopted |
| Policy Composition / Regression Guard (#536) | Planned | — | Phase D; release version not adopted |
| LSP/VS Code (#539) | Optional after GA | — | release version not adopted |

The bounded model core and local artifact MVP are internal, unpublished implementations, not a public verifier API or completion of Phases A/B. Deployment verification and provider equivalence remain planned. [#1119](https://github.com/albert-einshutoin/cdn-security-framework/issues/1119) and [#1123](https://github.com/albert-einshutoin/cdn-security-framework/issues/1123) record the accepted limits; [#533 → #534 → #1118 → #536](ROADMAP.md#4-version-release-train) owns product adoption.

Use the [OpenAPI integration guide](openapi-integration.md), [NestJS source
analysis guide](source-analysis-nestjs.md), [CLI reference](cli.md), and
[Programmatic API](programmatic-api.md) for the supported interfaces. The
Source-aware contract diff CLI remains planned for v2.1; the current NestJS
analyzer is programmatic and static only.

---

## Overall Flow

```mermaid
flowchart LR
  U[User]
  CDN[CDN Edge]
  SEC[Edge Security Layer]
  WAF[AWS WAF / CF Security]
  ORI[Origin / App]

  U --> CDN
  CDN --> SEC
  SEC -->|block| U
  SEC -->|allow| WAF
  WAF -->|block| U
  WAF -->|allow| ORI
  ORI --> CDN --> U
```

---

## Layer Responsibilities

### Edge Security Layer

Target:

* CloudFront Functions
* Cloudflare Workers

Responsibilities:

* Coarse inspection of Method / Path / User-Agent
* Query normalization and removal
* Early blocking (403/400)
* Security header injection

Characteristics:

* Ultra-low latency
* Stateless

---

### WAF Layer

Target:

* AWS WAF
* Cloudflare WAF

Responsibilities:

* Rate limiting
* OWASP Managed Rules
* Bot / CAPTCHA
* Body inspection

Characteristics:

* Stateful
* High precision

---

### Origin / Application

Responsibilities:

* Authentication / Authorization
* Business logic
* Data integrity

> Maintain the premise that "even if Edge fails, the App remains the last line of defense"

---

## Policy-Driven Design

```mermaid
flowchart TB
  P["Security Policy (YAML)"] --> C[Compiler]
  C --> CF[CloudFront Functions]
  C --> LAM["Lambda@Edge"]
  C --> CW[Cloudflare Workers]
```

### Role of Policy

* Human-reviewable
* Diffs visible in PRs
* CDN-agnostic

---

## CDN Implementation Mapping

| Concept       | CloudFront Functions | Lambda@Edge     | Cloudflare Workers |
| ------------- | -------------------- | --------------- | ------------------ |
| Entry blocking | Viewer Request       | Origin Request  | fetch()            |
| Header injection | Viewer Response      | Origin Response | Response headers   |
| Advanced validation | Not supported        | Supported       | Supported          |
| State management | Not supported        | Partially       | KV / DO            |

---

## Security Design Principles

1. **Fail Fast** – Block early
2. **Least Privilege** – Deny by default
3. **Defense in Depth** – Edge + WAF + App
4. **Portable Security** – CDN-independent

A planned Security Compiler comparison will evaluate declared, implemented,
allowed, and observed API views without treating any one as globally authoritative. See
[ADR 0003: Security Contract Trust Model](adr/0003-security-contract-trust-model.md).

---

## Common Anti-Patterns

* Relying on Edge alone for all protection
* Overlapping WAF rules and Functions
* Tightening CSP abruptly
* Proliferation of exception rules

---

## Use Cases This Design Fits

* Global distribution
* API + admin UI
* Multi-tenant
* OSS / template distribution

---

## Next Steps

* Organize threats in [threat-model.md](threat-model.md)
* Use [decision-matrix.md](decision-matrix.md) for Edge / WAF decisions
* Keep policy and runtimes in sync: [policy-runtime-sync.md](policy-runtime-sync.md)
* Observability: [observability.md](observability.md) for logging and metrics
* CI quality gate (policy lint + build + runtime + unit + drift + security-baseline): `.github/workflows/policy-lint.yml`

## Saved deployment fixture binding (internal)

`bindHttpArtifactDeployment(snapshot, input)` extends the existing internal
artifact HTTP verifier. `snapshot` must be the frozen object issued by
`captureHttpArtifactSnapshot`; a deserialized copy is rejected. `input` is saved
fixture JSON text or `undefined` when no receipt was collected. The module does
not acquire deployment configuration or contact a provider.

The authoritative input type is `HttpDeploymentFixtureInput` in
`src/contract/verification/artifact-http.ts`. Version 1 has this shape:

```ts
const input: HttpDeploymentFixtureInput = {
  version: 1,
  scope: 'saved-deployment-fixture',
  expected: {
    resourceIdSha256, deploymentVersionSha256,
    referenceTimeMs: 1000, maxAgeMs: 100,
  },
  receipts: [{
    resourceIdSha256, deploymentVersionSha256,
    artifactId: snapshot.artifactId, capturedAtMs: 950,
  }],
};
const binding = bindHttpArtifactDeployment(snapshot, JSON.stringify(input));
```

The two identity variables are lowercase SHA-256 hex strings, not raw resource
IDs. Each receipt identity may explicitly be `null` when uncollected. All v1
fields are required; extra fields and malformed identities are input errors.
No credential, URL, path, query, body, or raw resource identifier belongs here.

Input is limited to 8192 UTF-8 bytes and eight receipts. Times are nonnegative
safe integer milliseconds; `maxAgeMs` is at most 86400000. The freshness window
includes both `referenceTimeMs - maxAgeMs` and `referenceTimeMs`. A future
capture, an exact duplicate receipt, an invalid scope/JSON/type, or an unissued
snapshot throws a fixed `HttpArtifactError` without raw input. An unsupported
positive envelope version returns bounded `unknown` and is not decoded as v1.

| State | Meaning within this saved fixture |
| --- | --- |
| `missing` | Artifact material, a receipt, or a receipt identity is missing. |
| `unknown` | A receipt belongs to another resource, or its envelope version is unsupported. |
| `mixed` | The selected resource has multiple deployment-version/artifact identities. |
| `stale` | A version/artifact differs from the expectation, or a receipt is too old. |
| `current` | Every required identity and time condition matches. |

All applicable fixed reasons are retained. For combined v1 problems the state
priority is missing, unknown, mixed, stale, current. Receipt order and time
metadata changes that preserve every identity and reason do not alter the
semantic digest. Crossing the freshness boundary changes the stale reason and
digest even when the aggregate state remains `stale` or `missing`.
The original input SHA-256, issued snapshot digest, reference/window and capture
times remain separate metadata. Results are recursively frozen.

`current` describes identity/time binding only. It does not return a security
verdict, attest to a real deployment, or establish authentication enforcement.
The existing independent HTTP verifier can still return `VIOLATED` for an
artifact whose saved binding is `current`. Phase B, live readback, canonical
events, readiness, product adoption and publication remain separate work.

Run the repository fixtures with:

```sh
npx --no-install vitest run test/contract/artifact-http.test.ts test/contract/auth-cache.test.ts
```

This entry has no package barrel export, CLI, workflow, legacy adapter, or
automatic application. Reverting this addition removes the fixture binding.

## WAF rule data in Terraform JSON

The WAF-only compiler preserves strings inside generated rules as Cloudflare
data. At the shared output boundary, `${` and `%{` become `$${` and `%%{`, as
specified by [Terraform string escaping](https://developer.hashicorp.com/terraform/language/expressions/strings).
This covers custom/rate expressions and nested block-response content. For
example, the Policy path literal `/${1+1}` is emitted as `/$${1+1}` in Terraform
JSON. Authored `$${` or `%%{` data receives another escape so its literal text is
preserved too. Quotes, backslashes and other characters receive no additional
transformation at this boundary.

Compiler-owned zone/account and Logpush destination bindings retain their
Terraform reference syntax. Rules without template markers keep their existing
output. Free preflight retains its conservative input restrictions below;
unflagged UA Unicode/case-folding and quoting behavior remains a separate
boundary. This encoding does not attest to a Terraform plan/apply, provider
acceptance or live WAF protection.

## Cloudflare Free generation preflight

The WAF-only compiler offers an explicit, local Free preflight:

```sh
node scripts/compile-cloudflare-waf.js --policy policy.yml --out-dir review --cloudflare-free
node scripts/compile-cloudflare-waf.js --policy policy.yml --out-dir review --cloudflare-free --cloudflare-free-inventory saved-inventory.json
```

This invokes the existing WAF compiler and does not add a Worker. The flags opt
into preflight checks; shared rule-literal encoding also applies without them.
The flags belong to this script;
they are not new public `compileArtifacts` options or `cdn-security build` flags.

Checked on 2026-10-26: [Free custom rules](https://developers.cloudflare.com/waf/custom-rules/)
allow five rules across the zone's custom phase, one custom ruleset, and no Regex
or Log action. [Free rate limiting](https://developers.cloudflare.com/waf/rate-limiting-rules/)
allows one rule with a ten-second period and mitigation; the existing rate
validator still enforces its explicit threshold and URI-path expression subset.
[Bot Management fields](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/)
require an Enterprise add-on. [Logpush changed on 2026-09-30](https://developers.cloudflare.com/changelog/post/2026-09-30-logpush-usage-based-pricing/)
to availability on all plans with usage pricing, so this zero-additional-cost
profile rejects Logpush resources even when an account might have included usage.

The local subset accepts the compiler's Geo/ASCII-UA block expressions,
validated Free rate rules and the explicit static profile's literal path,
method and edge-port block shapes. [Cloudflare `lower()`](https://developers.cloudflare.com/ruleset-engine/rules-language/functions/#lower)
folds ASCII only. Non-ASCII UA literals return `unknown` with
`UA_UNICODE_CASE_UNSUPPORTED` and stop Free generation, including literals that
the existing JavaScript generator already lowercased. This profile makes no
Unicode case-folding equivalence claim. The compiler checks the original UA
literal before case conversion, so Unicode-to-ASCII mappings cannot bypass the
restriction. If the existing emitter cannot preserve a literal in canonical
JSON quoting, Free generation stops with `UA_LITERAL_ENCODING_UNSUPPORTED`.
The shared emitted-expression check rejects [Terraform template markers](https://developer.hashicorp.com/terraform/language/syntax/json#expression-mapping)
in both custom and rate rules with `EXPRESSION_TEMPLATE_UNSUPPORTED`, including
direct rate expressions and generated scope-down expressions. These input
restrictions apply to explicit Free mode. All emitted rules use the shared
literal encoding above. The preflight checks whole supported shapes and
counts disabled rules too. Unsupported fields, functions, actions, lists,
managed phases or resources return bounded `unknown` diagnostics and stop WAF
file generation. Known plan violations and capacity excess also stop generation;
`--allow-waf-approximation` cannot bypass this check. Existing output is preserved
on rejection. This checks generated resources, not complete Policy coverage:
Ordinary Worker `request.block.path_patterns` are not translated by this
compiler. The explicit static WAF profile below declares its own literal paths
and reuses `request.allow_methods`; `policyCoverage` still stays `unknown`.

The optional saved inventory is strict JSON, at most 8192 UTF-8 bytes:

```json
{"version":1,"scope":"saved-cloudflare-free-inventory","capturedAtMs":0,"complete":false,"plan":null,"existingCustomRules":null,"existingRateRules":null}
```

This example deliberately declares no account knowledge. Version 1 requires
exactly these fields. Times and known counts are safe nonnegative integers;
counts are at most 10000. `plan` is `free` or null, and either count may be null.
`complete: true` declares collection of the entire selected zone's corresponding
phases; it is not an attestation. Missing/partial/older-than-24-hour inventories,
unknown plan/counts and unsupported versions cannot produce `savedCapacity: fits`.
Future times, invalid types/fields/JSON/UTF-8 and oversized files are fixed input
errors. Raw input and inventory file paths are not echoed in those errors.

The stderr assessment reports generated counts, saved counts/time/input SHA-256,
and fixed reasons. For a complete fresh declared-Free inventory, `savedCapacity`
adds existing and generated counts and reports `fits` or `exceeded`. This is
append arithmetic only: Terraform ownership/import and preservation of existing
zone rules must be reviewed separately. Unknown inventory may still allow local
generation of the supported subset, with `savedCapacity: unknown`.
`liveDeployment` is always `unknown`, including when the saved arithmetic fits.
No account entitlement, API acceptance, actual deployment, protection or safety
is established. No API, credential, apply or automatic security relaxation is
performed. Reproduce with `npm run build:ts` then
`node scripts/cloudflare-waf-parity-unit-tests.js`.


### Free static site without a Worker

The separate `policy/archetypes/cloudflare-free-static-site.yml` is a WAF-only
alternative to the existing Worker-oriented `spa-static-site.yml`, which keeps
its existing Business rate configuration. Review the new file's explicit unused
PHP/WP endpoints before adoption; required PHP or static WP assets are not
blanket-blocked. Use the standalone compiler, not `init --archetype` or a Worker
build target:

```sh
node scripts/compile-cloudflare-waf.js --policy policy/archetypes/cloudflare-free-static-site.yml --cloudflare-free --out-dir review-static
```

The optional `firewall.waf.cloudflare_static_site` contract is defined in
`policy/schema.json`; types are generated from it. It requires explicit
`allow_ports` and literal `block_paths.exact`/`prefix` arrays, with at least one
nonempty. The shared `request.allow_methods` must be explicit and nonempty.
The preset generates four custom block rules (UA plus path/method/port), no rate
rule and no Worker. Existing saved-inventory capacity checks count all of them.
Other Worker/AWS compiler targets reject this profile before writing output.
The Worker/AWS `readiness` targets also return an explicit failure for it.

Path values are lowercase ASCII absolute literals (at most 256 characters),
matched against `lower(http.request.uri.path)`. Exact and prefix have their
literal meanings; there is no regex, query matching or URL-decoding adapter.
Lists contain at most 32 distinct entries and generated expressions at most
4096 ASCII bytes. `block_paths.exceptions` exempts only those exact paths from
the path rule. `method_exceptions` adds explicitly listed methods on each exact
path to the method rule. Path/method exceptions do not exempt edge-port or UA
blocks, and never emit `Skip`. The edge port is
[`cf.edge.server_port`](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.edge.server_port/),
not a Host header port. These fields and the Free custom-rule limits were checked
on 2026-10-27.

Unsupported Worker requirements (including `request.block.path_patterns`,
normalization, routes and response headers), monitor mode, AWS scope, malformed
or unknown fields and unsupported path literals fail before output. The required
`response_headers: {}` is intentional: this WAF-only preset does not generate
response headers; configure them at the origin or through a separately reviewed
Cloudflare mechanism. Free admission is still mandatory and approximation flags
cannot bypass these checks.

The tests compare emitted expressions with a finite, independent requirement
truth table over supplied synthetic Rules-language fields. They reuse selected
HTTP fixture input literals, without interpreting Worker results or inferring a
Cloudflare field from a raw target. This is static subset evidence, not a WAF
runtime. Actual URL-normalization settings, encoded-target mapping, provider
acceptance, existing-zone ownership/order, deployment and port-defense efficacy
remain `unknown`. No Cloud API, entitlement check, apply, production traffic or
claim about security effectiveness is involved.
