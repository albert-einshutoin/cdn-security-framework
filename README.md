# CDN Security Framework

> **Languages:** English · [日本語](./README.ja.md)

[![CI](https://github.com/albert-einshutoin/cdn-security-framework/actions/workflows/policy-lint.yml/badge.svg)](https://github.com/albert-einshutoin/cdn-security-framework/actions/workflows/policy-lint.yml)
[![npm release](https://github.com/albert-einshutoin/cdn-security-framework/actions/workflows/release-npm.yml/badge.svg)](https://github.com/albert-einshutoin/cdn-security-framework/actions/workflows/release-npm.yml)
[![coverage ≥ 80%](https://img.shields.io/badge/coverage-%E2%89%A580%25%20lines-brightgreen)](./.github/workflows/policy-lint.yml)
[![SLSA v1 provenance](https://img.shields.io/badge/SLSA-v1%20provenance-blue)](./docs/supply-chain.md)

See the [version roadmap](./docs/ROADMAP.md) for the current release train,
compatibility gates, and implemented/experimental/planned boundaries.

**CDN Security Framework** is a **security design and implementation framework** that can be used across major CDN edge execution environments such as CloudFront, CloudFront Functions, Lambda@Edge, and Cloudflare Workers.

The goal is simple.

> **"Make CDN security reusable as a design philosophy, so anyone in the world can build a secure initial setup in a short time."**

**First run:** follow the [candidate-tarball Quickstart](docs/quickstart.md) in an empty consumer. Distinguish published1.4.0 from the unpublished schema2 candidate by SHA/digest; preserve existing input.

## Product Surface and Release Status

**CDN Security Framework** is an **Application-aware Edge Security Compiler**.
It turns declared application intent and a reviewed security policy into
provider-specific edge and WAF artifacts. It does not reimplement a CDN, WAF,
bot-management service, or application authorization layer.

The product workflow is **Generate → Diff → Review → Apply**. Findings are
deterministic wherever the input is supported, and an omitted or unsupported
comparison is reported rather than guessed. OpenAPI, source analysis, policy,
and runtime evidence are separate truths; none is proof of the others.

Published: 1.4.0. On 2026-09-22 main implements and validates schema2 and explicit migration; 2.0.0 remains unpublished and before RC GO. [Evidence](https://github.com/albert-einshutoin/cdn-security-framework/issues/1023#issuecomment-5764409249).

### Capability status

| Capability | Status | Interface | Limit |
| --- | --- | --- | --- |
| OpenAPI inspect | Implemented | CLI/API | local refs only |
| OpenAPI policy candidate | Implemented | CLI/API | review-only; never auto-applied |
| OpenAPI↔Policy drift | Implemented | CLI/JSON/SARIF/GHA | no source needed |
| NestJS Source Analyzer core | Experimental/Implemented core | Programmatic | no app execution; metadata is not enforcement proof |
| Source-aware contract diff CLI | Planned v2.1 | — | — |
| Runtime Evidence v1 | Planned v2.3 | — | — |
| Policy Composition | Planned v2.4 | — | — |
| LSP/VS Code | Planned v3.1 | — | — |

For the runnable paths, see the [OpenAPI integration guide](docs/openapi-integration.md),
[NestJS source analysis guide](docs/source-analysis-nestjs.md),
[CLI reference](docs/cli.md), and [Programmatic API](docs/programmatic-api.md).
The [version roadmap](docs/ROADMAP.md) is the release-status source of truth.

The framework does not claim that a generated artifact is fully secure, that a
Guard or analyzer result proves runtime enforcement, or that an unsupported
provider control is available. Review generated candidates and provider
capability findings before applying them.

---

## Why This Framework Is Needed

Many CDN security setups suffer from issues such as:

* **Repeatedly hand-writing similar Edge rules** for each project
* **Fragmented design** across CloudFront vs Cloudflare
* Unclear **separation of responsibilities between WAF and Edge Functions**
* **Inconsistent initial security quality** depending on who implements it

This framework addresses these with **"policy-driven" + "runtime separation"**.

---

## Design Philosophy (Important)

### 1. Edge Is the "Front Line—Don't Let Attacks In"

* **Reduce the attack surface** before traffic reaches Origin or the app
* **Block obvious anomalies immediately**
* **Prevent accidents** through normalization and removal of unnecessary elements

### 2. Rules Are Written Declaratively (Policy)

* Do not edit CDN-specific code directly
* First write **human-readable policy**
* Then compile it into each CDN runtime

### 3. No Overlap with WAF

* **Functions / Workers**
  * Normalization, lightweight blocking, header injection
* **WAF**
  * Rate limiting, OWASP, Bot, CAPTCHA

> Edge Functions are the "upstream filter"; WAF is the "main defense"

---

## Supported CDN / Edge Runtimes

| Platform             | Support                          |
| -------------------- | -------------------------------- |
| AWS CloudFront       | Behavior / Policy design         |
| CloudFront Functions | Viewer Request / Response        |
| AWS Lambda@Edge      | Origin Request / Response       |
| Cloudflare           | CDN / Security Rules             |
| Cloudflare Workers   | Fetch Handler                    |

---

## Repository Structure

```
  README.md
  src/
    bin/cli.ts             # TypeScript source for the CLI
    scripts/               # TypeScript source for compilers, tests, and tools
    lib/                   # TypeScript source for public library APIs
  bin/                    # Generated package artifacts; do not edit or commit
    cli.js                 # Generated CLI entry (npx cdn-security)
  docs/
    architecture.md
    quickstart.md
    policy-runtime-sync.md
  policy/
    security.yml / base.yml
    profiles/
  scripts/                # Generated from src/scripts/*.ts; do not edit or commit
    compile.js
    compile-cloudflare.js
    compile-infra.js
    policy-lint.js
    runtime-tests.js
    cloudflare-runtime-tests.js
    compile-unit-tests.js
    infra-unit-tests.js
    check-drift.js
  templates/                # Internal: used by build to generate dist/edge/
    aws/
  dist/
    edge/                  # Generated: deploy this (viewer-request.js, viewer-response.js, origin-request.js)
    infra/                 # Generated WAF IaC: Terraform JSON and optional CloudFormation
  runtimes/                # Legacy / reference; deploy from dist/edge/
  examples/
```

The authoritative source for package code lives under `src/**/*.ts`. `npm run build:ts` generates the root-level JavaScript and `.d.ts` package artifacts during CI and npm packaging; they are not source files to edit or commit. Runtime templates under `templates/` are hand-written and generate deployable `dist/edge/` output.

See [IaC integration](docs/iac.md) for Terraform / CloudFormation / CDK / WAF usage.

### Operational docs
- [Quick start](docs/quickstart.md) — install, policy build, contract review, and deployment boundary
- [OpenAPI integration](docs/openapi-integration.md) — inspect an API contract, generate a review-only policy candidate, and understand safety limits
- [NestJS source analysis](docs/source-analysis-nestjs.md) — experimental programmatic source metadata with an explicit no-execution boundary
- [CLI reference](docs/cli.md) — `init` / `build` / `emit-waf` / `doctor` / `readiness` / `capabilities` / `explain` / `diff` / `migrate`
- [Programmatic API](docs/programmatic-api.md) — `require('cdn-security-framework')` for CI / IaC integration
- [Package/API manifest](docs/api-manifest.json) — machine-readable entrypoint, schema, bin, and package-file contract
- [Compiler strictness](docs/compiler-strictness.md) — phase contracts, strict checks, and remaining dynamic areas
- [Archetypes](docs/archetypes.md) — app-shaped policy presets (SPA, REST API, admin, microservice)
- [Policy recipes](docs/recipes.md) — copyable snippets for Cognito APIs, SPAs, admin panels, signed downloads, and Cloudflare GraphQL
- [Response DLP](docs/response-dlp.md) — Cloudflare Workers response masking/blocking for high-confidence data leaks
- [Secret rotation runbook](docs/runbooks/secret-rotation.md) — JWT / JWKS / signed URL / admin token / origin secret
- [Schema migration](docs/schema-migration.md) — how `policy/schema.json` evolves and the `migrate` CLI
- [Supply chain](docs/supply-chain.md) — SLSA v1 provenance and `npm audit signatures`
- [Template injection contract](docs/template-injection-contract.md) — marker-safe, parse-checked runtime config injection
- [Test strategy](docs/test-strategy.md) — Vitest migration policy and release-gate test workflow
- [Selective CI testing](docs/selective-testing.md) — change-impact analysis, safe fallback, and shadow comparison operations
- [ADR 0001: Plugin-safe emitter path](docs/adr/0001-plugin-safe-emitter-path.md) — bundler-backed prototype and migration criteria

- [Origin authentication](docs/origin-auth.md)
- [Signed URLs (Cloudflare)](docs/signed-urls.md)
- [Threat model](docs/threat-model.md)
- [Decision matrix](docs/decision-matrix.md)
- [Observability](docs/observability.md)
- [Changelog](CHANGELOG.md)

---

## Policy and Runtimes

* **Policy** (`policy/security.yml` or `policy/base.yml`) is the **single source of truth**. Edit the policy to change blocking rules, headers, or route protection.
* **Build** runs the CLI compiler: `./node_modules/.bin/cdn-security build` reads the policy, validates it, and generates **Edge Runtime** code into `dist/edge/*.js`. No manual sync of `CFG` or runtime config.
* See [Policy and runtime sync](docs/policy-runtime-sync.md) for details and IaC usage.

---

## Quick Start

Follow the [complete commands, fixtures and expected results](docs/quickstart.md), verifying the supplied candidate tarball SHA/digest. Unpublished-candidate installation differs from future published2.0.0 installation.

```bash
# Set this to the verified tarball supplied with the candidate SHA and SHA-256.
export CANDIDATE_TARBALL=/path/to/verified-candidate.tgz
shasum -a 256 "$CANDIDATE_TARBALL"
mkdir consumer
cd consumer
npm init -y
npm install --save-dev "$CANDIDATE_TARBALL"
./node_modules/.bin/cdn-security --help
```

### Init, lint and build

```bash
./node_modules/.bin/cdn-security init --platform aws --profile balanced
export EDGE_ADMIN_TOKEN=docs-fixture-token-not-for-deploy
node node_modules/cdn-security-framework/scripts/policy-lint.js policy/security.yml
./node_modules/.bin/cdn-security build --policy policy/security.yml --target aws --out-dir dist/aws
```

The Quickstart also covers Cloudflare JWT `init --guided`, playground authentication fixtures and POST JSON, OpenAPI inspect→review-only candidate→contract diff, and migration preview/save/backup/rollback. JWT/signed_url are not AWS success examples.

### 5. Deploy boundary

With the example’s `--out-dir dist/aws`, runtime code is in `dist/aws/edge/` and IaC fragments are in `dist/aws/infra/`. Without that option the defaults are `dist/edge/` and `dist/infra/`. Review the [IaC guide](docs/iac.md) before handing them to your Terraform/CDK/CDN workflow. Build does not deploy. Never deploy synthetic-token/placeholder artifacts; production needs a separately reviewed build with production secrets.

## Product Core and Generated Security Controls

### Product core

* Reviewable policy and schema validation
* OpenAPI inspection, review-only policy candidates, and OpenAPI↔Policy drift findings
* Programmatic API for CI / IaC integration
* Deterministic provider capability diagnostics and generated artifact diffs

### Generated security controls (maintenance surface)

* Block unwanted HTTP methods
* Early Path Traversal blocking
* UA / query anomaly detection
* Auth gates: static token, Basic auth, JWT (RS256/HS256), Signed URL
* Enforced security headers (HSTS, CSP, Referrer-Policy, Permissions-Policy)
* CORS and Cookie attribute management
* Cache poisoning mitigation
* Monitor mode for non-blocking observation
* Design that does not conflict with WAF

---

## What It Does Not Do (By Design)

* Advanced bot behavior analysis (WAF / Bot Management responsibility)
* Internal DB abuse
* Business logic tampering

---

## Target Use Cases

* Initial security for new Web / API services
* Global services using multiple CDNs
* OSS / SaaS "secure template" offerings
* Standardizing in-house security baselines

---

## For maintainers (publishing to npm)

* **package-lock.json**: Commit it so CI can run `npm ci`.
* **dist/**: Ignored via `.gitignore`. Consumers run `./node_modules/.bin/cdn-security build` to generate `dist/edge/` and `dist/infra/`. For CI drift checks, run `npm run build` in CI and compare with policy (do not commit `dist/`).
* **CI workflows**:
  * `.github/workflows/policy-lint.yml`: selective PR validation with required shadow comparison; exhaustive validation on `main`, `release/**`, manual, and daily runs
  * `.github/workflows/release-npm.yml`: tag-driven publish workflow
  * [Release compatibility matrix](docs/release-matrix.md): Node 20.17.0 / 22 / 24 evidence and cross-version digest comparison
  * [Deterministic output audit](docs/determinism-audit.md): repeated contract/report/golden checks and privacy boundary
* **Release by tag**:
  1. Bump `package.json` version (example: `1.0.1`)
  2. Commit and push to `main`
  3. Create and push tag `v1.0.1`
  4. GitHub Actions runs release checks, then publishes to npm if all checks pass
* **npm auth for release**:
  * Preferred: npm Trusted Publishing (OIDC) with `npm publish --provenance`
  * Fallback: set repository secret `NPM_TOKEN` and workflow uses token publish

---

## License

MIT License

---
