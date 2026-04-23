# README.md

> **Languages:** English · [日本語](./README.ja.md)

## CDN Security Framework

[![CI](https://github.com/albert-einshutoin/cdn-security-framework/actions/workflows/policy-lint.yml/badge.svg)](https://github.com/albert-einshutoin/cdn-security-framework/actions/workflows/policy-lint.yml)
[![npm release](https://github.com/albert-einshutoin/cdn-security-framework/actions/workflows/release-npm.yml/badge.svg)](https://github.com/albert-einshutoin/cdn-security-framework/actions/workflows/release-npm.yml)
[![coverage ≥ 80%](https://img.shields.io/badge/coverage-%E2%89%A580%25%20lines-brightgreen)](./.github/workflows/policy-lint.yml)
[![SLSA v1 provenance](https://img.shields.io/badge/SLSA-v1%20provenance-blue)](./docs/supply-chain.md)

**CDN Security Framework** is a **security design and implementation framework** that can be used across major CDN edge execution environments such as CloudFront, CloudFront Functions, Lambda@Edge, and Cloudflare Workers.

The goal is simple.

> **"Make CDN security reusable as a design philosophy, so anyone in the world can build a secure initial setup in a short time."**

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
  bin/
    cli.js                 # CLI entry (npx cdn-security)
  docs/
    architecture.md
    quickstart.md
    policy-runtime-sync.md
  policy/
    security.yml / base.yml
    profiles/
  scripts/
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
    infra/                 # Generated when policy has firewall: waf-rules.tf.json (Terraform)
  runtimes/                # Legacy / reference; deploy from dist/edge/
  examples/
```

See [IaC integration](docs/iac.md) for Terraform / CDK / WAF usage.

### Operational docs
- [Archetypes](docs/archetypes.md) — app-shaped policy presets (SPA, REST API, admin, microservice)
- [Secret rotation runbook](docs/runbooks/secret-rotation.md) — JWT / JWKS / signed URL / admin token / origin secret
- [Schema migration](docs/schema-migration.md) — how `policy/schema.json` evolves and the `migrate` CLI
- [Supply chain](docs/supply-chain.md) — SLSA v1 provenance and `npm audit signatures`

---

## Policy and Runtimes

* **Policy** (`policy/security.yml` or `policy/base.yml`) is the **single source of truth**. Edit the policy to change blocking rules, headers, or route protection.
* **Build** runs the CLI compiler: `npx cdn-security build` reads the policy, validates it, and generates **Edge Runtime** code into `dist/edge/*.js`. No manual sync of `CFG` or runtime config.
* See [Policy and runtime sync](docs/policy-runtime-sync.md) for details and IaC usage.

---

## Quick Start (5 minutes)

### 1. Install

```bash
npm install --save-dev cdn-security-framework
```

### 2. Init (scaffold policy)

```bash
npx cdn-security init
```

Answer the prompts. You can start from a **profile** (`strict` / `balanced` / `permissive`) or an **archetype** (`spa-static-site`, `rest-api`, `admin-panel`, `microservice-origin`). This creates `policy/security.yml` and a reference copy under `policy/profiles/` or `policy/archetypes/`.

Or non-interactive: `npx cdn-security init --platform aws --profile balanced --force`
Or with an archetype: `npx cdn-security init --platform aws --archetype rest-api --force`

### 3. Edit and build

Edit `policy/security.yml` as needed, then:

```bash
# AWS (default): generates viewer-request.js, viewer-response.js, origin-request.js
npx cdn-security build

# Cloudflare Workers: generates index.ts for Wrangler
npx cdn-security build --target cloudflare

# AWS + existing Terraform-managed Web ACL:
# generate only rule groups (skip aws_wafv2_web_acl output)
npx cdn-security build --rule-group-only
```

This validates the policy and generates Edge Runtime code into `dist/edge/`.

### 4. Test

```bash
npm run test:runtime
npm run test:unit
npm run test:drift
npm run test:security-baseline
```

Runs runtime, unit, drift, and security-baseline checks used by CI.

### 5. Deploy

Use the generated files in `dist/edge/` with Terraform, CDK, or your CDN console. Set `EDGE_ADMIN_TOKEN` in your environment or secrets for admin routes.

---

## What This Framework Provides

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
* **dist/**: Ignored via `.gitignore`. Users run `npm run build` to generate `dist/edge/` and `dist/infra/`. For CI drift checks, run `npm run build` in CI and compare with policy (do not commit `dist/`).
* **CI workflows**:
  * `.github/workflows/policy-lint.yml`: push/PR quality gate (lint/build/runtime/unit/drift/security-baseline + `npm pack --dry-run`)
  * `.github/workflows/release-npm.yml`: tag-driven publish workflow
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
