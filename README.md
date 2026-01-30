# README.md

## CDN Security Framework

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
    VISION.md
  policy/
    security.yml / base.yml
    profiles/
  scripts/
    compile.js
    policy-lint.js
    runtime-tests.js
  templates/                # Internal: used by build to generate dist/edge/
    aws/
  dist/
    edge/                  # Generated: deploy this (viewer-request.js, viewer-response.js, origin-request.js)
    infra/                 # Generated when policy has firewall: waf-rules.tf.json (Terraform)
  runtimes/                # Legacy / reference; deploy from dist/edge/
  examples/
```

See [IaC integration](docs/iac.md) for Terraform / CDK / WAF usage.

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

Answer the prompts (platform: AWS / Cloudflare, profile: Strict / Balanced / Permissive). This creates `policy/security.yml` and `policy/profiles/<profile>.yml`.

Or non-interactive: `npx cdn-security init --platform aws --profile balanced --force`

### 3. Edit and build

Edit `policy/security.yml` as needed, then:

```bash
npx cdn-security build
```

This validates the policy and generates `dist/edge/viewer-request.js` (and other Edge code).

### 4. Deploy

Use the generated files in `dist/edge/` with Terraform, CDK, or your CDN console. Set `EDGE_ADMIN_TOKEN` in your environment or secrets for admin routes.

---

## What This Framework Provides

* Block unwanted HTTP methods
* Early Path Traversal blocking
* UA / query anomaly detection
* Simple Edge auth for /admin, /docs
* Enforced security headers
* Cache poisoning mitigation
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
* **dist/**: If CI checks "dist drift" (`git diff --exit-code dist/`), run `npm run build` and commit `dist/edge/` (and later `dist/infra/`) so the repo stays in sync.
* **Publish**: From repo root, run `npm publish` (requires npm auth). Prefer publishing from a clean tree with version bumped in `package.json` and an entry in `CHANGELOG.md`. Scoped package (e.g. `@your-org/cdn-security-framework`) requires `--access public` for the first publish.

---

## License

MIT License

---
