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
  docs/
    architecture.md
    quickstart.md
    threat-model.md
    decision-matrix.md
    policy-runtime-sync.md
    observability.md
  policy/
    base.yml
    README.md
    profiles/
      balanced.yml
      strict.yml
      permissive.yml
  scripts/
    policy-lint.js
    runtime-tests.js
  runtimes/
    aws-cloudfront-functions/
    aws-lambda-edge/
    cloudflare-workers/
  examples/
    aws-cloudfront/
    cloudflare/
```

---

## Policy and Runtimes (Current State)

* **Policy** (`policy/base.yml` and `policy/profiles/*.yml`) is the **source of truth** for security rules. Edit the policy to change blocking rules, headers, or route protection.
* **Runtimes** (CloudFront Functions, Lambda@Edge, Cloudflare Workers) do **not** read the policy file today. Their config is in-code. When you change the policy, you must **manually update** each runtime's config (e.g. `CFG` in `viewer-request.js`) so it matches the policy.
* A **policy compiler** (policy → generated runtime code) is **planned** but not yet implemented. Until then, keep policy and runtimes in sync by hand when you change rules. See [Policy and runtime sync](docs/policy-runtime-sync.md) for the workflow and future direction.

---

## Quick Start (5 minutes)

### 1. Choose a policy profile

Pick a profile from `policy/profiles/` (e.g. `balanced`, `strict`, `permissive`) and copy it to `base.yml`. See [Policy profiles](policy/README.md) for how to choose.

```bash
cp policy/profiles/balanced.yml policy/base.yml
```

### 2. Set admin token for admin UI

```bash
export EDGE_ADMIN_TOKEN=your-secret-token
```

### 3. Deploy runtime per CDN

* AWS: `examples/aws-cloudfront/` or `runtimes/aws-cloudfront-functions/`
* Cloudflare: `examples/cloudflare/` or `runtimes/cloudflare-workers/`

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

## License

MIT License

---
