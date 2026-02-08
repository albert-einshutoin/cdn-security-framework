# Policy and Runtime Sync

This document describes how **policy** (`policy/security.yml` or `policy/base.yml`) and **runtimes** (CloudFront Functions, Lambda@Edge, Cloudflare Workers) stay in sync.

---

## Current State

* **Policy** is the single source of truth. You edit YAML to change:
  * Allowed methods, query/URI limits
  * Block rules (path patterns, UA deny list, missing headers)
  * Normalization (e.g. `drop_query_keys`)
  * Routes (e.g. `/admin`, `/docs`) and auth gate
  * Response headers (HSTS, CSP, etc.)

* **CloudFront Functions (viewer-request + viewer-response)** and **Lambda@Edge (origin-request)** are **generated** by the CLI compiler (`npx cdn-security build`) into `dist/edge/*.js`.
* **Cloudflare Workers** is **generated** by the Cloudflare target compiler (`npx cdn-security build --target cloudflare`) into `dist/edge/cloudflare/index.ts`.
* No manual sync of `CFG` or runtime config is required for generated targets.

---

## Workflow When You Change the Policy

1. Edit `policy/security.yml` (or `policy/base.yml`).
2. Build (validates policy and generates Edge code):
   ```bash
   npx cdn-security build
   ```
3. Deploy the generated files in **`dist/edge/`** to your CDN (e.g. Terraform `file("dist/edge/viewer-request.js")`, CDK, or console).
4. Deploy generated files from `dist/edge/` to each runtime target (CloudFront Functions, Lambda@Edge, Cloudflare Workers).

---

## Policy Compiler (Implemented)

The **policy compiler** (CLI: `npx cdn-security build`) does the following:

* Reads `policy/security.yml` or `policy/base.yml` (and optionally a path via `--policy`).
* Validates the policy (lint).
* Generates **Edge Runtime** code for AWS (`dist/edge/*.js`) and Cloudflare (`dist/edge/cloudflare/index.ts`).

The mapping from policy to generated code is implemented in `scripts/compile.js`, `scripts/compile-cloudflare.js`, and templates in `templates/`.

---

## Where to See the Mapping

| Policy concept        | CloudFront Functions     | Lambda@Edge        | Cloudflare Workers   |
| --------------------- | ------------------------ | ------------------- | -------------------- |
| `request.allow_methods` | `CFG.allowMethods`       | Same pattern        | `CFG.allowMethods`   |
| `request.limits`      | `CFG.maxQueryLength` etc.| Same                | Same                 |
| `request.block.*`     | `CFG.blockPathMarks`, `CFG.uaDenyContains` | Same | Same                 |
| `request.normalize.drop_query_keys` | `CFG.dropQueryKeys` | Same                | `CFG.dropQueryKeys`  |
| `routes[].auth_gate`  | `CFG.adminGate`          | JWT / Signed URL gate checks | Static token / Basic / JWT / Signed URL checks |
| `response_headers`    | `viewer-response.js`     | Origin response     | Response header set  |
| `origin.auth`         | —                        | Inject custom header | Inject custom header to upstream fetch |

See also [Architecture](architecture.md), [Decision matrix](decision-matrix.md), and [Observability](observability.md).
