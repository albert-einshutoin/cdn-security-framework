# Policy and Runtime Sync

This document describes how **policy** (`policy/base.yml` and `policy/profiles/*.yml`) and **runtimes** (CloudFront Functions, Lambda@Edge, Cloudflare Workers) stay in sync today, and the planned direction.

---

## Current State

* **Policy** is the human-readable source of truth. You edit YAML to change:
  * Allowed methods, query/URI limits
  * Block rules (path patterns, UA deny list, missing headers)
  * Normalization (e.g. `drop_query_keys`)
  * Routes (e.g. `/admin`, `/docs`) and auth gate
  * Response headers (HSTS, CSP, etc.)

* **Runtimes** do **not** read the policy file. Each runtime has its own in-code config (e.g. `CFG` in `viewer-request.js`, `env` in Workers). When you change the policy, you must **manually update** each runtime so its behavior matches the policy.

---

## Workflow When You Change the Policy

1. Edit `policy/base.yml` (or the profile you use).
2. Run policy lint (optional but recommended):
   ```bash
   node scripts/policy-lint.js policy/base.yml
   ```
3. Update each runtime that you use:
   * **CloudFront Functions**: `runtimes/aws-cloudfront-functions/viewer-request.js` and `viewer-response.js` — align `CFG` and header logic with the policy.
   * **Lambda@Edge**: `runtimes/aws-lambda-edge/origin-request.js` (and response if used) — same.
   * **Cloudflare Workers**: `runtimes/cloudflare-workers/src/index.ts` — align config and header logic with the policy.
4. Run runtime tests if available (e.g. `npm test` in the runtime or `scripts/`).
5. Deploy the updated runtime to your CDN.

---

## Future Direction: Policy Compiler

A **policy compiler** is planned. It would:

* Read `policy/base.yml` (and optionally profile overrides).
* Generate or validate runtime code for each target (CloudFront Functions, Lambda@Edge, Cloudflare Workers).

Until the compiler exists, the project keeps policy and runtimes **manually aligned** and documents the mapping in the runtime READMEs and in this doc.

---

## Where to See the Mapping

| Policy concept        | CloudFront Functions     | Lambda@Edge        | Cloudflare Workers   |
| --------------------- | ------------------------ | ------------------- | -------------------- |
| `request.allow_methods` | `CFG.allowMethods`       | Same pattern        | `CFG.allowMethods`   |
| `request.limits`      | `CFG.maxQueryLength` etc.| Same                | Same                 |
| `request.block.*`     | `CFG.blockPathMarks`, `CFG.uaDenyContains` | Same | Same                 |
| `request.normalize.drop_query_keys` | `CFG.dropQueryKeys` | Same                | `CFG.dropQueryKeys`  |
| `routes[].auth_gate`  | `CFG.adminGate`          | Same                | `env.EDGE_ADMIN_TOKEN` + prefixes |
| `response_headers`    | `viewer-response.js`     | Origin response     | Response header set  |

See also [Architecture](architecture.md), [Decision matrix](decision-matrix.md), and [Observability](observability.md).
