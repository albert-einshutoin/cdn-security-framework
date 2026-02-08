# DOs and DON'Ts

A concise list of what you **should do** and what you **should not do** when using this framework.

---

## DOs

### Workflow

| Do | Why |
|----|-----|
| **Edit only the policy** | `policy/security.yml` (or `policy/base.yml`) is the single source of truth. Change it and rebuild. |
| **Build after changes** | Run `npx cdn-security build` or `npm run build` after editing the policy so `dist/edge/` and `dist/infra/` are regenerated. |
| **Start with init** | Use `npx cdn-security init` to choose platform and profile and generate a policy scaffold. |
| **Validate the policy** | Run `npm run lint:policy` after edits; use it in CI as well. |
| **Test after build** | Run `npm run build && npm run test:runtime && npm run test:unit && npm run test:drift && npm run test:security-baseline` to verify generated code and CI guardrails. |
| **Set token in deployment** | Configure `EDGE_ADMIN_TOKEN` as a secret in Terraform, Wrangler, etc., for protected paths like `/admin`. |
| **Deploy generated artifacts** | Use `dist/edge/` for CloudFront Functions / Lambda@Edge / Workers, and `dist/infra/*.tf.json` with Terraform. |

### Design

| Do | Why |
|----|-----|
| **Keep Edge as “front filter”** | Edge does light normalization, blocking, and headers; leave rate limiting, OWASP, and bot handling to WAF. |
| **Address compliance in other layers** | Audit logs, data protection, and industry regulations (e.g. finance, HR) are handled in app, WAF, and logging. |
| **Regenerate dist/ in CI for drift checks** | If you need to detect drift between policy and output, run `npm run build` in CI and diff; do not commit `dist/`. |

---

## DON'Ts

### Editing

| Don't | Why |
|-------|-----|
| **Edit dist/edge/*.js or dist/edge/cloudflare/index.ts by hand** | They are overwritten on build. Put changes in the policy and rebuild. |
| **Modify templates/ as a user** | Templates are internal CLI assets. Customize via fork or PR. |
| **Manually sync CFG or runtime config** | Injected from the policy; no manual sync needed. |
| **Commit dist/** | It is gitignored; everyone generates it with `npm run build`. |

### Scope

| Don't expect the framework to | Why |
|------------------------------|-----|
| **Do advanced bot detection at Edge** | Bot management and rate limiting belong to WAF / CDN. |
| **Prevent DB abuse or business-logic attacks** | That is the application layer. |
| **Satisfy audit/compliance by itself** | Design audit and compliance in separate systems. |
| **Ship industry-specific templates** | Use Strict / Balanced / Permissive and tune policy per organization. |

---

## Summary

- **DO**: Edit policy → build → lint/test → deploy generated artifacts; keep Edge as the front filter and handle business/compliance elsewhere.
- **DON'T**: Hand-edit generated code or templates, commit dist/, or expect this tool to cover bots, DB, or audit by itself.

---

## Gap status

As of **2026-02-08**, the implementation gaps previously listed here are closed:

- Cloudflare Workers now supports JWT / Signed URL / Origin auth gates generated from policy.
- Default CI includes drift check against committed golden generated artifacts.
- Compiler test suite includes unit tests for compile core and infra compiler outputs.
- JA3/JA4 fingerprint rules can be generated via `firewall.waf.ja3_fingerprints` / `firewall.waf.ja4_fingerprints` (use `fingerprint_action: count` first).

Industry templates, audit, and compliance are intentionally out of scope (“DON’T”), not implementation gaps.
