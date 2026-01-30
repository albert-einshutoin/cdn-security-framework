# OSS / Public Repository Readiness – Audit Summary

This document summarizes gaps and documentation status for offering this framework as OSS and a public repository.

---

## 1. README vs Actual Repo (Resolved)

The following were missing or inconsistent; they are now addressed:

| Item | Status |
|------|--------|
| `docs/threat-model.md` | Created (EN + JA) |
| `docs/decision-matrix.md` | Created (EN + JA) |
| `policy/base.yml` | Exists; README uses `base.yml` (not `base.yaml`) |
| `policy/profiles/` and `balanced.yml` | Created |
| `examples/aws-cloudfront/`, `examples/cloudflare/` | Created with README (EN + JA) |

Quick Start now uses: `cp policy/profiles/balanced.yml policy/base.yml` and deploy via `runtimes/` or `examples/`.

---

## 2. Documentation

- **Present**: README (EN/JA), architecture, quickstart, threat-model, decision-matrix (EN/JA), SECURITY (EN/JA), LICENSE, per-runtime READMEs (EN/JA).
- **Language**: Non–`.ja` files and all code comments are **English only**. `.ja` files contain **Japanese only** for user-facing text.

---

## 3. OSS Conventions Added

| Item | Status |
|------|--------|
| CONTRIBUTING.md / CONTRIBUTING.ja.md | Created |
| CHANGELOG.md / CHANGELOG.ja.md | Created |
| CODE_OF_CONDUCT.md / CODE_OF_CONDUCT.ja.md | Created |
| .github/ISSUE_TEMPLATE (bug_report, feature_request, config) | Created |
| .github/PULL_REQUEST_TEMPLATE.md | Created |

---

## 4. Policy vs Runtimes

- **Policy**: `policy/security.yml` (or `policy/base.yml`) and `policy/profiles/` exist; human-readable, CDN-agnostic.
- **Compiler**: **Implemented**. The CLI (`npx cdn-security build`) reads the policy, validates it, and generates Edge Runtime code into `dist/edge/*.js` (e.g. CloudFront Functions viewer-request). No manual sync of CFG; Lambda@Edge and Cloudflare Workers codegen are planned for later.

---

## 5. Optional Next Steps

- CI is in place (policy lint, build, dist drift check, runtime tests).
- Policy compiler is implemented (init + build); extend to viewer-response, Lambda@Edge, Cloudflare, and `dist/infra/*.tf.json` (WAF) as needed.
- Version the project (e.g. tag v0.1.0) and keep CHANGELOG updated. Document npm publish steps (see README "For maintainers").

---

For the full Japanese audit (original findings and detailed recommendations), see [OSS-READINESS-AUDIT.ja.md](OSS-READINESS-AUDIT.ja.md).
