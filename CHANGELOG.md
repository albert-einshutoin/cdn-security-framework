# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once versioned.

---

## [Unreleased]

### Added

- Threat model (`docs/threat-model.md`) and decision matrix (`docs/decision-matrix.md`) for Edge vs WAF.
- Policy profile `policy/profiles/balanced.yml`; Quick Start uses `cp policy/profiles/balanced.yml policy/base.yml`.
- Deploy examples: `examples/aws-cloudfront/`, `examples/cloudflare/` with README (EN + JA).
- CONTRIBUTING.md, CODE_OF_CONDUCT.md, and `.github` issue/PR templates.
- OSS readiness audit: `docs/OSS-READINESS-AUDIT.ja.md` (Japanese).
- Lambda@Edge origin-request runtime support for JWT auth gates (RS256/HS256), Signed URL validation, and origin auth injection.
- Compiler unit tests for `scripts/compile.js` core logic (`pathPatternsToMarks`, `getAuthGates`, `getAdminGate`, `validateAuthGates`).
- Cloudflare Workers auth/runtime support for JWT (`HS256`/`RS256`), Signed URL, and origin custom-header auth generated from policy.
- Drift check with committed golden generated artifacts (`tests/golden/base/*`) and CI integration (`npm run test:drift`).
- Infra compiler support for JA3 fingerprint WAF block rules via `firewall.waf.ja3_fingerprints`.
- Infra compiler support for JA4 fingerprint rules and staged rollout mode via `firewall.waf.ja4_fingerprints` + `firewall.waf.fingerprint_action` (`count`/`block`).
- Fingerprint candidate extraction helper: `scripts/fingerprint-candidates.js` (WAF JSONL → JA3/JA4 candidates).
- Security baseline guardrail check: `scripts/security-baseline-check.js` + CI integration (`npm run test:security-baseline`).

### Changed

- Repository structure in README aligned with actual layout (`base.yml`, `profiles/`, `docs/quickstart.md`, `examples/`).
- Quick Start steps use existing paths: `policy/base.yml`, `policy/profiles/balanced.yml`, deploy via `runtimes/` or `examples/`.
- All runtime code and comments (CloudFront Functions, Lambda@Edge, Cloudflare Workers) use English only.
- Policy `policy/base.yml` comments and `.ja`-only files: Japanese only in `.ja` files; non-`.ja` files and code: English only.
- CI quality gate now includes compiler unit tests in addition to policy lint, build, and runtime tests.
- Runtime tests now include Cloudflare target checks; CI gate includes runtime + unit + drift checks.

### Fixed

- README no longer references non-existent files (`base.yaml`, `threat-model.md`, `decision-matrix.md`, empty `examples/`).
- `package.json` repository metadata (`repository`, `homepage`, `bugs`) now points to the actual GitHub repository.

---

## [0.1.0] – Initial (template)

- CloudFront Functions: Viewer Request / Viewer Response.
- Lambda@Edge: Origin Request (template; JWT/signing TODO).
- Cloudflare Workers: fetch handler with entry blocking, normalization, headers.
- Policy: `policy/base.yml` (human-readable; runtimes are hand-synced until compiler exists).
- Docs: README, architecture, quick start (EN + JA); SECURITY (EN + JA).

---

[Unreleased]: https://github.com/YOUR_ORG/YOUR_REPO/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/YOUR_ORG/YOUR_REPO/releases/tag/v0.1.0
