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

### Changed

- Repository structure in README aligned with actual layout (`base.yml`, `profiles/`, `docs/quickstart.md`, `examples/`).
- Quick Start steps use existing paths: `policy/base.yml`, `policy/profiles/balanced.yml`, deploy via `runtimes/` or `examples/`.
- All runtime code and comments (CloudFront Functions, Lambda@Edge, Cloudflare Workers) use English only.
- Policy `policy/base.yml` comments and `.ja`-only files: Japanese only in `.ja` files; non-`.ja` files and code: English only.

### Fixed

- README no longer references non-existent files (`base.yaml`, `threat-model.md`, `decision-matrix.md`, empty `examples/`).

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
