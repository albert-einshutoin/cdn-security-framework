# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once versioned.

---

## [Unreleased]

## [1.1.0] - 2026-04-23

### Security / Breaking

- `request.block.path_patterns` is now typed: pass either an array of literal substrings (legacy) or an object with `contains:` and `regex:` keys. Ambiguous regex-like array entries fail the build instead of being silently downgraded to substring matches. Affected the `strict` profile (migrated to the object form).
- `static_token` and `basic_auth` gates now require their env vars at build time. The silent `BUILD_TIME_INJECTION` fallback is removed; missing env fails the build unless `--allow-placeholder-token` is passed, in which case the visible placeholder `INSECURE_PLACEHOLDER__REBUILD_WITH_REAL_TOKEN` is embedded and a warning is logged.
- CloudFront Functions and Cloudflare Workers now compare `static_token` / `basic_auth` credentials with a constant-time equality helper to mitigate timing side-channels.
- Removed the legacy `CFG.adminGate` double-evaluation path. Auth is driven exclusively by `CFG.authGates`.
- `policy-lint` now validates policies against `policy/schema.json` via ajv, in addition to the existing cross-field auth-gate checks.
- **Edge-auth marker spoofing**: both the AWS CloudFront Functions handler and the Cloudflare Workers handler now strip any client-supplied `x-edge-authenticated` header at request entry / before forwarding to origin. Previously a client could set this header on an unauthenticated request and trick downstream code into trusting it.
- **`path_patterns.contains` case-normalization**: `contains` entries are lowercased at compile time. The runtime lowercases the URI before calling `includes()`, so uppercase policy entries like `%2E%2E` used to silently never match. This is the same silent-downgrade class as the regex reject; now both forms are normalized.
- **`auth_gate.header` case-normalization**: CloudFront Functions expose header keys in lowercase only, so the compiled `tokenHeaderName` is forced to lowercase. Policies that set `header: X-Edge-Token` previously caused every authenticated lookup to return `undefined` and reject valid requests.
- **JWT alg-confusion attack**: `verifyJwtRS256` / `verifyJwtHS256` (AWS) and `verifyJwt` (Cloudflare) now validate `header.alg` against a per-gate whitelist before running any signature math. Tokens carrying `alg=none` are always rejected, and by default a gate accepts only its configured `algorithm`. `auth_gate.allowed_algorithms: [...]` is accepted only when every entry matches the verifier selected by `auth_gate.algorithm`; cross-alg entries (e.g. `algorithm: RS256` + `allowed_algorithms: ["HS256"]`) are rejected at build time with an explicit error rather than silently routing tokens through the wrong verifier and locking every caller out. Previously a forged `alg=none` or `alg` substitution (e.g., RS256 → HS256 using the public JWKS key as an HMAC secret) could bypass signature verification.
- **JWT clock skew**: `exp` and `nbf` checks now honor a configurable tolerance `auth_gate.clock_skew_sec` (default 30s, clamped 0..600). Previously a client and edge disagreeing by a few seconds could cause valid tokens to be rejected at the exact expiry boundary.
- **X-Forwarded-For spoofing**: CloudFront Functions, Lambda@Edge origin-request, and Cloudflare Workers now strip any client-supplied `x-forwarded-for` header by default. The real client IP is available from CDN-provided headers (`cloudfront-viewer-address`, `cf-connecting-ip`); trusting an incoming XFF value could poison downstream rate limiters, IP-based allowlists, and audit logs. Users who terminate TLS behind a trusted upstream proxy can opt back in with `request.trust_forwarded_for: true`.
- **Host header allowlist (optional)**: `request.allowed_hosts: [...]` lets policies enforce a Host allowlist at the edge. Entries support exact match and `*.example.com` wildcard prefix, are case-insensitive, and ignore port suffixes. When unset, Host is not checked at the edge (behavior unchanged).

### Added

- Threat model (`docs/threat-model.md`) and decision matrix (`docs/decision-matrix.md`) for Edge vs WAF.
- Policy profile `policy/profiles/balanced.yml`; Quick Start uses `cp policy/profiles/balanced.yml policy/base.yml`.
- Deploy examples: `examples/aws-cloudfront/`, `examples/cloudflare/` with README (EN + JA).
- CONTRIBUTING.md, CODE_OF_CONDUCT.md, and `.github` issue/PR templates.
- OSS readiness audit: `docs/OSS-READINESS-AUDIT.ja.md` (Japanese).
- Lambda@Edge origin-request runtime support for JWT auth gates (RS256/HS256), Signed URL validation, and origin auth injection.
- Compiler unit tests for `scripts/compile.js` core logic (`parsePathPatterns`, `regexesLiteralCode`, `getAuthGates`, `validateAuthGates`).
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

[Unreleased]: https://github.com/albert-einshutoin/cdn-security-framework/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/albert-einshutoin/cdn-security-framework/compare/v1.0.0...v1.1.0
[0.1.0]: https://github.com/albert-einshutoin/cdn-security-framework/releases/tag/v0.1.0
