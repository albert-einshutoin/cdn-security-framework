# Roadmap

This document tracks post-Phase-3 work as explicit follow-up tracks.

---

## Track A: Cloudflare Workers JWT / Signed URL / Origin Auth

Status: Completed (2026-02-08)
Priority: Medium

Implemented:

- `npx cdn-security build --target cloudflare` now injects JWT / Signed URL / Origin auth configuration.
- Worker template enforces JWT (`HS256` / `RS256`), Signed URL, and origin custom header auth.
- Runtime test suite now includes Cloudflare auth behavior checks.
- Security matrix and DOs/DON'Ts documentation updated to reflect support.

---

## Track B: Compiler test depth

Status: Completed (2026-02-08)
Priority: High

Implemented:

- Core compiler unit tests for auth/path logic.
- Output-generation unit checks for `build()` artifacts.
- Infra compiler unit tests including JA3 WAF rule generation.
- CI drift check against committed golden generated artifacts.

---

## Track C: Issue-to-docs alignment

Status: Completed (2026-06-11)
Priority: Medium

Implementation status reconciliation:

- #128 was implemented as local runtime playground simulation and now has dedicated docs and tests in `docs` + CLI behavior.
- #103 and #105 are documented as implemented features in `docs/SECURITY-FEATURE-MATRIX.md` with explicit runtime scope and unsupported-target warnings.
- Closing these issues keeps issue tracker aligned with shipped behavior and avoids duplicated triage.

---

## Track D: Operational hardening and observability (Ongoing)

Status: Ongoing (2026-06-11)
Priority: High

Planned work in progress:

- Improve monitor-mode signal quality and visibility (`cdn-security capabilities` + operational docs).
- Add clearer guidance for policy rollout telemetry and false-positive triage.
- Expand end-to-end runbooks for multi-service deployments.

---

## Track E: Multi-CDN parity (Ongoing)

Status: Ongoing (2026-06-11)
Priority: Medium

Planned work in progress:

- Track behavior gaps across Cloudflare / AWS compilers and normalize warning semantics.
- Add parity-focused validation for unsupported targets and target-specific fallback behavior.

---

## Track F: Planned feature acceleration

Status: Planned
Priority: Medium

- dual-secret auth rotation model.
- overlay/policy inheritance support that is safe for enterprise teams.
- log-based policy validation helpers for monitor-to-enforce decisions.

---

## Track G: Strategic research

Status: Research
Priority: Low

- Rust/WASM compiler path feasibility (benchmark, packaging, contributor ergonomics).
- Additional CDN target compilers and long-term compiler architecture direction.
