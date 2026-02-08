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
