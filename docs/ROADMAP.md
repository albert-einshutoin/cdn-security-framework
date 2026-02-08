# Roadmap

This document tracks post-Phase-3 work as explicit follow-up tracks.

---

## Track A: Cloudflare Workers JWT / Signed URL / Origin Auth

Status: Planned (separate track)
Priority: Medium

### Scope

- Add JWT auth gate support (`RS256` / `HS256`) for Cloudflare Workers runtime.
- Add Signed URL validation support for Cloudflare Workers runtime.
- Evaluate and define origin auth handling equivalent to Lambda@Edge where feasible.

### Constraints

- Respect Workers CPU and memory limits.
- Avoid per-request heavy JWKS fetch; design cache strategy.
- Keep behavior aligned with policy schema and Lambda@Edge semantics.

### Acceptance criteria

1. `npx cdn-security build --target cloudflare` generates runtime code that enforces configured JWT and Signed URL gates.
2. Runtime tests cover pass/fail cases for both JWT and Signed URL in Cloudflare target.
3. SECURITY-FEATURE-MATRIX is updated from `—` to `✓` for supported items.
4. Docs explain any intentional feature parity gaps.

---

## Track B: Compiler test depth

Status: In progress
Priority: High

- Added compiler unit tests for core auth/path logic.
- Next: expand unit tests for output generation edge cases and infra compiler helpers.
