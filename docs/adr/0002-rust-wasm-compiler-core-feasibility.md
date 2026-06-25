# ADR 0002: Rust/WASM compiler feasibility for the CDN compiler

> **Status:** Proposed for v1.4.x

## Context

The TypeScript compiler path has steadily grown in responsibilities:

- policy parse/validation
- ReDoS policy checks
- template injection and output generation
- schema-backed lint behavior
- runtime-specific compile variants
- packaging smoke and drift verification

The project may benefit from a Rust/WASM layer in the future, but this must be an
evidence-based decision because it impacts release complexity and contributor
friction.

This issue asks for a measurable baseline before any native dependency is added.

## What we measured

- `scripts/benchmark-compiler.js` now measures:
  - compiler startup/compile latency (cold + warm)
  - compile memory RSS when `/usr/bin/time` is available
  - optional `npm ci --ignore-scripts --no-audit --no-fund` install timing
- baseline artifact for Node v24.2.0 (darwin/arm64):
  - `docs/benchmarks/compiler-baseline.json`
  - generated with:
    - `node scripts/benchmark-compiler.js --iterations 5 --warmup 1 --policy policy/base.yml --allow-placeholder-token --output docs/benchmarks/compiler-baseline.json`
  - cold start: `50.0ms`
  - warm p50/p95: `48.0ms` / `53.1ms`
  - compile RSS MiB (min / p50 / max): `56.3 / 56.4 / 56.8`
- optional install baseline:
  - `docs/benchmarks/compiler-baseline-with-install.json`
  - generated with:
    - `node scripts/benchmark-compiler.js --iterations 3 --warmup 1 --policy policy/base.yml --allow-placeholder-token --measure-install --install-iterations 1 --output docs/benchmarks/compiler-baseline-with-install.json`
  - `npm ci` median: `1,025.8ms`

## Options

### Option A: keep TypeScript as production compiler (recommended baseline)

Pros:

- minimal disruption to packaging, npm scripts, and existing release path
- predictable contributor onboarding with existing TypeScript ecosystem
- fast rollback profile (no native build artifacts)
- simpler vulnerability and supply-chain scanning

Cons:
- cannot capture some potential performance gains from compiled code without broader
  migration
- language-level safety improvements are limited by JavaScript runtime constraints

### Option B: isolate one Rust/WASM module

Pros:
- isolate high-value workloads first (for example regex analysis and security checks)
- keep most repo structure intact while validating a concrete boundary

Cons:
- new CI matrix for toolchain bootstrapping and artifact publishing
- native target packaging decisions across macOS/Linux/Windows
- cross-compilation and CI caching complexity
- contributor onboarding overhead for rustup/npm integration

### Option C: full compiler rewrite to Rust/WASM

Pros:
- potential long-term performance and memory wins if migration is complete
- ability to ship smaller runtime dependency footprint

Cons:
- highest production risk
- large API drift window with tests, golden artifacts, and docs
- major release coordination burden for all CLI scripts and maintainers

## Decision

For v1.4.x, this ADR recommends **staying with TypeScript in production** and
deferring native migration until baseline evidence is collected over at least one
release cycle.

## Recommended follow-up path

1. collect baseline metrics by Node version (20, 22, 24) using the new benchmark script
2. evaluate one targeted Rust/WASM module in a separate experimental branch
3. require a second ADR only after a measurable benchmark delta and maintainer
   maintenance model are accepted

## Release and maintenance risk assessment

### Immediate production risk (next 1–2 releases)

- **Packaging risk:** no immediate disruption because release process stays
  npm+node-only.
- **CI risk:** none, only benchmark script is additive.
- **Quality risk:** low; no production logic changed.

### Medium-term feasibility risks (if native path is adopted later)

- **Tooling risk:** CI must provision `rustup` and cache toolchains.
- **Supply-chain risk:** native artifacts add prebuilt/binary trust considerations.
- **Contributor risk:** higher bar for first-time contributors needing Rust tooling.
- **Platform risk:** publishing matrix must account for glibc/musl and OS ABI drift.
