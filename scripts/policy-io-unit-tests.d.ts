#!/usr/bin/env node
/**
 * Unit tests for src/scripts/lib/policy-io.ts (issue #182).
 *
 * Centralizes what was previously duplicated in compile-core,
 * compile-cloudflare, compile-infra, compile-cloudflare-waf, and the
 * CLI's `resolvePolicyPath` fallback:
 *   - defaultPolicyPath(rootDir) — `<rootDir>/policy/security.yml` else
 *     `<rootDir>/policy/base.yml`
 *   - defaultOutDir(rootDir)     — `<rootDir>/dist`
 *   - parseArgs(argv, rootDir)   — compiler-style argv with the exact
 *     pre-#182 semantics (last positional wins, --policy and positional
 *     priority follows argv order, --policy without a value is ignored,
 *     --out-dir same shape, unknown/boolean flags ignored)
 *   - loadPolicy / loadPolicyWithWarnings — parse a policy file, surface
 *     ENOENT for missing files so callers can map to a friendly message
 *
 * Kept self-contained (no Jest/Mocha) to match the existing test harness.
 */
export {};
