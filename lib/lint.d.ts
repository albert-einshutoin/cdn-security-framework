/**
 * Programmatic API: lintPolicy
 *
 * In-process equivalent of `scripts/policy-lint.js`. Returns a structured
 * result instead of calling process.exit. Stable public surface — the
 * underlying ajv / validateAuthGates / parsePathPatterns plumbing may change,
 * but the return shape is stable.
 *
 * Input:
 *   { policyPath: string, pkgRoot?: string }
 *   pkgRoot defaults to the installed package root (where schema.json lives).
 *
 * Output:
 *   { ok, errors[], warnings[], policy }
 *   - `policy` is the parsed YAML object (null if parse failed).
 */
export {};
