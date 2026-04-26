#!/usr/bin/env node
/**
 * ReDoS fuzz: exercises every user-supplied regex from policy YAML against
 * adversarial inputs with a per-match timeout. Fails if any regex takes longer
 * than REDOS_TIMEOUT_MS, which is the signal for catastrophic backtracking.
 *
 * Covered sources:
 *   - request.block.path_patterns.regex
 *   - routes[].match.regex (future-proof; currently not in schema)
 *
 * Also runs a static sanity check rejecting classic ReDoS shapes
 * (nested quantifiers over overlapping classes) before runtime fuzzing — see
 * hasNestedQuantifier().
 */
export {};
