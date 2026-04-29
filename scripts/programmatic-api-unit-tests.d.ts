#!/usr/bin/env node
/**
 * Programmatic API integration tests.
 *
 * These exercise the public entry `require('cdn-security-framework')` from
 * the repo (via its lib/index.js). We assert every function returns a
 * structured result object and NEVER calls process.exit — the whole point
 * of the Programmatic API is that callers decide exit behaviour.
 *
 * Coverage focus:
 *   - result shape stability (this is the contract)
 *   - lintPolicy in-process happy/error paths
 *   - compile + emitWaf backwards-compat (subprocess-backed today)
 *   - migratePolicy noop and error branches (no process.exit)
 *   - runDoctor re-export is callable
 */
export {};
