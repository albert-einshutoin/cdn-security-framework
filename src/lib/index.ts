// @ts-nocheck
/**
 * cdn-security-framework — Programmatic API
 *
 * Stable Node.js entry point for embedding the compiler in existing CI/CD
 * pipelines (Terraform wrappers, CDK app synth hooks, custom policy servers,
 * etc.) without shelling out to the CLI.
 *
 * Every exported function returns a structured result object. **None of them
 * call process.exit** — callers decide exit behaviour.
 *
 * Result contract (all functions):
 *   {
 *     ok:       boolean,        // true iff zero errors
 *     errors:   string[],       // human-readable error lines
 *     warnings: string[],       // non-fatal advisories
 *     ...cmdSpecific,           // per-function extra fields (see each docstring)
 *   }
 *
 * Scope note: v1 of this API provides a stable contract. compile() and
 * emitWaf() currently delegate to subprocesses internally; that is an
 * implementation detail and will be replaced by in-process module boundaries
 * in #69 (module split) without changing the public shape.
 */

const { lintPolicy } = require('./lint');
const { compile } = require('./compile');
const { emitWaf } = require('./emit-waf');
const { migratePolicy } = require('./migrate');

const { runDoctor } = require('../scripts/cli-doctor');

module.exports = {
  lintPolicy,
  compile,
  emitWaf,
  runDoctor,
  migratePolicy,
};
