"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.runDoctor = exports.migratePolicy = exports.emitWaf = exports.compile = exports.lintPolicy = void 0;
const { lintPolicy: lintPolicyImpl } = require('./lint');
const { compile: compileImpl } = require('./compile');
const { emitWaf: emitWafImpl } = require('./emit-waf');
const { migratePolicy: migratePolicyImpl } = require('./migrate');
const { runDoctor: runDoctorImpl } = require('../scripts/cli-doctor');
exports.lintPolicy = lintPolicyImpl;
exports.compile = compileImpl;
exports.emitWaf = emitWafImpl;
exports.migratePolicy = migratePolicyImpl;
exports.runDoctor = runDoctorImpl;
module.exports = {
    lintPolicy: exports.lintPolicy,
    compile: exports.compile,
    emitWaf: exports.emitWaf,
    runDoctor: exports.runDoctor,
    migratePolicy: exports.migratePolicy,
};
