/**
 * cli-doctor.js
 *
 * Implements `cdn-security doctor` — environment diagnostics.
 *
 * Exported as `runDoctor(opts)` so bin/cli.js and doctor-unit-tests.js share
 * one path. `runDoctor` never calls process.exit — it returns an exit code
 * and the structured result, so tests can introspect individual check rows
 * without spawning a subprocess.
 *
 * Contract:
 *   input:  { cwd, pkgRoot, policyPath?, reportPath? }
 *   output: { exitCode, report }
 *   report: { generatedAt, cdnSecurityVersion, checks: [{ name, status, detail }] }
 *
 *   status ∈ { pass, fail, warn, skip }
 *   exitCode = 0 when no check has status === 'fail', else 1.
 */
export {};
