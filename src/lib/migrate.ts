/**
 * Programmatic API: migratePolicy
 *
 * v1 is the only shipped schema, so this is a no-op for v1 → v1. Reports
 * structured errors for unknown targets, missing versions, and unregistered
 * migration paths. The CLI `migrate` subcommand translates this into exit
 * codes 0/1/2.
 *
 * Input:
 *   {
 *     policyPath: string,
 *     toVersion?: number | string,   // default: 1
 *     cwd?:       string,
 *   }
 *
 * Output:
 *   {
 *     ok:          boolean,
 *     errors:      string[],
 *     warnings:    string[],
 *     fromVersion: number | undefined,
 *     toVersion:   number,
 *     migrated:    boolean,           // true iff a migration actually ran
 *     noop:        boolean,           // true iff already at target
 *     reservedExit2?: boolean,        // true for "no migration path registered" — CLI exits 2
 *   }
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

interface MigratePolicyOptions {
  policyPath?: string;
  toVersion?: number | string;
  cwd?: string;
}

function resolveAbsolute(inputPath: string, cwd: string): string {
  return path.isAbsolute(inputPath) ? inputPath : path.join(cwd, inputPath);
}

function migratePolicy(opts: MigratePolicyOptions = {}) {
  opts = opts || {};
  const cwd = opts.cwd || process.cwd();
  const toVersionRaw = opts.toVersion === undefined ? 1 : opts.toVersion;
  const toVersion = Number(toVersionRaw);

  const warnings: string[] = [];

  if (!opts.policyPath) {
    return {
      ok: false,
      errors: ['policyPath is required'],
      warnings,
      fromVersion: undefined,
      toVersion,
      migrated: false,
      noop: false,
    };
  }

  const policyPath = resolveAbsolute(opts.policyPath, cwd);
  if (!fs.existsSync(policyPath)) {
    return {
      ok: false,
      errors: [`policy file not found: ${policyPath}`],
      warnings,
      fromVersion: undefined,
      toVersion,
      migrated: false,
      noop: false,
    };
  }

  if (Number.isNaN(toVersion)) {
    return {
      ok: false,
      errors: [`toVersion must be a number. Got: ${toVersionRaw}`],
      warnings,
      fromVersion: undefined,
      toVersion: NaN,
      migrated: false,
      noop: false,
    };
  }

  let doc: any;
  try {
    doc = yaml.load(fs.readFileSync(policyPath, 'utf8'));
  } catch (e: any) {
    return {
      ok: false,
      errors: [`failed to parse policy YAML: ${e.message}`],
      warnings,
      fromVersion: undefined,
      toVersion,
      migrated: false,
      noop: false,
    };
  }

  const fromVersion = doc && doc.version;

  if (fromVersion === undefined) {
    return {
      ok: false,
      errors: ['Policy has no `version` field. Add `version: 1` and retry.'],
      warnings,
      fromVersion: undefined,
      toVersion,
      migrated: false,
      noop: false,
    };
  }

  if (fromVersion === toVersion) {
    return {
      ok: true,
      errors: [],
      warnings,
      fromVersion,
      toVersion,
      migrated: false,
      noop: true,
    };
  }

  if (toVersion < fromVersion) {
    return {
      ok: false,
      errors: ['Downgrade migrations are not supported.'],
      warnings,
      fromVersion,
      toVersion,
      migrated: false,
      noop: false,
    };
  }

  // Forward migrations are registered here when a new schema version ships.
  // Contract: each step is a pure function (v_n policy) -> (v_n+1 policy).
  // v1 is currently the only shipped schema, so there is nothing to run.
  return {
    ok: false,
    errors: [
      `No migration path from v${fromVersion} to v${toVersion} is registered in this CLI version.`,
      'See docs/schema-migration.md for the migration policy and supported versions.',
    ],
    warnings,
    fromVersion,
    toVersion,
    migrated: false,
    noop: false,
    reservedExit2: true,
  };
}

module.exports = { migratePolicy };
