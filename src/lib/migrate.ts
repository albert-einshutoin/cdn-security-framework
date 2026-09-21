import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import type { MigratePolicyOptions, MigratePolicyResult } from './index';
import { MigrationError, checkMigrationValue, MIGRATION_MAX_BYTES, migrationFailure, transformPolicy } from './migration-transform';
import { readMigrationInput, saveMigration } from './migration-save';
const yaml = require('js-yaml');

export function parseMigrationYaml(content: string): unknown {
  if (Buffer.byteLength(content) > MIGRATION_MAX_BYTES) throw new MigrationError('MIGRATION_RESOURCE_LIMIT');
  try {
    const value = yaml.load(content, { schema: yaml.JSON_SCHEMA, json: false, maxAliases: 50, maxDepth: 64 });
    checkMigrationValue(value);
    return value;
  } catch (error) {
    if (error instanceof MigrationError) throw error;
    throw new MigrationError('MIGRATION_YAML_INVALID');
  }
}

export function migratePolicy(opts: MigratePolicyOptions = {}): MigratePolicyResult {
  try {
    if (!opts || typeof opts !== 'object' || typeof opts.policyPath !== 'string' || !opts.policyPath.trim()
      || (opts.write !== undefined && typeof opts.write !== 'boolean')
      || (opts.cwd !== undefined && typeof opts.cwd !== 'string')) throw new MigrationError('MIGRATION_ARGUMENT_INVALID');
    const input = path.resolve(opts.cwd ?? process.cwd(), opts.policyPath);
    const source = readMigrationInput(input);
    const result = transformPolicy(parseMigrationYaml(new TextDecoder('utf-8', { fatal: true }).decode(source.content)), opts.toVersion, opts.target);
    if (!result.ok || result.noop || !opts.write) return result;
    const serialized = yaml.dump(result.policy, { noRefs: true, sortKeys: false, lineWidth: -1 });
    if (!isDeepStrictEqual(parseMigrationYaml(serialized), result.policy)) throw new MigrationError('MIGRATION_SERIALIZATION_INVALID');
    const warnings = saveMigration(source, Buffer.from(serialized));
    return { ...result, saved: true, warnings };
  } catch (error: unknown) {
    return error instanceof MigrationError ? migrationFailure(error.code, error.exitCode)
      : migrationFailure('MIGRATION_IO_FAILED', 1);
  }
}
