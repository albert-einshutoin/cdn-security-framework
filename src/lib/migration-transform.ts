import v1Schema from './migration-v1-schema';
import type { MigratePolicyResult } from './index';
const Ajv = require('ajv');
const v2Schema = require('../policy/schema.json');
const { validatePolicy } = require('../validator');
const ajv = new Ajv({ allErrors: false, strict: true, strictRequired: false, allowUnionTypes: true });
const validators = { 1: ajv.compile(v1Schema), 2: ajv.compile(v2Schema) };
export const MIGRATION_MAX_BYTES = 1_048_576;

export class MigrationError extends Error {
  constructor(readonly code: string, readonly exitCode: 1 | 2 = 1) { super(code); }
}

// Bound traversal before cloning or validation, including repeated YAML aliases.
export function checkMigrationValue(value: unknown): void {
  let nodes = 0;
  const active = new Set<object>();
  function visit(v: unknown, depth: number): void {
    if (++nodes > 10_000 || depth > 64) throw new MigrationError('MIGRATION_RESOURCE_LIMIT');
    if (v === null || typeof v === 'boolean' || typeof v === 'string') return;
    if (typeof v === 'number' && Number.isFinite(v)) return;
    if (!v || typeof v !== 'object' || (!Array.isArray(v) && Object.getPrototypeOf(v) !== Object.prototype)) {
      throw new MigrationError('MIGRATION_STRUCTURE_INVALID');
    }
    if (active.has(v)) throw new MigrationError('MIGRATION_STRUCTURE_INVALID');
    if (Object.getOwnPropertySymbols(v).length) throw new MigrationError('MIGRATION_STRUCTURE_INVALID');
    active.add(v);
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(v))) {
      if (['__proto__', 'prototype', 'constructor'].includes(key) || !('value' in descriptor)) {
        throw new MigrationError('MIGRATION_STRUCTURE_INVALID');
      }
      if (Array.isArray(v) && key === 'length') continue;
      if (!descriptor.enumerable || (Array.isArray(v) && !/^(0|[1-9][0-9]*)$/.test(key))) throw new MigrationError('MIGRATION_STRUCTURE_INVALID');
      visit(descriptor.value, depth + 1);
    }
    active.delete(v);
  }
  visit(value, 0);
  if (Buffer.byteLength(JSON.stringify(value)) > MIGRATION_MAX_BYTES) throw new MigrationError('MIGRATION_RESOURCE_LIMIT');
}

export function migrationFailure(code: string, exitCode: 1 | 2, toVersion = 2, fromVersion?: number): MigratePolicyResult {
  return { ok: false, errors: [code], warnings: [], fromVersion, toVersion, migrated: false, noop: false, saved: false, exitCode, reservedExit2: exitCode === 2 };
}

/** Adapter only: no file I/O, environment expansion, defaults or input mutation. */
export function transformPolicy(input: unknown, to: number | string = 2, target?: string): MigratePolicyResult {
  let fromVersion: number | undefined;
  let toVersion = 2;
  try {
    if (typeof to === 'string' ? !/^[1-9][0-9]*$/.test(to) : !Number.isSafeInteger(to)) {
      throw new MigrationError('MIGRATION_TARGET_VERSION_INVALID');
    }
    toVersion = Number(to);
    if (!Number.isSafeInteger(toVersion) || toVersion < 1) throw new MigrationError('MIGRATION_TARGET_VERSION_INVALID');
    if (target !== undefined && target !== 'aws' && target !== 'cloudflare') throw new MigrationError('MIGRATION_TARGET_INVALID');
    checkMigrationValue(input);
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new MigrationError('MIGRATION_POLICY_INVALID');
    const policy = input as Record<string, any>;
    if (!Object.hasOwn(policy, 'version')) throw new MigrationError('MIGRATION_VERSION_MISSING');
    if (!Number.isSafeInteger(policy.version)) throw new MigrationError('MIGRATION_VERSION_INVALID');
    fromVersion = policy.version;
    if (fromVersion !== 1 && fromVersion !== 2) throw new MigrationError('MIGRATION_VERSION_UNSUPPORTED', 2);
    if (toVersion !== 1 && toVersion !== 2) throw new MigrationError('MIGRATION_TARGET_VERSION_UNSUPPORTED', 2);
    if (toVersion < fromVersion) throw new MigrationError('MIGRATION_DOWNGRADE_UNSUPPORTED');
    // No graph flattening: a separate explicit migration is required for referenced policies.
    if (Object.hasOwn(policy, 'extends') || Object.hasOwn(policy, '$ref')) throw new MigrationError('MIGRATION_MANUAL: extends/reference: migrate each dependency explicitly; graph migration is unsupported', 2);
    if (!validators[fromVersion](policy)) throw new MigrationError('MIGRATION_POLICY_INVALID: configuration does not match the declared schema');
    if (fromVersion === 2 && !validatePolicy({ policy, env: {} }).ok) throw new MigrationError('MIGRATION_POLICY_INVALID');
    if (fromVersion === toVersion) return { ok: true, errors: [], warnings: [], fromVersion, toVersion, migrated: false, noop: true, saved: false, exitCode: 0 };
    if (policy.firewall?.challenge?.difficulty > 4) throw new MigrationError('MIGRATION_MANUAL: firewall.challenge.difficulty: choose a supported value explicitly; no clamping', 2);
    const providerFields = [
      ...(policy.response_headers?.csp_nonce === true ? ['response_headers.csp_nonce'] : []),
      ...(Array.isArray(policy.routes) && policy.routes.some((r: any) => ['jwt', 'signed_url'].includes(r.auth_gate?.type)) ? ['routes.auth_gate'] : []),
    ];
    if (providerFields.length && target === undefined) throw new MigrationError('MIGRATION_MANUAL: target: select aws or cloudflare for nonce/JWT/signed_url settings', 2);
    if (providerFields.length && target === 'aws') throw new MigrationError(`MIGRATION_MANUAL: ${providerFields.join(', ')}: unsupported on AWS; choose provider or change configuration explicitly`, 2);
    const converted = JSON.parse(JSON.stringify(policy));
    converted.version = 2;
    if (!validators[2](converted) || !validatePolicy({ policy: converted, env: {} }).ok) throw new MigrationError('MIGRATION_POLICY_INVALID: converted configuration does not satisfy schema 2');
    return { ok: true, errors: [], warnings: [], fromVersion, toVersion, migrated: true, noop: false, saved: false, exitCode: 0, policy: converted };
  } catch (error: unknown) {
    return error instanceof MigrationError ? migrationFailure(error.code, error.exitCode, toVersion, fromVersion)
      : migrationFailure('MIGRATION_POLICY_INVALID', 1, toVersion, fromVersion);
  }
}
