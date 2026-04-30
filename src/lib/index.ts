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
 * Scope note: v1 of this API provides a stable contract. The compiler now has
 * explicit parser / validator / emitter phase modules. The emitter phase still
 * delegates to the existing target scripts for behaviour-preserving output,
 * without changing the public shape.
 */

export type CompileTarget = 'aws' | 'cloudflare';
export type WafFormat = 'terraform' | 'cloudformation' | 'cdk';
export type DoctorCheckStatus = 'pass' | 'fail' | 'warn' | 'skip';

export interface ApiResult {
  ok: boolean;
  errors: string[];
  warnings: string[];
}

export interface CompileOptions {
  policyPath?: string;
  outDir?: string;
  target?: CompileTarget;
  failOnPermissive?: boolean;
  failOnWafApproximation?: boolean;
  outputMode?: 'full' | 'rule-group' | string;
  ruleGroupOnly?: boolean;
  cwd?: string;
  pkgRoot?: string;
  env?: NodeJS.ProcessEnv;
}

export interface CompileResult extends ApiResult {
  edgeFiles: string[];
  infraFiles: string[];
  policyPath: string | null;
  outDir: string | null;
  target: string;
}

export interface EmitWafOptions extends Omit<CompileOptions, 'failOnPermissive'> {
  format?: WafFormat;
}

export interface EmitWafResult extends CompileResult {
  format: string;
  formatNotImplemented: boolean;
}

export interface LintPolicyOptions {
  policyPath?: string;
  pkgRoot?: string;
  env?: NodeJS.ProcessEnv;
}

export interface LintPolicyResult extends ApiResult {
  policy: unknown | null;
}

export interface MigratePolicyOptions {
  policyPath?: string;
  toVersion?: number | string;
  write?: boolean;
  cwd?: string;
}

export interface MigratePolicyResult extends ApiResult {
  fromVersion: number | undefined;
  toVersion: number;
  migrated: boolean;
  noop: boolean;
  reservedExit2?: boolean;
}

export interface DoctorOptions {
  cwd?: string;
  pkgRoot?: string;
  policyPath?: string;
  reportPath?: string | null;
  envProvider?: (name: string) => string | undefined;
  spawnSync?: typeof import('child_process').spawnSync;
  log?: boolean;
  strict?: boolean;
}

export interface DoctorCheck {
  name: string;
  status: DoctorCheckStatus;
  detail: string;
  [key: string]: unknown;
}

export interface DoctorReport {
  generatedAt: string;
  cdnSecurityVersion: string;
  policyPath: string;
  strict: boolean;
  exitCode: number;
  checks: DoctorCheck[];
}

export interface DoctorResult {
  exitCode: number;
  report: DoctorReport;
}

const { lintPolicy: lintPolicyImpl } = require('./lint');
const { compile: compileImpl } = require('./compile');
const { emitWaf: emitWafImpl } = require('./emit-waf');
const { migratePolicy: migratePolicyImpl } = require('./migrate');

const { runDoctor: runDoctorImpl } = require('../scripts/cli-doctor');

export const lintPolicy: (opts?: LintPolicyOptions) => LintPolicyResult = lintPolicyImpl;
export const compile: (opts?: CompileOptions) => CompileResult = compileImpl;
export const emitWaf: (opts?: EmitWafOptions) => EmitWafResult = emitWafImpl;
export const migratePolicy: (opts?: MigratePolicyOptions) => MigratePolicyResult =
  migratePolicyImpl;
export const runDoctor: (opts?: DoctorOptions) => DoctorResult = runDoctorImpl;

module.exports = {
  lintPolicy,
  compile,
  emitWaf,
  runDoctor,
  migratePolicy,
};
