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
    exitCode: number;
    checks: DoctorCheck[];
}
export interface DoctorResult {
    exitCode: number;
    report: DoctorReport;
}
export declare const lintPolicy: (opts?: LintPolicyOptions) => LintPolicyResult;
export declare const compile: (opts?: CompileOptions) => CompileResult;
export declare const emitWaf: (opts?: EmitWafOptions) => EmitWafResult;
export declare const migratePolicy: (opts?: MigratePolicyOptions) => MigratePolicyResult;
export declare const runDoctor: (opts?: DoctorOptions) => DoctorResult;
