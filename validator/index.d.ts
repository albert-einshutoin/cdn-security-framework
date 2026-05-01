import type { ErrorObject } from 'ajv';
import type { CDNSecurityFrameworkPolicy } from '../types/policy';
export type PolicyDraft = Partial<CDNSecurityFrameworkPolicy>;
export type ValidatePolicyOptions = {
    policy: PolicyDraft | null;
    pkgRoot?: string;
    env?: NodeJS.ProcessEnv;
};
export type ValidatePolicyResult = {
    ok: boolean;
    errors: string[];
    warnings: string[];
};
export declare function formatAjvErrors(errors?: ErrorObject[]): string[];
export declare function validateCorsCredentials(policy: PolicyDraft | null): string[];
export declare function validatePolicy(opts: ValidatePolicyOptions): ValidatePolicyResult;
