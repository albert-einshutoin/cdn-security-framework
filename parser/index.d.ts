import type { CDNSecurityFrameworkPolicy } from '../types/policy';
export type ParsePolicyOptions = {
    policyPath?: string;
};
export type ParsePolicyResult = {
    ok: boolean;
    errors: string[];
    warnings: string[];
    policy: Partial<CDNSecurityFrameworkPolicy> | null;
};
export declare function parsePolicyFile(opts?: ParsePolicyOptions): ParsePolicyResult;
