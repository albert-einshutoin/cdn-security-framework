export type ParsePolicyOptions = {
    policyPath?: string;
};
export type ParsePolicyResult = {
    ok: boolean;
    errors: string[];
    policy: any | null;
};
export declare function parsePolicyFile(opts?: ParsePolicyOptions): ParsePolicyResult;
