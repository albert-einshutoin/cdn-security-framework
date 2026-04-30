export type ValidatePolicyOptions = {
    policy: any;
    pkgRoot?: string;
    env?: NodeJS.ProcessEnv;
};
export declare function formatAjvErrors(errors: any[]): string[];
export declare function validateCorsCredentials(policy: any): string[];
export declare function validatePolicy(opts: ValidatePolicyOptions): {
    ok: boolean;
    errors: string[];
    warnings: string[];
};
