type WafPolicy = Record<string, any>;
export interface WafRuleBuildResult {
    rules: any[];
    blockResponse: any | null;
    blockResponseKey: string | null;
    capacity: number;
}
export declare function buildWafRules(waf: WafPolicy | undefined, projectName: string): WafRuleBuildResult;
export {};
