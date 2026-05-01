export type CompileTarget = 'aws' | 'cloudflare';
export type CompileArtifactsOptions = {
    policyPath?: string;
    outDir?: string;
    target?: CompileTarget;
    failOnPermissive?: boolean;
    failOnWafApproximation?: boolean;
    outputMode?: string;
    ruleGroupOnly?: boolean;
    cwd?: string;
    pkgRoot?: string;
    env?: NodeJS.ProcessEnv;
};
export type CompileResultBase = {
    edgeFiles: string[];
    infraFiles: string[];
    policyPath: string | null;
    outDir: string | null;
    target: string;
};
export type CompileArtifactsResult = CompileResultBase & {
    ok: boolean;
    errors: string[];
    warnings: string[];
};
export declare function resolveAbsolute(inputPath: string, cwd: string): string;
export declare function listInfraArtifacts(outDir: string, sinceMs?: number): string[];
export declare function compileArtifacts(opts?: CompileArtifactsOptions): CompileArtifactsResult;
