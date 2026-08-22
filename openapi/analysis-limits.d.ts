export interface OpenApiAnalysisLimits {
    maxDocumentBytes: number;
    maxResolvedDocuments: number;
    maxRefDepth: number;
    maxSchemaDepth: number;
    maxNodes: number;
    maxOperations: number;
    maxParametersPerOperation: number;
    maxSecuritySchemes: number;
    maxYamlAliases: number;
    maxStringLength: number;
    timeoutMs: number;
}
export type OpenApiAnalysisLimitName = keyof OpenApiAnalysisLimits;
export declare const OPENAPI_ANALYSIS_LIMIT_RANGES: Readonly<Record<OpenApiAnalysisLimitName, Readonly<{
    min: number;
    max: number;
}>>>;
export declare const DEFAULT_OPENAPI_ANALYSIS_LIMITS: Readonly<OpenApiAnalysisLimits>;
export declare function validateOpenApiAnalysisLimits(input: unknown): Readonly<OpenApiAnalysisLimits>;
