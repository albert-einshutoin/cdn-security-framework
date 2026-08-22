export declare const OPENAPI_ANALYSIS_ERROR_CODES: readonly ["OPENAPI_INPUT_NOT_FOUND", "OPENAPI_DOCUMENT_TOO_LARGE", "OPENAPI_UNSUPPORTED_VERSION", "OPENAPI_YAML_ALIAS_LIMIT", "OPENAPI_REF_OUTSIDE_ROOT", "OPENAPI_REMOTE_REF_DISABLED", "OPENAPI_REF_CYCLE_LIMIT", "OPENAPI_NODE_LIMIT", "OPENAPI_INVALID_LIMITS"];
export type OpenApiAnalysisErrorCode = typeof OPENAPI_ANALYSIS_ERROR_CODES[number];
export interface OpenApiAnalysisErrorOptions {
    sourceUri?: string;
    pointer?: string;
}
export declare class OpenApiAnalysisError extends Error {
    readonly code: OpenApiAnalysisErrorCode;
    readonly safeMessage: string;
    readonly sourceUri?: string;
    readonly pointer?: string;
    constructor(code: OpenApiAnalysisErrorCode, options?: OpenApiAnalysisErrorOptions);
    toJSON(): Record<string, string>;
}
