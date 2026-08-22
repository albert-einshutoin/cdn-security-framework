export declare const OPENAPI_ANALYSIS_ERROR_CODES: readonly ["OPENAPI_INPUT_NOT_FOUND", "OPENAPI_DOCUMENT_TOO_LARGE", "OPENAPI_PARSE_ERROR", "OPENAPI_INVALID_ROOT", "OPENAPI_UNSUPPORTED_VERSION", "OPENAPI_YAML_ALIAS_LIMIT", "OPENAPI_REF_OUTSIDE_ROOT", "OPENAPI_REMOTE_REF_DISABLED", "OPENAPI_REF_CYCLE_LIMIT", "OPENAPI_REF_NOT_FOUND", "OPENAPI_REF_POINTER_INVALID", "OPENAPI_REF_DEPTH_LIMIT", "OPENAPI_DOCUMENT_COUNT_LIMIT", "OPENAPI_GRAPH_SIZE_LIMIT", "OPENAPI_OPERATION_INVALID", "OPENAPI_OPERATION_LIMIT", "OPENAPI_NODE_LIMIT", "OPENAPI_INVALID_LIMITS"];
export type OpenApiAnalysisErrorCode = typeof OPENAPI_ANALYSIS_ERROR_CODES[number];
export interface OpenApiAnalysisErrorOptions {
    sourceUri?: string;
    pointer?: string;
    line?: number;
    column?: number;
}
export declare class OpenApiAnalysisError extends Error {
    readonly code: OpenApiAnalysisErrorCode;
    readonly safeMessage: string;
    readonly sourceUri?: string;
    readonly pointer?: string;
    readonly line?: number;
    readonly column?: number;
    constructor(code: OpenApiAnalysisErrorCode, options?: OpenApiAnalysisErrorOptions);
    toJSON(): Record<string, string | number>;
}
