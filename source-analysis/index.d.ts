import { type SecurityContractV1 } from '../contract/security-ir';
import { type HttpMethod } from '../contract/canonical-route';
export declare const SOURCE_ANALYZER_CAPABILITY_NAMES: readonly ["routePaths", "httpMethods", "routerPrefixes", "globalPrefixes", "authentication", "authorization", "requestContentTypes", "requestLimits", "sourceLocations", "inheritedMetadata", "dynamicExpressions"];
export declare const SOURCE_ANALYZER_CAPABILITY_STATUSES: readonly ["supported", "partial", "unsupported"];
export declare const SOURCE_ANALYZER_DIAGNOSTIC_CODES: readonly ["SOURCE_ANALYZER_INVALID_PLUGIN", "SOURCE_ANALYZER_DUPLICATE", "SOURCE_ANALYZER_UNKNOWN", "SOURCE_ANALYZER_INVALID_LIMITS", "SOURCE_ANALYZER_INPUT_INVALID", "SOURCE_ANALYZER_INPUT_OUTSIDE_ROOT", "SOURCE_ANALYZER_FILE_LIMIT", "SOURCE_ANALYZER_TOTAL_BYTES_LIMIT", "SOURCE_ANALYZER_FILE_BYTES_LIMIT", "SOURCE_ANALYZER_AST_NODE_LIMIT", "SOURCE_ANALYZER_DIAGNOSTIC_LIMIT", "SOURCE_ANALYZER_OPERATION_LIMIT", "SOURCE_ANALYZER_DEPTH_LIMIT", "SOURCE_ANALYZER_DYNAMIC_ROUTE", "SOURCE_ANALYZER_UNSUPPORTED_DECORATOR", "SOURCE_ANALYZER_CANCELLED", "SOURCE_ANALYZER_TIMEOUT", "SOURCE_ANALYZER_INVALID_RESULT", "SOURCE_ANALYZER_INTERNAL"];
export type SourceAnalyzerCapabilityName = typeof SOURCE_ANALYZER_CAPABILITY_NAMES[number];
export type SourceAnalyzerCapabilityStatus = typeof SOURCE_ANALYZER_CAPABILITY_STATUSES[number];
export type SourceAnalyzerDiagnosticCode = typeof SOURCE_ANALYZER_DIAGNOSTIC_CODES[number];
export interface AnalyzerCapability {
    status: SourceAnalyzerCapabilityStatus;
    reason: string;
}
export type AnalyzerCapabilities = Readonly<Record<SourceAnalyzerCapabilityName, AnalyzerCapability>>;
export interface SourceAnalysisLimits {
    maxFiles: number;
    maxTotalSourceBytes: number;
    maxFileBytes: number;
    maxAstNodes: number;
    maxDiagnostics: number;
    maxOperations: number;
    maxAnalysisDepth: number;
    timeoutMs: number;
}
export interface SourceAnalysisMetrics {
    files: number;
    totalSourceBytes: number;
    largestFileBytes: number;
    astNodes: number;
    diagnostics: number;
    operations: number;
    maxDepth: number;
}
export interface AnalyzerDiagnostic {
    code: SourceAnalyzerDiagnosticCode;
    safeMessage: string;
    sourceUri?: string;
    line?: number;
    column?: number;
}
export declare const SOURCE_ANALYZER_LOG_CODES: readonly ["SOURCE_ANALYZER_STARTED", "SOURCE_ANALYZER_COMPLETED", "SOURCE_ANALYZER_FAILED"];
export type SourceAnalyzerLogCode = typeof SOURCE_ANALYZER_LOG_CODES[number];
export interface SafeAnalyzerLogger {
    log(code: SourceAnalyzerLogCode): void | Promise<void>;
}
export interface SourceAnalysisContext {
    workspaceRoot: string;
    entrypoints: string[];
    limits: SourceAnalysisLimits;
    cancellationSignal?: AbortSignal;
    logger: SafeAnalyzerLogger;
}
export interface SourceAnalysisResult {
    contract: SecurityContractV1;
    diagnostics: AnalyzerDiagnostic[];
    unresolvedOperations: UnresolvedSourceOperationCandidate[];
    metrics: SourceAnalysisMetrics;
}
export interface UnresolvedSourceOperationCandidate {
    methods: HttpMethod[];
    path: null;
    reason: 'SOURCE_ANALYZER_DYNAMIC_ROUTE' | 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR';
    sourceUri: string;
    line: number;
    column: number;
}
export interface SourceAnalyzerPlugin {
    readonly id: string;
    readonly version: string;
    readonly languages: readonly string[];
    readonly frameworks: readonly string[];
    readonly capabilities: AnalyzerCapabilities;
    analyze(context: SourceAnalysisContext): Promise<SourceAnalysisResult>;
}
export type SourceAnalysisExecution = {
    status: 'success';
    result: SourceAnalysisResult;
} | {
    status: 'failed';
    diagnostics: AnalyzerDiagnostic[];
};
export declare const DEFAULT_SOURCE_ANALYSIS_LIMITS: Readonly<SourceAnalysisLimits>;
export declare class SourceAnalyzerContractError extends Error {
    readonly code: SourceAnalyzerDiagnosticCode;
    readonly safeMessage: string;
    constructor(code: SourceAnalyzerDiagnosticCode);
}
export declare function validateSourceAnalysisLimits(input: unknown): Readonly<SourceAnalysisLimits>;
export declare function validateSourceAnalyzerPlugin(input: unknown): SourceAnalyzerPlugin;
export declare function runSourceAnalyzer(input: SourceAnalyzerPlugin, context: SourceAnalysisContext): Promise<SourceAnalysisExecution>;
export declare class SourceAnalyzerRegistry {
    private readonly plugins;
    constructor(plugins?: readonly SourceAnalyzerPlugin[]);
    register(input: SourceAnalyzerPlugin): void;
    get(id: string, version: string): SourceAnalyzerPlugin;
    list(): SourceAnalyzerPlugin[];
}
