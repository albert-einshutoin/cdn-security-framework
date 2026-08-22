import { type OpenApiAnalysisLimits } from './analysis-limits';
export interface OpenApiRootDocument {
    openapi: string;
    paths?: Record<string, unknown>;
    [key: string]: unknown;
}
export interface LoadedOpenApiDocument {
    document: OpenApiRootDocument;
    sourceUri: string;
    contentDigest: string;
    version: '3.0' | '3.1';
    byteSize: number;
    refStatus: 'unresolved';
}
export interface LoadOpenApiDocumentOptions {
    inputPath: string;
    workspaceRoot: string;
    limits?: Partial<OpenApiAnalysisLimits>;
}
export declare function loadOpenApiDocument(options: LoadOpenApiDocumentOptions): LoadedOpenApiDocument;
