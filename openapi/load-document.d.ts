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
export interface LoadedOpenApiSourceDocument {
    document: unknown;
    sourceUri: string;
    contentDigest: string;
    byteSize: number;
    refStatus: 'unresolved';
}
export interface LoadedOpenApiDocumentMetadata {
    workspaceRoot: string;
    sourcePath: string;
    device: number;
    inode: number;
}
export declare function loadedOpenApiDocumentMetadata(value: LoadedOpenApiDocument | LoadedOpenApiSourceDocument): LoadedOpenApiDocumentMetadata;
export declare function validateLoadedOpenApiDocumentLimits(value: LoadedOpenApiDocument, limits: Readonly<OpenApiAnalysisLimits>): void;
export declare function isLoadedOpenApiDocument(value: unknown): value is LoadedOpenApiDocument;
export declare function loadOpenApiSourceDocument(options: LoadOpenApiDocumentOptions): LoadedOpenApiSourceDocument;
export declare function loadOpenApiDocument(options: LoadOpenApiDocumentOptions): LoadedOpenApiDocument;
