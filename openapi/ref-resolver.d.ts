import { type OpenApiAnalysisLimits } from './analysis-limits';
import { type ResolvedOpenApiGraph } from './document-graph';
import { type LoadedOpenApiDocument } from './load-document';
export interface OpenApiSourceIdentity {
    sourcePath: string;
    device: number;
    inode: number;
}
export { serializeResolvedOpenApiGraph } from './document-graph';
export type { OpenApiNodeLocation, OpenApiReferenceEdge, ResolvedOpenApiDocument, ResolvedOpenApiGraph, } from './document-graph';
export interface ResolveOpenApiReferencesOptions {
    root: LoadedOpenApiDocument;
    workspaceRoot: string;
    limits: OpenApiAnalysisLimits;
}
export interface ResolvedJsonPointer {
    value: Record<string, unknown> | unknown[];
    pointer: string;
}
export interface ResolvedJsonPointerValue {
    value: unknown;
    pointer: string;
}
export declare function isResolvedOpenApiGraph(value: unknown): value is ResolvedOpenApiGraph;
export declare function resolvedOpenApiSourceIdentities(graph: ResolvedOpenApiGraph): readonly OpenApiSourceIdentity[];
export declare function resolveJsonPointer(document: unknown, fragment: string, sourceUri: string): ResolvedJsonPointer;
export declare function resolveJsonPointerValue(document: unknown, fragment: string, sourceUri: string): ResolvedJsonPointerValue;
export declare function resolveOpenApiReferences(options: ResolveOpenApiReferencesOptions): ResolvedOpenApiGraph;
