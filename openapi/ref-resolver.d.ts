import { type OpenApiAnalysisLimits } from './analysis-limits';
import { type ResolvedOpenApiGraph } from './document-graph';
import { type LoadedOpenApiDocument } from './load-document';
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
export declare function resolveJsonPointer(document: unknown, fragment: string, sourceUri: string): ResolvedJsonPointer;
export declare function resolveOpenApiReferences(options: ResolveOpenApiReferencesOptions): ResolvedOpenApiGraph;
