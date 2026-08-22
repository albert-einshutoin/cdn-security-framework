export interface OpenApiNodeLocation {
    id: string;
    sourceUri: string;
    pointer: string;
}
export interface ResolvedOpenApiDocument {
    sourceUri: string;
    contentDigest: string;
    byteSize: number;
    document: unknown;
}
export interface OpenApiReferenceEdge {
    from: OpenApiNodeLocation;
    ref: string;
    target: OpenApiNodeLocation;
}
export interface ResolvedOpenApiGraph {
    readonly root: OpenApiNodeLocation;
    readonly documents: readonly ResolvedOpenApiDocument[];
    readonly references: readonly OpenApiReferenceEdge[];
    readonly totalByteSize: number;
}
export declare function serializeResolvedOpenApiGraph(graph: ResolvedOpenApiGraph): string;
