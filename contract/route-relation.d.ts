export declare const ROUTE_RELATIONS: readonly ["definitely-covered", "definitely-disjoint", "possibly-overlapping", "unknown"];
export type RouteRelation = typeof ROUTE_RELATIONS[number];
export type OpenApiPath = {
    kind: 'exact';
    value: string;
} | {
    kind: 'template';
    value: string;
};
export type PolicyPathMatcher = {
    kind: 'exact';
    value: string;
} | {
    kind: 'prefix';
    value: string;
} | {
    kind: 'pattern';
    syntax: 'regex';
    value: string;
};
export type RouteHostMatcher = {
    kind: 'any';
} | {
    kind: 'allowlist';
    values: readonly string[];
} | {
    kind: 'unknown';
};
export interface RouteRelationInput {
    path: OpenApiPath;
    methods: readonly string[];
    hosts: RouteHostMatcher;
}
export interface PolicyRelationInput {
    path: PolicyPathMatcher;
    methods: readonly string[];
    hosts: RouteHostMatcher;
}
export interface RouteRelationOptions {
    phase: 'normalized-path';
    collapseSlashes: boolean;
    removeDotSegments: boolean;
}
export interface RouteRelationResult {
    relation: RouteRelation;
    path: RouteRelation;
    method: RouteRelation;
    host: RouteRelation;
    isProvenDisjoint: boolean;
}
export declare function relatePath(source: OpenApiPath, policy: PolicyPathMatcher, options: RouteRelationOptions): RouteRelation;
export declare function relateMethods(source: readonly string[], policy: readonly string[]): RouteRelation;
export declare function relateHosts(source: RouteHostMatcher, policy: RouteHostMatcher): RouteRelation;
export declare function relateRoute(source: RouteRelationInput, policy: PolicyRelationInput, options: RouteRelationOptions): RouteRelationResult;
