import type { SecurityContractV1, ValueConstraintsV1 } from '../contract';
export type EstimateKind = 'exact' | 'upper-bound' | 'partial' | 'unknown';
export type RecommendationConfidence = 'high' | 'medium' | 'low';
export interface SafetyMarginOptions {
    absolute?: number;
    ratio?: number;
}
export interface AppliedSafetyMargin {
    absolute: number;
    ratio: number;
    before: number;
    after: number;
}
export interface RecommendationCandidate<T> {
    value: T | null;
    basis: string[];
    estimateKind: EstimateKind;
    margin: AppliedSafetyMargin | null;
    confidence: RecommendationConfidence;
    unsupportedReasons: string[];
}
export interface ParameterConstraintMetadata {
    name: string;
    location: 'query' | 'path' | 'header' | 'cookie';
    required: boolean;
    constraints: ValueConstraintsV1;
}
export interface OperationRequestLimitRecommendation {
    routeKey: string;
    requiredHeaders: RecommendationCandidate<string[]>;
    allowedContentTypes: RecommendationCandidate<string[]>;
    maxQueryParams: RecommendationCandidate<number>;
    maxQueryLength: RecommendationCandidate<number>;
    maxUriLength: RecommendationCandidate<number>;
    maxBodyBytes: RecommendationCandidate<number>;
    parameterConstraints: RecommendationCandidate<ParameterConstraintMetadata[]>;
}
export interface RouteRequestLimitRecommendation {
    path: string;
    allowedMethods: RecommendationCandidate<string[]>;
    operations: OperationRequestLimitRecommendation[];
}
export interface RequestLimitRecommendations {
    schemaVersion: 1;
    routes: RouteRequestLimitRecommendation[];
}
export interface RequestLimitRecommendationOptions {
    margin?: SafetyMarginOptions;
}
export declare function applySafetyMargin(value: number, options?: SafetyMarginOptions): AppliedSafetyMargin;
export declare function recommendRequestLimits(contract: SecurityContractV1, options?: RequestLimitRecommendationOptions): RequestLimitRecommendations;
