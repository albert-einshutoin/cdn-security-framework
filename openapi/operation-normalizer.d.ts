import { type SecurityContractV1 } from '../contract';
import { type OpenApiAnalysisLimits } from './analysis-limits';
import type { ResolvedOpenApiGraph } from './document-graph';
export interface NormalizationOptions {
    limits?: Partial<OpenApiAnalysisLimits>;
}
export declare function normalizeOpenApiOperations(graph: ResolvedOpenApiGraph, options?: NormalizationOptions): SecurityContractV1;
