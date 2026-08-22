import type { ApiOperationContractV1, SecurityContractV1 } from '../security-ir';
import type { AllowedRouteRuleV1, AllowedSurfaceModelV1, AllowedSurfaceTarget } from '../allowed-surface';
import type { FindingEvidenceV1, FindingInputV1, SecurityFindingV1 } from '../finding';
import { type RouteRelation } from '../route-relation';
export interface ContractDriftInput {
    declared: SecurityContractV1;
    allowed: AllowedSurfaceModelV1;
    target: AllowedSurfaceTarget;
}
export declare function pathRelation(operation: ApiOperationContractV1, policyPath: string, allowed: AllowedSurfaceModelV1, policyKind?: 'exact' | 'prefix'): RouteRelation;
export declare function policyEvidence(allowed: AllowedSurfaceModelV1, pointer: string, capability: string): FindingEvidenceV1;
export declare function evidenceFor(operation: ApiOperationContractV1, allowed: AllowedSurfaceModelV1, pointer: string, capability: string): FindingEvidenceV1[];
export declare function makeFinding(input: FindingInputV1): SecurityFindingV1;
export declare function stableFindings(findings: readonly SecurityFindingV1[]): SecurityFindingV1[];
export declare function matchingAuthRules(operation: ApiOperationContractV1, allowed: AllowedSurfaceModelV1): Array<{
    rule: AllowedRouteRuleV1;
    relation: RouteRelation;
}>;
export declare function validateComparisonInput(input: ContractDriftInput): void;
export declare function normalizedPathShape(value: string): string;
