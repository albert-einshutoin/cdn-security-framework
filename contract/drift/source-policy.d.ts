import type { AllowedSurfaceModelV1, AllowedSurfaceTarget } from '../allowed-surface';
import type { FindingEvidenceV1, SecurityFindingV1 } from '../finding';
import type { SecurityContractV1 } from '../security-ir';
export interface SourcePolicyDriftInput {
    implemented: SecurityContractV1;
    implementedEvidence: FindingEvidenceV1;
    allowed: AllowedSurfaceModelV1;
    target: AllowedSurfaceTarget;
}
export declare function compareSourcePolicyContracts(input: SourcePolicyDriftInput): SecurityFindingV1[];
