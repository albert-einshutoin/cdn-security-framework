import type { FindingEvidenceV1, SecurityFindingV1 } from '../finding';
import type { SecurityContractV1 } from '../security-ir';
export interface SourceOpenApiDriftInput {
    declared: SecurityContractV1;
    implemented: SecurityContractV1;
    declaredEvidence: FindingEvidenceV1;
    implementedEvidence: FindingEvidenceV1;
}
export interface SourceOpenApiDriftOptions {
    declaredPrivilegedRoles?: Readonly<Record<string, readonly string[]>>;
}
export declare function compareSourceOpenApiContracts(input: SourceOpenApiDriftInput, options?: SourceOpenApiDriftOptions): SecurityFindingV1[];
