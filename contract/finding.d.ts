export declare const FINDING_SEVERITIES: readonly ["error", "warning", "info"];
export declare const FINDING_CONFIDENCES: readonly ["deterministic", "high-confidence", "heuristic"];
export declare const FINDING_CATEGORIES: readonly ["inventory", "exposure", "authentication", "authorization", "resource-limit", "misconfiguration", "governance", "runtime-evidence"];
export declare const FINDING_EVIDENCE_SOURCES: readonly ["openapi", "source-ast", "policy", "runtime", "generated-artifact"];
export type FindingSeverity = typeof FINDING_SEVERITIES[number];
export type FindingConfidence = typeof FINDING_CONFIDENCES[number];
export type FindingCategory = typeof FINDING_CATEGORIES[number];
export type FindingEvidenceSource = typeof FINDING_EVIDENCE_SOURCES[number];
export interface FindingRouteV1 {
    method?: string;
    path?: string;
    operationId?: string;
}
export interface FindingEvidenceV1 {
    source: FindingEvidenceSource;
    uri: string;
    pointer?: string;
    digest: string;
    analyzer: string;
    capability: string;
    complete: boolean;
}
export interface FindingRemediationV1 {
    summary: string;
    safeAutoFix: boolean;
}
export interface SecurityFindingV1 {
    schemaVersion: 1;
    ruleId: string;
    instanceId: string;
    severity: FindingSeverity;
    confidence: FindingConfidence;
    category: FindingCategory;
    title: string;
    message: string;
    route?: FindingRouteV1;
    expected?: unknown;
    actual?: unknown;
    evidence: FindingEvidenceV1[];
    remediation?: FindingRemediationV1;
    tags?: string[];
}
export type FindingInputV1 = Omit<SecurityFindingV1, 'schemaVersion' | 'instanceId'>;
export interface FindingCreationOptions {
    workspaceRoot?: string;
}
export declare function computeFindingInstanceId(finding: FindingInputV1, options?: FindingCreationOptions): string;
export declare function createFinding(input: FindingInputV1, options?: FindingCreationOptions): SecurityFindingV1;
