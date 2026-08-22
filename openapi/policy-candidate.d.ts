import type { SecurityContractV1 } from '../contract';
export declare const POLICY_CANDIDATE_GENERATOR_VERSION: 1;
export declare const POLICY_CANDIDATE_PROFILES: readonly ["strict", "balanced", "permissive"];
export type PolicyCandidateProfile = typeof POLICY_CANDIDATE_PROFILES[number];
export type PolicyObject = Record<string, unknown>;
export interface AppliedPolicyRecommendation {
    id: string;
    policyPath: string;
    basis: string[];
    value: unknown;
}
export interface OmittedPolicyRecommendation {
    id: string;
    reason: string;
    basis: string[];
}
export interface PolicyCandidateMetadataV1 {
    schemaVersion: 1;
    generator: {
        name: 'cdn-security-openapi-policy-candidate';
        version: typeof POLICY_CANDIDATE_GENERATOR_VERSION;
    };
    profile: PolicyCandidateProfile;
    sourceDigest: string;
    irDigest: string;
    candidateDigest: string;
    appliedRecommendations: AppliedPolicyRecommendation[];
    omittedRecommendations: OmittedPolicyRecommendation[];
    capabilityFindings: unknown[];
}
export interface GeneratePolicyCandidateOptions {
    profile: PolicyCandidateProfile;
    profilePolicy: PolicyObject;
    sourceDigest: string;
    evaluateCapabilities?: (policy: PolicyObject) => {
        findings: unknown[];
    };
}
export interface GeneratedPolicyCandidate {
    policy: PolicyObject;
    metadata: PolicyCandidateMetadataV1;
}
export declare function explainOpenApiPathPrefixMapping(openApiPath: string): string;
export declare function generatePolicyCandidate(contract: SecurityContractV1, options: GeneratePolicyCandidateOptions): GeneratedPolicyCandidate;
