import type { OpenApiInspectionDiagnosticV1 } from '../openapi/inspect';
import { type AllowedSurfaceTarget, type AllowedTargetCapabilityV1 } from './allowed-surface';
import { type FindingCategory, type FindingConfidence, type FindingSeverity, type SecurityFindingV1 } from './finding';
import { type SecurityContractCapabilitiesV1 } from './security-ir';
export declare const CONTRACT_DIFF_FAIL_ON: readonly ["error", "warning", "never"];
export type ContractDiffFailOn = typeof CONTRACT_DIFF_FAIL_ON[number];
export interface DiffSecurityContractsOptions {
    openapiPath: string;
    policyPath: string;
    target: AllowedSurfaceTarget;
    workspaceRoot: string;
    exceptionsPath?: string;
    currentDate?: string;
    includeSuppressed?: boolean;
}
export interface ContractDiffSummaryV1 {
    total: number;
    error: number;
    warning: number;
    info: number;
    suppressed: number;
    bySeverity: Record<FindingSeverity, number>;
    byConfidence: Record<FindingConfidence, number>;
    byCategory: Record<FindingCategory, number>;
}
export interface ContractDiffReportV1 {
    schemaVersion: 1;
    inputDigests: {
        openapi: string;
        policy: string;
        exceptions: string | null;
    };
    target: AllowedSurfaceTarget;
    summary: ContractDiffSummaryV1;
    findings: SecurityFindingV1[];
    suppressedFindings: SecurityFindingV1[];
    exceptionDiagnostics: SecurityFindingV1[];
    appliedExceptionIds: string[];
    analyzerCapabilities: {
        openapi: SecurityContractCapabilitiesV1;
        policy: AllowedTargetCapabilityV1[];
    };
    analyzerDiagnostics: OpenApiInspectionDiagnosticV1[];
    omittedComparisons: string[];
}
export declare class ContractDiffInputError extends Error {
    readonly code: string;
    constructor(code: string, message: string);
}
interface ContractDiffExecution {
    report: ContractDiffReportV1;
    sourcePaths: string[];
}
export declare function diffSecurityContracts(options: DiffSecurityContractsOptions): ContractDiffReportV1;
export declare function diffSecurityContractsForCli(options: DiffSecurityContractsOptions): ContractDiffExecution;
export declare function contractDiffExitCode(report: ContractDiffReportV1, failOn: ContractDiffFailOn): 0 | 1;
export declare function formatContractDiffJson(report: ContractDiffReportV1): string;
export declare function formatContractDiffText(report: ContractDiffReportV1, options?: {
    color?: boolean;
}): string;
export {};
