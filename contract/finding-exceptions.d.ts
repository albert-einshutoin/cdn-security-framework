import { type SecurityFindingV1 } from './finding';
export declare const WAIVABLE_FINDING_RULE_IDS: readonly ["SC-AUTHN-001", "SC-AUTHN-002", "SC-AUTHN-003", "SC-AUTHN-004", "SC-EXPOSURE-001", "SC-EXPOSURE-002", "SC-EXPOSURE-003", "SC-INVENTORY-002", "SC-LIMIT-001", "SC-LIMIT-002", "SC-REQUEST-001", "SC-REQUEST-002", "SC-REQUEST-003"];
export type FindingExceptionTarget = 'aws' | 'cloudflare';
export interface FindingExceptionSelectorV1 {
    instance_id?: string;
    method?: string;
    path?: string;
    target?: FindingExceptionTarget;
    environment?: string;
}
export interface FindingExceptionV1 {
    id: string;
    rule_id: string;
    selector: FindingExceptionSelectorV1;
    reason: string;
    owner: string;
    expires_at: string;
    ticket?: string;
    allow_broad?: boolean;
    broad_reason?: string;
}
export interface FindingExceptionSetV1 {
    version: 1;
    exceptions: FindingExceptionV1[];
}
export interface FindingExceptionContext {
    currentDate: string;
    target?: FindingExceptionTarget;
    environment?: string;
    sourceUri?: string;
}
export interface FindingExceptionValidationResult {
    valid: boolean;
    errors: string[];
}
export interface FindingExceptionReportV1 {
    findings: SecurityFindingV1[];
    suppressedFindings: SecurityFindingV1[];
    appliedExceptionIds: string[];
    summary: {
        before: number;
        after: number;
        suppressed: number;
        governance: number;
    };
}
export interface LoadFindingExceptionsOptions {
    inputPath: string;
    workspaceRoot: string;
    currentDate: string;
}
export interface LoadedFindingExceptions {
    exceptions: FindingExceptionSetV1;
    sourceIdentity: {
        sourcePath: string;
        device: number;
        inode: number;
    };
}
export declare function validateFindingExceptionSet(value: unknown, context: Pick<FindingExceptionContext, 'currentDate'>): FindingExceptionValidationResult;
export declare function loadFindingExceptions(options: LoadFindingExceptionsOptions): FindingExceptionSetV1;
export declare function loadFindingExceptionsWithIdentity(options: LoadFindingExceptionsOptions): LoadedFindingExceptions;
export declare function applyFindingExceptions(findings: readonly SecurityFindingV1[], set: FindingExceptionSetV1, context: FindingExceptionContext): FindingExceptionReportV1;
