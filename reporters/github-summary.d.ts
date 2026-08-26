import { type ContractDiffFailOn, type ContractDiffReportV1 } from '../contract/contract-diff';
export declare function renderContractDiffGitHubSummary(report: ContractDiffReportV1, options?: {
    failOn?: ContractDiffFailOn;
}): string;
export interface UnifiedGitHubSummaryOptions {
    maxFindings?: number;
    maxOutputBytes?: number;
}
export type UnifiedGitHubSummaryExecutionStatus = string | {
    status?: string;
    outcome?: string;
    kind?: string;
    result?: string;
    ok?: boolean;
    thresholdReached?: boolean;
    exitCode?: number;
    errorCode?: string;
    code?: string;
    phase?: string;
    safeMessage?: string;
    message?: string;
};
export declare function renderUnifiedGitHubSummary(report: ContractDiffReportV1 | null | undefined, executionStatus?: UnifiedGitHubSummaryExecutionStatus, options?: UnifiedGitHubSummaryOptions): string;
