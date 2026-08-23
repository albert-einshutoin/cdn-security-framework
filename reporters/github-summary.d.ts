import { type ContractDiffFailOn, type ContractDiffReportV1 } from '../contract/contract-diff';
export declare function renderContractDiffGitHubSummary(report: ContractDiffReportV1, options?: {
    failOn?: ContractDiffFailOn;
}): string;
