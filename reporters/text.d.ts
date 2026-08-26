import type { ContractDiffReportV1 } from '../contract/contract-diff';
export interface UnifiedContractDiffTextOptions {
    color?: boolean;
    maxFindings?: number;
    includeSuppressed?: boolean;
    maxOutputBytes?: number;
}
export declare function renderUnifiedContractDiffText(report: ContractDiffReportV1, options?: UnifiedContractDiffTextOptions): string;
