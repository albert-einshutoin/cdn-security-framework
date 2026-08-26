import type { ContractDiffReportV1 } from '../contract/contract-diff';
export declare const JSON_REPORT_ERROR_CODES: readonly ["JSON_REPORT_INPUT_INVALID", "JSON_REPORT_SCHEMA_INVALID", "JSON_REPORT_PRIVACY_VIOLATION", "JSON_REPORT_OUTPUT_LIMIT_EXCEEDED", "JSON_REPORT_SERIALIZATION_FAILED"];
export type JsonReportErrorCode = typeof JSON_REPORT_ERROR_CODES[number];
export declare class JsonReportError extends Error {
    readonly code: JsonReportErrorCode;
    constructor(code: JsonReportErrorCode, message: string);
}
export interface UnifiedContractDiffJsonOptions {
    pretty?: boolean;
    newline?: boolean;
    maxOutputBytes?: number;
}
export declare function renderUnifiedContractDiffJson(report: ContractDiffReportV1, options?: UnifiedContractDiffJsonOptions): string;
