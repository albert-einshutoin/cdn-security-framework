import type { ContractDiffReportV1 } from '../contract/contract-diff';
export interface SarifLog {
    version: '2.1.0';
    $schema: string;
    runs: SarifRun[];
}
interface SarifRun {
    tool: {
        driver: {
            name: string;
            informationUri: string;
            rules: SarifRule[];
            properties: {
                analyzers: string[];
                findingSchemaVersion: number;
                reportSchemaVersion: number;
                capabilities?: {
                    openapi: Record<string, string>;
                    policy: Array<{
                        id: string;
                        status: string;
                    }>;
                };
                omittedComparisons?: string[];
                analyzerDiagnostics?: string[];
            };
        };
    };
    results: SarifResult[];
    invocations?: SarifInvocation[];
}
interface SarifInvocation {
    executionSuccessful: boolean;
    toolExecutionNotifications: Array<{
        descriptor: {
            id: string;
        };
        message: {
            text: string;
        };
    }>;
}
interface SarifRule {
    id: string;
    name: string;
    shortDescription: {
        text: string;
    };
    fullDescription: {
        text: string;
    };
    help: {
        text: string;
        markdown: string;
    };
    helpUri: string;
    defaultConfiguration: {
        level: SarifLevel;
    };
    properties: {
        category: string;
        confidence: string;
        tags: string[];
        evidenceSources?: string[];
        capabilities?: string[];
    };
}
interface SarifResult {
    ruleId: string;
    level: SarifLevel;
    message: {
        text: string;
    };
    partialFingerprints: {
        'securityContractFinding/v1': string;
    };
    locations?: SarifLocation[];
    relatedLocations?: SarifLocation[];
    suppressions?: Array<{
        kind: 'external';
        status: 'accepted';
    }>;
    properties: {
        category: string;
        confidence: string;
        tags: string[];
        evidenceSources?: string[];
        capabilities?: string[];
    };
}
interface SarifLocation {
    id?: number;
    message?: {
        text: string;
    };
    physicalLocation: {
        artifactLocation: {
            uri: string;
            uriBaseId: '%SRCROOT%';
        };
        region?: {
            startLine: number;
            startColumn?: number;
        };
        properties: {
            source: string;
            digest: string;
            analyzer: string;
            capability: string;
            complete: boolean;
        };
    };
    logicalLocations?: Array<{
        name: string;
        fullyQualifiedName: string;
        kind: 'jsonPointer';
    }>;
}
type SarifLevel = 'error' | 'warning' | 'note';
export declare const SARIF_ERROR_CODES: readonly ["SARIF_UNIFIED_REPORT_INVALID", "SARIF_LOCATION_INVALID", "SARIF_OUTPUT_LIMIT_EXCEEDED", "SARIF_PRIVACY_VIOLATION"];
export type SarifReportErrorCode = typeof SARIF_ERROR_CODES[number];
export declare class SarifReportError extends Error {
    readonly code: SarifReportErrorCode;
    constructor(code: SarifReportErrorCode, message: string);
}
export interface UnifiedContractDiffSarifOptions {
    maxRelatedLocations?: number;
    maxResults?: number;
    maxOutputBytes?: number;
}
export declare function renderFindingsAsSarif(report: ContractDiffReportV1): SarifLog;
export declare function renderUnifiedContractDiffSarif(report: ContractDiffReportV1, options?: UnifiedContractDiffSarifOptions): SarifLog;
export {};
