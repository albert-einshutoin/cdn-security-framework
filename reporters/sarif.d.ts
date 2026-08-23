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
            };
        };
    };
    results: SarifResult[];
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
export declare function renderFindingsAsSarif(report: ContractDiffReportV1): SarifLog;
export {};
