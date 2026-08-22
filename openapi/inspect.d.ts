import type { ExposureV1, SecurityContractCapabilitiesV1, SecurityContractV1 } from '../contract';
import { type OpenApiAnalysisLimits } from './analysis-limits';
export interface InspectOpenApiOptions {
    inputPath: string;
    workspaceRoot: string;
    limits?: Partial<OpenApiAnalysisLimits>;
}
export interface OpenApiInspectionDiagnosticV1 {
    code: 'OPENAPI_CAPABILITY_PARTIAL' | 'OPENAPI_CAPABILITY_UNSUPPORTED' | 'OPENAPI_LIMIT_NEAR';
    level: 'warning';
    message: string;
    capability?: keyof SecurityContractCapabilitiesV1;
    metric?: 'documentBytes' | 'graphBytes' | 'resolvedDocuments' | 'operations';
    used?: number;
    limit?: number;
}
export interface OpenApiInspectionV1 {
    schemaVersion: 1;
    analyzer: {
        name: 'cdn-security-openapi-inspect';
        version: 1;
        openapiVersion: '3.0' | '3.1';
        sourceDigest: string;
    };
    summary: {
        operationCount: number;
        exposures: Record<ExposureV1, number>;
        resolvedDocumentCount: number;
        referenceCount: number;
        totalByteSize: number;
    };
    capabilities: SecurityContractCapabilitiesV1;
    diagnostics: OpenApiInspectionDiagnosticV1[];
    contract: SecurityContractV1;
}
export declare function inspectOpenApi(options: InspectOpenApiOptions): OpenApiInspectionV1;
export declare function formatOpenApiInspectionJson(report: OpenApiInspectionV1): string;
export declare function formatOpenApiInspectionText(report: OpenApiInspectionV1): string;
