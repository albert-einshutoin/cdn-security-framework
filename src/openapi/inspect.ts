import type {
  CapabilityLevelV1,
  ExposureV1,
  SecurityContractCapabilitiesV1,
  SecurityContractV1,
} from '../contract';
import {
  DEFAULT_OPENAPI_ANALYSIS_LIMITS,
  validateOpenApiAnalysisLimits,
  type OpenApiAnalysisLimits,
} from './analysis-limits';
import { loadOpenApiDocument } from './load-document';
import { normalizeOpenApiOperations } from './operation-normalizer';
import { resolveOpenApiReferences } from './ref-resolver';

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

export interface OpenApiInspectionForCli {
  report: OpenApiInspectionV1;
  sourcePaths: readonly string[];
}

const CAPABILITY_MESSAGES: Record<CapabilityLevelV1, string | undefined> = {
  complete: undefined,
  partial: 'OpenAPI capability is only partially supported.',
  unsupported: 'OpenAPI capability is unsupported.',
};

function limitDiagnostic(
  metric: OpenApiInspectionDiagnosticV1['metric'],
  used: number,
  limit: number,
): OpenApiInspectionDiagnosticV1 | undefined {
  if (used * 5 < limit * 4) return undefined;
  return {
    code: 'OPENAPI_LIMIT_NEAR',
    level: 'warning',
    message: 'OpenAPI analysis usage is near the configured limit.',
    metric,
    used,
    limit,
  };
}

function escapeTerminalText(value: string): string {
  return value.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, (character) => (
    `\\u{${character.codePointAt(0)?.toString(16).padStart(4, '0')}}`
  ));
}

export function inspectOpenApiForCli(options: InspectOpenApiOptions): OpenApiInspectionForCli {
  const limits = validateOpenApiAnalysisLimits({
    ...DEFAULT_OPENAPI_ANALYSIS_LIMITS,
    ...(options.limits ?? {}),
  });
  const root = loadOpenApiDocument({
    inputPath: options.inputPath,
    workspaceRoot: options.workspaceRoot,
    limits,
  });
  const graph = resolveOpenApiReferences({ root, workspaceRoot: options.workspaceRoot, limits });
  const contract = normalizeOpenApiOperations(graph, { limits });
  const exposures: Record<ExposureV1, number> = {
    public: 0,
    authenticated: 0,
    privileged: 0,
    unknown: 0,
  };
  for (const operation of contract.operations) exposures[operation.exposure] += 1;
  const diagnostics: OpenApiInspectionDiagnosticV1[] = [];
  for (const [capability, level] of Object.entries(contract.capabilities) as Array<
    [keyof SecurityContractCapabilitiesV1, CapabilityLevelV1]
  >) {
    const message = CAPABILITY_MESSAGES[level];
    if (message) diagnostics.push({
      code: level === 'partial' ? 'OPENAPI_CAPABILITY_PARTIAL' : 'OPENAPI_CAPABILITY_UNSUPPORTED',
      level: 'warning',
      message,
      capability,
    });
  }
  for (const diagnostic of [
    limitDiagnostic('documentBytes', root.byteSize, limits.maxDocumentBytes),
    limitDiagnostic('graphBytes', graph.totalByteSize, limits.maxGraphBytes),
    limitDiagnostic('resolvedDocuments', graph.documents.length, limits.maxResolvedDocuments),
    limitDiagnostic('operations', contract.operations.length, limits.maxOperations),
  ]) if (diagnostic) diagnostics.push(diagnostic);

  const report: OpenApiInspectionV1 = {
    schemaVersion: 1,
    analyzer: {
      name: 'cdn-security-openapi-inspect',
      version: 1,
      openapiVersion: root.version,
      sourceDigest: root.contentDigest,
    },
    summary: {
      operationCount: contract.operations.length,
      exposures,
      resolvedDocumentCount: graph.documents.length,
      referenceCount: graph.references.length,
      totalByteSize: graph.totalByteSize,
    },
    capabilities: contract.capabilities,
    diagnostics,
    contract,
  };
  const workspaceRoot = fs.realpathSync(options.workspaceRoot);
  return {
    report,
    sourcePaths: graph.documents.map(({ sourceUri }) => (
      path.resolve(workspaceRoot, ...sourceUri.split('/').map(decodeURIComponent))
    )),
  };
}

export function inspectOpenApi(options: InspectOpenApiOptions): OpenApiInspectionV1 {
  return inspectOpenApiForCli(options).report;
}

export function formatOpenApiInspectionJson(report: OpenApiInspectionV1): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

export function formatOpenApiInspectionText(report: OpenApiInspectionV1): string {
  const { exposures } = report.summary;
  const capabilities = Object.entries(report.capabilities)
    .map(([name, level]) => `${name}=${level}`).join(' ');
  const limitWarnings = report.diagnostics.filter(({ code }) => code === 'OPENAPI_LIMIT_NEAR');
  const routes = report.contract.operations.map((operation) => {
    const parameters = operation.request.queryParameters.length
      + operation.request.pathParameters.length
      + operation.request.headerParameters.length
      + operation.request.cookieParameters.length;
    return `${escapeTerminalText(operation.routeKey)} exposure=${operation.exposure} auth=${operation.auth.mode}`
      + ` content-types=${operation.request.contentTypes.map(escapeTerminalText).join(',') || '-'}`
      + ` parameters=${parameters}`;
  });
  return [
    `OpenAPI version: ${report.analyzer.openapiVersion}`,
    `Source digest: ${report.analyzer.sourceDigest}`,
    `Operations: ${report.summary.operationCount}`,
    `Exposure: public=${exposures.public} authenticated=${exposures.authenticated}`
      + ` privileged=${exposures.privileged} unknown=${exposures.unknown}`,
    `Capabilities: ${capabilities}`,
    `Limit warnings: ${limitWarnings.length || 'none'}`,
    'Routes:',
    ...(routes.length > 0 ? routes : ['(none)']),
    '',
  ].join('\n');
}
import fs from 'node:fs';
import path from 'node:path';
