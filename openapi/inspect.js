"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.inspectOpenApi = inspectOpenApi;
exports.formatOpenApiInspectionJson = formatOpenApiInspectionJson;
exports.formatOpenApiInspectionText = formatOpenApiInspectionText;
const analysis_limits_1 = require("./analysis-limits");
const load_document_1 = require("./load-document");
const operation_normalizer_1 = require("./operation-normalizer");
const ref_resolver_1 = require("./ref-resolver");
const CAPABILITY_MESSAGES = {
    complete: undefined,
    partial: 'OpenAPI capability is only partially supported.',
    unsupported: 'OpenAPI capability is unsupported.',
};
function limitDiagnostic(metric, used, limit) {
    if (used * 5 < limit * 4)
        return undefined;
    return {
        code: 'OPENAPI_LIMIT_NEAR',
        level: 'warning',
        message: 'OpenAPI analysis usage is near the configured limit.',
        metric,
        used,
        limit,
    };
}
function escapeTerminalText(value) {
    return value.replace(/[\p{Cc}\p{Cf}]/gu, (character) => (`\\u{${character.codePointAt(0)?.toString(16).padStart(4, '0')}}`));
}
function inspectOpenApi(options) {
    const limits = (0, analysis_limits_1.validateOpenApiAnalysisLimits)({
        ...analysis_limits_1.DEFAULT_OPENAPI_ANALYSIS_LIMITS,
        ...(options.limits ?? {}),
    });
    const root = (0, load_document_1.loadOpenApiDocument)({
        inputPath: options.inputPath,
        workspaceRoot: options.workspaceRoot,
        limits,
    });
    const graph = (0, ref_resolver_1.resolveOpenApiReferences)({ root, workspaceRoot: options.workspaceRoot, limits });
    const contract = (0, operation_normalizer_1.normalizeOpenApiOperations)(graph, { limits });
    const exposures = {
        public: 0,
        authenticated: 0,
        privileged: 0,
        unknown: 0,
    };
    for (const operation of contract.operations)
        exposures[operation.exposure] += 1;
    const diagnostics = [];
    for (const [capability, level] of Object.entries(contract.capabilities)) {
        const message = CAPABILITY_MESSAGES[level];
        if (message)
            diagnostics.push({
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
    ])
        if (diagnostic)
            diagnostics.push(diagnostic);
    return {
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
}
function formatOpenApiInspectionJson(report) {
    return `${JSON.stringify(report, null, 2)}\n`;
}
function formatOpenApiInspectionText(report) {
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
