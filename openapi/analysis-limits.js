"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_OPENAPI_ANALYSIS_LIMITS = exports.OPENAPI_ANALYSIS_LIMIT_RANGES = void 0;
exports.validateOpenApiAnalysisLimits = validateOpenApiAnalysisLimits;
const analysis_error_1 = require("./analysis-error");
exports.OPENAPI_ANALYSIS_LIMIT_RANGES = Object.freeze({
    maxDocumentBytes: Object.freeze({ min: 1, max: 4 * 1024 * 1024 }),
    maxGraphBytes: Object.freeze({ min: 1, max: 256 * 1024 * 1024 }),
    maxResolvedDocuments: Object.freeze({ min: 1, max: 64 }),
    maxRefDepth: Object.freeze({ min: 1, max: 128 }),
    maxSchemaDepth: Object.freeze({ min: 1, max: 256 }),
    maxNodes: Object.freeze({ min: 1, max: 1_000_000 }),
    maxOperations: Object.freeze({ min: 1, max: 10_000 }),
    maxParametersPerOperation: Object.freeze({ min: 1, max: 500 }),
    maxSecuritySchemes: Object.freeze({ min: 1, max: 256 }),
    maxYamlAliases: Object.freeze({ min: 1, max: 1_000 }),
    maxStringLength: Object.freeze({ min: 1, max: 1024 * 1024 }),
    timeoutMs: Object.freeze({ min: 1, max: 60_000 }),
});
exports.DEFAULT_OPENAPI_ANALYSIS_LIMITS = Object.freeze({
    maxDocumentBytes: 2 * 1024 * 1024,
    maxGraphBytes: 64 * 1024 * 1024,
    maxResolvedDocuments: 32,
    maxRefDepth: 32,
    maxSchemaDepth: 64,
    maxNodes: 250_000,
    maxOperations: 2_000,
    maxParametersPerOperation: 100,
    maxSecuritySchemes: 64,
    maxYamlAliases: 100,
    maxStringLength: 64 * 1024,
    timeoutMs: 10_000,
});
const LIMIT_NAMES = Object.freeze(Object.keys(exports.OPENAPI_ANALYSIS_LIMIT_RANGES));
function validateOpenApiAnalysisLimits(input) {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_INVALID_LIMITS');
    }
    const record = input;
    if (Object.keys(record).length !== LIMIT_NAMES.length
        || Object.keys(record).some((key) => !LIMIT_NAMES.includes(key))) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_INVALID_LIMITS');
    }
    const validated = {};
    for (const name of LIMIT_NAMES) {
        const value = record[name];
        const range = exports.OPENAPI_ANALYSIS_LIMIT_RANGES[name];
        if (!Number.isInteger(value) || value < range.min || value > range.max) {
            throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_INVALID_LIMITS', {
                pointer: `/limits/${name}`,
            });
        }
        validated[name] = value;
    }
    return Object.freeze(validated);
}
