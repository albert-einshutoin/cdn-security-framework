"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.OpenApiAnalysisError = exports.OPENAPI_ANALYSIS_ERROR_CODES = void 0;
const node_path_1 = __importDefault(require("node:path"));
exports.OPENAPI_ANALYSIS_ERROR_CODES = [
    'OPENAPI_INPUT_NOT_FOUND',
    'OPENAPI_DOCUMENT_TOO_LARGE',
    'OPENAPI_UNSUPPORTED_VERSION',
    'OPENAPI_YAML_ALIAS_LIMIT',
    'OPENAPI_REF_OUTSIDE_ROOT',
    'OPENAPI_REMOTE_REF_DISABLED',
    'OPENAPI_REF_CYCLE_LIMIT',
    'OPENAPI_NODE_LIMIT',
    'OPENAPI_INVALID_LIMITS',
];
const SAFE_MESSAGES = {
    OPENAPI_INPUT_NOT_FOUND: 'OpenAPI input was not found.',
    OPENAPI_DOCUMENT_TOO_LARGE: 'OpenAPI document exceeds the configured size limit.',
    OPENAPI_UNSUPPORTED_VERSION: 'OpenAPI version is not supported.',
    OPENAPI_YAML_ALIAS_LIMIT: 'OpenAPI YAML alias limit was exceeded.',
    OPENAPI_REF_OUTSIDE_ROOT: 'OpenAPI reference is outside the workspace root.',
    OPENAPI_REMOTE_REF_DISABLED: 'Remote OpenAPI references are disabled.',
    OPENAPI_REF_CYCLE_LIMIT: 'OpenAPI reference cycle or depth limit was exceeded.',
    OPENAPI_NODE_LIMIT: 'OpenAPI analysis node limit was exceeded.',
    OPENAPI_INVALID_LIMITS: 'OpenAPI analysis limits are invalid.',
};
function safeSourceUri(sourceUri) {
    if (!sourceUri)
        return undefined;
    let withoutQuery = sourceUri.split(/[?#]/, 1)[0].replace(/\\/g, '/');
    if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(sourceUri)) {
        try {
            withoutQuery = new URL(sourceUri).pathname;
        }
        catch {
            return undefined;
        }
    }
    const filename = node_path_1.default.posix.basename(withoutQuery).replace(/[\u0000-\u001f\u007f]/g, '');
    return filename.slice(0, 255) || undefined;
}
function safePointer(pointer) {
    if (!pointer)
        return undefined;
    const cleaned = pointer
        .replace(/[\u0000-\u001f\u007f]/g, '')
        .replace(/\?.*$/, '')
        .replace(/(authorization|cookie|set[-_]?cookie|api[_-]?key|token|secret|password)\s*[:=]\s*[^/]+/gi, '$1=[REDACTED]')
        .replace(/\bBearer\s+[^/]+/gi, 'Bearer [REDACTED]');
    return cleaned.slice(0, 1_024) || undefined;
}
class OpenApiAnalysisError extends Error {
    code;
    safeMessage;
    sourceUri;
    pointer;
    constructor(code, options = {}) {
        const safeMessage = SAFE_MESSAGES[code];
        super(safeMessage);
        this.code = code;
        this.name = 'OpenApiAnalysisError';
        this.safeMessage = safeMessage;
        this.sourceUri = safeSourceUri(options.sourceUri);
        this.pointer = safePointer(options.pointer);
    }
    toJSON() {
        return {
            code: this.code,
            safeMessage: this.safeMessage,
            ...(this.sourceUri ? { sourceUri: this.sourceUri } : {}),
            ...(this.pointer ? { pointer: this.pointer } : {}),
        };
    }
}
exports.OpenApiAnalysisError = OpenApiAnalysisError;
