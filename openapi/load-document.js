"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadOpenApiDocument = loadOpenApiDocument;
const node_crypto_1 = require("node:crypto");
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const yaml = __importStar(require("js-yaml"));
const analysis_error_1 = require("./analysis-error");
const analysis_limits_1 = require("./analysis-limits");
const ref_boundary_1 = require("./ref-boundary");
const FORBIDDEN_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
function parseError(sourceUri, error) {
    const mark = error instanceof yaml.YAMLException ? error.mark : undefined;
    const reason = error instanceof yaml.YAMLException ? error.reason : '';
    if (/alias(?:es)?.*(?:limit|maxAliases)/i.test(reason)) {
        return new analysis_error_1.OpenApiAnalysisError('OPENAPI_YAML_ALIAS_LIMIT', { sourceUri });
    }
    if (/depth.*limit|maximum.*depth|maxDepth|nesting.*depth/i.test(reason)) {
        return new analysis_error_1.OpenApiAnalysisError('OPENAPI_NODE_LIMIT', { sourceUri });
    }
    return new analysis_error_1.OpenApiAnalysisError('OPENAPI_PARSE_ERROR', {
        sourceUri,
        ...(mark ? { line: mark.line + 1, column: mark.column + 1 } : {}),
    });
}
function parseDocument(source, sourceUri, limits) {
    const yamlOptions = {
        schema: yaml.JSON_SCHEMA,
        json: false,
        maxAliases: limits.maxYamlAliases,
        maxDepth: limits.maxSchemaDepth,
    };
    try {
        const json = JSON.parse(source);
        yaml.load(source, yamlOptions); // JSON subset pass also rejects duplicate mapping keys.
        return json;
    }
    catch (jsonError) {
        try {
            return yaml.load(source, yamlOptions);
        }
        catch (yamlError) {
            throw parseError(sourceUri, yamlError ?? jsonError);
        }
    }
}
function validateSafeValue(value, limits, state, ancestors, depth = 0) {
    state.nodes += 1;
    if (state.nodes > limits.maxNodes || depth > limits.maxSchemaDepth) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_NODE_LIMIT');
    }
    if (typeof value === 'string') {
        if (value.length > limits.maxStringLength)
            throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_NODE_LIMIT');
        return;
    }
    if (value === null || typeof value !== 'object')
        return;
    if (ancestors.has(value))
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_REF_CYCLE_LIMIT');
    if (!Array.isArray(value)) {
        const prototype = Object.getPrototypeOf(value);
        if (prototype !== Object.prototype && prototype !== null)
            throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_PARSE_ERROR');
    }
    ancestors.add(value);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    for (const [key, descriptor] of Object.entries(descriptors)) {
        if (!('value' in descriptor)
            || key.length > limits.maxStringLength
            || FORBIDDEN_KEYS.has(key)) {
            throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_PARSE_ERROR');
        }
        validateSafeValue(descriptor.value, limits, state, ancestors, depth + 1);
    }
    ancestors.delete(value);
}
function asRootDocument(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
        || Object.getPrototypeOf(value) !== Object.prototype) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_INVALID_ROOT');
    }
    const document = value;
    if (typeof document.openapi !== 'string'
        || (document.paths !== undefined
            && (document.paths === null || typeof document.paths !== 'object' || Array.isArray(document.paths)))) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_INVALID_ROOT');
    }
    return document;
}
function detectVersion(version) {
    const match = /^3\.(0|1)\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.exec(version);
    if (!match)
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_UNSUPPORTED_VERSION');
    return match[1] === '0' ? '3.0' : '3.1';
}
function loadOpenApiDocument(options) {
    if (!options || typeof options.inputPath !== 'string' || typeof options.workspaceRoot !== 'string') {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND');
    }
    const isNativeAbsolute = node_path_1.default.isAbsolute(options.inputPath);
    const isWindowsAbsolute = node_path_1.default.win32.isAbsolute(options.inputPath);
    if (!isNativeAbsolute && !isWindowsAbsolute
        && /^[A-Za-z][A-Za-z0-9+.-]*:/.test(options.inputPath)) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_REMOTE_REF_DISABLED');
    }
    const limits = (0, analysis_limits_1.validateOpenApiAnalysisLimits)({
        ...analysis_limits_1.DEFAULT_OPENAPI_ANALYSIS_LIMITS,
        ...(options.limits ?? {}),
    });
    const candidate = isNativeAbsolute || isWindowsAbsolute
        ? options.inputPath
        : node_path_1.default.resolve(options.workspaceRoot, options.inputPath);
    const resolvedPath = (0, ref_boundary_1.resolveOpenApiRefPath)({
        workspaceRoot: options.workspaceRoot,
        sourcePath: candidate,
        ref: '#',
    });
    let rootRealPath;
    try {
        rootRealPath = node_fs_1.default.realpathSync(options.workspaceRoot);
    }
    catch {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND', { sourceUri: options.inputPath });
    }
    if (!(0, ref_boundary_1.isPathWithinWorkspace)(rootRealPath, resolvedPath)) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_REF_OUTSIDE_ROOT', { sourceUri: candidate });
    }
    const sourceUri = node_path_1.default.relative(rootRealPath, resolvedPath).split(node_path_1.default.sep)
        .map((segment) => encodeURIComponent(segment)).join('/');
    let beforeRead;
    try {
        beforeRead = node_fs_1.default.statSync(resolvedPath);
    }
    catch {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND', { sourceUri });
    }
    if (!beforeRead.isFile())
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND', { sourceUri });
    if (beforeRead.size > limits.maxDocumentBytes) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_DOCUMENT_TOO_LARGE', { sourceUri });
    }
    let descriptor;
    let bytes;
    try {
        descriptor = node_fs_1.default.openSync(resolvedPath, node_fs_1.default.constants.O_RDONLY | (node_fs_1.default.constants.O_NOFOLLOW ?? 0));
        const opened = node_fs_1.default.fstatSync(descriptor);
        if (!opened.isFile() || opened.dev !== beforeRead.dev || opened.ino !== beforeRead.ino) {
            throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND', { sourceUri });
        }
        if (opened.size > limits.maxDocumentBytes) {
            throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_DOCUMENT_TOO_LARGE', { sourceUri });
        }
        const bounded = Buffer.allocUnsafe(limits.maxDocumentBytes + 1);
        let offset = 0;
        while (offset < bounded.length) {
            const read = node_fs_1.default.readSync(descriptor, bounded, offset, bounded.length - offset, null);
            if (read === 0)
                break;
            offset += read;
        }
        if (offset > limits.maxDocumentBytes) {
            throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_DOCUMENT_TOO_LARGE', { sourceUri });
        }
        bytes = bounded.subarray(0, offset);
    }
    catch (error) {
        if (error instanceof analysis_error_1.OpenApiAnalysisError)
            throw error;
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND', { sourceUri });
    }
    finally {
        if (descriptor !== undefined)
            node_fs_1.default.closeSync(descriptor);
    }
    let source;
    try {
        source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    }
    catch {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_PARSE_ERROR', { sourceUri });
    }
    const parsed = parseDocument(source, sourceUri, limits);
    validateSafeValue(parsed, limits, {
        nodes: 0,
    }, new Set());
    const document = asRootDocument(parsed);
    return {
        document,
        sourceUri,
        contentDigest: `sha256:${(0, node_crypto_1.createHash)('sha256').update(bytes).digest('hex')}`,
        version: detectVersion(document.openapi),
        byteSize: bytes.length,
        refStatus: 'unresolved',
    };
}
