"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.isPathWithinWorkspace = isPathWithinWorkspace;
exports.resolveOpenApiRefPath = resolveOpenApiRefPath;
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const analysis_error_1 = require("./analysis-error");
function pathImplementation(flavor) {
    if (flavor === 'posix')
        return node_path_1.default.posix;
    if (flavor === 'win32')
        return node_path_1.default.win32;
    return node_path_1.default;
}
function isPathWithinWorkspace(workspaceRoot, candidatePath, flavor = 'native') {
    const implementation = pathImplementation(flavor);
    const relative = implementation.relative(implementation.resolve(workspaceRoot), implementation.resolve(candidatePath));
    return relative === ''
        || (!relative.startsWith(`..${implementation.sep}`)
            && relative !== '..'
            && !implementation.isAbsolute(relative));
}
function resolveOpenApiRefPath(options) {
    const { workspaceRoot, sourcePath, ref } = options;
    const realpath = options.realpath ?? node_fs_1.default.realpathSync;
    if (/^https?:\/\//i.test(ref)) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_REMOTE_REF_DISABLED', { sourceUri: sourcePath });
    }
    const refPath = options.fragmentSeparated ? ref : ref.split('#', 1)[0];
    if (/^file:/i.test(refPath)
        || node_path_1.default.isAbsolute(refPath)
        || node_path_1.default.win32.isAbsolute(refPath)) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_REF_OUTSIDE_ROOT', { sourceUri: sourcePath });
    }
    if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(refPath)) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_REMOTE_REF_DISABLED', { sourceUri: sourcePath });
    }
    let rootRealPath;
    let sourceRealPath;
    try {
        rootRealPath = realpath(workspaceRoot);
        sourceRealPath = realpath(sourcePath);
    }
    catch {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND', { sourceUri: sourcePath });
    }
    if (!isPathWithinWorkspace(rootRealPath, sourceRealPath)) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_REF_OUTSIDE_ROOT', { sourceUri: sourcePath });
    }
    const lexicalCandidate = refPath
        ? node_path_1.default.resolve(node_path_1.default.dirname(sourceRealPath), refPath)
        : sourceRealPath;
    if (!isPathWithinWorkspace(rootRealPath, lexicalCandidate)) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_REF_OUTSIDE_ROOT', { sourceUri: sourcePath });
    }
    let candidateRealPath;
    try {
        candidateRealPath = realpath(lexicalCandidate);
    }
    catch {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND', { sourceUri: lexicalCandidate });
    }
    if (!isPathWithinWorkspace(rootRealPath, candidateRealPath)) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_REF_OUTSIDE_ROOT', { sourceUri: sourcePath });
    }
    return candidateRealPath;
}
