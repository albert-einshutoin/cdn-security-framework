"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SourceAnalyzerRegistry = exports.SourceAnalyzerContractError = exports.DEFAULT_SOURCE_ANALYSIS_LIMITS = exports.SOURCE_ANALYZER_LOG_CODES = exports.SOURCE_ANALYZER_DIAGNOSTIC_CODES = exports.SOURCE_ANALYZER_CAPABILITY_STATUSES = exports.SOURCE_ANALYZER_CAPABILITY_NAMES = void 0;
exports.validateSourceAnalysisLimits = validateSourceAnalysisLimits;
exports.validateSourceAnalyzerPlugin = validateSourceAnalyzerPlugin;
exports.runSourceAnalyzer = runSourceAnalyzer;
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const security_ir_1 = require("../contract/security-ir");
exports.SOURCE_ANALYZER_CAPABILITY_NAMES = [
    'routePaths',
    'httpMethods',
    'routerPrefixes',
    'globalPrefixes',
    'authentication',
    'authorization',
    'requestContentTypes',
    'requestLimits',
    'sourceLocations',
    'inheritedMetadata',
    'dynamicExpressions',
];
exports.SOURCE_ANALYZER_CAPABILITY_STATUSES = ['supported', 'partial', 'unsupported'];
exports.SOURCE_ANALYZER_DIAGNOSTIC_CODES = [
    'SOURCE_ANALYZER_INVALID_PLUGIN',
    'SOURCE_ANALYZER_DUPLICATE',
    'SOURCE_ANALYZER_UNKNOWN',
    'SOURCE_ANALYZER_INVALID_LIMITS',
    'SOURCE_ANALYZER_INPUT_INVALID',
    'SOURCE_ANALYZER_INPUT_OUTSIDE_ROOT',
    'SOURCE_ANALYZER_FILE_LIMIT',
    'SOURCE_ANALYZER_TOTAL_BYTES_LIMIT',
    'SOURCE_ANALYZER_FILE_BYTES_LIMIT',
    'SOURCE_ANALYZER_AST_NODE_LIMIT',
    'SOURCE_ANALYZER_DIAGNOSTIC_LIMIT',
    'SOURCE_ANALYZER_OPERATION_LIMIT',
    'SOURCE_ANALYZER_DEPTH_LIMIT',
    'SOURCE_ANALYZER_DYNAMIC_ROUTE',
    'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR',
    'SOURCE_ANALYZER_CANCELLED',
    'SOURCE_ANALYZER_TIMEOUT',
    'SOURCE_ANALYZER_INVALID_RESULT',
    'SOURCE_ANALYZER_INTERNAL',
];
const SOURCE_ANALYZER_RESULT_DIAGNOSTIC_CODES = [
    'SOURCE_ANALYZER_DYNAMIC_ROUTE',
    'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR',
];
exports.SOURCE_ANALYZER_LOG_CODES = [
    'SOURCE_ANALYZER_STARTED',
    'SOURCE_ANALYZER_COMPLETED',
    'SOURCE_ANALYZER_FAILED',
];
const SAFE_MESSAGES = Object.freeze({
    SOURCE_ANALYZER_INVALID_PLUGIN: 'Source analyzer plugin metadata is invalid.',
    SOURCE_ANALYZER_DUPLICATE: 'Source analyzer identity is already registered.',
    SOURCE_ANALYZER_UNKNOWN: 'Source analyzer identity is not registered.',
    SOURCE_ANALYZER_INVALID_LIMITS: 'Source analysis limits are invalid.',
    SOURCE_ANALYZER_INPUT_INVALID: 'Source analyzer input is invalid.',
    SOURCE_ANALYZER_INPUT_OUTSIDE_ROOT: 'Source analyzer input is outside the workspace root.',
    SOURCE_ANALYZER_FILE_LIMIT: 'Source analysis file limit was exceeded.',
    SOURCE_ANALYZER_TOTAL_BYTES_LIMIT: 'Source analysis total byte limit was exceeded.',
    SOURCE_ANALYZER_FILE_BYTES_LIMIT: 'Source analysis file byte limit was exceeded.',
    SOURCE_ANALYZER_AST_NODE_LIMIT: 'Source analysis AST node limit was exceeded.',
    SOURCE_ANALYZER_DIAGNOSTIC_LIMIT: 'Source analysis diagnostic limit was exceeded.',
    SOURCE_ANALYZER_OPERATION_LIMIT: 'Source analysis operation limit was exceeded.',
    SOURCE_ANALYZER_DEPTH_LIMIT: 'Source analysis depth limit was exceeded.',
    SOURCE_ANALYZER_DYNAMIC_ROUTE: 'A dynamic route expression could not be resolved statically.',
    SOURCE_ANALYZER_UNSUPPORTED_DECORATOR: 'A source decorator is not supported by this analyzer.',
    SOURCE_ANALYZER_CANCELLED: 'Source analysis was cancelled.',
    SOURCE_ANALYZER_TIMEOUT: 'Source analysis timed out.',
    SOURCE_ANALYZER_INVALID_RESULT: 'Source analyzer returned an invalid result.',
    SOURCE_ANALYZER_INTERNAL: 'Source analyzer failed unexpectedly.',
});
const LIMIT_RANGES = Object.freeze({
    maxFiles: Object.freeze({ min: 1, max: 100_000 }),
    maxTotalSourceBytes: Object.freeze({ min: 1, max: 1024 * 1024 * 1024 }),
    maxFileBytes: Object.freeze({ min: 1, max: 64 * 1024 * 1024 }),
    maxAstNodes: Object.freeze({ min: 1, max: 10_000_000 }),
    maxDiagnostics: Object.freeze({ min: 1, max: 100_000 }),
    maxOperations: Object.freeze({ min: 1, max: 100_000 }),
    maxAnalysisDepth: Object.freeze({ min: 1, max: 1_024 }),
    timeoutMs: Object.freeze({ min: 1, max: 300_000 }),
});
exports.DEFAULT_SOURCE_ANALYSIS_LIMITS = Object.freeze({
    maxFiles: 10_000,
    maxTotalSourceBytes: 128 * 1024 * 1024,
    maxFileBytes: 4 * 1024 * 1024,
    maxAstNodes: 1_000_000,
    maxDiagnostics: 1_000,
    maxOperations: 10_000,
    maxAnalysisDepth: 128,
    timeoutMs: 10_000,
});
const LIMIT_NAMES = Object.freeze(Object.keys(LIMIT_RANGES));
const METRIC_NAMES = Object.freeze([
    'files', 'totalSourceBytes', 'largestFileBytes', 'astNodes',
    'diagnostics', 'operations', 'maxDepth',
]);
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const SAFE_ID = /^[a-z][a-z0-9.-]{0,63}$/;
const SECRET_LIKE = /\b(?:Bearer|Basic)\s+\S+|\b(?:authorization|cookie|password|secret|client_secret|access_token|refresh_token|token|api[_-]?key)\s*[=:]\s*\S+/i;
class SourceAnalyzerContractError extends Error {
    code;
    safeMessage;
    constructor(code) {
        super(SAFE_MESSAGES[code]);
        this.code = code;
        this.name = 'SourceAnalyzerContractError';
        this.safeMessage = SAFE_MESSAGES[code];
    }
}
exports.SourceAnalyzerContractError = SourceAnalyzerContractError;
function safeText(value) {
    return typeof value === 'string' && value.length <= 1_024 && value.trim().length > 0
        && !/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(value) && !SECRET_LIKE.test(value);
}
function validateSourceAnalysisLimits(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_LIMITS');
    }
    const record = input;
    if (Object.keys(record).length !== LIMIT_NAMES.length
        || Object.keys(record).some((name) => !LIMIT_NAMES.includes(name))) {
        throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_LIMITS');
    }
    const output = {};
    for (const name of LIMIT_NAMES) {
        const value = record[name];
        const range = LIMIT_RANGES[name];
        if (!Number.isInteger(value) || value < range.min || value > range.max) {
            throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_LIMITS');
        }
        output[name] = value;
    }
    return Object.freeze(output);
}
function validateStringSet(value) {
    return Array.isArray(value) && value.length > 0 && value.length <= 128
        && value.every(safeText) && new Set(value).size === value.length;
}
function isSemanticVersion(value) {
    const match = SEMVER.exec(value);
    return Boolean(match) && !(match?.[4]?.split('.').some((identifier) => (/^\d+$/.test(identifier) && identifier.length > 1 && identifier.startsWith('0'))));
}
function validateSourceAnalyzerPlugin(input) {
    if (!input || typeof input !== 'object') {
        throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_PLUGIN');
    }
    const plugin = input;
    const capabilities = plugin.capabilities;
    if (!safeText(plugin.id) || !SAFE_ID.test(plugin.id)
        || !safeText(plugin.version) || !isSemanticVersion(plugin.version)
        || !validateStringSet(plugin.languages) || !validateStringSet(plugin.frameworks)
        || typeof plugin.analyze !== 'function' || !capabilities
        || Object.keys(capabilities).length !== exports.SOURCE_ANALYZER_CAPABILITY_NAMES.length
        || Object.keys(capabilities).some((name) => !exports.SOURCE_ANALYZER_CAPABILITY_NAMES.includes(name))) {
        throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_PLUGIN');
    }
    for (const name of exports.SOURCE_ANALYZER_CAPABILITY_NAMES) {
        const capability = capabilities[name];
        if (!capability || typeof capability !== 'object') {
            throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_PLUGIN');
        }
        const { status, reason } = capability;
        if (!exports.SOURCE_ANALYZER_CAPABILITY_STATUSES.includes(status)
            || !safeText(reason)) {
            throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_PLUGIN');
        }
    }
    return input;
}
function diagnostic(code, options = {}) {
    return {
        code,
        safeMessage: SAFE_MESSAGES[code],
        ...(options.sourceUri ? { sourceUri: options.sourceUri } : {}),
        ...(Number.isInteger(options.line) && options.line > 0 ? { line: options.line } : {}),
        ...(Number.isInteger(options.column) && options.column > 0 ? { column: options.column } : {}),
    };
}
function failed(code, options = {}) {
    return { status: 'failed', diagnostics: [diagnostic(code, options)] };
}
function relativeSourceUri(value, workspaceRoot) {
    if (value === undefined)
        return undefined;
    if (!safeText(value))
        throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
    const normalized = value.replace(/\\/g, '/');
    if (/[?#]/.test(normalized))
        throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
    const candidate = node_path_1.default.isAbsolute(value) ? node_path_1.default.resolve(value) : node_path_1.default.resolve(workspaceRoot, value);
    let absolute;
    try {
        absolute = node_fs_1.default.realpathSync(candidate);
    }
    catch {
        throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
    }
    const relative = node_path_1.default.relative(workspaceRoot, absolute).replace(/\\/g, '/');
    if (!relative || relative === '..' || relative.startsWith('../') || node_path_1.default.isAbsolute(relative)) {
        throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
    }
    return relative;
}
function validateMetrics(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
    }
    const record = input;
    if (Object.keys(record).length !== METRIC_NAMES.length
        || Object.keys(record).some((name) => !METRIC_NAMES.includes(name))) {
        throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
    }
    for (const name of METRIC_NAMES) {
        if (!Number.isInteger(record[name]) || record[name] < 0) {
            throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
        }
    }
    const metrics = record;
    if (metrics.largestFileBytes > metrics.totalSourceBytes) {
        throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
    }
    return { ...metrics };
}
const METRIC_LIMITS = [
    ['files', 'maxFiles', 'SOURCE_ANALYZER_FILE_LIMIT'],
    ['totalSourceBytes', 'maxTotalSourceBytes', 'SOURCE_ANALYZER_TOTAL_BYTES_LIMIT'],
    ['largestFileBytes', 'maxFileBytes', 'SOURCE_ANALYZER_FILE_BYTES_LIMIT'],
    ['astNodes', 'maxAstNodes', 'SOURCE_ANALYZER_AST_NODE_LIMIT'],
    ['diagnostics', 'maxDiagnostics', 'SOURCE_ANALYZER_DIAGNOSTIC_LIMIT'],
    ['operations', 'maxOperations', 'SOURCE_ANALYZER_OPERATION_LIMIT'],
    ['maxDepth', 'maxAnalysisDepth', 'SOURCE_ANALYZER_DEPTH_LIMIT'],
];
function exceededMetric(input, limits) {
    if (!input || typeof input !== 'object')
        return undefined;
    const metrics = input;
    for (const [metric, limit, code] of METRIC_LIMITS) {
        if (typeof metrics[metric] === 'number' && metrics[metric] > limits[limit])
            return code;
    }
    return undefined;
}
function validateResult(input, workspaceRoot, analyzerIdentity, capabilityStatuses) {
    if (!input || typeof input !== 'object') {
        throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
    }
    const candidate = input;
    if (!Array.isArray(candidate.diagnostics)) {
        throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
    }
    const metrics = validateMetrics(candidate.metrics);
    let contract;
    try {
        contract = (0, security_ir_1.createSecurityContract)(candidate.contract);
    }
    catch {
        throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
    }
    if (contract.source !== 'source-ast' || metrics.operations !== contract.operations.length
        || metrics.diagnostics !== candidate.diagnostics.length) {
        throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
    }
    if (contract.operations.some(({ provenance }) => provenance.some((evidence) => (evidence.source !== 'source-ast'
        || evidence.analyzer !== analyzerIdentity
        || !exports.SOURCE_ANALYZER_CAPABILITY_NAMES.includes(evidence.capability)
        || capabilityStatuses[evidence.capability] === 'unsupported'
        || relativeSourceUri(evidence.uri, workspaceRoot) !== evidence.uri)))) {
        throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
    }
    const diagnostics = candidate.diagnostics.map((value) => {
        if (!value || typeof value !== 'object') {
            throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
        }
        const item = value;
        if (!SOURCE_ANALYZER_RESULT_DIAGNOSTIC_CODES.includes(item.code)) {
            throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INVALID_RESULT');
        }
        return diagnostic(item.code, {
            sourceUri: relativeSourceUri(item.sourceUri, workspaceRoot),
            line: item.line,
            column: item.column,
        });
    });
    return { contract, diagnostics, metrics };
}
function log(logger, code) {
    try {
        Promise.resolve(logger.log(code)).catch(() => { });
    }
    catch { /* Logging must not change analysis results. */ }
}
function preflight(context, limits) {
    if (!Array.isArray(context.entrypoints) || context.entrypoints.length === 0) {
        return failed('SOURCE_ANALYZER_INPUT_INVALID');
    }
    if (context.entrypoints.length > limits.maxFiles)
        return failed('SOURCE_ANALYZER_FILE_LIMIT');
    let workspaceRoot;
    try {
        workspaceRoot = node_fs_1.default.realpathSync(context.workspaceRoot);
    }
    catch {
        return failed('SOURCE_ANALYZER_INPUT_INVALID');
    }
    let totalBytes = 0;
    const entrypoints = [];
    for (const entrypoint of context.entrypoints) {
        if (!safeText(entrypoint) || /[?#]/.test(entrypoint))
            return failed('SOURCE_ANALYZER_INPUT_INVALID');
        const candidate = node_path_1.default.resolve(workspaceRoot, entrypoint);
        let realPath;
        let stat;
        try {
            realPath = node_fs_1.default.realpathSync(candidate);
            stat = node_fs_1.default.statSync(realPath);
        }
        catch {
            return failed('SOURCE_ANALYZER_INPUT_INVALID');
        }
        const relative = node_path_1.default.relative(workspaceRoot, realPath).replace(/\\/g, '/');
        if (!relative || relative === '..' || relative.startsWith('../') || node_path_1.default.isAbsolute(relative)) {
            return failed('SOURCE_ANALYZER_INPUT_OUTSIDE_ROOT');
        }
        if (!stat.isFile())
            return failed('SOURCE_ANALYZER_INPUT_INVALID');
        if (stat.size > limits.maxFileBytes)
            return failed('SOURCE_ANALYZER_FILE_BYTES_LIMIT', { sourceUri: relative });
        totalBytes += stat.size;
        if (totalBytes > limits.maxTotalSourceBytes)
            return failed('SOURCE_ANALYZER_TOTAL_BYTES_LIMIT');
        entrypoints.push(relative);
    }
    return { workspaceRoot, entrypoints: [...new Set(entrypoints)].sort() };
}
async function runSourceAnalyzer(input, context) {
    let plugin;
    let limits;
    try {
        plugin = validateSourceAnalyzerPlugin(input);
        limits = validateSourceAnalysisLimits(context.limits);
    }
    catch (error) {
        return failed(error instanceof SourceAnalyzerContractError ? error.code : 'SOURCE_ANALYZER_INTERNAL');
    }
    if (context.cancellationSignal?.aborted)
        return failed('SOURCE_ANALYZER_CANCELLED');
    const analyzerIdentity = `${plugin.id}@${plugin.version}`;
    const capabilityStatuses = Object.fromEntries(exports.SOURCE_ANALYZER_CAPABILITY_NAMES.map((name) => ([name, plugin.capabilities[name].status])));
    const prepared = preflight(context, limits);
    if ('status' in prepared)
        return prepared;
    const controller = new AbortController();
    let interrupted;
    const interrupt = (code) => {
        if (!controller.signal.aborted) {
            interrupted = code;
            controller.abort();
        }
    };
    const onCancel = () => interrupt('SOURCE_ANALYZER_CANCELLED');
    context.cancellationSignal?.addEventListener('abort', onCancel, { once: true });
    const timeout = setTimeout(() => interrupt('SOURCE_ANALYZER_TIMEOUT'), limits.timeoutMs);
    const safeLogger = {
        log(code) {
            if (exports.SOURCE_ANALYZER_LOG_CODES.includes(code))
                log(context.logger, code);
        },
    };
    log(context.logger, 'SOURCE_ANALYZER_STARTED');
    const startedAt = performance.now();
    try {
        const aborted = new Promise((_, reject) => {
            controller.signal.addEventListener('abort', () => reject(new Error('analysis interrupted')), { once: true });
        });
        const result = await Promise.race([
            Promise.resolve().then(() => plugin.analyze({
                workspaceRoot: prepared.workspaceRoot,
                entrypoints: prepared.entrypoints,
                limits: { ...limits },
                cancellationSignal: controller.signal,
                logger: safeLogger,
            })),
            aborted,
        ]);
        if (context.cancellationSignal?.aborted) {
            interrupted = 'SOURCE_ANALYZER_CANCELLED';
            throw new SourceAnalyzerContractError(interrupted);
        }
        if (performance.now() - startedAt >= limits.timeoutMs) {
            interrupted = 'SOURCE_ANALYZER_TIMEOUT';
            throw new SourceAnalyzerContractError(interrupted);
        }
        const limitCode = exceededMetric(result.metrics, limits);
        if (limitCode)
            throw new SourceAnalyzerContractError(limitCode);
        const validated = validateResult(result, prepared.workspaceRoot, analyzerIdentity, capabilityStatuses);
        log(context.logger, 'SOURCE_ANALYZER_COMPLETED');
        return { status: 'success', result: validated };
    }
    catch (error) {
        log(context.logger, 'SOURCE_ANALYZER_FAILED');
        return failed(interrupted
            ?? (error instanceof SourceAnalyzerContractError ? error.code : 'SOURCE_ANALYZER_INTERNAL'));
    }
    finally {
        clearTimeout(timeout);
        context.cancellationSignal?.removeEventListener('abort', onCancel);
    }
}
class SourceAnalyzerRegistry {
    plugins = new Map();
    constructor(plugins = []) {
        for (const plugin of plugins)
            this.register(plugin);
    }
    register(input) {
        const plugin = validateSourceAnalyzerPlugin(input);
        const key = `${plugin.id}@${plugin.version}`;
        if (this.plugins.has(key))
            throw new SourceAnalyzerContractError('SOURCE_ANALYZER_DUPLICATE');
        this.plugins.set(key, plugin);
    }
    get(id, version) {
        const plugin = this.plugins.get(`${id}@${version}`);
        if (!plugin)
            throw new SourceAnalyzerContractError('SOURCE_ANALYZER_UNKNOWN');
        return plugin;
    }
    list() {
        return [...this.plugins.values()].sort((left, right) => {
            const leftKey = `${left.id}@${left.version}`;
            const rightKey = `${right.id}@${right.version}`;
            return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
        });
    }
}
exports.SourceAnalyzerRegistry = SourceAnalyzerRegistry;
