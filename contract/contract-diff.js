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
exports.ContractDiffInputError = exports.CONTRACT_DIFF_FAIL_ON = void 0;
exports.diffSecurityContracts = diffSecurityContracts;
exports.diffSecurityContractsForCli = diffSecurityContractsForCli;
exports.contractDiffExitCode = contractDiffExitCode;
exports.formatContractDiffJson = formatContractDiffJson;
exports.formatContractDiffText = formatContractDiffText;
const node_crypto_1 = require("node:crypto");
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const yaml = __importStar(require("js-yaml"));
const allowed_surface_1 = require("./allowed-surface");
const drift_1 = require("./drift");
const finding_exceptions_1 = require("./finding-exceptions");
const finding_1 = require("./finding");
const finding_order_1 = require("./finding-order");
const security_ir_1 = require("./security-ir");
exports.CONTRACT_DIFF_FAIL_ON = ['error', 'warning', 'never'];
class ContractDiffInputError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.code = code;
        this.name = 'ContractDiffInputError';
    }
}
exports.ContractDiffInputError = ContractDiffInputError;
const MAX_POLICY_FILE_BYTES = 1_048_576;
const MAX_POLICY_GRAPH_BYTES = 4_194_304;
const MAX_POLICY_SOURCES = 32;
function compareText(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
function within(root, candidate) {
    const relative = node_path_1.default.relative(root, candidate);
    return relative !== '' && relative !== '..' && !relative.startsWith(`..${node_path_1.default.sep}`)
        && !node_path_1.default.isAbsolute(relative);
}
function packageRoot() {
    const compiled = node_path_1.default.join(__dirname, '..');
    return node_fs_1.default.existsSync(node_path_1.default.join(compiled, 'policy', 'schema.json'))
        ? compiled
        : node_path_1.default.join(__dirname, '..', '..');
}
function canonicalJson(value) {
    if (Array.isArray(value))
        return `[${value.map(canonicalJson).join(',')}]`;
    if (value && typeof value === 'object') {
        const record = value;
        return `{${Object.keys(record).sort(compareText)
            .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(',')}}`;
    }
    return JSON.stringify(value) ?? 'null';
}
function digest(value) {
    return `sha256:${(0, node_crypto_1.createHash)('sha256').update(value).digest('hex')}`;
}
function semanticDigest(value) {
    return digest(canonicalJson(value));
}
function workspaceRoot(input) {
    if (typeof input !== 'string' || !input.trim()) {
        throw new ContractDiffInputError('CONTRACT_DIFF_WORKSPACE_INVALID', 'Workspace root is invalid.');
    }
    try {
        const root = node_fs_1.default.realpathSync(node_path_1.default.resolve(input));
        if (!node_fs_1.default.statSync(root).isDirectory())
            throw new Error('not a directory');
        return root;
    }
    catch {
        throw new ContractDiffInputError('CONTRACT_DIFF_WORKSPACE_INVALID', 'Workspace root was not found.');
    }
}
function inputFile(root, input, code, label) {
    if (typeof input !== 'string' || !input.trim()) {
        throw new ContractDiffInputError(code, `${label} path is required.`);
    }
    const candidate = node_path_1.default.resolve(root, input);
    try {
        const resolved = node_fs_1.default.realpathSync(candidate);
        if (!within(root, resolved) || !node_fs_1.default.statSync(resolved).isFile())
            throw new Error('invalid input');
        return resolved;
    }
    catch {
        throw new ContractDiffInputError(code, `${label} was not found inside the workspace root.`);
    }
}
function readBoundedPolicyFile(root, filePath) {
    let descriptor;
    try {
        descriptor = node_fs_1.default.openSync(filePath, node_fs_1.default.constants.O_RDONLY | (node_fs_1.default.constants.O_NOFOLLOW ?? 0) | (node_fs_1.default.constants.O_NONBLOCK ?? 0));
        const stat = node_fs_1.default.fstatSync(descriptor);
        const currentPath = node_fs_1.default.realpathSync(filePath);
        const currentStat = node_fs_1.default.statSync(currentPath);
        if (!within(root, currentPath) || currentStat.dev !== stat.dev || currentStat.ino !== stat.ino) {
            throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_OUTSIDE_ROOT', 'Policy input changed outside the workspace boundary.');
        }
        if (!stat.isFile() || stat.size > MAX_POLICY_FILE_BYTES) {
            throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_INVALID', 'Policy input is not a bounded regular file.');
        }
        const source = Buffer.allocUnsafe(MAX_POLICY_FILE_BYTES + 1);
        let bytes = 0;
        while (bytes < source.length) {
            const count = node_fs_1.default.readSync(descriptor, source, bytes, source.length - bytes, bytes);
            if (count === 0)
                break;
            bytes += count;
        }
        if (bytes > MAX_POLICY_FILE_BYTES) {
            throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_LIMIT', 'Policy input exceeds the file size limit.');
        }
        const content = source.subarray(0, bytes).toString('utf8');
        let parsed;
        try {
            parsed = yaml.load(content, {
                schema: yaml.JSON_SCHEMA,
                json: false,
                maxAliases: 50,
                maxDepth: 64,
            });
        }
        catch {
            throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_INVALID', 'Policy input could not be parsed safely.');
        }
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
            || Object.getPrototypeOf(parsed) !== Object.prototype) {
            throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_INVALID', 'Policy input root is invalid.');
        }
        return {
            document: parsed, content, digest: digest(content), bytes,
            device: stat.dev, inode: stat.ino,
        };
    }
    catch (error) {
        if (error instanceof ContractDiffInputError)
            throw error;
        throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_INVALID', 'Policy input could not be read safely.');
    }
    finally {
        if (descriptor !== undefined)
            try {
                node_fs_1.default.closeSync(descriptor);
            }
            catch { }
    }
}
function policySources(root, entryPath) {
    const sources = [];
    const aliases = new Map();
    const active = new Set();
    let totalBytes = 0;
    let visits = 0;
    const visit = (filePath, lexicalPath = filePath) => {
        aliases.set(lexicalPath, filePath);
        if (active.has(lexicalPath)) {
            throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_INVALID', 'Policy extends contains a cycle.');
        }
        visits += 1;
        if (visits > MAX_POLICY_SOURCES) {
            throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_LIMIT', 'Policy source count limit was exceeded.');
        }
        active.add(lexicalPath);
        const loaded = readBoundedPolicyFile(root, filePath);
        totalBytes += loaded.bytes;
        if (totalBytes > MAX_POLICY_GRAPH_BYTES) {
            throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_LIMIT', 'Policy source size limit was exceeded.');
        }
        const parent = loaded.document.extends;
        if (parent !== undefined) {
            if (typeof parent !== 'string' || !parent.trim()) {
                throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_INVALID', 'Policy extends is invalid.');
            }
            const lexicalParentPath = node_path_1.default.resolve(node_path_1.default.dirname(lexicalPath), parent.trim());
            const parentPath = inputFile(root, lexicalParentPath, 'CONTRACT_DIFF_POLICY_OUTSIDE_ROOT', 'Policy extends target');
            visit(parentPath, lexicalParentPath);
        }
        active.delete(lexicalPath);
        if (!sources.some((source) => source.filePath === filePath)) {
            sources.push({
                filePath, digest: loaded.digest, content: loaded.content,
                device: loaded.device, inode: loaded.inode,
            });
        }
    };
    visit(entryPath);
    return { aliases, sources };
}
function loadPolicy(root, policyPath) {
    const { parsePolicyFile } = require(node_path_1.default.join(packageRoot(), 'parser'));
    const { validatePolicy } = require(node_path_1.default.join(packageRoot(), 'validator'));
    const before = policySources(root, policyPath);
    const snapshots = new Map(before.sources.map(({ filePath, content }) => [filePath, content]));
    const parsed = parsePolicyFile({
        policyPath,
        readPolicyFile: (absolutePath) => {
            const lexicalPath = node_path_1.default.resolve(absolutePath);
            const resolvedPath = before.aliases.get(lexicalPath) ?? lexicalPath;
            const content = snapshots.get(resolvedPath);
            if (content === undefined)
                throw new Error('policy source is outside the verified snapshot');
            return content;
        },
    });
    if (!parsed.ok || !parsed.policy) {
        throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_INVALID', 'Policy input is invalid.');
    }
    const validation = validatePolicy({ policy: parsed.policy, pkgRoot: packageRoot(), env: {} });
    if (!validation.ok) {
        throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_INVALID', 'Policy input failed schema validation.');
    }
    const after = policySources(root, policyPath);
    const identity = ({ aliases, sources }) => ({
        aliases: [...aliases].sort(([left], [right]) => compareText(left, right)),
        sources: sources.map(({ filePath, digest }) => ({ filePath, digest })),
    });
    if (canonicalJson(identity(before)) !== canonicalJson(identity(after))) {
        throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_CHANGED', 'Policy input changed during analysis.');
    }
    return { policy: parsed.policy, sources: before.sources };
}
function sourceUri(root, filePath) {
    return node_path_1.default.relative(root, filePath).split(node_path_1.default.sep).map(encodeURIComponent).join('/');
}
function emptyCounts(values) {
    return Object.fromEntries(values.map((value) => [value, 0]));
}
function summary(active, suppressed) {
    const bySeverity = emptyCounts(finding_1.FINDING_SEVERITIES);
    const byConfidence = emptyCounts(finding_1.FINDING_CONFIDENCES);
    const byCategory = emptyCounts(finding_1.FINDING_CATEGORIES);
    for (const finding of active) {
        bySeverity[finding.severity] += 1;
        byConfidence[finding.confidence] += 1;
        byCategory[finding.category] += 1;
    }
    return {
        total: active.length,
        error: bySeverity.error,
        warning: bySeverity.warning,
        info: bySeverity.info,
        suppressed: suppressed.length,
        bySeverity,
        byConfidence,
        byCategory,
    };
}
function omittedComparisons(capabilities, policyCapabilities) {
    return [
        ...Object.entries(capabilities)
            .filter(([, status]) => status !== 'complete')
            .map(([name, status]) => `openapi.${name}:${status}`),
        ...policyCapabilities
            .filter(({ status }) => status !== 'supported')
            .map(({ id, status }) => `policy.${id}:${status}`),
    ].sort(compareText);
}
function execute(options) {
    if (!options || !['aws', 'cloudflare'].includes(options.target)) {
        throw new ContractDiffInputError('CONTRACT_DIFF_TARGET_INVALID', 'Target must be aws or cloudflare.');
    }
    if (options.environment !== undefined
        && (!options.environment.trim() || options.environment.length > 128)) {
        throw new ContractDiffInputError('CONTRACT_DIFF_ENVIRONMENT_INVALID', 'Environment must be 1 to 128 characters.');
    }
    const root = workspaceRoot(options.workspaceRoot);
    const rootStat = node_fs_1.default.statSync(root);
    const openapiPath = inputFile(root, options.openapiPath, 'CONTRACT_DIFF_OPENAPI_INVALID', 'OpenAPI input');
    const policyPath = inputFile(root, options.policyPath, 'CONTRACT_DIFF_POLICY_INVALID', 'Policy input');
    const { inspectOpenApiForCli } = require(node_path_1.default.join(packageRoot(), 'openapi', 'inspect'));
    const inspection = inspectOpenApiForCli({ inputPath: openapiPath, workspaceRoot: root });
    const loadedPolicy = loadPolicy(root, policyPath);
    const policyDigest = semanticDigest(loadedPolicy.policy);
    const allowed = (0, allowed_surface_1.projectPolicyToAllowedSurface)(loadedPolicy.policy, {
        policyDigest,
        sourceUri: sourceUri(root, policyPath),
    });
    let findings;
    try {
        findings = (0, drift_1.compareSecurityContracts)({
            declared: inspection.report.contract,
            allowed,
            target: options.target,
        });
    }
    catch (error) {
        if (error instanceof Error && /invalid contract drift input|visit budget/.test(error.message)) {
            throw new ContractDiffInputError('CONTRACT_DIFF_COMPARISON_LIMIT', 'Contract comparison input is invalid or exceeds its limit.');
        }
        throw error;
    }
    let suppressedFindings = [];
    let exceptionDiagnostics = [];
    let appliedExceptionIds = [];
    let exceptionsDigest = null;
    const sourceIdentities = [
        ...inspection.sourceIdentities,
        ...loadedPolicy.sources.map(({ filePath: sourcePath, device, inode }) => ({ sourcePath, device, inode })),
    ];
    if (options.exceptionsPath) {
        const exceptionsPath = inputFile(root, options.exceptionsPath, 'CONTRACT_DIFF_EXCEPTIONS_INVALID', 'Finding exceptions input');
        let exceptions;
        try {
            const currentDate = options.currentDate ?? new Date().toISOString().slice(0, 10);
            const loadedExceptions = (0, finding_exceptions_1.loadFindingExceptionsWithIdentity)({
                inputPath: exceptionsPath,
                workspaceRoot: root,
                currentDate,
            });
            exceptions = loadedExceptions.exceptions;
            sourceIdentities.push(loadedExceptions.sourceIdentity);
            const applied = (0, finding_exceptions_1.applyFindingExceptions)(findings, exceptions, {
                currentDate,
                target: options.target,
                environment: options.environment,
                sourceUri: sourceUri(root, exceptionsPath),
            });
            findings = applied.findings.filter(({ category }) => category !== 'governance');
            exceptionDiagnostics = applied.findings.filter(({ category }) => category === 'governance');
            suppressedFindings = applied.suppressedFindings;
            appliedExceptionIds = applied.appliedExceptionIds;
            exceptionsDigest = semanticDigest({ exceptions, currentDate });
        }
        catch (error) {
            if (error instanceof ContractDiffInputError)
                throw error;
            throw new ContractDiffInputError('CONTRACT_DIFF_EXCEPTIONS_INVALID', 'Finding exceptions input is invalid.');
        }
    }
    const active = [...findings, ...exceptionDiagnostics];
    const policyCapabilities = allowed.targetCapabilities[options.target];
    return {
        report: {
            schemaVersion: 1,
            inputDigests: {
                openapi: digest((0, security_ir_1.serializeSecurityContract)(inspection.report.contract)),
                policy: policyDigest,
                exceptions: exceptionsDigest,
            },
            target: options.target,
            summary: summary(active, suppressedFindings),
            findings,
            suppressedFindings: options.includeSuppressed ? suppressedFindings : [],
            exceptionDiagnostics,
            appliedExceptionIds,
            analyzerCapabilities: {
                openapi: inspection.report.capabilities,
                policy: policyCapabilities,
            },
            analyzerDiagnostics: inspection.report.diagnostics,
            omittedComparisons: omittedComparisons(inspection.report.capabilities, policyCapabilities),
        },
        sourceIdentities: sourceIdentities
            .filter((identity, index, values) => values.findIndex(({ device, inode }) => (device === identity.device && inode === identity.inode)) === index)
            .sort((left, right) => compareText(left.sourcePath, right.sourcePath)),
        workspace: { root, device: rootStat.dev, inode: rootStat.ino },
    };
}
function diffSecurityContracts(options) {
    return execute(options).report;
}
function diffSecurityContractsForCli(options) {
    return execute(options);
}
function contractDiffExitCode(report, failOn) {
    if (!exports.CONTRACT_DIFF_FAIL_ON.includes(failOn)) {
        throw new ContractDiffInputError('CONTRACT_DIFF_FAIL_ON_INVALID', 'fail-on must be error, warning, or never.');
    }
    if (failOn === 'never')
        return 0;
    if (report.summary.error > 0)
        return 1;
    return failOn === 'warning' && report.summary.warning > 0 ? 1 : 0;
}
function formatContractDiffJson(report) {
    return `${JSON.stringify(report, null, 2)}\n`;
}
function terminalText(value) {
    return value.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, (character) => (`\\u{${character.codePointAt(0)?.toString(16).padStart(4, '0')}}`));
}
function findingLines(finding, color) {
    const labels = { error: '\u001b[31mERROR\u001b[0m', warning: '\u001b[33mWARNING\u001b[0m', info: '\u001b[36mINFO\u001b[0m' };
    const label = color ? labels[finding.severity] : finding.severity.toUpperCase();
    const route = finding.route ? `${finding.route.method ?? '*'} ${finding.route.path ?? '*'}` : '-';
    const details = [
        finding.expected === undefined ? undefined : `expected=${terminalText(JSON.stringify(finding.expected) ?? 'null')}`,
        finding.actual === undefined ? undefined : `actual=${terminalText(JSON.stringify(finding.actual) ?? 'null')}`,
    ].filter((value) => Boolean(value)).join(' ');
    return [
        `${label} ${finding.ruleId} ${terminalText(route)} ${terminalText(finding.title)}`,
        ...(details ? [`  ${details}`] : []),
        ...finding.evidence.map(({ uri, pointer }) => `  evidence=${terminalText(uri)}${terminalText(pointer ?? '')}`),
        ...(finding.remediation ? [`  remediation=${terminalText(finding.remediation.summary)}`] : []),
    ];
}
function formatContractDiffText(report, options = {}) {
    const active = (0, finding_order_1.sortFindings)([...report.findings, ...report.exceptionDiagnostics]);
    return [
        `Summary: total=${report.summary.total} error=${report.summary.error}`
            + ` warning=${report.summary.warning} info=${report.summary.info}`
            + ` suppressed=${report.summary.suppressed}`,
        `Target: ${report.target}`,
        `OpenAPI digest: ${report.inputDigests.openapi}`,
        `Policy digest: ${report.inputDigests.policy}`,
        `Omitted/unknown comparisons: ${report.omittedComparisons.length || 'none'}`,
        ...report.omittedComparisons.map((comparison) => `  ${terminalText(comparison)}`),
        'Findings:',
        ...(active.length > 0 ? active.flatMap((finding) => findingLines(finding, Boolean(options.color))) : ['(none)']),
        ...(report.suppressedFindings.length > 0 ? [
            'Suppressed findings:',
            ...report.suppressedFindings.flatMap((finding) => findingLines(finding, Boolean(options.color))),
        ] : []),
        '',
    ].join('\n');
}
