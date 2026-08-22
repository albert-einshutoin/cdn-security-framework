"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FINDING_EVIDENCE_SOURCES = exports.FINDING_CATEGORIES = exports.FINDING_CONFIDENCES = exports.FINDING_SEVERITIES = void 0;
exports.computeFindingInstanceId = computeFindingInstanceId;
exports.createFinding = createFinding;
const node_crypto_1 = require("node:crypto");
exports.FINDING_SEVERITIES = ['error', 'warning', 'info'];
exports.FINDING_CONFIDENCES = ['deterministic', 'high-confidence', 'heuristic'];
exports.FINDING_CATEGORIES = [
    'inventory',
    'exposure',
    'authentication',
    'authorization',
    'resource-limit',
    'misconfiguration',
    'governance',
    'runtime-evidence',
];
exports.FINDING_EVIDENCE_SOURCES = [
    'openapi',
    'source-ast',
    'policy',
    'runtime',
    'generated-artifact',
];
const RULE_ID_PATTERN = /^SC-[A-Z][A-Z0-9]*-[0-9]{3}$/;
const SENSITIVE_KEY_PATTERN = /(?:authorization|cookie|set[-_]?cookie|api[-_]?key|token|secret|password)/i;
const MAX_REDACTION_DEPTH = 32;
const MAX_REDACTION_NODES = 10_000;
const MAX_REDACTED_STRING_LENGTH = 16_384;
function redactString(value) {
    const truncated = value.length > MAX_REDACTED_STRING_LENGTH;
    const bounded = value.slice(0, MAX_REDACTED_STRING_LENGTH);
    const redacted = bounded
        .replace(/([?&][^=\s&#]+)=([^&#\s]*)/g, '$1=[REDACTED]')
        .replace(/\b(authorization|cookie|set-cookie|x-api-key|api-key)\s*[:=]\s*[^\r\n]*/gi, '$1: [REDACTED]')
        .replace(/(["']?(?:authorization|cookie|set[-_]?cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|secret)["']?\s*[:=]\s*)[^\r\n]*/gi, '$1[REDACTED]')
        .replace(/\bBearer\s+[^\s,;]+/gi, 'Bearer [REDACTED]');
    return `${redacted.slice(0, MAX_REDACTED_STRING_LENGTH)}${truncated ? '[TRUNCATED]' : ''}`;
}
function redactValue(value, state = { seen: new WeakSet(), nodes: 0 }, depth = 0) {
    if (state.nodes >= MAX_REDACTION_NODES)
        return '[REDACTED_NODE_LIMIT]';
    state.nodes += 1;
    if (typeof value === 'string')
        return redactString(value);
    if (typeof value === 'function' || typeof value === 'symbol')
        return '[REDACTED_UNSUPPORTED]';
    if (typeof value === 'bigint')
        return value.toString();
    if (typeof value === 'number' && !Number.isFinite(value))
        return null;
    if (value === null || typeof value !== 'object')
        return value;
    if (depth >= MAX_REDACTION_DEPTH)
        return '[REDACTED_DEPTH_LIMIT]';
    if (state.seen.has(value))
        return '[REDACTED_CIRCULAR]';
    state.seen.add(value);
    if (Array.isArray(value)) {
        const output = [];
        for (let index = 0; index < value.length && state.nodes < MAX_REDACTION_NODES; index += 1) {
            output.push(redactValue(value[index], state, depth + 1));
        }
        if (output.length < value.length)
            output.push('[REDACTED_NODE_LIMIT]');
        return output;
    }
    const output = {};
    let complete = true;
    for (const key in value) {
        if (!Object.prototype.hasOwnProperty.call(value, key))
            continue;
        if (state.nodes >= MAX_REDACTION_NODES) {
            complete = false;
            break;
        }
        const child = value[key];
        if (SENSITIVE_KEY_PATTERN.test(key)) {
            state.nodes += 1;
            output[key] = '[REDACTED]';
        }
        else {
            output[key] = redactValue(child, state, depth + 1);
        }
    }
    if (!complete)
        output.__truncated__ = '[REDACTED_NODE_LIMIT]';
    return output;
}
function normalizeRoute(route) {
    if (!route)
        return undefined;
    const normalized = {};
    const method = route.method?.trim();
    const routePath = route.path?.trim();
    const operationId = route.operationId?.trim();
    if (method)
        normalized.method = redactString(method.toUpperCase());
    if (routePath)
        normalized.path = redactString(routePath.replace(/\\/g, '/'));
    if (operationId)
        normalized.operationId = redactString(operationId);
    return Object.keys(normalized).length > 0 ? normalized : undefined;
}
function normalizeEvidenceUri(uri, workspaceRoot) {
    const normalized = redactString(uri.trim().replace(/\\/g, '/'));
    if (/^file:/i.test(normalized)) {
        throw new Error('Finding file evidence uri is not supported');
    }
    const isWindowsAbsolute = /^[A-Za-z]:\//.test(normalized);
    const isPosixAbsolute = normalized.startsWith('/');
    if (!isWindowsAbsolute && !isPosixAbsolute) {
        if (normalized.split('/').includes('..'))
            throw new Error('Finding evidence uri escapes its root');
        return normalized.replace(/^\.\//, '');
    }
    if (!workspaceRoot)
        throw new Error('Finding absolute evidence uri requires workspaceRoot');
    const root = workspaceRoot.trim().replace(/\\/g, '/').replace(/\/$/, '');
    const comparableUri = isWindowsAbsolute ? normalized.toLowerCase() : normalized;
    const comparableRoot = isWindowsAbsolute ? root.toLowerCase() : root;
    if (!comparableUri.startsWith(`${comparableRoot}/`)) {
        throw new Error('Finding evidence uri is outside workspaceRoot');
    }
    const relative = normalized.slice(root.length + 1);
    if (!relative || relative.split('/').includes('..')) {
        throw new Error('Finding evidence uri is invalid');
    }
    return relative;
}
function sanitizeEvidence(evidence, options) {
    return {
        source: evidence.source,
        uri: normalizeEvidenceUri(evidence.uri, options.workspaceRoot),
        ...(evidence.pointer ? { pointer: redactString(evidence.pointer) } : {}),
        digest: redactString(evidence.digest),
        analyzer: redactString(evidence.analyzer),
        capability: redactString(evidence.capability),
        complete: evidence.complete,
    };
}
function stableSerialize(value) {
    if (value === null || typeof value !== 'object')
        return JSON.stringify(value);
    if (Array.isArray(value))
        return `[${value.map(stableSerialize).join(',')}]`;
    const record = value;
    return `{${Object.keys(record).sort().map((key) => (`${JSON.stringify(key)}:${stableSerialize(record[key])}`)).join(',')}}`;
}
function compareText(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
function canonicalEvidence(evidence, options) {
    return evidence.map((item) => sanitizeEvidence(item, options)).map(({ source, uri, pointer, digest, analyzer, capability, complete, }) => ({
        source,
        uri,
        ...(pointer ? { pointer } : {}),
        ...(digest ? { digest } : {}),
        ...(analyzer ? { analyzer } : {}),
        capability,
        complete,
    })).sort((a, b) => compareText(stableSerialize(a), stableSerialize(b)));
}
function computeFindingInstanceId(finding, options = {}) {
    const identity = {
        ruleId: finding.ruleId,
        route: normalizeRoute(finding.route) ?? null,
        evidence: canonicalEvidence(finding.evidence, options),
    };
    return (0, node_crypto_1.createHash)('sha256').update(stableSerialize(identity)).digest('hex');
}
function isNonEmptyString(value) {
    return typeof value === 'string' && value.trim().length > 0;
}
function assertValidInput(input) {
    if (!RULE_ID_PATTERN.test(input.ruleId)) {
        throw new Error('invalid Finding ruleId');
    }
    if (!Array.isArray(input.evidence) || input.evidence.length === 0) {
        throw new Error('Finding evidence must contain at least one item');
    }
    if (!exports.FINDING_SEVERITIES.includes(input.severity)
        || !exports.FINDING_CONFIDENCES.includes(input.confidence)
        || !exports.FINDING_CATEGORIES.includes(input.category)
        || !isNonEmptyString(input.title)
        || !isNonEmptyString(input.message)) {
        throw new Error('invalid Finding fields');
    }
    for (const evidence of input.evidence) {
        if (!exports.FINDING_EVIDENCE_SOURCES.includes(evidence.source)
            || !isNonEmptyString(evidence.uri)
            || !isNonEmptyString(evidence.digest)
            || !isNonEmptyString(evidence.analyzer)
            || !isNonEmptyString(evidence.capability)
            || typeof evidence.complete !== 'boolean') {
            throw new Error('invalid Finding evidence');
        }
    }
    if (input.route && Object.values(input.route).some((value) => (value !== undefined && !isNonEmptyString(value)))) {
        throw new Error('invalid Finding route');
    }
    if (input.remediation
        && (!isNonEmptyString(input.remediation.summary)
            || typeof input.remediation.safeAutoFix !== 'boolean')) {
        throw new Error('invalid Finding remediation');
    }
    if (input.tags && (!Array.isArray(input.tags) || input.tags.some((tag) => !isNonEmptyString(tag)))) {
        throw new Error('invalid Finding tags');
    }
}
function createFinding(input, options = {}) {
    assertValidInput(input);
    const evidence = input.evidence.map((item) => sanitizeEvidence(item, options));
    const route = normalizeRoute(input.route);
    return {
        schemaVersion: 1,
        ruleId: input.ruleId,
        instanceId: computeFindingInstanceId({ ...input, evidence, route }),
        severity: input.severity,
        confidence: input.confidence,
        category: input.category,
        title: redactString(input.title),
        message: redactString(input.message),
        ...(route ? { route } : {}),
        ...('expected' in input ? { expected: redactValue(input.expected) } : {}),
        ...('actual' in input ? { actual: redactValue(input.actual) } : {}),
        evidence,
        ...(input.remediation ? {
            remediation: {
                summary: redactString(input.remediation.summary),
                safeAutoFix: input.remediation.safeAutoFix,
            },
        } : {}),
        ...(input.tags ? { tags: [...new Set(input.tags.map(redactString))].sort() } : {}),
    };
}
