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
exports.WAIVABLE_FINDING_RULE_IDS = void 0;
exports.validateFindingExceptionSet = validateFindingExceptionSet;
exports.loadFindingExceptions = loadFindingExceptions;
exports.loadFindingExceptionsWithIdentity = loadFindingExceptionsWithIdentity;
exports.applyFindingExceptions = applyFindingExceptions;
const node_crypto_1 = require("node:crypto");
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const ajv_1 = __importDefault(require("ajv"));
const yaml = __importStar(require("js-yaml"));
const finding_1 = require("./finding");
const finding_order_1 = require("./finding-order");
exports.WAIVABLE_FINDING_RULE_IDS = [
    'SC-AUTHN-001', 'SC-AUTHN-002', 'SC-AUTHN-003', 'SC-AUTHN-004',
    'SC-EXPOSURE-001', 'SC-EXPOSURE-002', 'SC-EXPOSURE-003', 'SC-INVENTORY-002',
    'SC-LIMIT-001', 'SC-LIMIT-002',
    'SC-REQUEST-001', 'SC-REQUEST-002', 'SC-REQUEST-003',
];
const MAX_FILE_BYTES = 1_048_576;
const MAX_EXCEPTIONS = 10_000;
const MAX_APPLY_VISITS = 1_000_000;
const SENSITIVE_TEXT = /["']?(?:authorization|cookie|set-cookie|x-api-key|api[-_]?key|access[-_]?token|refresh[-_]?token|token|password|secret)["']?\s*[:=]\s*["']?[^\s,;}]+|\bBearer\s+\S+/i;
const NON_WAIVABLE_RULE = /^SC-(?:PARSER|SCHEMA|UNSAFE|GOV)-/;
function schemaPath() {
    const compiled = node_path_1.default.join(__dirname, '..', 'schemas', 'finding-exceptions-v1.schema.json');
    return node_fs_1.default.existsSync(compiled)
        ? compiled
        : node_path_1.default.join(__dirname, '..', '..', 'schemas', 'finding-exceptions-v1.schema.json');
}
const schema = JSON.parse(node_fs_1.default.readFileSync(schemaPath(), 'utf8'));
const validateSchema = new ajv_1.default({ allErrors: true, strict: true }).compile(schema);
function schemaErrors(errors) {
    return (errors ?? []).map((error) => {
        const extra = typeof error.params.additionalProperty === 'string'
            ? ` ${error.params.additionalProperty}` : '';
        return `${error.instancePath || '/'} ${error.message ?? 'is invalid'}${extra}`;
    });
}
function validDate(value) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value))
        return false;
    const parsed = new Date(`${value}T00:00:00Z`);
    return !Number.isNaN(parsed.valueOf()) && parsed.toISOString().slice(0, 10) === value;
}
function isBroadSelector(selector) {
    if (selector.instance_id)
        return false;
    return !selector.method || !selector.path || selector.method.includes('*') || selector.path.includes('*');
}
function validateFindingExceptionSet(value, context) {
    const errors = [];
    if (!context || !validDate(context.currentDate))
        errors.push('currentDate must be an ISO date');
    if (value && typeof value === 'object' && Array.isArray(value.exceptions)
        && value.exceptions.length > MAX_EXCEPTIONS) {
        return { valid: false, errors: [`exceptions must contain at most ${MAX_EXCEPTIONS} items`] };
    }
    if (!validateSchema(value))
        return { valid: false, errors: [...errors, ...schemaErrors(validateSchema.errors)] };
    const set = value;
    const ids = new Set();
    for (const exception of set.exceptions) {
        if (ids.has(exception.id))
            errors.push(`${exception.id}: duplicate exception id`);
        ids.add(exception.id);
        if (!exports.WAIVABLE_FINDING_RULE_IDS.includes(exception.rule_id)
            || NON_WAIVABLE_RULE.test(exception.rule_id)) {
            errors.push(`${exception.id}: unknown rule or non-waivable rule`);
        }
        if (exception.reason.trim().length < 20)
            errors.push(`${exception.id}: reason is too short or blank`);
        if (!exception.owner.trim())
            errors.push(`${exception.id}: owner must not be blank`);
        if (exception.ticket !== undefined && !exception.ticket.trim()) {
            errors.push(`${exception.id}: ticket must not be blank`);
        }
        if (!validDate(exception.expires_at))
            errors.push(`${exception.id}: expires_at must be a valid ISO date`);
        if (exception.selector.method !== undefined && !exception.selector.method.trim()) {
            errors.push(`${exception.id}: selector method must not be blank`);
        }
        if (exception.selector.path !== undefined && !exception.selector.path.trim()) {
            errors.push(`${exception.id}: selector path must not be blank`);
        }
        if (exception.selector.environment !== undefined && !exception.selector.environment.trim()) {
            errors.push(`${exception.id}: selector environment must not be blank`);
        }
        if (exception.selector.instance_id && (exception.selector.method || exception.selector.path)) {
            errors.push(`${exception.id}: instance_id cannot be combined with method or path`);
        }
        if (isBroadSelector(exception.selector)
            && (exception.allow_broad !== true || (exception.broad_reason?.trim().length ?? 0) < 20)) {
            errors.push(`${exception.id}: broad selector requires allow_broad and broad_reason`);
        }
        if (SENSITIVE_TEXT.test(exception.reason) || SENSITIVE_TEXT.test(exception.broad_reason ?? '')) {
            errors.push(`${exception.id}: sensitive text is not allowed in exception rationale`);
        }
    }
    return { valid: errors.length === 0, errors: [...new Set(errors)].sort() };
}
function within(root, candidate) {
    const relative = node_path_1.default.relative(root, candidate);
    return relative !== '' && !relative.startsWith(`..${node_path_1.default.sep}`) && relative !== '..' && !node_path_1.default.isAbsolute(relative);
}
function readBoundedRegularFile(filePath, root) {
    let fd;
    try {
        fd = node_fs_1.default.openSync(filePath, node_fs_1.default.constants.O_RDONLY | node_fs_1.default.constants.O_NOFOLLOW | node_fs_1.default.constants.O_NONBLOCK);
        const opened = node_fs_1.default.fstatSync(fd);
        if (!opened.isFile())
            throw new Error('Finding exception input must be a regular file');
        const verifiedPath = node_fs_1.default.realpathSync(filePath);
        if (!within(root, verifiedPath))
            throw new Error('Finding exception file is outside workspace');
        const verified = node_fs_1.default.statSync(verifiedPath);
        if (opened.dev !== verified.dev || opened.ino !== verified.ino) {
            throw new Error('Finding exception file changed while opening');
        }
        const chunks = [];
        let total = 0;
        while (total <= MAX_FILE_BYTES) {
            const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, MAX_FILE_BYTES + 1 - total));
            const read = node_fs_1.default.readSync(fd, chunk, 0, chunk.length, null);
            if (read === 0)
                break;
            chunks.push(chunk.subarray(0, read));
            total += read;
        }
        if (total > MAX_FILE_BYTES)
            throw new Error('Finding exception file is too large');
        return {
            content: Buffer.concat(chunks, total).toString('utf8'),
            device: opened.dev,
            inode: opened.ino,
        };
    }
    finally {
        if (fd !== undefined)
            node_fs_1.default.closeSync(fd);
    }
}
function loadFindingExceptions(options) {
    return loadFindingExceptionsWithIdentity(options).exceptions;
}
function loadFindingExceptionsWithIdentity(options) {
    if (!options || typeof options.inputPath !== 'string' || typeof options.workspaceRoot !== 'string') {
        throw new Error('invalid Finding exception loader options');
    }
    const workspacePath = node_path_1.default.resolve(options.workspaceRoot);
    const candidate = node_path_1.default.resolve(workspacePath, options.inputPath);
    if (!within(workspacePath, candidate))
        throw new Error('Finding exception file is outside workspace');
    const root = node_fs_1.default.realpathSync(workspacePath);
    let resolved;
    try {
        resolved = node_fs_1.default.realpathSync(candidate);
    }
    catch {
        throw new Error('Finding exception file was not found');
    }
    if (!within(root, resolved))
        throw new Error('Finding exception file is outside workspace');
    let parsed;
    let sourceIdentity;
    try {
        const loaded = readBoundedRegularFile(resolved, root);
        sourceIdentity = { sourcePath: resolved, device: loaded.device, inode: loaded.inode };
        parsed = yaml.load(loaded.content, {
            schema: yaml.JSON_SCHEMA, json: false, maxAliases: 50, maxDepth: 64,
        });
    }
    catch (error) {
        if (error instanceof Error && error.message.startsWith('Finding exception'))
            throw error;
        throw new Error('invalid Finding exception file');
    }
    const validation = validateFindingExceptionSet(parsed, { currentDate: options.currentDate });
    if (!validation.valid)
        throw new Error(`invalid Finding exception file: ${validation.errors.join('; ')}`);
    return { exceptions: parsed, sourceIdentity };
}
function globMatches(pattern, value) {
    if (!pattern.includes('*'))
        return pattern === value;
    const parts = pattern.split('*');
    let cursor = 0;
    if (parts[0] && !value.startsWith(parts[0]))
        return false;
    for (const part of parts) {
        if (!part)
            continue;
        const found = value.indexOf(part, cursor);
        if (found < 0)
            return false;
        cursor = found + part.length;
    }
    return !parts.at(-1) || value.endsWith(parts.at(-1));
}
function matches(finding, exception, context) {
    const selector = exception.selector;
    if (exception.rule_id !== finding.ruleId || !appliesToContext(exception, context))
        return false;
    if (selector.instance_id)
        return selector.instance_id === finding.instanceId;
    if (selector.method
        && (!finding.route?.method
            || !globMatches(selector.method.toUpperCase(), finding.route.method.toUpperCase())))
        return false;
    if (selector.path && (!finding.route?.path || !globMatches(selector.path, finding.route.path)))
        return false;
    return true;
}
function appliesToContext(exception, context) {
    return (exception.selector.target === undefined || exception.selector.target === context.target)
        && (exception.selector.environment === undefined
            || exception.selector.environment === context.environment);
}
function specificity(exception) {
    const selector = exception.selector;
    const routePatterns = [selector.method, selector.path].filter((value) => Boolean(value));
    const literalLength = routePatterns.reduce((total, value) => total + value.replaceAll('*', '').length, 0);
    const wildcardCount = routePatterns.reduce((total, value) => total + (value.match(/\*/g)?.length ?? 0), 0);
    return [
        Number(selector.instance_id !== undefined),
        Number(selector.method !== undefined && !selector.method.includes('*'))
            + Number(selector.path !== undefined && !selector.path.includes('*')),
        literalLength,
        routePatterns.length,
        -wildcardCount,
        Number(selector.target !== undefined) + Number(selector.environment !== undefined),
    ];
}
function compareSpecificity(left, right) {
    const leftScore = specificity(left);
    const rightScore = specificity(right);
    for (let index = 0; index < leftScore.length; index += 1) {
        if (leftScore[index] !== rightScore[index])
            return rightScore[index] - leftScore[index];
    }
    return left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
}
function exceptionDigest(set) {
    return `sha256:${(0, node_crypto_1.createHash)('sha256').update(JSON.stringify(set)).digest('hex')}`;
}
function evidenceUri(sourceUri) {
    const uri = sourceUri ?? 'finding-exceptions.yml';
    if (node_path_1.default.isAbsolute(uri))
        return node_path_1.default.basename(uri);
    if (node_path_1.default.win32.isAbsolute(uri))
        return node_path_1.default.win32.basename(uri);
    return uri;
}
function governanceFinding(ruleId, severity, title, message, actual, digest, context, exceptionIndex, sourceFinding) {
    return (0, finding_1.createFinding)({
        ruleId, severity, confidence: 'deterministic', category: 'governance', title, message, actual,
        ...(sourceFinding ? {
            route: { ...sourceFinding.route, operationId: sourceFinding.instanceId },
        } : {}),
        evidence: [{
                source: 'policy', uri: evidenceUri(context.sourceUri),
                ...(exceptionIndex === undefined ? {} : { pointer: `/exceptions/${exceptionIndex}` }),
                digest, analyzer: 'finding-exceptions@1',
                capability: 'finding-exceptions-v1', complete: true,
            }],
        remediation: { summary: 'Update or remove the exception and retain the audit record.', safeAutoFix: false },
        tags: ['non-waivable'],
    });
}
function isNonWaivable(finding) {
    return finding.category === 'governance' || NON_WAIVABLE_RULE.test(finding.ruleId)
        || finding.tags?.includes('non-waivable') === true;
}
function canonicalizeFindings(findings) {
    return findings.map((finding) => {
        if (finding.schemaVersion !== 1)
            throw new Error('invalid Finding exception input');
        const { schemaVersion: _schemaVersion, instanceId, ...input } = finding;
        const canonical = (0, finding_1.createFinding)(input);
        if (canonical.instanceId !== instanceId) {
            throw new Error('Finding instanceId does not match its canonical identity');
        }
        return canonical;
    });
}
function assertDataFields(value, required, optional = []) {
    if (value === null || typeof value !== 'object')
        throw new Error('invalid Finding exception input');
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
        throw new Error('invalid Finding exception input');
    }
    if (Object.getOwnPropertySymbols(value).length > 0)
        throw new Error('invalid Finding exception input');
    for (const key of [...required, ...optional]) {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor) {
            if (required.includes(key) || key in value)
                throw new Error('invalid Finding exception input');
            continue;
        }
        if (!('value' in descriptor))
            throw new Error('invalid Finding exception input');
    }
}
function dataField(value, key) {
    return Object.getOwnPropertyDescriptor(value, key)?.value;
}
function assertFindingDataProperties(finding) {
    assertDataFields(finding, ['schemaVersion', 'ruleId', 'instanceId', 'severity', 'confidence', 'category', 'title', 'message', 'evidence'], ['route', 'expected', 'actual', 'remediation', 'tags']);
    const route = dataField(finding, 'route');
    if (route !== undefined)
        assertDataFields(route, [], ['method', 'path', 'operationId']);
    const evidenceItems = dataField(finding, 'evidence');
    if (!Array.isArray(evidenceItems))
        throw new Error('invalid Finding exception input');
    for (const evidence of evidenceItems) {
        assertDataFields(evidence, ['source', 'uri', 'digest', 'analyzer', 'capability', 'complete'], ['pointer']);
    }
    const remediation = dataField(finding, 'remediation');
    if (remediation !== undefined)
        assertDataFields(remediation, ['summary', 'safeAutoFix']);
}
function consumeFindingNodes(value, state) {
    const pending = [value];
    const seen = new WeakSet();
    while (pending.length > 0) {
        state.visits += 1;
        if (state.visits > MAX_APPLY_VISITS) {
            throw new Error('Finding exception application exceeds visit budget');
        }
        const current = pending.pop();
        if (current === null || typeof current !== 'object' || seen.has(current))
            continue;
        seen.add(current);
        if (Array.isArray(current)) {
            if (current.length > MAX_APPLY_VISITS - state.visits) {
                throw new Error('Finding exception application exceeds visit budget');
            }
            state.visits += current.length;
            for (let index = 0; index < current.length; index += 1) {
                const descriptor = Object.getOwnPropertyDescriptor(current, index);
                if (!descriptor)
                    continue;
                if (!('value' in descriptor))
                    throw new Error('invalid Finding exception input');
                pending.push(descriptor.value);
            }
            continue;
        }
        for (const key in current) {
            if (!Object.prototype.hasOwnProperty.call(current, key))
                continue;
            const descriptor = Object.getOwnPropertyDescriptor(current, key);
            if (!descriptor || !('value' in descriptor))
                throw new Error('invalid Finding exception input');
            state.visits += 1;
            if (state.visits > MAX_APPLY_VISITS) {
                throw new Error('Finding exception application exceeds visit budget');
            }
            pending.push(descriptor.value);
        }
    }
}
function applyFindingExceptions(findings, set, context) {
    const validation = validateFindingExceptionSet(set, context);
    if (!validation.valid)
        throw new Error(`invalid Finding exception set: ${validation.errors.join('; ')}`);
    const digest = exceptionDigest(set);
    const budget = { visits: set.exceptions.length };
    for (const finding of findings) {
        consumeFindingNodes(finding, budget);
        assertFindingDataProperties(finding);
    }
    const canonicalFindings = canonicalizeFindings(findings);
    const governance = [];
    const exceptionIndexes = new Map(set.exceptions.map((exception, index) => [exception.id, index]));
    const live = set.exceptions.filter((exception, exceptionIndex) => {
        if (exception.expires_at >= context.currentDate)
            return true;
        governance.push(governanceFinding('SC-GOV-001', 'error', 'Finding exception has expired', 'An expired exception does not suppress its matching Finding.', { exceptionId: exception.id, owner: exception.owner, expiresAt: exception.expires_at }, digest, context, exceptionIndex));
        return false;
    });
    const matchedIds = new Set();
    const appliedIds = new Set();
    const active = [];
    const suppressed = [];
    const byRule = new Map();
    const applicableLive = live.filter((exception) => appliesToContext(exception, context));
    for (const exception of applicableLive) {
        const rules = byRule.get(exception.rule_id) ?? [];
        rules.push(exception);
        byRule.set(exception.rule_id, rules);
    }
    let visits = budget.visits;
    for (const finding of canonicalFindings) {
        const ruleExceptions = isNonWaivable(finding) ? [] : (byRule.get(finding.ruleId) ?? []);
        if (ruleExceptions.length > MAX_APPLY_VISITS - visits) {
            throw new Error('Finding exception application exceeds visit budget');
        }
        visits += ruleExceptions.length;
        const candidates = ruleExceptions.filter((exception) => matches(finding, exception, context));
        for (const candidate of candidates)
            matchedIds.add(candidate.id);
        if (candidates.length === 0) {
            active.push(finding);
            continue;
        }
        candidates.sort(compareSpecificity);
        const selected = candidates[0];
        suppressed.push(finding);
        appliedIds.add(selected.id);
        if (candidates.length > 1)
            governance.push(governanceFinding('SC-GOV-003', 'warning', 'Multiple exceptions match one Finding', 'The most specific exception was applied; remove redundant matching exceptions.', { findingInstanceId: finding.instanceId, selectedExceptionId: selected.id, matchCount: candidates.length }, digest, context, undefined, finding));
    }
    for (const exception of applicableLive) {
        if (!matchedIds.has(exception.id))
            governance.push(governanceFinding('SC-GOV-002', 'warning', 'Finding exception is unused', 'No current Finding matches this live exception; remove it if the underlying issue is gone.', { exceptionId: exception.id, owner: exception.owner, expiresAt: exception.expires_at }, digest, context, exceptionIndexes.get(exception.id)));
    }
    return {
        findings: (0, finding_order_1.sortFindings)([...active, ...governance]),
        suppressedFindings: (0, finding_order_1.sortFindings)(suppressed),
        appliedExceptionIds: [...appliedIds].sort(),
        summary: {
            before: canonicalFindings.length,
            after: active.length,
            suppressed: suppressed.length,
            governance: governance.length,
        },
    };
}
