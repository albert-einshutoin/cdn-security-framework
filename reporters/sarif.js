"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SarifReportError = exports.SARIF_ERROR_CODES = void 0;
exports.renderFindingsAsSarif = renderFindingsAsSarif;
exports.renderUnifiedContractDiffSarif = renderUnifiedContractDiffSarif;
const finding_order_1 = require("../contract/finding-order");
const sensitive_text_1 = require("../contract/sensitive-text");
const LEVELS = { error: 'error', warning: 'warning', info: 'note' };
const FINDING_REFERENCE = 'https://github.com/albert-einshutoin/cdn-security-framework/blob/main/docs/finding-reference.md';
exports.SARIF_ERROR_CODES = [
    'SARIF_UNIFIED_REPORT_INVALID',
    'SARIF_LOCATION_INVALID',
    'SARIF_OUTPUT_LIMIT_EXCEEDED',
    'SARIF_PRIVACY_VIOLATION',
];
class SarifReportError extends Error {
    code;
    constructor(code, message) {
        super(`[${code}] ${message}`);
        this.code = code;
        this.name = 'SarifReportError';
    }
}
exports.SarifReportError = SarifReportError;
const DEFAULT_MAX_RELATED_LOCATIONS = 32;
const DEFAULT_MAX_RESULTS = 10_000;
const DEFAULT_MAX_OUTPUT_BYTES = 1_048_576;
const MAX_UNIFIED_FINDINGS = 20_000;
const MAX_UNIFIED_EVIDENCE = 1_024;
const MAX_UNIFIED_AUXILIARY_ITEMS = 10_000;
const MAX_UNIFIED_INPUT_NODES = 500_000;
const MAX_UNIFIED_CANONICAL_NODES = 100_000;
const MAX_UNIFIED_STRING_LENGTH = 16_384;
const SOURCE_PRIORITY = {
    'source-ast': 0,
    openapi: 1,
    policy: 2,
    'generated-artifact': 3,
    runtime: 4,
};
const PRIMARY_SOURCE_ORDER = {
    'SC-AUTHN-001': ['openapi', 'policy', 'source-ast'],
    'SC-AUTHN-002': ['openapi', 'policy', 'source-ast'],
    'SC-AUTHN-003': ['openapi', 'policy', 'source-ast'],
    'SC-AUTHN-004': ['openapi', 'policy', 'source-ast'],
    'SC-AUTHN-005': ['openapi', 'source-ast', 'policy'],
    'SC-AUTHN-006': ['source-ast', 'policy'],
    'SC-AUTHZ-001': ['source-ast', 'openapi', 'policy'],
    'SC-AUTHZ-002': ['source-ast', 'policy'],
    'SC-EXPOSURE-001': ['openapi', 'policy', 'source-ast'],
    'SC-EXPOSURE-002': ['openapi', 'policy'],
    'SC-EXPOSURE-003': ['policy', 'openapi'],
    'SC-EXPOSURE-004': ['source-ast', 'policy'],
    'SC-EXPOSURE-005': ['policy', 'source-ast'],
    'SC-GOV-001': ['policy'],
    'SC-GOV-002': ['policy'],
    'SC-GOV-003': ['policy'],
    'SC-INVENTORY-001': ['source-ast', 'openapi', 'policy'],
    'SC-INVENTORY-002': ['policy', 'openapi'],
    'SC-INVENTORY-003': ['openapi', 'source-ast'],
    'SC-INVENTORY-004': ['openapi', 'source-ast', 'policy'],
    'SC-INVENTORY-005': ['policy', 'source-ast'],
    'SC-LIMIT-001': ['policy', 'openapi'],
    'SC-LIMIT-002': ['policy', 'openapi'],
    'SC-REQUEST-001': ['openapi', 'policy'],
    'SC-REQUEST-002': ['policy', 'openapi'],
    'SC-REQUEST-003': ['openapi', 'policy'],
};
const SOURCE_POSITION_PATTERN = /^line:([1-9]\d*):column:([1-9]\d*)$/u;
function compareText(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
function serializedBytes(value) {
    return Buffer.byteLength(JSON.stringify(value) ?? '', 'utf8');
}
function safeUri(uri) {
    const normalized = uri.trim();
    if (!normalized || normalized !== uri || normalized.includes('\\') || normalized.startsWith('/')
        || normalized.includes('?') || normalized.includes('#') || /[\u0000-\u001f\u007f]/.test(normalized)
        || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(normalized)
        || normalized.split('/').includes('..')) {
        throw new Error('SARIF evidence URI must be workspace-relative');
    }
    try {
        return normalized.split('/').map((segment) => {
            if (segment.replace(/%2e/gi, '.') === '..' || /%(?:2f|5c)/i.test(segment)) {
                throw new Error('unsafe encoded path segment');
            }
            return segment.replace(/%[0-9A-Fa-f]{2}|./gu, (value) => (/^%[0-9A-Fa-f]{2}$/.test(value) ? value.toUpperCase() : encodeURIComponent(value)));
        }).join('/');
    }
    catch {
        throw new Error('SARIF evidence URI must be workspace-relative');
    }
}
function normalizedEvidenceUri(evidence) {
    try {
        return safeUri(evidence.uri);
    }
    catch {
        throw new SarifReportError('SARIF_LOCATION_INVALID', 'Finding evidence URI is not workspace-relative.');
    }
}
function normalizedEvidencePointer(evidence) {
    return evidence.pointer?.trim() ?? '';
}
function evidenceKey(evidence) {
    return [evidence.uri, evidence.pointer ?? '', evidence.source, evidence.digest].join('\u0000');
}
function location(evidence, id) {
    const pointer = evidence.pointer?.trim();
    const sourcePosition = /^line:([1-9]\d*):column:([1-9]\d*)$/u.exec(pointer ?? '');
    const startLine = Number(sourcePosition?.[1]);
    const startColumn = Number(sourcePosition?.[2]);
    const physicalPosition = sourcePosition && Number.isSafeInteger(startLine) && Number.isSafeInteger(startColumn);
    return {
        ...(id === undefined ? {} : { id }),
        ...(id === undefined ? {} : { message: { text: `${evidence.source} evidence` } }),
        physicalLocation: {
            artifactLocation: { uri: safeUri(evidence.uri), uriBaseId: '%SRCROOT%' },
            ...(physicalPosition ? {
                region: {
                    startLine,
                    startColumn,
                },
            } : {}),
            properties: {
                source: evidence.source,
                digest: evidence.digest,
                analyzer: evidence.analyzer,
                capability: evidence.capability,
                complete: evidence.complete,
            },
        },
        ...(pointer && !physicalPosition ? {
            logicalLocations: [{ name: pointer, fullyQualifiedName: pointer, kind: 'jsonPointer' }],
        } : {}),
    };
}
function rule(finding) {
    const help = finding.remediation?.summary ?? finding.message;
    return {
        id: finding.ruleId,
        name: finding.ruleId.replace(/-/g, '_'),
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.message },
        help: { text: help, markdown: help },
        helpUri: FINDING_REFERENCE,
        defaultConfiguration: { level: LEVELS[finding.severity] },
        properties: {
            category: finding.category,
            confidence: finding.confidence,
            tags: [...new Set(finding.tags ?? [])].sort(compareText),
        },
    };
}
function result(finding, suppressed) {
    const evidence = [...finding.evidence].sort((left, right) => compareText(evidenceKey(left), evidenceKey(right)));
    return {
        ruleId: finding.ruleId,
        level: LEVELS[finding.severity],
        message: { text: finding.message },
        partialFingerprints: { 'securityContractFinding/v1': finding.instanceId },
        ...(evidence.length > 0 ? { locations: [location(evidence[0])] } : {}),
        ...(evidence.length > 1 ? {
            relatedLocations: evidence.slice(1).map((item, index) => location(item, index + 1)),
        } : {}),
        // Exception approval is external to source, so SARIF records accepted/external suppression.
        ...(suppressed ? { suppressions: [{ kind: 'external', status: 'accepted' }] } : {}),
        properties: {
            category: finding.category,
            confidence: finding.confidence,
            tags: [...new Set(finding.tags ?? [])].sort(compareText),
        },
    };
}
function renderFindingsAsSarif(report) {
    const findings = (0, finding_order_1.sortFindings)([
        ...report.findings,
        ...report.exceptionDiagnostics,
        ...report.suppressedFindings,
    ]);
    const suppressedIds = new Set(report.suppressedFindings.map(({ instanceId }) => instanceId));
    const rules = new Map();
    for (const finding of findings)
        if (!rules.has(finding.ruleId))
            rules.set(finding.ruleId, finding);
    const analyzers = [...new Set(findings.flatMap((finding) => (finding.evidence.map(({ analyzer }) => analyzer))))].sort(compareText);
    return {
        version: '2.1.0',
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        runs: [{
                tool: {
                    driver: {
                        name: 'cdn-security-framework',
                        informationUri: FINDING_REFERENCE,
                        rules: [...rules.values()].sort((left, right) => compareText(left.ruleId, right.ruleId)).map(rule),
                        properties: { analyzers, findingSchemaVersion: 1, reportSchemaVersion: report.schemaVersion },
                    },
                },
                results: findings.map((finding) => result(finding, suppressedIds.has(finding.instanceId))),
            }],
    };
}
function unifiedText(value) {
    if (typeof value !== 'string' || value.length > MAX_UNIFIED_STRING_LENGTH) {
        throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Unified SARIF text exceeds the string limit.');
    }
    if ((0, sensitive_text_1.hasUnsafeSensitiveText)(value)) {
        throw new SarifReportError('SARIF_PRIVACY_VIOLATION', 'Finding text contains sensitive data.');
    }
    return value.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, (character) => (`\\u{${character.codePointAt(0)?.toString(16).padStart(4, '0')}}`));
}
function unifiedMarkdown(value) {
    return value.replace(/[\\`*_[\]{}()<>#+.!|~-]/g, '\\$&');
}
function unifiedEvidenceKey(evidence) {
    return [
        SOURCE_PRIORITY[evidence.source], evidence.uri, normalizedEvidencePointer(evidence), evidence.source,
        evidence.digest, evidence.analyzer, evidence.capability, String(evidence.complete),
    ].join('\u0000');
}
function unifiedEvidenceIdentity(evidence) {
    return [normalizedEvidenceUri(evidence), normalizedEvidencePointer(evidence)].join('\u0000');
}
function canonicalJson(value, state = { ancestors: new WeakSet(), nodes: 0 }) {
    state.nodes += 1;
    if (state.nodes > MAX_UNIFIED_CANONICAL_NODES) {
        throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Finding identity exceeds the value limit.');
    }
    if (typeof value === 'string' && value.length > MAX_UNIFIED_STRING_LENGTH) {
        throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Finding identity contains an oversized string.');
    }
    if (value === null || typeof value !== 'object')
        return JSON.stringify(value) ?? String(value);
    if (state.ancestors.has(value))
        return '[circular]';
    state.ancestors.add(value);
    try {
        if (Array.isArray(value))
            return `[${value.map((item) => canonicalJson(item, state)).join(',')}]`;
        const record = value;
        return `{${Object.keys(record).sort(compareText)
            .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key], state)}`).join(',')}}`;
    }
    finally {
        state.ancestors.delete(value);
    }
}
function unifiedFindingKey(finding) {
    const { evidence, tags, ...fields } = finding;
    return `${canonicalJson({ ...fields, tags: tags ? [...tags].sort(compareText) : undefined })}\u0000${unifiedEvidence(evidence).map((item) => canonicalJson(item)).join('\u0000')}`;
}
function unifiedEvidence(evidence) {
    const sorted = [...evidence].sort((left, right) => compareText(unifiedEvidenceKey(left), unifiedEvidenceKey(right)));
    const seen = new Set();
    return sorted.filter((item) => {
        const identity = unifiedEvidenceIdentity(item);
        if (seen.has(identity))
            return false;
        seen.add(identity);
        return true;
    });
}
function primaryEvidence(finding, evidence) {
    const order = PRIMARY_SOURCE_ORDER[finding.ruleId];
    if (!order) {
        throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Finding rule family has no primary-source mapping.');
    }
    return order.flatMap((source) => evidence.filter((item) => item.source === source))[0];
}
function unifiedLocation(evidence, id) {
    const uri = normalizedEvidenceUri(evidence);
    const pointer = normalizedEvidencePointer(evidence);
    if (pointer?.startsWith('line:')) {
        const sourcePosition = SOURCE_POSITION_PATTERN.exec(pointer);
        if (!sourcePosition || sourcePosition[0] !== pointer
            || !Number.isSafeInteger(Number(sourcePosition[1]))
            || !Number.isSafeInteger(Number(sourcePosition[2]))) {
            throw new SarifReportError('SARIF_LOCATION_INVALID', 'Finding source coordinates are invalid.');
        }
    }
    try {
        return location({
            ...evidence,
            uri,
            source: unifiedText(evidence.source),
            pointer: evidence.pointer === undefined ? undefined : unifiedText(pointer),
            digest: unifiedText(evidence.digest),
            analyzer: unifiedText(evidence.analyzer),
            capability: unifiedText(evidence.capability),
        }, id);
    }
    catch (error) {
        if (error instanceof SarifReportError)
            throw error;
        throw new SarifReportError('SARIF_LOCATION_INVALID', 'Finding evidence location is invalid.');
    }
}
function unifiedRule(finding) {
    const help = finding.remediation?.summary ?? finding.message;
    const helpText = unifiedText(help);
    return {
        id: unifiedText(finding.ruleId),
        name: unifiedText(finding.ruleId.replace(/-/g, '_')),
        shortDescription: { text: unifiedText(finding.title) },
        fullDescription: { text: unifiedText(finding.message) },
        help: { text: helpText, markdown: unifiedMarkdown(helpText) },
        helpUri: FINDING_REFERENCE,
        defaultConfiguration: { level: LEVELS[finding.severity] },
        properties: {
            category: unifiedText(finding.category),
            confidence: unifiedText(finding.confidence),
            tags: [...new Set((finding.tags ?? []).map(unifiedText))].sort(compareText),
        },
    };
}
function assertBoundedUnifiedValue(value, state) {
    state.nodes += 1;
    if (state.nodes > MAX_UNIFIED_INPUT_NODES) {
        throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Unified report exceeds the value limit.');
    }
    if (typeof value === 'string') {
        if (value.length > MAX_UNIFIED_STRING_LENGTH) {
            throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Unified SARIF text exceeds the string limit.');
        }
        return;
    }
    if (value === null || typeof value !== 'object' || state.ancestors.has(value))
        return;
    state.ancestors.add(value);
    try {
        if (Array.isArray(value)) {
            if (value.length > MAX_UNIFIED_INPUT_NODES) {
                throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Unified report contains an oversized array.');
            }
            for (let index = 0; index < value.length; index += 1) {
                const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
                if (!descriptor || !('value' in descriptor)) {
                    throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Unified report contains an invalid array.');
                }
                assertBoundedUnifiedValue(descriptor.value, state);
            }
            return;
        }
        for (const key of Object.keys(value)) {
            if (key.length > MAX_UNIFIED_STRING_LENGTH) {
                throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Unified report contains an oversized key.');
            }
            const descriptor = Object.getOwnPropertyDescriptor(value, key);
            if (!descriptor || !('value' in descriptor)) {
                throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Unified report contains an accessor property.');
            }
            assertBoundedUnifiedValue(descriptor.value, state);
        }
    }
    finally {
        state.ancestors.delete(value);
    }
}
function assertUnifiedInputBounds(report) {
    const findingCollections = [report.findings, report.exceptionDiagnostics, report.suppressedFindings];
    const findingCount = findingCollections.reduce((total, findings) => total + findings.length, 0);
    if (findingCount > MAX_UNIFIED_FINDINGS) {
        throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Unified report exceeds the finding limit.');
    }
    const state = { ancestors: new WeakSet(), nodes: 0 };
    for (const findings of findingCollections) {
        for (const finding of findings) {
            if (!finding || typeof finding !== 'object' || !Array.isArray(finding.evidence)) {
                throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Unified report contains an invalid Finding.');
            }
            if (finding.evidence.length > MAX_UNIFIED_EVIDENCE) {
                throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Finding exceeds the evidence limit.');
            }
            assertBoundedUnifiedValue(finding, state);
            unifiedText(finding.ruleId);
            unifiedText(finding.title);
            unifiedText(finding.message);
            if (finding.remediation)
                unifiedText(finding.remediation.summary);
        }
    }
    if (report.analyzerDiagnostics.length > MAX_UNIFIED_AUXILIARY_ITEMS
        || report.omittedComparisons.length > MAX_UNIFIED_AUXILIARY_ITEMS
        || report.appliedExceptionIds.length > MAX_UNIFIED_AUXILIARY_ITEMS
        || report.analyzerCapabilities.policy.length > MAX_UNIFIED_AUXILIARY_ITEMS
        || Object.keys(report.analyzerCapabilities.openapi).length > MAX_UNIFIED_AUXILIARY_ITEMS) {
        throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Unified report exceeds an auxiliary item limit.');
    }
    assertBoundedUnifiedValue(report.analyzerCapabilities, state);
    assertBoundedUnifiedValue(report.analyzerDiagnostics, state);
    assertBoundedUnifiedValue(report.omittedComparisons, state);
    assertBoundedUnifiedValue(report.appliedExceptionIds, state);
}
function unifiedResult(finding, suppressed, maxRelatedLocations) {
    const evidence = unifiedEvidence(finding.evidence);
    const primary = primaryEvidence(finding, evidence);
    const related = evidence.filter((item) => item !== primary).slice(0, maxRelatedLocations);
    const sources = [...new Set(evidence.map(({ source }) => unifiedText(source)))].sort(compareText);
    const capabilities = [...new Set(evidence.map(({ capability }) => unifiedText(capability)))].sort(compareText);
    return {
        ruleId: unifiedText(finding.ruleId),
        level: LEVELS[finding.severity],
        message: { text: unifiedText(finding.message) },
        partialFingerprints: { 'securityContractFinding/v1': unifiedText(finding.instanceId) },
        ...(primary ? { locations: [unifiedLocation(primary)] } : {}),
        ...(related.length > 0 ? {
            relatedLocations: related.map((item, index) => unifiedLocation(item, index + 1)),
        } : {}),
        ...(suppressed ? { suppressions: [{ kind: 'external', status: 'accepted' }] } : {}),
        properties: {
            category: unifiedText(finding.category),
            confidence: unifiedText(finding.confidence),
            tags: [...new Set((finding.tags ?? []).map(unifiedText))].sort(compareText),
            ...(sources.length > 0 ? { evidenceSources: sources } : {}),
            ...(capabilities.length > 0 ? { capabilities } : {}),
        },
    };
}
function unifiedCapabilities(report) {
    const openapi = Object.fromEntries(Object.entries(report.analyzerCapabilities.openapi)
        .sort(([left], [right]) => compareText(left, right))
        .map(([name, status]) => [unifiedText(name), unifiedText(status)]));
    const policy = [...report.analyzerCapabilities.policy]
        .sort((left, right) => compareText(left.id, right.id) || compareText(left.status, right.status))
        .map(({ id, status }) => ({ id: unifiedText(id), status: unifiedText(status) }));
    return { openapi, policy };
}
function unifiedNotification(report, truncated) {
    const notifications = [];
    const capabilityStatuses = [
        ...Object.values(report.analyzerCapabilities.openapi),
        ...report.analyzerCapabilities.policy.map(({ status }) => status),
    ];
    if (capabilityStatuses.some((status) => status === 'unsupported' || status === 'partial' || status === 'warning-only')) {
        const unsupported = capabilityStatuses.some((status) => status === 'unsupported');
        notifications.push({
            descriptor: { id: unsupported ? 'SARIF_CAPABILITY_UNSUPPORTED' : 'SARIF_CAPABILITY_PARTIAL' },
            message: { text: unsupported
                    ? 'One or more analyzer capabilities are unsupported.'
                    : 'One or more analyzer capabilities are partial.' },
        });
    }
    const omitted = [...new Set(report.omittedComparisons)].sort(compareText);
    if (omitted.length > 0) {
        const failed = omitted.some((item) => /(?:^|:)failed(?:$|:)/u.test(item));
        notifications.push({
            descriptor: { id: failed ? 'SARIF_COMPARISON_FAILED' : 'SARIF_COMPARISON_PARTIAL' },
            message: { text: unifiedText(`${omitted.length} comparison(s) were omitted or unknown.`) },
        });
    }
    for (const diagnostic of [...report.analyzerDiagnostics].sort((left, right) => compareText([left.code, left.capability ?? '', left.metric ?? '', left.message, String(left.used ?? ''), String(left.limit ?? '')].join('\u0000'), [right.code, right.capability ?? '', right.metric ?? '', right.message, String(right.used ?? ''), String(right.limit ?? '')].join('\u0000')))) {
        notifications.push({
            descriptor: { id: 'SARIF_ANALYZER_DIAGNOSTIC' },
            message: { text: unifiedText(`${diagnostic.code}: ${diagnostic.message}`) },
        });
    }
    if (truncated)
        notifications.push({
            descriptor: { id: 'SARIF_OUTPUT_TRUNCATED' },
            message: { text: 'SARIF output was bounded by the configured result/location limit.' },
        });
    return notifications.length > 0 ? { executionSuccessful: true, toolExecutionNotifications: notifications } : undefined;
}
function renderUnifiedContractDiffSarif(report, options = {}) {
    if (!report || typeof report !== 'object' || report.schemaVersion !== 1 || !Array.isArray(report.findings)
        || !Array.isArray(report.suppressedFindings) || !Array.isArray(report.exceptionDiagnostics)
        || !Array.isArray(report.analyzerDiagnostics) || !Array.isArray(report.omittedComparisons)
        || !Array.isArray(report.appliedExceptionIds) || !report.analyzerCapabilities
        || typeof report.analyzerCapabilities !== 'object'
        || !report.analyzerCapabilities.openapi || typeof report.analyzerCapabilities.openapi !== 'object'
        || !Array.isArray(report.analyzerCapabilities.policy)) {
        throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Unified report is invalid.');
    }
    if (!options || typeof options !== 'object') {
        throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'SARIF options are invalid.');
    }
    const maxRelatedLocations = options.maxRelatedLocations ?? DEFAULT_MAX_RELATED_LOCATIONS;
    const maxResults = options.maxResults ?? DEFAULT_MAX_RESULTS;
    const maxOutputBytes = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
    if (![maxRelatedLocations, maxResults, maxOutputBytes].every((value) => Number.isSafeInteger(value) && value >= 0)
        || maxOutputBytes === 0) {
        throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'SARIF limits are invalid.');
    }
    try {
        assertUnifiedInputBounds(report);
        const allFindings = [
            ...report.findings,
            ...report.exceptionDiagnostics,
            ...report.suppressedFindings,
        ].sort((left, right) => ((0, finding_order_1.compareFindings)(left, right) || compareText(unifiedFindingKey(left), unifiedFindingKey(right))));
        const findings = allFindings.slice(0, maxResults);
        const suppressedIds = new Set(report.suppressedFindings.map(({ instanceId }) => instanceId));
        const rules = new Map();
        for (const finding of findings) {
            const existing = rules.get(finding.ruleId);
            if (!existing || unifiedFindingKey(finding) < unifiedFindingKey(existing))
                rules.set(finding.ruleId, finding);
        }
        const budgetSkeleton = {
            version: '2.1.0',
            $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
            runs: [{
                    tool: {
                        driver: {
                            name: 'cdn-security-framework',
                            informationUri: FINDING_REFERENCE,
                            rules: [],
                            properties: {
                                analyzers: [],
                                findingSchemaVersion: 1,
                                reportSchemaVersion: report.schemaVersion,
                                capabilities: { openapi: {}, policy: [] },
                                omittedComparisons: [],
                                analyzerDiagnostics: [],
                            },
                        },
                    },
                    results: [],
                }],
        };
        const staticOutputBytes = serializedBytes(budgetSkeleton);
        const invocationBudgetOutput = {
            ...budgetSkeleton,
            runs: [{
                    ...budgetSkeleton.runs[0],
                    invocations: [{ executionSuccessful: true, toolExecutionNotifications: [] }],
                }],
        };
        const invocationOverhead = serializedBytes(invocationBudgetOutput) - staticOutputBytes;
        let dynamicOutputBytes = 0;
        const assertAuxiliaryWithinLimit = (additionalBytes) => {
            if (staticOutputBytes + dynamicOutputBytes + additionalBytes > maxOutputBytes) {
                throw new SarifReportError('SARIF_OUTPUT_LIMIT_EXCEEDED', 'SARIF output exceeds the configured byte limit.');
            }
            dynamicOutputBytes += additionalBytes;
        };
        assertAuxiliaryWithinLimit(0);
        const accountArrayItem = (value, index) => {
            assertAuxiliaryWithinLimit((index > 0 ? 1 : 0) + serializedBytes(value));
        };
        const accountObjectEntry = (key, value, index) => {
            assertAuxiliaryWithinLimit((index > 0 ? 1 : 0) + serializedBytes(key) + 1 + serializedBytes(value));
        };
        const analyzerSet = new Set();
        for (const finding of findings) {
            for (const { analyzer: rawAnalyzer } of finding.evidence) {
                const analyzer = unifiedText(rawAnalyzer);
                if (analyzerSet.has(analyzer))
                    continue;
                accountArrayItem(analyzer, analyzerSet.size);
                analyzerSet.add(analyzer);
            }
        }
        const openapiCapabilities = report.analyzerCapabilities.openapi;
        const openapiEntries = new Map();
        for (const rawName in openapiCapabilities) {
            if (!Object.prototype.hasOwnProperty.call(openapiCapabilities, rawName))
                continue;
            openapiEntries.set(unifiedText(rawName), unifiedText(openapiCapabilities[rawName]));
        }
        let openapiEntryCount = 0;
        for (const [name, status] of openapiEntries) {
            accountObjectEntry(name, status, openapiEntryCount);
            openapiEntryCount += 1;
        }
        let policyEntryCount = 0;
        for (const { id: rawId, status: rawStatus } of report.analyzerCapabilities.policy) {
            accountArrayItem({ id: unifiedText(rawId), status: unifiedText(rawStatus) }, policyEntryCount);
            policyEntryCount += 1;
        }
        const omittedRawValues = new Set(report.omittedComparisons);
        let omittedComparisonCount = 0;
        for (const rawComparison of omittedRawValues) {
            accountArrayItem(unifiedText(rawComparison), omittedComparisonCount);
            omittedComparisonCount += 1;
        }
        const analyzerDiagnosticCodes = new Set();
        for (const { code: rawCode } of report.analyzerDiagnostics) {
            if (analyzerDiagnosticCodes.has(rawCode))
                continue;
            analyzerDiagnosticCodes.add(rawCode);
            accountArrayItem(unifiedText(rawCode), analyzerDiagnosticCodes.size - 1);
        }
        const truncated = findings.length < allFindings.length
            || allFindings.some((finding) => unifiedEvidence(finding.evidence).length > maxRelatedLocations + 1);
        let notificationCount = 0;
        const accountNotification = (id, text) => {
            const notification = { descriptor: { id }, message: { text } };
            assertAuxiliaryWithinLimit((notificationCount === 0 ? invocationOverhead : 0)
                + (notificationCount > 0 ? 1 : 0)
                + serializedBytes(notification));
            notificationCount += 1;
        };
        let capabilityUnsupported = false;
        let capabilityPartial = false;
        const observeCapabilityStatus = (status) => {
            if (status === 'unsupported')
                capabilityUnsupported = true;
            else if (status === 'partial' || status === 'warning-only')
                capabilityPartial = true;
        };
        for (const rawName in openapiCapabilities) {
            if (Object.prototype.hasOwnProperty.call(openapiCapabilities, rawName)) {
                observeCapabilityStatus(openapiCapabilities[rawName]);
            }
        }
        for (const { status } of report.analyzerCapabilities.policy)
            observeCapabilityStatus(status);
        if (capabilityUnsupported || capabilityPartial) {
            accountNotification(capabilityUnsupported ? 'SARIF_CAPABILITY_UNSUPPORTED' : 'SARIF_CAPABILITY_PARTIAL', capabilityUnsupported
                ? 'One or more analyzer capabilities are unsupported.'
                : 'One or more analyzer capabilities are partial.');
        }
        if (omittedRawValues.size > 0) {
            let omittedFailed = false;
            for (const item of omittedRawValues) {
                if (/(?:^|:)failed(?:$|:)/u.test(item)) {
                    omittedFailed = true;
                    break;
                }
            }
            accountNotification(omittedFailed ? 'SARIF_COMPARISON_FAILED' : 'SARIF_COMPARISON_PARTIAL', unifiedText(omittedRawValues.size + ' comparison(s) were omitted or unknown.'));
        }
        for (const diagnostic of report.analyzerDiagnostics) {
            accountNotification('SARIF_ANALYZER_DIAGNOSTIC', unifiedText(diagnostic.code + ': ' + diagnostic.message));
        }
        if (truncated) {
            accountNotification('SARIF_OUTPUT_TRUNCATED', 'SARIF output was bounded by the configured result/location limit.');
        }
        const analyzers = [...analyzerSet].sort(compareText);
        const properties = {
            analyzers,
            findingSchemaVersion: 1,
            reportSchemaVersion: report.schemaVersion,
            capabilities: unifiedCapabilities(report),
            omittedComparisons: [...omittedRawValues].sort(compareText).map(unifiedText),
            analyzerDiagnostics: [...analyzerDiagnosticCodes].sort(compareText).map(unifiedText),
        };
        const invocation = unifiedNotification(report, truncated);
        const emptyOutput = {
            version: '2.1.0',
            $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
            runs: [{
                    tool: {
                        driver: {
                            name: 'cdn-security-framework',
                            informationUri: FINDING_REFERENCE,
                            rules: [],
                            properties,
                        },
                    },
                    results: [],
                    ...(invocation ? { invocations: [invocation] } : {}),
                }],
        };
        const serializedEmptyOutput = JSON.stringify(emptyOutput);
        const emptyOutputBytes = Buffer.byteLength(serializedEmptyOutput, 'utf8');
        const fixedOutputBytes = emptyOutputBytes - 4;
        let rulesBytes = 2;
        let resultsBytes = 2;
        const outputRules = [];
        const outputResults = [];
        const assertOutputWithinLimit = () => {
            if (fixedOutputBytes + rulesBytes + resultsBytes > maxOutputBytes) {
                throw new SarifReportError('SARIF_OUTPUT_LIMIT_EXCEEDED', 'SARIF output exceeds the configured byte limit.');
            }
        };
        assertOutputWithinLimit();
        for (const finding of [...rules.values()].sort((left, right) => compareText(left.ruleId, right.ruleId))) {
            const item = unifiedRule(finding);
            const serializedItem = JSON.stringify(item);
            rulesBytes += (outputRules.length > 0 ? 1 : 0) + Buffer.byteLength(serializedItem, 'utf8');
            assertOutputWithinLimit();
            outputRules.push(item);
        }
        for (const finding of findings) {
            const item = unifiedResult(finding, suppressedIds.has(finding.instanceId), maxRelatedLocations);
            const serializedItem = JSON.stringify(item);
            resultsBytes += (outputResults.length > 0 ? 1 : 0) + Buffer.byteLength(serializedItem, 'utf8');
            assertOutputWithinLimit();
            outputResults.push(item);
        }
        const output = {
            ...emptyOutput,
            runs: [{
                    ...emptyOutput.runs[0],
                    tool: {
                        ...emptyOutput.runs[0].tool,
                        driver: {
                            ...emptyOutput.runs[0].tool.driver,
                            rules: outputRules,
                        },
                    },
                    results: outputResults,
                }],
        };
        if (Buffer.byteLength(JSON.stringify(output), 'utf8') > maxOutputBytes) {
            throw new SarifReportError('SARIF_OUTPUT_LIMIT_EXCEEDED', 'SARIF output exceeds the configured byte limit.');
        }
        return output;
    }
    catch (error) {
        if (error instanceof SarifReportError)
            throw error;
        throw new SarifReportError('SARIF_UNIFIED_REPORT_INVALID', 'Unified report could not be rendered.');
    }
}
