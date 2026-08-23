"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderFindingsAsSarif = renderFindingsAsSarif;
const finding_order_1 = require("../contract/finding-order");
const LEVELS = { error: 'error', warning: 'warning', info: 'note' };
const FINDING_REFERENCE = 'https://github.com/albert-einshutoin/cdn-security-framework/blob/main/docs/finding-reference.md';
function compareText(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
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
function evidenceKey(evidence) {
    return [evidence.uri, evidence.pointer ?? '', evidence.source, evidence.digest].join('\u0000');
}
function location(evidence, id) {
    const pointer = evidence.pointer?.trim();
    return {
        ...(id === undefined ? {} : { id }),
        ...(id === undefined ? {} : { message: { text: `${evidence.source} evidence` } }),
        physicalLocation: {
            artifactLocation: { uri: safeUri(evidence.uri), uriBaseId: '%SRCROOT%' },
            properties: {
                source: evidence.source,
                digest: evidence.digest,
                analyzer: evidence.analyzer,
                capability: evidence.capability,
                complete: evidence.complete,
            },
        },
        ...(pointer ? {
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
