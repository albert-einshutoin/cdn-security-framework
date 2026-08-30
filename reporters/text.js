"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderUnifiedContractDiffText = renderUnifiedContractDiffText;
const finding_order_1 = require("../contract/finding-order");
const sensitive_text_1 = require("../contract/sensitive-text");
const DEFAULT_MAX_OUTPUT_BYTES = 1_048_576;
const MAX_FIELD_LENGTH = 512;
const MAX_VALUE_DEPTH = 8;
const MAX_VALUE_NODES = 256;
const MAX_ARRAY_ITEMS = 32;
const MAX_OBJECT_KEYS = 32;
function compareText(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
function terminalText(value) {
    const bounded = (0, sensitive_text_1.redactSensitiveText)(value).slice(0, MAX_FIELD_LENGTH);
    return `${bounded}${value.length > MAX_FIELD_LENGTH ? '[TRUNCATED]' : ''}`
        .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, (character) => (`\\u{${character.codePointAt(0)?.toString(16).padStart(4, '0')}}`));
}
function safeValue(value, state, depth) {
    if (state.nodes >= MAX_VALUE_NODES)
        return '[REDACTED_NODE_LIMIT]';
    state.nodes += 1;
    if (typeof value === 'string')
        return terminalText(value);
    if (typeof value === 'bigint')
        return value.toString();
    if (typeof value === 'function' || typeof value === 'symbol')
        return '[REDACTED_UNSUPPORTED]';
    if (typeof value === 'number' && !Number.isFinite(value))
        return null;
    if (value === null || typeof value !== 'object')
        return value;
    if (depth >= MAX_VALUE_DEPTH)
        return '[REDACTED_DEPTH_LIMIT]';
    if (state.seen.has(value))
        return '[REDACTED_CIRCULAR]';
    state.seen.add(value);
    if (Array.isArray(value)) {
        const output = value.slice(0, MAX_ARRAY_ITEMS).map((item) => safeValue(item, state, depth + 1));
        if (value.length > output.length)
            output.push('[REDACTED_ARRAY_LIMIT]');
        return output;
    }
    const output = {};
    let keys;
    try {
        keys = Object.keys(value).sort(compareText);
    }
    catch {
        return '[REDACTED_UNREADABLE]';
    }
    for (const key of keys.slice(0, MAX_OBJECT_KEYS)) {
        if (sensitive_text_1.SENSITIVE_KEY_PATTERN.test(key)) {
            output[terminalText(key)] = '[REDACTED]';
            continue;
        }
        try {
            output[terminalText(key)] = safeValue(value[key], state, depth + 1);
        }
        catch {
            output[terminalText(key)] = '[REDACTED_UNREADABLE]';
        }
    }
    if (keys.length > MAX_OBJECT_KEYS)
        output.__truncated__ = '[REDACTED_OBJECT_LIMIT]';
    return output;
}
function safeValueText(value) {
    try {
        return terminalText(JSON.stringify(safeValue(value, { nodes: 0, seen: new WeakSet() }, 0)) ?? 'null');
    }
    catch {
        return '[REDACTED_UNSERIALIZABLE]';
    }
}
function positiveInteger(value, name, allowZero = false) {
    if (value === undefined)
        return undefined;
    if (!Number.isSafeInteger(value) || (allowZero ? value < 0 : value <= 0)) {
        throw new Error(`${name} must be ${allowZero ? 'a non-negative' : 'a positive'} safe integer`);
    }
    return value;
}
function capabilityAggregate(capabilities) {
    if (capabilities.some((status) => status === 'unsupported'))
        return 'unsupported';
    if (capabilities.some((status) => status !== 'complete' && status !== 'supported'))
        return 'partial';
    return 'complete';
}
function capabilityCounts(capabilities) {
    const counts = { complete: 0, partial: 0, unsupported: 0, supported: 0, 'warning-only': 0 };
    for (const status of capabilities)
        if (status in counts)
            counts[status] += 1;
    return Object.entries(counts)
        .filter(([, count]) => count > 0)
        .map(([status, count]) => `${status}=${count}`)
        .join(' ');
}
function capabilityLines(report) {
    const openapiEntries = Object.entries(report.analyzerCapabilities.openapi);
    const policyEntries = [...report.analyzerCapabilities.policy]
        .sort((left, right) => compareText(left.id, right.id));
    const openapiStatus = capabilityAggregate(openapiEntries.map(([, status]) => status));
    const policyStatus = capabilityAggregate(policyEntries.map(({ status }) => status));
    const lines = [
        'Capabilities:',
        `  OpenAPI: ${openapiStatus} (${capabilityCounts(openapiEntries.map(([, status]) => status)) || 'none'})`,
        `  Policy: ${policyStatus} (${capabilityCounts(policyEntries.map(({ status }) => status)) || 'none'})`,
    ];
    for (const [name, status] of openapiEntries.sort(([left], [right]) => compareText(left, right))) {
        if (status === 'complete')
            continue;
        lines.push(`    openapi.${name}: ${status} (${status === 'unsupported' ? 'not evaluated' : 'partial coverage'})`);
    }
    for (const { id, status } of policyEntries) {
        if (status === 'supported')
            continue;
        const reason = status === 'unsupported' ? 'not evaluated' : status === 'warning-only' ? 'warning-only' : 'partial coverage';
        lines.push(`    policy.${terminalText(id)}: ${status} (${reason})`);
    }
    return lines;
}
function diagnosticLines(report) {
    const diagnostics = [...report.analyzerDiagnostics].sort((left, right) => compareText([left.code, left.capability ?? '', left.metric ?? '', left.message].join('\u0000'), [right.code, right.capability ?? '', right.metric ?? '', right.message].join('\u0000')));
    return [
        'Analysis diagnostics:',
        ...(diagnostics.length === 0
            ? ['  none']
            : diagnostics.map((diagnostic) => {
                const scope = diagnostic.capability ?? diagnostic.metric ?? 'analysis';
                return `  ${terminalText(diagnostic.level.toUpperCase())} ${terminalText(diagnostic.code)} ${terminalText(scope)}: ${terminalText(diagnostic.message)}`;
            })),
    ];
}
function evidenceText(evidence) {
    const rawUri = evidence.uri.split(/[?#]/, 1)[0];
    const uri = /^(?:[A-Za-z][A-Za-z0-9+.-]*:|[A-Za-z]:[\\/]|\/)/u.test(rawUri)
        ? '[external]'
        : terminalText(rawUri);
    const pointer = evidence.pointer ? terminalText(evidence.pointer) : '';
    return `${uri}${pointer ? `#${pointer}` : ''}`;
}
function routeText(finding) {
    if (!finding.route)
        return '-';
    const method = terminalText(finding.route.method ?? '');
    const routePath = terminalText((finding.route.path ?? '').split(/[?#]/, 1)[0]);
    const operation = terminalText(finding.route.operationId ?? '');
    return [method, routePath].filter(Boolean).join(' ') || operation || '-';
}
function findingLines(finding, color) {
    const labels = {
        error: '\u001b[31mERROR\u001b[0m',
        warning: '\u001b[33mWARNING\u001b[0m',
        info: '\u001b[36mINFO\u001b[0m',
    };
    const label = color ? labels[finding.severity] : finding.severity.toUpperCase();
    return [
        `${label} ${terminalText(finding.ruleId)} [${terminalText(finding.confidence)}] ${routeText(finding)} ${terminalText(finding.title)}`,
        `  message=${terminalText(finding.message)}`,
        ...(finding.expected === undefined ? [] : [`  expected=${safeValueText(finding.expected)}`]),
        ...(finding.actual === undefined ? [] : [`  actual=${safeValueText(finding.actual)}`]),
        ...[...finding.evidence]
            .sort((left, right) => compareText([left.source, left.uri, left.pointer ?? '', left.digest, left.analyzer, left.capability, String(left.complete)].join('\u0000'), [right.source, right.uri, right.pointer ?? '', right.digest, right.analyzer, right.capability, String(right.complete)].join('\u0000')))
            .slice(0, MAX_ARRAY_ITEMS)
            .map((evidence) => `  evidence=${evidenceText(evidence)}`),
        ...(finding.evidence.length > MAX_ARRAY_ITEMS ? ['  evidence=[TRUNCATED]'] : []),
        ...(finding.remediation ? [`  remediation=${terminalText(finding.remediation.summary)}`] : []),
    ];
}
function findingSection(title, findings, color, maxFindings) {
    const displayed = maxFindings === undefined ? findings : findings.slice(0, maxFindings);
    const omitted = findings.length - displayed.length;
    const lines = [title, `  evaluated=${findings.length}${findings.length === 0 ? ' (no findings)' : ''}`];
    if (omitted > 0)
        lines.push(`  ${omitted} additional finding(s) omitted by maxFindings.`);
    if (displayed.length > 0)
        lines.push(...displayed.flatMap((finding) => findingLines(finding, color)));
    else
        lines.push('  (none)');
    return lines;
}
function byteLength(value) {
    return Buffer.byteLength(value, 'utf8');
}
function truncateOutput(value, maxBytes) {
    if (byteLength(value) <= maxBytes)
        return value;
    const marker = `\n[output truncated at ${maxBytes} bytes]\n`;
    const budget = Math.max(0, maxBytes - byteLength(marker));
    let bytes = 0;
    let prefix = '';
    for (const character of value) {
        const size = byteLength(character);
        if (bytes + size > budget)
            break;
        prefix += character;
        bytes += size;
    }
    const output = `${prefix}${marker}`;
    if (byteLength(output) <= maxBytes)
        return output;
    return Buffer.from(output, 'utf8').subarray(0, maxBytes).toString('utf8');
}
function renderUnifiedContractDiffText(report, options = {}) {
    if (!report || typeof report !== 'object')
        throw new Error('Contract diff report is required.');
    const maxFindings = positiveInteger(options.maxFindings, 'maxFindings', true);
    const maxOutputBytes = positiveInteger(options.maxOutputBytes, 'maxOutputBytes') ?? DEFAULT_MAX_OUTPUT_BYTES;
    const color = options.color === true;
    const omittedComparisons = [...new Set(report.omittedComparisons)].sort(compareText);
    const activeFindings = (0, finding_order_1.sortFindings)(report.findings);
    const diagnostics = (0, finding_order_1.sortFindings)(report.exceptionDiagnostics);
    const includeSuppressed = options.includeSuppressed ?? report.suppressedFindings.length > 0;
    const lines = [
        `Summary: total=${report.summary.total} error=${report.summary.error}`
            + ` warning=${report.summary.warning} info=${report.summary.info}`
            + ` suppressed=${report.summary.suppressed}`,
        `Target: ${terminalText(report.target)}`,
        `OpenAPI digest: ${terminalText(report.inputDigests.openapi)}`,
        `Policy digest: ${terminalText(report.inputDigests.policy)}`,
        `Exceptions digest: ${terminalText(report.inputDigests.exceptions ?? 'none')}`,
        `Omitted/unknown comparisons: ${omittedComparisons.length || 'none'}`,
        ...omittedComparisons.map((comparison) => `  ${terminalText(comparison)}`),
        'Input analysis:',
        '  declared: analyzed (OpenAPI)',
        '  implemented: not requested (source input is absent)',
        '  allowed: analyzed (Policy)',
        `  Exception input: ${report.inputDigests.exceptions ? 'analyzed' : 'not requested'}`,
        'Comparison:',
        `  status: ${omittedComparisons.length > 0 ? 'partial' : 'completed'}`,
        `  evaluated findings: ${report.summary.total}`,
        `  not evaluated: ${omittedComparisons.length > 0 ? `${omittedComparisons.length} comparison(s); absence of findings is not proof of no drift` : 'none'}`,
        ...capabilityLines(report),
        ...diagnosticLines(report),
        ...findingSection('Findings:', activeFindings, color, maxFindings),
        ...(includeSuppressed ? [
            'Suppressed findings:',
            ...findingSection('', (0, finding_order_1.sortFindings)(report.suppressedFindings), color, maxFindings).slice(1),
        ] : []),
        ...(diagnostics.length > 0 ? [
            'Exception/governance diagnostics:',
            ...diagnostics.flatMap((finding) => findingLines(finding, color)),
        ] : []),
        'Limitations:',
        ...(omittedComparisons.length > 0
            ? [`  ${omittedComparisons.length} comparison(s) were omitted or are unknown.`]
            : []),
        ...(report.analyzerDiagnostics.length > 0
            ? [`  ${report.analyzerDiagnostics.length} analyzer diagnostic(s) require attention.`]
            : []),
        ...(omittedComparisons.length === 0 && report.analyzerDiagnostics.length === 0
            ? ['  none reported']
            : []),
        '',
    ];
    return truncateOutput(lines.join('\n'), maxOutputBytes);
}
