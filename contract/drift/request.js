"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.compareRequestContracts = compareRequestContracts;
const recommendation_1 = require("../../recommendation");
const shared_1 = require("./shared");
const APPLICATION_DISCLAIMER = 'Application validation is not evaluated.';
const DEFAULT_BROADER_RATIO = 2;
function limitFinding(input, operation, name, recommendation, ratio, conditionalPreflightBypass) {
    const candidate = recommendation[name];
    if (candidate.value === null || !['exact', 'upper-bound'].includes(candidate.estimateKind))
        return [];
    const policyName = name[0].toLowerCase() + name.slice(1);
    const policyValue = input.allowed.defaults.limits[policyName];
    const pointerName = name.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`);
    const evidence = (0, shared_1.evidenceFor)(operation, input.allowed, `/request/limits/${pointerName}`, 'request-drift-v1');
    if (policyValue < candidate.value) {
        const monitor = input.allowed.defaults.requestDecision === 'would-block';
        const conditional = monitor || conditionalPreflightBypass;
        return [(0, shared_1.makeFinding)({
                ruleId: 'SC-LIMIT-001',
                severity: conditional ? 'warning' : 'error',
                confidence: 'deterministic',
                category: 'resource-limit',
                title: conditional
                    ? 'Policy limit may reject a declared finite request'
                    : 'Policy limit is below a declared finite requirement',
                message: `The effective Edge ${pointerName} limit is below the finite OpenAPI recommendation${conditionalPreflightBypass ? ' outside an allowed-origin CORS preflight' : ''}.`,
                route: { method: operation.method, path: operation.path, operationId: operation.operationId },
                expected: { control: pointerName, minimum: candidate.value, estimateKind: candidate.estimateKind },
                actual: {
                    control: pointerName,
                    value: policyValue,
                    decision: input.allowed.defaults.requestDecision,
                    ...(conditionalPreflightBypass ? { conditionalPreflightBypass: true } : {}),
                },
                evidence,
                remediation: { summary: 'Raise the limit to at least the finite recommendation or narrow the declared contract.', safeAutoFix: false },
            })];
    }
    if (candidate.value > 0 && policyValue > Math.ceil(candidate.value * ratio))
        return [(0, shared_1.makeFinding)({
                ruleId: 'SC-LIMIT-002',
                severity: 'warning',
                confidence: 'deterministic',
                category: 'resource-limit',
                title: 'Policy limit is materially broader than the finite recommendation',
                message: `The effective Edge ${pointerName} limit exceeds the finite recommendation by more than the configured ${ratio}x threshold.`,
                route: { method: operation.method, path: operation.path, operationId: operation.operationId },
                expected: { control: pointerName, recommended: candidate.value, materiallyBroaderRatio: ratio },
                actual: { control: pointerName, value: policyValue },
                evidence,
                remediation: { summary: 'Reduce the limit while retaining the documented recommendation margin.', safeAutoFix: false },
            })];
    return [];
}
function compareRequestContracts(input, options = {}) {
    (0, shared_1.validateComparisonInput)(input);
    const ratio = options.materiallyBroaderRatio ?? DEFAULT_BROADER_RATIO;
    if (!Number.isFinite(ratio) || ratio < 1 || ratio > 100) {
        throw new Error('invalid materially broader ratio');
    }
    const recommendations = (0, recommendation_1.recommendRequestLimits)(input.declared);
    const byRouteKey = new Map(recommendations.routes.flatMap(({ operations }) => operations)
        .map((recommendation) => [recommendation.routeKey, recommendation]));
    const findings = [];
    for (const operation of input.declared.operations) {
        const recommendation = byRouteKey.get(operation.routeKey);
        if (!recommendation)
            continue;
        const corsPreflight = input.allowed.defaults.corsPreflight;
        const preflightBypassesValidation = operation.method === 'OPTIONS'
            && corsPreflight.bypassScope === 'all-request-validation-including-host-and-auth'
            && (corsPreflight.origins.kind === 'any'
                || (corsPreflight.origins.kind === 'allowlist' && corsPreflight.origins.values.length > 0));
        for (const name of ['maxQueryParams', 'maxQueryLength', 'maxUriLength']) {
            findings.push(...limitFinding(input, operation, name, recommendation, ratio, preflightBypassesValidation));
        }
        const declaredHeaders = new Set(operation.request.requiredHeaders.map((header) => header.toLowerCase()));
        const requiredHeaders = input.allowed.defaults.requiredHeaders;
        const policyHeaders = new Set(requiredHeaders?.values ?? []);
        const unchecked = [...declaredHeaders].filter((header) => !policyHeaders.has(header)).sort();
        if (requiredHeaders && unchecked.length > 0)
            findings.push((0, shared_1.makeFinding)({
                ruleId: 'SC-REQUEST-001',
                severity: 'info',
                confidence: 'deterministic',
                category: 'misconfiguration',
                title: 'Required OpenAPI header is not checked at Edge',
                message: `The selected Edge target does not require one or more declared headers. ${APPLICATION_DISCLAIMER}`,
                route: { method: operation.method, path: operation.path, operationId: operation.operationId },
                expected: { requiredHeaders: [...declaredHeaders].sort() },
                actual: { edgeRequiredHeaders: [...policyHeaders].sort(), unchecked },
                evidence: (0, shared_1.evidenceFor)(operation, input.allowed, '/request/block/header_missing', 'request-drift-v1'),
                remediation: { summary: 'Decide whether these headers belong at Edge or only in Application validation.', safeAutoFix: false },
            }));
        const undeclared = [...policyHeaders].filter((header) => !declaredHeaders.has(header)).sort();
        if (requiredHeaders && undeclared.length > 0
            && input.declared.capabilities.parameters === 'complete') {
            const monitor = input.allowed.defaults.requestDecision === 'would-block';
            const conditional = monitor || preflightBypassesValidation;
            findings.push((0, shared_1.makeFinding)({
                ruleId: 'SC-REQUEST-002',
                severity: conditional ? 'warning' : 'error',
                confidence: 'deterministic',
                category: 'misconfiguration',
                title: conditional
                    ? 'Policy may require an undeclared header'
                    : 'Policy requires an undeclared header',
                message: `The effective Edge header requirement is absent from the OpenAPI client contract${preflightBypassesValidation ? ' and is conditional on CORS preflight handling' : ''}.`,
                route: { method: operation.method, path: operation.path, operationId: operation.operationId },
                expected: { requiredHeaders: [...declaredHeaders].sort() },
                actual: {
                    edgeRequiredHeaders: [...policyHeaders].sort(),
                    undeclared,
                    source: requiredHeaders.source,
                    decision: input.allowed.defaults.requestDecision,
                    ...(preflightBypassesValidation ? { conditionalPreflightBypass: true } : {}),
                },
                evidence: (0, shared_1.evidenceFor)(operation, input.allowed, '/request/block/header_missing', 'request-drift-v1'),
                remediation: { summary: 'Declare the client header or remove the Edge requirement.', safeAutoFix: false },
            }));
        }
        if (operation.request.contentTypes.length > 0)
            findings.push((0, shared_1.makeFinding)({
                ruleId: 'SC-REQUEST-003',
                severity: 'info',
                confidence: 'deterministic',
                category: 'misconfiguration',
                title: 'Content-Type compatibility is not enforced by the selected Edge target',
                message: `The current Policy schema has no request Content-Type allowlist, so compatibility cannot be enforced at Edge. ${APPLICATION_DISCLAIMER}`,
                route: { method: operation.method, path: operation.path, operationId: operation.operationId },
                expected: { contentTypes: operation.request.contentTypes },
                actual: { status: 'unsupported', target: input.target, capability: 'request.content_type' },
                evidence: (0, shared_1.evidenceFor)(operation, input.allowed, '/request', 'request-drift-v1'),
                remediation: { summary: 'Keep Content-Type validation in the Application until Edge support exists.', safeAutoFix: false },
            }));
    }
    return (0, shared_1.stableFindings)(findings);
}
