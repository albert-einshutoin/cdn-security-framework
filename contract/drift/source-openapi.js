"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.compareSourceOpenApiContracts = compareSourceOpenApiContracts;
const shared_1 = require("./shared");
const MAX_COMPARISON_VISITS = 1_000_000;
const SOURCE_SCOPE = 'Source metadata does not prove Guard runtime behavior.';
function validateInput(input, options) {
    if (!input?.declared || !input.implemented || !input.declaredEvidence || !input.implementedEvidence
        || !options || typeof options !== 'object' || Array.isArray(options)
        || input.declared.schemaVersion !== 1 || input.implemented.schemaVersion !== 1
        || input.declared.source !== 'openapi' || input.implemented.source !== 'source-ast'
        || input.declaredEvidence?.source !== 'openapi'
        || input.implementedEvidence?.source !== 'source-ast'
        || !Array.isArray(input.declared.operations) || !Array.isArray(input.implemented.operations)
        || input.declared.operations.length > MAX_COMPARISON_VISITS
        || input.implemented.operations.length > MAX_COMPARISON_VISITS
        || input.declared.operations.length
            > MAX_COMPARISON_VISITS - input.implemented.operations.length) {
        throw new Error('invalid source OpenAPI drift input');
    }
    let visits = input.declared.operations.length + input.implemented.operations.length;
    const consume = (count) => {
        if (!Number.isSafeInteger(count) || count < 0 || visits > MAX_COMPARISON_VISITS - count) {
            throw new Error('source OpenAPI drift comparison exceeds visit budget');
        }
        visits += count;
    };
    const validateOperation = (operation) => {
        const roles = operation.auth.analysis?.roles ?? [];
        if (roles.some((role) => typeof role !== 'string' || role.length > 16_384)) {
            throw new Error('invalid source role metadata');
        }
        consume(operation.provenance.length + operation.auth.alternatives.length
            + (operation.auth.analysis?.guards.length ?? 0) + roles.length);
        for (const alternative of operation.auth.alternatives)
            consume(alternative.schemes.length);
    };
    for (const operation of input.declared.operations)
        validateOperation(operation);
    for (const operation of input.implemented.operations)
        validateOperation(operation);
    if (options.declaredPrivilegedRoles !== undefined
        && (!options.declaredPrivilegedRoles || typeof options.declaredPrivilegedRoles !== 'object'
            || Array.isArray(options.declaredPrivilegedRoles))) {
        throw new Error('invalid declared privileged roles');
    }
    const rolesByRoute = options.declaredPrivilegedRoles ?? {};
    for (const routeKey in rolesByRoute) {
        if (!Object.hasOwn(rolesByRoute, routeKey))
            continue;
        const roles = rolesByRoute[routeKey];
        if (!routeKey || routeKey.length > 16_384
            || !Array.isArray(roles)
            || roles.some((role) => typeof role !== 'string' || role.length > 16_384)) {
            throw new Error('invalid declared privileged roles');
        }
        consume(roles.length + 1);
    }
}
function groupedByShape(operations) {
    const groups = new Map();
    for (const operation of operations) {
        const shape = (0, shared_1.normalizedPathShape)(operation.path);
        const group = groups.get(shape) ?? [];
        group.push(operation);
        groups.set(shape, group);
    }
    return groups;
}
function route(operation) {
    return { method: operation.method, path: operation.path, operationId: operation.operationId };
}
function inventoryFindings(input) {
    const declared = groupedByShape(input.declared.operations);
    const implemented = groupedByShape(input.implemented.operations);
    const findings = [];
    for (const shape of [...new Set([...declared.keys(), ...implemented.keys()])].sort()) {
        const declaredOperations = declared.get(shape) ?? [];
        const implementedOperations = implemented.get(shape) ?? [];
        if (declaredOperations.length === 0) {
            for (const operation of implementedOperations)
                findings.push((0, shared_1.makeFinding)({
                    ruleId: 'SC-INVENTORY-001',
                    severity: input.declared.capabilities.routes === 'complete' ? 'error' : 'warning',
                    confidence: input.declared.capabilities.routes === 'complete' ? 'deterministic' : 'heuristic',
                    category: 'inventory',
                    title: 'Implemented operation is not declared',
                    message: 'A statically detected Source operation has no corresponding OpenAPI route shape.',
                    route: route(operation),
                    expected: { declaredOperation: true },
                    actual: { implementedOperation: true },
                    evidence: [...operation.provenance, input.declaredEvidence],
                    remediation: { summary: 'Declare the operation or remove the unintended implementation.', safeAutoFix: false },
                }));
            continue;
        }
        if (implementedOperations.length === 0) {
            for (const operation of declaredOperations)
                findings.push((0, shared_1.makeFinding)({
                    ruleId: 'SC-INVENTORY-003',
                    severity: input.implemented.capabilities.routes === 'complete' ? 'error' : 'warning',
                    confidence: input.implemented.capabilities.routes === 'complete' ? 'deterministic' : 'heuristic',
                    category: 'inventory',
                    title: 'Declared operation has no statically detected implementation',
                    message: input.implemented.capabilities.routes === 'complete'
                        ? 'No Source operation matches this OpenAPI route shape.'
                        : 'No Source operation was detected, but Source route analysis is incomplete; absence is not proven.',
                    route: route(operation),
                    expected: { implementedOperation: true },
                    actual: { sourceRouteCapability: input.implemented.capabilities.routes },
                    evidence: [...operation.provenance, input.implementedEvidence],
                    remediation: { summary: 'Implement the operation or remove the stale declaration.', safeAutoFix: false },
                }));
            continue;
        }
        const declaredMethods = [...new Set(declaredOperations.map(({ method }) => method))].sort();
        const implementedMethods = [...new Set(implementedOperations.map(({ method }) => method))].sort();
        if (declaredMethods.join('\0') !== implementedMethods.join('\0'))
            findings.push((0, shared_1.makeFinding)({
                ruleId: 'SC-INVENTORY-004',
                severity: input.declared.capabilities.routes === 'complete'
                    && input.implemented.capabilities.routes === 'complete' ? 'error' : 'warning',
                confidence: input.declared.capabilities.routes === 'complete'
                    && input.implemented.capabilities.routes === 'complete' ? 'deterministic' : 'heuristic',
                category: 'inventory',
                title: 'Implemented and declared methods differ',
                message: 'The same normalized route shape has a different HTTP method set in Source and OpenAPI.',
                route: { path: declaredOperations[0].path },
                expected: { methods: declaredMethods },
                actual: { methods: implementedMethods },
                evidence: [
                    ...declaredOperations.flatMap(({ provenance }) => provenance),
                    ...implementedOperations.flatMap(({ provenance }) => provenance),
                ],
                remediation: { summary: 'Align the implemented and declared HTTP method sets.', safeAutoFix: false },
            }));
    }
    return findings;
}
function explicitSourceAuth(operation) {
    const analysis = operation.auth.analysis;
    if (!analysis || analysis.enforcementConfidence !== 'high')
        return undefined;
    if (operation.auth.mode === 'none' && analysis.explicitPublic)
        return { mode: 'public', kinds: [] };
    if (operation.auth.mode !== 'alternatives' || analysis.explicitPublic || analysis.guards.length === 0
        || analysis.guards.some(({ authKind }) => !authKind || authKind === 'unknown'))
        return undefined;
    return { mode: 'authenticated', kinds: [...new Set(analysis.guards.map(({ authKind }) => authKind))].sort() };
}
function explicitDeclaredAuth(operation) {
    if (operation.auth.mode === 'none' && operation.exposure === 'public') {
        return { mode: 'public', kinds: [] };
    }
    if (operation.auth.mode !== 'alternatives' || operation.auth.alternatives.some(({ anonymous, schemes }) => anonymous || schemes.some(({ kind, capability }) => kind === 'unknown' || capability !== 'supported')))
        return undefined;
    return {
        mode: 'authenticated',
        alternatives: operation.auth.alternatives.map(({ schemes }) => [...new Set(schemes.map(({ kind }) => kind))].sort()),
    };
}
function groupedByMethodShape(operations) {
    const groups = new Map();
    for (const operation of operations) {
        const key = `${operation.method} ${(0, shared_1.normalizedPathShape)(operation.path)}`;
        const group = groups.get(key) ?? [];
        group.push(operation);
        groups.set(key, group);
    }
    return groups;
}
function authMatches(expected, actual) {
    return expected.mode === actual.mode && (expected.mode === 'public'
        || expected.alternatives.some((kinds) => sameStrings(kinds, actual.kinds)));
}
function sameStrings(left, right) {
    return left.length === right.length && left.every((value, index) => value === right[index]);
}
function authFindings(input) {
    if (input.implemented.capabilities.authentication === 'unsupported')
        return [];
    const implemented = groupedByMethodShape(input.implemented.operations);
    const findings = [];
    for (const declared of input.declared.operations) {
        const sources = implemented.get(`${declared.method} ${(0, shared_1.normalizedPathShape)(declared.path)}`) ?? [];
        const expected = explicitDeclaredAuth(declared);
        if (!expected)
            continue;
        const contradictions = sources.flatMap((source) => {
            const actual = explicitSourceAuth(source);
            return actual && !authMatches(expected, actual) ? [{ source, actual }] : [];
        });
        if (contradictions.length === 0)
            continue;
        findings.push((0, shared_1.makeFinding)({
            ruleId: 'SC-AUTHN-005',
            severity: 'warning',
            confidence: 'high-confidence',
            category: 'authentication',
            title: 'Declared authentication differs from Source metadata',
            message: `Explicit OpenAPI authentication and high-confidence Source decorator metadata differ. ${SOURCE_SCOPE}`,
            route: route(declared),
            expected,
            actual: { candidates: contradictions.map(({ actual }) => actual) },
            evidence: [
                ...declared.provenance,
                ...contradictions.flatMap(({ source }) => source.provenance),
            ],
            remediation: { summary: 'Align the explicit OpenAPI contract and Source auth decorators.', safeAutoFix: false },
        }));
    }
    return findings;
}
function authorizationFindings(input, rolesByRoute) {
    if (!rolesByRoute)
        return [];
    const implemented = groupedByMethodShape(input.implemented.operations);
    const findings = [];
    for (const declared of input.declared.operations) {
        const roles = rolesByRoute[declared.routeKey];
        if (!roles)
            continue;
        const expected = [...new Set(roles)].sort();
        const contradictions = (implemented.get(`${declared.method} ${(0, shared_1.normalizedPathShape)(declared.path)}`) ?? []).flatMap((source) => {
            const analysis = source.auth.analysis;
            if (!analysis || analysis.enforcementConfidence !== 'high')
                return [];
            const actual = [...new Set(analysis.roles)].sort();
            return sameStrings(expected, actual) ? [] : [{ source, actual }];
        });
        if (contradictions.length === 0)
            continue;
        findings.push((0, shared_1.makeFinding)({
            ruleId: 'SC-AUTHZ-001',
            severity: 'warning',
            confidence: 'high-confidence',
            category: 'authorization',
            title: 'Declared privileged roles differ from Source metadata',
            message: `Explicit privileged-role configuration and high-confidence Source metadata differ. ${SOURCE_SCOPE}`,
            route: route(declared),
            expected: { roles: expected },
            actual: { candidates: contradictions.map(({ actual }) => ({ roles: actual })) },
            evidence: [
                ...declared.provenance,
                ...contradictions.flatMap(({ source }) => source.provenance),
            ],
            remediation: { summary: 'Align explicit privileged-role configuration and Source decorators.', safeAutoFix: false },
        }));
    }
    return findings;
}
function compareSourceOpenApiContracts(input, options = {}) {
    validateInput(input, options);
    return (0, shared_1.stableFindings)([
        ...inventoryFindings(input),
        ...authFindings(input),
        ...authorizationFindings(input, options.declaredPrivilegedRoles),
    ]);
}
