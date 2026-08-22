"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.comparePathMethodContracts = comparePathMethodContracts;
const shared_1 = require("./shared");
function comparePathMethodContracts(input) {
    (0, shared_1.validateComparisonInput)(input);
    const { declared, allowed } = input;
    const findings = [];
    const methodsPointer = allowed.defaults.methodSource === 'configured'
        ? '/request/allow_methods' : '/request';
    const operationsByPath = new Map();
    for (const operation of declared.operations) {
        const operations = operationsByPath.get(operation.path) ?? [];
        operations.push(operation);
        operationsByPath.set(operation.path, operations);
        if (!allowed.defaults.methods.includes(operation.method)) {
            const monitor = allowed.defaults.requestDecision === 'would-block';
            findings.push((0, shared_1.makeFinding)({
                ruleId: 'SC-EXPOSURE-002',
                severity: monitor ? 'warning' : 'error',
                confidence: 'deterministic',
                category: 'exposure',
                title: monitor ? 'Declared operation would be blocked in enforce mode' : 'Declared operation blocked by Policy',
                message: monitor
                    ? 'The selected Edge target currently allows this operation only because monitor mode downgrades the method rejection.'
                    : 'The selected Edge target rejects an operation declared by OpenAPI.',
                route: { method: operation.method, path: operation.path, operationId: operation.operationId },
                expected: { methods: [operation.method] },
                actual: { methods: allowed.defaults.methods, decision: allowed.defaults.requestDecision },
                evidence: (0, shared_1.evidenceFor)(operation, allowed, methodsPointer, 'path-method-drift-v1'),
                remediation: { summary: 'Align the effective Policy method set with the declared operation.', safeAutoFix: false },
            }));
        }
    }
    for (const [routePath, operations] of operationsByPath) {
        const declaredMethods = [...new Set(operations.map(({ method }) => method))].sort();
        const declaredMethodSet = new Set(declaredMethods);
        const extraMethods = allowed.defaults.methods.filter((method) => !declaredMethodSet.has(method));
        const monitor = allowed.defaults.requestDecision === 'would-block';
        if ((extraMethods.length > 0 || monitor) && declared.capabilities.routes === 'complete') {
            findings.push((0, shared_1.makeFinding)({
                ruleId: 'SC-EXPOSURE-001',
                severity: monitor ? 'warning' : 'error',
                confidence: 'deterministic',
                category: 'exposure',
                title: monitor
                    ? 'Monitor mode permits undeclared methods on a declared route'
                    : 'Policy allows undeclared methods on a declared route',
                message: monitor
                    ? 'Method rejections are observed but not blocked in monitor mode, so the Edge method surface is not restricted.'
                    : 'The global Edge method allowlist includes methods not declared for this OpenAPI route.',
                route: { path: routePath },
                expected: { methods: declaredMethods },
                actual: {
                    methods: allowed.defaults.methods,
                    extraMethods,
                    ...(monitor ? {
                        decision: allowed.defaults.requestDecision,
                        methodSurface: 'unrestricted-by-edge-in-monitor-mode',
                    } : {}),
                },
                evidence: (0, shared_1.evidenceFor)(operations[0], allowed, methodsPointer, 'path-method-drift-v1'),
                remediation: { summary: 'Remove undeclared methods or declare the intended operations.', safeAutoFix: false },
            }));
        }
    }
    const declaredShapes = new Set(declared.operations.map(({ path }) => (0, shared_1.normalizedPathShape)(path)));
    for (const rule of allowed.orderedRules) {
        if (rule.auth.kind === 'none')
            continue;
        const policyPaths = rule.auth.exactPath
            ? rule.match.authEffectiveValues
            : [...new Set([...rule.match.values, ...rule.match.authEffectiveValues])].sort();
        for (const prefix of policyPaths) {
            const exactRelations = rule.auth.exactPath
                ? declared.operations.map((operation) => (0, shared_1.pathRelation)(operation, prefix, allowed, 'exact'))
                : [];
            if (rule.auth.exactPath
                && !declaredShapes.has((0, shared_1.normalizedPathShape)(prefix))
                && exactRelations.every((relation) => relation === 'definitely-disjoint')) {
                findings.push((0, shared_1.makeFinding)({
                    ruleId: 'SC-INVENTORY-002',
                    severity: declared.capabilities.routes === 'complete' ? 'error' : 'warning',
                    confidence: 'deterministic',
                    category: 'inventory',
                    title: 'Exact Policy route is not declared',
                    message: 'An exact Edge Policy route has no corresponding OpenAPI operation.',
                    route: { path: prefix },
                    expected: { declaredRoute: true },
                    actual: { policyRule: rule.name, exactPath: true },
                    evidence: [(0, shared_1.policyEvidence)(allowed, rule.match.values.includes(prefix)
                            ? `${rule.pointer}/match/path_prefixes`
                            : `${rule.pointer}/auth_gate/exact_path`, 'path-method-drift-v1')],
                    remediation: { summary: 'Declare the route or remove the exact Policy rule.', safeAutoFix: false },
                }));
            }
            else if (!rule.auth.exactPath) {
                const relations = declared.operations.map((operation) => (0, shared_1.pathRelation)(operation, prefix, allowed));
                findings.push((0, shared_1.makeFinding)({
                    ruleId: 'SC-EXPOSURE-003',
                    severity: 'warning',
                    confidence: 'heuristic',
                    category: 'exposure',
                    title: 'Broad Policy rule may exceed the declared surface',
                    message: 'This prefix rule may cover routes outside the OpenAPI inventory; the analyzer does not promote this uncertainty to an Error.',
                    route: { path: prefix },
                    expected: { relation: 'declared-surface-only' },
                    actual: {
                        relations: [...new Set(relations.length === 0 ? ['unknown'] : relations)].sort(),
                        policyRule: rule.name,
                    },
                    evidence: [(0, shared_1.policyEvidence)(allowed, rule.match.values.includes(prefix)
                            ? `${rule.pointer}/match/path_prefixes`
                            : `${rule.pointer}/auth_gate`, 'path-method-drift-v1')],
                    remediation: { summary: 'Narrow the prefix or document the intentionally broader Edge surface.', safeAutoFix: false },
                }));
            }
        }
    }
    return (0, shared_1.stableFindings)(findings);
}
