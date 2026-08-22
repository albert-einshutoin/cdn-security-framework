"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.pathRelation = pathRelation;
exports.policyEvidence = policyEvidence;
exports.evidenceFor = evidenceFor;
exports.makeFinding = makeFinding;
exports.stableFindings = stableFindings;
exports.matchingAuthRules = matchingAuthRules;
exports.validateComparisonInput = validateComparisonInput;
exports.normalizedPathShape = normalizedPathShape;
const finding_1 = require("../finding");
const finding_order_1 = require("../finding-order");
const route_relation_1 = require("../route-relation");
const MAX_COMPARISON_VISITS = 1_000_000;
function pathRelation(operation, policyPath, allowed, policyKind = 'prefix') {
    return (0, route_relation_1.relatePath)({ kind: operation.path.includes('{') ? 'template' : 'exact', value: operation.path }, { kind: policyKind, value: policyPath }, {
        phase: 'normalized-path',
        collapseSlashes: allowed.defaults.pathNormalization.collapseSlashes,
        removeDotSegments: allowed.defaults.pathNormalization.removeDotSegments,
    });
}
function policyEvidence(allowed, pointer, capability) {
    const evidence = allowed.provenance[0];
    if (!evidence)
        throw new Error('allowed surface provenance is required');
    return { ...evidence, pointer, capability };
}
function evidenceFor(operation, allowed, pointer, capability) {
    return [...operation.provenance, policyEvidence(allowed, pointer, capability)];
}
function makeFinding(input) {
    return (0, finding_1.createFinding)(input);
}
function stableFindings(findings) {
    return (0, finding_order_1.sortFindings)([...new Map(findings.map((finding) => [finding.instanceId, finding])).values()]);
}
function matchingAuthRules(operation, allowed) {
    return allowed.orderedRules.flatMap((rule) => {
        const relations = rule.match.authEffectiveValues.map((policyPath) => pathRelation(operation, policyPath, allowed, rule.auth.exactPath ? 'exact' : 'prefix'));
        if (relations.includes('definitely-covered')) {
            return [{ rule, relation: 'definitely-covered' }];
        }
        if (relations.includes('possibly-overlapping')) {
            return [{ rule, relation: 'possibly-overlapping' }];
        }
        if (relations.includes('unknown'))
            return [{ rule, relation: 'unknown' }];
        return [];
    });
}
function validateComparisonInput(input) {
    if (!input || input.declared.schemaVersion !== 1 || input.allowed.schemaVersion !== 1
        || !['aws', 'cloudflare'].includes(input.target)
        || !Array.isArray(input.declared.operations) || !Array.isArray(input.allowed.orderedRules)
        || !Array.isArray(input.allowed.defaults?.methods)
        || (input.allowed.defaults.requiredHeaders !== undefined
            && !Array.isArray(input.allowed.defaults.requiredHeaders.values))) {
        throw new Error('invalid contract drift input');
    }
    let comparisonWidth = input.allowed.defaults.methods.length
        + (input.allowed.defaults.requiredHeaders?.values.length ?? 0);
    for (const rule of input.allowed.orderedRules) {
        if (!Array.isArray(rule.match?.values) || !Array.isArray(rule.match.authEffectiveValues)) {
            throw new Error('invalid contract drift input');
        }
        comparisonWidth += rule.match.values.length + rule.match.authEffectiveValues.length + 1;
        if (!Number.isSafeInteger(comparisonWidth) || comparisonWidth > MAX_COMPARISON_VISITS) {
            throw new Error('contract drift comparison exceeds visit budget');
        }
    }
    let visits = 0;
    const ruleCount = Math.max(1, input.allowed.orderedRules.length);
    for (const operation of input.declared.operations) {
        if (!Array.isArray(operation.auth?.alternatives))
            throw new Error('invalid contract drift input');
        let schemes = 0;
        for (const alternative of operation.auth.alternatives) {
            if (!Array.isArray(alternative.schemes))
                throw new Error('invalid contract drift input');
            schemes += alternative.schemes.length;
            if (!Number.isSafeInteger(schemes)) {
                throw new Error('contract drift comparison exceeds visit budget');
            }
        }
        const remaining = MAX_COMPARISON_VISITS - visits - comparisonWidth;
        if (remaining < 0 || schemes > Math.floor(remaining / ruleCount)) {
            throw new Error('contract drift comparison exceeds visit budget');
        }
        visits += comparisonWidth + schemes * ruleCount;
    }
}
function normalizedPathShape(value) {
    return value.replace(/\{[^{}\/]+\}/g, '{}');
}
