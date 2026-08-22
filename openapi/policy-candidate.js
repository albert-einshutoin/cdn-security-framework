"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.POLICY_CANDIDATE_PROFILES = exports.POLICY_CANDIDATE_GENERATOR_VERSION = void 0;
exports.explainOpenApiPathPrefixMapping = explainOpenApiPathPrefixMapping;
exports.generatePolicyCandidate = generatePolicyCandidate;
const node_crypto_1 = require("node:crypto");
const recommendation_1 = require("../recommendation");
exports.POLICY_CANDIDATE_GENERATOR_VERSION = 1;
exports.POLICY_CANDIDATE_PROFILES = ['strict', 'balanced', 'permissive'];
const POLICY_LIMITS = {
    max_query_params: 1_024,
    max_query_length: 65_536,
    max_uri_length: 8_192,
};
function compareText(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
function objectValue(value) {
    return value && typeof value === 'object' && !Array.isArray(value)
        ? value
        : {};
}
function canonicalJson(value) {
    if (Array.isArray(value))
        return `[${value.map(canonicalJson).join(',')}]`;
    if (value && typeof value === 'object') {
        return `{${Object.entries(value)
            .sort(([left], [right]) => compareText(left, right))
            .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
            .join(',')}}`;
    }
    return JSON.stringify(value);
}
function digest(value) {
    return `sha256:${(0, node_crypto_1.createHash)('sha256').update(canonicalJson(value)).digest('hex')}`;
}
function uniqueSorted(values) {
    return [...new Set(values)].sort(compareText);
}
function recommendationBasis(recommendations) {
    return uniqueSorted(recommendations.flatMap(({ basis }) => basis));
}
function applyNumericLimit(policyLimits, field, recommendations, applied, omitted) {
    const basis = recommendationBasis(recommendations);
    const usable = recommendations.length > 0 && recommendations.every((candidate) => (candidate.value !== null
        && (candidate.estimateKind === 'exact' || candidate.estimateKind === 'upper-bound')));
    const value = usable
        ? Math.max(...recommendations.map((candidate) => candidate.value))
        : null;
    if (value !== null && typeof policyLimits[field] === 'number') {
        omitted.push({
            id: field,
            reason: 'profile-baseline-retained-for-open-query-surface',
            basis,
        });
        return;
    }
    if (value !== null && value >= 1 && value <= POLICY_LIMITS[field]) {
        policyLimits[field] = value;
        applied.push({ id: field, policyPath: `request.limits.${field}`, basis, value });
        return;
    }
    omitted.push({
        id: field,
        reason: value === 0
            ? 'current-policy-schema-cannot-express-zero'
            : value !== null
                ? 'recommendation-outside-current-policy-schema-range'
                : 'recommendation-is-partial-unknown-or-unbounded',
        basis,
    });
}
function commonRequiredHeaders(contract) {
    const [first, ...rest] = contract.operations;
    if (!first)
        return [];
    const common = new Set(first.request.requiredHeaders);
    for (const operation of rest) {
        const current = new Set(operation.request.requiredHeaders);
        for (const header of common)
            if (!current.has(header))
                common.delete(header);
    }
    return uniqueSorted(common);
}
function explainOpenApiPathPrefixMapping(openApiPath) {
    return openApiPath.includes('{')
        ? 'path-template-not-representable-by-static-prefix'
        : 'prefix-match-would-also-match-descendant-paths';
}
function generatePolicyCandidate(contract, options) {
    if (!contract || contract.schemaVersion !== 1 || !Array.isArray(contract.operations)) {
        throw new Error('invalid security contract');
    }
    if (!exports.POLICY_CANDIDATE_PROFILES.includes(options.profile)) {
        throw new Error('invalid policy candidate profile');
    }
    if (!/^sha256:[a-f0-9]{64}$/.test(options.sourceDigest))
        throw new Error('invalid source digest');
    const policy = structuredClone(options.profilePolicy);
    const request = objectValue(policy.request);
    const limits = objectValue(request.limits);
    const block = objectValue(request.block);
    const recommendations = (0, recommendation_1.recommendRequestLimits)(contract);
    const operationRecommendations = recommendations.routes.flatMap(({ operations }) => operations);
    const applied = [];
    const omitted = [];
    delete policy.routes;
    if (contract.capabilities.routes === 'complete') {
        const methods = uniqueSorted(contract.operations.map(({ method }) => method));
        request.allow_methods = methods;
        applied.push({
            id: 'global-allowed-methods',
            policyPath: 'request.allow_methods',
            basis: recommendationBasis(recommendations.routes.map(({ allowedMethods }) => allowedMethods)),
            value: methods,
        });
    }
    else {
        omitted.push({ id: 'global-allowed-methods', reason: 'route-capability-is-not-complete', basis: [] });
    }
    const headers = commonRequiredHeaders(contract);
    const baselineHeaders = Array.isArray(block.header_missing)
        ? block.header_missing.filter((header) => typeof header === 'string')
        : [];
    if (headers.length > 0) {
        const requiredHeaders = uniqueSorted([...baselineHeaders, ...headers]);
        block.header_missing = requiredHeaders;
        applied.push({
            id: 'global-required-headers',
            policyPath: 'request.block.header_missing',
            basis: recommendationBasis(operationRecommendations.map(({ requiredHeaders }) => requiredHeaders)),
            value: requiredHeaders,
        });
    }
    const routeSpecificHeaders = uniqueSorted(contract.operations.flatMap(({ request: operationRequest }) => (operationRequest.requiredHeaders.filter((header) => !headers.includes(header)))));
    if (routeSpecificHeaders.length > 0)
        omitted.push({
            id: 'route-specific-required-headers',
            reason: 'current-policy-schema-only-supports-global-required-headers',
            basis: recommendationBasis(operationRecommendations.map(({ requiredHeaders }) => requiredHeaders)),
        });
    applyNumericLimit(limits, 'max_query_params', operationRecommendations.map(({ maxQueryParams }) => maxQueryParams), applied, omitted);
    applyNumericLimit(limits, 'max_query_length', operationRecommendations.map(({ maxQueryLength }) => maxQueryLength), applied, omitted);
    applyNumericLimit(limits, 'max_uri_length', operationRecommendations.map(({ maxUriLength }) => maxUriLength), applied, omitted);
    request.limits = limits;
    request.block = block;
    policy.request = request;
    if (contract.operations.some(({ auth }) => auth.mode !== 'none'))
        omitted.push({
            id: 'authentication',
            reason: 'authentication-requires-explicit-mapping-and-secret-configuration',
            basis: uniqueSorted(contract.operations.flatMap(({ provenance }) => provenance.flatMap(({ pointer }) => pointer ? [pointer] : []))),
        });
    if (contract.operations.some(({ request: operationRequest }) => operationRequest.contentTypes.length > 0)) {
        omitted.push({
            id: 'allowed-content-types',
            reason: 'current-policy-schema-has-no-equivalent-request-control',
            basis: recommendationBasis(operationRecommendations.map(({ allowedContentTypes }) => allowedContentTypes)),
        });
    }
    if (contract.operations.some(({ request: operationRequest }) => operationRequest.body))
        omitted.push({
            id: 'max-body-bytes',
            reason: 'current-policy-schema-has-no-equivalent-request-control',
            basis: recommendationBasis(operationRecommendations.map(({ maxBodyBytes }) => maxBodyBytes)),
        });
    if (contract.operations.some(({ request: operationRequest }) => (operationRequest.queryParameters.length + operationRequest.pathParameters.length
        + operationRequest.headerParameters.length + operationRequest.cookieParameters.length > 0)))
        omitted.push({
            id: 'parameter-constraints',
            reason: 'current-policy-schema-has-no-equivalent-request-control',
            basis: recommendationBasis(operationRecommendations.map(({ parameterConstraints }) => parameterConstraints)),
        });
    for (const route of recommendations.routes)
        omitted.push({
            id: `route-match:${route.path}`,
            reason: explainOpenApiPathPrefixMapping(route.path),
            basis: route.allowedMethods.basis,
        });
    applied.sort((left, right) => compareText(left.id, right.id));
    omitted.sort((left, right) => compareText(left.id, right.id));
    const capabilityFindings = options.evaluateCapabilities?.(policy).findings ?? [];
    return {
        policy,
        metadata: {
            schemaVersion: 1,
            generator: {
                name: 'cdn-security-openapi-policy-candidate',
                version: exports.POLICY_CANDIDATE_GENERATOR_VERSION,
            },
            profile: options.profile,
            sourceDigest: options.sourceDigest,
            irDigest: digest(contract),
            candidateDigest: digest(policy),
            appliedRecommendations: applied,
            omittedRecommendations: omitted,
            capabilityFindings,
        },
    };
}
