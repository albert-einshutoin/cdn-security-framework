"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.projectPolicyToAllowedSurface = projectPolicyToAllowedSurface;
const edge_cfg_1 = require("../scripts/lib/edge-cfg");
const auth_gate_validation_1 = require("../scripts/lib/auth-gate-validation");
const TARGET_CAPABILITIES = {
    aws: [
        { id: 'request.allow_methods', status: 'supported' },
        { id: 'request.allowed_hosts', status: 'supported' },
        { id: 'routes.request.allow_methods', status: 'unsupported' },
        { id: 'request.uri_query_limits', status: 'supported' },
        { id: 'request.header_limits', status: 'partial' },
        { id: 'request.path_normalization', status: 'supported' },
        { id: 'auth.route_gates', status: 'supported' },
        { id: 'routes.response.cache_control', status: 'supported' },
        { id: 'response.security_headers', status: 'supported' },
        { id: 'response.csp_nonce', status: 'unsupported' },
        { id: 'request.graphql_guard', status: 'warning-only' },
        { id: 'response.response_dlp', status: 'warning-only' },
    ],
    cloudflare: [
        { id: 'request.allow_methods', status: 'supported' },
        { id: 'request.allowed_hosts', status: 'supported' },
        { id: 'routes.request.allow_methods', status: 'unsupported' },
        { id: 'request.uri_query_limits', status: 'supported' },
        { id: 'request.header_limits', status: 'supported' },
        { id: 'request.path_normalization', status: 'supported' },
        { id: 'auth.route_gates', status: 'supported' },
        { id: 'routes.response.cache_control', status: 'supported' },
        { id: 'response.security_headers', status: 'supported' },
        { id: 'response.csp_nonce', status: 'supported' },
        { id: 'request.graphql_guard', status: 'supported' },
        { id: 'response.response_dlp', status: 'supported' },
    ],
};
const AUTH_PROTECTED_CACHE_CONTROL = 'no-store, no-cache, must-revalidate, private';
function stableMethods(methods) {
    return [...new Set(methods)].sort();
}
function stablePrefixes(prefixes) {
    return [...new Set(prefixes)].sort();
}
function credentialEnvironmentNames(route) {
    const gate = route.auth_gate;
    if (!gate)
        return [];
    switch (gate.type || 'static_token') {
        case 'static_token': return [gate.token_env || 'EDGE_ADMIN_TOKEN'];
        case 'basic_auth': return [gate.credentials_env || 'BASIC_AUTH_CREDS'];
        case 'jwt': return gate.secret_env ? [gate.secret_env] : [];
        case 'signed_url': return [gate.secret_env || 'URL_SIGNING_SECRET'];
    }
}
function typeSource(route) {
    if (!route.auth_gate)
        return 'absent';
    return route.auth_gate.type ? 'explicit' : 'compiler-default';
}
function authAlgorithms(route, kind) {
    const configured = route.auth_gate?.algorithm;
    if (kind === 'jwt') {
        const algorithm = configured || 'RS256';
        return {
            configuredAlgorithm: algorithm,
            ...((algorithm === 'HS256' || algorithm === 'RS256') ? { effectiveAlgorithm: algorithm } : {}),
        };
    }
    if (kind === 'signed_url') {
        return {
            configuredAlgorithm: configured || 'HMAC-SHA256',
            effectiveAlgorithm: 'HMAC-SHA256',
        };
    }
    return {};
}
function authVerifiability(policy, route, kind, algorithms) {
    if (kind === 'none')
        return { aws: 'not-applicable', cloudflare: 'not-applicable' };
    const runtimeUnsupported = kind === 'jwt' && !algorithms.effectiveAlgorithm;
    const awsErrors = (0, auth_gate_validation_1.validateAuthGateStructure)(policy, route);
    const cloudflareErrors = (0, auth_gate_validation_1.validateAuthGateStructure)(policy, route, { requireJwksAllowedHosts: true });
    return {
        aws: runtimeUnsupported || awsErrors.length > 0 ? 'unsupported-configuration' : 'enforced',
        cloudflare: runtimeUnsupported || cloudflareErrors.length > 0
            ? 'unsupported-configuration'
            : 'enforced',
    };
}
function sourceEvidence(options) {
    if (!/^sha256:[a-f0-9]{64}$/.test(options.policyDigest))
        throw new Error('invalid policy digest');
    const uri = options.sourceUri.trim().replace(/\\/g, '/').replace(/^\.\//, '');
    if (!uri || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(uri) || uri.startsWith('/')
        || uri.split('/').includes('..') || /[?#\u0000-\u001f\u007f]/.test(uri)) {
        throw new Error('invalid policy source uri');
    }
    return {
        source: 'policy',
        uri,
        digest: options.policyDigest,
        analyzer: 'allowed-surface@1',
        capability: 'policy-projection-v1',
        complete: true,
    };
}
function projectPolicyToAllowedSurface(policy, options) {
    const evidence = sourceEvidence(options);
    const routes = policy.routes || [];
    const request = (0, edge_cfg_1.buildRequestCfgBase)(policy);
    const gates = routes.filter((route) => route.auth_gate).map(edge_cfg_1.buildAuthGateBase);
    const compilerResponse = (0, edge_cfg_1.buildResponseCfgBase)(policy, gates);
    const configuredMethods = stableMethods(Array.isArray(request.allowMethods) ? request.allowMethods : []);
    const corsOptionsBypass = request.cors !== null;
    const methods = stableMethods(corsOptionsBypass ? [...configuredMethods, 'OPTIONS'] : configuredMethods);
    const mode = request.mode === 'monitor' ? 'monitor' : 'enforce';
    const requestDecision = mode === 'monitor' ? 'would-block' : 'block';
    const selectedResponseRule = routes.findIndex((route) => ((route.match.path_prefixes || []).length > 0
        && Boolean(route.auth_gate || route.response?.cache_control)));
    return {
        schemaVersion: 1,
        policyDigest: options.policyDigest,
        defaults: {
            mode,
            requestDecision,
            authenticationDecision: 'block',
            methods,
            configuredMethods,
            corsOptionsBypass,
            corsPreflight: {
                method: 'OPTIONS',
                allowedOriginDecision: corsOptionsBypass
                    ? 'early-204-before-request-validation'
                    : 'not-configured',
                allowedOriginResponseCacheControl: corsOptionsBypass ? 'no-store' : 'not-configured',
                nonMatchingOriginDecision: 'continue',
                bypassScope: corsOptionsBypass ? 'all-request-validation-including-host-and-auth' : 'none',
            },
            hosts: {
                kind: request.allowedHosts.length === 0 ? 'any' : 'allowlist',
                values: stablePrefixes(request.allowedHosts),
                comparison: 'case-insensitive-without-port',
                wildcard: 'leading-subdomain-only',
            },
            limits: {
                maxQueryLength: request.maxQueryLength,
                maxQueryParams: request.maxQueryParams,
                maxUriLength: request.maxUriLength,
                maxHeaderSize: request.maxHeaderSize,
                maxHeaderCount: request.maxHeaderCount,
            },
            pathNormalization: {
                ...request.normalizePath,
                routeMatchPhase: 'normalized-path',
            },
            response: {
                headers: Object.fromEntries(Object.entries(compilerResponse.headers).map(([name, value]) => [name, String(value)])),
                cspPublic: String(compilerResponse.csp_public),
                cspAdmin: String(compilerResponse.csp_admin),
                cspNonce: compilerResponse.csp_nonce,
                adminPathMatch: {
                    kind: 'prefix',
                    values: stablePrefixes(compilerResponse.adminPathPrefixes),
                    boundary: 'path-segment',
                    algorithm: 'equal-or-prefix-plus-slash',
                    comparison: 'literal-no-percent-decoding',
                    phase: 'normalized-path',
                },
                adminCacheControl: compilerResponse.adminCacheControl,
                forceVaryAuth: compilerResponse.forceVaryAuth,
                ...(compilerResponse.forceVaryAuth && compilerResponse.authProtectedPrefixes.length > 0 ? {
                    authProtectedCacheControlOverride: {
                        when: 'force-vary-auth-and-auth-protected-path',
                        value: AUTH_PROTECTED_CACHE_CONTROL,
                        pathMatch: {
                            kind: 'prefix',
                            values: stablePrefixes(compilerResponse.authProtectedPrefixes),
                            boundary: 'path-segment',
                            algorithm: 'equal-or-prefix-plus-slash',
                            comparison: 'literal-no-percent-decoding',
                            phase: 'normalized-path',
                        },
                    },
                } : {}),
                ...(compilerResponse.clearSiteDataPaths.length > 0 ? {
                    clearSiteDataCacheControlOverride: {
                        when: 'matching-path-and-status-200-through-399',
                        value: 'no-store',
                        order: 'after-auth-protected-override',
                        pathMatch: {
                            kind: 'prefix',
                            values: stablePrefixes(compilerResponse.clearSiteDataPaths),
                            boundary: 'path-segment',
                            algorithm: 'equal-or-prefix-plus-slash',
                            comparison: 'literal-no-percent-decoding',
                            phase: 'normalized-path',
                        },
                    },
                } : {}),
            },
        },
        orderedRules: routes.map((route, index) => {
            const gate = route.auth_gate;
            const authKind = gate ? (gate.type || 'static_token') : 'none';
            const algorithms = authAlgorithms(route, authKind);
            const verification = authVerifiability(policy, route, authKind, algorithms);
            const configuredPrefixes = stablePrefixes(route.match.path_prefixes || []);
            return {
                index,
                name: route.name,
                pointer: `/routes/${index}`,
                match: {
                    kind: 'prefix',
                    values: configuredPrefixes,
                    boundary: 'path-segment',
                    algorithm: 'equal-or-prefix-plus-slash',
                    comparison: 'literal-no-percent-decoding',
                    phase: 'normalized-path',
                    authEffectiveValues: gate
                        ? stablePrefixes((0, edge_cfg_1.buildAuthGateBase)(route).protectedPrefixes)
                        : [],
                },
                methods: {
                    source: 'global',
                    effective: methods,
                    ...(route.request?.allow_methods === undefined ? {} : {
                        configuredButNotEnforced: stableMethods(route.request.allow_methods),
                    }),
                },
                auth: {
                    kind: authKind,
                    typeSource: typeSource(route),
                    matching: {
                        aws: 'static-and-basic-in-policy-order-then-jwt-then-signed-url',
                        cloudflare: 'all-matching-rules-in-policy-order',
                    },
                    exactPath: authKind === 'signed_url' && gate?.exact_path === true,
                    preAuthBypassMethods: corsOptionsBypass ? ['OPTIONS'] : [],
                    preAuthBypassCondition: corsOptionsBypass ? 'allowed-cors-origin-preflight' : 'none',
                    credentialEnvironmentNames: credentialEnvironmentNames(route),
                    ...algorithms,
                    verifiability: verification,
                },
                requestLimits: { source: 'global' },
                response: {
                    ...(route.response?.cache_control === undefined ? {} : {
                        cacheControl: route.response.cache_control,
                    }),
                    ...(index === selectedResponseRule ? {
                        selectedBaseCacheControl: compilerResponse.adminCacheControl,
                    } : {}),
                    selection: index === selectedResponseRule ? 'first-auth-or-cache-rule' : 'not-selected',
                },
                mode: {
                    requestDecision,
                    authenticationDecision: 'block',
                },
            };
        }),
        targetCapabilities: {
            aws: TARGET_CAPABILITIES.aws.map((capability) => ({ ...capability })),
            cloudflare: TARGET_CAPABILITIES.cloudflare.map((capability) => ({ ...capability })),
        },
        provenance: [evidence],
    };
}
