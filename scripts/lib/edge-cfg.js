"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const { clampNumber, normalizeStringList, numberOr, } = require('./value-normalize');
const { DEFAULT_ADMIN_PATH_PREFIXES, DEFAULT_ALLOW_METHODS, DEFAULT_CLEAR_SITE_DATA_TYPES, DEFAULT_CSP_ADMIN, DEFAULT_CSP_PUBLIC, DEFAULT_DROP_QUERY_KEYS, DEFAULT_REQUIRED_HEADERS, DEFAULT_SECURITY_HEADERS, DEFAULT_UA_DENY_CONTAINS, JWKS_DEFAULTS, JWT_CLOCK_SKEW, LIMITS_DEFAULTS, } = require('./policy-defaults');
const { errorMessage, } = require('./errors');
const DEFAULT_CONTAINS = ['/../', '%2e%2e', '%2f..', '..%2f', '%5c'];
const LEGACY_KNOWN_MAP = {
    '(?i)\\.{2}/': { contains: ['/../', '..'] },
    '(?i)%2e%2e': { contains: ['%2e%2e'] },
};
function extractRegex(source) {
    if (typeof source !== 'string') {
        throw new Error('Regex source must be a string');
    }
    const trimmed = source.trim();
    if (!trimmed) {
        throw new Error('Regex source must be non-empty');
    }
    if (trimmed.startsWith('(?i)')) {
        return { pattern: trimmed.slice(4), flags: 'i' };
    }
    return { pattern: trimmed, flags: '' };
}
function compileRegexOrThrow(source, context) {
    const { pattern, flags } = extractRegex(source);
    try {
        return new RegExp(pattern, flags);
    }
    catch (e) {
        throw new Error(`Invalid regex in ${context}: ${source} — ${errorMessage(e)}`);
    }
}
function hasCatastrophicBacktrackShape(src) {
    if (typeof src !== 'string' || src.length === 0)
        return false;
    const body = src.replace(/^\(\?[ims]+\)/, '');
    const nested = /\(([^()]*[+*?{][^()]*)\)[+*?{]/;
    return nested.test(body);
}
function looksLikeRegex(s) {
    return /[\\(){}\[\]|^$+?*]|\.\{|\\\\/.test(s);
}
function parsePathPatterns(pathPatterns) {
    if (pathPatterns === undefined || pathPatterns === null) {
        return { contains: DEFAULT_CONTAINS.slice(), regexSources: [] };
    }
    if (Array.isArray(pathPatterns)) {
        const contains = new Set();
        const regexSources = [];
        for (const raw of pathPatterns) {
            const s = (raw || '').trim();
            if (!s)
                continue;
            const mapped = LEGACY_KNOWN_MAP[s];
            if (mapped) {
                if (mapped.contains)
                    mapped.contains.forEach((m) => contains.add(m.toLowerCase()));
                if (mapped.regex)
                    mapped.regex.forEach((m) => regexSources.push(m));
                continue;
            }
            if (looksLikeRegex(s)) {
                throw new Error(`Ambiguous path_patterns entry: "${s}". ` +
                    'Move regex-style patterns under `path_patterns.regex: [...]` or ' +
                    'literal substrings under `path_patterns.contains: [...]`.');
            }
            contains.add(s.toLowerCase());
        }
        if (contains.size === 0 && regexSources.length === 0) {
            return { contains: DEFAULT_CONTAINS.slice(), regexSources: [] };
        }
        return { contains: Array.from(contains), regexSources };
    }
    if (typeof pathPatterns === 'object' && pathPatterns !== null) {
        const obj = pathPatterns;
        const rawContains = Array.isArray(obj.contains) ? obj.contains.filter(Boolean) : [];
        const regexSources = Array.isArray(obj.regex) ? obj.regex.filter(Boolean) : [];
        const contains = [];
        for (const raw of rawContains) {
            const s = typeof raw === 'string' ? raw.trim() : '';
            if (!s)
                continue;
            if (looksLikeRegex(s)) {
                throw new Error(`Ambiguous path_patterns.contains entry: "${s}". ` +
                    'This looks like a regex. Move it under `path_patterns.regex: [...]`, ' +
                    'or escape the metacharacters if you genuinely want a literal substring.');
            }
            contains.push(s.toLowerCase());
        }
        for (const src of regexSources) {
            compileRegexOrThrow(src, 'request.block.path_patterns.regex');
            if (hasCatastrophicBacktrackShape(src)) {
                throw new Error(`request.block.path_patterns.regex: pattern rejected by ReDoS safety check ` +
                    `(nested-quantifier shape triggers catastrophic backtracking): ${JSON.stringify(src)}. ` +
                    `Rewrite without stacking quantifiers — for example, use a character class like ` +
                    `[a-z]+ instead of (a+)+.`);
            }
        }
        if (contains.length === 0 && regexSources.length === 0) {
            return { contains: DEFAULT_CONTAINS.slice(), regexSources: [] };
        }
        return { contains, regexSources };
    }
    throw new Error('request.block.path_patterns must be an array or an object with contains/regex');
}
function regexesLiteralCode(regexSources) {
    if (regexSources.length === 0)
        return '[]';
    const literals = regexSources.map((src) => {
        const re = compileRegexOrThrow(src, 'request.block.path_patterns.regex');
        return re.toString();
    });
    return '[' + literals.join(', ') + ']';
}
function buildAnomalyGuardConfig(policy) {
    const raw = policy && policy.request && policy.request.anomaly_guards;
    if (!raw || raw.enabled !== true) {
        return {
            enabled: false,
            crlf: false,
            malformedCookie: false,
            doubleEncodedTraversal: false,
            maxCookieBytes: 4096,
            maxCookiePairs: 80,
        };
    }
    return {
        enabled: true,
        crlf: raw.crlf !== false,
        malformedCookie: raw.malformed_cookie !== false,
        doubleEncodedTraversal: raw.double_encoded_traversal !== false,
        maxCookieBytes: clampNumber(raw.max_cookie_bytes, 1, 65536, 4096),
        maxCookiePairs: clampNumber(raw.max_cookie_pairs, 1, 1000, 80),
    };
}
function buildObsConfig(policy) {
    const obs = (policy && policy.observability) || {};
    const format = obs.log_format === 'text' ? 'text' : 'json';
    const correlationHeader = typeof obs.correlation_id_header === 'string' && obs.correlation_id_header.trim()
        ? obs.correlation_id_header.trim().toLowerCase()
        : '';
    let sampleRate = Number(obs.sample_rate);
    if (!Number.isFinite(sampleRate) || sampleRate < 0)
        sampleRate = 0;
    if (sampleRate > 1)
        sampleRate = 1;
    return {
        logFormat: format,
        correlationHeader,
        sampleRate,
        auditLogAuth: obs.audit_log_auth === true,
        auditHashSub: obs.audit_hash_sub === true,
    };
}
function findAdminCacheRoute(routes) {
    let adminPathPrefixes = [];
    let adminCacheControl = 'no-store';
    for (const route of routes) {
        const match = route.match || {};
        const prefixes = match.path_prefixes || [];
        const resp = route.response || {};
        if (prefixes.length && (route.auth_gate || resp.cache_control)) {
            adminPathPrefixes = prefixes;
            if (resp.cache_control)
                adminCacheControl = resp.cache_control;
            break;
        }
    }
    if (adminPathPrefixes.length === 0)
        adminPathPrefixes = [...DEFAULT_ADMIN_PATH_PREFIXES];
    return { adminPathPrefixes, adminCacheControl };
}
function collectAuthProtectedPrefixes(authGates) {
    return Array.from(new Set((authGates || []).flatMap((g) => Array.isArray(g.protectedPrefixes) ? g.protectedPrefixes : [])));
}
function buildAuthGateBase(route) {
    const gate = route.auth_gate || {};
    const match = route.match || {};
    const prefixes = match.path_prefixes || [];
    const authType = gate.type || 'static_token';
    return {
        name: route.name || 'unnamed',
        protectedPrefixes: prefixes.length ? prefixes : [...DEFAULT_ADMIN_PATH_PREFIXES],
        type: authType,
    };
}
function buildResponseCfgBase(policy, authGates) {
    const resHeaders = policy.response_headers || {};
    const { adminPathPrefixes, adminCacheControl } = findAdminCacheRoute(policy.routes || []);
    const authProtectedPrefixes = collectAuthProtectedPrefixes(authGates);
    const forceVaryAuth = resHeaders.force_vary_auth !== false;
    return {
        headers: {
            'strict-transport-security': resHeaders.hsts || DEFAULT_SECURITY_HEADERS['strict-transport-security'],
            'x-content-type-options': resHeaders.x_content_type_options || DEFAULT_SECURITY_HEADERS['x-content-type-options'],
            'referrer-policy': resHeaders.referrer_policy || DEFAULT_SECURITY_HEADERS['referrer-policy'],
            'permissions-policy': resHeaders.permissions_policy || DEFAULT_SECURITY_HEADERS['permissions-policy'],
        },
        csp_public: resHeaders.csp_public || DEFAULT_CSP_PUBLIC,
        csp_admin: resHeaders.csp_admin || DEFAULT_CSP_ADMIN,
        csp_report_only: resHeaders.csp_report_only || '',
        csp_report_uri: resHeaders.csp_report_uri || '',
        csp_nonce: resHeaders.csp_nonce === true,
        coop: resHeaders.coop || '',
        coep: resHeaders.coep || '',
        corp: resHeaders.corp || '',
        reporting_endpoints: resHeaders.reporting_endpoints || '',
        adminPathPrefixes,
        adminCacheControl,
        authProtectedPrefixes,
        forceVaryAuth,
        clearSiteDataPaths: normalizeStringList(resHeaders.clear_site_data_paths, 'preserve', { trim: false }),
        clearSiteDataTypes: Array.isArray(resHeaders.clear_site_data_types) && resHeaders.clear_site_data_types.length > 0
            ? resHeaders.clear_site_data_types
            : DEFAULT_CLEAR_SITE_DATA_TYPES,
        cors: resHeaders.cors || null,
        cookie_attributes: resHeaders.cookie_attributes || null,
    };
}
function buildJwksCacheCfg(policy) {
    const jwksGlobal = (policy.firewall || {}).jwks || {};
    return {
        staleIfErrorSec: clampNumber(jwksGlobal.stale_if_error_sec, 0, JWKS_DEFAULTS.staleMax, JWKS_DEFAULTS.staleIfErrorSec),
        negativeCacheSec: clampNumber(jwksGlobal.negative_cache_sec, 0, JWKS_DEFAULTS.negativeMax, JWKS_DEFAULTS.negativeCacheSec),
    };
}
function buildJwtGateConfig(gate, base) {
    const algorithm = gate.algorithm || 'RS256';
    const userAllowed = Array.isArray(gate.allowed_algorithms) && gate.allowed_algorithms.length > 0
        ? gate.allowed_algorithms.filter((a) => typeof a === 'string' && a !== 'none' && a === algorithm)
        : null;
    const allowedAlgorithms = userAllowed && userAllowed.length > 0 ? userAllowed : [algorithm];
    const clockSkewSec = clampNumber(gate.clock_skew_sec, JWT_CLOCK_SKEW.min, JWT_CLOCK_SKEW.max, JWT_CLOCK_SKEW.defaultSec);
    return {
        name: base.name,
        protectedPrefixes: base.protectedPrefixes,
        type: 'jwt',
        algorithm,
        allowed_algorithms: allowedAlgorithms,
        clock_skew_sec: clockSkewSec,
        jwks_url: gate.jwks_url || '',
        issuer: gate.issuer || '',
        audience: gate.audience || '',
        secret_env: gate.secret_env || '',
    };
}
function buildSignedUrlGateConfig(gate, base) {
    return {
        name: base.name,
        protectedPrefixes: base.protectedPrefixes,
        type: 'signed_url',
        algorithm: gate.algorithm || 'HMAC-SHA256',
        secret_env: gate.secret_env || 'URL_SIGNING_SECRET',
        expires_param: gate.expires_param || 'exp',
        signature_param: gate.signature_param || 'sig',
        exact_path: gate.exact_path === true,
        nonce_param: typeof gate.nonce_param === 'string' && gate.nonce_param.trim()
            ? gate.nonce_param.trim()
            : '',
    };
}
function buildRequestCfgBase(policy) {
    const defaults = policy.defaults || {};
    const request = policy.request || {};
    const limits = (request.limits || {});
    const block = (request.block || {});
    const normalize = (request.normalize || {});
    const dropQueryKeysArray = normalize.drop_query_keys || DEFAULT_DROP_QUERY_KEYS;
    const { contains: blockPath, regexSources: blockPathRegexSources } = parsePathPatterns(block.path_patterns);
    const pathNormalize = (normalize.path || {});
    const requiredHeaders = block.header_missing || DEFAULT_REQUIRED_HEADERS;
    const corsConfig = (policy.response_headers || {}).cors || null;
    const allowedHosts = normalizeStringList(request.allowed_hosts, 'lower');
    const trustForwardedFor = request.trust_forwarded_for === true;
    return {
        mode: defaults.mode || 'enforce',
        allowMethods: request.allow_methods || DEFAULT_ALLOW_METHODS,
        maxQueryLength: numberOr(limits.max_query_length, LIMITS_DEFAULTS.maxQueryLength),
        maxQueryParams: numberOr(limits.max_query_params, LIMITS_DEFAULTS.maxQueryParams),
        maxUriLength: numberOr(limits.max_uri_length, LIMITS_DEFAULTS.maxUriLength),
        maxHeaderCount: clampNumber(limits.max_header_count, LIMITS_DEFAULTS.headerCountMin, LIMITS_DEFAULTS.headerCountMax, LIMITS_DEFAULTS.maxHeaderCount),
        dropQueryKeysArray,
        uaDenyContains: block.ua_contains || DEFAULT_UA_DENY_CONTAINS,
        blockPathContains: blockPath,
        blockPathRegexSources,
        normalizePath: {
            collapseSlashes: !!pathNormalize.collapse_slashes,
            removeDotSegments: !!pathNormalize.remove_dot_segments,
        },
        requiredHeaders,
        allowedHosts,
        trustForwardedFor,
        cors: corsConfig,
        anomalyGuards: buildAnomalyGuardConfig(policy),
        obs: buildObsConfig(policy),
    };
}
module.exports = {
    DEFAULT_CONTAINS,
    parsePathPatterns,
    extractRegex,
    compileRegexOrThrow,
    hasCatastrophicBacktrackShape,
    regexesLiteralCode,
    buildAnomalyGuardConfig,
    buildObsConfig,
    findAdminCacheRoute,
    collectAuthProtectedPrefixes,
    buildAuthGateBase,
    buildResponseCfgBase,
    buildJwksCacheCfg,
    buildJwtGateConfig,
    buildSignedUrlGateConfig,
    buildRequestCfgBase,
};
