#!/usr/bin/env node
"use strict";
/**
 * Compile Cloudflare Workers: security.yml を読み、テンプレートに注入して dist/edge/cloudflare/index.ts に出力する。
 * Usage: node scripts/compile-cloudflare.js [path/to/security.yml] [--policy path] [--out-dir dir]
 */
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const { parsePathPatterns, regexesLiteralCode, validateAuthGates, hasAllowPlaceholderFlag, hasFailOnPermissiveFlag, hasCatastrophicBacktrackShape, compileRegexOrThrow, warnIfPermissive, warnSignedUrlReplay, buildObsConfig, } = require('./lib/compile-core');
const { assertInjectedConstDeclarations, injectTemplateCode, renderConstObject, runtimeCode, } = require('./lib/template-inject');
const repoRoot = path.join(__dirname, '..');
const argv = process.argv.slice(2);
const securityPath = path.join(repoRoot, 'policy', 'security.yml');
const basePath = path.join(repoRoot, 'policy', 'base.yml');
let policyPath = fs.existsSync(securityPath) ? securityPath : basePath;
let outDir = path.join(repoRoot, 'dist');
for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--policy' && argv[i + 1]) {
        policyPath = argv[++i];
        continue;
    }
    if (argv[i] === '--out-dir' && argv[i + 1]) {
        outDir = argv[++i];
        continue;
    }
    if (argv[i] === '--allow-placeholder-token') {
        continue;
    }
    if (argv[i] === '--fail-on-permissive') {
        continue;
    }
    if (!argv[i].startsWith('--')) {
        policyPath = argv[i];
    }
}
const allowPlaceholderToken = hasAllowPlaceholderFlag(argv);
const failOnPermissive = hasFailOnPermissiveFlag(argv);
let policy;
try {
    const content = fs.readFileSync(policyPath, 'utf8');
    policy = yaml.load(content);
}
catch (e) {
    if (e.code === 'ENOENT') {
        console.error('Error: policy file not found:', policyPath);
        process.exit(1);
    }
    console.error('Error: failed to parse policy YAML:', e.message);
    process.exit(1);
}
const permissive = warnIfPermissive(policy, { failOnPermissive });
if (permissive.failed) {
    process.exit(1);
}
// Non-fatal advisory: signed_url protecting write-like paths without nonce_param.
warnSignedUrlReplay(policy);
// Cloudflare Workers reads env at runtime for static_token/basic_auth, so build
// does not require the actual token value. Only structural gate fields matter.
// We still validate jwt/signed_url required fields via the shared helper.
validateAuthGates(policy, { allowPlaceholderToken: true });
const defaults = policy.defaults || {};
const request = policy.request || {};
const limits = request.limits || {};
const block = request.block || {};
const normalize = request.normalize || {};
const routes = policy.routes || [];
function normalizeResponseDlp(policyObj) {
    const raw = policyObj.response_dlp || {};
    const enabled = raw.enabled === true;
    const action = ['mask', 'block', 'report_only'].includes(raw.action) ? raw.action : 'report_only';
    const body = raw.body || {};
    const headers = raw.headers || {};
    const detectors = raw.detectors || {};
    const defaultContentTypes = ['text/', 'application/json', 'application/xml', 'text/xml', 'application/javascript'];
    const builtIn = Array.isArray(detectors.built_in) && detectors.built_in.length > 0
        ? detectors.built_in.filter((d) => d === 'api_key' || d === 'credit_card')
        : ['api_key', 'credit_card'];
    const customRegexes = Array.isArray(detectors.custom_regex) ? detectors.custom_regex : [];
    const customRegexSources = [];
    const customRegexNames = [];
    if (customRegexes.length > 10) {
        throw new Error('response_dlp.detectors.custom_regex supports at most 10 patterns');
    }
    for (const entry of customRegexes) {
        const name = typeof entry?.name === 'string' && entry.name.trim() ? entry.name.trim() : 'custom';
        const pattern = typeof entry?.pattern === 'string' ? entry.pattern.trim() : '';
        if (!pattern)
            continue;
        if (pattern.length > 256) {
            throw new Error(`response_dlp.detectors.custom_regex "${name}" exceeds 256 characters`);
        }
        compileRegexOrThrow(pattern, 'response_dlp.detectors.custom_regex.pattern');
        if (hasCatastrophicBacktrackShape(pattern)) {
            throw new Error(`response_dlp.detectors.custom_regex "${name}" rejected by ReDoS safety check ` +
                `(nested-quantifier shape triggers catastrophic backtracking)`);
        }
        customRegexNames.push(name);
        customRegexSources.push(pattern);
    }
    return {
        config: {
            enabled,
            action,
            mask: typeof raw.mask === 'string' && raw.mask ? raw.mask : '[REDACTED]',
            blockStatus: Number.isFinite(Number(raw.block_status))
                ? Math.max(400, Math.min(599, Number(raw.block_status)))
                : 451,
            blockBody: typeof raw.block_body === 'string' && raw.block_body ? raw.block_body : 'Response blocked by edge DLP',
            body: {
                enabled: enabled && body.enabled !== false,
                maxBytes: Number.isFinite(Number(body.max_bytes))
                    ? Math.max(1, Math.min(131072, Number(body.max_bytes)))
                    : 32768,
                contentTypes: Array.isArray(body.content_types) && body.content_types.length > 0
                    ? body.content_types.filter((s) => typeof s === 'string' && s.trim()).map((s) => s.toLowerCase())
                    : defaultContentTypes,
            },
            headers: {
                enabled: enabled && headers.enabled !== false,
                names: Array.isArray(headers.names) && headers.names.length > 0
                    ? headers.names.filter((s) => typeof s === 'string' && s.trim()).map((s) => s.toLowerCase())
                    : ['set-cookie', 'authorization', 'x-api-key'],
            },
            detectors: { builtIn, customRegexNames },
        },
        customRegexSources,
    };
}
function getWorkerAuthGates() {
    const gates = [];
    for (const route of routes) {
        const gate = route.auth_gate;
        if (!gate)
            continue;
        const match = route.match || {};
        const prefixes = match.path_prefixes || [];
        const authType = gate.type || 'static_token';
        const gateConfig = {
            name: route.name || 'unnamed',
            protectedPrefixes: prefixes.length ? prefixes : ['/admin', '/docs', '/swagger'],
            type: authType,
        };
        if (authType === 'static_token') {
            gateConfig.tokenHeaderName = gate.header || 'x-edge-token';
            gateConfig.tokenEnv = gate.token_env || 'EDGE_ADMIN_TOKEN';
        }
        else if (authType === 'basic_auth') {
            gateConfig.credentialsEnv = gate.credentials_env || 'BASIC_AUTH_CREDS';
        }
        else if (authType === 'jwt') {
            const algorithm = gate.algorithm || 'RS256';
            gateConfig.algorithm = algorithm;
            // Cloudflare Workers runtime uses a single verifier per gate selected by
            // `algorithm`. `allowed_algorithms` can only restrict acceptance to that
            // verifier — cross-alg entries would cause silent auth outage and are
            // rejected at build time via `validateAuthGates`.
            const userAllowed = Array.isArray(gate.allowed_algorithms) && gate.allowed_algorithms.length > 0
                ? gate.allowed_algorithms.filter((a) => typeof a === 'string' && a !== 'none' && a === algorithm)
                : null;
            gateConfig.allowed_algorithms = userAllowed && userAllowed.length > 0 ? userAllowed : [algorithm];
            gateConfig.clock_skew_sec = Number.isFinite(Number(gate.clock_skew_sec))
                ? Math.max(0, Math.min(600, Number(gate.clock_skew_sec)))
                : 30;
            gateConfig.jwks_url = gate.jwks_url || '';
            gateConfig.issuer = gate.issuer || '';
            gateConfig.audience = gate.audience || '';
            gateConfig.secret_env = gate.secret_env || '';
            gateConfig.cache_ttl_sec = Number(gate.cache_ttl_sec) || 3600;
        }
        else if (authType === 'signed_url') {
            gateConfig.algorithm = gate.algorithm || 'HMAC-SHA256';
            gateConfig.secret_env = gate.secret_env || 'URL_SIGNING_SECRET';
            gateConfig.expires_param = gate.expires_param || 'exp';
            gateConfig.signature_param = gate.signature_param || 'sig';
            gateConfig.exact_path = gate.exact_path === true;
            gateConfig.nonce_param = typeof gate.nonce_param === 'string' && gate.nonce_param.trim()
                ? gate.nonce_param.trim()
                : '';
        }
        gates.push(gateConfig);
    }
    return gates;
}
const authGates = getWorkerAuthGates();
const dropQueryKeysArray = normalize.drop_query_keys || [
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'gclid', 'fbclid',
];
const { contains: blockPathContains, regexSources: blockPathRegexSources } = parsePathPatterns(block.path_patterns);
const allowMethods = request.allow_methods || ['GET', 'HEAD', 'POST'];
const pathNormalize = normalize.path || {};
const requiredHeaders = block.header_missing || ['user-agent'];
const resHeaders = policy.response_headers || {};
const corsConfig = resHeaders.cors || null;
const originAuth = (policy.origin || {}).auth || null;
const rawAllowedHosts = Array.isArray(request.allowed_hosts) ? request.allowed_hosts : [];
const allowedHosts = rawAllowedHosts
    .map((h) => (typeof h === 'string' ? h.trim().toLowerCase() : ''))
    .filter(Boolean);
const trustForwardedFor = request.trust_forwarded_for === true;
const jwksGlobal = (policy.firewall || {}).jwks || {};
const jwksStaleIfError = Number.isFinite(Number(jwksGlobal.stale_if_error_sec))
    ? Math.max(0, Math.min(86400, Number(jwksGlobal.stale_if_error_sec)))
    : 3600;
const jwksNegativeCache = Number.isFinite(Number(jwksGlobal.negative_cache_sec))
    ? Math.max(0, Math.min(600, Number(jwksGlobal.negative_cache_sec)))
    : 60;
const fwGeo = (policy.firewall || {}).geo || {};
const geoBlockCountries = Array.isArray(fwGeo.block_countries)
    ? fwGeo.block_countries.map((c) => String(c || '').trim().toUpperCase()).filter(Boolean)
    : [];
const geoAllowCountries = Array.isArray(fwGeo.allow_countries)
    ? fwGeo.allow_countries.map((c) => String(c || '').trim().toUpperCase()).filter(Boolean)
    : [];
const cfgCode = renderConstObject('CFG', {
    mode: defaults.mode || 'enforce',
    allowMethods: runtimeCode(`new Set(${JSON.stringify(allowMethods)})`),
    maxQueryLength: Number(limits.max_query_length) || 1024,
    maxQueryParams: Number(limits.max_query_params) || 30,
    maxUriLength: Number(limits.max_uri_length) || 2048,
    maxHeaderSize: Number(limits.max_header_size) || 0,
    maxHeaderCount: Number.isFinite(Number(limits.max_header_count))
        ? Math.max(1, Math.min(500, Number(limits.max_header_count)))
        : 64,
    dropQueryKeys: runtimeCode(`new Set(${JSON.stringify(dropQueryKeysArray)})`),
    uaDenyContains: block.ua_contains || ['sqlmap', 'nikto', 'acunetix', 'masscan', 'python-requests'],
    blockPathContains,
    blockPathRegexes: runtimeCode(regexesLiteralCode(blockPathRegexSources)),
    normalizePath: {
        collapseSlashes: !!pathNormalize.collapse_slashes,
        removeDotSegments: !!pathNormalize.remove_dot_segments,
    },
    requiredHeaders,
    allowedHosts,
    trustForwardedFor,
    cors: corsConfig,
    authGates,
    originAuth,
    jwksStaleIfErrorSec: jwksStaleIfError,
    jwksNegativeCacheSec: jwksNegativeCache,
    geoBlockCountries: runtimeCode(`new Set(${JSON.stringify(geoBlockCountries)})`),
    geoAllowCountries: runtimeCode(`new Set(${JSON.stringify(geoAllowCountries)})`),
    obs: buildObsConfig(policy),
});
let adminPathPrefixes = ['/admin', '/docs', '/swagger'];
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
const authProtectedPrefixesForResp = Array.from(new Set((authGates || []).flatMap((g) => Array.isArray(g.protectedPrefixes) ? g.protectedPrefixes : [])));
const forceVaryAuth = resHeaders.force_vary_auth !== false;
const responseDlp = normalizeResponseDlp(policy);
const responseCfgCode = renderConstObject('RESPONSE_CFG', {
    headers: {
        'strict-transport-security': resHeaders.hsts || 'max-age=31536000; includeSubDomains; preload',
        'x-content-type-options': resHeaders.x_content_type_options || 'nosniff',
        'referrer-policy': resHeaders.referrer_policy || 'strict-origin-when-cross-origin',
        'permissions-policy': resHeaders.permissions_policy || 'camera=(), microphone=(), geolocation=()',
    },
    csp_public: resHeaders.csp_public || "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';",
    csp_admin: resHeaders.csp_admin || "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';",
    csp_report_only: resHeaders.csp_report_only || '',
    csp_report_uri: resHeaders.csp_report_uri || '',
    csp_nonce: resHeaders.csp_nonce === true,
    coop: resHeaders.coop || '',
    coep: resHeaders.coep || '',
    corp: resHeaders.corp || '',
    reporting_endpoints: resHeaders.reporting_endpoints || '',
    adminPathPrefixes,
    adminCacheControl,
    authProtectedPrefixes: authProtectedPrefixesForResp,
    forceVaryAuth,
    clearSiteDataPaths: Array.isArray(resHeaders.clear_site_data_paths)
        ? resHeaders.clear_site_data_paths.filter((s) => typeof s === 'string' && s.trim())
        : [],
    clearSiteDataTypes: Array.isArray(resHeaders.clear_site_data_types) && resHeaders.clear_site_data_types.length > 0
        ? resHeaders.clear_site_data_types
        : ['cache', 'cookies', 'storage'],
    cors: corsConfig,
    cookie_attributes: resHeaders.cookie_attributes || null,
    responseDlp: responseDlp.config,
    responseDlpCustomRegexes: runtimeCode(regexesLiteralCode(responseDlp.customRegexSources)),
});
const templatePath = path.join(repoRoot, 'templates', 'cloudflare', 'index.ts');
let code;
try {
    code = fs.readFileSync(templatePath, 'utf8');
}
catch (e) {
    if (e.code === 'ENOENT') {
        console.error('Error: template not found:', templatePath);
        process.exit(1);
    }
    throw e;
}
code = injectTemplateCode(code, '// {{INJECT_CONFIG}}', cfgCode);
code = injectTemplateCode(code, '// {{INJECT_RESPONSE_CFG}}', responseCfgCode);
assertInjectedConstDeclarations(code, ['CFG', 'RESPONSE_CFG'], { loader: 'ts' });
const distDir = path.join(outDir, 'edge', 'cloudflare');
fs.mkdirSync(distDir, { recursive: true });
const outPath = path.join(distDir, 'index.ts');
fs.writeFileSync(outPath, code, 'utf8');
console.log('Build complete:', outPath);
