#!/usr/bin/env node
"use strict";
/**
 * Compile Cloudflare Workers: security.yml を読み、テンプレートに注入して dist/edge/cloudflare/index.ts に出力する。
 * Usage: node scripts/compile-cloudflare.js [path/to/security.yml] [--policy path] [--out-dir dir]
 */
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require('fs');
const path = require('path');
const { regexesLiteralCode, validateAuthGates, hasAllowPlaceholderFlag, hasFailOnPermissiveFlag, hasCatastrophicBacktrackShape, compileRegexOrThrow, warnIfPermissive, warnSignedUrlReplay, buildChallengeConfig, buildGraphqlGuardConfig, } = require('./lib/compile-core');
const { buildAuthGateBase, buildJwtGateConfig, buildSignedUrlGateConfig, buildRequestCfgBase, buildResponseCfgBase, buildJwksCacheCfg, } = require('./lib/edge-cfg');
const { assertInjectedConstDeclarations, injectTemplateCode, renderConstObject, runtimeCode, } = require('./lib/template-inject');
const { clampNumber, normalizeStringList, numberOr, } = require('./lib/value-normalize');
const { LIMITS_DEFAULTS, } = require('./lib/policy-defaults');
const { parseArgs, loadPolicyWithWarnings, reportPolicyWarnings, reportPolicyLoadError, } = require('./lib/policy-io');
const { isErrnoException, } = require('./lib/errors');
const repoRoot = path.join(__dirname, '..');
const argv = process.argv.slice(2);
const { policyPath, outDir } = parseArgs(argv, repoRoot);
const allowPlaceholderToken = hasAllowPlaceholderFlag(argv);
const failOnPermissive = hasFailOnPermissiveFlag(argv);
let policy;
try {
    const parsed = loadPolicyWithWarnings(policyPath);
    reportPolicyWarnings(parsed.warnings || [], policyPath);
    policy = parsed.policy;
}
catch (e) {
    reportPolicyLoadError(policyPath, e);
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
validateAuthGates(policy, { allowPlaceholderToken: true, requireJwksAllowedHosts: true });
const routes = policy.routes || [];
function normalizeResponseDlp(policyObj) {
    const raw = policyObj.response_dlp || {};
    const enabled = raw.enabled === true;
    const action = ['mask', 'block', 'report_only'].includes(raw.action) ? raw.action : 'report_only';
    const body = raw.body || {};
    const headers = raw.headers || {};
    const detectors = raw.detectors || {};
    const defaultContentTypes = ['text/', 'application/json', 'application/xml', 'text/xml', 'application/javascript'];
    const hasContentTypes = Array.isArray(body.content_types) && body.content_types.length > 0;
    const hasHeaderNames = Array.isArray(headers.names) && headers.names.length > 0;
    const contentTypes = normalizeStringList(body.content_types, 'lower', { trim: false });
    const headerNames = normalizeStringList(headers.names, 'lower', { trim: false });
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
            blockStatus: clampNumber(raw.block_status, 400, 599, 451),
            blockBody: typeof raw.block_body === 'string' && raw.block_body ? raw.block_body : 'Response blocked by edge DLP',
            body: {
                enabled: enabled && body.enabled !== false,
                maxBytes: clampNumber(body.max_bytes, 1, 131072, 32768),
                contentTypes: hasContentTypes ? contentTypes : defaultContentTypes,
            },
            headers: {
                enabled: enabled && headers.enabled !== false,
                names: hasHeaderNames ? headerNames : ['set-cookie', 'authorization', 'x-api-key'],
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
        const authType = gate.type || 'static_token';
        const gateConfig = buildAuthGateBase(route);
        if (authType === 'static_token') {
            gateConfig.tokenHeaderName = gate.header || 'x-edge-token';
            gateConfig.tokenEnv = gate.token_env || 'EDGE_ADMIN_TOKEN';
        }
        else if (authType === 'basic_auth') {
            gateConfig.credentialsEnv = gate.credentials_env || 'BASIC_AUTH_CREDS';
        }
        else if (authType === 'jwt') {
            Object.assign(gateConfig, buildJwtGateConfig(gate, gateConfig));
            gateConfig.cache_ttl_sec = numberOr(gate.cache_ttl_sec, 3600);
        }
        else if (authType === 'signed_url') {
            Object.assign(gateConfig, buildSignedUrlGateConfig(gate, gateConfig));
        }
        gates.push(gateConfig);
    }
    return gates;
}
const authGates = getWorkerAuthGates();
const requestBase = buildRequestCfgBase(policy);
const limits = (policy.request || {}).limits || {};
const originAuth = (policy.origin || {}).auth || null;
const jwksCache = buildJwksCacheCfg(policy);
const fwGeo = (policy.firewall || {}).geo || {};
// Keep String() coercion here; policy authors sometimes provide numeric country-like values.
const geoBlockCountries = Array.isArray(fwGeo.block_countries)
    ? fwGeo.block_countries.map((c) => String(c || '').trim().toUpperCase()).filter(Boolean)
    : [];
const geoAllowCountries = Array.isArray(fwGeo.allow_countries)
    ? fwGeo.allow_countries.map((c) => String(c || '').trim().toUpperCase()).filter(Boolean)
    : [];
const challengeConfig = buildChallengeConfig(policy);
const responseDlp = normalizeResponseDlp(policy);
const responseBase = buildResponseCfgBase(policy, authGates);
const cfgCode = renderConstObject('CFG', {
    mode: requestBase.mode,
    allowMethods: runtimeCode(`new Set(${JSON.stringify(requestBase.allowMethods)})`),
    maxQueryLength: requestBase.maxQueryLength,
    maxQueryParams: requestBase.maxQueryParams,
    maxUriLength: requestBase.maxUriLength,
    maxHeaderSize: numberOr(limits.max_header_size, LIMITS_DEFAULTS.maxHeaderSize),
    maxHeaderCount: requestBase.maxHeaderCount,
    dropQueryKeys: runtimeCode(`new Set(${JSON.stringify(requestBase.dropQueryKeysArray)})`),
    uaDenyContains: requestBase.uaDenyContains,
    blockPathContains: requestBase.blockPathContains,
    blockPathRegexes: runtimeCode(regexesLiteralCode(requestBase.blockPathRegexSources)),
    normalizePath: requestBase.normalizePath,
    requiredHeaders: requestBase.requiredHeaders,
    allowedHosts: requestBase.allowedHosts,
    trustForwardedFor: requestBase.trustForwardedFor,
    cors: requestBase.cors,
    authGates,
    originAuth,
    jwksStaleIfErrorSec: jwksCache.staleIfErrorSec,
    jwksNegativeCacheSec: jwksCache.negativeCacheSec,
    geoBlockCountries: runtimeCode(`new Set(${JSON.stringify(geoBlockCountries)})`),
    geoAllowCountries: runtimeCode(`new Set(${JSON.stringify(geoAllowCountries)})`),
    challenge: challengeConfig,
    graphqlGuard: buildGraphqlGuardConfig(policy),
    anomalyGuards: requestBase.anomalyGuards,
    obs: requestBase.obs,
});
const responseCfgCode = renderConstObject('RESPONSE_CFG', {
    headers: responseBase.headers,
    csp_public: responseBase.csp_public,
    csp_admin: responseBase.csp_admin,
    csp_report_only: responseBase.csp_report_only,
    csp_report_uri: responseBase.csp_report_uri,
    csp_nonce: responseBase.csp_nonce,
    coop: responseBase.coop,
    coep: responseBase.coep,
    corp: responseBase.corp,
    reporting_endpoints: responseBase.reporting_endpoints,
    adminPathPrefixes: responseBase.adminPathPrefixes,
    adminCacheControl: responseBase.adminCacheControl,
    authProtectedPrefixes: responseBase.authProtectedPrefixes,
    forceVaryAuth: responseBase.forceVaryAuth,
    clearSiteDataPaths: responseBase.clearSiteDataPaths,
    clearSiteDataTypes: responseBase.clearSiteDataTypes,
    cors: responseBase.cors,
    cookie_attributes: responseBase.cookie_attributes,
    responseDlp: responseDlp.config,
    responseDlpCustomRegexes: runtimeCode(regexesLiteralCode(responseDlp.customRegexSources)),
});
const templatePath = path.join(repoRoot, 'templates', 'cloudflare', 'index.ts');
let code;
try {
    code = fs.readFileSync(templatePath, 'utf8');
}
catch (e) {
    if (isErrnoException(e) && e.code === 'ENOENT') {
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
