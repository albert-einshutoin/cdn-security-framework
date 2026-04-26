#!/usr/bin/env node
"use strict";
// @ts-nocheck
// @ts-nocheck
// @ts-nocheck
/**
 * Compile Cloudflare Workers: security.yml を読み、テンプレートに注入して dist/edge/cloudflare/index.ts に出力する。
 * Usage: node scripts/compile-cloudflare.js [path/to/security.yml] [--policy path] [--out-dir dir]
 */
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const { parsePathPatterns, regexesLiteralCode, validateAuthGates, hasAllowPlaceholderFlag, hasFailOnPermissiveFlag, warnIfPermissive, warnSignedUrlReplay, buildObsConfig, } = require('./lib/compile-core');
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
const cfgCode = [
    'const CFG = {',
    `  mode: ${JSON.stringify(defaults.mode || 'enforce')},`,
    `  allowMethods: new Set(${JSON.stringify(allowMethods)}),`,
    `  maxQueryLength: ${Number(limits.max_query_length) || 1024},`,
    `  maxQueryParams: ${Number(limits.max_query_params) || 30},`,
    `  maxUriLength: ${Number(limits.max_uri_length) || 2048},`,
    `  maxHeaderSize: ${Number(limits.max_header_size) || 0},`,
    `  maxHeaderCount: ${Number.isFinite(Number(limits.max_header_count)) ? Math.max(1, Math.min(500, Number(limits.max_header_count))) : 64},`,
    `  dropQueryKeys: new Set(${JSON.stringify(dropQueryKeysArray)}),`,
    `  uaDenyContains: ${JSON.stringify(block.ua_contains || ['sqlmap', 'nikto', 'acunetix', 'masscan', 'python-requests'])},`,
    `  blockPathContains: ${JSON.stringify(blockPathContains)},`,
    `  blockPathRegexes: ${regexesLiteralCode(blockPathRegexSources)},`,
    `  normalizePath: { collapseSlashes: ${!!pathNormalize.collapse_slashes}, removeDotSegments: ${!!pathNormalize.remove_dot_segments} },`,
    `  requiredHeaders: ${JSON.stringify(requiredHeaders)},`,
    `  allowedHosts: ${JSON.stringify(allowedHosts)},`,
    `  trustForwardedFor: ${trustForwardedFor ? 'true' : 'false'},`,
    `  cors: ${JSON.stringify(corsConfig)},`,
    `  authGates: ${JSON.stringify(authGates)},`,
    `  originAuth: ${JSON.stringify(originAuth)},`,
    `  jwksStaleIfErrorSec: ${jwksStaleIfError},`,
    `  jwksNegativeCacheSec: ${jwksNegativeCache},`,
    `  geoBlockCountries: new Set(${JSON.stringify(geoBlockCountries)}),`,
    `  geoAllowCountries: new Set(${JSON.stringify(geoAllowCountries)}),`,
    `  obs: ${JSON.stringify(buildObsConfig(policy))},`,
    '};',
].join('\n');
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
const responseCfgCode = [
    'const RESPONSE_CFG = {',
    '  headers: {',
    `    "strict-transport-security": ${JSON.stringify(resHeaders.hsts || 'max-age=31536000; includeSubDomains; preload')},`,
    `    "x-content-type-options": ${JSON.stringify(resHeaders.x_content_type_options || 'nosniff')},`,
    `    "referrer-policy": ${JSON.stringify(resHeaders.referrer_policy || 'strict-origin-when-cross-origin')},`,
    `    "permissions-policy": ${JSON.stringify(resHeaders.permissions_policy || 'camera=(), microphone=(), geolocation=()')},`,
    '  },',
    `  csp_public: ${JSON.stringify(resHeaders.csp_public || "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';")},`,
    `  csp_admin: ${JSON.stringify(resHeaders.csp_admin || "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';")},`,
    `  csp_report_only: ${JSON.stringify(resHeaders.csp_report_only || '')},`,
    `  csp_report_uri: ${JSON.stringify(resHeaders.csp_report_uri || '')},`,
    `  csp_nonce: ${resHeaders.csp_nonce === true ? 'true' : 'false'},`,
    `  coop: ${JSON.stringify(resHeaders.coop || '')},`,
    `  coep: ${JSON.stringify(resHeaders.coep || '')},`,
    `  corp: ${JSON.stringify(resHeaders.corp || '')},`,
    `  reporting_endpoints: ${JSON.stringify(resHeaders.reporting_endpoints || '')},`,
    `  adminPathPrefixes: ${JSON.stringify(adminPathPrefixes)},`,
    `  adminCacheControl: ${JSON.stringify(adminCacheControl)},`,
    `  authProtectedPrefixes: ${JSON.stringify(authProtectedPrefixesForResp)},`,
    `  forceVaryAuth: ${forceVaryAuth ? 'true' : 'false'},`,
    `  clearSiteDataPaths: ${JSON.stringify(Array.isArray(resHeaders.clear_site_data_paths)
        ? resHeaders.clear_site_data_paths.filter((s) => typeof s === 'string' && s.trim())
        : [])},`,
    `  clearSiteDataTypes: ${JSON.stringify(Array.isArray(resHeaders.clear_site_data_types) && resHeaders.clear_site_data_types.length > 0
        ? resHeaders.clear_site_data_types
        : ['cache', 'cookies', 'storage'])},`,
    `  cors: ${JSON.stringify(corsConfig)},`,
    `  cookie_attributes: ${JSON.stringify(resHeaders.cookie_attributes || null)},`,
    '};',
].join('\n');
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
code = code.replace('// {{INJECT_CONFIG}}', cfgCode);
code = code.replace('// {{INJECT_RESPONSE_CFG}}', responseCfgCode);
const distDir = path.join(outDir, 'edge', 'cloudflare');
fs.mkdirSync(distDir, { recursive: true });
const outPath = path.join(distDir, 'index.ts');
fs.writeFileSync(outPath, code, 'utf8');
console.log('Build complete:', outPath);
