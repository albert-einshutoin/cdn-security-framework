#!/usr/bin/env node
"use strict";
// @ts-nocheck
// @ts-nocheck
// @ts-nocheck
/**
 * Runtime tests: run request cases against CloudFront Functions viewer-request handler
 * and Lambda@Edge origin-request handler, asserting expected status codes.
 * Usage: node scripts/runtime-tests.js
 *
 * Test cases are aligned with policy/base.yml (balanced) and the viewer-request.js CFG.
 */
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
// =========================================================================
// Section 1: viewer-request.js tests (CloudFront Functions)
// =========================================================================
const viewerRequestPath = path.join(__dirname, '..', 'dist', 'edge', 'viewer-request.js');
let code;
try {
    code = fs.readFileSync(viewerRequestPath, 'utf8');
}
catch (e) {
    console.error('Could not read dist/edge/viewer-request.js. Run: npm run build');
    process.exit(1);
}
// Run the generated script in an isolated function and capture its handler.
const handler = Function(`${code}\nreturn handler;`)();
let originHandler;
// The build must have been invoked with EDGE_ADMIN_TOKEN set (see CI / npm script).
// Fall back to the documented placeholder only for --allow-placeholder-token builds.
const DEFAULT_TOKEN = process.env.EDGE_ADMIN_TOKEN
    || 'INSECURE_PLACEHOLDER__REBUILD_WITH_REAL_TOKEN';
function buildEvent(method, uri, headers, querystring) {
    const h = headers || {};
    const cfHeaders = {};
    for (const [k, v] of Object.entries(h)) {
        cfHeaders[k.toLowerCase()] = { value: v };
    }
    return {
        request: {
            method: method || 'GET',
            uri: uri || '/',
            headers: cfHeaders,
            querystring: querystring || '',
        },
    };
}
function runCase(name, event, expected) {
    const result = handler(event);
    const allowed = result && !result.statusCode && result.uri !== undefined;
    const got = allowed ? 'allow' : (result && result.statusCode);
    const ok = (expected === 'allow' && allowed) || (typeof expected === 'number' && got === expected);
    if (!ok) {
        console.error('FAIL:', name, '| expected', expected, 'got', got);
        return false;
    }
    console.log('OK:', name);
    return true;
}
const cases = [
    // Basic tests
    ['GET / with UA', buildEvent('GET', '/', { 'user-agent': 'Mozilla/5.0' }), 'allow'],
    ['GET / no UA', buildEvent('GET', '/'), 400],
    ['OPTIONS /', buildEvent('OPTIONS', '/', { 'user-agent': 'Mozilla' }), 405],
    // Phase A-1: URI length (using default max_uri_length: 2048)
    ['GET /normal-uri', buildEvent('GET', '/normal-uri', { 'user-agent': 'Mozilla' }), 'allow'],
    ['GET /very-long-uri (2049 chars)', buildEvent('GET', '/' + 'a'.repeat(2048), { 'user-agent': 'Mozilla' }), 414],
    // Phase A-2: Path normalization is done but doesn't reject (just normalizes)
    // Traversal patterns are blocked by blockPathContains / blockPathRegexes
    ['GET /foo/../bar (traversal)', buildEvent('GET', '/foo/../bar', { 'user-agent': 'Mozilla' }), 400],
    ['GET / with %2e%2e', buildEvent('GET', '/x%2e%2e/y', { 'user-agent': 'Mozilla' }), 400],
    // Phase A-3: Required headers (header_missing)
    // user-agent is required by default
    // UA deny list
    ['GET / with sqlmap UA', buildEvent('GET', '/', { 'user-agent': 'sqlmap/1.0' }), 403],
    ['GET / with nikto UA', buildEvent('GET', '/', { 'user-agent': 'Nikto scanner' }), 403],
    ['GET / with acunetix UA', buildEvent('GET', '/', { 'user-agent': 'Acunetix Web Scanner' }), 403],
    ['GET / with long UA (>512)', buildEvent('GET', '/', { 'user-agent': 'Mozilla/' + 'x'.repeat(510) }), 400],
    // Auth gates (static_token)
    ['GET /admin no token', buildEvent('GET', '/admin', { 'user-agent': 'Mozilla' }), 401],
    ['GET /admin with token', buildEvent('GET', '/admin', { 'user-agent': 'Mozilla', 'x-edge-token': DEFAULT_TOKEN }), 'allow'],
    ['GET /docs with token', buildEvent('GET', '/docs', { 'user-agent': 'Mozilla', 'x-edge-token': DEFAULT_TOKEN }), 'allow'],
    ['GET /swagger with token', buildEvent('GET', '/swagger', { 'user-agent': 'Mozilla', 'x-edge-token': DEFAULT_TOKEN }), 'allow'],
    // Query limits
    ['GET / with too many query params', buildEvent('GET', '/', { 'user-agent': 'Mozilla' }, Array(31).fill('a=b').join('&')), 400],
    ['GET / with long query string', buildEvent('GET', '/', { 'user-agent': 'Mozilla' }, 'x=' + 'a'.repeat(1100)), 414],
    // Query normalization (drop utm_* keys)
    ['GET / with utm params (should be stripped)', buildEvent('GET', '/', { 'user-agent': 'Mozilla' }, 'utm_source=google&foo=bar'), 'allow'],
    // Phase A-4: Header count cap (issue #9). Default is 64 from the compiler.
    // 64 headers (incl. user-agent) must pass; 65 must get 431.
    ['GET / with 64 headers (boundary)',
        (() => {
            const h = { 'user-agent': 'Mozilla' };
            for (let i = 0; i < 63; i++)
                h['x-filler-' + i] = 'v';
            return buildEvent('GET', '/', h);
        })(),
        'allow',
    ],
    ['GET / with 65 headers (over cap)',
        (() => {
            const h = { 'user-agent': 'Mozilla' };
            for (let i = 0; i < 64; i++)
                h['x-filler-' + i] = 'v';
            return buildEvent('GET', '/', h);
        })(),
        431,
    ],
];
let viewerFailed = 0;
for (const [name, event, expected] of cases) {
    if (!runCase(name, event, expected))
        viewerFailed++;
}
console.log('--- viewer-request: ' + (cases.length - viewerFailed) + '/' + cases.length + ' passed ---');
// x-edge-authenticated spoofing defense: the handler MUST strip any
// client-supplied value before the origin sees it. If the caller does not
// also supply a valid token the request must still fail auth.
(function runEdgeAuthSpoofingTests() {
    const spoofEvent = buildEvent('GET', '/admin', {
        'user-agent': 'Mozilla',
        'x-edge-authenticated': '1',
    });
    const result = handler(spoofEvent);
    const blocked = result && result.statusCode === 401;
    if (!blocked) {
        console.error('FAIL: spoofed x-edge-authenticated on /admin should still 401, got', result && result.statusCode);
        viewerFailed++;
    }
    else {
        console.log('OK: spoofed x-edge-authenticated on /admin still blocked (401)');
    }
    const passEvent = buildEvent('GET', '/not-protected', {
        'user-agent': 'Mozilla',
        'x-edge-authenticated': 'totally-fake',
    });
    const passResult = handler(passEvent);
    const headerStripped = passResult
        && passResult.uri !== undefined
        && passResult.headers
        && !passResult.headers['x-edge-authenticated'];
    if (!headerStripped) {
        console.error('FAIL: x-edge-authenticated leaked through on non-protected path', passResult && passResult.headers);
        viewerFailed++;
    }
    else {
        console.log('OK: x-edge-authenticated stripped from incoming request');
    }
})();
// X-Forwarded-For stripping: by default (trustForwardedFor=false), client-
// supplied XFF must be stripped before reaching origin.
(function runXForwardedForStripTests() {
    const event = buildEvent('GET', '/not-protected', {
        'user-agent': 'Mozilla',
        'x-forwarded-for': '127.0.0.1, 10.0.0.1',
    });
    const result = handler(event);
    const passed = result && result.uri !== undefined
        && result.headers && !result.headers['x-forwarded-for'];
    if (!passed) {
        console.error('FAIL: x-forwarded-for should be stripped by default, got', result && result.headers);
        viewerFailed++;
    }
    else {
        console.log('OK: x-forwarded-for stripped from incoming request');
    }
})();
// Host allowlist: we compile a standalone template instance with allowedHosts
// set so we can assert the reject/accept paths without touching the main
// policy.
(function runHostAllowlistTests() {
    const cfgCode = [
        'const CFG = {',
        '  mode: "enforce",',
        '  allowMethods: ["GET"],',
        '  maxQueryLength: 1024,',
        '  maxQueryParams: 30,',
        '  maxUriLength: 2048,',
        '  dropQueryKeys: new Set([]),',
        '  uaDenyContains: [],',
        '  blockPathContains: [],',
        '  blockPathRegexes: [],',
        '  normalizePath: { collapseSlashes: false, removeDotSegments: false },',
        '  requiredHeaders: [],',
        '  allowedHosts: ["api.example.com", "*.cdn.example.com"],',
        '  trustForwardedFor: false,',
        '  cors: null,',
        '  authGates: [],',
        '};',
    ].join('\n');
    const h = compileViewerTemplate(cfgCode);
    if (!h) {
        viewerFailed++;
        return;
    }
    const cases = [
        ['host-allow: api.example.com accepted', buildEvent('GET', '/', { host: 'api.example.com' }), 'allow'],
        ['host-allow: matches wildcard *.cdn.example.com', buildEvent('GET', '/', { host: 'edge.cdn.example.com' }), 'allow'],
        ['host-allow: matches wildcard case-insensitively', buildEvent('GET', '/', { host: 'EDGE.CDN.EXAMPLE.COM' }), 'allow'],
        ['host-allow: strips :port for match', buildEvent('GET', '/', { host: 'api.example.com:8443' }), 'allow'],
        ['host-allow: rejects unknown host', buildEvent('GET', '/', { host: 'evil.example.com' }), 400],
        ['host-allow: rejects missing host', buildEvent('GET', '/', {}), 400],
        ['host-allow: wildcard does not match parent domain', buildEvent('GET', '/', { host: 'cdn.example.com' }), 400],
    ];
    for (const [name, event, expected] of cases) {
        const result = h(event);
        const allowed = result && !result.statusCode && result.uri !== undefined;
        const got = allowed ? 'allow' : (result && result.statusCode);
        const ok = (expected === 'allow' && allowed) || (typeof expected === 'number' && got === expected);
        if (!ok) {
            console.error('FAIL:', name, '| expected', expected, 'got', got);
            viewerFailed++;
        }
        else {
            console.log('OK:', name);
        }
    }
})();
// =========================================================================
// Section 1b: viewer-request.js monitor mode tests
// =========================================================================
function compileViewerTemplate(cfgCode) {
    const templatePath = path.join(__dirname, '..', 'templates', 'aws', 'viewer-request.js');
    let vrCode;
    try {
        vrCode = fs.readFileSync(templatePath, 'utf8');
    }
    catch (e) {
        console.error('Could not read templates/aws/viewer-request.js');
        return null;
    }
    vrCode = vrCode.replace('// {{INJECT_CONFIG}}', cfgCode);
    const wrappedCode = '(function() {\n' + vrCode + '\nreturn handler;\n})()';
    try {
        return eval(wrappedCode);
    }
    catch (e) {
        console.error('Failed to eval viewer-request template:', e.message);
        return null;
    }
}
function runViewerMonitorTests() {
    const monitorCfg = [
        'const CFG = {',
        '  mode: "monitor",',
        '  allowMethods: ["GET", "HEAD"],',
        '  maxQueryLength: 1024,',
        '  maxQueryParams: 30,',
        '  maxUriLength: 2048,',
        '  dropQueryKeys: new Set(["utm_source"]),',
        '  uaDenyContains: ["sqlmap"],',
        '  blockPathContains: ["/../", "%2e%2e"],',
        '  blockPathRegexes: [],',
        '  normalizePath: { collapseSlashes: true, removeDotSegments: true },',
        '  requiredHeaders: ["user-agent"],',
        '  cors: null,',
        '  authGates: [{',
        '    name: "admin",',
        '    protectedPrefixes: ["/admin"],',
        '    type: "static_token",',
        '    tokenHeaderName: "x-edge-token",',
        '    tokenEnv: "EDGE_ADMIN_TOKEN",',
        '    token: "test-token"',
        '  }],',
        '};',
    ].join('\n');
    const monitorHandler = compileViewerTemplate(monitorCfg);
    if (!monitorHandler)
        return { failed: 1, total: 1 };
    const monitorCases = [
        // In monitor mode, blocked method should pass through
        ['viewer-monitor: POST blocked method passes through',
            buildEvent('POST', '/', { 'user-agent': 'Mozilla' }),
            'allow'],
        // In monitor mode, traversal should pass through
        ['viewer-monitor: path traversal passes through',
            buildEvent('GET', '/foo/../bar', { 'user-agent': 'Mozilla' }),
            'allow'],
        // In monitor mode, missing UA should pass through
        ['viewer-monitor: missing UA passes through',
            buildEvent('GET', '/'),
            'allow'],
        // In monitor mode, denied UA should pass through
        ['viewer-monitor: sqlmap UA passes through',
            buildEvent('GET', '/', { 'user-agent': 'sqlmap/1.0' }),
            'allow'],
        // In monitor mode, missing auth token should pass through
        ['viewer-monitor: /admin no token passes through',
            buildEvent('GET', '/admin', { 'user-agent': 'Mozilla' }),
            'allow'],
    ];
    let failed = 0;
    for (const [name, event, expected] of monitorCases) {
        const result = monitorHandler(event);
        const allowed = result && !result.statusCode && result.uri !== undefined;
        const got = allowed ? 'allow' : (result && result.statusCode);
        const ok = (expected === 'allow' && allowed);
        if (!ok) {
            console.error('FAIL:', name, '| expected', expected, 'got', got);
            failed++;
        }
        else {
            console.log('OK:', name);
        }
    }
    console.log('--- viewer-request (monitor): ' + (monitorCases.length - failed) + '/' + monitorCases.length + ' passed ---');
    return { failed, total: monitorCases.length };
}
const viewerMonitorResult = runViewerMonitorTests();
viewerFailed += viewerMonitorResult.failed;
// =========================================================================
// Section 2: origin-request.js tests (Lambda@Edge)
// =========================================================================
// Helper: create HS256 JWT
const HS256_SECRET = 'test-secret-for-runtime-tests-32b';
function createHS256Jwt(payload, secret) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const enc = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const headerB64 = enc(header);
    const payloadB64 = enc(payload);
    const sig = crypto.createHmac('sha256', secret)
        .update(headerB64 + '.' + payloadB64)
        .digest('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    return headerB64 + '.' + payloadB64 + '.' + sig;
}
// Build Lambda@Edge event format
function buildLambdaEdgeEvent(uri, headers, querystring) {
    const h = headers || {};
    const cfHeaders = {};
    for (const [k, v] of Object.entries(h)) {
        cfHeaders[k.toLowerCase()] = [{ key: k, value: v }];
    }
    return {
        Records: [{
                cf: {
                    request: {
                        uri: uri || '/',
                        headers: cfHeaders,
                        querystring: querystring || '',
                    },
                },
            }],
    };
}
// Async test runner for Lambda@Edge (result.status is string, not statusCode number)
async function runAsyncCase(name, event, expected) {
    const result = await originHandler(event);
    // Lambda@Edge pass-through returns the request object (has uri, no status)
    const isPassThrough = result && result.uri !== undefined && !result.status;
    const gotStatus = isPassThrough ? 'allow' : (result && result.status);
    const ok = (expected === 'allow' && isPassThrough) ||
        (typeof expected === 'string' && expected !== 'allow' && gotStatus === expected);
    if (!ok) {
        console.error('FAIL:', name, '| expected', expected, 'got', gotStatus);
        return false;
    }
    console.log('OK:', name);
    return true;
}
// Helper: compile origin-request template with inline config
function compileOriginTemplate(cfgCode) {
    const templatePath = path.join(__dirname, '..', 'templates', 'aws', 'origin-request.js');
    let originCode;
    try {
        originCode = fs.readFileSync(templatePath, 'utf8');
    }
    catch (e) {
        console.error('Could not read templates/aws/origin-request.js');
        return null;
    }
    originCode = originCode.replace('// {{INJECT_CONFIG}}', cfgCode);
    const wrappedCode = '(function() {\n' +
        'const crypto = require("crypto");\n' +
        'const https = require("https");\n' +
        originCode
            .replace("const crypto = require('crypto');", '')
            .replace("const https = require('https');", '') +
        '\nreturn exports.handler;\n' +
        '})()';
    try {
        return eval(wrappedCode);
    }
    catch (e) {
        console.error('Failed to eval origin-request template:', e.message);
        return null;
    }
}
// Helper: create signed URL query string
const SIGNED_URL_SECRET = 'test-signing-secret-for-urls-32b';
function createSignedUrlParams(uri, expiresSec, secret) {
    const signData = uri + String(expiresSec);
    const sig = crypto.createHmac('sha256', secret)
        .update(signData)
        .digest('base64url');
    return 'exp=' + expiresSec + '&sig=' + sig;
}
function createSignedUrlWithNonce(uri, expiresSec, secret, nonce) {
    const signData = uri + String(expiresSec) + '|' + nonce;
    const sig = crypto.createHmac('sha256', secret)
        .update(signData)
        .digest('base64url');
    return 'exp=' + expiresSec + '&nonce=' + nonce + '&sig=' + sig;
}
async function runOriginRequestTests() {
    const testSecret = HS256_SECRET;
    process.env.JWT_TEST_SECRET = testSecret;
    process.env.URL_SIGNING_SECRET = SIGNED_URL_SECRET;
    const originCfgCode = [
        'const CFG = {',
        '  project: "test",',
        '  mode: "enforce",',
        '  maxHeaderSize: 0,',
        '  jwtGates: [{',
        '    name: "api",',
        '    protectedPrefixes: ["/api"],',
        '    type: "jwt",',
        '    algorithm: "HS256",',
        '    jwks_url: "",',
        '    issuer: "test-issuer",',
        '    audience: "test-audience",',
        '    secret_env: "JWT_TEST_SECRET"',
        '  }],',
        '  signedUrlGates: [{',
        '    name: "assets",',
        '    protectedPrefixes: ["/assets"],',
        '    type: "signed_url",',
        '    algorithm: "HMAC-SHA256",',
        '    secret_env: "URL_SIGNING_SECRET",',
        '    expires_param: "exp",',
        '    signature_param: "sig",',
        '    exact_path: false,',
        '    nonce_param: ""',
        '  }, {',
        '    name: "one-time-download",',
        '    protectedPrefixes: ["/download/report.pdf"],',
        '    type: "signed_url",',
        '    algorithm: "HMAC-SHA256",',
        '    secret_env: "URL_SIGNING_SECRET",',
        '    expires_param: "exp",',
        '    signature_param: "sig",',
        '    exact_path: true,',
        '    nonce_param: "nonce"',
        '  }],',
        '  originAuth: null',
        '};',
    ].join('\n');
    originHandler = compileOriginTemplate(originCfgCode);
    if (!originHandler)
        return 1;
    const nowSec = Math.floor(Date.now() / 1000);
    const originCases = [
        // --- Pass-through ---
        ['origin: GET / pass-through',
            buildLambdaEdgeEvent('/'),
            'allow'],
        // --- JWT HS256 tests ---
        ['origin: GET /api/data no auth',
            buildLambdaEdgeEvent('/api/data'),
            '401'],
        ['origin: GET /api/data valid JWT',
            buildLambdaEdgeEvent('/api/data', {
                'Authorization': 'Bearer ' + createHS256Jwt({
                    sub: 'user1', iss: 'test-issuer', aud: 'test-audience',
                    exp: nowSec + 3600, nbf: nowSec - 60,
                }, testSecret),
            }),
            'allow'],
        ['origin: GET /api/data expired JWT',
            buildLambdaEdgeEvent('/api/data', {
                'Authorization': 'Bearer ' + createHS256Jwt({
                    sub: 'user1', iss: 'test-issuer', aud: 'test-audience',
                    exp: nowSec - 100,
                }, testSecret),
            }),
            '401'],
        ['origin: GET /api/data bad signature',
            buildLambdaEdgeEvent('/api/data', {
                'Authorization': 'Bearer ' + createHS256Jwt({
                    sub: 'user1', iss: 'test-issuer', aud: 'test-audience',
                    exp: nowSec + 3600,
                }, 'wrong-secret'),
            }),
            '401'],
        ['origin: GET /api/data wrong issuer',
            buildLambdaEdgeEvent('/api/data', {
                'Authorization': 'Bearer ' + createHS256Jwt({
                    sub: 'user1', iss: 'wrong-issuer', aud: 'test-audience',
                    exp: nowSec + 3600,
                }, testSecret),
            }),
            '401'],
        ['origin: GET /api/data wrong audience',
            buildLambdaEdgeEvent('/api/data', {
                'Authorization': 'Bearer ' + createHS256Jwt({
                    sub: 'user1', iss: 'test-issuer', aud: 'wrong-audience',
                    exp: nowSec + 3600,
                }, testSecret),
            }),
            '401'],
        ['origin: GET /api/data future nbf',
            buildLambdaEdgeEvent('/api/data', {
                'Authorization': 'Bearer ' + createHS256Jwt({
                    sub: 'user1', iss: 'test-issuer', aud: 'test-audience',
                    exp: nowSec + 7200, nbf: nowSec + 3600,
                }, testSecret),
            }),
            '401'],
        ['origin: GET /api/data malformed token',
            buildLambdaEdgeEvent('/api/data', {
                'Authorization': 'Bearer not-a-jwt',
            }),
            '401'],
        // alg confusion: alg=none must be rejected
        ['origin: GET /api/data alg=none rejected',
            buildLambdaEdgeEvent('/api/data', {
                'Authorization': 'Bearer ' + (function () {
                    const header = { alg: 'none', typ: 'JWT' };
                    const payload = { sub: 'user', iss: 'test-issuer', aud: 'test-audience', exp: nowSec + 3600 };
                    const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64')
                        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
                    return enc(header) + '.' + enc(payload) + '.';
                })(),
            }),
            '401'],
        // alg confusion: alg=RS256 on an HS256 gate must be rejected (wrong alg,
        // before any signature math runs).
        ['origin: GET /api/data alg=RS256 on HS256 gate rejected',
            buildLambdaEdgeEvent('/api/data', {
                'Authorization': 'Bearer ' + (function () {
                    const header = { alg: 'RS256', typ: 'JWT' };
                    const payload = { sub: 'user', iss: 'test-issuer', aud: 'test-audience', exp: nowSec + 3600 };
                    const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64')
                        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
                    const data = enc(header) + '.' + enc(payload);
                    const sig = crypto.createHmac('sha256', testSecret).update(data).digest('base64')
                        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
                    return data + '.' + sig;
                })(),
            }),
            '401'],
        // Clock skew: token expired 15s ago is still accepted with default 30s skew
        ['origin: GET /api/data just-expired JWT accepted within clock skew',
            buildLambdaEdgeEvent('/api/data', {
                'Authorization': 'Bearer ' + createHS256Jwt({
                    sub: 'user1', iss: 'test-issuer', aud: 'test-audience',
                    exp: nowSec - 15,
                }, testSecret),
            }),
            'allow'],
        // Clock skew: token expired way beyond skew is still rejected
        ['origin: GET /api/data long-expired JWT rejected past clock skew',
            buildLambdaEdgeEvent('/api/data', {
                'Authorization': 'Bearer ' + createHS256Jwt({
                    sub: 'user1', iss: 'test-issuer', aud: 'test-audience',
                    exp: nowSec - 600,
                }, testSecret),
            }),
            '401'],
        // Clock skew: token valid-from 15s in future is still accepted
        ['origin: GET /api/data near-future nbf accepted within clock skew',
            buildLambdaEdgeEvent('/api/data', {
                'Authorization': 'Bearer ' + createHS256Jwt({
                    sub: 'user1', iss: 'test-issuer', aud: 'test-audience',
                    exp: nowSec + 3600, nbf: nowSec + 15,
                }, testSecret),
            }),
            'allow'],
        // --- Signed URL tests ---
        ['origin: GET /assets/file.png valid signed URL',
            buildLambdaEdgeEvent('/assets/file.png', {}, createSignedUrlParams('/assets/file.png', nowSec + 3600, SIGNED_URL_SECRET)),
            'allow'],
        ['origin: GET /assets/file.png expired signed URL',
            buildLambdaEdgeEvent('/assets/file.png', {}, createSignedUrlParams('/assets/file.png', nowSec - 100, SIGNED_URL_SECRET)),
            '403'],
        ['origin: GET /assets/file.png bad signature',
            buildLambdaEdgeEvent('/assets/file.png', {}, createSignedUrlParams('/assets/file.png', nowSec + 3600, 'wrong-secret')),
            '403'],
        ['origin: GET /assets/file.png missing sig params',
            buildLambdaEdgeEvent('/assets/file.png', {}, 'foo=bar'),
            '403'],
        ['origin: GET /other/file not protected by signed URL',
            buildLambdaEdgeEvent('/other/file', {}, ''),
            'allow'],
        // --- exact_path: reject sibling-path replay ---
        ['origin: exact_path rejects sibling path with valid signature for /download/report.pdf',
            buildLambdaEdgeEvent('/download/leaked.pdf', {}, createSignedUrlWithNonce('/download/report.pdf', nowSec + 3600, SIGNED_URL_SECRET, 'nonce-0123456789abcdef')),
            'allow'],
        // --- nonce_param required: accept when present, reject when missing ---
        ['origin: exact_path + nonce accepts well-formed one-time URL',
            buildLambdaEdgeEvent('/download/report.pdf', {}, createSignedUrlWithNonce('/download/report.pdf', nowSec + 3600, SIGNED_URL_SECRET, 'nonce-0123456789abcdef')),
            'allow'],
        ['origin: exact_path + nonce rejects when nonce missing',
            buildLambdaEdgeEvent('/download/report.pdf', {}, createSignedUrlParams('/download/report.pdf', nowSec + 3600, SIGNED_URL_SECRET)),
            '403'],
        ['origin: exact_path + nonce rejects short/invalid nonce',
            buildLambdaEdgeEvent('/download/report.pdf', {}, createSignedUrlWithNonce('/download/report.pdf', nowSec + 3600, SIGNED_URL_SECRET, 'short')),
            '403'],
    ];
    let originFailed = 0;
    for (const [name, event, expected] of originCases) {
        if (!(await runAsyncCase(name, event, expected)))
            originFailed++;
    }
    // X-Forwarded-For stripping at origin (defense-in-depth).
    const xffEvent = buildLambdaEdgeEvent('/other/file', {
        'x-forwarded-for': '1.2.3.4, 5.6.7.8',
    });
    const xffResult = await originHandler(xffEvent);
    const xffStripped = xffResult && xffResult.uri !== undefined && !xffResult.headers['x-forwarded-for'];
    if (!xffStripped) {
        console.error('FAIL: origin should strip client-supplied x-forwarded-for, headers=', xffResult && xffResult.headers);
        originFailed++;
    }
    else {
        console.log('OK: origin strips client-supplied x-forwarded-for');
    }
    // Hop-by-hop / smuggling header stripping (defense-in-depth).
    const smugEvent = buildLambdaEdgeEvent('/other/file', {
        'transfer-encoding': 'chunked',
        'connection': 'close',
        'upgrade': 'websocket',
        'te': 'trailers',
        'keep-alive': 'timeout=5',
        'proxy-connection': 'keep-alive',
        'trailer': 'Expires',
    });
    const smugResult = await originHandler(smugEvent);
    const smugStripped = smugResult && smugResult.uri !== undefined
        && !smugResult.headers['transfer-encoding']
        && !smugResult.headers['connection']
        && !smugResult.headers['upgrade']
        && !smugResult.headers['te']
        && !smugResult.headers['keep-alive']
        && !smugResult.headers['proxy-connection']
        && !smugResult.headers['trailer'];
    if (!smugStripped) {
        console.error('FAIL: origin should strip hop-by-hop / smuggling headers, headers=', smugResult && smugResult.headers);
        originFailed++;
    }
    else {
        console.log('OK: origin strips hop-by-hop smuggling headers');
    }
    // Nonce forwarding: successful signed_url verification must set
    // X-Signed-URL-Nonce on the forwarded request.
    const nonceVal = 'nonce-0123456789abcdef';
    const nonceEvent = buildLambdaEdgeEvent('/download/report.pdf', {}, createSignedUrlWithNonce('/download/report.pdf', nowSec + 3600, SIGNED_URL_SECRET, nonceVal));
    const nonceResult = await originHandler(nonceEvent);
    const nonceHeader = nonceResult && nonceResult.headers && nonceResult.headers['x-signed-url-nonce'];
    const nonceOk = Array.isArray(nonceHeader) && nonceHeader[0] && nonceHeader[0].value === nonceVal;
    if (!nonceOk) {
        console.error('FAIL: origin should forward X-Signed-URL-Nonce, got=', nonceResult && nonceResult.headers && nonceResult.headers['x-signed-url-nonce']);
        originFailed++;
    }
    else {
        console.log('OK: origin forwards X-Signed-URL-Nonce header to origin');
    }
    const extraAsserts = 3;
    console.log('--- origin-request (enforce): ' + (originCases.length + extraAsserts - originFailed) + '/' + (originCases.length + extraAsserts) + ' passed ---');
    return { failed: originFailed, total: originCases.length + extraAsserts };
}
// Monitor mode tests: blocking checks should pass through
async function runMonitorModeTests() {
    const testSecret = HS256_SECRET;
    process.env.JWT_TEST_SECRET = testSecret;
    process.env.URL_SIGNING_SECRET = SIGNED_URL_SECRET;
    const monitorCfgCode = [
        'const CFG = {',
        '  project: "test",',
        '  mode: "monitor",',
        '  maxHeaderSize: 100,',
        '  jwtGates: [{',
        '    name: "api",',
        '    protectedPrefixes: ["/api"],',
        '    type: "jwt",',
        '    algorithm: "HS256",',
        '    jwks_url: "",',
        '    issuer: "test-issuer",',
        '    audience: "test-audience",',
        '    secret_env: "JWT_TEST_SECRET"',
        '  }],',
        '  signedUrlGates: [{',
        '    name: "assets",',
        '    protectedPrefixes: ["/assets"],',
        '    type: "signed_url",',
        '    algorithm: "HMAC-SHA256",',
        '    secret_env: "URL_SIGNING_SECRET",',
        '    expires_param: "exp",',
        '    signature_param: "sig"',
        '  }],',
        '  originAuth: null',
        '};',
    ].join('\n');
    const monitorHandler = compileOriginTemplate(monitorCfgCode);
    if (!monitorHandler)
        return { failed: 1, total: 1 };
    originHandler = monitorHandler;
    const nowSec = Math.floor(Date.now() / 1000);
    const monitorCases = [
        // In monitor mode, invalid JWT should pass through (allow)
        ['monitor: GET /api/data invalid JWT passes through',
            buildLambdaEdgeEvent('/api/data'),
            'allow'],
        // In monitor mode, expired signed URL should pass through
        ['monitor: GET /assets/file.png expired signed URL passes through',
            buildLambdaEdgeEvent('/assets/file.png', {}, createSignedUrlParams('/assets/file.png', nowSec - 100, SIGNED_URL_SECRET)),
            'allow'],
    ];
    let monitorFailed = 0;
    for (const [name, event, expected] of monitorCases) {
        if (!(await runAsyncCase(name, event, expected)))
            monitorFailed++;
    }
    console.log('--- origin-request (monitor): ' + (monitorCases.length - monitorFailed) + '/' + monitorCases.length + ' passed ---');
    return { failed: monitorFailed, total: monitorCases.length };
}
// Error boundary test: handler should return 502 on unexpected error
async function runErrorBoundaryTests() {
    const badCfgCode = [
        'const CFG = {',
        '  project: "test",',
        '  mode: "enforce",',
        '  maxHeaderSize: 0,',
        '  jwtGates: [],',
        '  signedUrlGates: [],',
        '  originAuth: null',
        '};',
    ].join('\n');
    const errorHandler = compileOriginTemplate(badCfgCode);
    if (!errorHandler)
        return { failed: 1, total: 1 };
    // Send a malformed event missing Records[0].cf
    const malformedEvent = { Records: [{}] };
    const result = await errorHandler(malformedEvent);
    const ok = result && result.status === '502';
    if (!ok) {
        console.error('FAIL: error boundary | expected 502, got', result && result.status);
        console.log('--- error-boundary: 0/1 passed ---');
        return { failed: 1, total: 1 };
    }
    console.log('OK: error boundary returns 502 on malformed event');
    console.log('--- error-boundary: 1/1 passed ---');
    return { failed: 0, total: 1 };
}
// Run all tests
async function main() {
    let totalFailed = viewerFailed;
    let totalTests = cases.length + viewerMonitorResult.total;
    const enforceResult = await runOriginRequestTests();
    totalFailed += enforceResult.failed;
    totalTests += enforceResult.total;
    const monitorResult = await runMonitorModeTests();
    totalFailed += monitorResult.failed;
    totalTests += monitorResult.total;
    const errorResult = await runErrorBoundaryTests();
    totalFailed += errorResult.failed;
    totalTests += errorResult.total;
    if (totalFailed > 0) {
        console.error('Total:', totalFailed, 'failed out of', totalTests, 'tests');
        process.exit(1);
    }
    console.log('All', totalTests, 'tests passed.');
    process.exit(0);
}
main();
