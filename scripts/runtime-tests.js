#!/usr/bin/env node
/**
 * Runtime tests: run request cases against CloudFront Functions viewer-request handler
 * and Lambda@Edge origin-request handler, asserting expected status codes.
 * Usage: node scripts/runtime-tests.js
 *
 * Test cases are aligned with policy/base.yml (balanced) and the viewer-request.js CFG.
 */

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
} catch (e) {
  console.error('Could not read dist/edge/viewer-request.js. Run: npm run build');
  process.exit(1);
}

// Run the script so handler() is defined (in global scope)
eval(code);

// ビルド時に EDGE_ADMIN_TOKEN 未設定なら BUILD_TIME_INJECTION が注入される
const DEFAULT_TOKEN = process.env.EDGE_ADMIN_TOKEN || 'BUILD_TIME_INJECTION';

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
  // Traversal patterns are blocked by blockPathMarks
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
];

let viewerFailed = 0;
for (const [name, event, expected] of cases) {
  if (!runCase(name, event, expected)) viewerFailed++;
}

console.log('--- viewer-request: ' + (cases.length - viewerFailed) + '/' + cases.length + ' passed ---');

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

async function runOriginRequestTests() {
  // Build a temporary test policy inline and compile the origin-request code
  const testSecret = HS256_SECRET;
  process.env.JWT_TEST_SECRET = testSecret;

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
    '  signedUrlGates: [],',
    '  originAuth: null',
    '};',
  ].join('\n');

  const templatePath = path.join(__dirname, '..', 'templates', 'aws', 'origin-request.js');
  let originCode;
  try {
    originCode = fs.readFileSync(templatePath, 'utf8');
  } catch (e) {
    console.error('Could not read templates/aws/origin-request.js');
    return 1;
  }

  originCode = originCode.replace('// {{INJECT_CONFIG}}', originCfgCode);

  // Wrap in a module scope to avoid polluting globals
  const wrappedCode = '(function() {\n' +
    'const crypto = require("crypto");\n' +
    'const https = require("https");\n' +
    originCode
      .replace("const crypto = require('crypto');", '')
      .replace("const https = require('https');", '') +
    '\nreturn exports.handler;\n' +
    '})()';

  let originHandler;
  try {
    originHandler = eval(wrappedCode);
  } catch (e) {
    console.error('Failed to eval origin-request template:', e.message);
    return 1;
  }

  // Make originHandler available to runAsyncCase
  global.originHandler = originHandler;

  const nowSec = Math.floor(Date.now() / 1000);

  const originCases = [
    // Pass-through (no protected prefix match)
    ['origin: GET / pass-through',
      buildLambdaEdgeEvent('/'),
      'allow'],

    // Missing Authorization header on protected route
    ['origin: GET /api/data no auth',
      buildLambdaEdgeEvent('/api/data'),
      '401'],

    // Valid JWT
    ['origin: GET /api/data valid JWT',
      buildLambdaEdgeEvent('/api/data', {
        'Authorization': 'Bearer ' + createHS256Jwt({
          sub: 'user1', iss: 'test-issuer', aud: 'test-audience',
          exp: nowSec + 3600, nbf: nowSec - 60,
        }, testSecret),
      }),
      'allow'],

    // Expired JWT
    ['origin: GET /api/data expired JWT',
      buildLambdaEdgeEvent('/api/data', {
        'Authorization': 'Bearer ' + createHS256Jwt({
          sub: 'user1', iss: 'test-issuer', aud: 'test-audience',
          exp: nowSec - 100,
        }, testSecret),
      }),
      '401'],

    // Bad signature (wrong secret)
    ['origin: GET /api/data bad signature',
      buildLambdaEdgeEvent('/api/data', {
        'Authorization': 'Bearer ' + createHS256Jwt({
          sub: 'user1', iss: 'test-issuer', aud: 'test-audience',
          exp: nowSec + 3600,
        }, 'wrong-secret'),
      }),
      '401'],

    // Wrong issuer
    ['origin: GET /api/data wrong issuer',
      buildLambdaEdgeEvent('/api/data', {
        'Authorization': 'Bearer ' + createHS256Jwt({
          sub: 'user1', iss: 'wrong-issuer', aud: 'test-audience',
          exp: nowSec + 3600,
        }, testSecret),
      }),
      '401'],

    // Wrong audience
    ['origin: GET /api/data wrong audience',
      buildLambdaEdgeEvent('/api/data', {
        'Authorization': 'Bearer ' + createHS256Jwt({
          sub: 'user1', iss: 'test-issuer', aud: 'wrong-audience',
          exp: nowSec + 3600,
        }, testSecret),
      }),
      '401'],

    // Future nbf (not yet valid)
    ['origin: GET /api/data future nbf',
      buildLambdaEdgeEvent('/api/data', {
        'Authorization': 'Bearer ' + createHS256Jwt({
          sub: 'user1', iss: 'test-issuer', aud: 'test-audience',
          exp: nowSec + 7200, nbf: nowSec + 3600,
        }, testSecret),
      }),
      '401'],

    // Malformed token (not 3 parts)
    ['origin: GET /api/data malformed token',
      buildLambdaEdgeEvent('/api/data', {
        'Authorization': 'Bearer not-a-jwt',
      }),
      '401'],
  ];

  let originFailed = 0;
  for (const [name, event, expected] of originCases) {
    if (!(await runAsyncCase(name, event, expected))) originFailed++;
  }

  console.log('--- origin-request: ' + (originCases.length - originFailed) + '/' + originCases.length + ' passed ---');
  return originFailed;
}

// Run all tests
async function main() {
  let totalFailed = viewerFailed;

  const originFailed = await runOriginRequestTests();
  totalFailed += originFailed;

  const totalTests = cases.length + 9; // 9 origin-request test cases
  if (totalFailed > 0) {
    console.error('Total:', totalFailed, 'failed out of', totalTests, 'tests');
    process.exit(1);
  }
  console.log('All', totalTests, 'tests passed.');
  process.exit(0);
}

main();
