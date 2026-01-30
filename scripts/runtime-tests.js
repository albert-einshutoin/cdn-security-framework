#!/usr/bin/env node
/**
 * Runtime tests: run request cases against CloudFront Functions viewer-request handler
 * and assert expected status (allow = pass through, or 400/401/403/405/414 = block).
 * Usage: node scripts/runtime-tests.js
 *
 * Test cases are aligned with policy/base.yml (balanced) and the viewer-request.js CFG.
 */

const fs = require('fs');
const path = require('path');

// ビルド成果物をテスト（npm run build 後に実行）
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

let failed = 0;
for (const [name, event, expected] of cases) {
  if (!runCase(name, event, expected)) failed++;
}

if (failed > 0) {
  console.error('Total:', failed, 'failed');
  process.exit(1);
}
console.log('All', cases.length, 'tests passed.');
process.exit(0);
