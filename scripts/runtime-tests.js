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

const viewerRequestPath = path.join(__dirname, '..', 'runtimes', 'aws-cloudfront-functions', 'viewer-request.js');
let code;
try {
  code = fs.readFileSync(viewerRequestPath, 'utf8');
} catch (e) {
  console.error('Could not read viewer-request.js:', e.message);
  process.exit(1);
}

// Run the script so handler() is defined (in global scope)
eval(code);

const DEFAULT_TOKEN = 'REPLACE_ME_WITH_EDGE_ADMIN_TOKEN';

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
  ['GET / with UA', buildEvent('GET', '/', { 'user-agent': 'Mozilla/5.0' }), 'allow'],
  ['GET / no UA', buildEvent('GET', '/'), 400],
  ['OPTIONS /', buildEvent('OPTIONS', '/', { 'user-agent': 'Mozilla' }), 405],
  ['GET /foo/../bar (traversal)', buildEvent('GET', '/foo/../bar', { 'user-agent': 'Mozilla' }), 400],
  ['GET / with %2e%2e', buildEvent('GET', '/x%2e%2e/y', { 'user-agent': 'Mozilla' }), 400],
  ['GET / with sqlmap UA', buildEvent('GET', '/', { 'user-agent': 'sqlmap/1.0' }), 403],
  ['GET / with nikto UA', buildEvent('GET', '/', { 'user-agent': 'Nikto scanner' }), 403],
  ['GET /admin no token', buildEvent('GET', '/admin', { 'user-agent': 'Mozilla' }), 401],
  ['GET /admin with token', buildEvent('GET', '/admin', { 'user-agent': 'Mozilla', 'x-edge-token': DEFAULT_TOKEN }), 'allow'],
  ['GET /docs with token', buildEvent('GET', '/docs', { 'user-agent': 'Mozilla', 'x-edge-token': DEFAULT_TOKEN }), 'allow'],
  ['GET / with too many query params', buildEvent('GET', '/', { 'user-agent': 'Mozilla' }, Array(31).fill('a=b').join('&')), 400],
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
