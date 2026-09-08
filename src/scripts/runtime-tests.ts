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
const { EventEmitter } = require('events');

type HeaderMap = Record<string, string>;
type CloudFrontHeaderMap = Record<string, { value: string; multiValue?: Array<{ value: string }> }>;
type LambdaHeaderMap = Record<string, Array<{ key: string; value: string }>>;
type ExpectedStatus = 'allow' | number | string;
type RuntimeCase = [string, any, ExpectedStatus];

// =========================================================================
// Section 1: viewer-request.js tests (CloudFront Functions)
// =========================================================================

const viewerRequestPath = path.join(__dirname, '..', 'dist', 'edge', 'viewer-request.js');
let code;
try {
  code = fs.readFileSync(viewerRequestPath, 'utf8');
} catch (_e: unknown) {
  console.error('Could not read dist/edge/viewer-request.js. Run: npm run build');
  process.exit(1);
}

// Run the generated script in an isolated function and capture its handler.
const handler = Function(`${code}\nreturn handler;`)();
let originHandler: any;

// The build must have been invoked with EDGE_ADMIN_TOKEN set (see CI / npm script).
// Fall back to the documented placeholder only for --allow-placeholder-token builds.
const DEFAULT_TOKEN = process.env.EDGE_ADMIN_TOKEN
  || 'INSECURE_PLACEHOLDER__REBUILD_WITH_REAL_TOKEN';

function buildEvent(method: string, uri: string, headers: HeaderMap = {}, querystring: any = ''): any {
  const h = headers || {};
  const cfHeaders: CloudFrontHeaderMap = {};
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

function runCase(name: string, event: any, expected: ExpectedStatus) {
  const result: any = handler(event);
  const allowed = result && !result.statusCode && result.uri !== undefined;
  const got = allowed ? 'allow' : (result && result.statusCode);
  const ok = (expected === 'allow' && allowed)
    || (expected !== 'allow' && String(got) === String(expected));
  if (!ok) {
    console.error('FAIL:', name, '| expected', expected, 'got', got);
    return false;
  }
  console.log('OK:', name);
  return true;
}

const cases: RuntimeCase[] = [
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
  ['GET / with CloudFront query object (should be normalized)',
    buildEvent('GET', '/', { 'user-agent': 'Mozilla' }, {
      utm_source: { value: 'google' },
      foo: { value: 'bar' },
      multi: { value: 'one', multiValue: [{ value: 'one' }, { value: 'two' }] },
    }),
    'allow'],

  // Phase A-4: Header count cap (issue #9). Default is 64 from the compiler.
  // 64 headers (incl. user-agent) must pass; 65 must get 431.
  ['GET / with 64 headers (boundary)',
    (() => {
      const h: HeaderMap = { 'user-agent': 'Mozilla' };
      for (let i = 0; i < 63; i++) h['x-filler-' + i] = 'v';
      return buildEvent('GET', '/', h);
    })(),
    'allow',
  ],
  ['GET / with 65 headers (over cap)',
    (() => {
      const h: HeaderMap = { 'user-agent': 'Mozilla' };
      for (let i = 0; i < 64; i++) h['x-filler-' + i] = 'v';
      return buildEvent('GET', '/', h);
    })(),
    431,
  ],
];

let viewerFailed = 0;
for (const [name, event, expected] of cases) {
  if (!runCase(name, event, expected)) viewerFailed++;
}

console.log('--- viewer-request: ' + (cases.length - viewerFailed) + '/' + cases.length + ' passed ---');

// Query normalization must preserve the CloudFront Functions object shape when
// the runtime supplies querystring as an object.
(function runQuerystringShapeTests() {
  const stringResult: any = handler(buildEvent('GET', '/', { 'user-agent': 'Mozilla' }, 'utm_source=google&foo=bar'));
  if (!stringResult || stringResult.querystring !== 'foo=bar') {
    console.error('FAIL: string querystring should drop utm_* and stay string, got', stringResult && stringResult.querystring);
    viewerFailed++;
  } else {
    console.log('OK: string querystring drops utm_* and stays string');
  }

  const objectResult: any = handler(buildEvent('GET', '/', { 'user-agent': 'Mozilla' }, {
    utm_source: { value: 'google' },
    foo: { value: 'bar' },
    multi: { value: 'one', multiValue: [{ value: 'one' }, { value: 'two' }] },
  }));
  const normalized = objectResult && objectResult.querystring;
  const objectShapePreserved = normalized
    && typeof normalized === 'object'
    && !Array.isArray(normalized)
    && !normalized.utm_source
    && normalized.foo?.value === 'bar'
    && Array.isArray(normalized.multi?.multiValue)
    && normalized.multi.multiValue.map((item: any) => item.value).join(',') === 'one,two';
  if (!objectShapePreserved) {
    console.error('FAIL: object querystring should drop utm_* and preserve multiValue shape, got', normalized);
    viewerFailed++;
  } else {
    console.log('OK: object querystring drops utm_* and preserves multiValue shape');
  }
})();

// x-edge-authenticated spoofing defense: the handler MUST strip any
// client-supplied value before the origin sees it. If the caller does not
// also supply a valid token the request must still fail auth.
(function runEdgeAuthSpoofingTests() {
  const spoofEvent = buildEvent('GET', '/admin', {
    'user-agent': 'Mozilla',
    'x-edge-authenticated': '1',
  });
  const result: any = handler(spoofEvent);
  const blocked = result && result.statusCode === 401;
  if (!blocked) {
    console.error('FAIL: spoofed x-edge-authenticated on /admin should still 401, got', result && result.statusCode);
    viewerFailed++;
  } else {
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
  } else {
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
  const result: any = handler(event);
  const passed = result && result.uri !== undefined
    && result.headers && !result.headers['x-forwarded-for'];
  if (!passed) {
    console.error('FAIL: x-forwarded-for should be stripped by default, got', result && result.headers);
    viewerFailed++;
  } else {
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
  if (!h) { viewerFailed++; return; }

  const cases: RuntimeCase[] = [
    ['host-allow: api.example.com accepted', buildEvent('GET', '/', { host: 'api.example.com' }), 'allow'],
    ['host-allow: matches wildcard *.cdn.example.com', buildEvent('GET', '/', { host: 'edge.cdn.example.com' }), 'allow'],
    ['host-allow: matches wildcard case-insensitively', buildEvent('GET', '/', { host: 'EDGE.CDN.EXAMPLE.COM' }), 'allow'],
    ['host-allow: strips :port for match', buildEvent('GET', '/', { host: 'api.example.com:8443' }), 'allow'],
    ['host-allow: rejects unknown host', buildEvent('GET', '/', { host: 'evil.example.com' }), 400],
    ['host-allow: rejects missing host', buildEvent('GET', '/', {}), 400],
    ['host-allow: wildcard does not match parent domain', buildEvent('GET', '/', { host: 'cdn.example.com' }), 400],
  ];
  for (const [name, event, expected] of cases) {
    const result: any = h(event);
    const allowed = result && !result.statusCode && result.uri !== undefined;
    const got = allowed ? 'allow' : (result && result.statusCode);
    const ok = (expected === 'allow' && allowed) || (typeof expected === 'number' && got === expected);
    if (!ok) {
      console.error('FAIL:', name, '| expected', expected, 'got', got);
      viewerFailed++;
    } else {
      console.log('OK:', name);
    }
  }
})();

// Lightweight request anomaly guards (#117): opt-in checks for CRLF,
// malformed Cookie headers, and one-pass double-encoded traversal indicators.
(function runRequestAnomalyGuardTests() {
  const cfgCode = [
    'const CFG = {',
    '  mode: "enforce",',
    '  allowMethods: ["GET"],',
    '  maxQueryLength: 1024,',
    '  maxQueryParams: 30,',
    '  maxUriLength: 2048,',
    '  maxHeaderCount: 64,',
    '  dropQueryKeys: new Set([]),',
    '  uaDenyContains: [],',
    '  blockPathContains: [],',
    '  blockPathRegexes: [],',
    '  normalizePath: { collapseSlashes: false, removeDotSegments: false },',
    '  requiredHeaders: [],',
    '  allowedHosts: [],',
    '  trustForwardedFor: false,',
    '  cors: null,',
    '  anomalyGuards: { enabled: true, crlf: true, malformedCookie: true, doubleEncodedTraversal: true, maxCookieBytes: 32, maxCookiePairs: 2 },',
    '  authGates: [],',
    '};',
  ].join('\n');
  const h = compileViewerTemplate(cfgCode);
  if (!h) { viewerFailed++; return; }

  const cases: RuntimeCase[] = [
    ['anomaly: raw CRLF in path rejected', buildEvent('GET', '/bad\r\npath', {}), 400],
    ['anomaly: encoded CRLF in query rejected', buildEvent('GET', '/', {}, 'next=%0d%0aheader'), 400],
    ['anomaly: encoded CRLF in CloudFront query object rejected',
      buildEvent('GET', '/', {}, { next: { value: '%0d%0aheader' } }),
      400],
    ['anomaly: CRLF in header value rejected', buildEvent('GET', '/', { 'x-test': 'ok\nbad' }), 400],
    ['anomaly: CRLF in header multiValue rejected',
      (() => {
        const event = buildEvent('GET', '/', {});
        event.request.headers['x-test'] = {
          value: 'ok',
          multiValue: [{ value: 'ok' }, { value: 'bad%0d%0aheader' }],
        };
        return event;
      })(),
      400],
    ['anomaly: malformed cookie delimiter rejected', buildEvent('GET', '/', { cookie: 'a=1;;b=2' }), 400],
    ['anomaly: malformed CloudFront cookie map rejected',
      (() => {
        const event = buildEvent('GET', '/', {});
        event.request.cookies = { session: { value: 'ok\nbad' } };
        return event;
      })(),
      400],
    ['anomaly: cookie pair count over limit rejected', buildEvent('GET', '/', { cookie: 'a=1; b=2; c=3' }), 400],
    ['anomaly: CloudFront cookie map pair count over limit rejected',
      (() => {
        const event = buildEvent('GET', '/', {});
        event.request.cookies = { a: { value: '1' }, b: { value: '2' }, c: { value: '3' } };
        return event;
      })(),
      400],
    ['anomaly: double-encoded traversal rejected', buildEvent('GET', '/%252e%252e%252fsecret', {}), 400],
    ['anomaly: double-encoded traversal in CloudFront query object rejected',
      buildEvent('GET', '/', {}, { next: { value: '%252e%252e%252fsecret' } }),
      400],
    ['anomaly: benign double-encoded space allowed', buildEvent('GET', '/download/%2520report', {}, 'name=hello%2520world'), 'allow'],
  ];

  for (const [name, event, expected] of cases) {
    const result: any = h(event);
    const allowed = result && !result.statusCode && result.uri !== undefined;
    const got = allowed ? 'allow' : (result && result.statusCode);
    const ok = (expected === 'allow' && allowed) || (typeof expected === 'number' && got === expected);
    if (!ok) {
      console.error('FAIL:', name, '| expected', expected, 'got', got);
      viewerFailed++;
    } else {
      console.log('OK:', name);
    }
  }
})();

// =========================================================================
// Section 1b: viewer-request.js monitor mode tests
// =========================================================================

function compileViewerTemplate(cfgCode: string): any {
  const templatePath = path.join(__dirname, '..', 'templates', 'aws', 'viewer-request.js');
  let vrCode;
  try {
    vrCode = fs.readFileSync(templatePath, 'utf8');
  } catch (_e: unknown) {
    console.error('Could not read templates/aws/viewer-request.js');
    return null;
  }

  vrCode = vrCode.replace('// {{INJECT_CONFIG}}', cfgCode);

  const wrappedCode = '(function() {\n' + vrCode + '\nreturn handler;\n})()';
  try {
    return eval(wrappedCode);
  } catch (e: unknown) {
    console.error('Failed to eval viewer-request template:', e instanceof Error ? e.message : String(e));
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
  if (!monitorHandler) return { failed: 1, total: 1 };

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

    // Auth gates fail closed even in monitor mode.
    ['viewer-monitor: /admin no token still blocked',
      buildEvent('GET', '/admin', { 'user-agent': 'Mozilla' }),
      401],
  ];

  let failed = 0;
  for (const [name, event, expected] of monitorCases) {
    const result: any = monitorHandler(event);
    const allowed = result && !result.statusCode && result.uri !== undefined;
    const got = allowed ? 'allow' : (result && result.statusCode);
    const ok = (expected === 'allow' && allowed)
      || (expected !== 'allow' && String(got) === String(expected));
    if (!ok) {
      console.error('FAIL:', name, '| expected', expected, 'got', got);
      failed++;
    } else {
      console.log('OK:', name);
    }
  }

  console.log('--- viewer-request (monitor): ' + (monitorCases.length - failed) + '/' + monitorCases.length + ' passed ---');
  return { failed, total: monitorCases.length };
}

const viewerMonitorResult = runViewerMonitorTests();
viewerFailed += viewerMonitorResult.failed;

// =========================================================================
// Section 1c: viewer-response.js CORS Vary Origin (issue #250)
// CHANGELOG 1.4.0 documents Vary: Origin on allowlisted CORS responses; lock it in at runtime.
// =========================================================================

function compileViewerResponseTemplate(responseCfgCode: string): any {
  const templatePath = path.join(__dirname, '..', 'templates', 'aws', 'viewer-response.js');
  let vrCode;
  try {
    vrCode = fs.readFileSync(templatePath, 'utf8');
  } catch (_e: unknown) {
    console.error('Could not read templates/aws/viewer-response.js');
    return null;
  }

  vrCode = vrCode.replace('// {{INJECT_RESPONSE_CONFIG}}', responseCfgCode);

  const wrappedCode = '(function() {\n' + vrCode + '\nreturn handler;\n})()';
  try {
    return eval(wrappedCode);
  } catch (e: unknown) {
    console.error('Failed to eval viewer-response template:', e instanceof Error ? e.message : String(e));
    return null;
  }
}

function viewerResponseCorsCfgCode(): string {
  return [
    'const RESPONSE_CFG = {',
    '  headers: {',
    '    "strict-transport-security": "max-age=31536000; includeSubDomains",',
    '    "x-content-type-options": "nosniff",',
    '    "referrer-policy": "strict-origin-when-cross-origin",',
    '    "permissions-policy": "geolocation=()",',
    '  },',
    '  csp_public: "default-src \'self\'",',
    '  csp_admin: "default-src \'self\'",',
    '  csp_report_only: "",',
    '  csp_report_uri: "",',
    '  csp_nonce: false,',
    '  coop: "",',
    '  coep: "",',
    '  corp: "",',
    '  reporting_endpoints: "",',
    '  adminPathPrefixes: [],',
    '  adminCacheControl: "",',
    '  authProtectedPrefixes: [],',
    '  forceVaryAuth: false,',
    '  clearSiteDataPaths: [],',
    '  clearSiteDataTypes: [],',
    '  cors: {',
    '    allow_origins: ["https://app.example.com", "https://admin.example.com"],',
    '    allow_credentials: true,',
    '    expose_headers: ["X-Request-Id"],',
    '  },',
    '  cookie_attributes: null,',
    '};',
  ].join('\n');
}

function runViewerResponseCorsVaryTests() {
  const handler = compileViewerResponseTemplate(viewerResponseCorsCfgCode());
  if (!handler) return { failed: 2, total: 2 };

  let failed = 0;
  const total = 2;

  const allowlisted = handler({
    request: {
      uri: '/api/data',
      headers: { origin: { value: 'https://app.example.com' } },
    },
    response: {
      statusCode: '200',
      headers: {},
    },
  });
  const allowOrigin = allowlisted.headers['access-control-allow-origin']?.value;
  const allowVary = allowlisted.headers.vary?.value;
  if (allowOrigin !== 'https://app.example.com' || allowVary !== 'Origin') {
    console.error('FAIL: aws viewer-response CORS should echo allowlisted origin and append Vary Origin', {
      allowOrigin,
      allowVary,
    });
    failed++;
  } else {
    console.log('OK: aws viewer-response CORS appends Vary Origin for allowlisted origin responses');
  }

  const merged = handler({
    request: {
      uri: '/',
      headers: { origin: { value: 'https://admin.example.com' } },
    },
    response: {
      statusCode: '200',
      headers: { vary: { value: 'Accept-Language' } },
    },
  });
  const mergedOrigin = merged.headers['access-control-allow-origin']?.value;
  const mergedVary = merged.headers.vary?.value;
  if (mergedOrigin !== 'https://admin.example.com' || mergedVary !== 'Accept-Language, Origin') {
    console.error('FAIL: aws viewer-response CORS should preserve existing Vary tokens when appending Origin', {
      mergedOrigin,
      mergedVary,
    });
    failed++;
  } else {
    console.log('OK: aws viewer-response CORS preserves existing Vary when appending Origin');
  }

  console.log('--- viewer-response (CORS Vary): ' + (total - failed) + '/' + total + ' passed ---');
  return { failed, total };
}

const viewerResponseCorsResult = runViewerResponseCorsVaryTests();
viewerFailed += viewerResponseCorsResult.failed;

// =========================================================================
// Section 2: origin-request.js tests (Lambda@Edge)
// =========================================================================

// Build Lambda@Edge event format
function buildLambdaEdgeEvent(uri: string, headers: HeaderMap = {}, querystring = '', method = 'GET') {
  const h = headers || {};
  const cfHeaders: LambdaHeaderMap = {};
  for (const [k, v] of Object.entries(h)) {
    cfHeaders[k.toLowerCase()] = [{ key: k, value: v }];
  }
  return {
    Records: [{
      cf: {
        request: {
          method,
          uri: uri || '/',
          headers: cfHeaders,
          querystring: querystring || '',
        },
      },
    }],
  };
}

// Async test runner for Lambda@Edge (result.status is string, not statusCode number)
async function runAsyncCase(name: string, event: any, expected: ExpectedStatus) {
  const result: any = await originHandler(event);
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
function compileOriginTemplate(cfgCode: string, deps: any = {}): any {
  const templatePath = path.join(__dirname, '..', 'templates', 'aws', 'origin-request.js');
  let originCode;
  try {
    originCode = fs.readFileSync(templatePath, 'utf8');
  } catch (_e: unknown) {
    console.error('Could not read templates/aws/origin-request.js');
    return null;
  }

  originCode = originCode.replace('// {{INJECT_CONFIG}}', cfgCode);

  const wrappedCode = '(function(deps) {\n' +
    'const crypto = deps.crypto || require("crypto");\n' +
    originCode
      .replace("const crypto = require('crypto');", '') +
    '\nreturn exports.handler;\n' +
    '})';

  try {
    return eval(wrappedCode)(deps);
  } catch (e: unknown) {
    console.error('Failed to eval origin-request template:', e instanceof Error ? e.message : String(e));
    return null;
  }
}

async function runOriginRequestTests() {
  originHandler = compileOriginTemplate('const CFG = { mode: "enforce", maxHeaderSize: 0, originAuth: null };');
  if (!originHandler) return { failed: 1, total: 1 };
  const originCases: RuntimeCase[] = [
    ['origin: GET / pass-through', buildLambdaEdgeEvent('/'), 'allow'],
  ];

  let originFailed = 0;
  for (const [name, event, expected] of originCases) {
    if (!(await runAsyncCase(name, event, expected))) originFailed++;
  }

  // X-Forwarded-For stripping at origin (defense-in-depth).
  const xffEvent = buildLambdaEdgeEvent('/other/file', {
    'x-forwarded-for': '1.2.3.4, 5.6.7.8',
  });
  const xffResult = await originHandler(xffEvent);
  const xffStripped = xffResult && xffResult.uri !== undefined && !xffResult.headers['x-forwarded-for'];
  if (!xffStripped) {
    console.error('FAIL: origin should strip client-supplied x-forwarded-for, headers=',
      xffResult && xffResult.headers);
    originFailed++;
  } else {
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
    console.error('FAIL: origin should strip hop-by-hop / smuggling headers, headers=',
      smugResult && smugResult.headers);
    originFailed++;
  } else {
    console.log('OK: origin strips hop-by-hop smuggling headers');
  }

  const extraAsserts = 2;
  console.log('--- origin-request (enforce): ' + (originCases.length + extraAsserts - originFailed) + '/' + (originCases.length + extraAsserts) + ' passed ---');
  return { failed: originFailed, total: originCases.length + extraAsserts };
}

async function runOriginAuthFailClosedTests() {
  const cfgCode = [
    'const CFG = {',
    '  project: "test",',
    '  mode: "monitor",',
    '  maxHeaderSize: 0,',
    '  originAuth: { type: "custom_header", header: "X-Origin-Verify", secret_env: "__MISSING_ORIGIN_SECRET_FOR_TEST__" },',
    '  trustForwardedFor: false,',
    '  obs: { logFormat: "json", correlationHeader: "" }',
    '};',
  ].join('\n');

  const authHandler = compileOriginTemplate(cfgCode);
  if (!authHandler) return { failed: 1, total: 1 };

  const previous = originHandler;
  originHandler = authHandler;
  const ok = await runAsyncCase(
    'origin: missing origin auth secret fails closed even in monitor mode',
    buildLambdaEdgeEvent('/other/file'),
    '503',
  );
  originHandler = previous;

  console.log('--- origin-auth fail-closed: ' + (ok ? '1/1' : '0/1') + ' passed ---');
  return { failed: ok ? 0 : 1, total: 1 };
}

async function runOriginAuthHmacTests() {
  const secret = 'origin-hmac-secret-for-runtime-test';
  process.env.ORIGIN_HMAC_TEST_SECRET = secret;
  const cfgCode = [
    'const CFG = {',
    '  project: "test",',
    '  mode: "enforce",',
    '  maxHeaderSize: 0,',
    '  originAuth: {',
    '    type: "hmac_signature",',
    '    secret_env: "ORIGIN_HMAC_TEST_SECRET",',
    `    secret: ${JSON.stringify(secret)},`,
    '    header_prefix: "X-CDN-Auth",',
    '    timestamp_tolerance_seconds: 300,',
    '    include_body_hash: false,',
    '    signed_components: ["method", "path", "query", "body", "timestamp", "nonce"]',
    '  },',
    '  trustForwardedFor: false,',
    '  obs: { logFormat: "json", correlationHeader: "" }',
    '};',
  ].join('\n');

  const hmacHandler = compileOriginTemplate(cfgCode);
  if (!hmacHandler) return { failed: 1, total: 1 };

  const event = buildLambdaEdgeEvent('/origin/resource', {}, 'b=2&a=1', 'POST');
  const result: any = await hmacHandler(event);
  const headers = result && result.headers;
  const ts = headers && headers['x-cdn-auth-timestamp'] && headers['x-cdn-auth-timestamp'][0].value;
  const nonce = headers && headers['x-cdn-auth-nonce'] && headers['x-cdn-auth-nonce'][0].value;
  const sig = headers && headers['x-cdn-auth-signature'] && headers['x-cdn-auth-signature'][0].value;
  const canonical = ['POST', '/origin/resource', 'a=1&b=2', '', ts, nonce].join('\n');
  const expected = crypto.createHmac('sha256', secret).update(canonical).digest('base64url');
  const fresh = Math.abs(Math.floor(Date.now() / 1000) - Number(ts)) <= 5;
  const ok = !!(result && result.uri === '/origin/resource' && ts && nonce && sig === expected && fresh && !headers['x-cdn-auth-body-sha256']);
  if (!ok) {
    console.error('FAIL: origin auth HMAC signs method/path/canonical query/timestamp/nonce');
    console.error({ ts, nonce, sig, expected, headers });
  } else {
    console.log('OK: origin auth HMAC signs method/path/canonical query/timestamp/nonce');
  }

  const bodyHashCfgCode = [
    'const CFG = {',
    '  project: "test",',
    '  mode: "enforce",',
    '  maxHeaderSize: 0,',
    '  originAuth: {',
    '    type: "hmac_signature",',
    '    secret_env: "ORIGIN_HMAC_TEST_SECRET",',
    `    secret: ${JSON.stringify(secret)},`,
    '    header_prefix: "X-CDN-Auth",',
    '    timestamp_tolerance_seconds: 300,',
    '    include_body_hash: true,',
    '    signed_components: ["method", "path", "query", "body", "timestamp", "nonce"]',
    '  },',
    '  trustForwardedFor: false,',
    '  obs: { logFormat: "json", correlationHeader: "" }',
    '};',
  ].join('\n');
  const bodyHashHandler = compileOriginTemplate(bodyHashCfgCode);
  let missingBodyOk = false;
  let emptyBodyOk = false;
  let bodyPresentOk = false;
  if (!bodyHashHandler) {
    console.error('FAIL: origin auth HMAC body hash template compiles');
  } else {
    const missingBodyResult: any = await bodyHashHandler(buildLambdaEdgeEvent(
      '/origin/upload',
      { 'Content-Length': '23' },
      '',
      'POST',
    ));
    missingBodyOk = !!(missingBodyResult && missingBodyResult.status === '503');
    if (!missingBodyOk) {
      console.error('FAIL: origin auth HMAC should fail closed when declared POST body is unavailable, got',
        missingBodyResult && missingBodyResult.status);
    } else {
      console.log('OK: origin auth HMAC fails closed when declared POST body is unavailable');
    }

    const emptyBodyResult: any = await bodyHashHandler(buildLambdaEdgeEvent(
      '/origin/empty',
      { 'Content-Length': '0' },
      '',
      'POST',
    ));
    const emptyHeaders = emptyBodyResult && emptyBodyResult.headers;
    const emptyTs = emptyHeaders && emptyHeaders['x-cdn-auth-timestamp'] && emptyHeaders['x-cdn-auth-timestamp'][0].value;
    const emptyNonce = emptyHeaders && emptyHeaders['x-cdn-auth-nonce'] && emptyHeaders['x-cdn-auth-nonce'][0].value;
    const emptySig = emptyHeaders && emptyHeaders['x-cdn-auth-signature'] && emptyHeaders['x-cdn-auth-signature'][0].value;
    const emptyHash = emptyHeaders && emptyHeaders['x-cdn-auth-body-sha256'] && emptyHeaders['x-cdn-auth-body-sha256'][0].value;
    const expectedEmptyHash = crypto.createHash('sha256').update(Buffer.alloc(0)).digest('hex');
    const emptyCanonical = ['POST', '/origin/empty', '', expectedEmptyHash, emptyTs, emptyNonce].join('\n');
    const expectedEmptySig = crypto.createHmac('sha256', secret).update(emptyCanonical).digest('base64url');
    emptyBodyOk = !!(emptyBodyResult && emptyBodyResult.uri === '/origin/empty'
      && emptyHash === expectedEmptyHash
      && emptySig === expectedEmptySig);
    if (!emptyBodyOk) {
      console.error('FAIL: origin auth HMAC should sign legitimately empty POST bodies');
      console.error({ emptyTs, emptyNonce, emptySig, expectedEmptySig, emptyHash, expectedEmptyHash, emptyHeaders });
    } else {
      console.log('OK: origin auth HMAC signs legitimately empty POST bodies');
    }

    const bodyEvent = buildLambdaEdgeEvent('/origin/upload', {}, '', 'POST');
    const bodyData = Buffer.from('payload-for-origin-auth').toString('base64');
    (bodyEvent.Records[0].cf.request as any).body = {
      data: bodyData,
      encoding: 'base64',
      inputTruncated: false,
    };
    const bodyResult: any = await bodyHashHandler(bodyEvent);
    const bodyHeaders = bodyResult && bodyResult.headers;
    const bodyTs = bodyHeaders && bodyHeaders['x-cdn-auth-timestamp'] && bodyHeaders['x-cdn-auth-timestamp'][0].value;
    const bodyNonce = bodyHeaders && bodyHeaders['x-cdn-auth-nonce'] && bodyHeaders['x-cdn-auth-nonce'][0].value;
    const bodySig = bodyHeaders && bodyHeaders['x-cdn-auth-signature'] && bodyHeaders['x-cdn-auth-signature'][0].value;
    const bodyHash = bodyHeaders && bodyHeaders['x-cdn-auth-body-sha256'] && bodyHeaders['x-cdn-auth-body-sha256'][0].value;
    const expectedBodyHash = crypto.createHash('sha256').update(Buffer.from('payload-for-origin-auth')).digest('hex');
    const bodyCanonical = ['POST', '/origin/upload', '', expectedBodyHash, bodyTs, bodyNonce].join('\n');
    const expectedBodySig = crypto.createHmac('sha256', secret).update(bodyCanonical).digest('base64url');
    bodyPresentOk = !!(bodyResult && bodyResult.uri === '/origin/upload'
      && bodyHash === expectedBodyHash
      && bodySig === expectedBodySig);
    if (!bodyPresentOk) {
      console.error('FAIL: origin auth HMAC should sign available request body');
      console.error({ bodyTs, bodyNonce, bodySig, expectedBodySig, bodyHash, expectedBodyHash, bodyHeaders });
    } else {
      console.log('OK: origin auth HMAC signs available request body');
    }
  }
  delete process.env.ORIGIN_HMAC_TEST_SECRET;
  const passed = [ok, missingBodyOk, emptyBodyOk, bodyPresentOk].filter(Boolean).length;
  console.log('--- origin-auth hmac: ' + passed + '/4 passed ---');
  return { failed: 4 - passed, total: 4 };
}

// Error boundary test: handler should return 502 on unexpected error
async function runErrorBoundaryTests() {
  const badCfgCode = [
    'const CFG = {',
    '  project: "test",',
    '  mode: "enforce",',
    '  maxHeaderSize: 0,',
    '  originAuth: null',
    '};',
  ].join('\n');

  const errorHandler = compileOriginTemplate(badCfgCode);
  if (!errorHandler) return { failed: 1, total: 1 };

  // Send a malformed event missing Records[0].cf
  const malformedEvent = { Records: [{}] };
  const result: any = await errorHandler(malformedEvent);
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

async function runOriginAllowSamplingTests() {
  const cfg = (sampleRate: number) => [
    'const CFG = {',
    '  project: "sampling-test",',
    '  mode: "enforce",',
    '  maxHeaderSize: 0,',
    '  originAuth: null,',
    `  obs: { logFormat: "json", correlationHeader: "traceparent", sampleRate: ${sampleRate}, auditLogAuth: false, auditHashSub: false }`,
    '};',
  ].join('\n');

  let failed = 0;
  const fullHandler = compileOriginTemplate(cfg(1));
  const captured: string[] = [];
  const originalLog = console.log;
  console.log = (line: any) => { captured.push(String(line)); };
  try {
    await fullHandler(buildLambdaEdgeEvent('/sampled', { traceparent: '00-origin-allow-test-01' }));
  } finally {
    console.log = originalLog;
  }
  const fullAllowLine = captured.find((line) => line.includes('"event":"allow"'));
  if (!fullAllowLine) {
    console.error('FAIL: origin sample_rate 1 should emit an allow decision');
    failed++;
  } else {
    const record = JSON.parse(fullAllowLine);
    const fieldsOk = record.method === 'GET'
      && record.uri === '/sampled'
      && record.correlation_id === '00-origin-allow-test-01';
    if (!fieldsOk) {
      console.error('FAIL: origin allow decision is missing fields', record);
      failed++;
    } else {
      console.log('OK: origin sample_rate 1 emits an allow decision with correlation fields');
    }
  }

  const zeroHandler = compileOriginTemplate(cfg(0));
  const zeroLogs: string[] = [];
  console.log = (line: any) => { zeroLogs.push(String(line)); };
  try {
    await zeroHandler(buildLambdaEdgeEvent('/not-sampled'));
  } finally {
    console.log = originalLog;
  }
  if (zeroLogs.some((line) => line.includes('"event":"allow"'))) {
    console.error('FAIL: origin sample_rate 0 should suppress allow decisions');
    failed++;
  } else {
    console.log('OK: origin sample_rate 0 suppresses allow decisions');
  }

  const partialHandler = compileOriginTemplate(cfg(0.5), {
    crypto: {
      ...crypto,
      randomUUID: (() => {
        let sequence = 0;
        return () => (++sequence % 2 === 0 ? 'minted-50' : 'minted-0');
      })(),
    },
  });
  const repeated: string[] = [];
  console.log = (line: any) => { repeated.push(String(line)); };
  try {
    for (let i = 0; i < 8; i++) await partialHandler(buildLambdaEdgeEvent('/stable-path'));
  } finally {
    console.log = originalLog;
  }
  const allowCount = repeated.filter((line) => line.includes('"event":"allow"')).length;
  if (allowCount !== 0 && allowCount !== 8) {
    console.error('FAIL: origin sampling changed after minting correlation IDs, allow logs=', allowCount);
    failed++;
  } else {
    console.log('OK: origin sampling is deterministic before correlation ID minting');
  }

  return { failed, total: 3 };
}

// Run all tests
async function main() {
  let totalFailed = viewerFailed;
  let totalTests = cases.length + viewerMonitorResult.total + viewerResponseCorsResult.total;

  const enforceResult: any = await runOriginRequestTests();
  totalFailed += enforceResult.failed;
  totalTests += enforceResult.total;

  const originAuthResult = await runOriginAuthFailClosedTests();
  totalFailed += originAuthResult.failed;
  totalTests += originAuthResult.total;

  const originAuthHmacResult = await runOriginAuthHmacTests();
  totalFailed += originAuthHmacResult.failed;
  totalTests += originAuthHmacResult.total;

  const errorResult = await runErrorBoundaryTests();
  totalFailed += errorResult.failed;
  totalTests += errorResult.total;

  const allowSamplingResult = await runOriginAllowSamplingTests();
  totalFailed += allowSamplingResult.failed;
  totalTests += allowSamplingResult.total;

  if (totalFailed > 0) {
    console.error('Total:', totalFailed, 'failed out of', totalTests, 'tests');
    process.exit(1);
  }
  console.log('All', totalTests, 'tests passed.');
  process.exit(0);
}

main();
