#!/usr/bin/env node
/**
 * Compile: security.yml (Source of Truth) を読み、テンプレートに注入して dist/edge/*.js に出力する。
 * Usage: node scripts/compile.js [path/to/security.yml] [--policy path] [--out-dir dir]
 * Default: policy/security.yml or policy/base.yml
 * Requires: npm install js-yaml
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const repoRoot = path.join(__dirname, '..');
const argv = process.argv.slice(2);
const securityPath = path.join(repoRoot, 'policy', 'security.yml');
const basePath = path.join(repoRoot, 'policy', 'base.yml');
let policyPath = fs.existsSync(securityPath) ? securityPath : basePath;
let outDir = path.join(repoRoot, 'dist');
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--policy' && argv[i + 1]) { policyPath = argv[++i]; continue; }
  if (argv[i] === '--out-dir' && argv[i + 1]) { outDir = argv[++i]; continue; }
  if (!argv[i].startsWith('--')) { policyPath = argv[i]; }
}

// 1. Policy (正) を読む
let policy;
try {
  const content = fs.readFileSync(policyPath, 'utf8');
  policy = yaml.load(content);
} catch (e) {
  if (e.code === 'ENOENT') {
    console.error('Error: policy file not found:', policyPath);
    process.exit(1);
  }
  console.error('Error: failed to parse policy YAML:', e.message);
  process.exit(1);
}

// path_patterns (正規表現) を CloudFront 用の blockPathMarks（部分文字列）に変換
function pathPatternsToMarks(pathPatterns) {
  if (!Array.isArray(pathPatterns) || pathPatterns.length === 0) {
    return ['/../', '%2e%2e', '%2f..', '..%2f', '%5c'];
  }
  const marks = new Set();
  const knownMap = {
    '(?i)\\.{2}/': ['/../', '..'],
    '(?i)%2e%2e': ['%2e%2e', '%2E%2E'],
  };
  for (const p of pathPatterns) {
    const s = (p || '').trim();
    if (knownMap[s]) knownMap[s].forEach((m) => marks.add(m));
    else if (s) marks.add(s.replace(/\\(\.)/g, '$1').replace(/\?i\)/g, '').slice(0, 20));
  }
  if (marks.size === 0) return ['/../', '%2e%2e', '%2f..', '..%2f', '%5c'];
  return Array.from(marks);
}

// routes から認証ゲート設定を取得（複数ルート対応）
function getAuthGates(policy) {
  const routes = policy.routes || [];
  const gates = [];
  
  for (const route of routes) {
    const gate = route.auth_gate;
    if (!gate) continue;
    
    const match = route.match || {};
    const prefixes = match.path_prefixes || [];
    const authType = gate.type || 'static_token';
    
    const gateConfig = {
      name: route.name || 'unnamed',
      protectedPrefixes: prefixes.length ? prefixes : ['/admin', '/docs', '/swagger'],
      type: authType,
    };
    
    if (authType === 'static_token') {
      const header = gate.header || 'x-edge-token';
      const tokenEnv = gate.token_env || 'EDGE_ADMIN_TOKEN';
      const token = process.env[tokenEnv] || process.env.EDGE_ADMIN_TOKEN || 'BUILD_TIME_INJECTION';
      gateConfig.tokenHeaderName = header;
      gateConfig.token = token;
    } else if (authType === 'basic_auth') {
      const credEnv = gate.credentials_env || 'BASIC_AUTH_CREDS';
      const credentials = process.env[credEnv] || 'BUILD_TIME_INJECTION';
      gateConfig.credentials = credentials; // base64 encoded user:pass
    }
    // JWT and signed_url types are handled in Lambda@Edge (Phase D)
    
    gates.push(gateConfig);
  }
  
  return gates;
}

// 後方互換性のための単一 adminGate 取得
function getAdminGate(policy) {
  const gates = getAuthGates(policy);
  const staticTokenGate = gates.find(g => g.type === 'static_token');
  
  if (staticTokenGate) {
    return {
      enabled: true,
      protectedPrefixes: staticTokenGate.protectedPrefixes,
      tokenHeaderName: staticTokenGate.tokenHeaderName,
      token: staticTokenGate.token,
    };
  }
  return { enabled: false, protectedPrefixes: [], tokenHeaderName: 'x-edge-token', token: '' };
}

const defaults = policy.defaults || {};
const request = policy.request || {};
const limits = request.limits || {};
const block = request.block || {};
const normalize = request.normalize || {};

const adminGate = getAdminGate(policy);
const authGates = getAuthGates(policy);

// 2. JS 用の設定オブジェクト (CFG) を組み立て（Set はコードとして出力）
const dropQueryKeysArray = normalize.drop_query_keys || [
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'gclid', 'fbclid',
];
const blockPathMarks = pathPatternsToMarks(block.path_patterns);
const pathNormalize = normalize.path || {};

const requiredHeaders = block.header_missing || ['user-agent'];

// CORS config for preflight handling in viewer-request
const corsConfig = (policy.response_headers || {}).cors || null;

const cfgCode = [
  'const CFG = {',
  `  mode: ${JSON.stringify(defaults.mode || 'enforce')},`,
  `  allowMethods: ${JSON.stringify(request.allow_methods || ['GET', 'HEAD', 'POST'])},`,
  `  maxQueryLength: ${Number(limits.max_query_length) || 1024},`,
  `  maxQueryParams: ${Number(limits.max_query_params) || 30},`,
  `  maxUriLength: ${Number(limits.max_uri_length) || 2048},`,
  `  dropQueryKeys: new Set(${JSON.stringify(dropQueryKeysArray)}),`,
  `  uaDenyContains: ${JSON.stringify(block.ua_contains || ['sqlmap', 'nikto', 'acunetix', 'masscan', 'python-requests'])},`,
  `  blockPathMarks: ${JSON.stringify(blockPathMarks)},`,
  `  normalizePath: { collapseSlashes: ${!!pathNormalize.collapse_slashes}, removeDotSegments: ${!!pathNormalize.remove_dot_segments} },`,
  `  requiredHeaders: ${JSON.stringify(requiredHeaders)},`,
  `  cors: ${JSON.stringify(corsConfig)},`,
  '  adminGate: ' + JSON.stringify(adminGate, null, 2).replace(/^/gm, '  ') + ',',
  `  authGates: ${JSON.stringify(authGates)},`,
  '};',
].join('\n');

// 3. テンプレートを読んで注入（templates/ は CLI 内部資産）
const templatePath = path.join(repoRoot, 'templates', 'aws', 'viewer-request.js');
let code;
try {
  code = fs.readFileSync(templatePath, 'utf8');
} catch (e) {
  if (e.code === 'ENOENT') {
    console.error('Error: template not found:', templatePath);
    process.exit(1);
  }
  throw e;
}

code = code.replace('// {{INJECT_CONFIG}}', cfgCode);

// 4. dist/edge/ に出力（Edge Runtime: Functions / Workers 用）
const distDir = path.join(outDir, 'edge');
fs.mkdirSync(distDir, { recursive: true });
const outPath = path.join(distDir, 'viewer-request.js');
fs.writeFileSync(outPath, code, 'utf8');

console.log('Build complete:', outPath);

// 5. viewer-response.js を生成（response_headers と routes から）
const resHeaders = policy.response_headers || {};
const routes = policy.routes || [];
let adminPathPrefixes = [];
let adminCacheControl = 'no-store';
for (const route of routes) {
  const match = route.match || {};
  const prefixes = match.path_prefixes || [];
  const resp = route.response || {};
  if (prefixes.length && (route.auth_gate || resp.cache_control)) {
    adminPathPrefixes = prefixes;
    if (resp.cache_control) adminCacheControl = resp.cache_control;
    break;
  }
}
if (adminPathPrefixes.length === 0) adminPathPrefixes = ['/admin', '/docs', '/swagger'];

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
  `  adminPathPrefixes: ${JSON.stringify(adminPathPrefixes)},`,
  `  adminCacheControl: ${JSON.stringify(adminCacheControl)},`,
  `  cors: ${JSON.stringify(resHeaders.cors || null)},`,
  `  cookie_attributes: ${JSON.stringify(resHeaders.cookie_attributes || null)},`,
  '};',
].join('\n');

const templateResponsePath = path.join(repoRoot, 'templates', 'aws', 'viewer-response.js');
let codeResponse;
try {
  codeResponse = fs.readFileSync(templateResponsePath, 'utf8');
} catch (e) {
  if (e.code === 'ENOENT') {
    console.error('Error: template not found:', templateResponsePath);
    process.exit(1);
  }
  throw e;
}
codeResponse = codeResponse.replace('// {{INJECT_RESPONSE_CONFIG}}', responseCfgCode);
const outPathResponse = path.join(distDir, 'viewer-response.js');
fs.writeFileSync(outPathResponse, codeResponse, 'utf8');
console.log('Build complete:', outPathResponse);

// 6. Lambda@Edge origin-request.js を生成
// JWT and signed_url auth gates need Lambda@Edge (crypto required)
const jwtGates = authGates.filter(g => g.type === 'jwt').map(g => {
  const route = (policy.routes || []).find(r => r.name === g.name);
  const gate = route?.auth_gate || {};
  return {
    name: g.name,
    protectedPrefixes: g.protectedPrefixes,
    type: 'jwt',
    algorithm: gate.algorithm || 'RS256',
    jwks_url: gate.jwks_url || '',
    issuer: gate.issuer || '',
    audience: gate.audience || '',
    secret_env: gate.secret_env || '',
  };
});

const signedUrlGates = authGates.filter(g => g.type === 'signed_url').map(g => {
  const route = (policy.routes || []).find(r => r.name === g.name);
  const gate = route?.auth_gate || {};
  return {
    name: g.name,
    protectedPrefixes: g.protectedPrefixes,
    type: 'signed_url',
    algorithm: gate.algorithm || 'HMAC-SHA256',
    secret_env: gate.secret_env || 'URL_SIGNING_SECRET',
    expires_param: gate.expires_param || 'exp',
    signature_param: gate.signature_param || 'sig',
  };
});

// Origin auth config
const originAuth = (policy.origin || {}).auth || null;

const originCfgCode = [
  'const CFG = {',
  `  project: ${JSON.stringify(policy.project || 'cdn-security')},`,
  `  mode: ${JSON.stringify(defaults.mode || 'enforce')},`,
  `  maxHeaderSize: ${Number(limits.max_header_size) || 0},`,
  `  jwtGates: ${JSON.stringify(jwtGates)},`,
  `  signedUrlGates: ${JSON.stringify(signedUrlGates)},`,
  `  originAuth: ${JSON.stringify(originAuth)},`,
  '};',
].join('\n');
const templateOriginPath = path.join(repoRoot, 'templates', 'aws', 'origin-request.js');
let codeOrigin;
try {
  codeOrigin = fs.readFileSync(templateOriginPath, 'utf8');
} catch (e) {
  if (e.code === 'ENOENT') {
    console.error('Error: template not found:', templateOriginPath);
    process.exit(1);
  }
  throw e;
}
codeOrigin = codeOrigin.replace('// {{INJECT_CONFIG}}', originCfgCode);
const outPathOrigin = path.join(distDir, 'origin-request.js');
fs.writeFileSync(outPathOrigin, codeOrigin, 'utf8');
console.log('Build complete:', outPathOrigin);
