#!/usr/bin/env node
/**
 * Compile Cloudflare Workers: security.yml を読み、テンプレートに注入して dist/edge/cloudflare/index.ts に出力する。
 * Usage: node scripts/compile-cloudflare.js [path/to/security.yml] [--policy path] [--out-dir dir]
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

const request = policy.request || {};
const limits = request.limits || {};
const block = request.block || {};
const normalize = request.normalize || {};
const routes = policy.routes || [];

let protectedPrefixes = ['/admin', '/docs', '/swagger'];
let adminTokenHeader = 'x-edge-token';
for (const route of routes) {
  const gate = route.auth_gate;
  if (!gate) continue;
  const match = route.match || {};
  const prefixes = match.path_prefixes || [];
  if (prefixes.length) protectedPrefixes = prefixes;
  adminTokenHeader = gate.header || 'x-edge-token';
  break;
}

// Get all auth gates
function getAuthGates() {
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
      gateConfig.tokenHeaderName = gate.header || 'x-edge-token';
    } else if (authType === 'basic_auth') {
      const credEnv = gate.credentials_env || 'BASIC_AUTH_CREDS';
      gateConfig.credentialsEnv = credEnv;
    }
    
    gates.push(gateConfig);
  }
  return gates;
}
const authGates = getAuthGates();

const dropQueryKeysArray = normalize.drop_query_keys || [
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'gclid', 'fbclid',
];
const blockPathMarks = pathPatternsToMarks(block.path_patterns);
const allowMethods = request.allow_methods || ['GET', 'HEAD', 'POST'];
const pathNormalize = normalize.path || {};
const requiredHeaders = block.header_missing || ['user-agent'];
const resHeaders = policy.response_headers || {};
const corsConfig = resHeaders.cors || null;

const cfgCode = [
  'const CFG = {',
  `  allowMethods: new Set(${JSON.stringify(allowMethods)}),`,
  `  maxQueryLength: ${Number(limits.max_query_length) || 1024},`,
  `  maxQueryParams: ${Number(limits.max_query_params) || 30},`,
  `  maxUriLength: ${Number(limits.max_uri_length) || 2048},`,
  `  maxHeaderSize: ${Number(limits.max_header_size) || 0},`,
  `  dropQueryKeys: new Set(${JSON.stringify(dropQueryKeysArray)}),`,
  `  uaDenyContains: ${JSON.stringify(block.ua_contains || ['sqlmap', 'nikto', 'acunetix', 'masscan', 'python-requests'])},`,
  `  blockPathMarks: ${JSON.stringify(blockPathMarks)},`,
  `  normalizePath: { collapseSlashes: ${!!pathNormalize.collapse_slashes}, removeDotSegments: ${!!pathNormalize.remove_dot_segments} },`,
  `  requiredHeaders: ${JSON.stringify(requiredHeaders)},`,
  `  cors: ${JSON.stringify(corsConfig)},`,
  `  authGates: ${JSON.stringify(authGates)},`,
  `  protectedPrefixes: ${JSON.stringify(protectedPrefixes)},`,
  `  adminTokenHeader: ${JSON.stringify(adminTokenHeader)},`,
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
    if (resp.cache_control) adminCacheControl = resp.cache_control;
    break;
  }
}

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
  `  cors: ${JSON.stringify(corsConfig)},`,
  `  cookie_attributes: ${JSON.stringify(resHeaders.cookie_attributes || null)},`,
  '};',
].join('\n');

const templatePath = path.join(repoRoot, 'templates', 'cloudflare', 'index.ts');
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
code = code.replace('// {{INJECT_RESPONSE_CFG}}', responseCfgCode);

const distDir = path.join(outDir, 'edge', 'cloudflare');
fs.mkdirSync(distDir, { recursive: true });
const outPath = path.join(distDir, 'index.ts');
fs.writeFileSync(outPath, code, 'utf8');

console.log('Build complete:', outPath);
