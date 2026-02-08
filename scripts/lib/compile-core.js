const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const repoRoot = path.join(__dirname, '..', '..');
const DEFAULT_MARKS = ['/../', '%2e%2e', '%2f..', '..%2f', '%5c'];

function parseArgs(argv, rootDir = repoRoot) {
  const securityPath = path.join(rootDir, 'policy', 'security.yml');
  const basePath = path.join(rootDir, 'policy', 'base.yml');
  let policyPath = fs.existsSync(securityPath) ? securityPath : basePath;
  let outDir = path.join(rootDir, 'dist');

  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--policy' && argv[i + 1]) {
      policyPath = argv[++i];
      continue;
    }
    if (argv[i] === '--out-dir' && argv[i + 1]) {
      outDir = argv[++i];
      continue;
    }
    if (!argv[i].startsWith('--')) {
      policyPath = argv[i];
    }
  }

  return { policyPath, outDir };
}

function loadPolicy(policyPath) {
  const content = fs.readFileSync(policyPath, 'utf8');
  return yaml.load(content);
}

function validateAuthGates(policy, options = {}) {
  const exitOnError = options.exitOnError !== false;
  const logger = options.logger || console;
  const routes = policy.routes || [];
  const errors = [];

  for (const route of routes) {
    const gate = route.auth_gate;
    if (!gate) continue;
    const name = route.name || 'unnamed';
    const authType = gate.type || 'static_token';

    if (authType === 'jwt') {
      const alg = gate.algorithm || 'RS256';
      if (alg === 'RS256' && !gate.jwks_url) {
        errors.push(`Route "${name}": JWT+RS256 requires "jwks_url"`);
      }
      if (alg === 'HS256' && !gate.secret_env) {
        errors.push(`Route "${name}": JWT+HS256 requires "secret_env"`);
      }
    } else if (authType === 'signed_url') {
      if (!gate.secret_env) {
        errors.push(`Route "${name}": signed_url requires "secret_env"`);
      }
    }
  }

  if (errors.length === 0) {
    return;
  }

  if (exitOnError) {
    logger.error('Auth gate validation failed:');
    errors.forEach((e) => logger.error('  -', e));
    process.exit(1);
  }

  const error = new Error('Auth gate validation failed');
  error.validationErrors = errors;
  throw error;
}

function pathPatternsToMarks(pathPatterns) {
  if (!Array.isArray(pathPatterns) || pathPatterns.length === 0) {
    return DEFAULT_MARKS;
  }

  const marks = new Set();
  const knownMap = {
    '(?i)\\.{2}/': ['/../', '..'],
    '(?i)%2e%2e': ['%2e%2e', '%2E%2E'],
  };

  for (const p of pathPatterns) {
    const s = (p || '').trim();
    if (knownMap[s]) {
      knownMap[s].forEach((m) => marks.add(m));
    } else if (s) {
      marks.add(s.replace(/\\(\.)/g, '$1').replace(/\?i\)/g, '').slice(0, 20));
    }
  }

  if (marks.size === 0) {
    return DEFAULT_MARKS;
  }
  return Array.from(marks);
}

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
      gateConfig.credentials = credentials;
    }

    gates.push(gateConfig);
  }

  return gates;
}

function getAdminGate(policy) {
  const gates = getAuthGates(policy);
  const staticTokenGate = gates.find((g) => g.type === 'static_token');

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

function build(policy, options = {}) {
  const rootDir = options.rootDir || repoRoot;
  const outDir = options.outDir || path.join(rootDir, 'dist');

  const defaults = policy.defaults || {};
  const request = policy.request || {};
  const limits = request.limits || {};
  const block = request.block || {};
  const normalize = request.normalize || {};

  const adminGate = getAdminGate(policy);
  const authGates = getAuthGates(policy);

  const dropQueryKeysArray = normalize.drop_query_keys || [
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'gclid', 'fbclid',
  ];
  const blockPathMarks = pathPatternsToMarks(block.path_patterns);
  const pathNormalize = normalize.path || {};
  const requiredHeaders = block.header_missing || ['user-agent'];
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

  const templatePath = path.join(rootDir, 'templates', 'aws', 'viewer-request.js');
  let code = fs.readFileSync(templatePath, 'utf8');
  code = code.replace('// {{INJECT_CONFIG}}', cfgCode);

  const distDir = path.join(outDir, 'edge');
  fs.mkdirSync(distDir, { recursive: true });
  const outPath = path.join(distDir, 'viewer-request.js');
  fs.writeFileSync(outPath, code, 'utf8');

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

  const templateResponsePath = path.join(rootDir, 'templates', 'aws', 'viewer-response.js');
  let codeResponse = fs.readFileSync(templateResponsePath, 'utf8');
  codeResponse = codeResponse.replace('// {{INJECT_RESPONSE_CONFIG}}', responseCfgCode);
  const outPathResponse = path.join(distDir, 'viewer-response.js');
  fs.writeFileSync(outPathResponse, codeResponse, 'utf8');

  const jwtGates = authGates.filter((g) => g.type === 'jwt').map((g) => {
    const route = (policy.routes || []).find((r) => r.name === g.name);
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

  const signedUrlGates = authGates.filter((g) => g.type === 'signed_url').map((g) => {
    const route = (policy.routes || []).find((r) => r.name === g.name);
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

  const templateOriginPath = path.join(rootDir, 'templates', 'aws', 'origin-request.js');
  let codeOrigin = fs.readFileSync(templateOriginPath, 'utf8');
  codeOrigin = codeOrigin.replace('// {{INJECT_CONFIG}}', originCfgCode);
  const outPathOrigin = path.join(distDir, 'origin-request.js');
  fs.writeFileSync(outPathOrigin, codeOrigin, 'utf8');

  return [outPath, outPathResponse, outPathOrigin];
}

function main(argv = process.argv.slice(2)) {
  const { policyPath, outDir } = parseArgs(argv, repoRoot);
  let policy;

  try {
    policy = loadPolicy(policyPath);
  } catch (e) {
    if (e.code === 'ENOENT') {
      console.error('Error: policy file not found:', policyPath);
      process.exit(1);
    }
    console.error('Error: failed to parse policy YAML:', e.message);
    process.exit(1);
  }

  validateAuthGates(policy);

  try {
    const outputs = build(policy, { outDir, rootDir: repoRoot });
    outputs.forEach((outPath) => console.log('Build complete:', outPath));
  } catch (e) {
    if (e.code === 'ENOENT') {
      console.error('Error: template not found:', e.path);
      process.exit(1);
    }
    throw e;
  }
}

module.exports = {
  DEFAULT_MARKS,
  parseArgs,
  loadPolicy,
  validateAuthGates,
  pathPatternsToMarks,
  getAuthGates,
  getAdminGate,
  build,
  main,
};
