const fs = require('fs');
const path = require('path');
const {
  assertInjectedConstDeclarations,
  injectTemplateCode,
  optimizeCloudFrontFunction,
  renderConstObject,
  runtimeCode,
} = require('./template-inject');
const {
  clampNumber,
  normalizeStringList,
  numberOr,
} = require('./value-normalize');
const {
  LIMITS_DEFAULTS,
} = require('./policy-defaults');
const {
  DEFAULT_CONTAINS,
  parsePathPatterns,
  extractRegex,
  compileRegexOrThrow,
  hasCatastrophicBacktrackShape,
  regexesLiteralCode,
  buildAnomalyGuardConfig,
  buildObsConfig,
  buildAuthGateBase,
  buildRequestCfgBase,
  buildResponseCfgBase,
  buildJwksCacheCfg,
  buildJwtGateConfig,
  buildSignedUrlGateConfig,
} = require('./edge-cfg');
const {
  parseArgs: parseArgsIo,
  hasFlag,
  loadPolicy: loadPolicyIo,
  loadPolicyWithWarnings,
  reportPolicyWarnings,
  reportPolicyLoadError,
} = require('./policy-io');
const {
  errorMessage,
  isErrnoException,
  PolicyValidationError,
} = require('./errors') as typeof import('./errors');

const repoRoot = path.join(__dirname, '..', '..');

// Backed by ./policy-io. Kept as a thin wrapper to preserve the
// (rootDir = repoRoot) default that older callers and tests rely on.
function parseArgs(argv: string[], rootDir: string = repoRoot) {
  return parseArgsIo(argv, rootDir);
}

function loadPolicy(policyPath: string) {
  return loadPolicyIo(policyPath);
}

// Reject JWKS URLs that point at loopback, private, link-local, or other
// internal address ranges. An attacker who can influence the JWKS URL at
// build time (via a policy PR) or at runtime (via a regression that lets a
// client seed the cache) could otherwise force the edge to fetch cloud
// metadata endpoints (169.254.169.254) or internal services.
const JWKS_DISALLOWED_HOSTNAMES = new Set([
  'localhost',
  'ip6-localhost',
  'ip6-loopback',
  'broadcasthost',
]);

function isPrivateIPv4Literal(hostname: string) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname);
  if (!m) return false;
  const octets = m.slice(1, 5).map(Number);
  if (octets.some((o) => o < 0 || o > 255)) return false;
  const [a, b] = octets;
  if (a === 10) return true;                             // 10.0.0.0/8
  if (a === 127) return true;                            // loopback
  if (a === 172 && b >= 16 && b <= 31) return true;      // 172.16.0.0/12
  if (a === 192 && b === 168) return true;               // 192.168.0.0/16
  if (a === 169 && b === 254) return true;               // link-local / metadata
  if (a === 100 && b >= 64 && b <= 127) return true;     // CGN 100.64.0.0/10
  if (a === 0) return true;                              // 0.0.0.0/8
  if (a >= 224) return true;                             // multicast / reserved
  return false;
}

function isPrivateIPv6Literal(hostname: string) {
  const h = hostname.startsWith('[') && hostname.endsWith(']')
    ? hostname.slice(1, -1).toLowerCase()
    : hostname.toLowerCase();
  if (!h.includes(':')) return false;
  if (h === '::' || h === '::1') return true;
  if (h.startsWith('fe80:') || h.startsWith('fe80::')) return true;   // link-local
  if (h.startsWith('fc') || h.startsWith('fd')) return true;          // ULA fc00::/7
  // IPv4-mapped IPv6 (::ffff:a.b.c.d). Node's WHATWG URL normalizes the
  // trailing IPv4 to hex (e.g. ::ffff:127.0.0.1 → ::ffff:7f00:1), so we
  // reject the entire `::ffff:` family. Legitimate public IdPs never serve
  // JWKS behind an IPv4-mapped literal — they use a real v4 or v6 address.
  if (h.startsWith('::ffff:')) return true;
  return false;
}

function validateJwksUrl(rawUrl: string, allowedHosts: any) {
  if (typeof rawUrl !== 'string' || rawUrl.trim() === '') {
    return { ok: false, reason: 'jwks_url is empty' };
  }
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { ok: false, reason: `jwks_url is not a valid URL: ${rawUrl}` };
  }
  if (parsed.protocol !== 'https:') {
    return { ok: false, reason: `jwks_url must use https:// (got ${parsed.protocol})` };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, reason: 'jwks_url must not contain userinfo (user:pass@host)' };
  }
  const hostname = (parsed.hostname || '').toLowerCase();
  if (!hostname) {
    return { ok: false, reason: 'jwks_url has empty hostname' };
  }
  if (JWKS_DISALLOWED_HOSTNAMES.has(hostname)) {
    return { ok: false, reason: `jwks_url hostname "${hostname}" is a loopback alias` };
  }
  if (isPrivateIPv4Literal(hostname) || isPrivateIPv6Literal(parsed.hostname)) {
    return { ok: false, reason: `jwks_url hostname "${hostname}" resolves to a private/loopback/link-local range` };
  }
  if (Array.isArray(allowedHosts) && allowedHosts.length > 0) {
    const normalized = normalizeStringList(allowedHosts, 'lower');
    if (!normalized.includes(hostname)) {
      return {
        ok: false,
        reason: `jwks_url hostname "${hostname}" is not in firewall.jwks.allowed_hosts (${normalized.join(', ')})`,
      };
    }
  }
  return { ok: true, hostname };
}

function validateAuthGates(policy: any, options: any = {}) {
  const exitOnError = options.exitOnError !== false;
  const logger = options.logger || console;
  const env = options.env || process.env;
  const allowPlaceholderToken = options.allowPlaceholderToken === true;
  const routes = policy.routes || [];
  const errors: string[] = [];
  const jwksAllowedHosts = ((policy.firewall || {}).jwks || {}).allowed_hosts;
  const normalizedJwksAllowedHosts = normalizeStringList(jwksAllowedHosts, 'lower');
  const requireJwksAllowedHosts = options.requireJwksAllowedHosts === true;

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
      if (alg === 'RS256' && requireJwksAllowedHosts && normalizedJwksAllowedHosts.length === 0) {
        errors.push(`Route "${name}": JWT+RS256 requires firewall.jwks.allowed_hosts for this target`);
      }
      if (gate.jwks_url) {
        const v = validateJwksUrl(gate.jwks_url, jwksAllowedHosts);
        if (!v.ok) {
          errors.push(`Route "${name}": ${v.reason}`);
        }
      }
      if (alg === 'HS256' && !gate.secret_env) {
        errors.push(`Route "${name}": JWT+HS256 requires "secret_env"`);
      }
      // The gate has a single verifier chosen by `gate.algorithm`. Accepting
      // any other alg via `allowed_algorithms` would route those tokens
      // through the wrong verifier and cause a silent auth outage, so fail
      // at build time rather than ship a config that never authenticates.
      if (Array.isArray(gate.allowed_algorithms) && gate.allowed_algorithms.length > 0) {
        const extras = gate.allowed_algorithms.filter(
          (a: any) => typeof a === 'string' && a !== 'none' && a !== alg,
        );
        if (extras.length > 0) {
          errors.push(
            `Route "${name}": auth_gate.allowed_algorithms contains ${JSON.stringify(extras)} ` +
              `but the gate only runs the "${alg}" verifier. Remove the extra algorithm(s) ` +
              `or switch the gate's "algorithm" field.`,
          );
        }
      }
    } else if (authType === 'signed_url') {
      if (!gate.secret_env) {
        errors.push(`Route "${name}": signed_url requires "secret_env"`);
      }
    } else if (authType === 'static_token') {
      const tokenEnv = gate.token_env || 'EDGE_ADMIN_TOKEN';
      const resolved = env[tokenEnv];
      if (!resolved && !allowPlaceholderToken) {
        errors.push(
          `Route "${name}": static_token requires env "${tokenEnv}" at build time. ` +
          'CloudFront Functions cannot read env at runtime, so the token is baked into dist/edge/viewer-request.js. ' +
          'Set the env var, or pass --allow-placeholder-token for non-production builds.',
        );
      }
    } else if (authType === 'basic_auth') {
      const credEnv = gate.credentials_env || 'BASIC_AUTH_CREDS';
      const resolved = env[credEnv];
      if (!resolved && !allowPlaceholderToken) {
        errors.push(
          `Route "${name}": basic_auth requires env "${credEnv}" at build time. ` +
          'Set the env var, or pass --allow-placeholder-token for non-production builds.',
        );
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

  throw new PolicyValidationError('Auth gate validation failed', errors);
}

const PLACEHOLDER_TOKEN = 'INSECURE_PLACEHOLDER__REBUILD_WITH_REAL_TOKEN';

function getAuthGates(policy: any, options: any = {}) {
  const env = options.env || process.env;
  const allowPlaceholderToken = options.allowPlaceholderToken === true;
  const routes = policy.routes || [];
  const gates: any[] = [];

  for (const route of routes) {
    const gate = route.auth_gate;
    if (!gate) continue;

    const authType = gate.type || 'static_token';
    const gateConfig: any = buildAuthGateBase(route);

    if (authType === 'static_token') {
      // CloudFront Functions only expose header keys in lowercase form, so
      // force the configured name to lowercase to avoid a silent mismatch
      // (e.g. policy says `X-Edge-Token`, runtime lookup `req.headers[...]`
      // returns undefined and every authenticated call fails).
      const header = (gate.header || 'x-edge-token').toLowerCase();
      const tokenEnv = gate.token_env || 'EDGE_ADMIN_TOKEN';
      const resolved = env[tokenEnv];
      const token = resolved != null && resolved !== ''
        ? resolved
        : (allowPlaceholderToken ? PLACEHOLDER_TOKEN : null);
      if (token === null) {
        throw new Error(`static_token for route "${gateConfig.name}" requires env ${tokenEnv}`);
      }
      gateConfig.tokenHeaderName = header;
      gateConfig.tokenEnv = tokenEnv;
      gateConfig.token = token;
      gateConfig.tokenIsPlaceholder = token === PLACEHOLDER_TOKEN;
    } else if (authType === 'basic_auth') {
      const credEnv = gate.credentials_env || 'BASIC_AUTH_CREDS';
      const resolved = env[credEnv];
      const credentials = resolved != null && resolved !== ''
        ? resolved
        : (allowPlaceholderToken ? PLACEHOLDER_TOKEN : null);
      if (credentials === null) {
        throw new Error(`basic_auth for route "${gateConfig.name}" requires env ${credEnv}`);
      }
      gateConfig.credentialsEnv = credEnv;
      gateConfig.credentials = credentials;
      gateConfig.credentialsIsPlaceholder = credentials === PLACEHOLDER_TOKEN;
    }

    gates.push(gateConfig);
  }

  return gates;
}

function hasAllowPlaceholderFlag(argv: string[]) {
  return hasFlag(argv, '--allow-placeholder-token');
}

function hasFailOnPermissiveFlag(argv: string[]) {
  return hasFlag(argv, '--fail-on-permissive');
}

function hasStrictOriginAuthFlag(argv: string[]) {
  return hasFlag(argv, '--strict-origin-auth');
}

// Verify that origin.auth secrets and runtime-shaping options are usable before
// emitting code. Called with { strict: true } under --strict-origin-auth and as
// a warning otherwise, so dev builds keep working while CI can fail closed.
function validateOriginAuth(policy: any, options: any = {}) {
  const env = options.env || process.env;
  const strict = options.strict === true;
  const logger = options.logger || console;

  const auth = policy && policy.origin && policy.origin.auth;
  if (!auth || !['custom_header', 'hmac_signature'].includes(auth.type)) return { warnings: [], errors: [] };

  const warnings: string[] = [];
  const errors: string[] = [];
  const envName = auth.secret_env || '';
  if (!envName) {
    errors.push(`origin.auth.secret_env is required when type=${auth.type}`);
  } else {
    const v = env[envName];
    if (v === undefined) {
      (strict ? errors : warnings).push(
        `origin.auth.secret_env "${envName}" is not set in the build environment. Origin will see an empty auth header at runtime unless the env is populated.`
      );
    } else if (v.length === 0) {
      (strict ? errors : warnings).push(
        `origin.auth.secret_env "${envName}" is set but empty. The edge will refuse to forward the origin-auth header, breaking origin trust.`
      );
    }
  }

  if (auth.type === 'custom_header' && (!auth.header || typeof auth.header !== 'string')) {
    errors.push('origin.auth.header is required when type=custom_header');
  }

  if (auth.type === 'hmac_signature') {
    const prefix = auth.header_prefix || 'X-CDN-Auth';
    if (typeof prefix !== 'string' || !/^[A-Za-z][A-Za-z0-9-]*$/.test(prefix)) {
      errors.push('origin.auth.header_prefix must match ^[A-Za-z][A-Za-z0-9-]*$ when type=hmac_signature');
    }
    const tolerance = auth.timestamp_tolerance_seconds == null ? 300 : Number(auth.timestamp_tolerance_seconds);
    if (!Number.isInteger(tolerance) || tolerance < 1 || tolerance > 3600) {
      errors.push('origin.auth.timestamp_tolerance_seconds must be an integer from 1 to 3600 when type=hmac_signature');
    }
    if (auth.signed_components != null) {
      const allowed = new Set(['method', 'path', 'query', 'body', 'timestamp', 'nonce']);
      const components = Array.isArray(auth.signed_components) ? auth.signed_components : [];
      if (components.length === 0 || components.some((c: any) => !allowed.has(c))) {
        errors.push('origin.auth.signed_components must contain one or more of method, path, query, body, timestamp, nonce');
      }
      if (!components.includes('timestamp') || !components.includes('nonce')) {
        errors.push('origin.auth.signed_components must include timestamp and nonce when type=hmac_signature');
      }
    }
  }

  warnings.forEach((w) => logger.warn('[origin-auth] ' + w));
  if (errors.length > 0 && strict) {
    logger.error('origin-auth validation failed (--strict-origin-auth):');
    errors.forEach((e) => logger.error('  - ' + e));
    throw new PolicyValidationError('origin-auth validation failed', errors);
  }
  return { warnings, errors };
}

// Heuristic: paths that usually mutate state and therefore deserve replay
// protection rather than just an expiry window. Matching is permissive (any
// prefix that contains one of these substrings) because write patterns vary
// by application convention.
const SIGNED_URL_WRITE_PATH_HINTS = ['/api/', '/write', '/admin', '/upload', '/delete'];

function warnSignedUrlReplay(policy: any, options: any = {}) {
  const logger = options.logger || console;
  const routes = policy.routes || [];
  const warnings: string[] = [];
  for (const route of routes) {
    const gate = route.auth_gate;
    if (!gate || gate.type !== 'signed_url') continue;
    if (gate.nonce_param && typeof gate.nonce_param === 'string' && gate.nonce_param.trim()) continue;
    const match = route.match || {};
    const prefixes = match.path_prefixes || [];
    const writeLike = prefixes.find((p: string) =>
      SIGNED_URL_WRITE_PATH_HINTS.some((hint) => p.toLowerCase().includes(hint)),
    );
    if (writeLike) {
      warnings.push(
        `Route "${route.name || 'unnamed'}": signed_url protects ${JSON.stringify(writeLike)} but has no "nonce_param". ` +
          'URLs are replayable within the expiry window — add nonce_param and enforce single-use at origin. See docs/signed-urls.md.',
      );
    }
  }
  if (warnings.length === 0) return { warned: false, warnings };
  for (const w of warnings) logger.error('[WARN] ' + w);
  return { warned: true, warnings };
}

function warnIfPermissive(policy: any, options: any = {}) {
  const failOnPermissive = options.failOnPermissive === true;
  const logger = options.logger || console;
  const risk = policy && policy.metadata && policy.metadata.risk_level;
  if (risk !== 'permissive') {
    return { warned: false, failed: false };
  }
  const msg =
    '[WARN] metadata.risk_level is "permissive" — this profile is intentionally loose and NOT recommended for production. ' +
    'See docs/profiles.md. Pass --fail-on-permissive in CI to hard-fail.';
  logger.error(msg);
  if (failOnPermissive) {
    logger.error('[ERROR] --fail-on-permissive set; refusing to build a permissive policy.');
    return { warned: true, failed: true };
  }
  return { warned: true, failed: false };
}

function warnWeakAwsCspNonce(policy: any, options: any = {}) {
  const logger = options.logger || console;
  const resHeaders = (policy && policy.response_headers) || {};
  if (resHeaders.csp_nonce !== true) {
    return { warned: false, failed: false };
  }
  const msg =
    '[ERROR] response_headers.csp_nonce is enabled for the AWS CloudFront Functions target. ' +
    'CloudFront Functions do not expose a cryptographic RNG, so Math.random cannot provide a secure CSP nonce. ' +
    'Use Cloudflare Workers, disable csp_nonce on AWS, or let the origin manage nonces.';
  logger.error(msg);
  return { warned: true, failed: true, warnings: [msg] };
}

function warnUnsupportedAwsResponseDlp(policy: any, options: any = {}) {
  const logger = options.logger || console;
  if (!policy || !policy.response_dlp || policy.response_dlp.enabled !== true) {
    return { warned: false, warnings: [] };
  }
  const msg =
    '[WARN] response_dlp is enabled but AWS CloudFront Functions cannot inspect response bodies. ' +
    'The AWS target does not enforce response DLP masking/blocking; use the Cloudflare Workers target for body/header response DLP or enforce DLP at the origin/Lambda@Edge.';
  logger.error(msg);
  return { warned: true, warnings: [msg] };
}

function buildChallengeConfig(policy: any) {
  const raw = policy && policy.firewall && policy.firewall.challenge;
  if (!raw || raw.enabled !== true) return null;

  const pathPrefixes = normalizeStringList(raw.path_prefixes);
  const uaContains = normalizeStringList(raw.ua_contains, 'lower');

  return {
    enabled: true,
    mode: raw.mode === 'report' || raw.mode === 'block' || raw.mode === 'challenge' ? raw.mode : 'challenge',
    pathPrefixes,
    uaContains,
    difficulty: clampNumber(raw.difficulty, 1, 4, 3),
    ttlSec: clampNumber(raw.ttl_sec, 60, 86400, 900),
    secretEnv: typeof raw.secret_env === 'string' && raw.secret_env.trim()
      ? raw.secret_env.trim()
      : 'CHALLENGE_SECRET',
    cookieName: typeof raw.cookie_name === 'string' && raw.cookie_name.trim()
      ? raw.cookie_name.trim()
      : '__cdn_challenge',
  };
}

function warnUnsupportedAwsChallenge(policy: any, options: any = {}) {
  const logger = options.logger || console;
  const challenge = buildChallengeConfig(policy);
  if (!challenge) return { warned: false, warnings: [] };

  const msg =
    '[WARN] firewall.challenge is enabled but the AWS / CloudFront targets do not support the experimental JS challenge primitive. ' +
    'CloudFront Functions cannot reliably serve and verify the HTML proof-of-work flow in this framework; use --target cloudflare or disable firewall.challenge for AWS builds.';
  logger.error(msg);
  return { warned: true, warnings: [msg] };
}

function buildGraphqlGuardConfig(policy: any) {
  const guard = policy && policy.request && policy.request.graphql_guard;
  if (!guard || typeof guard !== 'object') return null;

  const endpointPaths = Array.isArray(guard.endpoint_paths)
    ? normalizeStringList(guard.endpoint_paths)
    : ['/graphql'];

  return {
    endpointPaths: endpointPaths.length > 0 ? endpointPaths : ['/graphql'],
    maxDepth: clampNumber(guard.max_depth, 1, 64, 10),
    maxAliases: clampNumber(guard.max_aliases, 0, 10000, 20),
    maxFields: clampNumber(guard.max_fields, 1, 50000, 200),
    maxBodyBytes: clampNumber(guard.max_body_bytes, 1, 1048576, 65536),
    mode: guard.mode === 'report' ? 'report' : 'block',
  };
}

function warnUnsupportedGraphqlGuard(policy: any, target: string, options: any = {}) {
  const logger = options.logger || console;
  const guard = buildGraphqlGuardConfig(policy);
  if (!guard || target === 'cloudflare') return { warned: false, warnings: [] };

  const msg =
    `[WARN] request.graphql_guard is configured but target "${target}" cannot read request bodies at the edge. ` +
    'GraphQL depth/complexity enforcement is unsupported for CloudFront Functions/Lambda@Edge output; ' +
    'use the Cloudflare Workers target or enforce this guard at the origin.';
  logger.error(msg);
  return { warned: true, warnings: [msg] };
}

function build(policy: any, options: any = {}) {
  const rootDir = options.rootDir || repoRoot;
  const outDir = options.outDir || path.join(rootDir, 'dist');
  const env = options.env || process.env;
  const allowPlaceholderToken = options.allowPlaceholderToken === true;

  const authGates = getAuthGates(policy, { env, allowPlaceholderToken });
  const requestBase = buildRequestCfgBase(policy);

  const cfgCode = renderConstObject('CFG', {
    mode: requestBase.mode,
    allowMethods: requestBase.allowMethods,
    maxQueryLength: requestBase.maxQueryLength,
    maxQueryParams: requestBase.maxQueryParams,
    maxUriLength: requestBase.maxUriLength,
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
    anomalyGuards: requestBase.anomalyGuards,
    obs: requestBase.obs,
  });

  const templatePath = path.join(rootDir, 'templates', 'aws', 'viewer-request.js');
  let code = fs.readFileSync(templatePath, 'utf8');
  code = injectTemplateCode(code, '// {{INJECT_CONFIG}}', cfgCode);
  code = injectTemplateCode(code, '/* {{FEATURE_CORS}} */ true', String(Boolean(requestBase.cors)));
  code = injectTemplateCode(code, '/* {{FEATURE_HOST_ALLOWLIST}} */ true', String(requestBase.allowedHosts.length > 0));
  code = injectTemplateCode(
    code,
    '/* {{FEATURE_VIEWER_AUTH}} */ true',
    String(authGates.some((gate) => gate.type === 'static_token' || gate.type === 'basic_auth')),
  );
  code = injectTemplateCode(
    code,
    '/* {{FEATURE_ALLOW_SAMPLING}} */ true',
    String(requestBase.obs.sampleRate > 0),
  );
  assertInjectedConstDeclarations(code, ['CFG']);

  const distDir = path.join(outDir, 'edge');
  fs.mkdirSync(distDir, { recursive: true });
  const outPath = path.join(distDir, 'viewer-request.js');
  fs.writeFileSync(outPath, code, 'utf8');

  const responseBase = buildResponseCfgBase(policy, authGates);
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
  });

  const templateResponsePath = path.join(rootDir, 'templates', 'aws', 'viewer-response.js');
  let codeResponse = fs.readFileSync(templateResponsePath, 'utf8');
  codeResponse = injectTemplateCode(codeResponse, '// {{INJECT_RESPONSE_CONFIG}}', responseCfgCode);
  assertInjectedConstDeclarations(codeResponse, ['RESPONSE_CFG']);
  const outPathResponse = path.join(distDir, 'viewer-response.js');
  fs.writeFileSync(outPathResponse, codeResponse, 'utf8');

  const jwtGates = authGates.filter((g) => g.type === 'jwt').map((g) => {
    const route = (policy.routes || []).find((r: any) => r.name === g.name);
    const gate = route?.auth_gate || {};
    const compiled = buildJwtGateConfig(gate, g);
    return {
      ...compiled,
      // Lambda@Edge does not support custom environment variables. Secrets
      // therefore become deployment credentials and must be rebuilt/rotated
      // with the function artifact.
      secret: gate.secret_env ? (env[gate.secret_env] || '') : '',
    };
  });

  const signedUrlGates = authGates.filter((g) => g.type === 'signed_url').map((g) => {
    const route = (policy.routes || []).find((r: any) => r.name === g.name);
    const gate = route?.auth_gate || {};
    const compiled = buildSignedUrlGateConfig(gate, g);
    return { ...compiled, secret: gate.secret_env ? (env[gate.secret_env] || '') : '' };
  });

  const rawOriginAuth = (policy.origin || {}).auth || null;
  const originAuth = rawOriginAuth
    ? { ...rawOriginAuth, secret: rawOriginAuth.secret_env ? (env[rawOriginAuth.secret_env] || '') : '' }
    : null;
  const jwksCache = buildJwksCacheCfg(policy);
  const defaults = policy.defaults || {};
  const limits = (policy.request || {}).limits || {};
  const trustForwardedFor = requestBase.trustForwardedFor;

  const originCfgCode = renderConstObject('CFG', {
    project: policy.project || 'cdn-security',
    mode: defaults.mode || 'enforce',
    maxHeaderSize: numberOr(limits.max_header_size, LIMITS_DEFAULTS.maxHeaderSize),
    trustForwardedFor,
    jwtGates,
    signedUrlGates,
    originAuth,
    jwksStaleIfErrorSec: jwksCache.staleIfErrorSec,
    jwksNegativeCacheSec: jwksCache.negativeCacheSec,
    obs: requestBase.obs,
  });

  const templateOriginPath = path.join(rootDir, 'templates', 'aws', 'origin-request.js');
  let codeOrigin = fs.readFileSync(templateOriginPath, 'utf8');
  codeOrigin = injectTemplateCode(codeOrigin, '// {{INJECT_CONFIG}}', originCfgCode);
  assertInjectedConstDeclarations(codeOrigin, ['CFG']);
  const outPathOrigin = path.join(distDir, 'origin-request.js');
  fs.writeFileSync(outPathOrigin, codeOrigin, 'utf8');

  return [outPath, outPathResponse, outPathOrigin];
}

function main(argv: string[] = process.argv.slice(2)) {
  const { policyPath, outDir } = parseArgs(argv, repoRoot);
  const allowPlaceholderToken = hasAllowPlaceholderFlag(argv);
  const failOnPermissive = hasFailOnPermissiveFlag(argv);
  const strictOriginAuth = hasStrictOriginAuthFlag(argv);
  let policy;
  let policyWarnings: string[] = [];

  try {
    const parsed = loadPolicyWithWarnings(policyPath);
    policy = parsed.policy;
    policyWarnings = parsed.warnings;
  } catch (e: unknown) {
    reportPolicyLoadError(policyPath, e);
    process.exit(1);
  }
  reportPolicyWarnings(policyWarnings);

  // Surface permissive-profile warning before wasting build time.
  const permissive = warnIfPermissive(policy, { failOnPermissive });
  if (permissive.failed) {
    process.exit(1);
  }

  // Non-fatal advisory: signed_url protecting write-like paths without nonce_param.
  warnSignedUrlReplay(policy);
  const awsCspNonce = warnWeakAwsCspNonce(policy);
  if (awsCspNonce.failed) process.exit(1);
  warnUnsupportedAwsResponseDlp(policy);
  warnUnsupportedAwsChallenge(policy);
  warnUnsupportedGraphqlGuard(policy, 'aws');

  validateAuthGates(policy, { allowPlaceholderToken });

  try {
    validateOriginAuth(policy, { strict: strictOriginAuth });
  } catch (_e: unknown) {
    process.exit(1);
  }

  try {
    const outputs = build(policy, { outDir, rootDir: repoRoot, allowPlaceholderToken });
    for (const outPath of outputs.slice(0, 2)) {
      const source = fs.readFileSync(outPath, 'utf8');
      fs.writeFileSync(outPath, optimizeCloudFrontFunction(source, path.basename(outPath)), 'utf8');
    }
    outputs.forEach((outPath) => console.log('Build complete:', outPath));
    // Advertise placeholder usage loudly so humans notice in CI output.
    if (allowPlaceholderToken) {
      console.error('[WARN] Built with --allow-placeholder-token. Generated artifacts are NOT safe for production.');
    }
  } catch (e: unknown) {
    if (isErrnoException(e) && e.code === 'ENOENT') {
      console.error('Error: template not found:', e.path);
      process.exit(1);
    }
    console.error('Error:', errorMessage(e));
    process.exit(1);
  }
}

module.exports = {
  DEFAULT_CONTAINS,
  parseArgs,
  loadPolicy,
  validateAuthGates,
  parsePathPatterns,
  extractRegex,
  compileRegexOrThrow,
  hasCatastrophicBacktrackShape,
  regexesLiteralCode,
  getAuthGates,
  buildObsConfig,
  hasAllowPlaceholderFlag,
  hasFailOnPermissiveFlag,
  hasStrictOriginAuthFlag,
  validateOriginAuth,
  warnIfPermissive,
  warnWeakAwsCspNonce,
  warnUnsupportedAwsResponseDlp,
  warnSignedUrlReplay,
  buildChallengeConfig,
  warnUnsupportedAwsChallenge,
  buildGraphqlGuardConfig,
  buildAnomalyGuardConfig,
  warnUnsupportedGraphqlGuard,
  validateJwksUrl,
  build,
  optimizeCloudFrontFunction,
  main,
  PLACEHOLDER_TOKEN,
};
