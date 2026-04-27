const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const repoRoot = path.join(__dirname, '..', '..');
const DEFAULT_CONTAINS = ['/../', '%2e%2e', '%2f..', '..%2f', '%5c'];

const LEGACY_KNOWN_MAP = {
  '(?i)\\.{2}/': { contains: ['/../', '..'] },
  '(?i)%2e%2e': { contains: ['%2e%2e'] },
} as Record<string, { contains?: string[]; regex?: string[] }>;

function parseArgs(argv: string[], rootDir = repoRoot) {
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

function loadPolicy(policyPath: string) {
  const content = fs.readFileSync(policyPath, 'utf8');
  return yaml.load(content);
}

function extractRegex(source: string) {
  // Convert `(?i)...` to { pattern: '...', flags: 'i' }; else use the source as pattern.
  if (typeof source !== 'string') {
    throw new Error('Regex source must be a string');
  }
  const trimmed = source.trim();
  if (!trimmed) {
    throw new Error('Regex source must be non-empty');
  }
  if (trimmed.startsWith('(?i)')) {
    return { pattern: trimmed.slice(4), flags: 'i' };
  }
  return { pattern: trimmed, flags: '' };
}

function compileRegexOrThrow(source: string, context: string) {
  const { pattern, flags } = extractRegex(source);
  try {
    return new RegExp(pattern, flags);
  } catch (e: any) {
    throw new Error(`Invalid regex in ${context}: ${source} — ${e.message}`);
  }
}

// Catch the classic `(a+)+` / `([^x]+)*` / `(a|a)+` family: a group that itself
// carries a quantifier metacharacter inside, followed by an outer quantifier.
// Over-approximate on purpose — no legitimate path_patterns regex in this
// project needs stacked quantifiers, so false positives cost us nothing while
// false negatives would ship a runtime DoS to the edge. Paired with the
// runtime timeout fuzz in scripts/regex-fuzz-tests.js for defense in depth.
function hasCatastrophicBacktrackShape(src: string) {
  if (typeof src !== 'string' || src.length === 0) return false;
  // Strip the optional `(?i)` etc. inline-flag prefix so the heuristic sees
  // the same pattern body the engine will.
  const body = src.replace(/^\(\?[ims]+\)/, '');
  const nested = /\(([^()]*[+*?{][^()]*)\)[+*?{]/;
  return nested.test(body);
}

function looksLikeRegex(s: string) {
  // Heuristic: presence of common regex metacharacters suggests a regex intent.
  return /[\\(){}\[\]|^$+?*]|\.\{|\\\\/.test(s);
}

function parsePathPatterns(pathPatterns: any) {
  // Returns { contains: string[], regexSources: string[] } with strict validation.
  if (pathPatterns === undefined || pathPatterns === null) {
    return { contains: DEFAULT_CONTAINS.slice(), regexSources: [] };
  }

  if (Array.isArray(pathPatterns)) {
    // Legacy shape: list of strings. Each item is either a known regex literal
    // (expanded via LEGACY_KNOWN_MAP) or a plain substring (treated as contains).
    // Anything that looks like an unknown regex is rejected to avoid silent
    // downgrade to substring semantics.
    const contains = new Set<string>();
    const regexSources: string[] = [];
    for (const raw of pathPatterns) {
      const s = (raw || '').trim();
      if (!s) continue;
      const mapped = LEGACY_KNOWN_MAP[s];
      if (mapped) {
        // Runtime lowercases the URI before `includes()`, so contains entries
        // must also be lowercase or they never match.
        if (mapped.contains) mapped.contains.forEach((m: string) => contains.add(m.toLowerCase()));
        if (mapped.regex) mapped.regex.forEach((m: string) => regexSources.push(m));
        continue;
      }
      if (looksLikeRegex(s)) {
        throw new Error(
          `Ambiguous path_patterns entry: "${s}". ` +
          'Move regex-style patterns under `path_patterns.regex: [...]` or ' +
          'literal substrings under `path_patterns.contains: [...]`.',
        );
      }
      contains.add(s.toLowerCase());
    }
    if (contains.size === 0 && regexSources.length === 0) {
      return { contains: DEFAULT_CONTAINS.slice(), regexSources: [] };
    }
    return { contains: Array.from(contains), regexSources };
  }

  if (typeof pathPatterns === 'object') {
    const rawContains = Array.isArray(pathPatterns.contains) ? pathPatterns.contains.filter(Boolean) : [];
    const regexSources = Array.isArray(pathPatterns.regex) ? pathPatterns.regex.filter(Boolean) : [];
    // Reject regex-looking entries under `contains` to prevent silent downgrade
    // where a user accidentally puts a regex literal under `contains` and it
    // becomes a substring match that never fires.
    const contains: string[] = [];
    for (const raw of rawContains) {
      const s = typeof raw === 'string' ? raw.trim() : '';
      if (!s) continue;
      if (looksLikeRegex(s)) {
        throw new Error(
          `Ambiguous path_patterns.contains entry: "${s}". ` +
          'This looks like a regex. Move it under `path_patterns.regex: [...]`, ' +
          'or escape the metacharacters if you genuinely want a literal substring.',
        );
      }
      // Runtime lowercases the URI before `includes()`, so contains entries
      // must also be lowercase or they never match. Normalize at build time.
      contains.push(s.toLowerCase());
    }
    // Validate each regex compiles successfully at build time and reject the
    // classic nested-quantifier shape `(a+)+` family that triggers catastrophic
    // backtracking at runtime (effectively a DoS on the edge).
    for (const src of regexSources) {
      compileRegexOrThrow(src, 'request.block.path_patterns.regex');
      if (hasCatastrophicBacktrackShape(src)) {
        throw new Error(
          `request.block.path_patterns.regex: pattern rejected by ReDoS safety check ` +
          `(nested-quantifier shape triggers catastrophic backtracking): ${JSON.stringify(src)}. ` +
          `Rewrite without stacking quantifiers — for example, use a character class like ` +
          `[a-z]+ instead of (a+)+.`
        );
      }
    }
    if (contains.length === 0 && regexSources.length === 0) {
      return { contains: DEFAULT_CONTAINS.slice(), regexSources: [] };
    }
    return { contains, regexSources };
  }

  throw new Error('request.block.path_patterns must be an array or an object with contains/regex');
}

function regexesLiteralCode(regexSources: string[]) {
  // Emit real RegExp literals in generated JS so runtime avoids `new RegExp` at request time.
  if (regexSources.length === 0) return '[]';
  const literals = regexSources.map((src: string) => {
    const re = compileRegexOrThrow(src, 'request.block.path_patterns.regex');
    return re.toString();
  });
  return '[' + literals.join(', ') + ']';
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
    const normalized = allowedHosts
      .map((h) => (typeof h === 'string' ? h.trim().toLowerCase() : ''))
      .filter(Boolean);
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

  const error: any = new Error('Auth gate validation failed');
  error.validationErrors = errors;
  throw error;
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

    const match = route.match || {};
    const prefixes = match.path_prefixes || [];
    const authType = gate.type || 'static_token';

    const gateConfig: any = {
      name: route.name || 'unnamed',
      protectedPrefixes: prefixes.length ? prefixes : ['/admin', '/docs', '/swagger'],
      type: authType,
    };

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
  return Array.isArray(argv) && argv.includes('--allow-placeholder-token');
}

function hasFailOnPermissiveFlag(argv: string[]) {
  return Array.isArray(argv) && argv.includes('--fail-on-permissive');
}

function hasStrictOriginAuthFlag(argv: string[]) {
  return Array.isArray(argv) && argv.includes('--strict-origin-auth');
}

// Verify that when origin.auth.type=custom_header is configured, the env var
// named by `secret_env` is present and non-empty in the build environment.
// Called with { strict: true } under --strict-origin-auth and as a warning
// otherwise, so dev builds keep working while CI can fail closed.
function validateOriginAuth(policy: any, options: any = {}) {
  const env = options.env || process.env;
  const strict = options.strict === true;
  const logger = options.logger || console;

  const auth = policy && policy.origin && policy.origin.auth;
  if (!auth || auth.type !== 'custom_header') return { warnings: [], errors: [] };

  const warnings: string[] = [];
  const errors: string[] = [];
  const envName = auth.secret_env || '';
  if (!envName) {
    errors.push('origin.auth.secret_env is required when type=custom_header');
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

  warnings.forEach((w) => logger.warn('[origin-auth] ' + w));
  if (errors.length > 0 && strict) {
    logger.error('origin-auth validation failed (--strict-origin-auth):');
    errors.forEach((e) => logger.error('  - ' + e));
    const err: any = new Error('origin-auth validation failed');
    err.validationErrors = errors;
    throw err;
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

// Normalize observability config for injection into edge CFG objects.
// Kept next to the compiler so every target (CFF / Lambda@Edge / Worker)
// sees identical defaults and casing.
function buildObsConfig(policy: any) {
  const obs = (policy && policy.observability) || {};
  const format = obs.log_format === 'text' ? 'text' : 'json';
  const correlationHeader = typeof obs.correlation_id_header === 'string' && obs.correlation_id_header.trim()
    ? obs.correlation_id_header.trim().toLowerCase()
    : '';
  let sampleRate = Number(obs.sample_rate);
  if (!Number.isFinite(sampleRate) || sampleRate < 0) sampleRate = 0;
  if (sampleRate > 1) sampleRate = 1;
  return {
    logFormat: format,
    correlationHeader,
    sampleRate,
    auditLogAuth: obs.audit_log_auth === true,
    auditHashSub: obs.audit_hash_sub === true,
  };
}

function build(policy: any, options: any = {}) {
  const rootDir = options.rootDir || repoRoot;
  const outDir = options.outDir || path.join(rootDir, 'dist');
  const env = options.env || process.env;
  const allowPlaceholderToken = options.allowPlaceholderToken === true;

  const defaults = policy.defaults || {};
  const request = policy.request || {};
  const limits = request.limits || {};
  const block = request.block || {};
  const normalize = request.normalize || {};

  const authGates = getAuthGates(policy, { env, allowPlaceholderToken });

  const dropQueryKeysArray = normalize.drop_query_keys || [
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'gclid', 'fbclid',
  ];
  const { contains: blockPathContains, regexSources: blockPathRegexSources } = parsePathPatterns(block.path_patterns);
  const pathNormalize = normalize.path || {};
  const requiredHeaders = block.header_missing || ['user-agent'];
  const corsConfig = (policy.response_headers || {}).cors || null;
  // Host allowlist: lowercase entries so we can compare against the lowercase
  // Host header value without per-request normalization.
  const rawAllowedHosts = Array.isArray(request.allowed_hosts) ? request.allowed_hosts : [];
  const allowedHosts = rawAllowedHosts
    .map((h: any) => (typeof h === 'string' ? h.trim().toLowerCase() : ''))
    .filter(Boolean);
  const trustForwardedFor = request.trust_forwarded_for === true;

  const obsCfg = buildObsConfig(policy);

  const cfgCode = [
    'const CFG = {',
    `  mode: ${JSON.stringify(defaults.mode || 'enforce')},`,
    `  allowMethods: ${JSON.stringify(request.allow_methods || ['GET', 'HEAD', 'POST'])},`,
    `  maxQueryLength: ${Number(limits.max_query_length) || 1024},`,
    `  maxQueryParams: ${Number(limits.max_query_params) || 30},`,
    `  maxUriLength: ${Number(limits.max_uri_length) || 2048},`,
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
    `  obs: ${JSON.stringify(obsCfg)},`,
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

  // Union of every auth-gate protected prefix — used to force no-store +
  // Vary: Authorization regardless of which gate type applies. Issue #8.
  const authProtectedPrefixes = Array.from(new Set(
    (authGates || []).flatMap((g) => Array.isArray(g.protectedPrefixes) ? g.protectedPrefixes : []),
  ));
  const forceVaryAuth = resHeaders.force_vary_auth !== false; // default on

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
    `  authProtectedPrefixes: ${JSON.stringify(authProtectedPrefixes)},`,
    `  forceVaryAuth: ${forceVaryAuth ? 'true' : 'false'},`,
    `  clearSiteDataPaths: ${JSON.stringify(
      Array.isArray(resHeaders.clear_site_data_paths)
        ? resHeaders.clear_site_data_paths.filter((s: any) => typeof s === 'string' && s.trim())
        : []
    )},`,
    `  clearSiteDataTypes: ${JSON.stringify(
      Array.isArray(resHeaders.clear_site_data_types) && resHeaders.clear_site_data_types.length > 0
        ? resHeaders.clear_site_data_types
        : ['cache', 'cookies', 'storage']
    )},`,
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
    const route = (policy.routes || []).find((r: any) => r.name === g.name);
    const gate = route?.auth_gate || {};
    const algorithm = gate.algorithm || 'RS256';
    // Runtime has only one verifier per gate (RS256 or HS256), so the emitted
    // whitelist can only ever contain that algorithm. `allowed_algorithms` is
    // honored for its intersection with `algorithm` (filtering `none`/unknown
    // values out at runtime too), but cross-alg entries are rejected at build
    // time in `validateAuthGates` to avoid a silent auth outage.
    const userAllowed = Array.isArray(gate.allowed_algorithms) && gate.allowed_algorithms.length > 0
      ? gate.allowed_algorithms.filter((a: any) => typeof a === 'string' && a !== 'none' && a === algorithm)
      : null;
    const allowedAlgorithms = userAllowed && userAllowed.length > 0 ? userAllowed : [algorithm];
    const clockSkewSec = Number.isFinite(Number(gate.clock_skew_sec))
      ? Math.max(0, Math.min(600, Number(gate.clock_skew_sec)))
      : 30;
    return {
      name: g.name,
      protectedPrefixes: g.protectedPrefixes,
      type: 'jwt',
      algorithm,
      allowed_algorithms: allowedAlgorithms,
      clock_skew_sec: clockSkewSec,
      jwks_url: gate.jwks_url || '',
      issuer: gate.issuer || '',
      audience: gate.audience || '',
      secret_env: gate.secret_env || '',
    };
  });

  const signedUrlGates = authGates.filter((g) => g.type === 'signed_url').map((g) => {
    const route = (policy.routes || []).find((r: any) => r.name === g.name);
    const gate = route?.auth_gate || {};
    return {
      name: g.name,
      protectedPrefixes: g.protectedPrefixes,
      type: 'signed_url',
      algorithm: gate.algorithm || 'HMAC-SHA256',
      secret_env: gate.secret_env || 'URL_SIGNING_SECRET',
      expires_param: gate.expires_param || 'exp',
      signature_param: gate.signature_param || 'sig',
      exact_path: gate.exact_path === true,
      nonce_param: typeof gate.nonce_param === 'string' && gate.nonce_param.trim()
        ? gate.nonce_param.trim()
        : '',
    };
  });

  const originAuth = (policy.origin || {}).auth || null;
  const jwksGlobal = (policy.firewall || {}).jwks || {};
  const jwksStaleIfError = Number.isFinite(Number(jwksGlobal.stale_if_error_sec))
    ? Math.max(0, Math.min(86400, Number(jwksGlobal.stale_if_error_sec)))
    : 3600;
  const jwksNegativeCache = Number.isFinite(Number(jwksGlobal.negative_cache_sec))
    ? Math.max(0, Math.min(600, Number(jwksGlobal.negative_cache_sec)))
    : 60;

  const obsCfgOrigin = buildObsConfig(policy);

  const originCfgCode = [
    'const CFG = {',
    `  project: ${JSON.stringify(policy.project || 'cdn-security')},`,
    `  mode: ${JSON.stringify(defaults.mode || 'enforce')},`,
    `  maxHeaderSize: ${Number(limits.max_header_size) || 0},`,
    `  trustForwardedFor: ${trustForwardedFor ? 'true' : 'false'},`,
    `  jwtGates: ${JSON.stringify(jwtGates)},`,
    `  signedUrlGates: ${JSON.stringify(signedUrlGates)},`,
    `  originAuth: ${JSON.stringify(originAuth)},`,
    `  jwksStaleIfErrorSec: ${jwksStaleIfError},`,
    `  jwksNegativeCacheSec: ${jwksNegativeCache},`,
    `  obs: ${JSON.stringify(obsCfgOrigin)},`,
    '};',
  ].join('\n');

  const templateOriginPath = path.join(rootDir, 'templates', 'aws', 'origin-request.js');
  let codeOrigin = fs.readFileSync(templateOriginPath, 'utf8');
  codeOrigin = codeOrigin.replace('// {{INJECT_CONFIG}}', originCfgCode);
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

  try {
    policy = loadPolicy(policyPath);
  } catch (e: any) {
    if (e.code === 'ENOENT') {
      console.error('Error: policy file not found:', policyPath);
      process.exit(1);
    }
    console.error('Error: failed to parse policy YAML:', e.message);
    process.exit(1);
  }

  // Surface permissive-profile warning before wasting build time.
  const permissive = warnIfPermissive(policy, { failOnPermissive });
  if (permissive.failed) {
    process.exit(1);
  }

  // Non-fatal advisory: signed_url protecting write-like paths without nonce_param.
  warnSignedUrlReplay(policy);

  validateAuthGates(policy, { allowPlaceholderToken });

  try {
    validateOriginAuth(policy, { strict: strictOriginAuth });
  } catch (e: any) {
    process.exit(1);
  }

  try {
    const outputs = build(policy, { outDir, rootDir: repoRoot, allowPlaceholderToken });
    outputs.forEach((outPath) => console.log('Build complete:', outPath));
    // Advertise placeholder usage loudly so humans notice in CI output.
    if (allowPlaceholderToken) {
      console.error('[WARN] Built with --allow-placeholder-token. Generated artifacts are NOT safe for production.');
    }
  } catch (e: any) {
    if (e.code === 'ENOENT') {
      console.error('Error: template not found:', e.path);
      process.exit(1);
    }
    console.error('Error:', e.message);
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
  warnSignedUrlReplay,
  validateJwksUrl,
  build,
  main,
  PLACEHOLDER_TOKEN,
};
