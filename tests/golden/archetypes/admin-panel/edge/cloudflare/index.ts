/**
 * Cloudflare Workers — TEMPLATE
 *
 * 【注意】このファイルはテンプレートです。直接デプロイしないでください。
 * security.yml（または policy/security.yml）を編集し、npx cdn-security build --target cloudflare で dist/edge/cloudflare/index.ts を生成してください。
 */

const CFG = {
  mode: "enforce",
  allowMethods: new Set(["GET","HEAD","POST"]),
  maxQueryLength: 512,
  maxQueryParams: 20,
  maxUriLength: 1024,
  maxHeaderSize: 0,
  maxHeaderCount: 64,
  dropQueryKeys: new Set(["utm_source","utm_medium","utm_campaign","utm_term","utm_content","gclid","fbclid"]),
  uaDenyContains: ["sqlmap","nikto","acunetix","masscan","curl","wget","python-requests"],
  blockPathContains: ["/../","%2e%2e",".git/",".env"],
  blockPathRegexes: [],
  normalizePath: { collapseSlashes: false, removeDotSegments: false },
  requiredHeaders: ["user-agent"],
  allowedHosts: [],
  trustForwardedFor: false,
  cors: null,
  authGates: [{"name":"admin","protectedPrefixes":["/"],"type":"static_token","tokenHeaderName":"x-edge-token","tokenEnv":"EDGE_ADMIN_TOKEN"}],
  originAuth: null,
  jwksStaleIfErrorSec: 3600,
  jwksNegativeCacheSec: 60,
  geoBlockCountries: new Set([]),
  geoAllowCountries: new Set([]),
  obs: {"logFormat":"json","correlationHeader":"traceparent","sampleRate":0,"auditLogAuth":true,"auditHashSub":true},
};

const RESPONSE_CFG = {
  headers: {
    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
  },
  csp_public: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self';",
  csp_admin: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self';",
  csp_report_only: "",
  csp_report_uri: "",
  csp_nonce: false,
  coop: "same-origin",
  coep: "require-corp",
  corp: "",
  reporting_endpoints: "",
  adminPathPrefixes: ["/"],
  adminCacheControl: "no-store",
  authProtectedPrefixes: ["/"],
  forceVaryAuth: true,
  clearSiteDataPaths: [],
  clearSiteDataTypes: ["cache","cookies","storage"],
  cors: null,
  cookie_attributes: null,
};

type WorkerEnv = Record<string, string | undefined>;

type JwksCacheEntry = {
  fetchedAt: number;
  keys: Array<Record<string, any>>;
};

const jwksCache = new Map<string, JwksCacheEntry>();

type JwksNegativeEntry = { failedAt: number; reason: string };
const jwksNegativeCache = new Map<string, JwksNegativeEntry>();

function deny(code: number, msg: string) {
  return new Response(msg, { status: code, headers: { 'cache-control': 'no-store' } });
}

type ReqCtx = { method: string; uri: string; correlationId: string };

// Structured log emitter. Shape matches the AWS side so downstream pipelines
// can aggregate across CDN vendors with a single schema. Issue #21.
function logEvent(event: string, fields: Record<string, any>) {
  if (CFG.obs && CFG.obs.logFormat === 'text') {
    console.log('[' + event + ']', fields.status != null ? fields.status : '',
      fields.block_reason ? fields.block_reason : '');
    return;
  }
  const rec: Record<string, any> = { ts: Date.now(), level: event === 'block' ? 'warn' : 'info', event };
  for (const k of Object.keys(fields)) {
    if (fields[k] != null && fields[k] !== '') rec[k] = fields[k];
  }
  console.log(JSON.stringify(rec));
}

function readCorrelation(req: Request | null): string {
  if (!CFG.obs || !CFG.obs.correlationHeader || !req) return '';
  return req.headers.get(CFG.obs.correlationHeader) || '';
}

function reqCtx(req: Request | null): ReqCtx {
  if (!req) return { method: '', uri: '/', correlationId: '' };
  let uri = '/';
  try { uri = new URL(req.url).pathname; } catch (_e) { /* ignore */ }
  return { method: req.method, uri, correlationId: readCorrelation(req) };
}

async function hashSub(sub: string): Promise<string> {
  if (!sub) return '';
  const data = new TextEncoder().encode(sub);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(digest);
  let hex = '';
  for (let i = 0; i < bytes.length && hex.length < 16; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex.slice(0, 16);
}

function shouldBlock(code: number, msg: string, ctx?: ReqCtx | null): Response | null {
  const base = {
    status: code,
    block_reason: msg,
    method: ctx && ctx.method,
    uri: ctx && ctx.uri,
    correlation_id: ctx && ctx.correlationId,
  };
  if (CFG.mode === 'monitor') {
    logEvent('monitor', base);
    return null;
  }
  logEvent('block', base);
  return deny(code, msg);
}

function normalizePath(pathname: string): string {
  let p = pathname;
  if (CFG.normalizePath.collapseSlashes) {
    p = p.replace(/\/+/g, '/');
  }
  if (CFG.normalizePath.removeDotSegments) {
    const segments = p.split('/');
    const out: string[] = [];
    for (const seg of segments) {
      if (seg === '..') out.pop();
      else if (seg !== '.') out.push(seg);
    }
    p = out.join('/') || '/';
  }
  return p;
}

function base64UrlToBytes(input: string): Uint8Array {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(input.length / 4) * 4, '=');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function decodeJwtPart(part: string): any {
  const bytes = base64UrlToBytes(part);
  const text = new TextDecoder().decode(bytes);
  return JSON.parse(text);
}

function timingSafeEqual(a: string, b: string): boolean {
  // Iterates at least PAD (64) positions so short tokens (the common case)
  // take constant time regardless of prefix match — avoids the admin-prefix
  // timing oracle in threat-model §12. Longer tokens scale with max(|a|, |b|),
  // same as Go's hmac.Equal. No early-exit on length mismatch.
  const PAD = 64;
  const sa = typeof a === 'string' ? a : '';
  const sb = typeof b === 'string' ? b : '';
  let len = sa.length > sb.length ? sa.length : sb.length;
  if (len < PAD) len = PAD;
  let diff = (sa.length ^ sb.length) | 0;
  for (let i = 0; i < len; i++) {
    const ca = i < sa.length ? sa.charCodeAt(i) : 0;
    const cb = i < sb.length ? sb.charCodeAt(i) : 0;
    diff |= (ca ^ cb);
  }
  return diff === 0;
}

async function hmacSha256Base64Url(secret: string, message: string): Promise<string> {
  const keyData = new TextEncoder().encode(secret);
  const msgData = new TextEncoder().encode(message);
  const key = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, msgData);
  const bytes = new Uint8Array(sig);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

// Runtime SSRF guard — mirrors the build-time validator in scripts/lib/
// compile-core.js. Build already rejects unsafe URLs, but re-checking here
// limits the blast radius of any future regression that lets an http:// or
// private-range URL reach the fetcher.
function isUnsafeJwksUrl(rawUrl: string): string | null {
  let u: URL;
  try { u = new URL(rawUrl); } catch { return 'malformed URL'; }
  if (u.protocol !== 'https:') return 'non-https scheme';
  if (u.username || u.password) return 'userinfo present';
  const host = (u.hostname || '').toLowerCase();
  if (!host || host === 'localhost') return 'loopback hostname';
  if (/^127\./.test(host) || host === '::1' || host === '[::1]') return 'loopback literal';
  if (/^10\./.test(host)) return 'rfc1918 10/8';
  if (/^192\.168\./.test(host)) return 'rfc1918 192.168/16';
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return 'rfc1918 172.16/12';
  if (/^169\.254\./.test(host)) return 'link-local / metadata';
  if (/^0\./.test(host)) return 'reserved 0/8';
  return null;
}

async function fetchJwks(jwksUrl: string, ttlSec: number): Promise<Array<Record<string, any>>> {
  const unsafe = isUnsafeJwksUrl(jwksUrl);
  if (unsafe) {
    throw new Error('JWKS URL rejected: ' + unsafe);
  }
  const now = Date.now();
  const cached = jwksCache.get(jwksUrl);

  // Fresh window — serve cache
  if (cached && (now - cached.fetchedAt) < ttlSec * 1000) {
    return cached.keys;
  }

  const staleIfErrorSec: number = typeof (CFG as any).jwksStaleIfErrorSec === 'number' ? (CFG as any).jwksStaleIfErrorSec : 3600;
  const negativeCacheSec: number = typeof (CFG as any).jwksNegativeCacheSec === 'number' ? (CFG as any).jwksNegativeCacheSec : 60;
  const staleWindowMs = (ttlSec + staleIfErrorSec) * 1000;
  const negativeWindowMs = negativeCacheSec * 1000;

  // Honor negative cache — skip re-fetch if we just failed and have stale
  // keys to serve. Prevents hammering a broken IdP.
  const neg = jwksNegativeCache.get(jwksUrl);
  if (neg && (now - neg.failedAt) < negativeWindowMs) {
    if (cached && (now - cached.fetchedAt) < staleWindowMs) {
      console.log('[jwks] serving stale keys (negative cache active)');
      return cached.keys;
    }
    throw new Error('JWKS fetch skipped (negative cache): ' + neg.reason);
  }

  try {
    // `redirect: 'error'` forces Workers' fetch to refuse any 3xx, so an
    // attacker who briefly controls the JWKS host cannot redirect us to a
    // cloud-metadata endpoint or a different tenant's IdP.
    const res = await fetch(jwksUrl, { method: 'GET', redirect: 'error' });
    if (!res.ok) throw new Error('Failed to fetch JWKS: ' + res.status);
    const body = await res.json();
    const keys = Array.isArray((body as any)?.keys) ? (body as any).keys : [];
    jwksCache.set(jwksUrl, { fetchedAt: now, keys });
    jwksNegativeCache.delete(jwksUrl);
    return keys;
  } catch (err: any) {
    jwksNegativeCache.set(jwksUrl, { failedAt: now, reason: err?.message || 'unknown' });
    // Stale-if-error: keep serving the last known-good keys during the
    // stale-if-error window so an IdP outage doesn't cause 100% 401.
    if (cached && (now - cached.fetchedAt) < staleWindowMs) {
      console.log('[jwks] refresh failed, serving stale keys:', err?.message);
      return cached.keys;
    }
    throw err;
  }
}

function isJwtAlgAllowed(headerAlg: unknown, gate: any, expected: string): boolean {
  if (typeof headerAlg !== 'string' || headerAlg.length === 0) return false;
  if (headerAlg.toLowerCase() === 'none') return false;
  const allowed: string[] = Array.isArray(gate?.allowed_algorithms) && gate.allowed_algorithms.length > 0
    ? gate.allowed_algorithms
    : [expected];
  return allowed.includes(headerAlg);
}

async function verifyJwt(gate: any, token: string, env: WorkerEnv): Promise<{ valid: boolean; error?: string; payload?: any }> {
  const parts = token.split('.');
  if (parts.length !== 3) return { valid: false, error: 'Invalid token format' };

  const [headerB64, payloadB64, signatureB64] = parts;

  let header: any;
  let payload: any;
  try {
    header = decodeJwtPart(headerB64);
    payload = decodeJwtPart(payloadB64);
  } catch (_e) {
    return { valid: false, error: 'Malformed JWT' };
  }

  // alg whitelist — reject alg=none and any algorithm not explicitly accepted
  // by this gate. This blocks RS256↔HS256 confusion and the classic alg=none
  // bypass.
  if (!isJwtAlgAllowed(header?.alg, gate, gate.algorithm || 'RS256')) {
    return { valid: false, error: 'Unexpected JWT algorithm' };
  }

  const skewSec: number = Number.isFinite(Number(gate?.clock_skew_sec)) ? Number(gate.clock_skew_sec) : 30;
  const nowSec = Math.floor(Date.now() / 1000);
  if (payload.exp && nowSec >= payload.exp + skewSec) return { valid: false, error: 'Token expired' };
  if (payload.nbf && nowSec + skewSec < payload.nbf) return { valid: false, error: 'Token not yet valid' };
  if (gate.issuer && payload.iss !== gate.issuer) return { valid: false, error: 'Invalid issuer' };
  if (gate.audience) {
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(gate.audience)) return { valid: false, error: 'Invalid audience' };
  }

  const signData = `${headerB64}.${payloadB64}`;

  if (gate.algorithm === 'HS256') {
    const secret = env[gate.secret_env] || '';
    if (!secret) return { valid: false, error: 'JWT secret not configured' };
    const expected = await hmacSha256Base64Url(secret, signData);
    if (!timingSafeEqual(expected, signatureB64)) return { valid: false, error: 'Invalid signature' };
    return { valid: true, payload };
  }

  if (gate.algorithm === 'RS256') {
    if (!gate.jwks_url) return { valid: false, error: 'JWKS URL missing' };
    let keys = await fetchJwks(gate.jwks_url, gate.cache_ttl_sec || 3600);
    let jwk = keys.find((k) => k.kid === header.kid && k.kty === 'RSA');
    // Key rotation: if `kid` is not in our cache, invalidate and refetch once
    // — the IdP may have rotated keys since our last fetch. This prevents a
    // "stuck isolate" 401 storm after rotation.
    if (!jwk) {
      jwksCache.delete(gate.jwks_url);
      keys = await fetchJwks(gate.jwks_url, gate.cache_ttl_sec || 3600);
      jwk = keys.find((k) => k.kid === header.kid && k.kty === 'RSA');
    }
    if (!jwk) return { valid: false, error: 'JWK key not found' };

    const verifyKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    const ok = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      verifyKey,
      base64UrlToBytes(signatureB64),
      new TextEncoder().encode(signData),
    );
    return ok ? { valid: true, payload } : { valid: false, error: 'Invalid signature' };
  }

  return { valid: false, error: 'Unsupported JWT algorithm' };
}

async function verifySignedUrl(gate: any, url: URL, env: WorkerEnv): Promise<{ valid: boolean; error?: string; nonce?: string | null }> {
  const exp = url.searchParams.get(gate.expires_param || 'exp');
  const sig = url.searchParams.get(gate.signature_param || 'sig');
  if (!exp || !sig) return { valid: false, error: 'Missing exp or sig' };

  const expSec = Number(exp);
  if (!Number.isFinite(expSec) || Math.floor(Date.now() / 1000) > expSec) {
    return { valid: false, error: 'URL expired' };
  }

  let nonce: string | null = null;
  if (gate.nonce_param) {
    nonce = url.searchParams.get(gate.nonce_param);
    if (!nonce) return { valid: false, error: 'Missing nonce' };
    if (nonce.length < 16 || nonce.length > 256 || !/^[A-Za-z0-9._~-]+$/.test(nonce)) {
      return { valid: false, error: 'Malformed nonce' };
    }
  }

  const secret = env[gate.secret_env] || '';
  if (!secret) return { valid: false, error: 'URL signing secret not configured' };

  const signData = `${url.pathname}${exp}` + (nonce ? `|${nonce}` : '');
  const expected = await hmacSha256Base64Url(secret, signData);
  if (!timingSafeEqual(expected, sig)) return { valid: false, error: 'Invalid signature' };
  return { valid: true, nonce };
}

function isHostAllowed(hostHeader: string): boolean {
  const allowedHosts: string[] = Array.isArray(CFG.allowedHosts) ? CFG.allowedHosts : [];
  if (allowedHosts.length === 0) return true;
  let host = (hostHeader || '').toLowerCase();
  const colon = host.indexOf(':');
  if (colon !== -1) host = host.slice(0, colon);
  for (const allowed of allowedHosts) {
    if (allowed === host) return true;
    if (allowed.length > 2 && allowed.startsWith('*.')) {
      const suffix = allowed.slice(1);
      if (host.length > suffix.length && host.endsWith(suffix)) return true;
    }
  }
  return false;
}

function handleCorsPreflight(request: Request): Response | null {
  if (request.method !== 'OPTIONS' || !CFG.cors) return null;

  const origin = request.headers.get('origin') || '';
  if (!origin) return null;

  const allowedOrigins = CFG.cors.allow_origins || [];
  const isAllowed = allowedOrigins.includes('*') || allowedOrigins.includes(origin);
  if (!isAllowed) return null;

  const headers: Record<string, string> = {
    'Access-Control-Allow-Origin': origin,
    'Cache-Control': 'no-store',
  };

  if (CFG.cors.allow_methods) headers['Access-Control-Allow-Methods'] = CFG.cors.allow_methods.join(', ');
  if (CFG.cors.allow_headers) headers['Access-Control-Allow-Headers'] = CFG.cors.allow_headers.join(', ');
  if (CFG.cors.allow_credentials) headers['Access-Control-Allow-Credentials'] = 'true';
  if (CFG.cors.max_age) headers['Access-Control-Max-Age'] = String(CFG.cors.max_age);

  return new Response(null, { status: 204, headers });
}

export default {
  async fetch(request: Request, env: WorkerEnv): Promise<Response> {
    const url = new URL(request.url);
    const ctx = reqCtx(request);

    const preflight = handleCorsPreflight(request);
    if (preflight) return preflight;

    // Host allowlist — reject requests whose Host does not match before running
    // any other checks.
    if (!isHostAllowed(request.headers.get('host') || url.hostname)) {
      const r = shouldBlock(400, 'Host Not Allowed', ctx);
      if (r) return r;
    }

    // Geo enforcement (issue #12). request.cf.country is free and arrives before
    // any auth/JWKS work. Block list wins; allow list (non-empty) rejects any
    // country not explicitly enumerated. `T1` / empty represent Tor / unknown —
    // the allow list rejects them by design; block lists that include 'T1'
    // get the opt-in.
    {
      const country = (request as any).cf && (request as any).cf.country
        ? String((request as any).cf.country).toUpperCase()
        : '';
      if (CFG.geoBlockCountries.size > 0 && country && CFG.geoBlockCountries.has(country)) {
        const r = shouldBlock(403, 'Geo Blocked', ctx);
        if (r) return r;
      } else if (CFG.geoAllowCountries.size > 0 && (!country || !CFG.geoAllowCountries.has(country))) {
        const r = shouldBlock(403, 'Geo Blocked', ctx);
        if (r) return r;
      }
    }

    if (request.method === 'OPTIONS' && CFG.cors) {
      // let through non-matching origin preflight
    } else if (!CFG.allowMethods.has(request.method)) {
      const r = shouldBlock(405, 'Method Not Allowed', ctx);
      if (r) return r;
    }

    if (url.pathname.length > CFG.maxUriLength) {
      const r = shouldBlock(414, 'URI Too Long', ctx);
      if (r) return r;
    }

    // Header count cap (issue #9). Applied before path normalization because
    // origins that parse header maps don't care about URI shape.
    if (CFG.maxHeaderCount && CFG.maxHeaderCount > 0) {
      let headerCount = 0;
      request.headers.forEach(() => { headerCount++; });
      if (headerCount > CFG.maxHeaderCount) {
        const r = shouldBlock(431, 'Request Header Fields Too Large', ctx);
        if (r) return r;
      }
    }

    url.pathname = normalizePath(url.pathname);

    const pathLower = url.pathname.toLowerCase();
    for (const m of CFG.blockPathContains) {
      if (pathLower.includes(m)) {
        const r = shouldBlock(400, 'Bad Request', ctx);
        if (r) return r;
      }
    }
    for (const re of CFG.blockPathRegexes) {
      if (re.test(url.pathname)) {
        const r = shouldBlock(400, 'Bad Request', ctx);
        if (r) return r;
      }
    }

    for (const h of CFG.requiredHeaders) {
      const val = request.headers.get(h);
      if (!val) {
        const r = shouldBlock(400, 'Missing ' + h, ctx);
        if (r) return r;
      }
    }

    if (CFG.maxHeaderSize > 0) {
      let totalSize = 0;
      request.headers.forEach((value, key) => {
        totalSize += key.length + value.length;
      });
      if (totalSize > CFG.maxHeaderSize) {
        const r = shouldBlock(431, 'Request Header Fields Too Large', ctx);
        if (r) return r;
      }
    }

    const ua = request.headers.get('user-agent') || '';
    if (ua && ua.length > 512) {
      const r = shouldBlock(400, 'User-Agent Too Long', ctx);
      if (r) return r;
    }
    const uaLower = ua.toLowerCase();
    for (const s of CFG.uaDenyContains) {
      if (uaLower.includes(s)) {
        const r = shouldBlock(403, 'Forbidden', ctx);
        if (r) return r;
      }
    }

    const qs = url.search.slice(1);
    if (qs.length > CFG.maxQueryLength) {
      const r = shouldBlock(414, 'URI Too Long', ctx);
      if (r) return r;
    }
    const parts = qs ? qs.split('&') : [];
    if (parts.length > CFG.maxQueryParams) {
      const r = shouldBlock(400, 'Too many query params', ctx);
      if (r) return r;
    }

    for (const k of CFG.dropQueryKeys) url.searchParams.delete(k);

    // Nonce to forward to origin after a successful signed_url verification.
    // Collected here and attached when we build the origin-facing Request.
    let signedUrlNonce: string | null = null;
    for (const gate of CFG.authGates) {
      // signed_url gates may opt into exact_path matching to prevent a signature
      // for /assets/ from being replayed against /assets/other-file.
      const useExact = gate.type === 'signed_url' && gate.exact_path === true;
      const isProtected = useExact
        ? gate.protectedPrefixes.some((p: string) => url.pathname === p)
        : gate.protectedPrefixes.some((p: string) => url.pathname === p || url.pathname.startsWith(p + '/'));
      if (!isProtected) continue;

      if (gate.type === 'static_token') {
        const tok = request.headers.get(gate.tokenHeaderName) || '';
        const expectedToken = env[gate.tokenEnv] || '';
        if (!expectedToken) {
          console.error('[auth] static_token env missing:', gate.tokenEnv);
          const r = shouldBlock(503, 'Auth misconfigured', ctx);
          if (r) return r;
          continue;
        }
        if (!timingSafeEqual(tok, expectedToken)) {
          const r = shouldBlock(401, 'Unauthorized', ctx);
          if (r) return r;
        }
      } else if (gate.type === 'basic_auth') {
        const authHeader = request.headers.get('authorization') || '';
        const expectedCreds = env[gate.credentialsEnv] || '';
        if (!expectedCreds) {
          console.error('[auth] basic_auth env missing:', gate.credentialsEnv);
          const r = shouldBlock(503, 'Auth misconfigured', ctx);
          if (r) return r;
          continue;
        }
        if (!authHeader.startsWith('Basic ')) {
          if (CFG.mode === 'monitor') {
            console.log('[monitor] 401 Missing Basic auth');
          } else {
            return new Response('Unauthorized', {
              status: 401,
              headers: { 'WWW-Authenticate': 'Basic realm="Protected"', 'Cache-Control': 'no-store' },
            });
          }
        } else {
          const provided = authHeader.slice(6);
          if (!timingSafeEqual(provided, expectedCreds)) {
            if (CFG.mode === 'monitor') {
              console.log('[monitor] 401 Invalid Basic auth credentials');
            } else {
              return new Response('Unauthorized', {
                status: 401,
                headers: { 'WWW-Authenticate': 'Basic realm="Protected"', 'Cache-Control': 'no-store' },
              });
            }
          }
        }
      } else if (gate.type === 'jwt') {
        const authHeader = request.headers.get('authorization') || '';
        if (!authHeader.startsWith('Bearer ')) {
          const r = shouldBlock(401, 'Missing or invalid Authorization header', ctx);
          if (r) return r;
          continue;
        }
        const token = authHeader.slice(7);
        const verified = await verifyJwt(gate, token, env);
        if (!verified.valid) {
          const r = shouldBlock(401, verified.error || 'Invalid token', ctx);
          if (r) return r;
          continue;
        }
        if (CFG.obs && CFG.obs.auditLogAuth) {
          const rawSub = (verified.payload && verified.payload.sub) || '';
          logEvent('audit', {
            auth_event: 'auth_pass',
            gate_type: 'jwt',
            gate_name: gate.name || '',
            sub: CFG.obs.auditHashSub ? await hashSub(rawSub) : rawSub,
            method: ctx.method,
            uri: ctx.uri,
            correlation_id: ctx.correlationId,
          });
        }
      } else if (gate.type === 'signed_url') {
        const verified = await verifySignedUrl(gate, url, env);
        if (!verified.valid) {
          const r = shouldBlock(403, verified.error || 'Invalid signature', ctx);
          if (r) return r;
          continue;
        }
        if (gate.nonce_param && verified.nonce) {
          signedUrlNonce = verified.nonce;
        }
        if (CFG.obs && CFG.obs.auditLogAuth) {
          logEvent('audit', {
            auth_event: 'auth_pass',
            gate_type: 'signed_url',
            gate_name: gate.name || '',
            method: ctx.method,
            uri: ctx.uri,
            correlation_id: ctx.correlationId,
          });
        }
      }
    }

    const forwardHeaders = new Headers(request.headers);
    // Strip any client-supplied edge-auth marker before forwarding to origin.
    // Only the edge is allowed to assert this; trusting an incoming value
    // would let a client spoof authenticated state.
    forwardHeaders.delete('x-edge-authenticated');
    // Strip client-supplied X-Forwarded-For unless explicitly trusted. The
    // real client IP is already available via cf-connecting-ip, and a spoofed
    // XFF value can poison downstream rate limiters, IP allowlists, and logs.
    if (!CFG.trustForwardedFor) {
      forwardHeaders.delete('x-forwarded-for');
    }
    // Request-smuggling defense: strip hop-by-hop headers before origin
    // forward. Any client-supplied Transfer-Encoding / Connection / Upgrade
    // can desynchronize Worker ↔ origin framing (CL.TE, TE.CL, H2.TE) and
    // smuggle a second request. Cloudflare re-frames the request, so these
    // headers carry no legitimate meaning from the viewer.
    for (const h of ['transfer-encoding', 'connection', 'keep-alive', 'te', 'upgrade', 'proxy-connection', 'proxy-authenticate', 'proxy-authorization', 'trailer']) {
      forwardHeaders.delete(h);
    }
    if (CFG.originAuth && CFG.originAuth.type === 'custom_header') {
      const envName = CFG.originAuth.secret_env || '';
      const secret = envName ? (env[envName] || '') : '';
      if (secret) {
        const headerName = CFG.originAuth.header || 'X-Origin-Verify';
        forwardHeaders.set(headerName, secret);
      } else {
        console.log(JSON.stringify({
          ts: new Date().toISOString(),
          level: 'error',
          event: 'error',
          block_reason: 'origin_auth_secret_missing',
          secret_env: envName,
          uri: ctx.uri,
          correlation_id: ctx.correlationId,
        }));
      }
    }
    // Forward signed-URL nonce so origin can enforce single-use. The edge
    // cannot enforce replay protection statelessly — origin must reject
    // re-use (SET NX in KV/Redis).
    if (signedUrlNonce) {
      forwardHeaders.set('X-Signed-URL-Nonce', signedUrlNonce);
    }

    // Propagate correlation / trace header so origin logs can join edge logs.
    // When the header is missing, mint one so every request has a stable ID.
    if (CFG.obs && CFG.obs.correlationHeader) {
      const incoming = request.headers.get(CFG.obs.correlationHeader);
      if (!incoming) {
        const buf = new Uint8Array(16);
        crypto.getRandomValues(buf);
        const id = Array.from(buf, (b: number) => b.toString(16).padStart(2, '0')).join('');
        forwardHeaders.set(CFG.obs.correlationHeader, id);
      }
    }

    const res = await fetch(new Request(url.toString(), {
      method: request.method,
      headers: forwardHeaders,
      body: request.body,
      redirect: request.redirect,
    }));

    const out = new Response(res.body, res);
    const rh = RESPONSE_CFG.headers;
    if (rh['strict-transport-security']) out.headers.set('Strict-Transport-Security', rh['strict-transport-security']);
    if (rh['x-content-type-options']) out.headers.set('X-Content-Type-Options', rh['x-content-type-options']);
    if (rh['referrer-policy']) out.headers.set('Referrer-Policy', rh['referrer-policy']);
    if (rh['permissions-policy']) out.headers.set('Permissions-Policy', rh['permissions-policy']);

    // Cross-Origin isolation (issue #10). Only emitted when operator opts in.
    if (RESPONSE_CFG.coop) out.headers.set('Cross-Origin-Opener-Policy', RESPONSE_CFG.coop);
    if (RESPONSE_CFG.coep) out.headers.set('Cross-Origin-Embedder-Policy', RESPONSE_CFG.coep);
    if (RESPONSE_CFG.corp) out.headers.set('Cross-Origin-Resource-Policy', RESPONSE_CFG.corp);
    if (RESPONSE_CFG.reporting_endpoints) out.headers.set('Reporting-Endpoints', RESPONSE_CFG.reporting_endpoints);

    const isAdminPath = RESPONSE_CFG.adminPathPrefixes.some((p: string) => url.pathname === p || url.pathname.startsWith(p + '/'));
    const isAuthPath = (RESPONSE_CFG.authProtectedPrefixes || []).some((p: string) => url.pathname === p || url.pathname.startsWith(p + '/'));

    // Per-response CSP nonce (issue #11). crypto.getRandomValues is a CS-PRNG on Workers.
    let cspNonce = '';
    if (RESPONSE_CFG.csp_nonce) {
      const buf = new Uint8Array(16);
      crypto.getRandomValues(buf);
      // base64url without padding, ~22 chars.
      cspNonce = btoa(String.fromCharCode(...buf)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      out.headers.set('X-CSP-Nonce', cspNonce);
    }
    const applyNonce = (csp: string): string => {
      if (!csp || !cspNonce) return csp;
      return csp.split("'nonce-PLACEHOLDER'").join("'nonce-" + cspNonce + "'");
    };

    if (isAdminPath) {
      if (RESPONSE_CFG.adminCacheControl) out.headers.set('Cache-Control', RESPONSE_CFG.adminCacheControl);
      if (RESPONSE_CFG.csp_admin) out.headers.set('Content-Security-Policy', applyNonce(RESPONSE_CFG.csp_admin));
    } else {
      if (RESPONSE_CFG.csp_public) out.headers.set('Content-Security-Policy', applyNonce(RESPONSE_CFG.csp_public));
    }

    if (RESPONSE_CFG.csp_report_only) {
      out.headers.set('Content-Security-Policy-Report-Only', applyNonce(RESPONSE_CFG.csp_report_only));
    }

    // Force no-store + Vary on any auth-gate prefix (issue #8). Broader than adminPathPrefixes
    // which only fires for the first admin-shaped route.
    if (RESPONSE_CFG.forceVaryAuth && isAuthPath) {
      out.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      out.headers.set('Pragma', 'no-cache');
      const existingVary = out.headers.get('vary') || '';
      const tokens = existingVary.split(',').map((s: string) => s.trim()).filter(Boolean);
      const lower = tokens.map((t: string) => t.toLowerCase());
      if (lower.indexOf('authorization') === -1) tokens.push('Authorization');
      if (lower.indexOf('cookie') === -1) tokens.push('Cookie');
      out.headers.set('Vary', tokens.join(', '));
    }

    // Clear-Site-Data on configured logout paths (issue #20). Only on 2xx/3xx.
    const status = out.status;
    const isSuccess = status >= 200 && status < 400;
    const hitsClearPath = (RESPONSE_CFG.clearSiteDataPaths || []).some((p: string) =>
      url.pathname === p || url.pathname.startsWith(p + '/'),
    );
    if (hitsClearPath && isSuccess) {
      const types = (RESPONSE_CFG.clearSiteDataTypes || []).map((t: string) => '"' + t + '"');
      if (types.length > 0) out.headers.set('Clear-Site-Data', types.join(', '));
      out.headers.set('Cache-Control', 'no-store');
    }

    out.headers.delete('x-powered-by');
    out.headers.delete('server');

    // Cookie attribute append — multi-cookie aware via getAll/append (issue #13).
    if (RESPONSE_CFG.cookie_attributes) {
      const attrs: string[] = [];
      if (RESPONSE_CFG.cookie_attributes.secure) attrs.push('Secure');
      if (RESPONSE_CFG.cookie_attributes.http_only) attrs.push('HttpOnly');
      if (RESPONSE_CFG.cookie_attributes.same_site) attrs.push('SameSite=' + RESPONSE_CFG.cookie_attributes.same_site);

      if (attrs.length > 0) {
        // Workers runtime exposes multiple Set-Cookie via Headers#getSetCookie()
        // (per the Fetch standard). Fall back to get() on older runtimes.
        type HeadersWithGetSetCookie = Headers & { getSetCookie?: () => string[] };
        const h = out.headers as HeadersWithGetSetCookie;
        const cookies: string[] = typeof h.getSetCookie === 'function'
          ? h.getSetCookie()
          : (out.headers.get('set-cookie') ? [out.headers.get('set-cookie') as string] : []);
        if (cookies.length > 0) {
          out.headers.delete('set-cookie');
          const attrStr = attrs.join('; ');
          for (const cookie of cookies) {
            const needsSecure = RESPONSE_CFG.cookie_attributes.secure && !/(?:^|; *)Secure(?:;|$)/i.test(cookie);
            const needsHttpOnly = RESPONSE_CFG.cookie_attributes.http_only && !/(?:^|; *)HttpOnly(?:;|$)/i.test(cookie);
            const needsSameSite = RESPONSE_CFG.cookie_attributes.same_site && !/(?:^|; *)SameSite=/i.test(cookie);
            if (needsSecure || needsHttpOnly || needsSameSite) {
              const missing: string[] = [];
              if (needsSecure) missing.push('Secure');
              if (needsHttpOnly) missing.push('HttpOnly');
              if (needsSameSite) missing.push('SameSite=' + RESPONSE_CFG.cookie_attributes.same_site);
              out.headers.append('Set-Cookie', cookie + '; ' + missing.join('; '));
            } else {
              out.headers.append('Set-Cookie', cookie);
            }
          }
        }
      }
    }

    if (RESPONSE_CFG.cors) {
      const origin = request.headers.get('origin') || '';
      const allowedOrigins = RESPONSE_CFG.cors.allow_origins || [];
      const isAllowed = allowedOrigins.includes('*') || allowedOrigins.includes(origin);

      if (origin && isAllowed) {
        out.headers.set('Access-Control-Allow-Origin', origin);
        if (RESPONSE_CFG.cors.allow_credentials) out.headers.set('Access-Control-Allow-Credentials', 'true');
        if (RESPONSE_CFG.cors.expose_headers?.length > 0) out.headers.set('Access-Control-Expose-Headers', RESPONSE_CFG.cors.expose_headers.join(', '));
      }
    }

    return out;
  },
};
