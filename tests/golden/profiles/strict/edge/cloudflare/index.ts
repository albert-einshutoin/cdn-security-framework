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
  dropQueryKeys: new Set(["utm_source","utm_medium","utm_campaign","utm_term","utm_content","gclid","fbclid"]),
  uaDenyContains: ["sqlmap","nikto","acunetix","masscan","python-requests","zgrab","nmap","curl","wget","scanner"],
  blockPathContains: ["/../","..","%2e%2e","%2e%2e"],
  blockPathRegexes: [/%2f\.\.\//i, /\.\.%2f/i, /\\\.\.\\/i],
  normalizePath: { collapseSlashes: false, removeDotSegments: false },
  requiredHeaders: ["user-agent"],
  cors: null,
  authGates: [{"name":"admin","protectedPrefixes":["/admin","/docs","/swagger","/api/admin","/internal"],"type":"static_token","tokenHeaderName":"x-edge-token","tokenEnv":"EDGE_ADMIN_TOKEN"}],
  originAuth: null,
};

const RESPONSE_CFG = {
  headers: {
    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
  },
  csp_public: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self';",
  csp_admin: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self';",
  adminPathPrefixes: ["/admin","/docs","/swagger","/api/admin","/internal"],
  adminCacheControl: "no-store",
  cors: null,
  cookie_attributes: null,
};

type WorkerEnv = Record<string, string | undefined>;

type JwksCacheEntry = {
  fetchedAt: number;
  keys: Array<Record<string, any>>;
};

const jwksCache = new Map<string, JwksCacheEntry>();

function deny(code: number, msg: string) {
  return new Response(msg, { status: code, headers: { 'cache-control': 'no-store' } });
}

function shouldBlock(code: number, msg: string): Response | null {
  if (CFG.mode === 'monitor') {
    console.log('[monitor]', code, msg);
    return null;
  }
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
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
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

async function fetchJwks(jwksUrl: string, ttlSec: number): Promise<Array<Record<string, any>>> {
  const now = Date.now();
  const cached = jwksCache.get(jwksUrl);
  if (cached && (now - cached.fetchedAt) < ttlSec * 1000) {
    return cached.keys;
  }

  const res = await fetch(jwksUrl, { method: 'GET' });
  if (!res.ok) throw new Error('Failed to fetch JWKS');
  const body = await res.json();
  const keys = Array.isArray(body?.keys) ? body.keys : [];
  jwksCache.set(jwksUrl, { fetchedAt: now, keys });
  return keys;
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

  const nowSec = Math.floor(Date.now() / 1000);
  if (payload.exp && nowSec >= payload.exp) return { valid: false, error: 'Token expired' };
  if (payload.nbf && nowSec < payload.nbf) return { valid: false, error: 'Token not yet valid' };
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
    const keys = await fetchJwks(gate.jwks_url, gate.cache_ttl_sec || 3600);
    const jwk = keys.find((k) => k.kid === header.kid && k.kty === 'RSA');
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

async function verifySignedUrl(gate: any, url: URL, env: WorkerEnv): Promise<{ valid: boolean; error?: string }> {
  const exp = url.searchParams.get(gate.expires_param || 'exp');
  const sig = url.searchParams.get(gate.signature_param || 'sig');
  if (!exp || !sig) return { valid: false, error: 'Missing exp or sig' };

  const expSec = Number(exp);
  if (!Number.isFinite(expSec) || Math.floor(Date.now() / 1000) > expSec) {
    return { valid: false, error: 'URL expired' };
  }

  const secret = env[gate.secret_env] || '';
  if (!secret) return { valid: false, error: 'URL signing secret not configured' };

  const expected = await hmacSha256Base64Url(secret, `${url.pathname}${exp}`);
  if (!timingSafeEqual(expected, sig)) return { valid: false, error: 'Invalid signature' };
  return { valid: true };
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

    const preflight = handleCorsPreflight(request);
    if (preflight) return preflight;

    if (request.method === 'OPTIONS' && CFG.cors) {
      // let through non-matching origin preflight
    } else if (!CFG.allowMethods.has(request.method)) {
      const r = shouldBlock(405, 'Method Not Allowed');
      if (r) return r;
    }

    if (url.pathname.length > CFG.maxUriLength) {
      const r = shouldBlock(414, 'URI Too Long');
      if (r) return r;
    }

    url.pathname = normalizePath(url.pathname);

    const pathLower = url.pathname.toLowerCase();
    for (const m of CFG.blockPathContains) {
      if (pathLower.includes(m)) {
        const r = shouldBlock(400, 'Bad Request');
        if (r) return r;
      }
    }
    for (const re of CFG.blockPathRegexes) {
      if (re.test(url.pathname)) {
        const r = shouldBlock(400, 'Bad Request');
        if (r) return r;
      }
    }

    for (const h of CFG.requiredHeaders) {
      const val = request.headers.get(h);
      if (!val) {
        const r = shouldBlock(400, 'Missing ' + h);
        if (r) return r;
      }
    }

    if (CFG.maxHeaderSize > 0) {
      let totalSize = 0;
      request.headers.forEach((value, key) => {
        totalSize += key.length + value.length;
      });
      if (totalSize > CFG.maxHeaderSize) {
        const r = shouldBlock(431, 'Request Header Fields Too Large');
        if (r) return r;
      }
    }

    const ua = request.headers.get('user-agent') || '';
    if (ua && ua.length > 512) {
      const r = shouldBlock(400, 'User-Agent Too Long');
      if (r) return r;
    }
    const uaLower = ua.toLowerCase();
    for (const s of CFG.uaDenyContains) {
      if (uaLower.includes(s)) {
        const r = shouldBlock(403, 'Forbidden');
        if (r) return r;
      }
    }

    const qs = url.search.slice(1);
    if (qs.length > CFG.maxQueryLength) {
      const r = shouldBlock(414, 'URI Too Long');
      if (r) return r;
    }
    const parts = qs ? qs.split('&') : [];
    if (parts.length > CFG.maxQueryParams) {
      const r = shouldBlock(400, 'Too many query params');
      if (r) return r;
    }

    for (const k of CFG.dropQueryKeys) url.searchParams.delete(k);

    for (const gate of CFG.authGates) {
      const isProtected = gate.protectedPrefixes.some((p: string) => url.pathname === p || url.pathname.startsWith(p + '/'));
      if (!isProtected) continue;

      if (gate.type === 'static_token') {
        const tok = request.headers.get(gate.tokenHeaderName) || '';
        const expectedToken = env[gate.tokenEnv] || '';
        if (!expectedToken) {
          console.error('[auth] static_token env missing:', gate.tokenEnv);
          const r = shouldBlock(503, 'Auth misconfigured');
          if (r) return r;
          continue;
        }
        if (!timingSafeEqual(tok, expectedToken)) {
          const r = shouldBlock(401, 'Unauthorized');
          if (r) return r;
        }
      } else if (gate.type === 'basic_auth') {
        const authHeader = request.headers.get('authorization') || '';
        const expectedCreds = env[gate.credentialsEnv] || '';
        if (!expectedCreds) {
          console.error('[auth] basic_auth env missing:', gate.credentialsEnv);
          const r = shouldBlock(503, 'Auth misconfigured');
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
          const r = shouldBlock(401, 'Missing or invalid Authorization header');
          if (r) return r;
          continue;
        }
        const token = authHeader.slice(7);
        const verified = await verifyJwt(gate, token, env);
        if (!verified.valid) {
          const r = shouldBlock(401, verified.error || 'Invalid token');
          if (r) return r;
          continue;
        }
      } else if (gate.type === 'signed_url') {
        const verified = await verifySignedUrl(gate, url, env);
        if (!verified.valid) {
          const r = shouldBlock(403, verified.error || 'Invalid signature');
          if (r) return r;
          continue;
        }
      }
    }

    const forwardHeaders = new Headers(request.headers);
    // Strip any client-supplied edge-auth marker before forwarding to origin.
    // Only the edge is allowed to assert this; trusting an incoming value
    // would let a client spoof authenticated state.
    forwardHeaders.delete('x-edge-authenticated');
    if (CFG.originAuth && CFG.originAuth.type === 'custom_header') {
      const secret = env[CFG.originAuth.secret_env || ''] || '';
      if (secret) {
        const headerName = CFG.originAuth.header || 'X-Origin-Verify';
        forwardHeaders.set(headerName, secret);
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

    const isAdminPath = RESPONSE_CFG.adminPathPrefixes.some((p: string) => url.pathname === p || url.pathname.startsWith(p + '/'));
    if (isAdminPath) {
      if (RESPONSE_CFG.adminCacheControl) out.headers.set('Cache-Control', RESPONSE_CFG.adminCacheControl);
      if (RESPONSE_CFG.csp_admin) out.headers.set('Content-Security-Policy', RESPONSE_CFG.csp_admin);
    } else {
      if (RESPONSE_CFG.csp_public) out.headers.set('Content-Security-Policy', RESPONSE_CFG.csp_public);
    }

    out.headers.delete('x-powered-by');

    if (RESPONSE_CFG.cookie_attributes) {
      const setCookie = out.headers.get('set-cookie');
      if (setCookie) {
        const attrs: string[] = [];
        if (RESPONSE_CFG.cookie_attributes.secure) attrs.push('Secure');
        if (RESPONSE_CFG.cookie_attributes.http_only) attrs.push('HttpOnly');
        if (RESPONSE_CFG.cookie_attributes.same_site) attrs.push('SameSite=' + RESPONSE_CFG.cookie_attributes.same_site);

        if (attrs.length > 0 && !setCookie.includes('Secure') && !setCookie.includes('HttpOnly') && !setCookie.includes('SameSite')) {
          out.headers.set('Set-Cookie', setCookie + '; ' + attrs.join('; '));
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
