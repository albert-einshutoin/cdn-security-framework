/**
 * Cloudflare Workers — TEMPLATE
 *
 * 【注意】このファイルはテンプレートです。直接デプロイしないでください。
 * security.yml（または policy/security.yml）を編集し、npx cdn-security build --target cloudflare で dist/edge/cloudflare/index.ts を生成してください。
 *
 * Purpose:
 * - Same as CloudFront Functions: entry blocking, normalization, token gate
 * - Response header injection
 *
 * You can also:
 * - Use KV/Durable Objects for stateful rate limiting
 * - Extend with bot detection, country/ASN rules, etc.
 */

const CFG = {
  allowMethods: new Set(["GET","HEAD","POST"]),
  maxQueryLength: 1024,
  maxQueryParams: 30,
  maxUriLength: 2048,
  maxHeaderSize: 0,
  dropQueryKeys: new Set(["utm_source","utm_medium","utm_campaign","utm_term","utm_content","gclid","fbclid"]),
  uaDenyContains: ["sqlmap","nikto","acunetix","masscan","python-requests"],
  blockPathMarks: ["/../","..","%2e%2e","%2E%2E"],
  normalizePath: { collapseSlashes: false, removeDotSegments: false },
  requiredHeaders: ["user-agent"],
  cors: null,
  authGates: [{"name":"admin","protectedPrefixes":["/admin","/docs","/swagger"],"type":"static_token","tokenHeaderName":"x-edge-token"}],
  protectedPrefixes: ["/admin","/docs","/swagger"],
  adminTokenHeader: "x-edge-token",
};

const RESPONSE_CFG = {
  headers: {
    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
  },
  csp_public: "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';",
  csp_admin: "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';",
  adminPathPrefixes: ["/admin","/docs","/swagger"],
  adminCacheControl: "no-store",
  cors: null,
  cookie_attributes: null,
};

function deny(code: number, msg: string) {
  return new Response(msg, { status: code, headers: { "cache-control": "no-store" } });
}

function normalizePath(pathname: string): string {
  let p = pathname;
  if (CFG.normalizePath.collapseSlashes) {
    p = p.replace(/\/+/g, '/');
  }
  if (CFG.normalizePath.removeDotSegments) {
    // RFC 3986 準拠の dot-segment 除去
    const segments = p.split('/');
    const out: string[] = [];
    for (const seg of segments) {
      if (seg === '..') { out.pop(); }
      else if (seg !== '.') { out.push(seg); }
    }
    p = out.join('/') || '/';
  }
  return p;
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
  
  if (CFG.cors.allow_methods) {
    headers['Access-Control-Allow-Methods'] = CFG.cors.allow_methods.join(', ');
  }
  if (CFG.cors.allow_headers) {
    headers['Access-Control-Allow-Headers'] = CFG.cors.allow_headers.join(', ');
  }
  if (CFG.cors.allow_credentials) {
    headers['Access-Control-Allow-Credentials'] = 'true';
  }
  if (CFG.cors.max_age) {
    headers['Access-Control-Max-Age'] = String(CFG.cors.max_age);
  }
  
  return new Response(null, { status: 204, headers });
}

export default {
  async fetch(request: Request, env: { EDGE_ADMIN_TOKEN?: string }): Promise<Response> {
    const url = new URL(request.url);

    // Handle CORS preflight
    const preflight = handleCorsPreflight(request);
    if (preflight) return preflight;

    // Skip method check for OPTIONS if CORS enabled
    if (request.method === 'OPTIONS' && CFG.cors) {
      // Non-matching origin OPTIONS - let it through or deny
    } else if (!CFG.allowMethods.has(request.method)) {
      return deny(405, "Method Not Allowed");
    }

    // URI length check
    if (url.pathname.length > CFG.maxUriLength) return deny(414, "URI Too Long");

    // Path normalization
    url.pathname = normalizePath(url.pathname);

    const path = url.pathname.toLowerCase();
    for (const m of CFG.blockPathMarks) if (path.includes(m)) return deny(400, "Bad Request");

    // Required headers check
    for (const h of CFG.requiredHeaders) {
      const val = request.headers.get(h);
      if (!val) return deny(400, "Missing " + h);
    }

    // Header size check (Cloudflare Workers can access all headers)
    if (CFG.maxHeaderSize > 0) {
      let totalSize = 0;
      request.headers.forEach((value, key) => {
        totalSize += key.length + value.length;
      });
      if (totalSize > CFG.maxHeaderSize) return deny(431, "Request Header Fields Too Large");
    }

    // UA deny list check
    const ua = request.headers.get("user-agent") || "";
    if (ua && ua.length > 512) return deny(400, "User-Agent Too Long");
    const uaLower = ua.toLowerCase();
    for (const s of CFG.uaDenyContains) if (uaLower.includes(s)) return deny(403, "Forbidden");

    const qs = url.search.slice(1);
    if (qs.length > CFG.maxQueryLength) return deny(414, "URI Too Long");
    const parts = qs ? qs.split("&") : [];
    if (parts.length > CFG.maxQueryParams) return deny(400, "Too many query params");

    for (const k of CFG.dropQueryKeys) url.searchParams.delete(k);

    // Check auth gates (including Basic auth)
    for (const gate of CFG.authGates) {
      const isProtected = gate.protectedPrefixes.some((p: string) => url.pathname === p || url.pathname.startsWith(p + "/"));
      if (!isProtected) continue;
      
      if (gate.type === 'static_token') {
        const tok = request.headers.get(gate.tokenHeaderName) || "";
        const expectedToken = (env as any)[gate.tokenHeaderName?.replace(/-/g, '_').toUpperCase()] || env.EDGE_ADMIN_TOKEN || "";
        if (tok !== expectedToken) return deny(401, "Unauthorized");
      } else if (gate.type === 'basic_auth') {
        const authHeader = request.headers.get('authorization') || "";
        if (!authHeader.startsWith('Basic ')) {
          return new Response('Unauthorized', {
            status: 401,
            headers: { 'WWW-Authenticate': 'Basic realm="Protected"', 'Cache-Control': 'no-store' }
          });
        }
        const provided = authHeader.slice(6);
        const expectedCreds = (env as any)[gate.credentialsEnv] || "";
        if (provided !== expectedCreds) {
          return new Response('Unauthorized', {
            status: 401,
            headers: { 'WWW-Authenticate': 'Basic realm="Protected"', 'Cache-Control': 'no-store' }
          });
        }
      }
    }

    // Legacy: Check protected prefixes (backward compatibility)
    const isProtected = CFG.protectedPrefixes.some((p: string) => url.pathname === p || url.pathname.startsWith(p + "/"));
    if (isProtected) {
      const tok = request.headers.get(CFG.adminTokenHeader) || "";
      if (tok !== (env.EDGE_ADMIN_TOKEN || "")) return deny(401, "Unauthorized");
    }

    const res = await fetch(new Request(url.toString(), request));

    const out = new Response(res.body, res);
    const rh = RESPONSE_CFG.headers;
    if (rh["strict-transport-security"]) out.headers.set("Strict-Transport-Security", rh["strict-transport-security"]);
    if (rh["x-content-type-options"]) out.headers.set("X-Content-Type-Options", rh["x-content-type-options"]);
    if (rh["referrer-policy"]) out.headers.set("Referrer-Policy", rh["referrer-policy"]);
    if (rh["permissions-policy"]) out.headers.set("Permissions-Policy", rh["permissions-policy"]);

    const isAdminPath = RESPONSE_CFG.adminPathPrefixes.some((p: string) => url.pathname === p || url.pathname.startsWith(p + "/"));
    if (isAdminPath) {
      if (RESPONSE_CFG.adminCacheControl) out.headers.set("Cache-Control", RESPONSE_CFG.adminCacheControl);
      if (RESPONSE_CFG.csp_admin) out.headers.set("Content-Security-Policy", RESPONSE_CFG.csp_admin);
    } else {
      if (RESPONSE_CFG.csp_public) out.headers.set("Content-Security-Policy", RESPONSE_CFG.csp_public);
    }

    out.headers.delete("x-powered-by");

    // Cookie attributes (add Secure, HttpOnly, SameSite to existing Set-Cookie headers)
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

    // CORS headers for actual requests
    if (RESPONSE_CFG.cors) {
      const origin = request.headers.get('origin') || '';
      const allowedOrigins = RESPONSE_CFG.cors.allow_origins || [];
      const isAllowed = allowedOrigins.includes('*') || allowedOrigins.includes(origin);
      
      if (origin && isAllowed) {
        out.headers.set('Access-Control-Allow-Origin', origin);
        if (RESPONSE_CFG.cors.allow_credentials) {
          out.headers.set('Access-Control-Allow-Credentials', 'true');
        }
        if (RESPONSE_CFG.cors.expose_headers && RESPONSE_CFG.cors.expose_headers.length > 0) {
          out.headers.set('Access-Control-Expose-Headers', RESPONSE_CFG.cors.expose_headers.join(', '));
        }
      }
    }

    return out;
  },
};
