/**
 * CloudFront Functions (Viewer Request) — TEMPLATE
 *
 * 【注意】このファイルはテンプレートです。直接デプロイしないでください。
 * security.yml（または policy/security.yml）を編集し、npx cdn-security build で dist/edge/viewer-request.js を生成してください。
 *
 * Purpose:
 * - Reduce attack surface at the edge: block unwanted methods, obvious traversal, anomalous UA, excessive query
 * - Mitigate cache-key pollution: strip utm, fbclid, gclid, etc.
 * - Optional simple token gate for /admin, /docs, /swagger
 *
 * Why this design:
 * - CloudFront Functions are ultra-low latency and stateless
 * - CloudFront Functions cannot read env vars at runtime, so static_token
 *   values are embedded at build time. Treat dist/edge/viewer-request.js as a
 *   secret artifact when static tokens are configured.
 * - Rate limiting and bot behavior analysis are not available here; those
 *   belong to WAF/Shield
 */

const CFG = {
  mode: "enforce",
  allowMethods: ["GET","HEAD","POST"],
  maxQueryLength: 1024,
  maxQueryParams: 30,
  maxUriLength: 2048,
  dropQueryKeys: new Set(["utm_source","utm_medium","utm_campaign","utm_term","utm_content","gclid","fbclid"]),
  uaDenyContains: ["sqlmap","nikto","acunetix","masscan","python-requests"],
  blockPathContains: ["/../","..","%2e%2e","%2E%2E"],
  blockPathRegexes: [],
  normalizePath: { collapseSlashes: false, removeDotSegments: false },
  requiredHeaders: ["user-agent"],
  cors: null,
  authGates: [{"name":"admin","protectedPrefixes":["/admin","/docs","/swagger"],"type":"static_token","tokenHeaderName":"x-edge-token","tokenEnv":"EDGE_ADMIN_TOKEN","token":"ci-build-token-not-for-deploy","tokenIsPlaceholder":false}],
};

  function resp(statusCode, body) {
    return {
      statusCode,
      statusDescription: String(statusCode),
      headers: {
        "content-type": { value: "text/plain; charset=utf-8" },
        "cache-control": { value: "no-store" },
      },
      body: body || "Denied",
    };
  }

  function shouldBlock(checkResult) {
    if (!checkResult) return null;
    if (CFG.mode === 'monitor') {
      console.log('[monitor]', checkResult.statusCode, checkResult.body || '');
      return null;
    }
    return checkResult;
  }

  function constantTimeEqual(a, b) {
    // Constant-time string equality for CFF (no SubtleCrypto available).
    // Length comparison leaks length, which is acceptable for fixed-length tokens.
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return diff === 0;
  }

  function handleCorsPreflight(req) {
    // Handle CORS preflight (OPTIONS) requests
    if (req.method !== 'OPTIONS' || !CFG.cors) return null;

    const origin = req.headers['origin']?.value || '';
    if (!origin) return null;

    const allowedOrigins = CFG.cors.allow_origins || [];
    const isAllowed = allowedOrigins.includes('*') || allowedOrigins.includes(origin);
    if (!isAllowed) return null;

    const headers = {
      'access-control-allow-origin': { value: origin },
      'cache-control': { value: 'no-store' },
    };

    if (CFG.cors.allow_methods) {
      headers['access-control-allow-methods'] = { value: CFG.cors.allow_methods.join(', ') };
    }
    if (CFG.cors.allow_headers) {
      headers['access-control-allow-headers'] = { value: CFG.cors.allow_headers.join(', ') };
    }
    if (CFG.cors.allow_credentials) {
      headers['access-control-allow-credentials'] = { value: 'true' };
    }
    if (CFG.cors.max_age) {
      headers['access-control-max-age'] = { value: String(CFG.cors.max_age) };
    }

    return {
      statusCode: 204,
      statusDescription: 'No Content',
      headers,
    };
  }

  function blockIfMethodNotAllowed(req) {
    // Skip method check for OPTIONS if CORS is enabled (handled by preflight)
    if (req.method === 'OPTIONS' && CFG.cors) return null;
    if (!CFG.allowMethods.includes(req.method)) return resp(405, "Method Not Allowed");
    return null;
  }

  function blockIfUriTooLong(req) {
    if ((req.uri || '').length > CFG.maxUriLength) {
      return resp(414, 'URI Too Long');
    }
    return null;
  }

  function normalizePath(req) {
    let p = req.uri || '/';
    if (CFG.normalizePath.collapseSlashes) {
      p = p.replace(/\/+/g, '/');
    }
    if (CFG.normalizePath.removeDotSegments) {
      // RFC 3986 dot-segment removal
      const segments = p.split('/');
      const out = [];
      for (const seg of segments) {
        if (seg === '..') { out.pop(); }
        else if (seg !== '.') { out.push(seg); }
      }
      p = out.join('/') || '/';
    }
    req.uri = p;
    return null;
  }

  function blockIfTraversal(req) {
    const uri = req.uri || "";
    const lower = uri.toLowerCase();
    for (const m of CFG.blockPathContains) {
      if (lower.includes(m)) return resp(400, "Bad Request");
    }
    for (const re of CFG.blockPathRegexes) {
      if (re.test(uri)) return resp(400, "Bad Request");
    }
    return null;
  }

  function blockIfHeaderMissing(req) {
    for (const h of CFG.requiredHeaders) {
      const val = req.headers[h.toLowerCase()]?.value;
      if (!val) return resp(400, "Missing " + h);
    }
    return null;
  }

  function blockIfBadUA(req) {
    const ua = req.headers["user-agent"]?.value || "";
    if (ua && ua.length > 512) return resp(400, "User-Agent Too Long");

    const lower = (ua || "").toLowerCase();
    for (const mark of CFG.uaDenyContains) {
      if (lower.includes(mark)) return resp(403, "Forbidden");
    }
    return null;
  }

  function guardAndNormalizeQuery(req) {
    const qs = req.querystring || "";

    if (qs.length > CFG.maxQueryLength) return resp(414, "URI Too Long");

    const parts = qs ? qs.split("&") : [];
    if (parts.length > CFG.maxQueryParams) return resp(400, "Too many query params");

    const kept = [];
    for (const p of parts) {
      if (!p) continue;
      const eq = p.indexOf("=");
      const k = eq === -1 ? p : p.slice(0, eq);
      if (!k) continue;
      if (CFG.dropQueryKeys.has(k)) continue;
      kept.push(p);
    }
    req.querystring = kept.join("&");
    return null;
  }

  function basicAuthResp() {
    return {
      statusCode: 401,
      statusDescription: 'Unauthorized',
      headers: {
        'www-authenticate': { value: 'Basic realm="Protected"' },
        'content-type': { value: 'text/plain; charset=utf-8' },
        'cache-control': { value: 'no-store' },
      },
      body: 'Unauthorized',
    };
  }

  function checkAuthGates(req) {
    const uri = req.uri || "/";

    for (const gate of CFG.authGates) {
      const isProtected = gate.protectedPrefixes.some(
        (p) => uri === p || uri.startsWith(p + "/")
      );
      if (!isProtected) continue;

      if (gate.type === 'static_token') {
        const token = req.headers[gate.tokenHeaderName]?.value || "";
        if (!constantTimeEqual(token, gate.token)) {
          return resp(401, "Unauthorized");
        }
      } else if (gate.type === 'basic_auth') {
        const authHeader = req.headers['authorization']?.value || "";
        if (!authHeader.startsWith('Basic ')) {
          return basicAuthResp();
        }
        const provided = authHeader.slice(6);
        if (!constantTimeEqual(provided, gate.credentials)) {
          return basicAuthResp();
        }
      }
      // jwt and signed_url types are handled in Lambda@Edge

      // Signal to origin that request passed edge auth
      req.headers["x-edge-authenticated"] = { value: "1" };
    }
    return null;
  }

  function handler(event) {
    const req = event.request;

    // 0) CORS preflight handling
    const preflight = handleCorsPreflight(req);
    if (preflight) return preflight;

    // 1) Method allowlist
    const m = shouldBlock(blockIfMethodNotAllowed(req));
    if (m) return m;

    // 2) URI length check
    const uriLen = shouldBlock(blockIfUriTooLong(req));
    if (uriLen) return uriLen;

    // 3) Path normalization
    normalizePath(req);

    // 4) Path traversal (coarse)
    const t = shouldBlock(blockIfTraversal(req));
    if (t) return t;

    // 5) Required headers check
    const hm = shouldBlock(blockIfHeaderMissing(req));
    if (hm) return hm;

    // 6) UA sanity (deny list)
    const u = shouldBlock(blockIfBadUA(req));
    if (u) return u;

    // 7) Query guard + normalize
    const q = shouldBlock(guardAndNormalizeQuery(req));
    if (q) return q;

    // 8) Auth gates (static token, basic auth)
    const auth = shouldBlock(checkAuthGates(req));
    if (auth) return auth;

    return req;
  }
