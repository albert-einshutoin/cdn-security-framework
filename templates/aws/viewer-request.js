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
 * - Rate limiting and bot behavior analysis are not available here; those belong to WAF/Shield
 *
 * You can also:
 * - Split rules by path (/api, /static) using Behavior separation
 * - Move stricter JWT validation to Lambda@Edge (e.g. RS256)
 */

// {{INJECT_CONFIG}}

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
      // RFC 3986 準拠の dot-segment 除去
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
    const uri = (req.uri || "").toLowerCase();
    for (const m of CFG.blockPathMarks) {
      if (uri.includes(m)) return resp(400, "Bad Request");
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
    // UA length check (if UA exists)
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

    // drop keys
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
        if (token !== gate.token) {
          return resp(401, "Unauthorized");
        }
      } else if (gate.type === 'basic_auth') {
        const authHeader = req.headers['authorization']?.value || "";
        if (!authHeader.startsWith('Basic ')) {
          return basicAuthResp();
        }
        const provided = authHeader.slice(6);
        if (provided !== gate.credentials) {
          return basicAuthResp();
        }
      }
      // jwt and signed_url types are handled in Lambda@Edge
      
      // Signal to origin that request passed edge auth
      req.headers["x-edge-authenticated"] = { value: "1" };
    }
    return null;
  }

  // Legacy adminGate for backward compatibility
  function adminGate(req) {
    if (!CFG.adminGate.enabled) return null;

    const uri = req.uri || "/";
    const isProtected = CFG.adminGate.protectedPrefixes.some(
      (p) => uri === p || uri.startsWith(p + "/")
    );
    if (!isProtected) return null;

    const token = req.headers[CFG.adminGate.tokenHeaderName]?.value || "";
    if (token !== CFG.adminGate.token) {
      return resp(401, "Unauthorized");
    }

    req.headers["x-edge-authenticated"] = { value: "1" };
    return null;
  }

  function handler(event) {
    const req = event.request;

    // 0) CORS preflight handling
    const preflight = handleCorsPreflight(req);
    if (preflight) return preflight;

    // 1) Method allowlist
    const m = blockIfMethodNotAllowed(req);
    if (m) return m;

    // 2) URI length check
    const uriLen = blockIfUriTooLong(req);
    if (uriLen) return uriLen;

    // 3) Path normalization
    normalizePath(req);

    // 4) Path traversal (coarse)
    const t = blockIfTraversal(req);
    if (t) return t;

    // 5) Required headers check
    const hm = blockIfHeaderMissing(req);
    if (hm) return hm;

    // 6) UA sanity (deny list)
    const u = blockIfBadUA(req);
    if (u) return u;

    // 7) Query guard + normalize
    const q = guardAndNormalizeQuery(req);
    if (q) return q;

    // 8) Auth gates (includes Basic auth, static token, etc.)
    const auth = checkAuthGates(req);
    if (auth) return auth;

    // 9) Legacy admin gate (backward compatibility)
    const g = adminGate(req);
    if (g) return g;

    return req;
  }
