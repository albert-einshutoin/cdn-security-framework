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

const CFG = {
  mode: "enforce",
  allowMethods: ["GET","HEAD","POST"],
  maxQueryLength: 1024,
  maxQueryParams: 30,
  dropQueryKeys: new Set(["utm_source","utm_medium","utm_campaign","utm_term","utm_content","gclid","fbclid"]),
  uaDenyContains: ["sqlmap","nikto","acunetix","masscan","python-requests"],
  blockPathMarks: ["/../","..","%2e%2e","%2E%2E"],
  adminGate:   {
    "enabled": true,
    "protectedPrefixes": [
      "/admin",
      "/docs",
      "/swagger"
    ],
    "tokenHeaderName": "x-edge-token",
    "token": "BUILD_TIME_INJECTION"
  }
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

  function blockIfMethodNotAllowed(req) {
    if (!CFG.allowMethods.includes(req.method)) return resp(405, "Method Not Allowed");
    return null;
  }

  function blockIfTraversal(req) {
    const uri = (req.uri || "").toLowerCase();
    for (const m of CFG.blockPathMarks) {
      if (uri.includes(m)) return resp(400, "Bad Request");
    }
    return null;
  }

  function blockIfBadUA(req) {
    const ua = req.headers["user-agent"]?.value || "";
    // Blocking missing UA is configurable (relax if you have API/IoT clients without UA)
    if (!ua) return resp(400, "Missing User-Agent");
    if (ua.length > 512) return resp(400, "User-Agent Too Long");

    const lower = ua.toLowerCase();
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

  function adminGate(req) {
    if (!CFG.adminGate.enabled) return null;

    const uri = req.uri || "/";
    const isProtected = CFG.adminGate.protectedPrefixes.some(
      (p) => uri === p || uri.startsWith(p + "/")
    );
    if (!isProtected) return null;

    const token = req.headers[CFG.adminGate.tokenHeaderName]?.value || "";
    if (token !== CFG.adminGate.token) {
      // Optionally return 404 to hide existence of the path
      return resp(401, "Unauthorized");
    }

    // Optional: signal to origin that request passed edge auth
    req.headers["x-edge-authenticated"] = { value: "1" };
    return null;
  }

  function handler(event) {
    const req = event.request;

    // 1) Method allowlist
    const m = blockIfMethodNotAllowed(req);
    if (m) return m;

    // 2) Path traversal (coarse)
    const t = blockIfTraversal(req);
    if (t) return t;

    // 3) UA sanity
    const u = blockIfBadUA(req);
    if (u) return u;

    // 4) Query guard + normalize
    const q = guardAndNormalizeQuery(req);
    if (q) return q;

    // 5) Admin gate
    const g = adminGate(req);
    if (g) return g;

    return req;
  }
