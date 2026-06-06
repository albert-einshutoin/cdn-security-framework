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
  allowMethods: ["GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"],
  maxQueryLength: 1024,
  maxQueryParams: 30,
  maxUriLength: 2048,
  maxHeaderCount: 48,
  dropQueryKeys: new Set(["utm_source","utm_medium","utm_campaign","utm_term","utm_content","gclid","fbclid"]),
  uaDenyContains: ["sqlmap","nikto","acunetix","masscan"],
  blockPathContains: ["/../","%2e%2e"],
  blockPathRegexes: [],
  normalizePath: {"collapseSlashes":false,"removeDotSegments":false},
  requiredHeaders: ["user-agent"],
  allowedHosts: [],
  trustForwardedFor: false,
  cors: {"allow_origins":["https://app.example.com"],"allow_methods":["GET","POST","PUT","PATCH","DELETE","OPTIONS"],"allow_headers":["authorization","content-type","x-request-id"],"allow_credentials":true,"max_age":600},
  authGates: [{"name":"api","protectedPrefixes":["/api"],"type":"jwt"}],
  anomalyGuards: {"enabled":true,"crlf":true,"malformedCookie":false,"doubleEncodedTraversal":true,"maxCookieBytes":4096,"maxCookiePairs":80},
  obs: {"logFormat":"json","correlationHeader":"traceparent","sampleRate":0,"auditLogAuth":true,"auditHashSub":true},
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

  function appendVary(headers, token) {
    var existing = (headers["vary"] && headers["vary"].value) || '';
    var tokens = existing.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
    var lower = tokens.map(function (s) { return s.toLowerCase(); });
    if (lower.indexOf(token.toLowerCase()) === -1) tokens.push(token);
    headers["vary"] = { value: tokens.join(', ') };
  }

  // Structured log emitter. CloudFront Functions supports console.log + JSON.stringify
  // on flat primitives (our records only contain those). `event` distinguishes
  // block / monitor / audit records for downstream Logs Insights queries.
  function logEvent(event, fields) {
    if (CFG.obs && CFG.obs.logFormat === 'text') {
      console.log('[' + event + ']',
        fields && fields.status != null ? fields.status : '',
        fields && fields.block_reason ? fields.block_reason : '');
      return;
    }
    var rec = { ts: Date.now(), level: event === 'block' ? 'warn' : 'info', event: event };
    if (fields) {
      for (var k in fields) {
        if (Object.prototype.hasOwnProperty.call(fields, k) && fields[k] != null && fields[k] !== '') {
          rec[k] = fields[k];
        }
      }
    }
    console.log(JSON.stringify(rec));
  }

  function readCorrelation(req) {
    if (!CFG.obs || !CFG.obs.correlationHeader) return '';
    var h = req && req.headers && req.headers[CFG.obs.correlationHeader];
    return (h && h.value) || '';
  }

  function shouldBlock(checkResult, req) {
    if (!checkResult) return null;
    var reason = (checkResult.body && String(checkResult.body)) || 'blocked';
    var base = {
      status: checkResult.statusCode,
      block_reason: reason,
      method: req && req.method,
      uri: req && req.uri,
      correlation_id: req ? readCorrelation(req) : '',
    };
    if (CFG.mode === 'monitor') {
      logEvent('monitor', base);
      return null;
    }
    logEvent('block', base);
    return checkResult;
  }

  function shouldBlockAuth(checkResult, req) {
    if (!checkResult) return null;
    logEvent(CFG.mode === 'monitor' ? 'monitor' : 'block', {
      status: checkResult.statusCode,
      block_reason: (checkResult.body && String(checkResult.body)) || 'auth_failed',
      method: req && req.method,
      uri: req && req.uri,
      correlation_id: req ? readCorrelation(req) : '',
    });
    return checkResult;
  }

  function constantTimeEqual(a, b) {
    // Constant-time string equality for CFF (no SubtleCrypto / timingSafeEqual
    // available). Always iterates at least PAD (64) positions so short tokens
    // (the common case) take constant time regardless of prefix match.
    // For tokens longer than PAD, iteration scales with max(|a|, |b|) — same
    // behaviour as Go's hmac.Equal. No early-exit on length mismatch.
    var PAD = 64;
    var sa = typeof a === 'string' ? a : '';
    var sb = typeof b === 'string' ? b : '';
    var len = sa.length > sb.length ? sa.length : sb.length;
    if (len < PAD) len = PAD;
    var diff = (sa.length ^ sb.length) | 0;
    for (var i = 0; i < len; i++) {
      var ca = i < sa.length ? sa.charCodeAt(i) : 0;
      var cb = i < sb.length ? sb.charCodeAt(i) : 0;
      diff |= (ca ^ cb);
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
    appendVary(headers, 'Origin');

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

  function blockIfHostNotAllowed(req) {
    // Host header allowlist. When CFG.allowedHosts is empty, allowlist is
    // disabled and any host is accepted. Entries are lowercase (normalized at
    // build time). Supports `*.example.com` wildcard prefix.
    if (!CFG.allowedHosts || CFG.allowedHosts.length === 0) return null;
    var hostHeader = (req.headers['host'] && req.headers['host'].value) || '';
    var host = hostHeader.toLowerCase();
    // Strip optional :port suffix so :8443 etc. still match.
    var colon = host.indexOf(':');
    if (colon !== -1) host = host.slice(0, colon);
    for (var i = 0; i < CFG.allowedHosts.length; i++) {
      var allowed = CFG.allowedHosts[i];
      if (allowed === host) return null;
      if (allowed.length > 2 && allowed.charCodeAt(0) === 42 && allowed.charCodeAt(1) === 46) {
        // '*.example.com' — match suffix including the dot
        var suffix = allowed.slice(1);
        if (host.length > suffix.length && host.slice(-suffix.length) === suffix) return null;
      }
    }
    return resp(400, 'Host Not Allowed');
  }

  function blockIfUriTooLong(req) {
    if ((req.uri || '').length > CFG.maxUriLength) {
      return resp(414, 'URI Too Long');
    }
    return null;
  }

  function blockIfTooManyHeaders(req) {
    if (!CFG.maxHeaderCount || CFG.maxHeaderCount <= 0) return null;
    var h = req.headers || {};
    // Count normalized header names. `headers` keys are already lower-cased by CF.
    var n = 0;
    for (var k in h) { if (Object.prototype.hasOwnProperty.call(h, k)) n++; }
    if (n > CFG.maxHeaderCount) {
      return resp(431, 'Request Header Fields Too Large');
    }
    return null;
  }

  function hasRawControlLineBreak(s) {
    return typeof s === 'string' && (s.indexOf('\r') !== -1 || s.indexOf('\n') !== -1);
  }

  function hasEncodedCrlfIndicator(s) {
    if (typeof s !== 'string' || s.length === 0) return false;
    var lower = s.toLowerCase();
    return lower.indexOf('%0d') !== -1 || lower.indexOf('%0a') !== -1;
  }

  function hasCrlfIndicator(s) {
    return hasRawControlLineBreak(s) || hasEncodedCrlfIndicator(s);
  }

  function decodeOnceWhenPercent25Present(s) {
    if (typeof s !== 'string' || s.length === 0) return '';
    if (s.toLowerCase().indexOf('%25') === -1) return '';
    try {
      return decodeURIComponent(s);
    } catch (_e) {
      return '';
    }
  }

  function hasDoubleEncodedTraversalIndicator(s) {
    const decoded = decodeOnceWhenPercent25Present(s);
    if (!decoded) return false;
    const lower = decoded.toLowerCase();
    return lower.indexOf('%2e%2e') !== -1 ||
      lower.indexOf('..%2f') !== -1 ||
      lower.indexOf('..%5c') !== -1 ||
      lower.indexOf('%2f..') !== -1 ||
      lower.indexOf('%5c..') !== -1 ||
      lower.indexOf('../') !== -1 ||
      lower.indexOf('..\\') !== -1;
  }

  function hasCookieControlChar(cookie) {
    if (typeof cookie !== 'string') return false;
    for (var i = 0; i < cookie.length; i++) {
      var code = cookie.charCodeAt(i);
      if (code < 32 || code === 127) return true;
    }
    return false;
  }

  function isMalformedCookie(cookie) {
    if (typeof cookie !== 'string' || cookie.length === 0) return false;
    const guards = CFG.anomalyGuards || {};
    if (guards.maxCookieBytes && cookie.length > guards.maxCookieBytes) return true;
    if (hasCookieControlChar(cookie)) return true;

    const parts = cookie.split(';');
    let pairCount = 0;
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i].trim();
      // A leading/trailing semicolon is tolerated, but an empty middle segment
      // (`a=1;;b=2`) is a clear delimiter anomaly.
      if (!part) {
        if (i > 0 && i < parts.length - 1) return true;
        continue;
      }
      const eq = part.indexOf('=');
      if (eq <= 0) return true;
      if (!part.slice(0, eq).trim()) return true;
      pairCount++;
      if (guards.maxCookiePairs && pairCount > guards.maxCookiePairs) return true;
    }
    return false;
  }

  function querystringMatches(qs, predicate) {
    if (!qs) return false;
    if (typeof qs === 'string') return predicate(qs);
    if (typeof qs !== 'object') return false;
    for (const k in qs) {
      if (!Object.prototype.hasOwnProperty.call(qs, k)) continue;
      if (predicate(k)) return true;
      const entry = qs[k];
      if (!entry || typeof entry !== 'object') {
        if (predicate(String(entry))) return true;
        continue;
      }
      if (predicate(entry.value)) return true;
      if (Array.isArray(entry.multiValue)) {
        for (const mv of entry.multiValue) {
          if (predicate(mv && mv.value)) return true;
        }
      }
    }
    return false;
  }

  function headerEntryMatches(entry, predicate) {
    if (!entry || typeof entry !== 'object') return false;
    if (predicate(entry.value)) return true;
    if (Array.isArray(entry.multiValue)) {
      for (const mv of entry.multiValue) {
        if (predicate(mv && mv.value)) return true;
      }
    }
    return false;
  }

  function serializeCookieMap(cookies) {
    if (!cookies || typeof cookies !== 'object') return '';
    const parts = [];
    for (const name in cookies) {
      if (!Object.prototype.hasOwnProperty.call(cookies, name)) continue;
      const entry = cookies[name];
      if (!entry || typeof entry !== 'object') {
        parts.push(name + '=' + String(entry));
        continue;
      }
      if (Array.isArray(entry.multiValue) && entry.multiValue.length > 0) {
        for (const mv of entry.multiValue) {
          parts.push(name + '=' + String((mv && mv.value) || ''));
        }
      } else {
        parts.push(name + '=' + String(entry.value || ''));
      }
    }
    return parts.join('; ');
  }

  function cookieStringFromRequest(req, headers) {
    const cookieMap = serializeCookieMap(req.cookies);
    if (cookieMap) return cookieMap;
    const entry = headers['cookie'];
    if (!entry || typeof entry !== 'object') return '';
    if (Array.isArray(entry.multiValue) && entry.multiValue.length > 0) {
      const parts = [];
      for (const mv of entry.multiValue) {
        parts.push((mv && mv.value) || '');
      }
      return parts.join('; ');
    }
    return entry.value || '';
  }

  function blockIfRequestAnomaly(req) {
    const guards = CFG.anomalyGuards || {};
    if (guards.enabled !== true) return null;

    const uri = req.uri || '';

    if (guards.crlf !== false && (hasCrlfIndicator(uri) || querystringMatches(req.querystring, hasCrlfIndicator))) {
      return resp(400, 'Bad Request');
    }
    if (guards.doubleEncodedTraversal !== false &&
      (hasDoubleEncodedTraversalIndicator(uri) || querystringMatches(req.querystring, hasDoubleEncodedTraversalIndicator))) {
      return resp(400, 'Bad Request');
    }

    const headers = req.headers || {};
    for (const name in headers) {
      if (!Object.prototype.hasOwnProperty.call(headers, name)) continue;
      if (guards.crlf !== false && headerEntryMatches(headers[name], hasCrlfIndicator)) {
        return resp(400, 'Bad Request');
      }
    }

    const cookie = cookieStringFromRequest(req, headers);
    if (guards.malformedCookie !== false && isMalformedCookie(cookie)) {
      return resp(400, 'Malformed Cookie');
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
    const limited = blockIfQueryLimits(req);
    if (limited) return limited;
    normalizeQuery(req);
    return null;
  }

  function blockIfQueryLimits(req) {
    const originalQuerystring = req.querystring;
    const qs = serializeQuerystring(originalQuerystring);

    if (qs.length > CFG.maxQueryLength) return resp(414, "URI Too Long");

    const parts = qs ? qs.split("&") : [];
    if (parts.length > CFG.maxQueryParams) return resp(400, "Too many query params");
    return null;
  }

  function normalizeQuery(req) {
    const originalQuerystring = req.querystring;
    const qs = serializeQuerystring(originalQuerystring);
    const parts = qs ? qs.split("&") : [];

    const kept = [];
    for (const p of parts) {
      if (!p) continue;
      const eq = p.indexOf("=");
      const k = eq === -1 ? p : p.slice(0, eq);
      if (!k) continue;
      if (CFG.dropQueryKeys.has(k)) continue;
      kept.push(p);
    }
    req.querystring = normalizeQuerystringOutput(originalQuerystring, kept);
    return null;
  }

  function encodeQueryPair(k, v) {
    return encodeURIComponent(k) + (v === undefined ? "" : "=" + encodeURIComponent(String(v)));
  }

  function serializeQuerystring(qs) {
    if (!qs) return "";
    if (typeof qs === "string") return qs;
    const parts = [];
    for (const k in qs) {
      if (!Object.prototype.hasOwnProperty.call(qs, k)) continue;
      const entry = qs[k];
      if (!entry || typeof entry !== "object") {
        parts.push(encodeQueryPair(k, entry));
        continue;
      }
      if (Array.isArray(entry.multiValue) && entry.multiValue.length > 0) {
        for (const mv of entry.multiValue) {
          parts.push(encodeQueryPair(k, mv && mv.value));
        }
      } else {
        parts.push(encodeQueryPair(k, entry.value));
      }
    }
    return parts.join("&");
  }

  function normalizeQuerystringOutput(originalQuerystring, parts) {
    if (!originalQuerystring || typeof originalQuerystring === "string") {
      return parts.join("&");
    }
    const next = {};
    for (const p of parts) {
      const eq = p.indexOf("=");
      const key = decodeURIComponent(eq === -1 ? p : p.slice(0, eq));
      if (!key) continue;
      const value = eq === -1 ? "" : decodeURIComponent(p.slice(eq + 1));
      if (!next[key]) {
        next[key] = { value: value };
      } else if (Array.isArray(next[key].multiValue)) {
        next[key].multiValue.push({ value: value });
      } else {
        next[key].multiValue = [{ value: next[key].value }, { value: value }];
      }
    }
    return next;
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

    // 0a) Strip any client-supplied edge-auth marker. Only the edge itself is
    //     allowed to set this; trusting an incoming value would let a client
    //     spoof authenticated state to the origin.
    if (req.headers) {
      delete req.headers['x-edge-authenticated'];
      // Strip client-supplied X-Forwarded-For unless explicitly trusted.
      // CloudFront populates cloudfront-viewer-address for the real client IP;
      // leaving a spoofed XFF header in place can poison downstream rate
      // limiting, IP-based allowlists, and audit logs.
      if (!CFG.trustForwardedFor) {
        delete req.headers['x-forwarded-for'];
      }
    }

    // 0b) CORS preflight handling
    const preflight = handleCorsPreflight(req);
    if (preflight) return preflight;

    // 0c) Host allowlist (early reject — cheaper than running every check)
    const host = shouldBlock(blockIfHostNotAllowed(req), req);
    if (host) return host;

    // 1) Method allowlist
    const m = shouldBlock(blockIfMethodNotAllowed(req), req);
    if (m) return m;

    // 2) URI length check
    const uriLen = shouldBlock(blockIfUriTooLong(req), req);
    if (uriLen) return uriLen;

    // 2b) Header count cap (issue #9) — 431 protects origin parsers from
    //     hash-collision / amplification under small-but-many-headers payloads.
    const hc = shouldBlock(blockIfTooManyHeaders(req), req);
    if (hc) return hc;

    // 3) Query length / count caps before any query anomaly scan.
    const qLimit = shouldBlock(blockIfQueryLimits(req), req);
    if (qLimit) return qLimit;

    // 4) Lightweight anomaly guards. Run after cheap caps, before path
    // normalization and origin/auth forwarding.
    const anomaly = shouldBlock(blockIfRequestAnomaly(req), req);
    if (anomaly) return anomaly;

    // 5) Raw path traversal (coarse). Run before dot-segment normalization so
    // suspicious input like /public/../private cannot be rewritten to /private
    // before the block patterns see it.
    const rawTraversal = shouldBlock(blockIfTraversal(req), req);
    if (rawTraversal) return rawTraversal;

    // 6) Path normalization
    normalizePath(req);

    // 6b) Path traversal after normalization. Preserves existing behavior for
    // block rules that intentionally match canonicalized paths.
    const t = shouldBlock(blockIfTraversal(req), req);
    if (t) return t;

    // 7) Required headers check
    const hm = shouldBlock(blockIfHeaderMissing(req), req);
    if (hm) return hm;

    // 8) UA sanity (deny list)
    const u = shouldBlock(blockIfBadUA(req), req);
    if (u) return u;

    // 9) Query normalize after anomaly checks have seen the raw query.
    normalizeQuery(req);

    // 10) Auth gates (static token, basic auth)
    const auth = shouldBlockAuth(checkAuthGates(req), req);
    if (auth) return auth;

    return req;
  }
