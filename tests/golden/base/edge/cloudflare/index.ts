/**
 * Cloudflare Workers — TEMPLATE
 *
 * 【注意】このファイルはテンプレートです。直接デプロイしないでください。
 * security.yml（または policy/security.yml）を編集し、npx cdn-security build --target cloudflare で dist/edge/cloudflare/index.ts を生成してください。
 */

const CFG = {
  mode: "enforce",
  allowMethods: new Set(["GET","HEAD","POST"]),
  maxQueryLength: 1024,
  maxQueryParams: 30,
  maxUriLength: 2048,
  maxHeaderSize: 0,
  maxHeaderCount: 64,
  dropQueryKeys: new Set(["utm_source","utm_medium","utm_campaign","utm_term","utm_content","gclid","fbclid"]),
  uaDenyContains: ["sqlmap","nikto","acunetix","masscan","python-requests"],
  blockPathContains: ["/../","../","%2e%2e"],
  blockPathRegexes: [],
  normalizePath: {"collapseSlashes":true,"removeDotSegments":true,"caseInsensitive":true,"rejectAmbiguousEncoding":true},
  requiredHeaders: ["user-agent"],
  allowedHosts: [],
  trustForwardedFor: false,
  cors: null,
  authGates: [{"name":"admin","protectedPrefixes":["/admin","/docs","/swagger"],"type":"static_token","tokenHeaderName":"x-edge-token","tokenEnv":"EDGE_ADMIN_TOKEN"}],
  authGateIndex: null,
  authGateIndexMaxLength: 0,
  originAuth: null,
  jwksStaleIfErrorSec: 3600,
  jwksNegativeCacheSec: 60,
  geoBlockCountries: new Set([]),
  geoAllowCountries: new Set([]),
  challenge: null,
  graphqlGuard: null,
  anomalyGuards: {"enabled":true,"crlf":true,"malformedCookie":false,"doubleEncodedTraversal":true,"maxCookieBytes":4096,"maxCookiePairs":80},
  obs: {"logFormat":"json","correlationHeader":"","sampleRate":0,"auditLogAuth":false,"auditHashSub":false},
};

function pathCandidates(uri, index) {
  var found = [], seen = Object.create(null);
  function add(key) {
    var ids = Object.prototype.hasOwnProperty.call(index, key) ? index[key] : [];
    for (var j = 0; j < ids.length; j++) {
      if (!seen[ids[j]]) { seen[ids[j]] = true; found.push(ids[j]); }
    }
  }
  for (var i = uri.indexOf('/'); i !== -1; i = uri.indexOf('/', i + 1)) add(uri.slice(0, i));
  add(uri);
  return found.sort(function(a, b) { return a - b; });
}

const RESPONSE_CFG = {
  headers: {"strict-transport-security":"max-age=31536000; includeSubDomains; preload","x-content-type-options":"nosniff","referrer-policy":"strict-origin-when-cross-origin","permissions-policy":"camera=(), microphone=(), geolocation=()"},
  csp_public: "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';",
  csp_admin: "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';",
  csp_report_only: "",
  csp_report_uri: "",
  csp_nonce: false,
  coop: "",
  coep: "",
  corp: "",
  reporting_endpoints: "",
  adminPathPrefixes: ["/admin","/docs","/swagger"],
  adminPathIndex: null,
  adminPathIndexMaxLength: 0,
  adminCacheControl: "no-store",
  authProtectedPrefixes: ["/admin","/docs","/swagger"],
  authPathIndex: null,
  authPathIndexMaxLength: 0,
  forceVaryAuth: true,
  caseInsensitive: true,
  clearSiteDataPaths: [],
  clearSiteDataTypes: ["cache","cookies","storage"],
  cors: null,
  cookie_attributes: null,
  responseDlp: {"enabled":false,"action":"report_only","mask":"[REDACTED]","blockStatus":451,"blockBody":"Response blocked by edge DLP","body":{"enabled":false,"maxBytes":32768,"contentTypes":["text/","application/json","application/xml","text/xml","application/javascript"]},"headers":{"enabled":false,"names":["set-cookie","authorization","x-api-key"]},"detectors":{"builtIn":["api_key","credit_card"],"customRegexNames":[]}},
  responseDlpCustomRegexes: [],
};
const JWKS_MAX_BODY_BYTES = 256 * 1024;
function deny(code, msg) {
  return new Response(msg, { status: code, headers: { "cache-control": "no-store" } });
}
function logEvent(event, fields) {
  if (CFG.obs && CFG.obs.logFormat === "text") {
    console.log(
      "[" + event + "]",
      fields.status != null ? fields.status : "",
      fields.block_reason ? fields.block_reason : ""
    );
    return;
  }
  const rec = { ts: Date.now(), level: event === "block" ? "warn" : "info", event };
  for (const k of Object.keys(fields))
    fields[k] != null && fields[k] !== "" && (rec[k] = fields[k]);
  console.log(JSON.stringify(rec));
}
function readCorrelation(req) {
  return !CFG.obs || !CFG.obs.correlationHeader || !req ? "" : req.headers.get(CFG.obs.correlationHeader) || "";
}
function reqCtx(req, pathname) {
  if (!req) return { method: "", uri: "/", correlationId: "" };
  let uri = "/";
  try {
    uri = pathname === void 0 ? new URL(req.url).pathname : pathname;
  } catch {
  }
  return { method: req.method, uri, correlationId: readCorrelation(req) };
}
function shouldBlock(code, msg, ctx) {
  const base = {
    status: code,
    block_reason: msg,
    method: ctx && ctx.method,
    uri: ctx && ctx.uri,
    correlation_id: ctx && ctx.correlationId
  };
  return CFG.mode === "monitor" ? (logEvent("monitor", base), null) : (logEvent("block", base), deny(code, msg));
}
function shouldBlockAuth(code, msg, ctx) {
  const base = {
    status: code,
    block_reason: msg,
    method: ctx && ctx.method,
    uri: ctx && ctx.uri,
    correlation_id: ctx && ctx.correlationId
  };
  return logEvent(CFG.mode === "monitor" ? "monitor" : "block", base), code === 401 ? deny(401, "Unauthorized") : code === 403 ? deny(403, "Forbidden") : code === 503 ? deny(503, "Service Unavailable") : deny(code, "Denied");
}
function hasAmbiguousPathEncoding(uri) {
  const s = String(uri || "").toLowerCase();
  return s.includes("%2f") || s.includes("%5c") || s.includes("%252f") || s.includes("%255c") || s.includes("%252e");
}
function canonicalizePath(pathname) {
  const opts = CFG.normalizePath || {}, raw = String(pathname || "/");
  if (raw[0] === "/" && !/[;%]|\/\/|(?:^|\/)\.{1,2}(?:\/|$)/.test(raw)) return raw;
  let p = raw.replace(/;[^/]*/g, "");
  for (let round = 0; round < 3 && /%[0-9A-Fa-f]{2}/.test(p); round++)
    try {
      const next = decodeURIComponent(p);
      if (next === p) break;
      p = next;
    } catch {
      return null;
    }
  if (/%[0-9A-Fa-f]{2}/.test(p)) return null;
  if (p = p.replace(/;[^/]*/g, ""), p.startsWith("/") || (p = "/" + p), opts.collapseSlashes !== !1 && (p = p.replace(/\/+/g, "/")), opts.removeDotSegments !== !1) {
    const out = [];
    for (const seg of p.split("/"))
      seg === ".." ? out.pop() : seg !== "." && out.push(seg);
    p = out.join("/") || "/";
  }
  return p;
}
function normalizeForMatch(value) {
  const raw = value || "/";
  return CFG.normalizePath?.caseInsensitive !== !1 ? raw.toLowerCase() : raw;
}
function pathMatchesExact(uri, prefix) {
  return uri === prefix;
}
function pathMatchesPrefix(uri, prefix) {
  const left = uri, right = prefix;
  return left === right || left.startsWith(right + "/");
}
const authMatchPrefixes = CFG.authGates.map((gate) => gate.protectedPrefixes.map(normalizeForMatch)), authGateIds = CFG.authGates.map((_gate, index) => index), adminMatchPrefixes = RESPONSE_CFG.adminPathPrefixes.map(normalizeForMatch), protectedMatchPrefixes = (RESPONSE_CFG.authProtectedPrefixes || []).map(normalizeForMatch), clearSiteDataValue = (RESPONSE_CFG.clearSiteDataTypes || []).map((t) => '"' + t + '"').join(", "), dlpGlobalRegexes = (RESPONSE_CFG.responseDlpCustomRegexes || []).map((re) => new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g"));
function normalizePath(pathname) {
  return canonicalizePath(pathname);
}
function rawPathnameFromRequestUrl(rawUrl) {
  const text = String(rawUrl || ""), schemeIdx = text.indexOf("://");
  let pathStart = -1;
  if (schemeIdx !== -1 ? pathStart = text.indexOf("/", schemeIdx + 3) : text.startsWith("/") && (pathStart = 0), pathStart === -1) return "/";
  let pathEnd = text.length;
  const queryStart = text.indexOf("?", pathStart), hashStart = text.indexOf("#", pathStart);
  return queryStart !== -1 && queryStart < pathEnd && (pathEnd = queryStart), hashStart !== -1 && hashStart < pathEnd && (pathEnd = hashStart), text.slice(pathStart, pathEnd) || "/";
}
function blockIfPathPattern(pathname, ctx) {
  const pathLower = pathname.toLowerCase();
  for (const m of CFG.blockPathContains)
    if (pathLower.includes(m)) {
      const r = shouldBlock(400, "Bad Request", ctx);
      if (r) return r;
    }
  for (const re of CFG.blockPathRegexes)
    if (re.test(pathname)) {
      const r = shouldBlock(400, "Bad Request", ctx);
      if (r) return r;
    }
  return null;
}
function hasRawControlLineBreak(s) {
  return typeof s == "string" && (s.indexOf("\r") !== -1 || s.indexOf(`
`) !== -1);
}
function hasEncodedCrlfIndicator(s) {
  if (typeof s != "string" || s.length === 0) return !1;
  const lower = s.toLowerCase();
  return lower.indexOf("%0d") !== -1 || lower.indexOf("%0a") !== -1;
}
function hasCrlfIndicator(s) {
  return hasRawControlLineBreak(s) || hasEncodedCrlfIndicator(s);
}
function decodeOnceWhenPercent25Present(s) {
  if (typeof s != "string" || s.length === 0 || s.toLowerCase().indexOf("%25") === -1) return "";
  try {
    return decodeURIComponent(s);
  } catch {
    return "";
  }
}
function hasDoubleEncodedTraversalIndicator(s) {
  const decoded = decodeOnceWhenPercent25Present(s);
  if (!decoded) return !1;
  const lower = decoded.toLowerCase();
  return lower.indexOf("%2e%2e") !== -1 || lower.indexOf("..%2f") !== -1 || lower.indexOf("..%5c") !== -1 || lower.indexOf("%2f..") !== -1 || lower.indexOf("%5c..") !== -1 || lower.indexOf("../") !== -1 || lower.indexOf("..\\") !== -1;
}
function hasCookieControlChar(cookie) {
  if (typeof cookie != "string") return !1;
  for (let i = 0; i < cookie.length; i++) {
    const code = cookie.charCodeAt(i);
    if (code < 32 || code === 127) return !0;
  }
  return !1;
}
function isMalformedCookie(cookie) {
  if (typeof cookie != "string" || cookie.length === 0) return !1;
  const guards = CFG.anomalyGuards || {};
  if (guards.maxCookieBytes && cookie.length > guards.maxCookieBytes || hasCookieControlChar(cookie)) return !0;
  const parts = cookie.split(";");
  let pairCount = 0;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i].trim();
    if (!part) {
      if (i > 0 && i < parts.length - 1) return !0;
      continue;
    }
    const eq = part.indexOf("=");
    if (eq <= 0 || !part.slice(0, eq).trim() || (pairCount++, guards.maxCookiePairs && pairCount > guards.maxCookiePairs)) return !0;
  }
  return !1;
}
function blockIfRequestAnomaly(request, rawPathname, query, ctx) {
  const guards = CFG.anomalyGuards || {};
  if (guards.enabled !== !0) return null;
  if (guards.crlf !== !1 && (hasCrlfIndicator(rawPathname) || hasCrlfIndicator(query)) || guards.doubleEncodedTraversal !== !1 && (hasDoubleEncodedTraversalIndicator(rawPathname) || hasDoubleEncodedTraversalIndicator(query)))
    return shouldBlock(400, "Bad Request", ctx);
  let headerBlock = null;
  if (request.headers.forEach((value) => {
    !headerBlock && guards.crlf !== !1 && hasCrlfIndicator(value) && (headerBlock = shouldBlock(400, "Bad Request", ctx));
  }), headerBlock) return headerBlock;
  const cookie = request.headers.get("cookie") || "";
  return guards.malformedCookie !== !1 && isMalformedCookie(cookie) ? shouldBlock(400, "Malformed Cookie", ctx) : null;
}
function cancelForwardBody(state) {
  const body = state.body;
  state.body = null, body instanceof ReadableStream && discardBody(body);
}
function discardBody(body) {
  body && body.cancel().catch(() => console.error("[body-inspection] cancellation failed"));
}
function timingSafeEqual(a, b) {
  const sa = typeof a == "string" ? a : "", sb = typeof b == "string" ? b : "";
  let len = sa.length > sb.length ? sa.length : sb.length;
  len < 64 && (len = 64);
  let diff = sa.length ^ sb.length | 0;
  for (let i = 0; i < len; i++) {
    const ca = i < sa.length ? sa.charCodeAt(i) : 0, cb = i < sb.length ? sb.charCodeAt(i) : 0;
    diff |= ca ^ cb;
  }
  return diff === 0;
}
function isHostAllowed(hostHeader) {
  const allowedHosts = Array.isArray(CFG.allowedHosts) ? CFG.allowedHosts : [];
  if (allowedHosts.length === 0) return !0;
  let host = (hostHeader || "").toLowerCase();
  const colon = host.indexOf(":");
  colon !== -1 && (host = host.slice(0, colon));
  for (const allowed of allowedHosts) {
    if (allowed === host) return !0;
    if (allowed.length > 2 && allowed.startsWith("*.")) {
      const suffix = allowed.slice(1);
      if (host.length > suffix.length && host.endsWith(suffix)) return !0;
    }
  }
  return !1;
}
function appendVary(headers, token) {
  const tokens = (headers.get("vary") || "").split(",").map((s) => s.trim()).filter(Boolean);
  tokens.map((s) => s.toLowerCase()).indexOf(token.toLowerCase()) === -1 && tokens.push(token), headers.set("Vary", tokens.join(", "));
}
var stdin_default = {
  async fetch(request, env) {
    const url = new URL(request.url), rawPathname = rawPathnameFromRequestUrl(request.url), ctx = reqCtx(request, url.pathname), allowSamplingKey = "", preflight = null;
    if (preflight) return preflight;
    if (!isHostAllowed(request.headers.get("host") || url.hostname)) {
      const r = shouldBlock(400, "Host Not Allowed", ctx);
      if (r) return r;
    }
    {
      const country = request.cf && request.cf.country ? String(request.cf.country).toUpperCase() : "";
      if (CFG.geoBlockCountries.size > 0 && country && CFG.geoBlockCountries.has(country)) {
        const r = shouldBlock(403, "Geo Blocked", ctx);
        if (r) return r;
      } else if (CFG.geoAllowCountries.size > 0 && (!country || !CFG.geoAllowCountries.has(country))) {
        const r = shouldBlock(403, "Geo Blocked", ctx);
        if (r) return r;
      }
    }
    if (!(request.method === "OPTIONS" && CFG.cors)) {
      if (!CFG.allowMethods.has(request.method)) {
        const r = shouldBlock(405, "Method Not Allowed", ctx);
        if (r) return r;
      }
    }
    if (rawPathname.length > CFG.maxUriLength) {
      const r = shouldBlock(414, "URI Too Long", ctx);
      if (r) return r;
    }
    let headerCount = 0, headerSize = 0;
    if ((CFG.maxHeaderCount > 0 || CFG.maxHeaderSize > 0) && request.headers.forEach((value, key) => {
      headerCount++, headerSize += key.length + value.length;
    }), CFG.maxHeaderCount && CFG.maxHeaderCount > 0 && headerCount > CFG.maxHeaderCount) {
      const r = shouldBlock(431, "Request Header Fields Too Large", ctx);
      if (r) return r;
    }
    if (CFG.maxHeaderSize > 0 && headerSize > CFG.maxHeaderSize) {
      const r = shouldBlock(431, "Request Header Fields Too Large", ctx);
      if (r) return r;
    }
    const qs = url.search.slice(1);
    if (qs.length > CFG.maxQueryLength) {
      const r = shouldBlock(414, "URI Too Long", ctx);
      if (r) return r;
    }
    let queryCount = qs ? 1 : 0;
    for (let i = qs.indexOf("&"); i !== -1; i = qs.indexOf("&", i + 1)) queryCount++;
    if (queryCount > CFG.maxQueryParams) {
      const r = shouldBlock(400, "Too many query params", ctx);
      if (r) return r;
    }
    const anomalyBlock = blockIfRequestAnomaly(request, rawPathname, qs, ctx);
    if (anomalyBlock) return anomalyBlock;
    if ((CFG.normalizePath || {}).rejectAmbiguousEncoding !== !1 && (hasAmbiguousPathEncoding(rawPathname) || hasAmbiguousPathEncoding(url.pathname))) {
      const r = shouldBlock(400, "Bad Request", ctx);
      if (r) return r;
    }
    const rawPathBlock = blockIfPathPattern(rawPathname, ctx);
    if (rawPathBlock) return rawPathBlock;
    const canonical = normalizePath(rawPathname);
    if (canonical === null) {
      const r = shouldBlock(400, "Bad Request", ctx);
      if (r) return r;
    } else
      url.pathname = canonical;
    const normalizedPathBlock = CFG.mode !== "monitor" && url.pathname === rawPathname ? null : blockIfPathPattern(url.pathname, ctx);
    if (normalizedPathBlock) return normalizedPathBlock;
    for (const h of CFG.requiredHeaders)
      if (!request.headers.get(h)) {
        const r = shouldBlock(400, "Missing " + h, ctx);
        if (r) return r;
      }
    const ua = request.headers.get("user-agent") || "";
    if (ua && ua.length > 512) {
      const r = shouldBlock(400, "User-Agent Too Long", ctx);
      if (r) return r;
    }
    const uaLower = ua.toLowerCase(), challenge = null;
    if (challenge) return challenge;
    for (const s of CFG.uaDenyContains)
      if (uaLower.includes(s)) {
        const r = shouldBlock(403, "Forbidden", ctx);
        if (r) return r;
      }
    if (CFG.dropQueryKeys.size > 0) {
      const params = url.searchParams;
      for (const key of CFG.dropQueryKeys) params.has(key) && params.delete(key);
      url.search = params.toString();
    }
    const bodyState = { body: request.body };
    try {
      let signedUrlNonce = null;
      const matchPath = normalizeForMatch(url.pathname), gateIds = CFG.authGateIndex ? pathCandidates(matchPath.slice(0, CFG.authGateIndexMaxLength + 1), CFG.authGateIndex) : authGateIds;
      for (const gateIndex of gateIds) {
        const gate = CFG.authGates[gateIndex], prefixes = authMatchPrefixes[gateIndex];
        if ((gate.type === "signed_url" && gate.exact_path === !0 ? prefixes.some((p) => pathMatchesExact(matchPath, p)) : CFG.authGateIndex || prefixes.some((p) => pathMatchesPrefix(matchPath, p))) && gate.type === "static_token") {
          const tok = request.headers.get(gate.tokenHeaderName) || "", expectedToken = env[gate.tokenEnv] || "";
          if (!expectedToken)
            return console.error("[auth] static_token env missing:", gate.tokenEnv), shouldBlockAuth(503, "Auth misconfigured", ctx);
          if (!timingSafeEqual(tok, expectedToken))
            return shouldBlockAuth(401, "Unauthorized", ctx);
        }
      }
      const forwardHeaders = new Headers(request.headers);
      forwardHeaders.delete("x-edge-authenticated"), forwardHeaders.delete("x-csp-nonce");
      let cspNonce = "";
      CFG.trustForwardedFor || forwardHeaders.delete("x-forwarded-for");
      for (const h of ["transfer-encoding", "connection", "keep-alive", "te", "upgrade", "proxy-connection", "proxy-authenticate", "proxy-authorization", "trailer"])
        forwardHeaders.delete(h);
      signedUrlNonce && forwardHeaders.set("X-Signed-URL-Nonce", signedUrlNonce);
      let forwardedCorrelationId = ctx.correlationId;
      if (CFG.obs && CFG.obs.correlationHeader && !request.headers.get(CFG.obs.correlationHeader)) {
        const buf = new Uint8Array(16);
        crypto.getRandomValues(buf);
        const id = Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
        forwardHeaders.set(CFG.obs.correlationHeader, id), forwardedCorrelationId = id;
      }
      const res = await fetch(new Request(url.toString(), {
        method: request.method,
        headers: forwardHeaders,
        body: bodyState.body,
        redirect: request.redirect,
        duplex: "half"
      }));
      bodyState.body = null;
      const out = new Response(res.body, res), rh = RESPONSE_CFG.headers;
      rh["strict-transport-security"] && out.headers.set("Strict-Transport-Security", rh["strict-transport-security"]), rh["x-content-type-options"] && out.headers.set("X-Content-Type-Options", rh["x-content-type-options"]), rh["referrer-policy"] && out.headers.set("Referrer-Policy", rh["referrer-policy"]), rh["permissions-policy"] && out.headers.set("Permissions-Policy", rh["permissions-policy"]), RESPONSE_CFG.coop && out.headers.set("Cross-Origin-Opener-Policy", RESPONSE_CFG.coop), RESPONSE_CFG.coep && out.headers.set("Cross-Origin-Embedder-Policy", RESPONSE_CFG.coep), RESPONSE_CFG.corp && out.headers.set("Cross-Origin-Resource-Policy", RESPONSE_CFG.corp), RESPONSE_CFG.reporting_endpoints && out.headers.set("Reporting-Endpoints", RESPONSE_CFG.reporting_endpoints);
      const isAdminPath = RESPONSE_CFG.adminPathIndex ? pathHasMatch(matchPath.slice(0, RESPONSE_CFG.adminPathIndexMaxLength + 1), RESPONSE_CFG.adminPathIndex) : adminMatchPrefixes.some((p) => pathMatchesPrefix(matchPath, p)), isAuthPath = RESPONSE_CFG.authPathIndex ? pathHasMatch(matchPath.slice(0, RESPONSE_CFG.authPathIndexMaxLength + 1), RESPONSE_CFG.authPathIndex) : protectedMatchPrefixes.some((p) => pathMatchesPrefix(matchPath, p));
      cspNonce && out.headers.set("X-CSP-Nonce", cspNonce);
      const applyNonce = (csp) => !csp || !cspNonce ? csp : csp.split("'nonce-PLACEHOLDER'").join("'nonce-" + cspNonce + "'");
      isAdminPath ? (RESPONSE_CFG.adminCacheControl && out.headers.set("Cache-Control", RESPONSE_CFG.adminCacheControl), RESPONSE_CFG.csp_admin && out.headers.set("Content-Security-Policy", applyNonce(RESPONSE_CFG.csp_admin))) : RESPONSE_CFG.csp_public && out.headers.set("Content-Security-Policy", applyNonce(RESPONSE_CFG.csp_public)), RESPONSE_CFG.csp_report_only && out.headers.set("Content-Security-Policy-Report-Only", applyNonce(RESPONSE_CFG.csp_report_only)), RESPONSE_CFG.forceVaryAuth && isAuthPath && (out.headers.set("Cache-Control", "no-store, no-cache, must-revalidate, private"), out.headers.set("Pragma", "no-cache"), appendVary(out.headers, "Authorization"), appendVary(out.headers, "Cookie"));
      const status = out.status, isSuccess = status >= 200 && status < 400;
      if ((RESPONSE_CFG.clearSiteDataPaths || []).some(
        (p) => url.pathname === p || url.pathname.startsWith(p + "/")
      ) && isSuccess && (clearSiteDataValue && out.headers.set("Clear-Site-Data", clearSiteDataValue), out.headers.set("Cache-Control", "no-store")), out.headers.delete("x-powered-by"), out.headers.delete("server"), RESPONSE_CFG.cookie_attributes) {
        const attrs = [];
        if (RESPONSE_CFG.cookie_attributes.secure && attrs.push("Secure"), RESPONSE_CFG.cookie_attributes.http_only && attrs.push("HttpOnly"), RESPONSE_CFG.cookie_attributes.same_site && attrs.push("SameSite=" + RESPONSE_CFG.cookie_attributes.same_site), attrs.length > 0) {
          const h = out.headers, cookies = typeof h.getSetCookie == "function" ? h.getSetCookie() : out.headers.get("set-cookie") ? [out.headers.get("set-cookie")] : [];
          if (cookies.length > 0) {
            out.headers.delete("set-cookie");
            for (const cookie of cookies) {
              const needsSecure = RESPONSE_CFG.cookie_attributes.secure && !/(?:^|; *)Secure(?:;|$)/i.test(cookie), needsHttpOnly = RESPONSE_CFG.cookie_attributes.http_only && !/(?:^|; *)HttpOnly(?:;|$)/i.test(cookie), needsSameSite = RESPONSE_CFG.cookie_attributes.same_site && !/(?:^|; *)SameSite=/i.test(cookie);
              if (needsSecure || needsHttpOnly || needsSameSite) {
                const missing = [];
                needsSecure && missing.push("Secure"), needsHttpOnly && missing.push("HttpOnly"), needsSameSite && missing.push("SameSite=" + RESPONSE_CFG.cookie_attributes.same_site), out.headers.append("Set-Cookie", cookie + "; " + missing.join("; "));
              } else
                out.headers.append("Set-Cookie", cookie);
            }
          }
        }
      }
      return out;
    } finally {
      cancelForwardBody(bodyState);
    }
  }
};
export {
  stdin_default as default
};
