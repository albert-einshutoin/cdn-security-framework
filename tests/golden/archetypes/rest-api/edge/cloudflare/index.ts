/**
 * Cloudflare Workers — TEMPLATE
 *
 * 【注意】このファイルはテンプレートです。直接デプロイしないでください。
 * security.yml（または policy/security.yml）を編集し、npx cdn-security build --target cloudflare で dist/edge/cloudflare/index.ts を生成してください。
 */

const CFG = {
  mode: "enforce",
  allowMethods: new Set(["GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"]),
  maxQueryLength: 1024,
  maxQueryParams: 30,
  maxUriLength: 2048,
  maxHeaderSize: 0,
  maxHeaderCount: 48,
  dropQueryKeys: new Set(["utm_source","utm_medium","utm_campaign","utm_term","utm_content","gclid","fbclid"]),
  uaDenyContains: ["sqlmap","nikto","acunetix","masscan"],
  blockPathContains: ["/../","%2e%2e"],
  blockPathRegexGroups: [],
  normalizePath: {"collapseSlashes":true,"removeDotSegments":true,"caseInsensitive":true,"rejectAmbiguousEncoding":true},
  requiredHeaders: ["user-agent"],
  blockedHeaders: [],
  allowedHosts: [],
  trustForwardedFor: false,
  cors: {"allow_origins":["https://app.example.com"],"allow_methods":["GET","POST","PUT","PATCH","DELETE","OPTIONS"],"allow_headers":["authorization","content-type","x-request-id"],"allow_credentials":true,"max_age":600},
  authGates: [{"name":"api","protectedPrefixes":["/api"],"type":"jwt","algorithm":"RS256","allowed_algorithms":["RS256"],"clock_skew_sec":30,"jwks_url":"https://auth.example.com/.well-known/jwks.json","issuer":"https://auth.example.com/","audience":"api.example.com","secret_env":"","cache_ttl_sec":3600}],
  authGateIndex: null,
  authGateIndexMaxLength: 0,
  originAuth: null,
  jwksStaleIfErrorSec: 120,
  jwksNegativeCacheSec: 30,
  geoBlockCountries: new Set([]),
  geoAllowCountries: new Set([]),
  challenge: null,
  graphqlGuard: null,
  anomalyGuards: {"enabled":true,"crlf":true,"malformedCookie":false,"doubleEncodedTraversal":true,"maxCookieBytes":4096,"maxCookiePairs":80},
  obs: {"logFormat":"json","correlationHeader":"traceparent","sampleRate":0,"auditLogAuth":true,"auditHashSub":true},
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
  headers: {"strict-transport-security":"max-age=31536000; includeSubDomains; preload","x-content-type-options":"nosniff","referrer-policy":"no-referrer","permissions-policy":"camera=(), microphone=(), geolocation=()"},
  csp_public: "default-src 'none'; frame-ancestors 'none';",
  csp_admin: "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';",
  csp_report_only: "",
  csp_report_uri: "",
  csp_nonce: false,
  coop: "",
  coep: "",
  corp: "",
  reporting_endpoints: "",
  adminPathPrefixes: ["/api"],
  adminPathIndex: null,
  adminPathIndexMaxLength: 0,
  adminCacheControl: "no-store",
  authProtectedPrefixes: ["/api"],
  authPathIndex: null,
  authPathIndexMaxLength: 0,
  forceVaryAuth: true,
  caseInsensitive: true,
  clearSiteDataPaths: [],
  clearSiteDataTypes: ["cache","cookies","storage"],
  cors: {"allow_origins":["https://app.example.com"],"allow_methods":["GET","POST","PUT","PATCH","DELETE","OPTIONS"],"allow_headers":["authorization","content-type","x-request-id"],"allow_credentials":true,"max_age":600},
  cookie_attributes: null,
  responseDlp: {"enabled":false,"action":"report_only","mask":"[REDACTED]","blockStatus":451,"blockBody":"Response blocked by edge DLP","body":{"enabled":false,"maxBytes":32768,"contentTypes":["text/","application/json","application/xml","text/xml","application/javascript"]},"headers":{"enabled":false,"names":["set-cookie","authorization","x-api-key"]},"detectors":{"builtIn":["api_key","credit_card"],"customRegexNames":[]}},
  responseDlpCustomRegexes: [],
};
const rsaVerifyKeys = /* @__PURE__ */ new WeakMap(), hmacKeys = /* @__PURE__ */ new WeakMap(), jwksCache = /* @__PURE__ */ new Map(), jwksNegativeCache = /* @__PURE__ */ new Map(), jwksRefreshState = /* @__PURE__ */ new Map(), JWKS_REFRESH_WINDOW_MS = 5e3, JWKS_REFRESH_MAX_ATTEMPTS = 2, JWKS_FETCH_TIMEOUT_MS = 2e3, JWKS_MAX_BODY_BYTES = 256 * 1024, JWKS_MAX_KEYS = 100;
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
async function hashSub(sub) {
  if (!sub) return "";
  const data = new TextEncoder().encode(sub), digest = await crypto.subtle.digest("SHA-256", data), bytes = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < bytes.length && hex.length < 16; i++)
    hex += bytes[i].toString(16).padStart(2, "0");
  return hex.slice(0, 16);
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
  for (const group of CFG.blockPathRegexGroups)
    if (!(group.required && !pathname.includes(group.required))) {
      for (const re of group.regexes)
        if (re.test(pathname)) {
          const r = shouldBlock(400, "Bad Request", ctx);
          if (r) return r;
        }
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
function base64UrlToBytes(input) {
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(input.length / 4) * 4, "="), binary = atob(base64), bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
function decodeJwtPart(part) {
  const bytes = base64UrlToBytes(part), text = new TextDecoder().decode(bytes);
  return JSON.parse(text);
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
async function hmacSha256Base64Url(secret, message, owner) {
  let entry = hmacKeys.get(owner);
  if (!entry || entry.secret !== secret) {
    const key2 = crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, !1, ["sign"]);
    entry = { secret, key: key2 }, hmacKeys.set(owner, entry), key2.catch(() => {
      hmacKeys.get(owner) === entry && hmacKeys.delete(owner);
    });
  }
  const key = await entry.key, msgData = new TextEncoder().encode(message), sig = await crypto.subtle.sign("HMAC", key, msgData), bytes = new Uint8Array(sig);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function isUnsafeJwksUrl(rawUrl) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return "malformed URL";
  }
  if (u.protocol !== "https:") return "non-https scheme";
  if (u.username || u.password) return "userinfo present";
  const host = (u.hostname || "").toLowerCase();
  return !host || host === "localhost" ? "loopback hostname" : /^127\./.test(host) || host === "::1" || host === "[::1]" ? "loopback literal" : /^10\./.test(host) ? "rfc1918 10/8" : /^192\.168\./.test(host) ? "rfc1918 192.168/16" : /^172\.(1[6-9]|2\d|3[01])\./.test(host) ? "rfc1918 172.16/12" : /^169\.254\./.test(host) ? "link-local / metadata" : /^0\./.test(host) ? "reserved 0/8" : null;
}
async function readLimitedResponseText(res, maxBytes) {
  const body = res.body;
  if (!body) {
    const text = await res.text();
    if (new TextEncoder().encode(text).byteLength > maxBytes)
      throw new Error("JWKS response too large");
    return text;
  }
  const reader = body.getReader(), chunks = [];
  let total = 0;
  for (; ; ) {
    const chunk = await reader.read();
    if (chunk.done) break;
    if (total += chunk.value.byteLength, total > maxBytes) {
      try {
        await reader.cancel();
      } catch {
      }
      throw new Error("JWKS response too large");
    }
    chunks.push(chunk.value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks)
    merged.set(chunk, offset), offset += chunk.byteLength;
  return new TextDecoder().decode(merged);
}
function validateJwksKeys(body) {
  const keys = Array.isArray(body?.keys) ? body.keys : [];
  if (keys.length > JWKS_MAX_KEYS)
    throw new Error("JWKS key count exceeds limit");
  return keys;
}
async function fetchJwks(jwksUrl, ttlSec, options) {
  const unsafe = isUnsafeJwksUrl(jwksUrl);
  if (unsafe)
    throw new Error("JWKS URL rejected: " + unsafe);
  const now = Date.now(), cached = jwksCache.get(jwksUrl);
  if (!(options?.forceRefresh === !0) && cached && now - cached.fetchedAt < ttlSec * 1e3)
    return cached.keys;
  const staleIfErrorSec = typeof CFG.jwksStaleIfErrorSec == "number" ? CFG.jwksStaleIfErrorSec : 3600, negativeCacheSec = typeof CFG.jwksNegativeCacheSec == "number" ? CFG.jwksNegativeCacheSec : 60, staleWindowMs = (ttlSec + staleIfErrorSec) * 1e3, negativeWindowMs = negativeCacheSec * 1e3, neg = jwksNegativeCache.get(jwksUrl);
  if (neg && now - neg.failedAt < negativeWindowMs) {
    if (cached && now - cached.fetchedAt < staleWindowMs)
      return console.log("[jwks] serving stale keys (negative cache active)"), cached.keys;
    throw new Error("JWKS fetch skipped (negative cache): " + neg.reason);
  }
  let state = jwksRefreshState.get(jwksUrl);
  if (state || (state = { windowStartedAt: now, attempts: 0 }, jwksRefreshState.set(jwksUrl, state)), !state.inFlight) {
    if (now - state.windowStartedAt >= JWKS_REFRESH_WINDOW_MS && (state.windowStartedAt = now, state.attempts = 0), state.attempts >= JWKS_REFRESH_MAX_ATTEMPTS) {
      if (cached && now - cached.fetchedAt < ttlSec * 1e3) return cached.keys;
      throw new Error("JWKS refresh window exhausted");
    }
    state.attempts++;
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), JWKS_FETCH_TIMEOUT_MS);
    state.inFlight = (async () => {
      try {
        const res = await fetch(jwksUrl, { method: "GET", redirect: "manual", signal: controller.signal });
        if (!res.ok)
          throw discardBody(res.body), new Error("Failed to fetch JWKS: " + res.status);
        const bodyText = await readLimitedResponseText(res, JWKS_MAX_BODY_BYTES), keys = validateJwksKeys(JSON.parse(bodyText));
        return jwksCache.set(jwksUrl, { fetchedAt: Date.now(), keys }), jwksNegativeCache.delete(jwksUrl), keys;
      } catch (err) {
        throw jwksNegativeCache.set(jwksUrl, { failedAt: Date.now(), reason: err?.message || "unknown" }), err;
      } finally {
        clearTimeout(timer);
      }
    })();
  }
  const inFlight = state.inFlight;
  try {
    return await inFlight;
  } catch (err) {
    if (cached && Date.now() - cached.fetchedAt < staleWindowMs)
      return console.log("[jwks] refresh failed, serving stale keys:", err?.message), cached.keys;
    throw err;
  } finally {
    state.inFlight === inFlight && (state.inFlight = void 0);
  }
}
function isJwtAlgAllowed(headerAlg, gate, expected) {
  return typeof headerAlg != "string" || headerAlg.length === 0 || headerAlg.toLowerCase() === "none" ? !1 : (Array.isArray(gate?.allowed_algorithms) && gate.allowed_algorithms.length > 0 ? gate.allowed_algorithms : [expected]).includes(headerAlg);
}
function isMatchingRs256Jwk(key, kid) {
  return typeof kid == "string" && kid.length > 0 && key?.kid === kid && key?.kty === "RSA" && (!key.alg || key.alg === "RS256");
}
async function verifyJwt(gate, token, env) {
  const parts = token.split(".");
  if (parts.length !== 3) return { valid: !1, error: "Invalid token format" };
  const [headerB64, payloadB64, signatureB64] = parts;
  let header, payload;
  try {
    header = decodeJwtPart(headerB64), payload = decodeJwtPart(payloadB64);
  } catch {
    return { valid: !1, error: "Malformed JWT" };
  }
  if (!isJwtAlgAllowed(header?.alg, gate, gate.algorithm || "RS256"))
    return { valid: !1, error: "Unexpected JWT algorithm" };
  const skewSec = Number.isFinite(Number(gate?.clock_skew_sec)) ? Number(gate.clock_skew_sec) : 30, nowSec = Math.floor(Date.now() / 1e3);
  if (!Number.isFinite(Number(payload.exp))) return { valid: !1, error: "Missing exp claim" };
  if (nowSec >= Number(payload.exp) + skewSec) return { valid: !1, error: "Token expired" };
  if (payload.nbf && nowSec + skewSec < payload.nbf) return { valid: !1, error: "Token not yet valid" };
  if (gate.issuer && payload.iss !== gate.issuer) return { valid: !1, error: "Invalid issuer" };
  if (gate.audience && !(Array.isArray(payload.aud) ? payload.aud : [payload.aud]).includes(gate.audience))
    return { valid: !1, error: "Invalid audience" };
  const signData = `${headerB64}.${payloadB64}`;
  if (gate.algorithm === "HS256") {
    const secret = env[gate.secret_env] || "";
    if (!secret) return { valid: !1, error: "JWT secret not configured" };
    const expected = await hmacSha256Base64Url(secret, signData, gate);
    return timingSafeEqual(expected, signatureB64) ? { valid: !0, payload } : { valid: !1, error: "Invalid signature" };
  }
  if (gate.algorithm === "RS256") {
    if (!gate.jwks_url) return { valid: !1, error: "JWKS URL missing" };
    try {
      const ttl = gate.cache_ttl_sec || 3600;
      let keys = await fetchJwks(gate.jwks_url, ttl), jwk = keys.find((k) => isMatchingRs256Jwk(k, header.kid));
      if (jwk || (keys = await fetchJwks(gate.jwks_url, ttl, { forceRefresh: !0 }), jwk = keys.find((k) => isMatchingRs256Jwk(k, header.kid))), !jwk)
        return { valid: !1, error: "JWK key not found" };
      let imported = rsaVerifyKeys.get(jwk);
      imported || (imported = crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, !1, ["verify"]), rsaVerifyKeys.set(jwk, imported), imported.catch(() => {
        rsaVerifyKeys.get(jwk) === imported && rsaVerifyKeys.delete(jwk);
      }));
      const verifyKey = await imported;
      return await crypto.subtle.verify(
        "RSASSA-PKCS1-v1_5",
        verifyKey,
        base64UrlToBytes(signatureB64),
        new TextEncoder().encode(signData)
      ) ? { valid: !0, payload } : { valid: !1, error: "Invalid signature" };
    } catch (err) {
      return { valid: !1, error: err?.message || "JWKS verification failed" };
    }
  }
  return { valid: !1, error: "Unsupported JWT algorithm" };
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
function handleCorsPreflight(request) {
  if (request.method !== "OPTIONS" || !CFG.cors) return null;
  const origin = request.headers.get("origin") || "";
  if (!origin) return null;
  const allowedOrigins = CFG.cors.allow_origins || [];
  if (!(allowedOrigins.includes("*") || allowedOrigins.includes(origin))) return null;
  const headers = new Headers({
    "Access-Control-Allow-Origin": origin,
    "Cache-Control": "no-store"
  });
  return appendVary(headers, "Origin"), CFG.cors.allow_methods && headers.set("Access-Control-Allow-Methods", CFG.cors.allow_methods.join(", ")), CFG.cors.allow_headers && headers.set("Access-Control-Allow-Headers", CFG.cors.allow_headers.join(", ")), CFG.cors.allow_credentials && headers.set("Access-Control-Allow-Credentials", "true"), CFG.cors.max_age && headers.set("Access-Control-Max-Age", String(CFG.cors.max_age)), new Response(null, { status: 204, headers });
}
var stdin_default = {
  async fetch(request, env) {
    const url = new URL(request.url), rawPathname = rawPathnameFromRequestUrl(request.url), ctx = reqCtx(request, url.pathname), allowSamplingKey = "";
    for (const header of CFG.blockedHeaders)
      if (request.headers.has(header)) {
        const blocked = shouldBlock(403, "Forbidden Header", ctx);
        if (blocked) return blocked;
      }
    const preflight = handleCorsPreflight(request);
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
        if ((gate.type === "signed_url" && gate.exact_path === !0 ? prefixes.some((p) => pathMatchesExact(matchPath, p)) : CFG.authGateIndex || prefixes.some((p) => pathMatchesPrefix(matchPath, p))) && gate.type === "jwt") {
          const authHeader = request.headers.get("authorization") || "";
          if (!authHeader.startsWith("Bearer "))
            return shouldBlockAuth(401, "Missing or invalid Authorization header", ctx);
          const token = authHeader.slice(7), verified = await verifyJwt(gate, token, env);
          if (!verified.valid)
            return shouldBlockAuth(401, verified.error || "Invalid token", ctx);
          if (CFG.obs && CFG.obs.auditLogAuth) {
            const rawSub = verified.payload && verified.payload.sub || "";
            logEvent("audit", {
              auth_event: "auth_pass",
              gate_type: "jwt",
              gate_name: gate.name || "",
              sub: CFG.obs.auditHashSub ? await hashSub(rawSub) : rawSub,
              method: ctx.method,
              uri: ctx.uri,
              correlation_id: ctx.correlationId
            });
          }
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
      if (RESPONSE_CFG.cors) {
        const origin = request.headers.get("origin") || "", allowedOrigins = RESPONSE_CFG.cors.allow_origins || [], isAllowed = allowedOrigins.includes("*") || allowedOrigins.includes(origin);
        origin && isAllowed && (out.headers.set("Access-Control-Allow-Origin", origin), appendVary(out.headers, "Origin"), RESPONSE_CFG.cors.allow_credentials && out.headers.set("Access-Control-Allow-Credentials", "true"), RESPONSE_CFG.cors.expose_headers?.length > 0 && out.headers.set("Access-Control-Expose-Headers", RESPONSE_CFG.cors.expose_headers.join(", ")));
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
