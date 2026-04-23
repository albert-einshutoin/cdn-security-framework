/**
 * CloudFront Functions (Viewer Response) — TEMPLATE
 *
 * 【注意】このファイルはテンプレートです。直接デプロイしないでください。
 * security.yml（または policy/security.yml）を編集し、npx cdn-security build で dist/edge/viewer-response.js を生成してください。
 *
 * Purpose:
 * - Enforce security headers at the CDN (consistent across multiple origins)
 * - Apply path-specific behavior (e.g. no-store for /admin, Vary on auth paths)
 *
 * Limitations (CloudFront Functions):
 * - The CFF `headers` map is case-insensitive keyed and holds a single { value }
 *   per name. Multiple Set-Cookie values emitted by the origin are visible to
 *   CFF as a single comma-joined string. Rewriting multi-cookie attributes in
 *   CFF can therefore corrupt cookie payloads; real multi-cookie mutation must
 *   run in Lambda@Edge (origin-response) or a Workers runtime.
 * - No Web Crypto API. CSP nonces are derived from Math.random, which is not a
 *   cryptographic PRNG. Use the Cloudflare Worker target (crypto.getRandomValues)
 *   for production CSP nonces, or disable `csp_nonce` on the AWS target.
 */

function set(headers, k, v) { headers[k.toLowerCase()] = { value: v }; }

// {{INJECT_RESPONSE_CONFIG}}

// Non-cryptographic CSP nonce. CloudFront Functions do not expose crypto.
function weakNonce() {
  var chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  var out = '';
  for (var i = 0; i < 22; i++) {
    out += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return out;
}

function handler(event) {
  const res = event.response;
  const req = event.request;
  const h = res.headers;

  const rh = RESPONSE_CFG.headers;
  if (rh["strict-transport-security"]) set(h, "Strict-Transport-Security", rh["strict-transport-security"]);
  if (rh["x-content-type-options"]) set(h, "X-Content-Type-Options", rh["x-content-type-options"]);
  if (rh["referrer-policy"]) set(h, "Referrer-Policy", rh["referrer-policy"]);
  if (rh["permissions-policy"]) set(h, "Permissions-Policy", rh["permissions-policy"]);

  // Cross-Origin isolation headers (issue #10)
  if (RESPONSE_CFG.coop) set(h, "Cross-Origin-Opener-Policy", RESPONSE_CFG.coop);
  if (RESPONSE_CFG.coep) set(h, "Cross-Origin-Embedder-Policy", RESPONSE_CFG.coep);
  if (RESPONSE_CFG.corp) set(h, "Cross-Origin-Resource-Policy", RESPONSE_CFG.corp);

  // Reporting-Endpoints (RFC: replaces Report-To). Verbatim string from policy.
  if (RESPONSE_CFG.reporting_endpoints) set(h, "Reporting-Endpoints", RESPONSE_CFG.reporting_endpoints);

  const uri = req.uri || "/";
  const isAdminPath = RESPONSE_CFG.adminPathPrefixes.some(function (p) { return uri === p || uri.startsWith(p + "/"); });
  // Union of auth-gate prefixes — broader than admin-only; catches jwt/basic/signed_url too.
  const isAuthPath = (RESPONSE_CFG.authProtectedPrefixes || []).some(function (p) {
    return uri === p || uri.startsWith(p + "/");
  });

  // CSP: substitute per-response nonce into any `'nonce-PLACEHOLDER'` in policy strings.
  var nonce = '';
  if (RESPONSE_CFG.csp_nonce) {
    nonce = weakNonce();
    set(h, "X-CSP-Nonce", nonce);
  }
  function applyNonce(csp) {
    if (!csp) return csp;
    if (!nonce) return csp;
    return csp.split("'nonce-PLACEHOLDER'").join("'nonce-" + nonce + "'");
  }

  if (isAdminPath) {
    if (RESPONSE_CFG.adminCacheControl) set(h, "Cache-Control", RESPONSE_CFG.adminCacheControl);
    if (RESPONSE_CFG.csp_admin) set(h, "Content-Security-Policy", applyNonce(RESPONSE_CFG.csp_admin));
  } else {
    if (RESPONSE_CFG.csp_public) set(h, "Content-Security-Policy", applyNonce(RESPONSE_CFG.csp_public));
  }

  // Content-Security-Policy-Report-Only (issue #19). Emitted alongside the enforced CSP
  // so operators can A/B new policies before enforcing. `csp_report_uri` hints the target
  // endpoint but the policy string itself is authoritative.
  if (RESPONSE_CFG.csp_report_only) {
    set(h, "Content-Security-Policy-Report-Only", applyNonce(RESPONSE_CFG.csp_report_only));
  }

  // Force no-store + Vary: Authorization on ANY auth-gate-protected path (issue #8).
  // Prevents a caching proxy/browser from reusing an authenticated response across
  // identities. This is intentionally broader than `adminCacheControl` which only
  // fired for the first matching admin route.
  if (RESPONSE_CFG.forceVaryAuth && isAuthPath) {
    set(h, "Cache-Control", "no-store, no-cache, must-revalidate, private");
    set(h, "Pragma", "no-cache");
    // Append Authorization+Cookie to Vary without clobbering existing Vary.
    var existingVary = (h["vary"] && h["vary"].value) || '';
    var tokens = existingVary.split(',').map(function (s) { return s.trim().toLowerCase(); }).filter(Boolean);
    if (tokens.indexOf('authorization') === -1) tokens.push('Authorization');
    if (tokens.indexOf('cookie') === -1) tokens.push('Cookie');
    set(h, "Vary", tokens.join(', '));
  }

  if (h["x-powered-by"]) delete h["x-powered-by"];
  if (h["server"]) delete h["server"];

  // Cookie attributes (add Secure, HttpOnly, SameSite to existing Set-Cookie headers).
  // NOTE: CFF exposes only a single joined value for Set-Cookie. We guard against
  // multi-cookie corruption by only appending when no existing attribute is present
  // in the joined string. Operators needing strict per-cookie rewriting must use
  // the Lambda@Edge origin-response hook or the Cloudflare Worker target.
  if (RESPONSE_CFG.cookie_attributes && h["set-cookie"]) {
    const attrs = [];
    if (RESPONSE_CFG.cookie_attributes.secure) attrs.push('Secure');
    if (RESPONSE_CFG.cookie_attributes.http_only) attrs.push('HttpOnly');
    if (RESPONSE_CFG.cookie_attributes.same_site) attrs.push('SameSite=' + RESPONSE_CFG.cookie_attributes.same_site);

    if (attrs.length > 0) {
      const existing = h["set-cookie"].value;
      const attrStr = attrs.join('; ');
      if (!existing.includes('Secure') && !existing.includes('HttpOnly') && !existing.includes('SameSite')) {
        h["set-cookie"].value = existing + '; ' + attrStr;
      }
    }
  }

  // CORS headers
  if (RESPONSE_CFG.cors) {
    const origin = req.headers['origin']?.value || '';
    const allowedOrigins = RESPONSE_CFG.cors.allow_origins || [];
    const isAllowed = allowedOrigins.includes('*') || allowedOrigins.includes(origin);

    if (origin && isAllowed) {
      set(h, 'Access-Control-Allow-Origin', origin);
      if (RESPONSE_CFG.cors.allow_credentials) {
        set(h, 'Access-Control-Allow-Credentials', 'true');
      }
      if (RESPONSE_CFG.cors.expose_headers && RESPONSE_CFG.cors.expose_headers.length > 0) {
        set(h, 'Access-Control-Expose-Headers', RESPONSE_CFG.cors.expose_headers.join(', '));
      }
    }
  }

  return res;
}
