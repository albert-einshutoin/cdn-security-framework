/**
 * CloudFront Functions (Viewer Response) — TEMPLATE
 *
 * 【注意】このファイルはテンプレートです。直接デプロイしないでください。
 * security.yml（または policy/security.yml）を編集し、npx cdn-security build で dist/edge/viewer-response.js を生成してください。
 *
 * Purpose:
 * - Enforce security headers at the CDN (consistent across multiple origins)
 * - Apply path-specific behavior (e.g. no-store for /admin)
 *
 * You can also:
 * - Use Response Headers Policy where possible for easier ops
 * - Introduce CSP gradually with report-only profile first
 */

function set(headers, k, v) { headers[k.toLowerCase()] = { value: v }; }

// {{INJECT_RESPONSE_CONFIG}}

function handler(event) {
  const res = event.response;
  const req = event.request;
  const h = res.headers;

  const rh = RESPONSE_CFG.headers;
  if (rh["strict-transport-security"]) set(h, "Strict-Transport-Security", rh["strict-transport-security"]);
  if (rh["x-content-type-options"]) set(h, "X-Content-Type-Options", rh["x-content-type-options"]);
  if (rh["referrer-policy"]) set(h, "Referrer-Policy", rh["referrer-policy"]);
  if (rh["permissions-policy"]) set(h, "Permissions-Policy", rh["permissions-policy"]);

  const uri = req.uri || "/";
  const isAdminPath = RESPONSE_CFG.adminPathPrefixes.some(function (p) { return uri === p || uri.startsWith(p + "/"); });
  if (isAdminPath) {
    if (RESPONSE_CFG.adminCacheControl) set(h, "Cache-Control", RESPONSE_CFG.adminCacheControl);
    if (RESPONSE_CFG.csp_admin) set(h, "Content-Security-Policy", RESPONSE_CFG.csp_admin);
  } else {
    if (RESPONSE_CFG.csp_public) set(h, "Content-Security-Policy", RESPONSE_CFG.csp_public);
  }

  if (h["x-powered-by"]) delete h["x-powered-by"];

  // Cookie attributes (add Secure, HttpOnly, SameSite to existing Set-Cookie headers)
  if (RESPONSE_CFG.cookie_attributes && h["set-cookie"]) {
    const attrs = [];
    if (RESPONSE_CFG.cookie_attributes.secure) attrs.push('Secure');
    if (RESPONSE_CFG.cookie_attributes.http_only) attrs.push('HttpOnly');
    if (RESPONSE_CFG.cookie_attributes.same_site) attrs.push('SameSite=' + RESPONSE_CFG.cookie_attributes.same_site);
    
    if (attrs.length > 0) {
      const existing = h["set-cookie"].value;
      // Only add attributes if they don't already exist
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
