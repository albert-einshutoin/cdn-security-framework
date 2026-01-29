/**
 * CloudFront Functions - Viewer Response
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

function handler(event) {
  const res = event.response;
  const req = event.request;
  const h = res.headers;

  set(h, "Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  set(h, "X-Content-Type-Options", "nosniff");
  set(h, "Referrer-Policy", "strict-origin-when-cross-origin");
  set(h, "Permissions-Policy", "camera=(), microphone=(), geolocation=()");

  const uri = req.uri || "/";
  if (uri.startsWith("/admin")) {
    set(h, "Cache-Control", "no-store");
    set(h, "Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';");
  } else {
    set(h, "Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';");
  }

  // Strip noisy headers from origin if present
  if (h["x-powered-by"]) delete h["x-powered-by"];

  return res;
}
