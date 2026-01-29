/**
 * Cloudflare Workers
 *
 * Purpose:
 * - Same as CloudFront Functions: entry blocking, normalization, token gate
 * - Response header injection
 *
 * You can also:
 * - Use KV/Durable Objects for stateful rate limiting (beyond what Functions can do)
 * - Extend with bot detection, country/ASN rules, etc.
 */

const CFG = {
    allowMethods: new Set(["GET", "HEAD", "POST"]),
    maxQueryLength: 1024,
    maxQueryParams: 30,
    dropQueryKeys: new Set(["utm_source","utm_medium","utm_campaign","utm_term","utm_content","gclid","fbclid"]),
    uaDenyContains: ["sqlmap","nikto","acunetix","masscan","python-requests"],
    protectedPrefixes: ["/admin","/docs","/swagger"],
    adminTokenHeader: "x-edge-token",
  };

  function deny(code: number, msg: string) {
    return new Response(msg, { status: code, headers: { "cache-control": "no-store" } });
  }

  export default {
    async fetch(request: Request, env: any): Promise<Response> {
      const url = new URL(request.url);

      if (!CFG.allowMethods.has(request.method)) return deny(405, "Method Not Allowed");

      const path = url.pathname.toLowerCase();
      if (path.includes("/../") || path.includes("%2e%2e")) return deny(400, "Bad Request");

      const ua = request.headers.get("user-agent") || "";
      if (!ua) return deny(400, "Missing User-Agent");
      const uaLower = ua.toLowerCase();
      for (const s of CFG.uaDenyContains) if (uaLower.includes(s)) return deny(403, "Forbidden");

      const qs = url.search.slice(1);
      if (qs.length > CFG.maxQueryLength) return deny(414, "URI Too Long");
      const parts = qs ? qs.split("&") : [];
      if (parts.length > CFG.maxQueryParams) return deny(400, "Too many query params");

      // drop keys
      for (const k of CFG.dropQueryKeys) url.searchParams.delete(k);

      // /admin gate
      const isProtected = CFG.protectedPrefixes.some(p => url.pathname === p || url.pathname.startsWith(p + "/"));
      if (isProtected) {
        const tok = request.headers.get(CFG.adminTokenHeader) || "";
        if (tok !== env.EDGE_ADMIN_TOKEN) return deny(401, "Unauthorized");
      }

      // fetch origin
      const res = await fetch(new Request(url.toString(), request));

      // add security headers
      const out = new Response(res.body, res);
      out.headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
      out.headers.set("X-Content-Type-Options", "nosniff");
      out.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
      out.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
      out.headers.set("Content-Security-Policy",
        url.pathname.startsWith("/admin")
          ? "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';"
          : "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';"
      );

      if (url.pathname.startsWith("/admin")) out.headers.set("Cache-Control", "no-store");
      out.headers.delete("x-powered-by");

      return out;
    },
  };
