# Response Security Headers

The `response_headers` section of `policy/security.yml` drives what the viewer-response (AWS CloudFront Functions) and Cloudflare Worker emit back to the client. This document captures the headers the framework owns beyond the familiar HSTS/XCTO/Referrer-Policy/Permissions-Policy quartet — in particular the bits that protect authenticated paths, opt in to cross-origin isolation, and enable a safe CSP rollout.

## Fields

| Key | Type | Default | Notes |
|---|---|---|---|
| `force_vary_auth` | boolean | `true` | When `true`, any path matched by any `auth_gate.match.path_prefixes` receives `Cache-Control: no-store, no-cache, must-revalidate, private` and `Vary: Authorization, Cookie`. Prevents shared-cache mix-ups between identities. Disable only if you know the downstream caches do not key by user. |
| `csp_public` / `csp_admin` | string | safe defaults | CSP strings emitted for non-admin vs. admin paths. `'nonce-PLACEHOLDER'` is substituted at response time when `csp_nonce` is enabled. |
| `csp_nonce` | boolean | `false` | When `true`, the framework injects a per-response nonce into any `'nonce-PLACEHOLDER'` token in `csp_public` / `csp_admin` / `csp_report_only`, and exposes it to the origin via `X-CSP-Nonce`. AWS target uses `Math.random` (non-CS-PRNG — see limits); Cloudflare target uses `crypto.getRandomValues`. |
| `csp_report_only` | string | `""` | If set, emitted as `Content-Security-Policy-Report-Only` alongside the enforced CSP. Use this to A/B a new policy without breaking traffic. |
| `csp_report_uri` | string | `""` | Forwarded verbatim in any `report-uri` / `report-to` directive your policy string uses. Not validated by the framework. |
| `coop` | `same-origin` \| `same-origin-allow-popups` \| `unsafe-none` | unset | `Cross-Origin-Opener-Policy`. |
| `coep` | `require-corp` \| `credentialless` \| `unsafe-none` | unset | `Cross-Origin-Embedder-Policy`. |
| `corp` | `same-site` \| `same-origin` \| `cross-origin` | unset | `Cross-Origin-Resource-Policy`. |
| `reporting_endpoints` | string | `""` | Verbatim `Reporting-Endpoints` value (RFC replacement for `Report-To`). |

## Behavior at a glance

### Cache safety for authenticated paths (`force_vary_auth`)

Previously only the first admin-shaped route received `Cache-Control: no-store`. A JWT or signed-URL gate on `/api` or `/download` would inherit the default cacheability — fine for public assets, a foot-gun for authenticated endpoints.

With `force_vary_auth: true` (default):

1. Build time: the compiler takes the union of `match.path_prefixes` across every `auth_gate` and emits it as `authProtectedPrefixes`.
2. Response time: if the request URI hits any prefix in that union, the response gains:
   - `Cache-Control: no-store, no-cache, must-revalidate, private`
   - `Pragma: no-cache`
   - `Vary: Authorization, Cookie` (merged into any existing `Vary`)

### CSP nonce rollout

1. Set `csp_nonce: true`.
2. Replace any inline `<script>` bootstrap code with `<script nonce="{{NONCE}}">...</script>` at the origin and have the origin read the nonce from the `X-CSP-Nonce` response header the framework forwards.
3. Put `'nonce-PLACEHOLDER'` in your `csp_public` and `csp_admin` strings. The edge substitutes a fresh nonce per response.

### Report-Only rollout

Set `csp_report_only` to the stricter CSP you want to try. The enforced `csp_public` / `csp_admin` keeps the current behaviour; the `Report-Only` copy surfaces violations via your `report-uri`/`report-to` without breaking pages.

### Cross-origin isolation

`coop` + `coep` + `corp` enable crossOriginIsolated contexts (SharedArrayBuffer, high-resolution timers). They are opt-in because `require-corp` will break embedded third-party assets that do not serve `Cross-Origin-Resource-Policy`. Verify your third-party chain first.

## Platform limits

### CloudFront Functions (AWS)

- Multi-value `Set-Cookie` is exposed to CFF as a single joined string. Appending cookie attributes safely requires string-level guards; cookie rewrites that must handle multiple cookies independently should run in Lambda@Edge (`origin-response`) or in the Cloudflare Worker target.
- No Web Crypto API. CSP nonces fall back to `Math.random`. Treat this as a rollout convenience, not as cryptographic defence in depth — prefer the Cloudflare target for production if the nonce property matters. You can also disable `csp_nonce` on AWS and manage nonces at the origin.

### Cloudflare Workers

- Uses `crypto.getRandomValues` (CS-PRNG) for CSP nonces.
- Multi-value `Set-Cookie` handling goes through `Headers#getSetCookie()` when available, falling back to `Headers#get('set-cookie')` on older runtimes. Attribute checks are regex-anchored (`(?:^|; *)Secure(?:;|$)`) to avoid matching substrings of cookie values.

## Example

```yaml
response_headers:
  hsts: "max-age=31536000; includeSubDomains; preload"
  x_content_type_options: "nosniff"
  referrer_policy: "strict-origin-when-cross-origin"
  permissions_policy: "camera=(), microphone=(), geolocation=()"

  force_vary_auth: true

  coop: same-origin
  coep: require-corp
  corp: same-origin
  reporting_endpoints: 'csp="https://reports.example.com/csp", default="https://reports.example.com/default"'

  csp_public: "default-src 'self'; script-src 'self' 'nonce-PLACEHOLDER'; report-to csp"
  csp_admin:  "default-src 'self'; script-src 'self' 'nonce-PLACEHOLDER'; frame-ancestors 'none'"
  csp_nonce: true
  csp_report_only: "default-src 'self'; script-src 'self'; report-to csp"
```

## Threat coverage

- Issue #8 — `force_vary_auth` prevents shared-cache leakage between authenticated users.
- Issue #10 — COOP/COEP/CORP unlock cross-origin-isolation and reduce framing/embedding risk.
- Issue #11 — per-response CSP nonces remove the need for `'unsafe-inline'`.
- Issue #13 — Cloudflare target rewrites Set-Cookie attributes without corrupting multi-cookie responses; AWS target documents the single-cookie limit.
- Issue #19 — `csp_report_only` ships alongside the enforced CSP for safe iterations.
