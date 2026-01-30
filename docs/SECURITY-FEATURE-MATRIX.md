# Security Feature Matrix

This document maps **which security-related YAML settings are supported** by category: **supported / partial / not supported**.

---

## Conclusion: Comprehensive security framework with YAML-driven configuration

- **Supported**: All major security features including Request Hygiene, Response Security, Authentication (Token/Basic/JWT/Signed URL), CORS, Cookie attributes, WAF (rate limit, managed rules, geo, IP), Transport (TLS/HTTP), Origin auth/timeout
- **Partial**: Fingerprint (JA3) depends on WAF/Shield Advanced

---

## 1. Transport (communication protection)

| Feature | Status | Notes |
|---------|--------|-------|
| **TLS version (1.2 / 1.3)** | Supported | `transport.tls.minimum_version` / `security_policy` → `dist/infra/cloudfront-settings.tf.json` |
| **HTTP version (H2 / H3)** | Supported | `transport.http.versions` → `dist/infra/cloudfront-settings.tf.json` |
| **HSTS (HTTPS enforcement)** | Supported | `response_headers.hsts`; injected in viewer-response / Cloudflare. |

---

## 2. Firewall / Access (who gets through)

| Feature | Status | Notes |
|---------|--------|-------|
| **Geo block (country/region)** | Supported | `firewall.geo.block_countries` / `allow_countries` → `dist/infra/geo-restriction.tf.json` |
| **IP allowlist / blocklist** | Supported | `firewall.ip.allowlist` / `blocklist` → `dist/infra/ip-sets.tf.json` |
| **Rate limiting (DDoS)** | Supported | `firewall.waf.rate_limit` → `dist/infra/waf-rules.tf.json` (rate-based rule). |
| **WAF managed rules (SQLi, XSS, OWASP Top 10)** | Supported | `firewall.waf.managed_rules` array → `dist/infra/waf-rules.tf.json` (aws_wafv2_web_acl). |

---

## 3. Authentication

| Feature | Status | Notes |
|---------|--------|-------|
| **Basic auth** | Supported | `routes[].auth_gate.type: basic_auth` with `credentials_env`. Edge template in viewer-request. |
| **Token auth** | Supported | `routes[].auth_gate.type: static_token` with `header` and `token_env` for path-based token gate. |
| **Signed URL** | Supported | `routes[].auth_gate.type: signed_url` with `algorithm`, `secret_env`, `expires_param`, `signature_param`. Lambda@Edge required. |
| **JWT validation** | Supported | `routes[].auth_gate.type: jwt` with `algorithm` (RS256/HS256), `jwks_url`, `issuer`, `audience`. Lambda@Edge required. |

---

## 4. Request Hygiene

| Feature | Status | Notes |
|---------|--------|-------|
| **HTTP method restriction** | Supported | `request.allow_methods` injected in viewer-request / Cloudflare. |
| **URI length limit** | Supported | `request.limits.max_uri_length` → 414 if exceeded. |
| **Query length limit** | Supported | `request.limits.max_query_length` → 414 if exceeded. |
| **Query param count limit** | Supported | `request.limits.max_query_params` → 400 if exceeded. |
| **Header size limit** | Supported | `request.limits.max_header_size` → 431 if exceeded. Lambda@Edge / Cloudflare only. |
| **Path normalization** | Supported | `request.normalize.path.collapse_slashes`, `remove_dot_segments` clean up URIs. |
| **Query normalization** | Supported | `request.normalize.drop_query_keys` strips tracking params (utm_*, gclid, etc.). |
| **Required headers** | Supported | `request.block.header_missing` checks for required headers (generalized, not just UA). |
| **Bot/scanner (User-Agent)** | Supported | `request.block.ua_contains` blocks known scanners. |
| **Fingerprint (JA3)** | Partial | WAF/Shield Advanced dependent. Out of framework scope. |

---

## 5. Response Security (browser protection)

| Feature | Status | Notes |
|---------|--------|-------|
| **Security headers** | Supported | `response_headers` (hsts, x_content_type_options, referrer_policy, permissions_policy, csp_public, csp_admin). |
| **CORS** | Supported | `response_headers.cors` with allow_origins, allow_methods, allow_headers, expose_headers, allow_credentials, max_age. |
| **Cookie attributes** | Supported | `response_headers.cookie_attributes` with secure, http_only, same_site (Strict/Lax/None). |

---

## 6. Origin Security

| Feature | Status | Notes |
|---------|--------|-------|
| **Origin auth (custom header)** | Supported | `origin.auth.type: custom_header` with `header` and `secret_env`. Lambda@Edge injects secret header. |
| **Timeout** | Supported | `origin.timeout.connect` / `read` → `dist/infra/cloudfront-origin.tf.json` |

---

## Summary

| Category | Supported | Partial | Not supported |
|----------|-----------|---------|---------------|
| **Transport** | HSTS, TLS version, HTTP version | — | — |
| **Firewall / Access** | Rate limit, Geo, IP, WAF managed rules | — | — |
| **Authentication** | Token, Basic, JWT, Signed URL | — | — |
| **Request Hygiene** | Method, URI/Query/Header limits, Normalization, UA block, Required headers | Fingerprint (JA3) | — |
| **Response Security** | Security headers, CORS, Cookie attributes | — | — |
| **Origin Security** | Origin auth, Timeout | — | — |

---

## Runtime Support Matrix

| Feature | CloudFront Functions | Lambda@Edge | Cloudflare Workers | Terraform |
|---------|---------------------|-------------|-------------------|-----------|
| URI/Query limits | ✓ | ✓ | ✓ | — |
| Path normalization | ✓ | ✓ | ✓ | — |
| Required headers | ✓ | ✓ | ✓ | — |
| Header size limit | — | ✓ | ✓ | — |
| CORS | ✓ | ✓ | ✓ | — |
| Basic auth | ✓ | ✓ | ✓ | — |
| Cookie attributes | ✓ | ✓ | ✓ | — |
| Geo block | — | — | — | ✓ |
| IP allow/block | — | — | — | ✓ |
| WAF managed rules | — | — | — | ✓ |
| TLS/HTTP version | — | — | — | ✓ |
| JWT validation | — | ✓ | ✓ | — |
| Signed URL | — | ✓ | ✓ | — |
| Origin auth | — | ✓ | ✓ | — |
| Origin timeout | — | — | — | ✓ |

---

## Usage Examples

### JWT Authentication

```yaml
routes:
  - name: api
    match:
      path_prefixes: ["/api"]
    auth_gate:
      type: jwt
      algorithm: RS256
      jwks_url: "https://cognito-idp.region.amazonaws.com/xxx/.well-known/jwks.json"
      issuer: "https://cognito-idp.region.amazonaws.com/xxx"
      audience: "api-client-id"
```

### CORS Configuration

```yaml
response_headers:
  cors:
    allow_origins: ["https://example.com"]
    allow_methods: ["GET", "POST", "OPTIONS"]
    allow_headers: ["Content-Type", "Authorization"]
    allow_credentials: true
    max_age: 86400
```

### Geo Blocking

```yaml
firewall:
  geo:
    block_countries: ["CN", "RU"]
```

This document describes how much of the current implementation is driven by YAML. When adding new features, update this matrix and the schema/compiler accordingly.
