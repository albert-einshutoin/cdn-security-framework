# Policy Recipes

> **Languages:** English - [日本語](./recipes.ja.md)

Recipes are copyable starting points for common deployments. Paste one into
`policy/security.yml`, replace placeholder domains and environment variable
names, then run the commands below the snippet.

These recipes are more specific than [archetypes](./archetypes.md): an archetype
describes an app shape, while a recipe includes target assumptions, auth mode,
required environment variables, and verification commands.

---

## Cognito JWT API

**Use when:** A JSON API is protected by AWS Cognito RS256 access tokens.
**Primary target:** AWS CloudFront + Lambda@Edge origin-request, or Cloudflare Workers.
**Required env:** `ORIGIN_SECRET` only if you also enable `origin.auth`.

```yaml
version: 1
project: cognito-api
metadata:
  risk_level: strict
  description: Cognito-protected JSON API.
defaults:
  mode: enforce
request:
  allow_methods: [GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE]
  limits:
    max_uri_length: 2048
    max_query_length: 2048
    max_query_params: 64
    max_header_count: 80
  block:
    header_missing: [user-agent]
    ua_contains: [sqlmap, nikto, acunetix]
  normalize:
    path:
      collapse_slashes: true
      remove_dot_segments: true
    drop_query_keys: ["utm_*", gclid, fbclid]
routes:
  - name: api
    match:
      path_prefixes: ["/api"]
    auth_gate:
      type: jwt
      algorithm: RS256
      allowed_algorithms: [RS256]
      jwks_url: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example/.well-known/jwks.json"
      issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example"
      cache_ttl_sec: 3600
response_headers:
  hsts: "max-age=31536000; includeSubDomains; preload"
  x_content_type_options: "nosniff"
  referrer_policy: "no-referrer"
  csp_public: "default-src 'none'; frame-ancestors 'none';"
  cors:
    allow_origins: ["https://app.example.com"]
    allow_methods: [GET, POST, PUT, PATCH, DELETE, OPTIONS]
    allow_headers: [Authorization, Content-Type]
    allow_credentials: true
    max_age: 600
firewall:
  jwks:
    allowed_hosts:
      - "cognito-idp.us-east-1.amazonaws.com"
  waf:
    scope: CLOUDFRONT
    rate_limit: 1000
    managed_rules:
      - AWSManagedRulesCommonRuleSet
      - AWSManagedRulesKnownBadInputsRuleSet
      - AWSManagedRulesIPReputationList
    logging:
      enabled: true
      destination_arn_env: WAF_LOG_DESTINATION_ARN
      redacted_fields: [authorization, cookie]
```

Commands:

```bash
npm run lint:policy -- policy/security.yml
npx cdn-security capabilities --policy policy/security.yml --target aws
npx cdn-security readiness --policy policy/security.yml --target aws --strict
npx cdn-security build --policy policy/security.yml --target aws --out-dir dist
```

Replace the Cognito region, user pool ID, and `firewall.jwks.allowed_hosts`
entry together. Cognito access tokens use `client_id` rather than `aud`; add
`audience` only if you intentionally validate ID tokens. For Cloudflare Workers,
run the same recipe with `--target cloudflare`; keep `allowed_hosts` because
Workers cannot perform low-level DNS safety checks before fetching JWKS.

---

## Next.js or SPA Static Site

**Use when:** CloudFront or Cloudflare serves a built Next.js static export,
React/Vue/Svelte SPA, or static marketing site.
**Primary target:** AWS CloudFront Functions or Cloudflare Workers.
**Required env:** none.

```yaml
version: 1
project: spa-static-site
metadata:
  risk_level: balanced
  description: Static frontend with browser security headers.
defaults:
  mode: enforce
request:
  allow_methods: [GET, HEAD, OPTIONS]
  limits:
    max_uri_length: 2048
    max_query_length: 1024
    max_query_params: 40
    max_header_count: 64
  block:
    header_missing: [user-agent]
    ua_contains: [sqlmap, nikto, acunetix]
  normalize:
    path:
      collapse_slashes: true
      remove_dot_segments: true
    drop_query_keys: ["utm_*", gclid, fbclid]
response_headers:
  hsts: "max-age=31536000; includeSubDomains; preload"
  x_content_type_options: "nosniff"
  referrer_policy: "strict-origin-when-cross-origin"
  permissions_policy: "camera=(), microphone=(), geolocation=()"
  csp_public: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://api.example.com; object-src 'none'; base-uri 'self'; frame-ancestors 'self';"
  cors:
    allow_origins: ["https://www.example.com"]
    allow_methods: [GET, HEAD, OPTIONS]
    allow_headers: [Content-Type]
    max_age: 86400
firewall:
  waf:
    scope: CLOUDFRONT
    rate_limit: 2000
    managed_rules:
      - AWSManagedRulesCommonRuleSet
      - AWSManagedRulesKnownBadInputsRuleSet
```

Commands:

```bash
npm run lint:policy -- policy/security.yml
npx cdn-security capabilities --policy policy/security.yml --target aws
npx cdn-security build --policy policy/security.yml --target aws --out-dir dist
npm run test:runtime
```

If your Next.js deployment is SSR rather than static export, add origin-side
cache controls and review authenticated route caching with
`response_headers.force_vary_auth`.

---

## Internal Admin Panel

**Use when:** A private admin UI sits behind the CDN and needs a simple edge gate
in addition to VPN, IP allowlists, or identity-aware proxy controls.
**Primary target:** AWS CloudFront Functions or Cloudflare Workers.
**Required env:** `EDGE_ADMIN_TOKEN`.

```yaml
version: 1
project: internal-admin
metadata:
  risk_level: strict
  description: Internal admin panel protected by static edge token and WAF allowlist.
defaults:
  mode: enforce
request:
  allow_methods: [GET, HEAD, POST]
  limits:
    max_uri_length: 2048
    max_query_length: 1024
    max_query_params: 40
    max_header_count: 64
  block:
    header_missing: [user-agent]
    ua_contains: [sqlmap, nikto, acunetix, curl, wget, python-requests]
  normalize:
    path:
      collapse_slashes: true
      remove_dot_segments: true
routes:
  - name: admin
    match:
      path_prefixes: ["/"]
    auth_gate:
      type: static_token
      header: x-edge-admin-token
      token_env: EDGE_ADMIN_TOKEN
    response:
      cache_control: "no-store, no-cache, must-revalidate"
response_headers:
  hsts: "max-age=31536000; includeSubDomains; preload"
  x_content_type_options: "nosniff"
  referrer_policy: "no-referrer"
  permissions_policy: "camera=(), microphone=(), geolocation=(), payment=()"
  csp_admin: "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';"
  force_vary_auth: true
firewall:
  ip:
    allowlist:
      - "203.0.113.0/24"
  waf:
    scope: CLOUDFRONT
    rate_limit: 500
    managed_rules:
      - AWSManagedRulesCommonRuleSet
      - AWSManagedRulesKnownBadInputsRuleSet
      - AWSManagedRulesIPReputationList
      - AWSManagedRulesAnonymousIpList
    logging:
      enabled: true
      destination_arn_env: WAF_LOG_DESTINATION_ARN
      redacted_fields: [authorization, cookie, x-api-key]
```

Commands:

```bash
export EDGE_ADMIN_TOKEN=replace-with-a-strong-random-token
npm run lint:policy -- policy/security.yml
npx cdn-security readiness --policy policy/security.yml --target aws --strict
npx cdn-security build --policy policy/security.yml --target aws --out-dir dist
```

Treat the static token as a short-term edge guard, not the only admin identity
control. Rotate it through your CDN/IaC secret flow and pair it with SSO.

---

## Signed Download URLs

**Use when:** Private files are served from an origin path and links should expire
without exposing a long-lived bearer token.
**Primary target:** AWS Lambda@Edge origin-request or Cloudflare Workers.
**Required env:** `URL_SIGNING_SECRET`; `ORIGIN_SECRET` if origin auth is enabled.

```yaml
version: 1
project: signed-downloads
metadata:
  risk_level: strict
  description: Expiring signed URLs for private downloads.
defaults:
  mode: enforce
request:
  allow_methods: [GET, HEAD]
  limits:
    max_uri_length: 2048
    max_query_length: 1024
    max_query_params: 16
    max_header_count: 64
  block:
    header_missing: [user-agent]
  normalize:
    path:
      collapse_slashes: true
      remove_dot_segments: true
routes:
  - name: private-downloads
    match:
      path_prefixes: ["/downloads"]
    auth_gate:
      type: signed_url
      algorithm: HMAC-SHA256
      secret_env: URL_SIGNING_SECRET
      expires_param: exp
      signature_param: sig
      nonce_param: nonce
    response:
      cache_control: "private, no-store"
response_headers:
  hsts: "max-age=31536000; includeSubDomains; preload"
  x_content_type_options: "nosniff"
  referrer_policy: "no-referrer"
  csp_public: "default-src 'none'; frame-ancestors 'none';"
  force_vary_auth: true
origin:
  auth:
    type: hmac_signature
    secret_env: ORIGIN_SECRET
    header_prefix: X-Edge-Origin
    signed_components: [method, path, query, timestamp, nonce]
    timestamp_tolerance_seconds: 300
    include_body_hash: false
firewall:
  waf:
    scope: CLOUDFRONT
    rate_limit: 1000
    managed_rules:
      - AWSManagedRulesCommonRuleSet
      - AWSManagedRulesKnownBadInputsRuleSet
```

Commands:

```bash
export URL_SIGNING_SECRET=replace-with-url-signing-secret
export ORIGIN_SECRET=replace-with-origin-hmac-secret
npm run lint:policy -- policy/security.yml
npx cdn-security readiness --policy policy/security.yml --target aws --strict
npx cdn-security build --policy policy/security.yml --target aws --out-dir dist
npm run test:runtime
```

`nonce_param` forwards `X-Signed-URL-Nonce` to the origin. The origin must enforce
single use, for example with a Redis `SET NX` or equivalent write.

---

## Cloudflare GraphQL API

**Use when:** A GraphQL API needs bounded body inspection and optional response
DLP at the Worker layer.
**Primary target:** Cloudflare Workers.
**Required env:** `ORIGIN_SECRET` if HMAC origin auth is enabled.

```yaml
version: 1
project: cloudflare-graphql-api
metadata:
  risk_level: strict
  description: Cloudflare GraphQL API with body guard and response DLP report-only rollout.
defaults:
  mode: enforce
request:
  allow_methods: [GET, HEAD, OPTIONS, POST]
  limits:
    max_uri_length: 2048
    max_query_length: 2048
    max_query_params: 64
    max_header_count: 80
  graphql_guard:
    endpoint_paths: ["/graphql"]
    max_depth: 8
    max_aliases: 20
    max_fields: 200
    max_body_bytes: 65536
    mode: block
  block:
    header_missing: [user-agent]
    ua_contains: [sqlmap, nikto, acunetix]
  normalize:
    path:
      collapse_slashes: true
      remove_dot_segments: true
response_headers:
  hsts: "max-age=31536000; includeSubDomains; preload"
  x_content_type_options: "nosniff"
  referrer_policy: "no-referrer"
  csp_public: "default-src 'none'; frame-ancestors 'none';"
  cors:
    allow_origins: ["https://app.example.com"]
    allow_methods: [GET, POST, OPTIONS]
    allow_headers: [Authorization, Content-Type]
    allow_credentials: true
    max_age: 600
response_dlp:
  enabled: true
  action: report_only
  body:
    enabled: true
    max_bytes: 32768
    content_types: ["application/json", "text/"]
  headers:
    enabled: true
    names: [set-cookie, authorization, x-api-key]
  detectors:
    built_in: [api_key, credit_card]
origin:
  auth:
    type: hmac_signature
    secret_env: ORIGIN_SECRET
    header_prefix: X-Edge-Origin
    signed_components: [method, path, query, timestamp, nonce]
    timestamp_tolerance_seconds: 300
    include_body_hash: false
firewall:
  waf:
    scope: CLOUDFRONT
    rate_limit: 1000
    managed_rules:
      - AWSManagedRulesCommonRuleSet
```

Commands:

```bash
export ORIGIN_SECRET=replace-with-origin-hmac-secret
npm run lint:policy -- policy/security.yml
npx cdn-security capabilities --policy policy/security.yml --target cloudflare
npx cdn-security readiness --policy policy/security.yml --target cloudflare --strict
npx cdn-security build --policy policy/security.yml --target cloudflare --out-dir dist
npm run test:runtime
```

Start `response_dlp.action` at `report_only`, review Worker logs for
`response_dlp_report_only`, then promote to `mask` or `block` after tuning.

---

## Recipe Maintenance

Run these checks after editing recipes:

```bash
npm run lint:policy -- policy/base.yml
npm run test:security-baseline
git diff --check
```

`test:security-baseline` includes a lightweight freshness check that both
English and Japanese recipe docs exist and retain the five core recipe headings.
