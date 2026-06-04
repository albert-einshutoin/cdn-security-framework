# ポリシーレシピ

> **言語:** [English](./recipes.md) - 日本語

レシピは、よくあるデプロイ形態向けにそのまま貼り付けられる出発点です。
`policy/security.yml` に貼り付け、ドメイン名と環境変数名を置き換えてから、
snippet 下のコマンドを実行してください。

[アーキタイプ](./archetypes.ja.md) がアプリ形状を表すのに対し、レシピは
target 前提、認証方式、必要な環境変数、検証コマンドまで含む具体例です。

---

## Cognito JWT API

**用途:** AWS Cognito の RS256 access token で JSON API を保護する。
**主 target:** AWS CloudFront + Lambda@Edge origin-request、または Cloudflare Workers。
**必要 env:** `origin.auth` も有効化する場合のみ `ORIGIN_SECRET`。

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
      path_prefixes: ["/api/"]
    auth_gate:
      type: jwt
      algorithm: RS256
      allowed_algorithms: [RS256]
      jwks_url: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example/.well-known/jwks.json"
      issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example"
      audience: "example-client-id"
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

コマンド:

```bash
npm run lint:policy -- policy/security.yml
npx cdn-security capabilities --policy policy/security.yml --target aws
npx cdn-security readiness --policy policy/security.yml --target aws --strict
npx cdn-security build --policy policy/security.yml --target aws --out-dir dist
```

Cognito の region、user pool ID、client ID、`firewall.jwks.allowed_hosts`
を必ず揃えて置き換えてください。Cloudflare Workers でも同じレシピを
`--target cloudflare` で使えます。Workers は JWKS fetch 前の低レベル DNS
検査ができないため、`allowed_hosts` は維持してください。

---

## Next.js or SPA Static Site

**用途:** Next.js static export、React/Vue/Svelte SPA、静的マーケティングサイトを
CloudFront または Cloudflare で配信する。
**主 target:** AWS CloudFront Functions または Cloudflare Workers。
**必要 env:** なし。

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

コマンド:

```bash
npm run lint:policy -- policy/security.yml
npx cdn-security capabilities --policy policy/security.yml --target aws
npx cdn-security build --policy policy/security.yml --target aws --out-dir dist
npm run test:runtime
```

Next.js が static export ではなく SSR の場合は、origin 側の cache-control と
認証付き route の cache 境界を `response_headers.force_vary_auth` と合わせて確認してください。

---

## Internal Admin Panel

**用途:** VPN、IP allowlist、identity-aware proxy と併用しつつ、社内向け管理画面を
簡易 edge gate で保護する。
**主 target:** AWS CloudFront Functions または Cloudflare Workers。
**必要 env:** `EDGE_ADMIN_TOKEN`。

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

コマンド:

```bash
export EDGE_ADMIN_TOKEN=replace-with-a-strong-random-token
npm run lint:policy -- policy/security.yml
npx cdn-security readiness --policy policy/security.yml --target aws --strict
npx cdn-security build --policy policy/security.yml --target aws --out-dir dist
```

static token は短期的な edge guard として扱い、唯一の管理者認証にしないでください。
CDN/IaC の secret flow で rotate し、SSO と併用してください。

---

## Signed Download URLs

**用途:** private file を origin path から配信し、長期 bearer token ではなく期限付きリンクで保護する。
**主 target:** AWS Lambda@Edge origin-request または Cloudflare Workers。
**必要 env:** `URL_SIGNING_SECRET`。origin auth を有効化する場合は `ORIGIN_SECRET`。

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
      path_prefixes: ["/downloads/"]
    auth_gate:
      type: signed_url
      algorithm: HMAC-SHA256
      secret_env: URL_SIGNING_SECRET
      expires_param: exp
      signature_param: sig
      exact_path: true
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

コマンド:

```bash
export URL_SIGNING_SECRET=replace-with-url-signing-secret
export ORIGIN_SECRET=replace-with-origin-hmac-secret
npm run lint:policy -- policy/security.yml
npx cdn-security readiness --policy policy/security.yml --target aws --strict
npx cdn-security build --policy policy/security.yml --target aws --out-dir dist
npm run test:runtime
```

`nonce_param` は `X-Signed-URL-Nonce` を origin に転送します。単回利用の保証は
origin 側で Redis `SET NX` などを使って実装してください。

---

## Cloudflare GraphQL API

**用途:** GraphQL API に Worker layer の body guard と任意の response DLP を適用する。
**主 target:** Cloudflare Workers。
**必要 env:** HMAC origin auth を有効化する場合は `ORIGIN_SECRET`。

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

コマンド:

```bash
export ORIGIN_SECRET=replace-with-origin-hmac-secret
npm run lint:policy -- policy/security.yml
npx cdn-security capabilities --policy policy/security.yml --target cloudflare
npx cdn-security readiness --policy policy/security.yml --target cloudflare --strict
npx cdn-security build --policy policy/security.yml --target cloudflare --out-dir dist
npm run test:runtime
```

`response_dlp.action` は `report_only` から始め、Worker log の
`response_dlp_report_only` を確認してから `mask` または `block` へ上げてください。

---

## レシピのメンテナンス

レシピを編集したら次を実行してください。

```bash
npm run lint:policy -- policy/base.yml
npm run test:security-baseline
git diff --check
```

`test:security-baseline` には、英日レシピ docs が存在し、5 つの主要 recipe heading
を維持しているかを確認する軽量 freshness check が含まれます。
