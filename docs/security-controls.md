# Policy Security Controls

> **Languages:** English · [日本語](./security-controls.ja.md)

These examples use the schema2 candidate installed as described in the [Quickstart](quickstart.md). Run the local binary in a separate empty consumer directory; the examples compile artifacts and do not deploy anything. They complement the [auth operational notes](auth.md) and [anomaly guard reference](request-anomaly-guards.md).

## Host, forwarded IP, paths and auth header names

Save this complete policy as `http-controls.yml`:

```yaml
version: 2
request:
  allow_methods: [GET, HEAD, OPTIONS]
  allowed_hosts: [API.example.test, '*.edge.example.test']
  trust_forwarded_for: false
  block:
    path_patterns:
      contains: ['/.env', '/../', '%2e%2e', '%2f..', '..%2f', '%5c']
      regex: ['^/internal(?:/|$)']
  anomaly_guards:
    enabled: true
    crlf: true
    malformed_cookie: true
    double_encoded_traversal: true
    max_cookie_bytes: 4096
    max_cookie_pairs: 80
response_headers: {}
routes:
  - name: admin
    match: { path_prefixes: ['/admin'] }
    auth_gate:
      type: static_token
      header: X-Admin-Token
      token_env: EDGE_ADMIN_TOKEN
```

```bash
EDGE_ADMIN_TOKEN=docs-fixture-token-not-for-deploy node node_modules/cdn-security-framework/scripts/policy-lint.js http-controls.yml
EDGE_ADMIN_TOKEN=docs-fixture-token-not-for-deploy ./node_modules/.bin/cdn-security build -p http-controls.yml --target aws --out-dir out-http-aws
EDGE_ADMIN_TOKEN=docs-fixture-token-not-for-deploy ./node_modules/.bin/cdn-security build -p http-controls.yml --target cloudflare --out-dir out-http-cf
```

The token above is a public synthetic fixture, never a production credential. A build does not provision Worker runtime secrets; deployed Workers need the corresponding secret binding separately.

| Control | Behavior and caveat |
| --- | --- |
| `request.allowed_hosts` | Exact names and `*.` suffix wildcards are case-insensitive. The runtime ignores the incoming Host's port suffix: `API.example.test:8443` matches, so this is not a port restriction. `*.edge.example.test` matches a subdomain, not `edge.example.test` itself. A mismatch returns 400 in enforce mode. Omitted or empty means no Host allowlist; this does not establish DNS/TLS ownership. |
| `request.trust_forwarded_for` | Defaults to `false`: incoming `x-forwarded-for` is stripped before origin forwarding. Set `true` only behind a controlled upstream proxy that sanitizes/replaces the header, and only when ingress prevents clients from bypassing that proxy. This switch does not authenticate a proxy or make arbitrary client-supplied IPs trustworthy; spoofed values can poison origin IP decisions and audit data. |
| `request.block.path_patterns` | Use the typed object: `contains` holds literal substrings, while `regex` holds JavaScript RegExp sources compiled at build time. These are not glob patterns. Nonempty custom lists replace the built-in path-pattern defaults; this example retains their literal traversal entries. Prefer bounded, simple expressions; invalid expressions and detected nested-quantifier shapes such as `(a+)+` are rejected. This is not a complete regex performance analysis. These are edge-runtime controls, not a promise that the same expressions run in provider WAF rules. |
| `routes[].auth_gate.header` | For `static_token`, `X-Admin-Token` and the HTTP name `x-admin-token` address the same header. AWS normalizes the configured lookup name; Workers use the case-insensitive Headers API. This does not lowercase the credential value. Basic/JWT use `Authorization`; their required `Basic ` / `Bearer ` prefixes and credential bytes are not made case-insensitive by this setting. |

Use enforce mode for the pass/block behavior above; monitor mode can forward would-be policy blocks and is not equivalent protection.

## JWT verifier and clock tolerance (Cloudflare)

Save as `jwt-controls.yml`:

```yaml
version: 2
request:
  allow_methods: [GET]
response_headers: {}
routes:
  - name: api
    match: { path_prefixes: ['/api'] }
    auth_gate:
      type: jwt
      algorithm: HS256
      allowed_algorithms: [HS256]
      clock_skew_sec: 30
      secret_env: EDGE_JWT_SECRET
      issuer: https://idp.example.test
      audience: example-api
```

```bash
EDGE_JWT_SECRET=docs-fixture-secret-not-for-deploy node node_modules/cdn-security-framework/scripts/policy-lint.js jwt-controls.yml
EDGE_JWT_SECRET=docs-fixture-secret-not-for-deploy ./node_modules/.bin/cdn-security build -p jwt-controls.yml --target cloudflare --out-dir out-jwt
```

- `auth_gate.clock_skew_sec` tolerates clock differences for `exp` and `nbf`. The default is 30 seconds; policy input must be an integer from 0 through 600. Larger tolerance widens acceptance near token time boundaries; it does not fix an incorrect issuer, audience or signature.
- `auth_gate.allowed_algorithms` defaults to the gate's configured `algorithm`. It constrains the JWT header `alg`; it does not select a different verifier. For example, `algorithm: RS256` with `allowed_algorithms: [HS256]` fails at build time. Never combine HMAC and public-key algorithms as a rotation shortcut. `none` is rejected; adding it or another algorithm does not create an alternate verification path.
- This example is Cloudflare-only. AWS builds reject JWT and signed-URL gates because their former origin-request verification could be skipped on cache hits. Do not remove authentication to make an AWS build pass; follow the [migration guidance](auth.md#aws-authentication-support-and-migration).
- The public synthetic secret is only for local compilation. Configure real runtime secrets separately; compilation is not token verification or deployment evidence. RS256 additionally needs a pinned `firewall.jwks.allowed_hosts` and the [JWKS restrictions](auth.md#jwks-cache-lifecycle).

## Raw anomaly checks

The `anomaly_guards` block in `http-controls.yml` opts into the existing pre-normalization checks. It is disabled unless `enabled: true`; each individual check then defaults to true. In enforce mode:

- `crlf` rejects raw CR/LF and `%0d`/`%0a` indicators in URI, query and header values, including CloudFront query-object values and header `multiValue` entries.
- `double_encoded_traversal` detects bounded double-encoded indicators such as `%252e%252e`; it performs at most one extra decode when `%25` is present.
- `malformed_cookie` checks delimiter structure, control characters and the size/pair limits, including CloudFront cookie maps before flattening. The default limits are 4096 bytes and 80 pairs.

These checks cover what the CDN event or Fetch Headers API actually delivers to the framework. They cannot recover bytes already normalized by a client or CDN, and are not a broad SQLi/XSS scanner or proof of deployed WAF effectiveness. CloudFront viewer-request and Workers implement the guards; Lambda@Edge origin-request does not duplicate them. See [runtime details and rollout](request-anomaly-guards.md).
