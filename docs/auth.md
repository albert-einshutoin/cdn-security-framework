# Auth Gates — Operational Notes

This document covers runtime behaviour of the four auth-gate types
(`static_token`, `basic_auth`, `jwt`, `signed_url`) with focus on
cache lifecycle and timing-oracle resistance.


## AWS authentication support and migration

AWS builds reject `jwt` and `signed_url` gates, including in monitor mode and with
`--allow-placeholder-token`. Their origin-request verifier is skipped on
CloudFront cache hits. Viewer-response `no-store`/`Vary` headers cannot disable
CloudFront's internal cache; a cache policy with positive minimum TTL can even
override origin `no-store`. The compiler does not own or verify distribution
cache behaviors, so an operator assertion cannot make this configuration safe.

Use Cloudflare Workers for these gates, or migrate to an independently enforced
viewer-request authentication layer before removing the old gate. Keep protected
traffic blocked during migration and invalidate previously cached protected
responses after correcting the deployed configuration. Rebuilding alone does not
repair an existing deployment. Do not remove authentication just to pass build.
AWS `static_token`/`basic_auth` still authenticate before cache lookup; origin
authentication headers remain available for origin access control.

This is a breaking restriction for the next 2.0 release. Package/schema versions
are not changed by this fix. Restoring AWS JWT/signed URL support requires a
verified per-viewer authentication/deployment contract; there is no bypass flag.
The AWS JWT/JWKS and signed URL implementations have been removed from the generated origin-request template.
The JWT/JWKS sections below describe Cloudflare Workers.

See [AWS trigger order](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-cloudfront-trigger-events.html)
and [cache policies](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-managed-cache-policies.html).

## AWS monitor responses with an unresolved path

With `defaults.mode: monitor`, request paths outside the bounded normalization
model may reach the origin unchanged. When no auth-protected prefixes are configured,
the response function preserves the
origin status and content, applies the global headers and baseline CSP, and
skips route-specific admin matching and `Clear-Site-Data`. It records
`response_path_unknown` using the selected JSON/text log format without adding
the raw path, body, or credentials to that diagnostic.

Such responses receive `no-store`, `Pragma: no-cache`, and `Vary: Authorization,
Cookie` even if `force_vary_auth` is disabled, because path-specific response
behavior is unknown. Enforce mode and policies with any auth-protected prefix retain their
error for an unresolved response path. Keep required auth gates configured;
removing them is not a safe way to enable this behavior. These
viewer-facing headers do not verify or disable CloudFront's internal cache.
Local generated-function checks are not deployed CloudFront evidence.

## Admin Token / Basic Auth Comparison

Both `static_token` and `basic_auth` gates verify the presented credential
via a constant-time compare implemented for CloudFront Functions and
Cloudflare Workers.

Properties:
- Always iterates at least 64 positions regardless of credential length —
  short tokens (the common case) take constant time
- For tokens longer than 64 chars, iteration scales with `max(|a|, |b|)`
  (same behaviour as Go's `hmac.Equal`)
- Length mismatch does NOT short-circuit — length is included in the
  accumulator
- Works identically for both platforms

This blocks the byte-by-byte timing oracle described in threat model §12.

## JWKS Cache Lifecycle

`jwt` gates with `algorithm: RS256` fetch JWKS from `jwks_url`. Three
cache windows are maintained:

| Window | Default | Bound | Meaning |
|---|---|---|---|
| Fresh | `cache_ttl_sec` (Cloudflare) | — | Serve from cache without fetching |
| Stale-if-error | 3600 s | 0..86400 | After refresh fails, keep serving last-known keys |
| Negative cache | 60 s | 0..600 | After refresh fails, skip re-fetching for this window |

Configure globally under `firewall.jwks`:

```yaml
firewall:
  jwks:
    allowed_hosts:
      - idp.example.com
    stale_if_error_sec: 3600
    negative_cache_sec: 60
```

For Cloudflare Worker builds, `firewall.jwks.allowed_hosts` is required when
any RS256 JWT gate is configured. Workers cannot inspect DNS resolution targets
before `fetch`, so the compiler pins JWKS hosts at build time.

JWKS responses are capped at 256 KiB and 100 keys before parsing/caching.
For RS256, the Cloudflare Workers runtime selects JWKs by matching `kid`, requiring
`kty: RSA`, and accepting either an omitted `alg` field or `alg: RS256`.
JWKs with a conflicting `alg` are ignored; the JWT header algorithm allowlist
remains the authority for accepted token algorithms.

### Behaviour Matrix

| State | Network call? | Outcome |
|---|---|---|
| Fresh cache hit | No | Serve cached keys |
| Fresh expired + IdP OK | Yes | Refresh + serve new keys |
| Fresh expired + IdP fails + within stale-if-error | Yes (once) | Serve stale cached keys; log warning |
| Fresh expired + IdP fails + outside stale-if-error | Yes (once) | Reject JWT verification |
| Within negative-cache window + stale available | No | Serve stale cached keys; skip fetch |
| Within negative-cache window + no cache | No | Reject JWT verification |
| `kid` not in cache | If endpoint budget permits | Refresh without deleting cached keys; otherwise reject unknown key |

### Operational Implications

- **IdP outage** doesn't cause 100% 401 as long as some tokens were
  verified within `stale_if_error_sec` before the outage and the
  isolate / container kept the cache.
- **Refresh budget:** each configured JWKS URL has at most two fetch attempts
  (initial load and failures included) per fixed five-second window in each
  Worker isolate. Concurrent cold, expired, and forced fetches share in-flight
  work. Unknown kids create no state; denied requests do not slide the window.
- **Key rotation:** a healthy endpoint can take up to five seconds plus a
  two-second fetch/body deadline to recognize a new key, with continuing requests
  and timely scheduling. Redirects use `manual`; every non-2xx is rejected.
- **Broken IdP:** configured `negative_cache_sec` also delays further attempts.
  Once healthy, fetching resumes when both that TTL and the fixed budget allow
  it. Stale keys require an actual fetch failure and are valid only within
  `cache_ttl_sec + stale_if_error_sec` since the last successful fetch. Exhausting
  the refresh budget alone never authorizes expired keys. A gate TTL shorter
  than five seconds can temporarily fail closed when both attempts are spent.

### Limits on Coverage

- Edge functions are stateless per-invocation in worst case (new cold
  starts, isolate recycle). Cache hit ratio depends on traffic volume
  and CDN affinity.
- Negative cache is per-isolate / per-container. Two isolates may both
  hit the IdP once during an outage — the protection is best-effort.

## Signed URL Auth Gate

See `docs/signed-urls.md` for signed-URL specifics, including `exact_path`,
`nonce_param`, and single-use enforcement at origin.
