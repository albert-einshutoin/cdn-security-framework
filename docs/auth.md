# Auth Gates — Operational Notes

This document covers runtime behaviour of the four auth-gate types
(`static_token`, `basic_auth`, `jwt`, `signed_url`) with focus on
cache lifecycle and timing-oracle resistance.

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
| Fresh | 600 s (AWS) / `cache_ttl_sec` (Cloudflare) | — | Serve from cache without fetching |
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

### Behaviour Matrix

| State | Network call? | Outcome |
|---|---|---|
| Fresh cache hit | No | Serve cached keys |
| Fresh expired + IdP OK | Yes | Refresh + serve new keys |
| Fresh expired + IdP fails + within stale-if-error | Yes (once) | Serve stale cached keys; log warning |
| Fresh expired + IdP fails + outside stale-if-error | Yes (once) | Reject JWT verification |
| Within negative-cache window + stale available | No | Serve stale cached keys; skip fetch |
| Within negative-cache window + no cache | No | Reject JWT verification |
| `kid` not in cache | Yes (once) | Invalidate + refetch — handles IdP key rotation |

### Operational Implications

- **IdP outage** doesn't cause 100% 401 as long as some tokens were
  verified within `stale_if_error_sec` before the outage and the
  isolate / container kept the cache.
- **Key rotation** completes transparently on the first request with the
  new `kid` — cache invalidates, refetches, finds the new key.
- **Broken IdP** (persistent 5xx or DNS failure) is rate-limited to one
  attempt per `negative_cache_sec`. Edge functions stop hammering the
  IdP after the first failure.

### Limits on Coverage

- Edge functions are stateless per-invocation in worst case (new cold
  starts, isolate recycle). Cache hit ratio depends on traffic volume
  and CDN affinity.
- Negative cache is per-isolate / per-container. Two isolates may both
  hit the IdP once during an outage — the protection is best-effort.

## Signed URL Auth Gate

See `docs/signed-urls.md` for signed-URL specifics, including `exact_path`,
`nonce_param`, and single-use enforcement at origin.
