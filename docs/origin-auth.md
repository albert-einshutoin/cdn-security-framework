# Origin Authentication

`origin.auth` protects the CDN-to-origin hop. Use `custom_header` for simple allowlisting, or `hmac_signature` when the origin must reject copied headers, modified paths, reordered query strings, or stale replays.

## HMAC Signature Mode

```yaml
origin:
  auth:
    type: hmac_signature
    secret_env: ORIGIN_AUTH_SECRET
    header_prefix: X-CDN-Auth
    timestamp_tolerance_seconds: 300
    include_body_hash: false
    signed_components: [method, path, query, body, timestamp, nonce]
```

Generated runtimes read the secret from `secret_env`. The policy stores only the env var name.

Headers emitted to the origin:

- `X-CDN-Auth-Timestamp`
- `X-CDN-Auth-Nonce`
- `X-CDN-Auth-Body-SHA256` when `include_body_hash: true`
- `X-CDN-Auth-Signature`

Canonical input is the configured `signed_components`, joined by `\n`. The default is:

```text
METHOD
PATH
CANONICAL_QUERY
BODY_SHA256_OR_EMPTY
TIMESTAMP
NONCE
```

`CANONICAL_QUERY` sorts decoded query pairs by key, then value, and re-encodes them with `encodeURIComponent`. Duplicate keys are preserved. Signature format is base64url HMAC-SHA256.
Custom component lists must still include `timestamp` and `nonce`; otherwise the replay headers would not be bound to the signature.

## Replay Limits

The timestamp limits replay to `timestamp_tolerance_seconds`; the nonce lets your application reject second use inside that window. The edge is stateless, so nonce replay protection must live at the origin, for example Redis `SET key value NX EX 300`.

## Body Hash

`include_body_hash: false` is the default because not every edge phase can read bodies cheaply. Set it to `true` only when the runtime can read the body and the origin needs payload binding. AWS Lambda@Edge refuses to sign truncated request bodies, or requests where headers show a payload was sent but CloudFront did not include the body. Legitimately empty requests still sign the empty SHA-256 digest.

## Node / Express Verification

```js
const crypto = require('crypto');

function canonicalQuery(searchParams) {
  return [...searchParams.entries()]
    .sort((a, b) => a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0]))
    .map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v))
    .join('&');
}

function verifyCdnOriginAuth(req, { secret, toleranceSeconds = 300, nonceStore }) {
  const prefix = 'x-cdn-auth';
  const ts = req.get(prefix + '-timestamp');
  const nonce = req.get(prefix + '-nonce');
  const sig = req.get(prefix + '-signature');
  if (!ts || !nonce || !sig) return false;

  const age = Math.abs(Math.floor(Date.now() / 1000) - Number(ts));
  if (!Number.isFinite(age) || age > toleranceSeconds) return false;
  if (nonceStore && !nonceStore.claim(nonce, toleranceSeconds)) return false;

  const url = new URL(req.originalUrl || req.url, 'https://origin.local');
  const bodyHash = req.get(prefix + '-body-sha256') || '';
  const canonical = [
    req.method.toUpperCase(),
    url.pathname,
    canonicalQuery(url.searchParams),
    bodyHash,
    ts,
    nonce,
  ].join('\n');
  const expected = crypto.createHmac('sha256', secret).update(canonical).digest('base64url');
  const a = Buffer.from(expected);
  const b = Buffer.from(sig);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
```

Reject requests with missing headers, stale timestamps, replayed nonces, or signature mismatch. Keep the secret in your origin secret manager and rotate it like other edge HMAC secrets.
