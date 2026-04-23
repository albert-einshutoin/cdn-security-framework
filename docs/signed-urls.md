# Signed URL Hardening

## Purpose

The `signed_url` auth gate grants time-bounded access to a protected resource by binding a URL to an HMAC-SHA256 signature. Without additional constraints, a signed URL can be replayed against sibling paths under the same prefix, or re-used repeatedly until it expires. This document covers two framework-level mitigations:

- **`exact_path`** — scope the signature to a single path (default behaviour matches any path under the gate prefix).
- **`nonce_param`** — bind a per-URL nonce into the HMAC input so the edge can forward a single-use identifier to the origin.

## Threat Model

| Attack | Mitigation |
|---|---|
| Signed URL for `/download/a.pdf` reused against `/download/b.pdf` when both share the same signing secret and prefix | `exact_path: true` |
| Single signed URL replayed by multiple clients (leaked URL, browser back button) | `nonce_param` + origin-side single-use store (edge cannot enforce single-use alone) |
| Signed URL tampered by flipping the nonce value to collide with another user's session | Nonce is included in the HMAC input (`uri + exp + '|' + nonce`), so any change to the nonce invalidates the signature |

## Policy Configuration

```yaml
routes:
  - name: one-time-download
    match:
      path_prefixes: ["/download/"]
    auth_gate:
      type: signed_url
      algorithm: HMAC-SHA256
      secret_env: URL_SIGNING_SECRET
      expires_param: exp
      signature_param: sig
      exact_path: true        # signature is bound to a single URI path
      nonce_param: nonce      # per-URL nonce forwarded to origin as X-Signed-URL-Nonce
```

- `exact_path` defaults to `false` (backwards-compatible prefix match).
- `nonce_param` defaults to `""` (no nonce; signature covers `uri + exp` only).
- `exact_path` and `nonce_param` are independent and may be used separately.

## Signing Rules

The HMAC input is constructed as:

```
signData = uri + exp + ( nonce ? '|' + nonce : '' )
signature = HMAC-SHA256-Hex(secret, signData)
```

The nonce is appended only when `nonce_param` is configured. Existing URLs signed without a nonce continue to work unchanged.

### Nonce Format

The edge runtime enforces a strict nonce format to prevent injection of arbitrary data into downstream logs or single-use stores:

- Length: 16–256 characters
- Charset: `A-Z a-z 0-9 . _ ~ -` (URL-safe unreserved characters)

Malformed nonces are rejected with `403 Malformed nonce` before signature verification runs.

## Origin-Side Single-Use Enforcement

The edge runtime verifies the signature and (if configured) forwards the nonce as `X-Signed-URL-Nonce`. The edge cannot enforce single-use on its own — each CloudFront Function / Worker invocation is stateless. The origin MUST implement atomic single-use:

```ts
// Pseudocode for an origin endpoint
const nonce = req.headers['x-signed-url-nonce'];
if (!nonce) return reject(403, 'Nonce required');

// Redis SET NX with TTL longer than signed URL expiry
const acquired = await redis.set(`nonce:${nonce}`, '1', 'EX', 3600, 'NX');
if (!acquired) return reject(409, 'URL already used');
```

Choose a TTL at least equal to the maximum signed URL lifetime.

## Warning: Write-like Paths Without Nonce

The compiler emits a non-fatal warning when a `signed_url` gate protects a path prefix containing write-like hints (`/api/`, `/write`, `/admin`, `/upload`, `/delete`) without `nonce_param` set:

```
[WARN] Route "admin-upload" uses signed_url on a write-like path ("/admin/upload") without nonce_param.
       Signed URLs can be replayed on write endpoints. Set nonce_param and enforce single-use at origin.
```

Address by either adding `nonce_param` or moving the route to a different auth gate (JWT, static token).

## Runtime Behaviour Summary

| Input | Edge response |
|---|---|
| Valid signature + valid nonce + path matches | 200 (passes through, `X-Signed-URL-Nonce` forwarded) |
| Valid signature, no nonce configured | 200 (passes through) |
| Missing nonce when `nonce_param` set | 403 Missing nonce |
| Malformed nonce (length/charset) | 403 Malformed nonce |
| Signature mismatch (nonce tampered) | 403 Invalid signature |
| `exact_path: true` and URI differs from prefix | Gate does not match → normal routing |
| Expired (`exp < now`) | 403 URL expired |

## Cross-Reference

- Threat model: `docs/threat-model.md` §5 (Auth Gate)
- Policy schema: `policy/schema.json` — `routes[].auth_gate`
- Runtime reference: `runtimes/aws/origin-request.js`, `runtimes/cloudflare/index.ts`
