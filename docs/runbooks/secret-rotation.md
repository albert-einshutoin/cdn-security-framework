# Runbook: Secret Rotation

> **Languages:** English · [日本語](./secret-rotation.ja.md)

This runbook covers rotating the four secrets the framework consumes at build and runtime:

| Env var | Consumer | Rotation class |
| --- | --- | --- |
| `JWT_SECRET` | HS256 JWT gate | Hot (grace window via dual-secret) |
| `JWKS_URL` / kids | RS256 JWT gate | Hot (publish new kid, wait, revoke) |
| `URL_SIGNING_SECRET` | Signed URL gate | Warm (grace window for already-issued URLs) |
| `EDGE_ADMIN_TOKEN` | `static_token` gate | Cold (baked into `dist/edge/` at build time) |
| `ORIGIN_SECRET` | Origin auth header | Hot (coordinated with origin) |

> **Baseline principle**: never rotate to a single new value. Always go through a **dual-secret window**: accept both old and new for long enough to cover in-flight tokens, the longest issued signed URL, and your deploy pipeline's propagation time. Only then revoke the old secret.

---

## 1. Rotate the HS256 JWT secret (`JWT_SECRET`)

HS256 is a symmetric shared secret. Rotation requires issuer + verifier to swap it together. The framework only verifies; the issuer is your identity provider or API.

### Procedure
1. **Pre-flight**: know the JWT lifetime (`exp - iat`) of the longest-lived token you issue. Typical: 1h access, 7d refresh.
2. **Generate** a new 32-byte random secret; store it under a new name:
   ```bash
   openssl rand -base64 32
   ```
   Upload to your secret store with a new key, e.g. `JWT_SECRET_V2`.
3. **Update the issuer** to sign with `V2` but **keep publishing `V1` tokens during the grace window** if your IdP supports dual-sign. If not, skip to step 4 and accept the verifier-side dual accept window instead.
4. **Update the verifier policy** to accept both:
   ```yaml
   routes:
     - name: api
       auth_gate:
         type: jwt
         algorithm: HS256
         secret_envs: ["JWT_SECRET", "JWT_SECRET_V2"]   # verifier tries each
   ```
   Rebuild and deploy `dist/edge/origin-request.js`.
5. **Wait** `max(access_token_ttl, refresh_token_ttl) + clock_skew_sec + deploy_propagation`. For 7-day refresh tokens, plan for 8 days.
6. **Cut over**: update the issuer to only sign with `V2`. Update policy to verify only `V2`. Rebuild and deploy.
7. **Revoke** `JWT_SECRET` from the secret store.

### Verification
- Synthetic canary: issue a token with `V2` and hit `/api/health`; expect 200.
- Log grep: `block_reason: "Invalid token"` on the edge should be flat. If you see spikes, extend the grace window; do not revoke `V1` yet.

---

## 2. Rotate an RS256 JWKS key

RS256 keys are asymmetric; rotation is driven by the `kid` claim and the JWKS endpoint.

### Procedure
1. **Publish** a new key to the JWKS endpoint with a new `kid`. Keep the old key in the JWKS response.
2. **Update the issuer** to start signing with the new `kid`.
3. **Wait** `firewall.jwks.cache_ttl_sec + firewall.jwks.stale_if_error_sec + max_token_ttl`. The framework caches JWKS responses, so until the cached response is refreshed, the edge will not see the new `kid`.
4. **Remove** the old key from the JWKS endpoint.
5. **Wait** another `cache_ttl_sec` for the removal to propagate.
6. **Verify** that tokens signed by the old key now return `401 block_reason: "Unknown kid"`.

### Pitfalls
- If `firewall.jwks.cache_ttl_sec` is large (e.g. 1h), step 3 must wait a full hour *plus* token TTL. Short TTLs give faster rotation but more JWKS endpoint load.
- Never remove the old kid *before* waiting the cache window. Issued tokens carrying the old kid will fail and users will be logged out mid-session.

---

## 3. Rotate the URL signing secret (`URL_SIGNING_SECRET`)

Signed URLs embed a signature computed at issue time. Rotating the secret invalidates every URL already in a user's inbox, email, or share sheet.

### Procedure
1. **Decide a grace window** equal to `max(signed_url.default_ttl, email_delivery_window)`. 72h is a common floor.
2. **Generate** `URL_SIGNING_SECRET_V2`.
3. **Update the verifier** to accept both:
   ```yaml
   routes:
     - name: downloads
       auth_gate:
         type: signed_url
         secret_envs: ["URL_SIGNING_SECRET", "URL_SIGNING_SECRET_V2"]
   ```
   Rebuild and deploy.
4. **Update the issuer** (your app) to start signing new URLs with `V2`.
5. **Wait** the grace window.
6. **Remove** `URL_SIGNING_SECRET` from the verifier policy and secret store.

### Hard cutoff for a compromise
If the old secret is compromised, skip the grace window:
1. Rotate the issuer to `V2` immediately.
2. Deploy verifier with **only** `V2`.
3. Accept that already-issued URLs break. Communicate to users ("your previous download link is no longer valid — request a new one").
4. Audit logs for requests that verified against `V1` in the compromise window.

---

## 4. Rotate `EDGE_ADMIN_TOKEN` (static_token gate)

CloudFront Functions cannot read env vars at runtime. The `static_token` gate bakes the token into `dist/edge/viewer-request.js` at **build time**. Rotation therefore requires a rebuild + redeploy, not just a secret-store update.

### Procedure
1. **Generate** a new token: `openssl rand -hex 32`.
2. **Update the secret store** (`EDGE_ADMIN_TOKEN` value).
3. **Rebuild**: `EDGE_ADMIN_TOKEN=<new> npm run build`.
4. **Deploy** `dist/edge/viewer-request.js` to CloudFront. There is a brief cut-over window (CloudFront global propagation: 2–5 min) where some edges serve the old token, some the new. Plan admin access accordingly.
5. **Communicate** the new token to admin operators.

### Dual-token window (optional)
The static_token gate accepts a single value per build. If you need zero-downtime rotation, temporarily deploy a policy that stacks two routes with the same prefix but different tokens, wait, then collapse to the new token. In practice, for an admin-only path protected by an L7 ACL already, the 5-minute propagation window is acceptable.

---

## 5. Rotate `ORIGIN_SECRET` (origin auth custom header)

The origin auth gate adds a shared-secret header (e.g. `X-Edge-Secret`) to every origin request. Rotation requires the origin (ALB, NGINX, CF Worker, or app) to accept both values during the window.

### Procedure
1. **Generate** `ORIGIN_SECRET_V2`.
2. **Update the origin** to accept requests carrying either `V1` or `V2`.
3. **Rebuild and deploy** the edge with `V2` (the edge forwards a single secret; the origin owns the dual-accept).
4. **Wait** deploy propagation + a conservative buffer (5–15 min).
5. **Update the origin** to accept only `V2`.
6. **Revoke** `V1`.

### Verification
- Synthetic request hitting origin directly (bypassing the edge) with `V1`: expect 401 after step 5.
- Edge request: expect 200 throughout.

---

## Post-rotation verification (applies to all rotations)

After any rotation:

1. **Canary**: a synthetic request that exercises the rotated gate.
2. **Log grep**: spike in `block_reason` related to the rotated credential within the first 10 minutes means the grace window was too short.
3. **User-impact sampling**: check support channels and front-end error rates.
4. **Audit**: verify the old secret is purged from the secret store, CI env, and any cached `.env` files.

---

## Incident rollback

If a rotation causes user-visible failures:

1. **Restore** the old secret to the secret store (you kept it, right? See below).
2. **Revert** the verifier policy to accept both old and new.
3. **Rebuild and deploy**.
4. **Investigate** before re-attempting: likely cause is an under-sized grace window or a cache you didn't account for.

**Always keep the previous secret in an offline vault for at least 24 hours post-rotation.** Do not purge immediately.

---

## Cross-links
- [Auth gates design](../auth.md)
- [Quickstart](../quickstart.md)
- [JWKS caching details](../auth.md#jwks-caching)
