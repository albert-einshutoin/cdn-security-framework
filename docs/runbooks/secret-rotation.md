# Runbook: Secret Rotation

> **Languages:** English · [日本語](./secret-rotation.ja.md)

This runbook covers rotating the four secrets the framework consumes at build and runtime:

| Env var | Consumer | Rotation class |
| --- | --- | --- |
| `JWT_SECRET` | HS256 JWT gate | Cold on AWS; coordinated cutover on Cloudflare |
| `JWKS_URL` / kids | RS256 JWT gate | Hot (publish new kid, wait, revoke) |
| `URL_SIGNING_SECRET` | Signed URL gate | Cold; already-issued URLs are invalidated |
| `EDGE_ADMIN_TOKEN` | `static_token` gate | Cold (baked into `dist/edge/` at build time) |
| `ORIGIN_SECRET` | Origin auth header | Cold on AWS; coordinated with origin |

> **Current contract**: `secret_env` accepts one environment-variable name. The framework does not support `secret_envs` or multiple accepted secrets in one gate. Do not model a dual-secret window by stacking identical routes: every matching gate is evaluated, so that configuration requires both credentials rather than either credential. Use RS256/JWKS when verifier-side overlap is required.

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
3. **Schedule a coordinated cutoff** because an HS256 gate accepts one secret. Stop issuing long-lived V1 tokens and wait for their TTL where possible.
4. **Update the existing `JWT_SECRET` value**, switch the issuer to V2, then rebuild and deploy AWS `origin-request.js`. Cloudflare reads the runtime secret, but the issuer and Worker secret still need a coordinated cutover.
5. **Verify** V2 canaries immediately and revoke V1 after propagation. If verifier-side overlap is mandatory, migrate the gate to RS256/JWKS before rotating.

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
2. **Stop issuing V1 URLs** and wait for the grace window if the old secret is not compromised.
3. **Replace** `URL_SIGNING_SECRET`, update the issuer, then rebuild/deploy AWS or update the Cloudflare Worker secret in one coordinated window.
4. **Verify** a newly issued URL and revoke the old value. The framework currently cannot accept old and new signed-URL secrets simultaneously.

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

### No dual-token route workaround
The gate accepts one value per build. Stacking two routes with the same prefix does **not** provide OR semantics; both gates run. Plan a maintenance/cutover window or put a separately managed authenticator in front of the edge.

---

## 5. Rotate `ORIGIN_SECRET` (origin auth)

The origin auth gate adds either a shared-secret header (`custom_header`) or HMAC signature headers (`hmac_signature`) to every origin request. Rotation requires the origin (ALB, NGINX, CF Worker, or app) to accept both values during the window.

### Procedure
1. **Generate** `ORIGIN_SECRET_V2`.
2. **Update the origin** to accept requests carrying either `V1` or `V2`.
3. **Rebuild and deploy** the edge with `V2` (the edge signs/forwards with a single secret; the origin owns the dual-accept).
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
