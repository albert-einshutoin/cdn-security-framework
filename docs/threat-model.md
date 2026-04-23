# Threat Model

This document organizes threats that this Edge Security Framework is designed to mitigate, and clarifies which layer (Edge / WAF / Origin) is responsible.

---

## Scope

* **In scope**: Traffic that hits the CDN edge (Viewer Request / Origin Request / Workers fetch).
* **Out of scope**: Internal DB abuse, business logic flaws, post-authentication abuse (handled by application).

---

## Threat Categories

### 1. Path Traversal / LFI

| Threat | Edge responsibility | WAF / Origin |
|--------|---------------------|---------------|
| Obvious `../`, `%2e%2e`, encoded path manipulation in URI | Block early (400) | WAF managed rules for broader patterns; Origin validates path resolution |

**Framework**: Edge blocks coarse patterns (`..\/`, `%2e%2e`, etc.). Full coverage is WAF/Origin.

---

### 2. Unwanted HTTP Methods

| Threat | Edge responsibility | WAF / Origin |
|--------|---------------------|---------------|
| TRACE, CONNECT, arbitrary methods on public paths | Block (405) | — |

**Framework**: `allow_methods` in policy; Edge denies anything not in the list.

---

### 3. Scanner / Automated Abuse (UA-based)

| Threat | Edge responsibility | WAF / Origin |
|--------|---------------------|---------------|
| Known scanner UAs (sqlmap, nikto, acunetix, masscan, etc.) | Block (403) | Bot management, rate limit, CAPTCHA |

**Framework**: Edge does coarse UA deny list. Sophisticated bot detection is WAF.

---

### 4. Query String Abuse (DoS / Cache Poisoning)

| Threat | Edge responsibility | WAF / Origin |
|--------|---------------------|---------------|
| Excessive query length / param count | Block (414 / 400) | — |
| Cache-key pollution via utm_*, gclid, fbclid | Normalize (drop keys) | — |

**Framework**: `max_query_length`, `max_query_params`, `drop_query_keys`.

---

### 5. Missing or Malformed Headers

| Threat | Edge responsibility | WAF / Origin |
|--------|---------------------|---------------|
| Missing User-Agent (often automation) | Block (400) or allow by policy | — |

**Framework**: Optional `header_missing` block (e.g. User-Agent). Configurable per profile.

---

### 6. Admin / Internal Path Exposure

| Threat | Edge responsibility | WAF / Origin |
|--------|---------------------|---------------|
| Unauthenticated access to /admin, /docs, /swagger | Simple token gate (401) | App-level auth for sensitive actions |

**Framework**: Edge auth_gate (static token). For strong auth, use Origin or Lambda@Edge (e.g. JWT).

---

### 7. Security Headers Missing

| Threat | Edge responsibility | WAF / Origin |
|--------|---------------------|---------------|
| Missing HSTS, X-Content-Type-Options, CSP, etc. | Inject on response | — |

**Framework**: Viewer Response / Worker adds headers from policy.

---

### 8. Information Leakage

| Threat | Edge responsibility | WAF / Origin |
|--------|---------------------|---------------|
| X-Powered-By, Server version in response | Strip or overwrite | — |

**Framework**: Response handler can remove or normalize such headers.

---

### 9. JWKS SSRF (Server-Side Request Forgery via JWT gates)

| Threat | Edge responsibility | WAF / Origin |
|--------|---------------------|---------------|
| Malicious or accidental `jwks_url` pointing at cloud metadata (`169.254.169.254`), loopback, RFC1918, or link-local ranges | Reject at build time and re-validate at runtime | — |
| Attacker-controlled redirect from JWKS host to internal endpoint | Refuse 3xx responses (`redirect: 'error'` in Workers / explicit 3xx rejection in Lambda@Edge) | — |
| Out-of-scope IdP host when policy has an explicit allowlist | Reject at build time via `firewall.jwks.allowed_hosts` | — |

**Framework**:
- Build-time validator (`validateJwksUrl`) enforces `https://`, rejects userinfo, loopback, RFC1918, link-local, IPv4-mapped IPv6, and optional `firewall.jwks.allowed_hosts` membership.
- Runtime `fetchJwks` re-checks the URL and refuses any 3xx response.
- Recommended operator practice: always set `firewall.jwks.allowed_hosts` in production to pin the exact IdP hostname(s).

---

### 10. HTTP Request Smuggling / Desync

| Threat | Edge responsibility | WAF / Origin |
|--------|---------------------|---------------|
| Client-supplied `Transfer-Encoding: chunked` desynchronizing CloudFront/Worker ↔ origin framing (CL.TE / TE.CL / H2.TE) | Strip hop-by-hop headers before origin forward | — |
| Client-supplied `Connection`, `Upgrade`, `TE`, `Keep-Alive`, `Proxy-*`, `Trailer` | Strip before origin forward | — |

**Framework**: The AWS origin-request Lambda and Cloudflare Worker both delete `transfer-encoding`, `connection`, `keep-alive`, `te`, `upgrade`, `proxy-connection`, `proxy-authenticate`, `proxy-authorization`, and `trailer` from the forwarded request. The CDN re-frames the request, so none of these carry legitimate viewer intent.

### 11. Signed URL Replay

| Threat | Edge responsibility | WAF / Origin |
|--------|---------------------|---------------|
| Signed URL for `/download/a.pdf` reused against sibling path `/download/b.pdf` | `exact_path: true` binds signature to a single URI | — |
| Single signed URL replayed repeatedly within its TTL | `nonce_param` binds per-URL nonce into HMAC + edge forwards `X-Signed-URL-Nonce` | Origin enforces single-use (e.g., Redis `SET NX`) |
| Nonce tampered to collide with another session | Nonce included in HMAC input (`uri + exp + '|' + nonce`); tampering invalidates signature | — |
| Write endpoint (POST/PUT/DELETE) protected by long-lived signed URL | Compile-time warning when `signed_url` gate hits write-like prefix without `nonce_param` | — |

**Framework**: See `docs/signed-urls.md` for signing rules, nonce format (16–256 chars, URL-safe unreserved), and origin-side enforcement pattern. Edge enforces signature + nonce binding; single-use still requires origin cooperation because edge functions are stateless per invocation.

### 12. Admin Token Timing Oracle

| Threat | Edge responsibility | WAF / Origin |
|--------|---------------------|---------------|
| Attacker with traffic control infers admin token byte-by-byte via response-time delta between early- vs late-mismatch positions | Constant-time compare that iterates at least 64 positions regardless of length; no early-exit on length mismatch | — |
| Length leaks via short-circuit on `a.length !== b.length` | Fixed-pad iteration + length XORed into accumulator | — |

**Framework**: Both CloudFront Functions (`viewer-request.js`) and Cloudflare Workers (`index.ts`) use a pad-to-64 constant-time compare for `static_token` and `basic_auth` gates. See `docs/auth.md` for properties and limits.

### 13. JWKS Outage / Key Rotation Availability

| Threat | Edge responsibility | WAF / Origin |
|--------|---------------------|---------------|
| IdP outage causes 100% 401 until edge isolate recycles | Stale-if-error cache window (`firewall.jwks.stale_if_error_sec`, default 3600s) serves last-known-good keys | — |
| Edge hammers a broken IdP on every request | Negative cache (`firewall.jwks.negative_cache_sec`, default 60s) skips re-fetch after a failure | — |
| Key rotation: new `kid` at IdP but edge keeps using old cached JWKS | On `kid`-miss, invalidate + refetch once before rejecting | — |

**Framework**: JWKS fetch in AWS (`templates/aws/origin-request.js`) and Cloudflare (`templates/cloudflare/index.ts`) implements all three windows. See `docs/auth.md` for the behaviour matrix.

---

## What This Framework Does Not Mitigate

* **Advanced bot behavior** (WAF / Bot Management).
* **OWASP Top 10 in body** (WAF / application).
* **Rate limiting** (WAF / API gateway).
* **DDoS** (CDN + Shield / WAF).
* **Internal / DB abuse** (application).

Use `decision-matrix.md` to decide Edge vs WAF for each control.

---

## OWASP Mapping (2026 baseline)

This framework should be operated with explicit references to:

- **OWASP Top 10:2025**
- **OWASP API Security Top 10 (2023)**

Practical interpretation:

| OWASP area | Framework role | Notes |
|------------|----------------|-------|
| Input and request abuse | Edge + WAF | Method/path/query/header checks at edge, deep inspection in WAF/app. |
| Auth/session weaknesses | Edge + Origin | Edge gate is coarse filtering; critical authn/authz remains app/origin responsibility. |
| Security misconfiguration | CI + policy | Keep policy lint/build/runtime/unit/drift checks mandatory in CI. |
| Software supply chain risk | CI + dependency hygiene | Keep lockfile, monitor dependencies, and treat generated artifacts as reproducible outputs. |
| API abuse patterns | WAF + app controls | Use API schema validation/rate limiting outside edge runtime. |
