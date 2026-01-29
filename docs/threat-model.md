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

## What This Framework Does Not Mitigate

* **Advanced bot behavior** (WAF / Bot Management).
* **OWASP Top 10 in body** (WAF / application).
* **Rate limiting** (WAF / API gateway).
* **DDoS** (CDN + Shield / WAF).
* **Internal / DB abuse** (application).

Use `decision-matrix.md` to decide Edge vs WAF for each control.
