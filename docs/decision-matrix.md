# Decision Matrix: Edge vs WAF

Use this matrix to decide whether a control belongs in **Edge** (CloudFront Functions / Workers) or **WAF** (AWS WAF / Cloudflare WAF).

---

## Principles

| Criterion | Prefer Edge | Prefer WAF |
|-----------|-------------|------------|
| Latency | Must be ultra-low, no external call | Can tolerate rule evaluation / state |
| State | Stateless only | Stateful (rate, session, IP list) |
| Data inspected | Method, URI, query, headers only | Body, full request, behavior over time |
| Complexity | Simple pattern match / normalization | Complex rules, ML, CAPTCHA |

---

## By Control Type

| Control | Edge | WAF | Notes |
|---------|------|-----|------|
| Block unwanted methods (GET/HEAD/POST only) | ✓ | — | Edge: fast, no state. |
| Path traversal (coarse: `../`, encoded) | ✓ | ✓ | Edge: first filter. WAF: broader patterns. |
| UA deny list (scanner names) | ✓ | — | Edge: simple string match. |
| Bot / automation detection (behavior) | — | ✓ | WAF: stateful, fingerprinting. |
| Rate limiting | — | ✓ | WAF or API gateway. |
| Query length / param count limit | ✓ | — | Edge: cheap. |
| Query key normalization (drop utm_*, etc.) | ✓ | — | Edge: cache hygiene. |
| Missing User-Agent block | ✓ | — | Edge: one header check. |
| Static token gate (/admin) | ✓ | — | Edge: one header. Strong auth → Origin/Lambda@Edge. |
| JWT / OIDC validation | — | — | Lambda@Edge or Origin. Not in CloudFront Functions. |
| Security header injection | ✓ | — | Edge: response rewrite. |
| OWASP CRS / SQLi, XSS in body | — | ✓ | WAF managed rules. |
| CAPTCHA / challenge | — | ✓ | WAF / Bot Management. |
| Geo / ASN block | Optional (Workers) | ✓ | WAF often easier. |
| DDoS mitigation | — | ✓ | CDN + Shield / WAF. |

---

## Summary

* **Edge**: Normalization, coarse blocking, header injection, simple token gate. No state, no body, minimal latency.
* **WAF**: Rate limit, OWASP, Bot, CAPTCHA, body inspection, stateful rules.
* **Origin / Lambda@Edge**: Strong auth (JWT), business rules, dynamic config.

When in doubt: if it needs **state** or **body** or **complex logic**, put it in WAF or Origin, not in Edge Functions.
