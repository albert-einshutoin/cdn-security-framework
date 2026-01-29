# AWS CloudFront Functions Runtime

This directory contains the runtime for **Viewer Request** and **Viewer Response** used with CloudFront Functions.

## What Does It Protect?

- Reduces the attack surface at the edge (unwanted methods, path traversal, anomalous User-Agent, excessive query params)
- Query normalization (e.g., strip utm and similar to avoid cache key pollution)
- Enforces security headers at the CDN (consistent across multiple origins)

## Where to Attach

- `viewer-request.js` → **Viewer Request**
- `viewer-response.js` → **Viewer Response**

## Minimal Setup

### 1) Admin token

Replace the following in `viewer-request.js`:

- `CFG.adminGate.token = "REPLACE_ME_WITH_EDGE_ADMIN_TOKEN"`

> CloudFront Functions do not easily support external secret references, so "inject at build time" is a safe approach for now.
> Once a compiler is added, this can be generated automatically from `policy/base.yml`.

## Verification (Example)

### Admin gate

```bash
curl -i https://YOUR_DOMAIN/admin
curl -i -H "x-edge-token: REPLACE_ME_WITH_EDGE_ADMIN_TOKEN" https://YOUR_DOMAIN/admin
```

### Query normalization

```bash
curl -i "https://YOUR_DOMAIN/?utm_source=x&foo=1"
```

## What Else Can You Do?

- Create a separate Behavior for `/api/*` and extend `allowMethods` (e.g., PUT, DELETE).
- Block only obvious attacks in Functions; leave rate limiting and OWASP to AWS WAF.
