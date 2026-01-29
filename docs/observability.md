# Observability and Metrics

This document describes recommended **logging and metrics** for the Edge Security Layer (CloudFront Functions, Lambda@Edge, Cloudflare Workers) so you can observe blocks and reason about traffic.

---

## Scope

* **Edge Security Layer** blocks or normalizes requests before they reach WAF or Origin. To operate safely, you should know:
  * How many requests were blocked, and why (method, path traversal, UA, query, admin gate).
  * Whether security headers were applied on responses.
* This doc defines **recommended** log fields and metric dimensions. Implement them in your runtime or via CDN logging (e.g. CloudFront access logs, Workers analytics).

---

## Recommended Log Fields (when a request is blocked)

When the Edge Security Layer returns 4xx (400, 401, 403, 405, 414), log at least:

| Field | Description | Example |
|-------|-------------|---------|
| `block_reason` | Why the request was blocked | `method_not_allowed`, `path_traversal`, `ua_denied`, `query_limit`, `admin_unauthorized` |
| `status_code` | HTTP status returned | `400`, `401`, `403`, `405`, `414` |
| `method` | Request method | `GET`, `OPTIONS` |
| `uri` or `path` | Request URI (sanitized; avoid logging full query if sensitive) | `/admin`, `/foo/../bar` |
| `user_agent` | User-Agent (optional; may be long or sensitive) | Truncate or hash in strict environments |

Optional: `request_id`, `timestamp`, `region` / `edge_location` (if your CDN provides them).

---

## Block Reason Mapping

| Policy / runtime check | Recommended `block_reason` | Status |
|------------------------|----------------------------|--------|
| Method not in allow list | `method_not_allowed` | 405 |
| Path traversal pattern (e.g. `../`, `%2e%2e`) | `path_traversal` | 400 |
| UA in deny list or missing UA | `ua_denied` | 403 or 400 |
| Query string too long or too many params | `query_limit` | 414 or 400 |
| Admin path without valid token | `admin_unauthorized` | 401 |

---

## Metrics (recommended dimensions)

If you aggregate metrics (e.g. in CloudWatch, Datadog, or Cloudflare Analytics), use dimensions such as:

| Metric / dimension | Description |
|--------------------|-------------|
| `edge_security_block_count` | Count of requests blocked by the Edge Security Layer (counter). |
| `block_reason` | Dimension: `method_not_allowed`, `path_traversal`, `ua_denied`, `query_limit`, `admin_unauthorized`. |
| `status_code` | Dimension: 400, 401, 403, 405, 414. |

Example: `edge_security_block_count{block_reason="ua_denied", status_code="403"}`.

---

## Implementation notes

* **CloudFront Functions**: No direct logging API; use CloudFront access logs and/or enable logging in the response (e.g. custom header `x-edge-block-reason` for debugging; remove in production if sensitive). Alternatively, send logs from Lambda@Edge if you use it in the same behavior.
* **Lambda@Edge**: Use `console.log` (or your logger) with structured JSON including `block_reason` and `status_code`; ship logs to CloudWatch Logs and create metrics from filters.
* **Cloudflare Workers**: Use `console.log` or Workers analytics / custom metrics; add optional `x-edge-block-reason` header for debugging.

---

## Security headers (response)

For responses that pass through the Edge Security Layer, the framework adds security headers (HSTS, X-Content-Type-Options, CSP, etc.). To verify in production:

* Sample responses and check that expected headers are present.
* Optionally log a metric such as `edge_security_headers_applied_count` per path prefix (e.g. `/`, `/admin`) if your runtime can do so without high overhead.

---

## Related

* [Architecture](architecture.md) — Edge vs WAF vs Origin.
* [Threat model](threat-model.md) — threats addressed at the edge.
