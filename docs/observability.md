# Observability and Metrics

This document describes recommended **logging and metrics** for the Edge Security Layer (CloudFront Functions, Lambda@Edge, Cloudflare Workers) so you can observe blocks and reason about traffic.

---

## Scope

* **Edge Security Layer** blocks or normalizes requests before they reach WAF or Origin. To operate safely, you should know:
  * How many requests were blocked, and why (method, path traversal, UA, query, admin gate).
  * Whether security headers were applied on responses.
* This doc defines **recommended** log fields and metric dimensions. Implement them in your runtime or via CDN logging (e.g. CloudFront access logs, Workers analytics).

---

## Structured JSON Logs (generated runtime)

When `observability.log_format: json` is set (default), the generated viewer-request / origin-request / Cloudflare Worker emit one JSON line per decision to `console.log`. Fields:

| Field | Description | Example |
|-------|-------------|---------|
| `ts` | ISO-8601 timestamp | `2026-04-23T12:34:56.789Z` |
| `level` | `info` on block/monitor/audit, `error` on runtime error | `info` |
| `event` | `block`, `monitor` (monitor mode), `audit`, `error` | `block` |
| `status` | HTTP status returned | `405` |
| `block_reason` | Why the request was blocked (see mapping below) | `method_not_allowed` |
| `method` | Request method | `POST` |
| `uri` | Request URI path (without query by default) | `/admin` |
| `correlation_id` | Value of the configured correlation header (minted at origin if absent) | `00-4bf9...-01` |

Audit events (`audit_log_auth: true`) add:

| Field | Description |
|-------|-------------|
| `auth_event` | `auth_pass` on successful JWT / signed URL |
| `gate_type` | `jwt`, `signed_url`, `static_token` |
| `gate_name` | Route's `name:` from policy |
| `sub` | JWT `sub` — hashed to first 16 hex of SHA-256 when `audit_hash_sub: true` |

Example block event:

```json
{"ts":"2026-04-23T12:34:56.789Z","level":"info","event":"block","status":405,"block_reason":"method_not_allowed","method":"POST","uri":"/anything","correlation_id":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
```

### Policy

```yaml
observability:
  log_format: "json"               # "json" (default) or "text"
  correlation_id_header: "traceparent"  # or "x-request-id"
  sample_rate: 1                   # 0..1; currently advisory (block/audit always emit)
  audit_log_auth: true             # emit audit events on auth gate success
  audit_hash_sub: true             # SHA-256 truncate sub to 16 hex (PII-safe)
```

### Correlation propagation

At Lambda@Edge / Worker, if the incoming request does **not** carry `correlation_id_header`, the runtime mints one (`crypto.randomUUID` / `crypto.getRandomValues`) and sets it on the forwarded request. Downstream services then see a consistent ID across edge logs, WAF logs, and origin logs.

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

---

## WAF Logging (AWS)

`firewall.waf.logging` renders `aws_wafv2_logging_configuration` alongside the web ACL. The compiler adds a Terraform variable for the destination ARN so the ARN itself stays in your secret manager / CI pipeline rather than the policy file.

```yaml
firewall:
  waf:
    scope: CLOUDFRONT
    logging:
      enabled: true
      destination_arn_env: "WAF_LOG_DESTINATION_ARN"
      redacted_fields:
        - "authorization"
        - "cookie"
        - "x-api-key"
```

### Destination choices

- **Kinesis Firehose → S3**: canonical low-cost path; supports >10k records/sec and cross-region delivery. Required for PCI / SOC2 retention windows above 30 days.
- **CloudWatch Logs**: cheapest when you already query in CW Insights; watch the per-log-group rate limits.
- **S3 direct**: only if you do not need stream replay and accept eventual consistency.

Regardless of destination, the ARN must satisfy `aws_wafv2_logging_configuration` naming — Kinesis Firehose names must start with `aws-waf-logs-`.

### Redaction

`redacted_fields` drops the listed request fields from every log record before it leaves the WAF. Accepted values: `authorization`, `cookie`, `set-cookie`, `x-api-key`, `x-csrf-token`. Redaction happens inside AWS WAF — downstream pipelines never see the raw value. Add `cookie` + `authorization` at minimum for anything that handles authenticated traffic.

### Lint warning

`npm run lint:policy` emits a non-fatal warning when `defaults.mode == enforce`, `firewall.waf.scope == CLOUDFRONT`, and logging is not enabled:

```
Policy lint warnings: policy/security.yml
  - firewall.waf.logging is not enabled while scope=CLOUDFRONT. PCI-DSS / SOC2 require WAF log retention — set logging.enabled: true and supply destination_arn_env.
```

This is advisory — REGIONAL scope skips the warning because ALB + WAF logs are often captured via ALB access logs already.

### Managed-rule coverage lint

Same lint pass warns when enforce-mode policies omit every one of BotControl / ATP / IPReputationList / AnonymousIpList. These four are where operators most frequently forget to opt in and are responsible for the vast majority of "why didn't the WAF catch this?" retros. The warning does not fail the build — adopt the rules you need for your risk posture.

### Custom block response

`firewall.waf.block_response` surfaces a branded page instead of the vanilla WAF 403 (which leaks the vendor). Emitted as `custom_response_bodies` on both the rule group and web ACL so any block rule can reference it via `custom_response_body_key: cdn_sec_block`.

```yaml
firewall:
  waf:
    block_response:
      status_code: 403
      body: "Access denied. Reference: {RID}"
      content_type: "TEXT_PLAIN"
```

---

## Fingerprint Operations (JA3/JA4)

For JA3/JA4 operations, use a staged rollout:

1. Start with `firewall.waf.fingerprint_action: count`.
2. Collect WAF logs and extract candidates.
3. Promote to `block` only after false-positive review.

Candidate extraction helper:

```bash
node scripts/fingerprint-candidates.js --input waf-logs.jsonl --min-count 20 --top 50
```

The script outputs:

- top JA3/JA4 candidates by frequency
- a policy patch snippet (`recommended_policy_patch`) for review
