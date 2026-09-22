# Observability and Metrics

This document describes recommended **logging and metrics** for the Edge Security Layer (CloudFront Functions, Lambda@Edge, Cloudflare Workers) so you can observe blocks and reason about traffic.

---

## Scope

* **Edge Security Layer** blocks or normalizes requests at its configured invocation events. To operate safely, you should know:
  * How many requests were blocked, and why (method, path traversal, UA, query, admin gate).
  * Whether security headers were applied on responses.
* Distinguish generated runtime logs below from operator-built aggregation and metrics. The compiler does not automatically create these counters or metric filters.

---

## Structured JSON Logs (generated runtime)

When `observability.log_format: json` is set (default), the generated viewer-request / origin-request / Cloudflare Worker emit denied, monitor, audit, and error decisions to `console.log`. Allowed requests are emitted according to `observability.sample_rate`. Fields:

| Field | Description | Example |
|-------|-------------|---------|
| `ts` | Unix timestamp in milliseconds | `1776947696789` |
| `level` | `warn` on block; `info` on allow/monitor/audit; runtime errors use `info` or `error` depending on the emitter | `warn` |
| `event` | `allow`, `block`, `monitor` (monitor mode), `audit`, `error` | `block` |
| `status` | HTTP status returned | `405` |
| `block_reason` | Why the request was blocked (see mapping below) | `method_not_allowed` |
| `method` | Request method | `POST` |
| `uri` | Request URI path (without query by default) | `/admin` |
| `correlation_id` | Value of the configured correlation header (minted at origin if absent) | `00-4bf9...-01` |

Cloudflare JWT/signed_url success audit events (`audit_log_auth: true`) add the fields below. AWS rejects these authentication settings at build time; origin logging is not a substitute:

| Field | Description |
|-------|-------------|
| `auth_event` | `auth_pass` on successful JWT / signed URL |
| `gate_type` | `jwt`, `signed_url`, `static_token` |
| `gate_name` | Route's `name:` from policy |
| `sub` | JWT `sub` — hashed to first 16 hex of SHA-256 when `audit_hash_sub: true` |

Example block event:

```json
{"ts":1776947696789,"level":"warn","event":"block","status":405,"block_reason":"method_not_allowed","method":"POST","uri":"/anything","correlation_id":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
```

### Policy

```yaml
observability:
  log_format: "json"               # "json" (default) or "text"
  correlation_id_header: "traceparent"  # or "x-request-id"
  sample_rate: 1                   # 0..1; sample allowed requests (block/audit always emit)
  audit_log_auth: true             # emit audit events on auth gate success
  audit_hash_sub: true             # SHA-256 truncate sub to 16 hex (PII-safe)
```

### Correlation propagation

At Lambda@Edge / Worker, if the incoming request does **not** carry `correlation_id_header`, the runtime mints one (`crypto.randomUUID` / `crypto.getRandomValues`) and sets it on the forwarded request. Forwarded downstream logs can use that ID, but earlier viewer/WAF records need not contain an ID minted later.

Allow sampling is deterministic. The runtime uses the incoming correlation ID when present, otherwise it uses the request method and URI path. Lambda@Edge and Workers capture that key before minting a missing correlation ID, so retries for the same method/path remain in the same sample bucket. `sample_rate: 0` disables allow logs; `1` emits each allowed decision reached by that function; it does not guarantee observation or delivery for every viewer request. Block, monitor, audit, and error logs are never sampled.

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

* **CloudFront Functions**: `console.log()` in a LIVE function handling real traffic is sent to CloudWatch Logs. Cache-behavior function logs use `/aws/cloudfront/function/<FunctionName>` in `us-east-1`. Test invocations return logs in their test output instead of delivering them to CloudWatch. [AWS: Edge function logs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/edge-functions-logs.html)
* This logging support does not permit arbitrary direct HTTP calls to an external logging API. CloudFront Functions restricts network access and truncates function logs at 10KB. [AWS: CloudFront Functions restrictions](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-function-restrictions.html)
* **Same cache behavior**: each event type can have one edge-function association. Do not mix CloudFront Functions and Lambda@Edge across viewer-request/viewer-response. CloudFront Functions viewer events may be combined with Lambda@Edge origin-request/origin-response. [AWS: all edge-function restrictions](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/edge-function-restrictions-all.html)
* **Origin observation**: origin-request runs only when forwarding to the origin; origin-response runs after an origin response. Cache hits bypass these events, and an origin-request function-generated response bypasses origin-response. Origin logs therefore do not cover all viewer requests. [AWS: trigger events](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-cloudfront-trigger-events.html)
* **Lambda@Edge**: the current origin-request template also uses `console.log`; inspect CloudWatch logs in the invocation Region. Metric filters and aggregation using runtime fields such as `status` are operator-built.
* **Cloudflare Workers**: distinguish the current Worker's `console.log` output from separately configured analytics/metrics aggregation. Debug headers exposing credentials or internal decisions are not a recommended production default.

### Delivery and completeness

Edge-function log delivery is best effort: records may arrive late or be missing. An absent log is not evidence that no request occurred. Account separately for invocation conditions, sampling, truncation and delivery; do not use these logs as a complete request ledger or billing reconciliation. [AWS: delivery limits](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/edge-functions-logs.html)

Implementation checked on 2026-09-22 at main `111f995bd35d3b24bdd1ee7dd72c35bce19f9170`: `logEvent` and sampling in `templates/aws/viewer-request.js`, `templates/aws/origin-request.js`, and `templates/cloudflare/index.ts`. No runtime/logging feature is added here.

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
