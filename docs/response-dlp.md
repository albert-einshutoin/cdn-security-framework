# Response DLP

> **Languages:** English - [日本語](./response-dlp.ja.md)

`response_dlp` is an opt-in response data-loss prevention guard for targets that can inspect response headers and bounded text-like response bodies. The current enforcement target is Cloudflare Workers.

```yaml
response_dlp:
  enabled: true
  action: report_only       # report_only | mask | block
  mask: "[REDACTED]"
  block_status: 451
  block_body: "Response blocked by edge DLP"
  body:
    enabled: true
    max_bytes: 32768
    content_types:
      - "text/"
      - "application/json"
  headers:
    enabled: true
    names:
      - "set-cookie"
      - "authorization"
      - "x-api-key"
  detectors:
    built_in:
      - "api_key"
      - "credit_card"
    custom_regex:
      - name: "internal_token"
        pattern: "internal_[A-Za-z0-9]{16,}"
```

## Target Support

Cloudflare Workers can inspect configured response headers and clone text-like response bodies before returning the response. When enabled, the compiler injects DLP configuration and detector regexes into `dist/edge/cloudflare/index.ts`.

CloudFront Functions cannot inspect response bodies. The AWS target emits an unsupported warning when `response_dlp.enabled: true` and does not enforce response DLP masking or blocking. Use Cloudflare Workers, Lambda/origin-side controls, or an application-layer DLP control for AWS deployments.

## Actions

| Action | Behavior |
|--------|----------|
| `report_only` | Logs a DLP finding, adds `X-Edge-DLP: report_only`, and leaves the response unchanged. |
| `mask` | Replaces matched values with `mask`, removes `content-length` for body rewrites, and adds `X-Edge-DLP: mask`. |
| `block` | Returns a synthetic response with `block_status`, `block_body`, `Cache-Control: no-store`, and `X-Edge-DLP: block`. |

Start with `report_only` so you can tune detectors against production-shaped traffic before mutating or blocking responses.

## Detectors

Built-in detectors are intentionally high-confidence:

- `api_key`: common key prefixes such as `sk-live-`, `sk_test_`, and `ghp_`.
- `credit_card`: 13-19 digit card-like values that pass Luhn validation.

Custom regex detectors are compiled at build time, capped at 10 patterns and 256 characters per pattern, and rejected when they match known nested-quantifier ReDoS shapes. Keep custom detectors narrow and prefer anchored or prefix-specific patterns.

## Body Limits

Body inspection only runs when `body.enabled` is not false and the response `Content-Type` contains one of the configured `content_types` substrings. The default list covers text and JSON/XML-like responses.

`body.max_bytes` defaults to `32768` and is capped at `131072`. If `Content-Length` is above the limit, or the cloned body exceeds the limit after reading, the Worker passes the response through unchanged. This keeps edge CPU and memory cost bounded.

## Header Limits

Header inspection is limited to `headers.names`. If no names are configured, the default set is `set-cookie`, `authorization`, and `x-api-key`. Response DLP does not parse cookies semantically; it scans configured header values as strings.

## Operational Notes

- Do not use response DLP as the only protection for secrets. Prevent sensitive values from reaching the origin response whenever possible.
- Use `report_only` first and monitor DLP findings where `event` is `monitor` and `block_reason` is `response_dlp_report_only` before switching to `mask` or `block`.
- Keep `max_bytes` close to the largest response shape you intentionally inspect.
- Avoid custom regexes that scan broad text with ambiguous wildcards. Build-time guards catch common ReDoS shapes, but narrow patterns are still safer and faster.
- Compressed or encrypted payloads are not decoded by this feature unless the runtime exposes a readable decoded body.
