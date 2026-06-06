> **Languages:** English - [日本語](./request-anomaly-guards.ja.md)

# Request Anomaly Guards

`request.anomaly_guards` enables lightweight request hygiene checks before the
edge forwards traffic to origin. The guards are intentionally narrow: they look
for CRLF injection indicators, malformed Cookie headers, and bounded
double-encoded traversal signals without running broad signature scans.

```yaml
request:
  anomaly_guards:
    enabled: true
    # Defaults to true when enabled.
    crlf: true
    malformed_cookie: true
    double_encoded_traversal: true
    max_cookie_bytes: 4096
    max_cookie_pairs: 80
```

## Checks

- **CRLF indicators**: rejects raw `\r` / `\n` and encoded `%0d` / `%0a`
  indicators in the request URI, query string, or request header values.
- **Malformed Cookie header**: rejects control characters, empty delimiter
  segments such as `a=1;;b=2`, cookie pairs without a `name=value` delimiter,
  and configured Cookie size/pair-count overages.
- **Double-encoded traversal**: only when `%25` is present, performs at most one
  extra `decodeURIComponent` pass and rejects traversal indicators such as
  `%252e%252e`, `%252f`, and `%255c` after that pass.

## Runtime Support

CloudFront Functions viewer-request and Cloudflare Workers enforce these
guards. Lambda@Edge origin-request keeps its existing `max_header_size` handling
and does not duplicate the viewer-request checks.

## Performance

The guards run after URI/header count caps and before path normalization or
origin/auth forwarding. Work is bounded by the number of headers plus the
URI/query length. Decode-based traversal detection is skipped unless `%25` is
present, and it performs one decode attempt only.

## Rollout

Use `enabled: true` with the default checks on strict/admin surfaces where you
control clients. For broad browser/API traffic, start with `malformed_cookie:
false` if legacy clients may send non-standard Cookie delimiters.
