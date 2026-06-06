> **言語:** [English](./request-anomaly-guards.md) - 日本語

# Request Anomaly Guards

`request.anomaly_guards` は、origin へ転送する前に軽量な request hygiene
check を行う opt-in 設定です。対象は意図的に狭く、CRLF injection indicator、
不正な Cookie header、bounded な double-encoded traversal signal だけを見ます。
広範な SQLi/XSS signature scan は WAF managed rules に任せます。

```yaml
request:
  anomaly_guards:
    enabled: true
    # enabled 時の既定は true。
    crlf: true
    malformed_cookie: true
    double_encoded_traversal: true
    max_cookie_bytes: 4096
    max_cookie_pairs: 80
```

## チェック内容

- **CRLF indicator**: request URI、query string、request header value 内の
  生の `\r` / `\n` と、encoded form の `%0d` / `%0a` を拒否します。
- **不正な Cookie header**: control character、`a=1;;b=2` のような空 delimiter、
  `name=value` delimiter のない pair、設定した Cookie size / pair count 超過を拒否します。
- **Double-encoded traversal**: `%25` がある場合だけ最大 1 回の追加
  `decodeURIComponent` を行い、その後に `%252e%252e`、`%252f`、`%255c`
  由来の traversal indicator が見えたら拒否します。

## Runtime 対応

CloudFront Functions viewer-request と Cloudflare Workers が enforcement 対応です。
Lambda@Edge origin-request は既存の `max_header_size` handling を維持し、
viewer-request check を重複実装しません。

## 性能制約

この guard は URI/header count cap の後、path normalization や origin/auth forwarding
の前に動きます。処理量は header 数と URI/query 長に対して bounded です。decode-based
traversal 検出は `%25` がない限り skip し、decode attempt は 1 回だけです。

## Rollout

client を制御できる strict/admin surface では default checks のまま `enabled: true`
を使えます。広い browser/API traffic では、legacy client が非標準 Cookie delimiter
を送る可能性がある場合、まず `malformed_cookie: false` で始めてください。
