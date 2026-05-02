# GraphQL Guard

> **Languages:** English · [日本語](./graphql-guard.ja.md)

`request.graphql_guard` adds a lightweight GraphQL depth and complexity guard for body-readable edge targets. The initial runtime implementation is Cloudflare Workers only.

```yaml
request:
  allow_methods: ["GET", "HEAD", "POST"]
  graphql_guard:
    endpoint_paths: ["/graphql"]
    max_depth: 8
    max_aliases: 20
    max_fields: 200
    max_body_bytes: 65536
    mode: block
```

## Target Support

Cloudflare Workers can clone and inspect the POST body before forwarding the original request stream to origin, so the compiler injects `CFG.graphqlGuard` into `dist/edge/cloudflare/index.ts`.

CloudFront Functions and the current AWS edge output cannot read request bodies. When `request.graphql_guard` is configured for the AWS target, the compiler emits an unsupported warning and does not attempt partial enforcement. Enforce the same policy at origin or compile the Cloudflare Workers target for this guard.

## Runtime Behavior

The guard applies only to `POST` requests whose normalized path matches `endpoint_paths`. Entries are prefix-matched, so `/graphql` also covers `/graphql/private`.

Supported body shapes:

- `application/json` with a string `query` property.
- `application/graphql` with the query as the raw request body.

Violations return `400` in `mode: block`. In `mode: report`, the Worker logs a `monitor` event and forwards the request.

## Limits

`max_body_bytes` caps how many bytes the Worker will read from a cloned request body. The default is `65536` bytes and the schema maximum is `1048576`. Requests above the cap are treated as violations. Keep this value close to real GraphQL document size; variables can still be large and should be capped by origin or a separate request-size control.

The scanner counts:

- `max_depth`: selection-set nesting depth.
- `max_aliases`: alias tokens in selection sets.
- `max_fields`: field-name tokens in selection sets, including repeated fields and fields inside fragment definitions.

## Parser Limitations

This is a bounded scanner, not a full GraphQL validator. It skips comments, quoted strings, and block strings, then counts braces and GraphQL names. It does not expand fragment spreads or understand schema-specific cost weights. That means:

- False positives are possible for unusual documents.
- False negatives are possible when a low field count still maps to expensive resolver work.
- Persisted queries, variables, and schema-aware complexity should still be enforced at the application layer.

## Rollout Guidance

Start with `mode: report` and conservative thresholds from production traffic. Watch edge logs for `GraphQL depth limit exceeded`, `GraphQL alias limit exceeded`, `GraphQL field limit exceeded`, and malformed-query events. After tuning, switch to `mode: block` for the endpoint paths you own.
