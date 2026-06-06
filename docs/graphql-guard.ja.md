# GraphQL Guard

> **Languages:** [English](./graphql-guard.md) · 日本語

`request.graphql_guard` は、body を読める Edge target 向けに GraphQL の深さと簡易 complexity を検査するガードです。初期実装の runtime 対応は Cloudflare Workers のみです。

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

## Target 対応

Cloudflare Workers は POST body を clone して検査し、元の request stream を origin に転送できます。そのため compiler は `dist/edge/cloudflare/index.ts` に `CFG.graphqlGuard` を注入します。

CloudFront Functions と現在の AWS edge 出力は request body を読めません。AWS target で `request.graphql_guard` が設定されている場合、compiler は unsupported warning を出し、部分的な enforcement は行いません。このガードが必要な場合は Cloudflare Workers target を使うか、origin 側で同等の制御を実装してください。

## Runtime 動作

対象は、正規化後の path が `endpoint_paths` に一致する `POST` request だけです。path は prefix match なので、`/graphql` は `/graphql/private` も対象にします。

対応する body 形式:

- `application/json` かつ string の `query` property を持つ body。
- `application/graphql` かつ query を raw body に持つ body。

違反時は `mode: block` なら `400` を返します。`mode: report` では `monitor` event を log に出し、request は origin に転送します。

## 上限

`max_body_bytes` は Worker が clone body から読む最大 byte 数です。default は `65536` bytes、schema 上の最大は `1048576` です。上限を超えた request は違反として扱います。GraphQL document の実サイズに近い値にしてください。variables が大きいケースは、この guard とは別に origin や request-size 制御で上限を設ける必要があります。

scanner が数えるもの:

- `max_depth`: selection set のネスト深さ。
- `max_aliases`: selection set 内の alias token 数。
- `max_fields`: selection set 内の field name token 数。repeated field と fragment definition 内の field も含みます。

## Parser の制限

これは bounded scanner であり、完全な GraphQL validator ではありません。comments、quoted string、block string を読み飛ばし、brace と GraphQL name を数えます。fragment spread の展開や schema 固有の cost weight は理解しません。そのため:

- 通常と異なる document では false positive が起こり得ます。
- field 数が少なくても resolver が重い query では false negative が起こり得ます。
- persisted query、variables、schema-aware complexity は application layer でも検査してください。

## 段階導入

最初は `mode: report` とし、本番 traffic から保守的なしきい値を決めてください。edge log で `GraphQL depth limit exceeded`、`GraphQL alias limit exceeded`、`GraphQL field limit exceeded`、malformed-query event を確認します。調整後、自分たちが所有する endpoint path から `mode: block` に切り替えてください。
