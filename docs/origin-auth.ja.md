# オリジン認証

`origin.auth` は CDN からオリジンへの hop を保護します。単純な allowlist には `custom_header`、コピーされたヘッダ、改ざんされた path/query、古い replay をオリジンで拒否したい場合は `hmac_signature` を使います。

## HMAC 署名モード

```yaml
origin:
  auth:
    type: hmac_signature
    secret_env: ORIGIN_AUTH_SECRET
    header_prefix: X-CDN-Auth
    timestamp_tolerance_seconds: 300
    include_body_hash: false
    signed_components: [method, path, query, body, timestamp, nonce]
```

生成 runtime は `secret_env` で指定された env var から secret を読みます。policy には env var 名だけを書き、secret 値は書きません。

オリジンへ付与するヘッダ:

- `X-CDN-Auth-Timestamp`
- `X-CDN-Auth-Nonce`
- `X-CDN-Auth-Body-SHA256`（`include_body_hash: true` のとき）
- `X-CDN-Auth-Signature`

canonical input は `signed_components` の順に値を並べ、`\n` で結合します。既定は次の形です。

```text
METHOD
PATH
CANONICAL_QUERY
BODY_SHA256_OR_EMPTY
TIMESTAMP
NONCE
```

`CANONICAL_QUERY` は decoded query pair を key、value の順にソートし、`encodeURIComponent` で再エンコードします。同じ key が複数ある場合も保持します。署名形式は base64url の HMAC-SHA256 です。
`signed_components` をカスタマイズする場合も `timestamp` と `nonce` は必須です。これらが署名に束縛されないと replay 対策が成立しません。

## Replay 制限

timestamp は `timestamp_tolerance_seconds` の範囲外の replay を拒否するための値です。nonce はその許容時間内の 2 回目利用をアプリ側で拒否するために使います。edge はステートレスなので、nonce replay 防止は Redis `SET key value NX EX 300` のようにオリジン側で実装してください。

## body hash

既定は `include_body_hash: false` です。すべての edge phase が body を安価に読めるわけではないためです。payload まで署名に束ねたい、かつ runtime が body を読める場合だけ `true` にしてください。AWS Lambda@Edge では body が truncate されている場合、または payload を持ち得る request で CloudFront が body を含めていない場合、部分 body や空 body への署名を避けるため fail closed します。

## Node / Express 検証例

```js
const crypto = require('crypto');

function canonicalQuery(searchParams) {
  return [...searchParams.entries()]
    .sort((a, b) => a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0]))
    .map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v))
    .join('&');
}

function verifyCdnOriginAuth(req, { secret, toleranceSeconds = 300, nonceStore }) {
  const prefix = 'x-cdn-auth';
  const ts = req.get(prefix + '-timestamp');
  const nonce = req.get(prefix + '-nonce');
  const sig = req.get(prefix + '-signature');
  if (!ts || !nonce || !sig) return false;

  const age = Math.abs(Math.floor(Date.now() / 1000) - Number(ts));
  if (!Number.isFinite(age) || age > toleranceSeconds) return false;
  if (nonceStore && !nonceStore.claim(nonce, toleranceSeconds)) return false;

  const url = new URL(req.originalUrl || req.url, 'https://origin.local');
  const bodyHash = req.get(prefix + '-body-sha256') || '';
  const canonical = [
    req.method.toUpperCase(),
    url.pathname,
    canonicalQuery(url.searchParams),
    bodyHash,
    ts,
    nonce,
  ].join('\n');
  const expected = crypto.createHmac('sha256', secret).update(canonical).digest('base64url');
  const a = Buffer.from(expected);
  const b = Buffer.from(sig);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
```

ヘッダ不足、古い timestamp、replay された nonce、署名不一致はいずれも拒否してください。secret はオリジン側の secret manager に置き、他の edge HMAC secret と同じ運用でローテーションします。
