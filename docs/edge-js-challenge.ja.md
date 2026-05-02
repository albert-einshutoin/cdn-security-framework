# Edge JS Challenge

`firewall.challenge` は、Cloudflare Workers 専用の opt-in experimental JavaScript challenge / lightweight proof-of-work 機能です。疑わしいブラウザ風トラフィックに軽い摩擦を与えるためのもので、CAPTCHA や本格的な bot management の代替ではありません。

```yaml
firewall:
  challenge:
    enabled: true
    mode: challenge       # report | block | challenge
    path_prefixes: ["/login", "/checkout"]
    ua_contains: ["headlesschrome"]
    difficulty: 3         # SHA-256 hex の先頭ゼロ数。最大 6
    ttl_sec: 900
    secret_env: CHALLENGE_SECRET
```

モード:

| Mode | 挙動 |
|------|------|
| `report` | 対象リクエストをログに出し、許可します。まずこのモードで影響確認してください。 |
| `block` | 対象リクエストを 403 で拒否します。 |
| `challenge` | HTML challenge page を返し、ブラウザ内で軽量 PoW を解かせ、検証成功後に署名付き `HttpOnly; Secure; SameSite=Lax` cookie を設定します。 |

運用上の注意:

- JavaScript が必要です。支援技術、強化ブラウザ、スクリプト無効環境、synthetic monitor、API client を誤検知する可能性があります。まず `report` でログを確認してから `challenge` にしてください。
- `difficulty` は低く保ってください。3 を超える値は古いモバイル端末で CPU / battery cost が目立つ場合があります。
- `CHALLENGE_SECRET`、または設定した `secret_env` を Cloudflare Worker secret として設定してください。他の edge HMAC secret と同じ扱いでローテーションします。ローテーションすると既存 challenge cookie は無効になります。
- cookie は IP ではなく User-Agent hash と expiry に結び付けます。モバイルネットワークのIP変動で破綻しにくくするためです。
- AWS CloudFront Functions / Lambda@Edge build では unsupported warning を出します。この framework ではそれらの target で HTML challenge flow の配信と検証を実装しません。
