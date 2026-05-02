# Edge JS Challenge

`firewall.challenge` is an opt-in, experimental Cloudflare Workers-only JavaScript challenge with a lightweight proof-of-work check. It is intended as low-cost friction for suspicious browser-shaped traffic, not as a CAPTCHA replacement or a bot-management product.

```yaml
firewall:
  challenge:
    enabled: true
    mode: challenge       # report | block | challenge
    path_prefixes: ["/login", "/checkout"]
    ua_contains: ["headlesschrome"]
    difficulty: 3         # leading SHA-256 hex zeroes, max 6
    ttl_sec: 900
    secret_env: CHALLENGE_SECRET
```

Modes:

| Mode | Behavior |
|------|----------|
| `report` | Logs matching traffic and allows it. Use this before enforcement. |
| `block` | Returns 403 for matching traffic. |
| `challenge` | Serves an HTML page that runs a small browser proof-of-work, verifies the solution, then sets a signed `HttpOnly; Secure; SameSite=Lax` cookie. |

Operational notes:

- This feature requires JavaScript and may block assistive technology, hardened browsers, script-disabled clients, synthetic monitors, and API clients. Start in `report` mode and review logs before enabling `challenge`.
- Keep `difficulty` low. Values above 3 can create noticeable CPU/battery cost on older mobile devices.
- Set `CHALLENGE_SECRET` (or your configured `secret_env`) as a Cloudflare Worker secret. Rotate it like other edge HMAC secrets; rotation invalidates existing challenge cookies.
- The cookie is bound to the User-Agent hash and expiry, not to IP, to avoid breaking mobile networks with changing addresses.
- AWS CloudFront Functions / Lambda@Edge builds emit an unsupported warning. This framework does not attempt to serve and verify the HTML challenge flow on those targets.
