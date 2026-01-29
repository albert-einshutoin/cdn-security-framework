# Cloudflare Workers Runtime

This directory contains the runtime for Cloudflare Workers.

## What Does It Protect?

- Same “entry blocking, normalization, header injection” as CloudFront Functions.
- Workers can also hold state when combined with KV / Durable Objects (e.g., for rate limiting).

## Setup

```bash
cd runtimes/cloudflare-workers
npm i -g wrangler
wrangler login
```

## Secret (Admin Gate)

```bash
wrangler secret put EDGE_ADMIN_TOKEN
```

## Deploy

```bash
wrangler deploy
```

## Verification

```bash
curl -i https://YOUR_WORKER_DOMAIN/admin
curl -i -H "x-edge-token: YOUR_TOKEN" https://YOUR_WORKER_DOMAIN/admin
```

## What Else Can You Do?

- Per-IP rate limiting with KV / Durable Objects (hard to do with Functions alone).
- More advanced bot detection (design so it does not overlap with WAF features).
