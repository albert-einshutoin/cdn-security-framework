# Quick Start

## Purpose

This guide walks you through getting this template running in the shortest path.

## 1. Choose a Runtime

- **AWS CloudFront** → `runtimes/aws-cloudfront-functions`
- **Cloudflare** → `runtimes/cloudflare-workers`
- **Advanced validation (JWT/signing)** → use `runtimes/aws-lambda-edge` in addition

## 2. Simple Gate for /admin

### CloudFront Functions

Replace `CFG.adminGate.token` in `viewer-request.js`.

### Cloudflare Workers

```bash
wrangler secret put EDGE_ADMIN_TOKEN
```

## 3. Verify Behavior

- `/admin` returns 401 without a token
- Request with token is allowed
- Traversal, anomalous User-Agent, and excessive query params are blocked
