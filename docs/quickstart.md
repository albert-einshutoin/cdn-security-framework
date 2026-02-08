# Quick Start

## Purpose

This guide walks you through getting this framework running in the shortest path: install → init → edit policy → build → deploy.

## 1. Install and init

```bash
npm install --save-dev cdn-security-framework
npx cdn-security init
```

Choose platform (AWS CloudFront / Cloudflare Workers) and profile (Strict / Balanced / Permissive). This creates `policy/security.yml` and `policy/profiles/<profile>.yml`.

Non-interactive: `npx cdn-security init --platform aws --profile balanced --force`

## 2. Edit policy and build

Edit `policy/security.yml` as needed (allow_methods, block rules, routes, etc.), then:

```bash
# AWS (default)
npx cdn-security build

# Cloudflare Workers
npx cdn-security build --target cloudflare
```

This validates the policy and generates **Edge Runtime** code into `dist/edge/`. For AWS, this produces `viewer-request.js`, `viewer-response.js`, and `origin-request.js`. For Cloudflare, it produces `cloudflare/index.ts`. No manual editing of `CFG` or runtime config.

## 3. Admin gate token

For `/admin`, `/docs`, `/swagger` protection:

- Set `EDGE_ADMIN_TOKEN` in your environment or CDN secret management (e.g. Terraform, Wrangler).
- The build injects it at compile time when the variable is set; otherwise it uses a placeholder you can replace in your deployment pipeline.

You do **not** edit `viewer-request.js` by hand; the token is driven by policy (routes.auth_gate.token_env) and environment.

## 4. Test

```bash
npm run test:runtime
```

Runs all runtime tests (viewer-request + origin-request).

## 5. Deploy

Use the generated files in **`dist/edge/`** with Terraform, CDK, or your CDN console:

- **AWS**: Reference `dist/edge/viewer-request.js` and `dist/edge/viewer-response.js` in your CloudFront Function config. Reference `dist/edge/origin-request.js` in your Lambda@Edge config (required for JWT and Signed URL auth gates).
- **Cloudflare**: Deploy `dist/edge/cloudflare/index.ts` with Wrangler (`wrangler deploy`).

## 6. Verify behavior

- `/admin` returns 401 without a token
- Request with valid token is allowed
- Path traversal, anomalous User-Agent, and excessive query params are blocked
