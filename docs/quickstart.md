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
npx cdn-security build
```

This validates the policy and generates **Edge Runtime** code into `dist/edge/` (e.g. `dist/edge/viewer-request.js` for AWS CloudFront Functions). No manual editing of `CFG` or runtime config.

## 3. Admin gate token

For `/admin`, `/docs`, `/swagger` protection:

- Set `EDGE_ADMIN_TOKEN` in your environment or CDN secret management (e.g. Terraform, Wrangler).
- The build injects it at compile time when the variable is set; otherwise it uses a placeholder you can replace in your deployment pipeline.

You do **not** edit `viewer-request.js` by hand; the token is driven by policy (routes.auth_gate.token_env) and environment.

## 4. Deploy

Use the generated files in **`dist/edge/`** with Terraform, CDK, or your CDN console:

- AWS: reference `dist/edge/viewer-request.js` (and optionally viewer-response.js when generated) in your CloudFront Function / Lambda@Edge config.
- Cloudflare: use generated Workers code from `dist/edge/` when Cloudflare target is implemented.

## 5. Verify behavior

- `/admin` returns 401 without a token
- Request with valid token is allowed
- Path traversal, anomalous User-Agent, and excessive query params are blocked
