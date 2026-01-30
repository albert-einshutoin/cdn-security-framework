# Example: Cloudflare Workers (E2E)

This example uses **cdn-security-framework** as a dev dependency: init → edit policy → build with `--target cloudflare` → deploy the generated **`dist/edge/cloudflare/index.ts`** to Cloudflare Workers.

---

## Prerequisites

- Node.js 18+
- Cloudflare account
- Wrangler CLI (`npm i -g wrangler` or use `npx wrangler`) and `wrangler login`

---

## Steps

### 1. Install and init

From this directory (`examples/cloudflare/`):

```bash
npm install
npm run init
```

This installs the framework from the repo root (`file:../..`) and creates `policy/security.yml` and `policy/profiles/balanced.yml`. For the published package, use `"cdn-security-framework": "^1.0.0"` in your project's `package.json`.

### 2. Edit policy (optional)

Edit `policy/security.yml` to adjust allowed methods, block rules, routes, response headers, etc.

### 3. Build

```bash
npm run build
```

This runs `npx cdn-security build --target cloudflare`: validates the policy and generates **`dist/edge/cloudflare/index.ts`**. Deploy this generated file (or copy it into your Worker project). Wrangler will compile TypeScript when you deploy.

### 4. Set the admin token secret

```bash
wrangler secret put EDGE_ADMIN_TOKEN
```

Enter your secret token when prompted. The Worker reads it from `env.EDGE_ADMIN_TOKEN`.

### 5. Deploy

Copy or link the generated Worker into a Wrangler project and deploy:

- **Option A**: Create a Worker project that uses the generated file. For example, create `src/index.ts` that re-exports or copy `dist/edge/cloudflare/index.ts` into your Worker's `src/`, then:

  ```bash
  wrangler deploy
  ```

- **Option B**: From the framework repo root, run Wrangler with the generated file. Configure `wrangler.toml` so that `main` points to `dist/edge/cloudflare/index.ts` (or the path relative to your project).

Ensure your Worker is attached to a route (e.g. `*\.yourdomain.com/*`) in the Cloudflare dashboard or via `wrangler.toml` routes.

### 6. Verify

```bash
# Without token: 401
curl -i https://YOUR_WORKER_DOMAIN/admin

# With token: allowed
curl -i -H "x-edge-token: YOUR_TOKEN" https://YOUR_WORKER_DOMAIN/admin

# Traversal / bad UA / too many query params: blocked
curl -i "https://YOUR_WORKER_DOMAIN/foo/../bar"
```

---

## Summary

| Step   | Command / action |
|--------|-------------------|
| Install | `npm install` (uses cdn-security-framework from repo or npm) |
| Init    | `npm run init` → creates `policy/security.yml` |
| Build   | `npm run build` → generates `dist/edge/cloudflare/index.ts` |
| Deploy  | Use `dist/edge/cloudflare/index.ts` in your Worker project and run `wrangler deploy` |

---

## See also

- [Cloudflare Workers Runtime](../../runtimes/cloudflare-workers/README.md)
- [Quick Start](../../docs/quickstart.md)
- [Policy and runtime sync](../../docs/policy-runtime-sync.md)
