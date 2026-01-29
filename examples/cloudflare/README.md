# Example: Cloudflare Workers

This example shows how to deploy the Edge Security runtime with **Cloudflare Workers**.

---

## Prerequisites

- Cloudflare account
- Wrangler CLI (`npm i -g wrangler`) and `wrangler login`

---

## Steps

### 1. Use the runtime

From the repo root:

```bash
cd runtimes/cloudflare-workers
```

Or copy the contents of `runtimes/cloudflare-workers/` into your own Worker project.

### 2. Install and build (if needed)

```bash
npm install
npm run build   # if you have a build step
```

### 3. Set the admin token secret

```bash
wrangler secret put EDGE_ADMIN_TOKEN
```

Enter your secret token when prompted.

### 4. Deploy

```bash
wrangler deploy
```

Note: Your Worker must be attached to a route (e.g. `*\.yourdomain.com/*`) in the Cloudflare dashboard or via `wrangler.toml` routes.

### 5. Verify

```bash
# Without token: 401
curl -i https://YOUR_WORKER_DOMAIN/admin

# With token: allowed
curl -i -H "x-edge-token: YOUR_TOKEN" https://YOUR_WORKER_DOMAIN/admin

# Traversal / bad UA / too many query params: blocked
curl -i "https://YOUR_WORKER_DOMAIN/foo/../bar"
```

---

## Policy alignment

Runtime behavior is aligned with `policy/base.yml` (or `policy/profiles/balanced.yml`). When the policy compiler is added, Workers code can be generated from the policy.

---

## See also

- [Cloudflare Workers Runtime](../../runtimes/cloudflare-workers/README.md)
- [Quick Start](../../docs/quickstart.md)
- [Architecture](../../docs/architecture.md)
