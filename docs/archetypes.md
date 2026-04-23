# Policy Archetypes

> **Languages:** English · [日本語](./archetypes.ja.md)

Archetypes are policy presets shaped around common application topologies. Unlike profiles (`strict`, `balanced`, `permissive`), which describe a **security posture**, archetypes describe the **app shape**: what methods the origin expects, where auth sits, which CSP strategy fits the rendered output.

Pick an archetype that matches your app, then tune the policy. Every archetype sets `metadata.risk_level` so existing CI gates (permissive warnings, drift checks) still apply.

---

## Available archetypes

### `spa-static-site`
**For**: built SPA (React / Vue / Svelte) or a static marketing site served from CloudFront/Cloudflare.
**Methods**: `GET`, `HEAD` only — no writes.
**Auth**: none at the edge (the origin is immutable assets).
**Headers**: nonce-based CSP for inline shell scripts, HSTS preload, strict Referrer-Policy.
**Defenses**: `/../` + `.git/` + `.env` path blocking, scanner UA blocklist.

### `rest-api`
**For**: JSON API origin. No HTML rendered.
**Methods**: full REST set including `OPTIONS` for CORS preflight.
**Auth**: RS256 JWT on `/api/*` (JWKS with SSRF guard + stale-if-error cache).
**Headers**: `default-src 'none'; frame-ancestors 'none';` — defense-in-depth for accidental HTML.
**CORS**: allowlisted origin + credentials + 10-min preflight cache.
**Rate limits**: aggressive on `/api/auth` (200/IP/5min).

### `admin-panel`
**For**: internal admin UI.
**Methods**: `GET`, `HEAD`, `POST`.
**Auth**: `static_token` gate at the root of the site (pair with L7 IP allowlist / VPN / WAF geo-block).
**Headers**: strict CSP + COOP + COEP, no-store everywhere, narrow permissions-policy.
**Defenses**: expanded UA blocklist (no curl/wget/python-requests).

### `microservice-origin`
**For**: backend microservice behind the CDN. The origin must only accept requests that came through this edge.
**Methods**: full REST set except `OPTIONS`.
**Auth**: edge injects `X-Edge-Secret: $ORIGIN_SECRET` so the origin can reject direct hits.
**Headers**: `default-src 'none'; frame-ancestors 'none';`, HSTS.
**Timeouts**: 5s connect, 30s read.

---

## Using an archetype

### Interactive scaffold

```bash
npx cdn-security init
```

At the starter prompt, pick **Archetype**, then choose one of the four.

### Non-interactive

```bash
npx cdn-security init --platform aws --archetype rest-api
```

Scaffolds `policy/security.yml` from `policy/archetypes/rest-api.yml` and places a copy in `policy/archetypes/rest-api.yml` for reference. Edit `policy/security.yml` as needed, then run `npm run build`.

### Mutual exclusivity

`--profile` and `--archetype` cannot be combined. Pick one starter shape. To switch later, copy the target archetype or profile over `policy/security.yml` and re-run `npm run build` + `npm run test:drift`.

---

## Archetype vs profile

| | Profile | Archetype |
| --- | --- | --- |
| Purpose | Security posture dial | App-shape preset |
| Choices | strict / balanced / permissive | spa-static-site / rest-api / admin-panel / microservice-origin |
| Dictates | How much security vs compatibility | Which auth, methods, CSP, CORS to start from |
| `risk_level` | Matches the profile name | Set per archetype (balanced or strict) |

You can start from a profile and adjust, or start from an archetype and dial the risk_level after review. The compiler treats all policies as YAML — archetypes are not a special code path.

---

## CI coverage

Each archetype has a matching golden fixture under `tests/golden/archetypes/<name>/` exercised by `npm run test:drift`. Any compiler change that alters archetype output is caught there before release.

Adding a new archetype? See [How to add an archetype](#how-to-add-an-archetype) below.

---

## How to add an archetype

1. Create `policy/archetypes/<name>.yml`. Required: `version: 1`, `metadata.risk_level`, `metadata.description`. Fold use-case guidance into `description`.
2. Lint: `npm run lint:policy -- policy/archetypes/<name>.yml`
3. Generate the golden fixture:
   ```bash
   mkdir -p tests/golden/archetypes/<name>
   EDGE_ADMIN_TOKEN=ci-build-token-not-for-deploy \
     node scripts/compile.js --policy policy/archetypes/<name>.yml --out-dir tests/golden/archetypes/<name>
   # ...and compile-cloudflare.js, compile-infra.js, compile-cloudflare-waf.js
   ```
4. Add the archetype to `scripts/check-drift.js` scenarios.
5. Add a choice to the `init` wizard in `bin/cli.js`.
6. Document it in this file (EN + JA).
