# Policy

This directory holds the **security policy** (source of truth) and **profiles** that you can copy to `base.yml`.

---

## Files

| File | Role |
|------|------|
| `base.yml` | Active policy. Edit this, or overwrite it with a profile (see below). |
| `profiles/balanced.yml` | Default: balanced security vs compatibility. |
| `profiles/strict.yml` | Stricter limits and more blocks; best when you control clients. |
| `profiles/permissive.yml` | Looser limits and fewer blocks; for APIs, scripts, legacy clients. |

---

## Choosing a Profile

| Profile | When to use |
|---------|-------------|
| **balanced** | Default. Good for most sites and APIs (browser + normal clients). |
| **strict** | Maximum edge security: tighter query/URI limits, more UA blocks (e.g. curl/wget), more path patterns, stricter CSP. Use when you don’t need to allow generic scripts or legacy clients. |
| **permissive** | Fewer blocks and higher limits. Use for APIs or when clients may omit User-Agent or use PUT/DELETE/OPTIONS. |

After choosing, copy the profile to `base.yml`:

```bash
cp policy/profiles/balanced.yml policy/base.yml
# or
cp policy/profiles/strict.yml policy/base.yml
cp policy/profiles/permissive.yml policy/base.yml
```

Then **sync runtimes** manually (see [Policy and runtime sync](../docs/policy-runtime-sync.md)). Run policy lint before deploying:

```bash
node scripts/policy-lint.js policy/base.yml
```

---

## Profile Comparison (summary)

| Setting | balanced | strict | permissive |
|--------|----------|--------|------------|
| `max_query_length` | 1024 | 512 | 2048 |
| `max_query_params` | 30 | 20 | 50 |
| `max_uri_length` | 2048 | 1024 | 4096 |
| UA block list | scanners | scanners + curl, wget, etc. | scanners only |
| Block missing User-Agent | yes | yes | no |
| Allowed methods (default) | GET, HEAD, POST | GET, HEAD, POST | + PUT, PATCH, DELETE, OPTIONS |
| Admin path prefixes | /admin, /docs, /swagger | + /api/admin, /internal | /admin, /docs, /swagger |
| CSP | standard | stricter (script-src, form-action) | standard |

---

## Related

* [Policy and runtime sync](../docs/policy-runtime-sync.md) — how to keep policy and runtimes in sync.
* [Architecture](../docs/architecture.md) — policy-driven design.
