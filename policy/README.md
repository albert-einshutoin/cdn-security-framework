# Policy

This directory holds the **security policy** (source of truth) and **profiles** that you can copy to `security.yml` or `base.yml`.

---

## Recommended: init and build

**Preferred flow:** use the CLI to create policy and generate runtimes:

```bash
npx cdn-security init    # Creates policy/security.yml and policy/profiles/<profile>.yml
npx cdn-security build   # Reads policy/security.yml (or policy/base.yml if security.yml is missing) and generates dist/edge/ and dist/infra/
```

Build looks for `policy/security.yml` first; if it does not exist, it uses `policy/base.yml`. So you can use either file as your active policy.

---

## Files

| File | Role |
|------|------|
| `security.yml` | Created by `npx cdn-security init`. Active policy when present. |
| `base.yml` | Alternative active policy. Used by build when `security.yml` is missing. Edit this, or overwrite with a profile (see below). |
| `profiles/balanced.yml` | Default: balanced security vs compatibility. |
| `profiles/strict.yml` | Stricter limits and more blocks; best when you control clients. |
| `profiles/permissive.yml` | Looser limits and fewer blocks; for APIs, scripts, legacy clients. |

---

## Choosing a Profile (when using base.yml)

If you use `base.yml` instead of `init`, choose a profile and copy it to `base.yml`:

| Profile | When to use |
|---------|-------------|
| **balanced** | Default. Good for most sites and APIs (browser + normal clients). |
| **strict** | Maximum edge security: tighter query/URI limits, more UA blocks (e.g. curl/wget), more path patterns, stricter CSP. Use when you don’t need to allow generic scripts or legacy clients. |
| **permissive** | Fewer blocks and higher limits. Use for APIs or when clients may omit User-Agent or use PUT/DELETE/OPTIONS. |

```bash
cp policy/profiles/balanced.yml policy/base.yml
# or
cp policy/profiles/strict.yml policy/base.yml
cp policy/profiles/permissive.yml policy/base.yml
```

Then run **build** to generate runtimes (see [Policy and runtime sync](../docs/policy-runtime-sync.md)). Run policy lint before deploying:

```bash
npx cdn-security build
# or
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

## Numeric field bounds

Policy lint (`npm run lint:policy`) rejects values outside these ranges to catch
footguns (zero/negative limits, runaway caches, WAF-incompatible rate ceilings)
early. If your environment genuinely needs a value outside these bounds, open an
issue with the use case.

| Field | Min | Max | Notes |
|--------|-----|-----|-------|
| `request.limits.max_query_length` | 1 | 65,536 | Bytes |
| `request.limits.max_query_params` | 1 | 1,024 | Keys |
| `request.limits.max_uri_length` | 1 | 8,192 | Bytes |
| `request.limits.max_header_size` | 1 | 65,536 | Bytes |
| `routes[].auth_gate.clock_skew_sec` | 0 | 600 | Seconds |
| `routes[].auth_gate.cache_ttl_sec` | 0 | 86,400 | Seconds (1 day) |
| `response_headers.cors.max_age` | 0 | 86,400 | Seconds (browser CORS cap) |
| `firewall.waf.rate_limit` | 100 | 2,000,000,000 | AWS WAFv2 rate-based window |
| `origin.timeout.connect` | 1 | 10 | CloudFront cap |
| `origin.timeout.read` | 1 | 60 | CloudFront cap |

---

## Permissive profile warning

The `permissive` profile is tagged `metadata.risk_level: permissive`. Whenever the compiler sees that tag it prints a warning to stderr and, if `--fail-on-permissive` is passed, exits non-zero. Gate production CI with:

```bash
npx cdn-security build --fail-on-permissive
```

See [docs/profiles.md](../docs/profiles.md) for the full profile comparison and the recommended dev/prod gate pattern.

---

## Related

* [Profiles](../docs/profiles.md) — how to choose a profile and gate permissive in production CI.
* [Policy and runtime sync](../docs/policy-runtime-sync.md) — how to keep policy and runtimes in sync.
* [Architecture](../docs/architecture.md) — policy-driven design.

---

## Optional WAF fingerprint controls

You can add TLS fingerprint rules in policy:

```yaml
firewall:
  waf:
    fingerprint_action: count   # count | block
    ja3_fingerprints:
      - "0123456789abcdef0123456789abcdef"
    ja4_fingerprints:
      - "t13d1516h2_8daaf6152771_02713d6af862"
```

Recommended rollout: start with `count`, review logs/metrics, then switch to `block`.
