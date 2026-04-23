# Security Profiles

This framework ships three built-in profiles in `policy/profiles/`. Each one is a complete `security.yml` starting point that you copy and then customize.

| Profile | `metadata.risk_level` | Intended use |
|---------|-----------------------|--------------|
| `strict` | `strict` | High-security public sites, admin panels, low-trust clients. May break legacy clients or aggressive scrapers. |
| `balanced` | `balanced` | Default recommendation for typical web + API traffic. Reasonable block posture with low false-positive rate. |
| `permissive` | `permissive` | API-only surfaces or legacy compatibility. **Intentionally loose. NOT recommended for production.** |

The `risk_level` field is declarative: the build tool reads it and adjusts its behavior accordingly. It does not change the actual compiled output on its own — what changes behavior is the rest of the policy (allow_methods, limits, block rules, etc.).

---

## Choosing a profile

Start with **`balanced`** unless you have a specific reason not to. It is the reference configuration this framework is tuned for.

- Pick **`strict`** if you are hardening a public admin UI, payments flow, or high-value target and you can coordinate with client owners to fix any resulting compatibility regressions.
- Pick **`permissive`** only when you are running behind an upstream layer that already applies meaningful filtering (e.g. an API gateway with its own WAF) and you explicitly need to accept broader inputs for compatibility — for example, accepting all HTTP methods for an RPC-style API.

When in doubt, start `balanced` and tighten individual fields rather than switching wholesale to `strict`.

---

## The `permissive` warning

Because `permissive` is intentionally loose, the build tool prints a warning whenever it compiles a policy tagged `metadata.risk_level: permissive`:

```
[WARN] metadata.risk_level is "permissive" — this profile is intentionally loose and NOT recommended for production. See docs/profiles.md. Pass --fail-on-permissive in CI to hard-fail.
```

This is printed to `stderr` so it does not pollute generated output, but it is visible in CI logs.

### Hard-failing in production CI

For production pipelines, gate the build with `--fail-on-permissive`. The build will exit with a non-zero status if the policy is tagged permissive:

```bash
# Passes for strict / balanced; fails for permissive
cdn-security build --fail-on-permissive
# or directly:
node scripts/compile.js --policy policy/security.yml --fail-on-permissive
```

Recommended pattern:

- **Development / staging**: run `cdn-security build` (warning only)
- **Production release**: run `cdn-security build --fail-on-permissive`

This makes it impossible to accidentally ship a permissive policy to a production CDN.

### Opting in to the tag

The tag is optional. Base profiles (`policy/base.yml`) and hand-rolled policies are not tagged by default and will not trigger the warning.

If you copy `policy/profiles/permissive.yml` as the starting point for your own `policy/security.yml`, the `metadata.risk_level: permissive` tag comes with it. Leave it in place so the production CI gate can catch accidental deploys. Remove or change it only after you have tightened the policy enough that it no longer qualifies as permissive — and then you should use `balanced` or `strict` instead.

---

## Customizing a profile

Copy the profile you want as your starting point, then edit:

```bash
cp policy/profiles/balanced.yml policy/security.yml
$EDITOR policy/security.yml
npm run lint:policy
npm run build
```

See [quickstart.md](quickstart.md) for the full onboarding flow and [policy-runtime-sync.md](policy-runtime-sync.md) for the compile / deploy loop.
