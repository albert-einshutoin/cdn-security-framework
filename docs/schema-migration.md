# Policy Schema Migration

> **Languages:** English · [日本語](./schema-migration.ja.md)

This document defines how `policy/schema.json` evolves across schema versions and how consumers upgrade their policies.

---

## Current version: `1`

All policy files must declare `version: 1` at the top level. Any other value is rejected at lint time.

---

## SemVer contract for the schema

The schema version in `policy.version` is **not** the npm package version. The two evolve independently:

- **Additive changes** (new optional keys, new enum members) — published in a **minor** npm release. `version: 1` continues to lint and build.
- **Breaking changes** (renaming a key, removing a field, tightening a validator in a way that would reject existing valid policies) — bump the schema to `version: 2` and publish in a **major** npm release.

The schema bump and the npm major bump ship together.

### What counts as a breaking change

| Change | Breaking? |
| --- | --- |
| Add a new optional key | No |
| Add a new value to an enum | No |
| Tighten an existing validator (e.g. lower a max) that could reject previously valid values | **Yes** |
| Rename a key | **Yes** |
| Remove a key | **Yes** |
| Change the semantic meaning of an existing key | **Yes** |

---

## Deprecation window

When a key is slated for removal:

1. The release that introduces the replacement emits a **`lint:policy` warning** (not error) naming the deprecated key and the replacement.
2. The deprecation warning ships in at least **one minor release** before the breaking change.
3. The breaking change ships in the next major release, along with a `version: 2` schema and a registered CLI migration (see below).

---

## The `migrate` CLI

```bash
npx cdn-security migrate --policy policy/security.yml --to 2
```

- Prints the current and target schema versions.
- If a registered migration exists, rewrites the policy in memory (and to disk with `--write`) to the target version.
- Exits non-zero and references this document if no migration path is registered in the installed CLI version.

The v1-only current build prints:

```
[INFO] Current schema version: 1
[INFO] Target schema version:  1
[OK] Already at target version — no migration needed.
```

### Migration author contract

Each migration step is a pure function `(policy v_n) → (policy v_n+1)` registered in `bin/cli.js`. Chaining is automatic: `--to 3` on a v1 policy runs `v1→v2` then `v2→v3`.

Migrations:
- Must not lose user configuration. Deprecated keys should be translated, not dropped silently.
- Must emit a one-line summary per transformation applied, so diff review is straightforward.
- Must include a matching unit test case in `scripts/compile-unit-tests.js`.

---

## Example: hypothetical v1 → v2 migration

Suppose a future release renames `request.block.ua_contains` to `request.block.user_agent.contains` and moves method allow-listing into `request.methods.allow`.

### v1 input

```yaml
version: 1
request:
  allow_methods: [GET, HEAD]
  block:
    ua_contains: [sqlmap, nikto]
```

### v2 output

```yaml
version: 2
request:
  methods:
    allow: [GET, HEAD]
  block:
    user_agent:
      contains: [sqlmap, nikto]
```

### Running the migration

```bash
npx cdn-security migrate --policy policy/security.yml --to 2 --write
```

Expected log:

```
[INFO] Policy: policy/security.yml
[INFO] Current schema version: 1
[INFO] Target schema version:  2
[MIGRATE v1→v2] Renamed request.allow_methods → request.methods.allow
[MIGRATE v1→v2] Renamed request.block.ua_contains → request.block.user_agent.contains
[SUCCESS] Wrote migrated policy to policy/security.yml
```

---

## Rollback

If a v2 policy regresses in production:

1. Pin your npm dependency to the last v1-compatible major version.
2. Restore the pre-migration policy from git (the original file is the migration's source of truth).
3. File an issue — a migration that loses information is a bug.

---

## Release coupling

- The schema file: `policy/schema.json`
- The CLI validator: `scripts/policy-lint.js`
- The migration registry: `bin/cli.js` (`migrate` command)
- The release changelog: `CHANGELOG.md`

All four must be updated together when bumping schema versions.
