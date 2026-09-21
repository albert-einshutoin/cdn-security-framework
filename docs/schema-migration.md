# Policy Schema Migration

> **Languages:** English · [日本語](./schema-migration.ja.md)

## Published and candidate contracts

Published `cdn-security-framework@1.4.0` uses Policy **version 1**. The unpublished main candidate uses **version 2**; package.json still says 1.4.0 until the release GO gate. Identify a candidate by commit SHA and tarball SHA-256, not package version. No npm 2.0.0 release is implied here.

Core lint/build/API, each inherited policy document, init/guided, profiles/archetypes and OpenAPI candidates require v2. They do not silently migrate v1. Finding, Security IR, inspection, report and exception schema versions are independent and unchanged.

Breaking validation changes require a Policy schema major and npm major release. Additive optional fields do not require a Policy version bump. A future deprecation needs its own documented transition; this migration does not implement hypothetical renames or arbitrary version chaining.

## Explicit migration

Use the executable installed from the **candidate tarball**, not npm latest:

```bash
./node_modules/.bin/cdn-security migrate --policy policy/security.yml
./node_modules/.bin/cdn-security migrate --policy policy/security.yml --target cloudflare
./node_modules/.bin/cdn-security migrate --policy policy/security.yml --target cloudflare --write
```

Default `--to` is **2**. Preview reads the input and prints a fixed summary; it creates no files. The API `migratePolicy({ policyPath, toVersion?, target?, write?, cwd? })` also returns the converted `policy` as an intentional Policy artifact, which may contain sensitive configuration. Do not treat this object as a sanitized diagnostic or log it indiscriminately. Errors/warnings and CLI summaries contain fixed codes and known field names, not original YAML, paths, environment values or secrets. The API never calls process.exit.

| Setting or input | Outcome |
| --- | --- |
| Valid v1, ordinary settings | Change version to 2 only; preserve metadata, strings, environment references and array order |
| difficulty 1–4 | Preserve |
| difficulty 5/6 | Exit 2: explicitly choose a supported value; never clamp to 4 |
| AWS csp_nonce true | Exit 2: choose Cloudflare, origin-managed nonces, or explicitly change configuration; never disable automatically |
| AWS JWT/signed_url | Exit 2: unsupported by the AWS cache-hit enforcement boundary; never remove or disable automatically |
| Cloudflare nonce/JWT/signed_url | Preserve valid settings; schema validity does not establish deployment readiness |
| Provider-sensitive settings without target | Exit 2: explicitly select aws/cloudflare |
| Unknown fields / invalid data | Exit 1; do not discard unknown configuration |
| extends or root $ref | Exit 2; graph migration is unsupported, no dependencies are read or flattened |

The Policy schema has no target field. Migration's optional target is explicitly supplied by the user, unlike build's AWS default. Ordinary conversion is provider independent. Unknown target names are errors. No JWKS, external API or environment expansion occurs during migration. A separate target build still enforces #1017 and all existing safety checks.

Input version must be numeric 1 or 2. Version validation precedes noop: unknown equal versions cannot succeed; malformed v2 cannot evade validation. Valid v2→v2 and explicit valid v1→v1 are read-only noops, even with --write. Downgrade is unsupported. API toVersion retains number|string; CLI strings must be integer spellings such as `1` or `2`, not `2.0`.

| Result | CLI exit / API exitCode |
| --- | --- |
| Converted preview, saved conversion, validated noop | 0 |
| Argument, parse, schema, downgrade, resource or I/O error | 1 |
| Unsupported version or explicit human decision required | 2 (`reservedExit2: true`) |

## Preservation and bounded inputs

The single v1 adapter validates against the schema shipped in the published 1.4.0 tarball (schema SHA-256 `dcf963406f7afaff82edb3d8ae775de26587438d815d5bb3dbde4b57ee9ba1bd`). Core never consults this legacy schema. Only version changes automatically. Input objects are not mutated.

The guarantee covers parsed JSON-compatible settings, not YAML comments, formatting, anchor spelling or object identity. Aliased values may be serialized independently. Unsupported tags/merge structures, cycles, special prototype keys and non-JSON values are rejected rather than silently converted. Limits: 1 MiB input/output, depth 64, 50 YAML aliases and 10,000 visited values (repeated aliases count). No referenced graph is migrated. Every v2 inherited document must declare version 2; a v2 root cannot hide a v1 dependency.

## Explicit save and rollback

`--write` / `write: true` authorizes changing the selected policy **only on successful conversion**. Noop, manual-decision and invalid-input results never save. Leaf symlinks are rejected at input read; writing a multi-link input is rejected. Trusted parent directory aliases are resolved and their identity is pinned.

Saving requires an absent sibling `<policy>.v1.bak`; an existing file, symlink, hardlink or directory at that name is a collision. The backup holds the original bytes with mode 0600. A separate exclusive staging file holds the complete validated, round-trip-checked output. Before rename, input bytes, file identity, link count, mode and parent identity are rechecked; the staged file must retain the original ownership and final permission bits. The commit point is the successful rename over the selected policy. The report writer's truncate-in-place behavior is **not** used.

Before commit, failures leave the original bytes/hash unchanged and cleanup removes only owned temporary/backup files. After commit the policy has intentionally changed and the original backup remains. Cleanup failures after commit are a success with a fixed warning, not a claim that the input is unchanged. Existing unrelated files are not overwritten. A concurrent external edit is preserved, not reverted by the tool.

Special permission bits are rejected; ACLs and extended attributes are not preserved by replacement. If cleanup itself is denied before commit, the fixed error `MIGRATION_SAVE_FAILED_CLEANUP_INCOMPLETE` indicates that owned artifacts may remain and need inspection; the input is still not committed. Unknown replacement files are never deleted as cleanup.

This contract assumes a trusted, exclusively managed POSIX local directory. It does not promise protection against arbitrary same-user mutation after final checks, crash/power-loss durability or Windows/network filesystem behavior. Use version control as the durable rollback source; the local backup does not replace it.

In a disposable rehearsal or an explicitly approved rollback:

1. Restore the saved pre-migration v1 bytes from git or `.v1.bak`.
2. Pin `cdn-security-framework@1.4.0` (never latest) in the rollback environment.
3. Lint/build the restored v1 policy using that pinned package and the intended provider.

The published 1.4.0 tarball omits the `esbuild` runtime dependency needed by its Cloudflare build. The disposable rollback rehearsal therefore installs `esbuild@0.28.0`, the version pinned by tag v1.4.0, alongside the unchanged published package. Pristine 1.4.0 Cloudflare build fails without this prerequisite; lint and AWS build do not establish Cloudflare rollback readiness. This does not add a candidate dependency.

Restoring v1 into the candidate v2 core is not a downgrade adapter. Returning to 1.4.0 also loses later safety hardening, including input/output privacy and AWS refusal safeguards; rollback is not automatically safe for production.
