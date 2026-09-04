# Deterministic output audit

`npm run test:determinism` is the release audit for the current contract and
report formats. It executes the same LF fixtures in two distinct workspace
roots and requires byte-identical output for:

- OpenAPI inspection and the review-only policy candidate (including metadata);
- the NestJS Source Analyzer composition example;
- AWS and Cloudflare generated artifacts;
- JSON, SARIF, and GitHub Summary contract-diff reports; and
- Finding instance IDs and sorted finding order when evidence/object order or
  message text changes without changing semantic identity.

It also repeats Finding identity checks 100 times, compares Windows and POSIX
path separators, and reruns the OpenAPI, policy, and generated-artifact checks
with CRLF inputs. The CRLF report comparison ignores only byte-derived digests,
instance IDs, and byte sizes; all other semantic output must remain equal.
Contract reports include one active and one expired exception so JSON, SARIF,
and GitHub Summary suppression and governance output are compared together.

The audit also inventories the 49 committed golden files, checks workspace-
relative paths, and rejects secret-like literals, absolute home/temp paths, and
malformed fixture entries. It records only scenario counts and SHA-256 digests
in `reports/determinism-audit.json`; it never records source contents, policy
secrets, query values, or runtime timestamps.

Golden fixtures are evidence of the current output contract, not a replacement
for a semantic review. The audit has no implicit update mode. A golden change
must be a separate, reviewed diff with its changed output explained; do not
regenerate fixtures merely to make CI green.

The audit runs child processes with a minimal environment and overrides these
three variables with fixed, non-production fixture values so its digests never
depend on runner secrets: `EDGE_ADMIN_TOKEN`, `ORIGIN_SECRET`, and `JWT_SECRET`.
The report must be a direct child of `reports/`; symlink and hard-link targets
are rejected.

```bash
npm run test:determinism -- --output reports/determinism-audit.json
```
