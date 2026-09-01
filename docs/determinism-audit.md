# Deterministic output audit

`npm run test:determinism` is the release audit for the current contract and
report formats. It executes the same supported fixtures twice and requires
byte-identical output for:

- OpenAPI inspection and the review-only policy candidate (including metadata);
- the NestJS Source Analyzer composition example;
- AWS and Cloudflare generated artifacts;
- JSON, SARIF, and GitHub Summary contract-diff reports; and
- Finding instance IDs and sorted finding order when evidence/object order or
  message text changes without changing semantic identity.

The audit also inventories the 49 committed golden files, checks workspace-
relative paths, and rejects secret-like literals, absolute home/temp paths, and
malformed fixture entries. It records only scenario counts and SHA-256 digests
in `reports/determinism-audit.json`; it never records source contents, policy
secrets, query values, or runtime timestamps.

Golden fixtures are evidence of the current output contract, not a replacement
for a semantic review. The audit has no implicit update mode. A golden change
must be a separate, reviewed diff with its changed output explained; do not
regenerate fixtures merely to make CI green.

Run locally with non-production fixture values:

```bash
EDGE_ADMIN_TOKEN=determinism-token-not-for-deploy \
ORIGIN_SECRET=determinism-origin-not-for-deploy \
JWT_SECRET=determinism-jwt-not-for-deploy \
npm run test:determinism -- --output reports/determinism-audit.json
```
