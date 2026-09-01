# Release compatibility matrix

The release workflow validates the package on Node 20.17.0, Node 22, and Node
24. `full-validation` runs the complete `npm run test:ci` gate on Node 24. The
same matrix then runs generated-boundary, documentation, API-contract, packed
install, CLI, OpenAPI, NestJS example, and AWS/Cloudflare build checks.

Each matrix job writes a `schemaVersion: 1` JSON report containing only:

- the Node and package versions;
- public export keys and schema digests;
- pass/fail booleans for CLI and representative examples; and
- relative generated-file paths, sizes, and SHA-256 digests.

`full-release-matrix-audit` requires exactly the three reports and fails when
Node majors, package version, API exports, schemas, example checks, or generated
artifact digests differ. Reports are uploaded as 30-day GitHub Actions artifacts;
they do not contain environment values, absolute paths, OpenAPI source, or
generated runtime contents.

For a local representative report (not a substitute for hosted Node 20/22
evidence):

```bash
EDGE_ADMIN_TOKEN=matrix-token-not-for-deploy \
ORIGIN_SECRET=matrix-origin-not-for-deploy \
JWT_SECRET=matrix-jwt-not-for-deploy \
npm run test:release-matrix -- --output reports/release-matrix/local.json
```

The matrix does not widen the supported engine range (`>=20.17.0`), add an OS
matrix, or create a performance percentage gate.
