# OpenAPI review example

This fixture demonstrates the review-only OpenAPI flow. From the repository
root:

```bash
npm ci
mkdir -p reports
npx cdn-security openapi inspect \
  --input examples/openapi/openapi.yaml \
  --workspace-root . \
  --json \
  --out reports/openapi-contract.json
npx cdn-security openapi generate-policy \
  --input examples/openapi/openapi.yaml \
  --workspace-root . \
  --profile balanced \
  --out policy/openapi.candidate.yml
npm run lint:policy -- policy/openapi.candidate.yml
npx cdn-security build \
  --policy policy/openapi.candidate.yml \
  --out-dir dist/openapi-candidate
```

Review the generated candidate and `policy/openapi.candidate.meta.json` before copying any setting into an active
policy. Generation does not overwrite `policy/security.yml`, apply a policy,
or deploy artifacts.

The fixture contains an explicitly public health endpoint, authenticated user
and admin-like endpoints, a required tenant header, a bounded query parameter,
a JSON body, a multipart upload with unknown size, and local component `$ref`s.
The `/admin/reports` name does not prove privileged authorization, and a bearer
scheme does not provide safe JWT issuer, audience, JWKS, algorithm, or secret
values to infer.

See the [full integration guide](../../docs/openapi-integration.md) for the
threat model, review checklist, limits, and troubleshooting.
