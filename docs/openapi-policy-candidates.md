# OpenAPI policy candidates

`cdn-security openapi generate-policy` creates a review-only policy candidate
and a deterministic metadata sidecar. It never reads, merges, or overwrites
`policy/security.yml`, and it never deploys generated artifacts.

## Mapping contract

| OpenAPI / recommendation | Policy candidate | Rule |
| --- | --- | --- |
| Union of operation methods | `request.allow_methods` | Applied globally. Route-specific method restrictions are reported as omitted because the current route matcher cannot express exact OpenAPI paths. |
| Headers required by every operation | `request.block.header_missing` | The intersection is added to the selected profile baseline. Route-specific required headers are reported as omitted. |
| Finite `maxQueryParams` recommendation for every operation | `request.limits.max_query_params` | The largest recommended value is used only when it is within the current policy schema range. |
| Finite `maxQueryLength` recommendation for every operation | `request.limits.max_query_length` | The largest recommended value is used only when it is within the current policy schema range. |
| Finite `maxUriLength` recommendation for every operation | `request.limits.max_uri_length` | The largest path recommendation is used only when it is within the current policy schema range. |
| Route-specific methods or headers | Metadata `omittedRecommendations` | A policy path prefix also matches descendants, so it is broader than an exact OpenAPI path. |
| Request content types, body size, and parameter constraints | Metadata `omittedRecommendations` | The current policy schema has no equivalent request control. No invented field or approximate control is emitted. |
| Bearer, OAuth2, API key, or other authentication declarations | Metadata `omittedRecommendations` | Authentication remains a recommendation unless a future explicit mapping contract provides all required policy values. JWT issuer, audience, JWKS, algorithms, and secrets are never inferred. |

The selected built-in profile supplies the reviewed baseline controls. Example
profile routes are removed because they contain application-specific path and
authentication assumptions. OpenAPI-derived fields replace only the mappings
listed above.
If a limit recommendation is partial, unknown, unbounded, zero-only, or outside
the current schema range, the selected profile value is retained and the
recommendation is reported as omitted.

## Generate and review

```bash
npx cdn-security openapi generate-policy \
  --input openapi.yaml \
  --profile balanced \
  --out policy/openapi.candidate.yml
```

The command also writes `policy/openapi.candidate.meta.json`. Existing output
files cause the command to fail; use `--force` only after reviewing the paths.
Both files stay inside `--workspace-root` (the current directory by default),
and neither file may replace the OpenAPI input or a referenced source file.

Review the candidate and sidecar before copying any setting into the active
policy. In particular, inspect `omittedRecommendations` and
`capabilityFindings`. Then validate and build the candidate explicitly:

```bash
npm run lint:policy -- policy/openapi.candidate.yml
npx cdn-security build --policy policy/openapi.candidate.yml --out-dir dist/candidate
```

Building the candidate only generates local artifacts. It does not apply or
deploy the policy.

## Determinism and metadata

The YAML and JSON sidecar contain no timestamp or absolute path. Repeating the
command with the same input bytes and options produces byte-identical output;
normalized field order does not affect the candidate policy. The sidecar
records the raw source digest, Security IR digest, candidate digest,
generator version, applied and omitted recommendations, and target capability
findings. It never records raw credentials, request bodies, or inferred secret
values.
