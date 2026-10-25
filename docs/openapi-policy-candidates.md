# OpenAPI policy candidates

`cdn-security openapi generate-policy` creates a review-only policy candidate
and a deterministic metadata sidecar. It never reads, merges, or overwrites
`policy/security.yml`, and it never deploys generated artifacts.

## Mapping contract

| OpenAPI / recommendation | Policy candidate | Rule |
| --- | --- | --- |
| Union of operation methods | `request.allow_methods` | Applied globally. Route-specific method restrictions are reported as omitted because the current route matcher cannot express exact OpenAPI paths. |
| Headers required by every operation | `request.block.header_missing` | The intersection is added to the selected profile baseline. Route-specific required headers are reported as omitted. |
| Finite query and URI limit recommendations | Metadata `omittedRecommendations` | OpenAPI does not forbid undeclared query parameters, so the selected profile limits are retained instead of treating the declared parameters as a closed upper bound. |
| Route-specific methods or headers | Metadata `omittedRecommendations` | A policy path prefix also matches descendants, so it is broader than an exact OpenAPI path. |
| Request content types, body size, and parameter constraints | Metadata `omittedRecommendations` | The current policy schema has no equivalent request control. No invented field or approximate control is emitted. |
| Bearer, OAuth2, API key, or other authentication declarations | Metadata `omittedRecommendations` | Authentication remains a recommendation unless a future explicit mapping contract provides all required policy values. JWT issuer, audience, JWKS, algorithms, and secrets are never inferred. |

The selected built-in profile supplies the reviewed baseline controls. Example
profile routes are removed because they contain application-specific path and
authentication assumptions. OpenAPI-derived fields replace only the mappings
listed above.
Limit recommendations are reported as omitted and the selected profile values
are retained. A future contract may apply them only if it can prove that
additional query input is forbidden.

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

## Version-aware Next.js virtual patch

Provide both the application's manifest and npm lockfile to add reviewed,
version-specific controls to the same candidate:

```bash
npx cdn-security openapi generate-policy \
  --input openapi.yaml --profile balanced \
  --package-json package.json --package-lock package-lock.json \
  --deployment self-hosted --out policy/next.candidate.yml
npx cdn-security build --policy policy/next.candidate.yml --target aws --out-dir dist/next-aws
```

Current catalog `nextjs-advisory-v2` covers **CVE-2025-29927 plus the listed Next.js GHSA advisories**. It is not
a complete dependency audit or a live advisory feed. It checks direct production
`next` declarations against npm lockfile v2/v3, including matching root identity
and dependency declarations. Only stable exact versions resolved from the public
npm `next` tarball are supported. Aliases, local/workspace links, private registries,
prereleases, missing resolutions, and development-only Next installations remain
unknown. Inputs must be regular UTF-8 files inside the workspace, at most 8 MiB
each. No package scripts, installs, network lookups, or module traversal run.

`--deployment` describes the **origin**, independently of the edge provider:

| Origin | Result for an affected Next.js version |
| --- | --- |
| `self-hosted` (`next start` or standalone) | Generate `request.block.header_present: [x-middleware-subrequest]`. |
| `static-export` | Report this CVE as not applicable; no middleware runtime exists. |
| `unknown` (default) | Refuse generation with `APPLICATION_ANALYSIS_UNKNOWN`; no files are written. |

The [vendor advisory](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw)
lists affected versions `>=11.1.4 <12.3.5`, `>=13.0.0 <13.5.9`,
`>=14.0.0 <14.2.25`, and `>=15.0.0 <15.2.3`. Versions outside these ranges
receive no patch for **this CVE**; that does not establish general safety.
Managed hosting is not inferred. Choose `unknown` for unsupported deployment
contexts rather than guessing that a host is unaffected.

For additional catalog entries, the candidate is deliberately conservative: the
rewrite/redirect hostname SSRF and AVIF optimization RCE are `unknown` because
package metadata cannot prove the exact route/config entry or safe disablement.
The Edge Server Action body advisory is also `unknown` until a provider proves a
5 MiB limit before origin (AWS WAF body inspection is 16 KiB by default and 64
KiB maximum for CloudFront; [inspection limits](https://docs.aws.amazon.com/waf/latest/developerguide/waf-oversize-request-components.html)
alone do not establish a 5 MiB enforcement rule). Cache confusion and the
Turbopack middleware bypass are `upgrade-required`. The latter also has a vendor
workaround requiring authorization in the page's server-side data path; neither
is converted to a generic Edge rule.

Curated boundaries, checked 2026-10-26 (stable versions only):

| Advisory | Affected Next.js versions | Diagnostic for an affected self-hosted version |
| --- | --- | --- |
| [Hostname SSRF](https://github.com/vercel/next.js/security/advisories/GHSA-p9j2-gv94-2wf4) | `>=12.0.0 <15.5.21` or `>=16.0.0 <16.2.11` | `unknown` |
| [Server Action body](https://github.com/vercel/next.js/security/advisories/GHSA-4c39-4ccg-62r3) | `>=13.0.0 <15.5.21` or `>=16.0.0 <16.2.11` | `unknown` |
| [AVIF optimization](https://github.com/vercel/next.js/security/advisories/GHSA-2xp9-vwfh-vxw4) | `>=10.0.0 <15.5.24` or `>=16.0.0 <16.3.3` | `unknown` |
| [Server-fetch cache confusion](https://github.com/vercel/next.js/security/advisories/GHSA-68g3-v927-f742) | `>=13.0.0 <15.5.21` or `>=16.0.0 <16.2.11` | `upgrade-required` |
| [Turbopack middleware bypass](https://github.com/vercel/next.js/security/advisories/GHSA-6gpp-xcg3-4w24) | `>=16.0.0 <16.2.11` | `upgrade-required` |

Version matching does not prove the vulnerable feature is enabled. An explicit
static export has no relevant Next.js server runtime; an unknown deployment
stops generation and the live check. A version outside a listed range is only
`not-affected-version` for that entry. Catalog changes require vendor-source and
boundary-test review; an updated, withdrawn, or contradictory advisory requires
reassessment. A contradictory live version range fails the check.

Both AWS CloudFront Functions and Cloudflare Workers reject any occurrence of
the header, including an empty value, before CORS preflight or origin forwarding.
The rule applies to every path, including framework routes absent from OpenAPI.
With application inputs, OpenAPI-derived global methods, required headers and
numeric limits are omitted and the selected profile baseline is retained because
an API specification does not describe all application traffic. Other OpenAPI
recommendations remain visible for review. Review profile limits and CSP against
your pages, assets and authentication before adoption.

The candidate also records omissions for runtime API-schema validation, adaptive
bot/rate suppression, and origin-direct-access prevention. Those require
application, provider, or network evidence and are not claimed by an OpenAPI
policy candidate.

The sidecar's `application` field records both raw input digests, the supplied
deployment, catalog coverage, resolved version, decision and advisory source.
Invalid input or manifest/lock mismatch is `APPLICATION_INPUT_INVALID`; unresolved
analysis stops generation. Source digests bind supplied files, not installed code
or a running deployment. Upgrade Next.js as the permanent fix. The virtual patch
depends on enforcing the edge rule on every external route and preventing direct
origin access; monitor mode only logs.

For a self-hosted origin behind Cloudflare, review `capabilityFindings` first.
The balanced profile contains AWS managed-WAF mappings that Cloudflare cannot
represent exactly, so a full `build --target cloudflare` can refuse those
mappings. Review and edit that candidate's WAF settings for the provider before
building; do not treat this header control as proof of WAF parity or account
entitlement.

Programmatic callers of `generatePolicyCandidate` can supply the same offline
inputs as `application: { packageJson: manifestText, packageLock: lockText,
deployment: 'self-hosted' }` in its options. Omit `application` to retain the
existing OpenAPI-only mapping. Unknown analysis throws an error with code
`APPLICATION_ANALYSIS_UNKNOWN`; invalid inputs use `APPLICATION_INPUT_INVALID`.
The API parses the supplied strings and does not read files.

## Continuous advisory check

`cdn-security advisory check --package-json package.json --package-lock
package-lock.json --deployment self-hosted` queries public GitHub-reviewed npm
advisories for an exact direct production Next.js version. Its JSON separates
`mitigation-candidate-available` (supported by this catalog), `unassessed`
(no curated assessment), `unknown`, `upgrade-required`, and `not-applicable` (only this advisory and deployment
combination). A candidate does not prove that a policy is active at the CDN.
The `catalogFindings` field separately reports curated entries as `unknown`,
`upgrade-required`, `not-affected-version`, or `not-applicable`; unknown and
upgrade-required entries remain actionable even when the GitHub feed is empty or
has not yet ingested a vendor advisory.

The GitHub API endpoint is fixed. The check is bounded to 100 entries, 4 MiB,
and 10 seconds; a next page, unavailable or invalid response, or unknown version
or deployment never produces a clean result. Exit `0` means no actionable result
within this scope, `2` means action is needed, and `1` means the check is unknown
or input is invalid. Coverage is limited to direct production `next`, the listed
vendor catalog, and public GitHub-reviewed advisories. The check time and input digests do not attest the
running deployment or CDN attachment. Upgrading Next.js according to the vendor
advisory is the permanent remedy.

## Determinism and metadata

The YAML and JSON sidecar contain no timestamp or absolute path. Repeating the
command with the same input bytes and options produces byte-identical output;
normalized field order does not affect the candidate policy. The sidecar
records the raw source digest, Security IR digest, candidate digest,
generator version, applied and omitted recommendations, and target capability
findings. It never records raw credentials, request bodies, or inferred secret
values.
