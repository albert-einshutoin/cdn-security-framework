# Finding reference

Security Compiler findings use the internal `SecurityFindingV1` contract and
the stable rule ID form `SC-<CATEGORY>-<3 digits>`.

## Rule ID allocation

| Category | Prefix | Example |
| --- | --- | --- |
| Inventory drift | `SC-INVENTORY` | `SC-INVENTORY-001`: route found only in Source |
| Exposure | `SC-EXPOSURE` | `SC-EXPOSURE-001`: undeclared Method allowed by Policy |
| Authentication | `SC-AUTHN` | `SC-AUTHN-001`: authentication contract mismatch |
| Authorization | `SC-AUTHZ` | `SC-AUTHZ-001`: authorization contract mismatch |
| Resource limits | `SC-LIMIT` | `SC-LIMIT-001`: request limit below a finite requirement |
| Request validation | `SC-REQUEST` | `SC-REQUEST-001`: declared required header is not checked at Edge |
| Misconfiguration | `SC-MISCONFIG` | `SC-MISCONFIG-001`: inconsistent security setting |
| Governance | `SC-GOVERNANCE` | `SC-GOVERNANCE-001`: required review evidence missing |
| Runtime evidence | `SC-RUNTIME` | `SC-RUNTIME-001`: observed contract drift candidate |

For each prefix, `001`–`099` are allocated to v1 built-in rules, `100`–`899`
are reserved for future built-in rules, and `900`–`999` are reserved for local
rules and are never emitted by the core compiler. Published IDs are not reused.

## Stability and safety

- `instanceId` is the SHA-256 digest of the rule ID, normalized route, and
  canonical evidence identity. Evidence must include a URI, content digest,
  analyzer, declared capability, and completeness. Absolute filesystem paths
  require an explicit workspace root and are stored
  relative to it. Message wording, evidence order, timestamps, and workspace
  location do not affect the ID.
- Findings are ordered by severity, rule ID, path, method, then instance ID.
- Sensitive object keys, authorization values, bearer values, cookies, API
  keys, and URL query values are redacted before a Finding is returned.
- Confidence values follow [ADR 0003](adr/0003-security-contract-trust-model.md):
  `deterministic`, `high-confidence`, and `heuristic`.

The contract and drift comparators are exported from `cdn-security-framework/contract`.

## OpenAPI and Policy drift rules

`compareSecurityContracts({ declared, allowed, target }, options)` compares one
normalized OpenAPI Security Contract with one effective Allowed Surface Model.
The target is required because AWS and Cloudflare do not enforce every Policy
capability in the same way. Monitor mode is retained in `actual`; a control that
would block only in enforce mode is not reported as an enforce-mode Error.

| Rule | Severity | Deterministic condition |
| --- | --- | --- |
| `SC-EXPOSURE-001` | Error; Warning in monitor mode | The effective method surface allows a method absent from a completely declared route. Monitor mode observes method rejection but permits the request. |
| `SC-EXPOSURE-002` | Error; Warning in monitor mode | An OpenAPI operation is outside the effective method set. |
| `SC-INVENTORY-002` | Error; Warning for partial route inventory | An exact Policy route has no same-shape OpenAPI route. Parameter names do not affect shape equality. |
| `SC-EXPOSURE-003` | Warning | A broad prefix rule may extend beyond the declared surface. Unknown overlap is never promoted to Error. |
| `SC-AUTHN-001` | Warning | An authenticated operation has no enforced Edge auth gate. |
| `SC-AUTHN-002` | Error | An explicitly public operation is definitely covered by an enforced Edge auth gate. |
| `SC-AUTHN-003` | Warning | Credential kind, location, or name is provably incompatible. |
| `SC-AUTHN-004` | Info | Auth compatibility cannot be proved. |
| `SC-LIMIT-001` | Error; Warning in monitor mode or for conditional CORS preflight | An effective limit is below a finite exact or upper-bound recommendation. |
| `SC-LIMIT-002` | Warning | An effective limit is more than `materiallyBroaderRatio` times a positive finite recommendation. The default ratio is `2`; the recommendation already includes its documented safety margin. |
| `SC-REQUEST-001` | Info | An OpenAPI-required header is not required at Edge. |
| `SC-REQUEST-002` | Error; Warning in monitor mode or for conditional CORS preflight | Edge requires a header missing from a complete OpenAPI parameter contract. Effective runtime defaults are included. |
| `SC-REQUEST-003` | Info | OpenAPI declares request content types, but the current Policy schema has no Edge content-type allowlist. |
| `SC-GOV-001` | Error | An expired exception remains in the exception set and suppresses nothing. |
| `SC-GOV-002` | Warning | A live exception matches no current Finding. |
| `SC-GOV-003` | Warning | Multiple live exceptions match one Finding; only the most specific is applied. |

## Source AST and OpenAPI drift rules

`compareSourceOpenApiContracts(input, options)` compares normalized Source AST metadata with OpenAPI. Parameter names do not affect route-shape equality. Missing operations become Errors only when the relevant route inventory is complete; explicit authentication and role contradictions remain Warnings because metadata does not prove runtime Guard behavior.

| Rule | Severity | Condition |
| --- | --- | --- |
| `SC-INVENTORY-001` | Error; Warning unless both inventories are complete | A statically detected Source operation has no same-shape OpenAPI route. |
| `SC-INVENTORY-003` | Error; Warning for partial Source inventory | An OpenAPI operation has no statically detected same-shape Source route. |
| `SC-INVENTORY-004` | Error; Warning unless both inventories are complete | The same normalized route shape has different HTTP method sets. |
| `SC-AUTHN-005` | Warning | Explicit OpenAPI auth contradicts high-confidence Source decorator metadata. Unknown metadata is not reported; partial route identity lowers confidence to heuristic. |
| `SC-AUTHZ-001` | Warning | Explicitly supplied privileged roles contradict high-confidence Source role metadata with complete authorization evidence. Partial route identity lowers confidence to heuristic. |

See [Finding Exceptions](finding-exceptions.md) for the exception lifecycle and audit procedure.

### Authentication compatibility

OpenAPI alternatives remain OR branches; schemes inside an alternative remain
AND requirements. The comparator reports compatibility only when one complete
alternative is satisfied.

| OpenAPI scheme | Edge gate | Result |
| --- | --- | --- |
| API key | Static token with the same header location and name | Compatible |
| API key | Different kind, location, or name | Incompatible |
| HTTP Basic | Basic auth | Compatible |
| HTTP Basic | Other supported gate | Incompatible |
| Bearer | JWT | Unknown; Bearer is not inferred to mean JWT |
| Unsupported or incomplete scheme | Any | Unknown |

All authentication findings describe only the selected Edge target. They do
not claim that Application authentication is absent. Expected/actual evidence
contains credential metadata, never credential values.

### False-positive boundaries and remediation

- Partial, unsupported, pattern, or unknown route relations do not produce a
  deterministic Error. Review the evidence and make the contract complete
  before tightening Policy.
- Zero-valued recommendations do not trigger broad-limit warnings. Partial or
  unknown request estimates do not produce limit Errors.
- Header names are compared case-insensitively. API-key headers required by every
  non-anonymous authentication alternative count as declared client headers. `SC-REQUEST-001` may be an
  intentional Application-only validation boundary; `SC-REQUEST-002` means an
  Edge requirement must be documented for clients or removed.
- Content-type validation remains an Application responsibility until the
  Policy schema and selected target expose that capability.
