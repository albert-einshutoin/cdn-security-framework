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
| Resource limits | `SC-LIMIT` | `SC-LIMIT-001`: unnecessarily broad request limit |
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

This contract is internal in v1 and is not exported from the package's public
API. Rule implementations are added by later Security Compiler phases.
