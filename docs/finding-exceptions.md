# Finding Exceptions

Finding exceptions are temporary, auditable suppressions. Keep them in a separate YAML or JSON file; do not add them to the security policy.

```yaml
version: 1
exceptions:
  - id: EXC-2026-001
    rule_id: SC-AUTHN-001
    selector:
      method: POST
      path: /webhooks/stripe
      target: cloudflare
      environment: production
    reason: Application verifies the signed webhook payload.
    owner: payments-team
    expires_at: 2026-12-01
    ticket: SEC-123
```

`id`, `rule_id`, `selector`, `reason`, `owner`, and `expires_at` are required. Prefer an exact `instance_id`; otherwise use an exact `method` and `path`. A rule-only or wildcard selector is rejected unless `allow_broad: true` and a separate `broad_reason` are present. Never put credentials, tokens, cookies, passwords, or other secrets in rationale fields.

Load the file with `loadFindingExceptions()`, then pass its result and an explicit ISO `currentDate` to `applyFindingExceptions()`. The explicit date keeps CI output deterministic. The report contains active `findings`, original `suppressedFindings`, sorted `appliedExceptionIds`, and before/after counts.

## Lifecycle and audit

1. Create the narrowest exception and record its owner, reason, expiry, and tracking ticket.
2. Review the report on every CI run. Expired exceptions do not suppress and produce `SC-GOV-001` Error. Unused exceptions produce `SC-GOV-002` Warning. Multiple matches produce `SC-GOV-003` Warning and only the most specific exception is applied.
3. To extend an exception, update `expires_at` through the normal code-review trail; never extend it automatically.
4. Delete the exception when its Finding disappears or the underlying issue is fixed. Retain version-control history as the audit record.

Parser, schema, unsafe-input, governance, and explicitly `non-waivable` Findings cannot be suppressed.
