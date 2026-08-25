# Source AST and OpenAPI drift

`compareSourceOpenApiContracts` compares an OpenAPI `SecurityContractV1` with a Source AST contract without modifying either input. The comparison reuses normalized route shapes, ignores path-parameter names, deduplicates Finding Contract v1 results, and returns them in stable order.

## Rules and confidence

- `SC-INVENTORY-001` (error, deterministic): a statically implemented route shape is absent when both Source and OpenAPI route inventories are complete. Incomplete capability on either side lowers this to a heuristic warning.
- `SC-INVENTORY-003` (error, deterministic): a declared operation is absent from complete Source route analysis. Partial or unsupported Source route capability lowers this to a heuristic warning because an unresolved route is not proof of absence.
- `SC-INVENTORY-004` (error, deterministic): Source and OpenAPI have different method sets for the same normalized route shape. Incomplete route capability on either side lowers this to a heuristic warning.
- `SC-AUTHN-005` (warning, high-confidence): explicit OpenAPI public/authenticated metadata contradicts high-confidence Source `Public` or mapped Guard metadata. Multiple OpenAPI authentication alternatives are not flattened into an AND comparison. Partial route identity lowers confidence to heuristic.
- `SC-AUTHZ-001` (warning, high-confidence): explicitly configured `declaredPrivilegedRoles` differ from high-confidence Source role metadata. Route names and tags are never used to infer privilege. Partial route identity lowers confidence to heuristic.

Both comparison roots must provide evidence. Findings for matched operations include both operation evidence sets; inventory-absence findings combine the present operation evidence with the missing side's root evidence.

## Not proven

Static Source metadata does not prove Guard runtime behavior, business authorization, BOLA safety, dynamic route registration, unresolved global prefixes, or runtime module composition. Missing Guards are not treated as public access. When Source capability is partial or authentication confidence is unknown, the comparator suppresses deterministic authentication claims and downgrades absence findings.
