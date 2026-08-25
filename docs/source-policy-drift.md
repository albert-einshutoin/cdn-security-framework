# Source AST and Policy drift

Use `compareSourcePolicyContracts` after projecting a validated Policy with `projectPolicyToAllowedSurface`. Supply the normalized `source-ast` contract, its project-level evidence, the Allowed Surface Model, and the selected `aws` or `cloudflare` target.

The comparator reports `SC-EXPOSURE-004/005`, `SC-INVENTORY-005`, `SC-AUTHN-006`, and `SC-AUTHZ-002` as Finding Contract v1 records in stable order. Exact and definitely covered routes may support deterministic findings; prefix, partial, unsupported, and unknown relations remain warnings or are omitted when no safe comparison exists. Monitor mode never claims that a method is currently blocked.

Source decorator metadata proves only that configured symbols and static arguments were found. It does not prove Guard behavior, Global Guard presence, role enforcement, or application security. Dynamic routes, partial project graphs, runtime prefixes, custom wrappers outside configured mappings, and runtime route discovery remain outside this comparison.
