# OpenAPI analysis threat model

## Assets

- CI and developer-machine CPU and memory
- workspace files and path confidentiality
- network isolation during analysis
- deterministic Findings and safe diagnostics

## Trust boundaries

OpenAPI YAML/JSON, local `$ref` documents, anchors, strings, and schema graphs are
untrusted. The future Loader and Resolver must receive a validated
`OpenApiAnalysisLimits` object and must enforce each relevant limit while
reading or traversing input. Parser-library defaults are not a security boundary.

`timeoutMs` is a deadline contract for a supervising Worker or child process.
Synchronous JavaScript cannot be forcibly interrupted by this value alone, so a
Loader must not claim that checking elapsed time guarantees termination.

## Default budget fixture

Defaults are explicit workload envelopes established before selecting a parser:

| Limit | Default | Hard maximum | Basis |
| --- | ---: | ---: | --- |
| `maxDocumentBytes` | 2 MiB | 4 MiB | Bound each pre-parse read |
| `maxGraphBytes` | 64 MiB | 256 MiB | Bound aggregate raw bytes across resolved documents |
| `maxResolvedDocuments` | 32 | 64 | Bound document graph breadth and parser invocations |
| `maxRefDepth` | 32 | 128 | Bound chained local references independently of cycle detection |
| `maxSchemaDepth` | 64 | 256 | Bound recursive schema traversal |
| `maxNodes` | 250,000 | 1,000,000 | Global traversal stop independent of object type |
| `maxOperations` | 2,000 | 10,000 | Supports large APIs while bounding route work |
| `maxParametersPerOperation` | 100 | 500 | 2,000 × 100 gives a 200,000-parameter visit envelope |
| `maxSecuritySchemes` | 64 | 256 | Bound auth normalization work |
| `maxYamlAliases` | 100 | 1,000 | Bound alias expansion before materialization |
| `maxStringLength` | 64 KiB | 1 MiB | Bound scalar allocation and diagnostic handling |
| `timeoutMs` | 10,000 ms | 60,000 ms | Supervisor deadline; not a synchronous interrupt |

These values are contract fixtures, not parser benchmark claims. #274 will add
the corpus used to measure parser-specific cost; defaults may only change with a
versioned contract update and benchmark evidence.

## Abuse cases and mitigations

| Abuse case | Mitigation |
| --- | --- |
| Oversized document or string | Check byte/string limits before parse or copy |
| YAML alias expansion | Configure parser alias limits and count materialized aliases |
| Deep/cyclic `$ref` or schema graph | Track visited identities and enforce ref, schema, and global node limits |
| Remote `$ref` causes SSRF | Reject `http:` and `https:` in v1; no network fetch support |
| `file:` or absolute path reads host files | Reject before filesystem resolution |
| Relative traversal leaves workspace | Check lexical path and real path against the real workspace root |
| Symlink escapes workspace | Re-check `realpath` after resolution |
| Error leaks source text or credentials | Emit only stable code, safe message, filename, and JSON Pointer |
| Synchronous analysis stalls CI | Run analysis under a Worker/child-process supervisor using `timeoutMs` |

Limit violations use stable `OPENAPI_*` error codes and are distinct from syntax
errors. Error serialization must never include input bodies, Authorization,
Cookie, query values, absolute workspace paths, or stack traces.

## Residual risk

- Parser-specific allocation may exceed raw byte estimates; benchmark it with
  the #274 corpus before choosing a parser.
- OS and filesystem race conditions can occur between `realpath` validation and
  a later read. The Loader should open/read the validated target immediately and
  avoid re-resolving attacker-controlled paths.
- A same-workspace malicious file remains readable by design. Workspace trust
  and repository review remain required.
- Custom limits can increase workload up to hard maxima; run untrusted analysis
  in an isolated Worker or child process.
