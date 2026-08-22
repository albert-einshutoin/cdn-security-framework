# ADR 0003: Security Contract Trust Model

> **Status:** Accepted

## Context

The Security Compiler compares four independent views of an API. They can
legitimately disagree because each view answers a different question. Treating
one view as globally authoritative would hide drift and could turn incomplete
analysis or sparse traffic into an unsafe policy change.

Existing documents remain valid within their narrower scopes:

- `security.yml` is the source of truth for compiler output, so it represents
  the **Allowed API**, not the declared, implemented, or observed API.
- The threat model assigns enforcement responsibilities; it does not prove
  which routes the application implements.
- The Edge/WAF decision matrix chooses an enforcement layer; it does not define
  precedence between contract inputs.

## Decision

### Four truths

| View | Meaning | What it does not prove |
| --- | --- | --- |
| **Declared API / OpenAPI** | The API surface the producer declares as public | That the route is implemented, reachable, or allowed by deployed policy |
| **Implemented API / Source AST** | Routes and guards a supported analyzer can statically establish in source | Runtime reachability, behavior outside analyzer capability, or absence of a guard it cannot recognize |
| **Allowed API / Policy** | The surface Edge/WAF configuration permits | That a permitted route is declared, implemented, required, or safe at the application layer |
| **Observed API / Runtime** | Evidence that traffic matching a route was observed | That unobserved routes are unused or safe to remove; observation is evidence, not authority |

There is no automatic precedence order between the four truths. A disagreement
produces a Finding. The compiler must not silently rewrite one input to match
another.

### Confidence and CI gating

Confidence describes how strongly the analyzer can establish a Finding; it is
separate from severity.

| Confidence | Boundary | Default severity ceiling | Default CI behavior |
| --- | --- | --- | --- |
| `deterministic` | Derived mechanically from complete inputs within declared analyzer capabilities; the same normalized inputs always yield the same result | `error` | May fail CI |
| `high-confidence` | Depends on supported framework conventions, incomplete static reachability, or another documented assumption | `warning` | Does not fail CI |
| `heuristic` | Inferred from names, traffic frequency, similarity, or other probabilistic signals | `info` | Does not fail CI |

By default, only a `deterministic` Finding may cause a non-zero exit. A user may
explicitly configure selected `high-confidence` Finding IDs to gate CI. A
`heuristic` Finding never gates CI. Configuration may tighten gating but must
not relabel confidence or allow an LLM to choose severity or exit status.

A result is `deterministic` only when every required input was parsed
successfully and each analyzer reports the capability needed for the claim. A
missing or unsupported analyzer downgrades the result instead of turning
absence of evidence into evidence of absence.

### Mismatch examples

| Case | Finding | Severity | Confidence | Default gate |
| --- | --- | --- | --- | --- |
| A route is established in Source but absent from OpenAPI | `undocumented-endpoint` | `error` | `deterministic` when Source extraction is complete; otherwise `high-confidence` | Fail only when deterministic |
| An OpenAPI operation is denied by Policy | `declared-but-blocked` | `error` | `deterministic` | Fail |
| Policy permits a route absent from both OpenAPI and complete Source analysis | `unnecessary-exposure` | `error` | `deterministic` only with complete Source capability | Fail only when deterministic |
| OpenAPI requires auth but Source analysis cannot establish a guard | `auth-contract-mismatch` | `warning` | `high-confidence` | Warn |
| OpenAPI and Source establish different HTTP methods for the same route | `method-contract-mismatch` | `error` | `deterministic` when Source extraction is complete | Fail only when deterministic |
| Policy permits more methods than the declared operation | `overbroad-method-allowance` | `error` | `deterministic` | Fail |
| Runtime observes a route absent from OpenAPI | `observed-undocumented-route` | `warning` | `high-confidence` | Warn |
| A declared route has not been observed during the selected Runtime window | `removal-candidate` | `info` | `heuristic` | Inform only |
| Source contains a dynamic route the analyzer cannot resolve | `analysis-gap` | `warning` | `high-confidence` | Warn |
| OpenAPI and Policy agree, but Runtime reports rejected traffic | `runtime-policy-drift-candidate` | `warning` | `high-confidence` until collection position and deployed digest are verified | Warn |

### Automated change boundaries

The compiler and its integrations must not:

- remove a Method or Route because it was not observed at Runtime;
- conclude that authentication is absent merely because a Source analyzer did
  not find a guard; the Finding must include analyzer capability and confidence;
- apply Policy generated from OpenAPI directly to production; generated policy
  is a reviewable candidate;
- use LLM output to decide Allow/Block behavior, Finding confidence or severity,
  CI gating, or process exit status.

AI may explain deterministic results, summarize evidence, group Findings, and
draft remediation text. Such output is advisory, must preserve the underlying
Finding IDs and provenance, and cannot change machine decisions.

### Provenance

Every Finding and generated candidate must carry enough provenance to reproduce
the decision:

- input file identity and a digest of its normalized content;
- Operation and Route identity when applicable;
- analyzer name, version, declared capability, and confidence;
- policy or runtime collection identity when applicable;
- the rule/Finding ID and Security Contract schema version.

Digests, normalized identifiers, and analyzer versions belong inside
deterministic snapshots. Wall-clock generation and observation timestamps must
be stored as metadata outside deterministic snapshots. A timestamp is never a
substitute for a content digest.

## Consequences

- Drift remains visible instead of being silently reconciled.
- CI failures are reproducible and limited to claims the tool can prove.
- Source and Runtime analysis must expose capability and completeness rather
  than returning an ambiguous empty result.
- Generated policy requires review and the existing deployment workflow.
- Finding and Security IR contracts must preserve provenance and stable IDs.

## Rejected alternatives

### Global precedence such as Runtime > Source > OpenAPI > Policy

Rejected because the inputs answer different questions. Runtime can be sparse,
Source analysis can be incomplete, and Policy describes enforcement rather than
intent or implementation.

### Runtime-driven automatic route removal

Rejected because an observation window cannot prove that a route is unnecessary.

### Treating a missing Source guard as unauthenticated

Rejected because analyzers cannot recognize every framework, wrapper, or dynamic
guard. Capability must qualify the result.

### LLM adjudication of security decisions

Rejected because it is not a deterministic or auditable basis for Allow/Block,
severity, CI gating, or exit status.

### Direct deployment of OpenAPI-derived Policy

Rejected because a declared contract does not prove implementation safety or
operational intent. Generated output remains a review candidate.
