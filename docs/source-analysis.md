# Source Analysis Trust Boundary

Source analyzers describe the **Implemented API / Source AST** view from
[ADR 0003](adr/0003-security-contract-trust-model.md). They are deterministic,
static analyzers. An empty or failed analysis never proves that routes,
authentication, authorization, or limits are absent.

## Execution boundary

The internal `SourceAnalyzerPlugin` contract does not load plugins. Callers
register analyzers that were imported statically by trusted application code.
The framework does not discover, `require`, or `import` analyzer packages,
decorator factories, application configuration, build scripts, or analyzed
source files. Analyzer implementations must parse source as data and must not
execute it. LLM output cannot determine extracted values, capability status,
Finding confidence or severity, CI gates, or process exit status.

Before invoking an analyzer, `runSourceAnalyzer()`:

- resolves the real workspace root and every entrypoint;
- rejects missing inputs, directories, traversal, absolute paths outside the
  root, and symlink escapes;
- deduplicates entrypoints by resolved real path, then enforces file count,
  per-file bytes, and total entrypoint bytes;
- supplies a bounded cancellation signal and a logger that accepts only fixed
  event codes.

Analyzers must apply the same root and limit checks to files discovered after
the initial entrypoints. The wrapper validates reported metrics and fails
closed when a declared limit is exceeded; metrics are not permission to read
outside the workspace.

## Plugin contract

Each plugin has a stable lowercase ID, a semantic version, declared languages
and frameworks, the complete capability map, and one asynchronous `analyze`
function. Capabilities use `supported`, `partial`, or `unsupported` plus a
non-empty reason for:

- route paths and HTTP methods;
- controller/router prefixes and global prefixes/versioning;
- authentication and authorization metadata;
- request content types and request/body limits;
- source locations and inherited metadata;
- dynamic expression resolution.

Static uncertainty stays explicit. Dynamic routes, unsupported decorators,
unrecognized guards, and inherited metadata outside analyzer capability must
produce an `unknown` value, a partial/unsupported capability, or a safe analyzer
diagnostic. They must not be guessed.

## TypeScript project loader

`loadTypeScriptProject()` builds an analyzer-internal TypeScript `Program` from
JSON/JSONC without executing source, `ts-node`, compiler plugins, transformers,
Nest CLI, webpack, or build scripts. It supports local workspace `extends`,
`files`/`include`/`exclude`, path aliases, and `.ts`, `.tsx`, `.mts`, and `.cts`.
Package, remote, absolute, and symlink-escaping configuration paths fail closed.

The loader resolves source files by real path, permits only workspace files and
TypeScript's `lib*.d.ts` standard-library files, plus bounded `node_modules/**/package.json`
metadata needed for type resolution, and applies file, byte, AST-node,
diagnostic, depth, cooperative deadline, and cancellation limits before returning. Project references are detected
but not loaded in v1, so the result carries a fixed partial-capability diagnostic.
Already-materialized syntax diagnostics are bounded and normalized; the loader
does not eagerly compute the full semantic diagnostic set. TypeScript messages and source snippets are discarded; diagnostics retain only
a fixed safe message, numeric TypeScript code, and optional workspace-relative
position.

`TypeScriptAnalysisCache` is process-local and content-based. Its digest covers
the canonical config chain, compiler options, source and standard-library contents,
TypeScript version, and loader
version; invalid, cancelled, and limit-exceeded loads are never cached. A prior
Program may be reused internally, but cache-free execution remains correct.

## NestJS authentication metadata

`createNestJsSourceAnalyzer()` accepts a validated programmatic auth option;
`schemas/nestjs-source-analysis-options.schema.json` describes the same plain-data
shape. The analyzer never loads JavaScript configuration or executes decorators.
Only configured Public/Role decorator symbol names and explicit Guard mappings
have meaning. Guard class names alone never imply JWT, API-key, issuer, audience,
algorithm, or other runtime behavior.

Class and method `@UseGuards()` metadata is composed in execution order and kept
as one authentication alternative; multiple Guards are not converted into OR.
An unmapped or dynamic Guard remains `unknown`. An explicitly configured Public
decorator can produce `auth.mode: none`, but absence of a local Guard never does,
because global and `APP_GUARD` behavior is only a partial capability. Static Role
labels are reported in `auth.analysis.roles`; they do not prove authorization
enforcement. These labels are emitted verbatim and can contain internal
organization names, so consumers must treat the IR as review data rather than a
public artifact.

`auth.analysis` preserves discovered Guard order, mapped kinds, explicit Public
state, Role labels, enforcement confidence, and fixed capability reasons. Source
provenance points to the class/method decorators. Dynamic arguments, spreads,
computed labels, executable config, Guard bodies, global bootstrap behavior, and
cryptographic correctness are not inferred.

## Limits and cancellation

`SourceAnalysisLimits` bounds files, total source bytes, bytes per file, AST
nodes, diagnostics, operations, analysis depth, and a cooperative wall-clock
timeout. The analyzer reports corresponding integer metrics. Cancellation
before or during analysis and an ignored timeout return a failed execution
without a contract. The wrapper also rejects a result returned after the
deadline, even when synchronous analyzer work delayed the timer. Partial
contracts are not supported by this version.

The internal object contract does not provide hard process isolation: a trusted
analyzer must yield to the event loop and observe the cancellation signal.
Untrusted or potentially non-yielding analyzers require a future worker/process
host; dynamic plugin loading and that host are outside this issue.
The project loader itself extracts no API operations, so its operation metric is
zero; the framework analyzer that consumes the Program enforces `maxOperations`.

## Result validation and data minimization

A successful result contains only a `SecurityContractV1`, analyzer diagnostics,
and bounded metrics. The wrapper rebuilds the contract with
`createSecurityContract()`, requires `source: source-ast`, and verifies metric
counts. A `complete` routes or authentication claim requires every corresponding
analyzer capability to be `supported`; source parameter and request-body shape
extraction cannot be `complete` in this contract version. Every returned operation
also requires non-unsupported route-path and HTTP-method extraction. This removes unknown framework AST fields and rejects invalid routes,
absolute or escaping provenance URIs, query fragments, and secret-like values.

Lifecycle events (`STARTED`, `COMPLETED`, and `FAILED`) are wrapper-owned. Calls
made through the logger supplied to an analyzer cannot emit them early or twice;
wrapper writes to asynchronous loggers are serialized.

Analyzer diagnostics are separate from security Findings. They contain a
stable code, a framework-owned safe message, an optional workspace-relative
source URI, and positive line/column numbers. Plugin-provided messages, source
snippets, literal bodies, tokens, secrets, stack traces, and absolute paths are
not retained. Throws and invalid results become fixed safe diagnostics; they
do not terminate the process and do not become an empty successful contract.

## Registry boundary

The internal registry is deterministic and rejects duplicate `id@version`
identities and unknown analyzers. This contract is not exported from the public
package API. Dynamic npm plugin loading and framework-specific analysis are
outside this phase.
