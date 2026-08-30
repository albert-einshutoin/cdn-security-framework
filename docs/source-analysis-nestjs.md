# NestJS source analysis

## What is extracted

The analyzer statically reads project-local TypeScript selected by `tsconfig.json`.
It extracts controller prefixes, supported HTTP decorators, static route strings,
project-local inheritance, configured local Guard mappings, explicit Public
decorators, and static Role labels. Aliased NestJS imports, local `extends`, and
TypeScript `paths` aliases are supported by the example.

It parses code; it never imports application modules, executes decorators, starts
NestJS, or evaluates configuration JavaScript. Keep `security-analyzer.yml` as
plain data with only `public_decorators`, `roles_decorators`, and explicit
`guard_mappings`; the schema rejects unknown keys and unsupported auth kinds.

## Security boundary and confidence

A detected Guard or Role is metadata, not proof of enforcement. Guard bodies,
cryptographic validation, middleware order, dependency injection, and runtime
behavior remain outside the analyzer. Missing local Guard metadata never proves a
route is public. Only a configured explicit Public decorator can produce that
conclusion, and all results still require runtime/security review.

Deterministic findings are proven from supported static inputs. Heuristic findings
mean at least one capability is partial. Global Guards (`APP_GUARD` included),
dynamic paths, custom decorator wrappers, module graphs, runtime global prefixes,
versioning, and referenced projects can make absence claims incomplete. The
analyzer reports dynamic/unsupported cases instead of executing them.

Typical false positives come from runtime prefixes or global policy unknown to the
fixture. Typical false negatives come from custom wrappers, generated controllers,
module composition, or routes in unloaded project references. Prefer literal or
`const` route segments, direct NestJS decorator imports, direct configured
Public/Role calls, and explicit local Guard mappings. Do not suppress a partial
diagnostic merely to make CI green.

## Contract diff and CI

`examples/nestjs-contract/run-analysis.cjs` shows the safe composition:
`runSourceAnalyzer` produces Source IR, OpenAPI normalization produces declared IR,
Policy projection produces allowed surface, then
`compareSourceOpenApiContracts` and `compareSourcePolicyContracts` create findings.
The current `contract diff` CLI does not load application source; use this
programmatic composition until a CLI source input is added. Review warning and
heuristic findings, record narrow expiring exceptions, and fail CI only at the
severity chosen by the repository.

Troubleshooting:

- `SOURCE_ANALYZER_INPUT_INVALID`: fix TypeScript syntax/module resolution; do not execute the app as a fallback.
- `SOURCE_ANALYZER_DYNAMIC_ROUTE`: replace the expression with a static `const`, or review the route manually.
- `SOURCE_ANALYZER_DYNAMIC_AUTH_METADATA`: call the configured decorator directly with static values.
- `SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED`: preserve a manual/global-Guard review gate.
- Project-reference partial status: analyze each referenced project explicitly.

## Benchmark

Run `npm run benchmark:source-analysis`. The generated workload has 100 controllers
and 1,000 operations, path aliases, repeated decorator symbols, and one dynamic
diagnostic per controller. The JSON report separates project load, AST traversal,
IR generation, comparison, total time, heap delta, files, nodes, operations, and
project-loader cold/cached state. IR generation deliberately uses the normal
cache-free Analyzer path; the report does not claim a warm Analyzer measurement.
`benchmark:source-analysis:ci` runs one integrated sample and only enforces a
tolerant 60-second runaway ceiling. Timings and heap deltas are noisy;
compare the same Node version, architecture, power state, and iteration count, and
use medians before treating a change as a regression. Cache invalidation after a
source edit is covered by integration tests.

Reference run (Node 24.2.0, macOS arm64, 2026-08-25): cold-loader pipeline total
778 ms; cached-loader pipeline totals 537/511 ms; 102 files, 11,641 AST nodes,
1,000 operations, and 100 expected dynamic diagnostics. This is a comparison
point, not a portable pass/fail limit or an Analyzer warm-cache claim.
