# OpenAPI analysis benchmark

`npm run benchmark:openapi` generates fixed-seed inputs in a temporary directory and exercises the production pipeline directly:

1. document parsing and safety validation;
2. local `$ref` resolution;
3. security-contract IR normalization and serialization.

The JSON report records cold and warm samples for parse, reference resolution, normalization, total wall time, approximate heap delta, input bytes, operation count, resolved documents, references, and output bytes. It contains no hostname, absolute path, or timestamp. Network references remain disabled.

## Workloads

| ID | Purpose |
| --- | --- |
| `operations-100` | 100 operations without references |
| `shared-refs-1000` | 1,000 operations sharing a component reference |
| `nested-refs-10000` | 10,000 operations using nested local schema references |
| `deep-schema` | Schema nesting close to the default depth limit |
| `repeated-refs` | Repeated-reference cache behavior |
| `early-document-limit` | Oversized input rejected during parsing before resolution or normalization |

Large fixture files are generated, not committed. `test/fixtures/openapi/generated/` documents that boundary.

## Representative baseline

Apple Silicon, macOS arm64, two samples per workload; values below are the warm total in milliseconds. Exact machine identity is intentionally excluded.

| Node | 100 ops | 1,000 shared refs | 10,000 nested refs | Deep | Repeated refs | Early reject |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 20.17.0 | 5.597 | 44.564 | 596.136 | 0.446 | 31.844 | 0.106 |
| 22.23.2 | 5.057 | 40.093 | 521.080 | 0.461 | 27.449 | 0.123 |
| 24.19.0 | 3.796 | 35.140 | 523.620 | 0.454 | 29.599 | 0.103 |

The complete time and heap baselines are in `openapi-analysis-baseline.json`.

## CI policy

- Regular validation runs only `shared-refs-1000` with a tolerant absolute ceiling of 15 seconds and 512 MiB approximate heap delta. It never runs the 10,000-operation workload.
- The scheduled/manual `OpenAPI Analysis Benchmark` workflow runs all workloads on Node 20.17.0, 22, and 24. Only this dedicated workflow applies percentage gates: 50% for warm wall time and 100% for approximate heap delta.
- Shared-runner variance therefore cannot fail a pull-request check through a percentage comparison.

Run `npm run benchmark:openapi -- --iterations 3 --output report.json` for a full JSON report. Threshold changes require before/after reports, the tested Node versions and host class, and a written reason in the pull request. Microbenchmark gains are not treated as product-speed claims; Rust/WASM replacement is outside this benchmark's scope.
