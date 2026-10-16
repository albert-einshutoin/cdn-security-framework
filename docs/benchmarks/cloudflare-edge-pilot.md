# Generated Cloudflare Worker pilot — 2026-10-16

Status: **failed partial measurement; qualification INCONCLUSIVE**. Related work: [Issue #1026](https://github.com/albert-einshutoin/cdn-security-framework/issues/1026). This report does not close the issue or establish a performance gate.

## Environment and workload

- Compiler commit: [`7f1e1c4a1d2d5e02565b71c728566d7eff2bf048`](https://github.com/albert-einshutoin/cdn-security-framework/commit/7f1e1c4a1d2d5e02565b71c728566d7eff2bf048); source tree `45198d20e9138dfe7ec93e5a4c73a2d9f83053c9`, identical to main merge `597335d5e3a97eedc74a1adf31e30cb0f01bf47d`.
- Real Cloudflare Workers Free; compatibility date `2026-10-12`, flag `global_fetch_strictly_public`. Disposable gateway → Service Binding → generated Worker or `fetch(request)` no-op → synthetic HTTP origin; synthetic JWKS and credentials only. Compiler output was not instrumented. Deployment used `--no-bundle`; deployed version IDs were retained, but remote module bytes were not downloaded and rehashed.
- Five workloads: normal GET; 256 regex rules with an approximately 8 KiB path; a 64 KiB GraphQL request; 1 MiB body signing; RS256/JWKS authentication. Selected allow/deny outputs, forwarding, hashes, signatures, and security headers had correctness checks.
- Inputs were synthetic: the 64 KiB GraphQL body is a small query padded with spaces, the 8 KiB path uses repeated ASCII, and the 1 MiB signing body repeats one ASCII character. These sizes do not describe equally sized complex production inputs.
- At most four in-flight client requests, paced at no more than 50 starts/second. This was a capped closed-loop test, not a sustained-throughput or saturation result. KIX and PDX were both observed.
- Planned: 100 warmup + 500 measured requests per workload/variant/run, three runs, with separate no-op A/A intervals. Actual: 8,809 requests started; 13 completed 500-request measurement intervals = 6,500 samples. Completed series plus smoke retained 8,314 individual rows. The interrupted series' other 495 requests were not individually retained; their outcomes are unknown.

## CPU observations

The following are **provider log-query display values for the entire pilot**, including startup, smoke, warmup, and complete/partial measurement phases. They are not isolated 500-request CPU distributions. The query grouped `$workers.cpuTimeMs` by Worker, restricted to the disposable pilot's name prefix. Effective CPU sample counts, underlying precision, query sampling, and percentile-estimator accuracy were not verified. `uniq($metadata.requestId)` was not accepted as the CPU sample count.

| Generated workload | CPU p50 ms | CPU p95 ms | CPU p99 ms |
| --- | ---: | ---: | ---: |
| Normal forwarding | 1 | 1 | 2 |
| Regex 256 / approximately 8 KiB path | 1 | 2 | 5 |
| GraphQL 64 KiB | 1 | 3 | 6 |
| HMAC body signing 1 MiB | 3 | 5 | 15 |
| RS256/JWKS | 1 | 4 | 7 |

The shared no-op's display was 1 / 1 / 2 ms across multiple inputs. Its percentiles cannot be subtracted to obtain individual features' added CPU. Gateway and origin observations were separate; Service Binding CPU rollup attribution was not established, so their quantiles were not added together. RS256 includes initial key acquisition and later requests; isolate cache-hit completeness was not proven.

GraphQL Analytics yielded a CPU p50/p95/p99 estimate of **0.941 / 1.369 / 2.028 ms** for the normal generated workload in run 0. Its estimated request count was 520 for 500 client requests, `avg.sampleInterval` approximately 4.19, with unknown quantile reservoir size. Raw CPU/wall fields were in microseconds and converted to milliseconds. Target-Worker data was empty in the other 16 of 17 observed intervals, including after one delayed recheck. Those values remain **UNKNOWN**. API rate limits also prevented completion of the lifetime query. These estimates and the whole-pilot log display have different populations and must not be pooled.

## Client response times

Run 0 is the only complete five-workload comparison. Each cell below uses 500 individual samples and nearest-rank percentiles, in milliseconds. Timing ends when the response body is drained. It includes network, gateway, origin, and body transfer, with mixed PoPs.

| Workload | No-op p50 / p95 / p99 ms | Generated p50 / p95 / p99 ms |
| --- | ---: | ---: |
| Normal forwarding | 22.751 / 131.785 / 140.127 | 23.606 / 131.429 / 133.865 |
| Regex / approximately 8 KiB | 22.436 / 38.248 / 134.674 | 25.877 / 131.805 / 134.027 |
| GraphQL 64 KiB | 32.826 / 137.534 / 157.774 | 39.758 / 143.144 / 155.617 |
| HMAC 1 MiB | 124.535 / 187.969 / 203.523 | 123.405 / 190.694 / 201.849 |
| RS256 | 26.485 / 131.179 / 135.254 | 24.325 / 132.163 / 138.255 |

Unequal PoP proportions can move p95 substantially. Neither the regex difference nor a generated percentile below the no-op proves a code regression or improvement. There was no old/new product revision comparison. Supplemental run-1 intervals are retained separately in the [aggregate JSON](cloudflare-edge-pilot.json).

## Failure, cleanup, and evidence limits

On the second run's no-op 1 MiB path, the **test gateway** returned HTTP 503 with `Worker exceeded CPU time limit.` The provider invocation display showed CPU 10 ms and wall 34 ms. Generated HMAC code was not on that path. The gateway buffers, concatenates, and forwards the body; no profile established which internal operation consumed each millisecond. No product defect is inferred from this fixture failure, and the plan/CPU limit was not raised.

This attempt reached deletion confirmation for all eight disposable Workers within 364.727 seconds. An earlier deployment attempt was interrupted by a host reboot before load began; its deletion was delayed beyond 15 minutes. All eight names from that attempt were confirmed absent before the single retry. Both attempts' resources are now deleted. Existing sites, DNS, routes, permissions, and subscriptions were not changed.

The published JSON contains selected aggregates, workload metadata, and SHA-256 provenance for retained local evidence. Full raw logs, cloud runner/fixtures, and individual CPU samples are not published with this report; it is **not an independently reproducible benchmark package**. No credentials, account identifiers, deployment URLs, local filesystem paths, or raw request headers are included. Historical measurements are not rerun by documentation CI.

## Requirements for a qualified benchmark

1. **Make the measurement fixture eligible.** Keep input limits and correctness oracles while removing avoidable gateway copies; measure fixture overhead independently. Establish cleanup that survives loss of the load-generator host. A fixture limit/error invalidates the run; do not relax the threshold to label it successful.
2. **Bind each observation to its population.** Pin compiler, policy/input hashes, generated bytes, deployed version, runtime/plan, PoP, request ID, and interval. Export target-Worker CPU and wall values with known units, precision, sample rates, and completeness. Preserve missing values, errors, timeouts, and truncated results. A CDN WAF/cache response before Worker invocation must not be credited to generated code.
3. **Separate conditions.** Normal traffic, early/late rejects, body/path/header boundaries, JWT/JWKS cold and cache-hit behavior, GraphQL, regex, DLP, and supported attack families need explicit expectations. Keep PoPs, platform/event stages, cache state, and concurrency separate. Test baseline and generated code with identical fixtures and alternating order, including no-op A/A checks.
4. **Choose a load model and report delivered load.** Measure both fixed-concurrency latency and fixed-arrival-rate behavior; disclose scheduling delay, missed starts, errors, throughput, and client resource limits. Load tools measure client latency; platform telemetry is still required for Edge CPU.
5. **Qualify statistical and regression rules.** A proposed starting design is at least 1,000 measured requests × three runs per comparable workload/variant. Evaluate p95 only after A/A stability and telemetry completeness pass. Treat p99 as descriptive until a larger study, initially 10,000 × five runs, assesses tail variability and temporal correlation. These are project proposals, not universal guarantees of statistical sufficiency. Do not average run/PoP percentiles. Relative thresholds need an absolute floor above observed measurement error and explicit baseline review. No threshold is enforced by this report.

## Existing tools and public suites

These are candidates for future work; none was installed or run for this documentation change.

| Tool or suite | Relevant use | Boundary |
| --- | --- | --- |
| [Grafana k6](https://grafana.com/docs/k6/latest/using-k6/scenarios/executors/constant-arrival-rate/) and [thresholds](https://grafana.com/docs/k6/latest/using-k6/thresholds/) | Scripted scenarios, fixed arrival rate, percentile/error thresholds | Allocate enough VUs and report dropped iterations; CPU needs provider telemetry. |
| [Vegeta](https://github.com/tsenart/vegeta) | Constant-rate HTTP load and reporting | Reuse product-specific payloads and correctness checks; not an Edge security score. |
| [wrk2](https://github.com/giltene/wrk2) | Constant-throughput latency tests that account for coordinated omission | Its README documents approximately ±1 ms latency granularity; unsuitable for establishing sub-ms CPU costs. |
| [OWASP CRS regression corpus](https://github.com/coreruleset/coreruleset/tree/main/tests/regression/tests) with [go-ftw](https://github.com/coreruleset/go-ftw) | Reusable HTTP security regression inputs; cloud mode can judge HTTP statuses | Select applicable supported controls and adapt expectations to this framework's contracts. A correctness corpus does not itself define a performance workload. |
| [OWASP Benchmark](https://owasp.org/projects/benchmark) | Java/Python vulnerability-detection tool evaluation | AST-tool evaluation, not a drop-in generated-Edge CPU benchmark. |

For this project, a reasonable next design is **k6 + versioned framework workloads/oracles + provider CPU evidence**, borrowing applicable CRS cases for correctness coverage. No reviewed source here supplies a single standard score covering generated Edge CPU, latency, and all security behavior. That is a scope assessment, not a claim that no other suites exist.

Provider references: [invocation CPU/wall fields](https://developers.cloudflare.com/changelog/post/2025-04-09-workers-timing/) and [metrics, reservoir quantiles, and CPU rollover](https://developers.cloudflare.com/workers/observability/metrics-and-analytics/).
