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

## Reproducible harness follow-up

The source checkout now contains `benchmarks/edge/k6.js`, a loopback-only native-workerd runner, shared synthetic inputs/oracles, and an explicit provider CPU collector. These additions do not change the generated product code or qualify the historical pilot. Install an official k6 binary separately and verify its release checksum; k6 is not an npm or runtime dependency.

```sh
npm run build:ts
node scripts/edge-benchmark-unit-tests.js
mkdir -p reports
node scripts/benchmark-edge-k6.js --output reports/edge-k6-run \
  --k6 /absolute/path/to/k6 --samples 100 --warmup 20 --rate 20 --runs 3
```

Use a new output directory each time. Nine cases cover ordinary forwarding, method denial, 256 regexes with an 8 KiB path and last-pattern denial, padded 64 KiB GraphQL and depth denial, 1 MiB HMAC, and valid/invalid RS256. Each runs against no-op and generated code; alternating order reverses on successive runs. `--only hmac --samples 1000 --warmup 100 --rate 50 --runs 3` focuses on the 1 MiB path. This is selected coverage, not a measurement of every supported attack or runtime.

The gateway authenticates and expires requests, then validates body length using Cloudflare's `FixedLengthStream` and native body consumption. This removes the JavaScript read/copy callback for every chunk. Short bodies return 400 and oversized bodies return 413 before target invocation. Both writer and reader must settle, and errors other than the known length violations propagate. Size bounds and origin byte/hash/signature oracles remain active. Native workerd correctness checks are separate from confirming that managed Edge CPU-limit failures are resolved. Invalid expiry configuration also fails closed.

The runner uses k6's constant-arrival-rate executor with four VUs, at most 50 starts/second, a 20,000-request cap including preflight, and a 15-minute local watchdog. A duration-boundary iteration cannot send an extra request. Missing metrics, oracle failures, dropped iterations, interrupted processes, and malformed/truncated artifacts reject the run; failed series and complete parseable prefixes are retained with diagnostics and raw-file hashes. Invalid JSON is not skipped to produce a passing result. Raw files stay under ignored `reports/`; the manifest/config include synthetic probe credentials and must not be published.

`report.json` separates warmup and measurement and records nearest-rank p50/p95/p99 from individual k6 points. This metric is HTTP sending + waiting + receiving, excluding connection setup and scheduling. It is distinct from the pilot's client-start-to-drain measurement. Local workerd is not managed Edge CPU evidence. JWKS cold/cache-hit attribution, no-op A/A stability, host noise, and provider completeness still require qualification before accepting budgets.

For an authorized disposable cloud run using the same prepared fixtures, `collect-edge-benchmark-cpu.js` issues at most three 2,000-event [Workers Observability queries](https://developers.cloudflare.com/api/resources/workers/subresources/observability/subresources/telemetry/methods/query/). Supply account/token through the process environment; do not put credentials in command arguments or commit them. The API documents `Workers Observability Write` permission even for this query; a 403 stops collection and never triggers permission expansion. Local generation does not deploy anything.

```sh
node scripts/collect-edge-benchmark-cpu.js --directory reports/cloud-run \
  --series r0-hmac-generated-measured --worker csf-1026-HEX-hmac --version DEPLOYED_VERSION
```

The collector requires successful client counts and point hashes, pins Worker/version/timeframe, and joins individual CPU/wall observations to client IDs and PoPs. Missing CPU, missing/truncated events, or unknown PoPs produce `UNKNOWN` with no aggregate fallback; malformed input, duplicate invocations, failed outcomes, or version/interval mismatches fail. A complete capture reports `CAPTURE_COMPLETE` while qualification remains `INCONCLUSIVE`: capture completeness alone does not establish a performance budget, underlying provider precision, a controlled comparison, or an SLO. Gateway and origin CPU remain separate; their quantiles are not subtracted or added. The local budget check accepts an explicitly chosen relative tolerance and absolute floor and has a regression-detection test; no unmeasured production threshold is enforced.

The collector selects invocation logs (`$metadata.type = cf-worker-event`) and reads the invocation's `request.cf.colo`, matching the observed provider response. Exception logs are not an additional CPU sample. `--model iterations` adds paced, fixed-count characterization with four VUs and a bounded deadline. It waits for a VU instead of promising a fixed arrival rate; HTTP timings exclude its pacing sleep. The default `arrival` model remains available and fails on dropped iterations. At 50 starts/second, four busy VUs can run out during latency spikes around or above 80 ms. Fixed-count success does not certify that stress workload, and missing requests or earlier failed runs must remain visible.

## PoP, individual log qualification, and repeated measurements

The small managed run on 2026-10-17 matched CPU to 180/180 generated and 178/180 no-op client IDs. New Requests sent through Service Bindings lacked `cf.colo`, preventing strict PoP joins. Only 341/360 gateway invocations were captured, so missing logs cannot establish that a request never arrived. The previous collector discarded query run state, population count, and ABR information. Saved event arrays cannot distinguish provider sampling from incomplete query output. These CPU observations remain ineligible for a formal baseline.

`--topology direct` invokes the generated handler inside a public invocation, behind the same authentication, expiry, and body limits. Gateway and direct paths share input/path/header/body/signature oracles. The manifest pins each disposable role URL and rejects routing direct measurements back through the gateway. Original generated TS, transformed handler, and deployed wrapper hashes are distinct. Individual CPU includes the **measurement wrapper**; it is neither pure handler CPU nor a subtraction of no-op quantiles. Client `x-csf-ingress-colo` must match the provider invocation's `request.cf.colo` by client ID. [`cf.colo`](https://developers.cloudflare.com/workers/runtime-apis/request/) identifies the ingress data center, not a guarantee of physical execution placement.

The collector retains the complete query result in a private snapshot, requiring `run.status=COMPLETED`, a matching population count, and explicit `statistics.abr_level=1`. Short pages continue by cursor until the population is returned, with at most three pages of 2,000 events. Incomplete/unknown or active ABR sampling, page caps, and premature empty pages remain `UNKNOWN`; duplicate cursors and population changes fail. CPU/PoP/version/outcome joins remain separate requirements. This conservative ABR check also leaves omitted provider values unqualified. Diagnose remaining missing IDs using query receipts; do not substitute aggregate CPU or inferred PoPs. See the [query API](https://developers.cloudflare.com/api/resources/workers/subresources/observability/subresources/telemetry/methods/query/).

```sh
# Both AA arms invoke the same no-op. AB preserves the no-op/generated comparison.
node scripts/benchmark-edge-k6.js --output reports/edge-aa --k6 /absolute/path/to/k6 \
  --only basic,graphql,hmac --samples 1000 --warmup 100 --rate 50 --runs 3 \
  --model iterations --topology direct --comparison AA
```

Run AB with a new output directory and `--comparison AB`. Local execution denies external networking; managed CPU and ingress PoP remain `UNKNOWN`. The initial p50/p95 candidate minimum is 1,000 samples per case, ingress PoP, arm, and run, for at least three runs. A PoP with fewer samples stays unqualified; do not pool PoPs. `assessAaRepeatability` binds the case/PoP/no-op deployment and checks p50/p95 variation across every arm/run plus binomial 95% order-statistic interval widths against preselected relative tolerances and absolute floors. Intervals assume independent, identically distributed observations and do not establish temporal independence. Passing means `READY_FOR_BASELINE_REVIEW`, never an SLO. p99 always remains descriptive pending a separate tail/correlation study, such as 10,000 samples × five runs. JWKS cold/hit attribution needs a separate explicit measurement.

Additional managed measurement estimate (2026-10-17; full measurement not started, stopped at the small pilot below):

|Scope|Client requests including warmup|Conservative Worker invocation cap|Proposed window|
|---|---:|---:|---|
|Three cases, AA+AB, 1,000 samples × three runs, warmup 100|39,600 plus readiness, capped at 40,000|80,000|Four concurrent, pacing at most 50 starts/s, 40 minutes|
|Nine cases, same settings|118,800 plus readiness, capped at 120,000|240,000 with separate JWKS allowance|Four concurrent, about 90–120 minutes total, split over at least three days on Free|

Invocation counts include public HTTP calls to the origin. Current [Free limits](https://developers.cloudflare.com/workers/platform/pricing/) are 100,000 requests/day and 10 ms CPU/invocation. Stop before exceeding limits. Estimated incremental cost is $0 only if a fresh quota check leaves enough capacity plus a reserve for other uses. The nine-case plan cannot finish on Free in one day. Upgrading to Paid incurs a minimum $5 monthly charge and does not fit the $0.20 cap. Do not change the subscription automatically; quota shortage, CPU limit failures, or incomplete telemetry stop qualification. Earlier approval for 20,000 requests and 15 minutes does not authorize this additional window.

Local reproduction on 2026-10-17 (Apple M4, macOS arm64, Node24.2.0, workerd1.20261012.1, k6 2.3.0): AA and AB with the settings above each completed three runs, totaling 36,000 measured plus 3,600 warmup requests, all with correct oracles and zero invalid/dropped requests. Each cell is the minimum–maximum of per-run quantiles, not an average of quantiles.

|Case|Both AA arms p95 ms|Generated AB p50 ms|Generated AB p95 ms|Generated AB p99 ms|
|---|---:|---:|---:|---:|
|Normal pass|4.251–5.046|2.703–2.895|4.854–5.243|8.243–11.215|
|GraphQL 64KiB|8.296–9.994|4.553–4.750|10.738–11.508|17.265–18.300|
|HMAC 1MiB|12.382–14.210|7.587–8.048|12.926–13.730|17.500–19.984|

AA variation and interval widths stayed within the relative 20%/absolute HTTP 5ms floor selected before aggregation. This shared Mac also ran browser and TypeScript validation activity. Without provider CPU or ingress PoP, qualification remains `INCONCLUSIVE`; these values establish neither managed Edge latency, CPU improvement, a constant 50RPS workload, nor an SLO. The later managed pilot obtained ingress PoP and query receipts but did not capture every CPU row; its results follow below.

## Additional managed-window pilot — 2026-10-17

The approved limits were 40,000 client requests, concurrency four, 40 minutes including deployment and cleanup, and at most $0.20 extra cost. Immediately before execution, Free usage was 2,028/100,000 requests and 2,141/200,000 log events; estimated additional usage cost was $0. Four direct targets and one synthetic origin were deployed without changing existing sites, DNS, or the subscription. Deployment start through confirmed cleanup took 73.267 seconds, excluding preparation/authentication checks. There were 245 client requests: five readiness/invalid-body checks and 240 pilot requests. All five disposable Workers returned 404 after deletion. The pilot used paced shared iterations, four VUs, a nominal pace of 20 starts/second, 20 warmup plus 20 measured requests per arm, and one run.

**Ingress PoP binding is resolved; missing provider logs remain unresolved.** All 120 measured client requests reported KIX. The 111 captured CPU rows matched client ID, version, interval, outcome, and ingress PoP. Basic no-op had 14/20 rows and 1MiB no-op 17/20; the other four series had 20/20 each. All six queries were COMPLETED with ABR=1, returned rows equalling the query population, and ingestion sampleInterval=1. Widening intervals by five seconds on both sides did not find the nine missing IDs; a direct query for a missing ID returned zero rows. An independent re-query several minutes later retained the same gaps. This separates the observed gaps from interval boundaries, ordinary pagination truncation, and observed query/ingestion sampling, but does not establish whether the provider lost or failed to return those logs. Rows from separate queries are never unioned to claim completeness.

The API also returned two different client IDs sharing a metadata event ID. The collector now uses cursors only when another page is required, checking cursor progress then, rather than treating cursor uniqueness as measurement identity on a complete page. Duplicate client-ID invocations remain errors. Ingestion sampling is checked independently of ABR using the events time-series receipt; missing or non-one sample intervals remain UNKNOWN. The observed metadata IDs differ from the uniqueness described in the [API contract](https://developers.cloudflare.com/api/resources/workers/subresources/observability/subresources/telemetry/methods/query/).

|Generated case (20 requests, one run each)|Provider CPU p50 / p95 / p99 ms|Client HTTP p50 / p95 / p99 ms|CPU matches|
|---|---:|---:|---:|
|Basic forwarding|1 / 2 / 5|40.774 / 69.255 / 78.747|20/20|
|GraphQL 64KiB|2 / 4 / 4|39.116 / 45.966 / 55.473|20/20|
|HMAC 1MiB|11 / 18 / 18|139.254 / 163.667 / 185.045|20/20|

CPU is the provider-reported public invocation including the fixture wrapper; underlying precision is unverified. Only integer milliseconds were observed, which cannot establish sub-ms differences. At n=20, nearest-rank p99 is the maximum, not a qualified tail budget. The 1MiB no-op also reported CPU 13/20/20ms over only 17 captured rows. These populations do not isolate generated HMAC overhead, and quantiles must not be subtracted. CPU values above the nominal Free 10ms limit also mean successful small-pilot HTTP responses do not establish suitability for sustained load.

All 240 pilot requests matched the oracle with zero invalid/dropped requests; short-body 400 and oversized-body 413 checks also passed. Because capture completeness failed, the planned AA/AB measurements of 1,000 requests per arm across three runs were not started. Qualification stays INCONCLUSIVE. Before another full run, establish complete capture of the same small population and recheck quotas/deadlines. The three-case full plan remains 39,600 requests including warmup, plus readiness, capped at 40,000 client requests / 80,000 Worker invocations / concurrency four / 40 minutes. Estimated extra usage cost is $0 with sufficient Free quota; stop if a subscription change would be required.

## Ingestion sampling and the 1 MiB fixture — 2026-10-17

The earlier nine missing records were still absent about 34 minutes later. New deployments explicitly configured and read back observability.logs enabled, head_sampling_rate=1, persist, and invocation_logs. The older deployment did not retain the nested logs settings readback, so a settings difference is not established as the cause of its nine gaps. Small probes matched CPU/PoP for 40/40 HTTP/2 requests and 120/120 HTTP/1.1 requests; this does not establish an HTTP/2-specific cause either.

The subsequent AA run stopped on the 1 MiB no-op series: 740 of 1,000 requests succeeded, with 259 HTTP 503 and one HTTP 502. Provider logs included 257 exceededCpu outcomes on the no-op Worker, and origin ingestion buckets had sampleInterval above one. All five disposable Workers were deleted and verified as 404. Generated HMAC was absent from that path, so this is not attributed to a product HMAC defect.

The shared fixture body reader now uses native FixedLengthStream. Targeted units, native workerd checks covering 240 valid requests across three cases and both targets, and complete test:ci validation passed. Exact bytes, short-body 400, overflow 413, source cancellation, and propagation of unknown errors remain checked. Specialist review confirmed the fixes.

|1 MiB no-op diagnostic|Successful/sent|HTTP p50 / p95 / p99 ms|Qualification|
|---|---:|---:|---|
|JavaScript chunk copy|740/1,000|106.299 / 186.878 / 254.515|Failed trial, including error responses|
|Native fixed-length pipe|1,000/1,000|71.990 / 142.601 / 172.723|One diagnostic run; incomplete CPU capture|

These were separate diagnostic trials at different times and conditions. They do not establish an improvement percentage or a qualified generated-code comparison. After the native change, stored CPU matched 996/1,000 requests. Despite ABR=1, one ingestion bucket had sampleInterval=1.2571428571428571. Three of the four missing IDs had CPU/PoP/version records in an independent live tail, locating this loss after execution in the storage/retrieval path. This does not establish the same cause for the earlier nine gaps. The [API contract](https://developers.cloudflare.com/api/resources/workers/subresources/observability/subresources/telemetry/methods/query/) distinguishes platform ingestion sampling from query ABR.

Generated warmup then had one TCP broken pipe out of 100 requests (k6 error_code 1201). The run stopped before its measured phase and deleted every Worker. Failed requests were not replaced or silently retried. A separate small live-stream diagnostic will validate canary synchronization and complete coverage rather than fill stored CPU gaps with aggregates. Formal AA/repetition qualification remains INCONCLUSIVE.

The live path also remained unqualified. Two 1 MiB probes started after canary synchronization, each with 400/400 measured requests matching the oracle and zero invalid/dropped requests. In the latter, waiting up to 60 seconds for every ID still produced only 73/400 fully matched live CPU traces (38/200 no-op, 35/200 generated). This path was not adopted into the maintained harness; its artifacts remain diagnostic. The native WebSocket shutdown issue was addressed with verified loading of an existing ws installation, bounded termination, persisted tail ownership, and shared guardian cleanup. All 28 lifecycle and 11 producer checks and specialist review passed. The latter process exited 1 without hanging; both tail sessions were deleted and verified absent, and all five Workers were deleted and verified 404.

The latter persisted query matched 195/200 no-op and 200/200 generated requests. Both returned COMPLETED, ABR=1, and sampleInterval=1. Two of the five missing no-op IDs had CPU/PoP/version traces in the live stream. Thus sampleInterval=1 is not proof of completeness either. Individual client-ID matching remains mandatory; partial stored/live populations are not merged into a passing capture.

The fully matched 200-request generated HMAC 1 MiB series reported CPU p50/p95/p99 of **4/10/25 ms** and client HTTP **125.732/185.921/206.141 ms**, all ingress KIX. These include the fixture wrapper. Underlying CPU precision is unverified and p99 is descriptive. Missing control CPU and insufficient repetitions prevent adoption as an AA baseline or performance budget.

This approved 60-minute window sent 7,924 client requests in total. All 20 disposable Workers were deleted; existing sites, DNS, and subscription were unchanged. Usage remained within Free allowances, with estimated additional charges of $0. The planned three-case AA/AB series of 1,000 requests per arm across three repetitions remains incomplete because the full-capture prerequisite failed.

Next options are a separately approved low-rate Free diagnostic (at most 300 requests, concurrency one, at most 1 RPS, about ten minutes), or first validating CPUTimeMs Logpush in an existing Paid test environment. Neither has been executed or proven complete. [Logpush requires Paid](https://developers.cloudflare.com/workers/observability/logs/logpush/) and [defines CPUTimeMs](https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/account/workers_trace_events/). An existing Paid environment needs quota, destination, permission, and cost checks. A new subscription has a [minimum $5 monthly charge](https://developers.cloudflare.com/workers/platform/pricing/), exceeding the authorized additional $0.20.

After a complete path is validated, the proposed main run is 39,600 requests including warmup for three-case AA/AB, 1,000 samples per arm across three repetitions; up to 40,000 additional client requests including canaries; up to 80,000 target/origin invocations; concurrency four; a new 60-minute window. A cumulative 48,000 client-request cap including this window needs separate approval and fresh quota checks. With remaining Paid allowances, compute/Logpush variable charges are estimated at $0. Beyond allowances, a sensitivity estimate for 80,000 invocations at at most 30 CPU-ms each is $0.024 requests + $0.048 CPU + $0.004 Logpush = $0.076, plus destination costs. The 30 ms figure is a costing assumption, not a measurement setting. CPU limits, destination costs, and other usage must be checked before execution; stop if the additional $0.20 cap cannot be met. Subscription minimums are separate.


## Free low-rate diagnostic stopped during deployment — 2026-10-17

After confirming that no existing Paid test environment was available, a separate diagnostic was authorized for at most 300 client requests including readiness/warmup, 1 RPS, concurrency one, ten minutes from deployment through cleanup, and estimated additional cost $0. The plan covered basic pass-through, GraphQL 64 KiB, and HMAC 1 MiB, with two warmup and twenty measured requests per arm: 132 planned load requests. Each case independently checked persisted and live CPU populations before allowing the next case. The private k6 copy changed only its VU count and corresponding pacing; inputs, oracle, and generated artifacts were unchanged. This was not the formal A/A campaign.

At 17:34 JST, Free usage was 18,007/100,000 requests and 18,182/200,000 log events. The existing token was rotated with the same single account, Workers Observability Edit permission only, and 18:00 JST expiry. API active status and an empty bounded CPU query with COMPLETED/ABR1 were verified. All 36 mocked lifecycle scenarios, 11 live producer/adapter checks, and the unchanged k6 oracle check passed. Specialist findings about authentication contracts and cleanup reserves were repaired: parent load cutoff is 210 seconds before the hard deadline, and the guardian begins cleanup 180 seconds before it. Maintained source hashes still match the preceding complete-validation receipt.

Deployment began at 17:34:31.967 JST. The first synthetic-origin upload API returned HTTP 200, but the immediately following Worker metadata lookup returned HTTP 404/code 10007, causing Wrangler 4.151.0 to fail. The CLI bytes match prior successful deployments. Code 10007 means [Worker or workers.dev subdomain not found](https://developers.cloudflare.com/workers/observability/errors/); the exact cause, including whether propagation or provider state was involved, remains unknown. No speculative redeployment retry was performed. One Worker deployment was attempted, zero deployments completed, no tails were created, and zero client requests were sent. There are no new CPU or HTTP quantile measurements.

The attempt stopped and confirmed absence within 4.446 seconds. All five reserved Worker names remained HTTP 404 on subsequent queries. Subscription, DNS, and existing sites were unchanged; the local plaintext CPU token was deleted. Estimated additional charges are $0, not a confirmed invoice. The record is `reports/issue-1026-low-rate-20261017/closure.json`, with execution bindings and receipts in the same directory. This deployment failure provides no causal evidence about CPU-log loss. A complete capture path remains unestablished and formal qualification remains INCONCLUSIVE.


## Zero-cost diagnostic preparation and authentication blocker — 2026-10-18

Work resumed in the existing worktree at HEAD `944091e99266a6d69204a37088c19858f1a4d552`. Index and working copies of the initial nine files and both diffs were saved separately; 2,563 historical evidence files were hashed. Earlier reports, failed logs and approvals were preserved. Hash-only raw evidence remains hash-only; diagnosis uses the existing readable receipts.

At 18:04 JST, the existing OAuth could read the account workers.dev state, and the previous origin name returned 404/code10007. A CPU query restricted to that account and name returned 403/code10000. The earlier collector token expired on October17, so current collection authorization is unverified. The Free dashboard showed 294/100,000 daily requests, 4/200,000 daily log events and $0.00 current-period billable usage; a fresh pre-deployment check and final billing confirmation remain separate. Deployment operations, diagnostic requests and CPU samples are all zero. This request's ten-minute cloud window remains unused.

A local regression reproduced and fixed the collector silently ignoring extra IDs while declaring complete capture. Direct topology, case/arm, the client manifest endpoint, Worker role and identity hashes are bound together to prevent gateway/origin CPU from being mistaken for target CPU. Aggregation/collection sources and executable JavaScript hashes are retained in the identity and collection result. The collector now binds the client point count and series, requires a finite interval, rejects extra/duplicate/invalid bindings and retains individual matched ID/CPU/PoP/version/outcome rows. Missing CPU remains unknown. This does not establish that the historical CPU losses or code10007 are resolved. The shared k6 path accepts `--concurrency 1`, with pacing derived from the same concurrency. After an abort, a k6 child that ignores SIGTERM is killed after two seconds and reaped; the failed series is retained and no next series starts. Product-generated code, authentication and body oracles are unchanged.

Minimal local check (no cloud deployment):

```sh
npm run build:ts
node scripts/edge-benchmark-unit-tests.js
node scripts/benchmark-edge-k6.js --output reports/edge-local-diagnostic \
  --k6 /absolute/path/to/verified/k6 --only basic,graphql,hmac \
  --samples 2 --warmup 1 --runs 1 --rate 1 --concurrency 1 \
  --model iterations --topology direct
```

The smallest cloud proposal is three cases × two arms × (one warmup + two measured requests) = 18 requests, plus at most five readiness and three body-rejection requests: 26 client requests and at most 52 target/origin invocations. Concurrency1, at most1RPS, at most five disposable Workers and ten minutes from first deployment to confirmed deletion remain hard limits, with cleanup time reserved. Upload HTTP200 alone cannot start load: Worker/version readback and real HTTP readiness must agree. Unknown creation results permit only bounded readback of the same names, without re-upload. Every measured ID in each case must match through the same stored path; missing CPU, sampling, CPU-limit or transport errors stop the next case. This is preparation; deployment-path repair and live Edge acceptance remain incomplete.

Continuing requires short-lived Workers Observability Edit authentication restricted to the same account. No permission expansion or paid service is performed, and secret values must never enter chat or the PR. New records are in `reports/issue-1026-zero-cost-20261018/`. Complete CPU capture is unproven, qualification remains **INCONCLUSIVE**, and the Goal remains incomplete. Draft PR source acceptance and local validation do not replace these conditions.


## Zero-cost execution and bounded readback repair — 2026-10-18 19:07 JST

The 18:04 JST authentication blocker above was resolved with a token restricted to the same account and Workers Observability Edit, expiring at 19:30 JST. Existing OAuth was refreshed with unchanged scopes. The fresh Free dashboard showed 1,056/100,000 daily requests, 6/200,000 log events and $0.00 current-period billable usage. Credentials are private; the collector token plaintext file was removed when this window ended.

The single authorized cloud window was consumed. Four Workers received one upload each. Origin/bare/basic passed settings, version/etag, 100% deployment and workers.dev readback. GraphQL returned upload HTTP200 followed immediately by settings GET 404/code10007, stopping before HTTP readiness. The same GraphQL settings GET returned200 during cleanup 9.245seconds later. This observes temporary absence in this settings readback; it does not establish the historical CLI root cause or public HTTP reachability. Root cause remains UNKNOWN.

There were zero client requests and zero CPU samples. The four created Workers were deleted after ownership-tag checks; all five target names, including the uncreated hmac name, returned settings GET 404/code10007. The entire window lasted32.228seconds and first-deployment-to-final-absence lasted32.172seconds. The guardian stopped, zero owned Workers remain, and cleanup finished within ten minutes. Estimated additional cost is $0; final billing is unconfirmed.

Based on that observation, settings readback for the same successfully uploaded name now retries only the exact404/code10007, at most six reads separated by two seconds. Each API retains its five-second timeout, the load cutoff remains390seconds from the initial start, and cleanup must finish by600seconds. Final absence, unknown404,403, transport errors and ownership/version/etag/sampling/deployment mismatches remain errors. There is no upload/DELETE resend, name substitution, CLI update or alternate-path fallback. Cleanup uses the same bounded reader; an attempted upload that remains absent before any DELETE stays UNKNOWN. Cleanup shares an80-second budget across all targets, capped one second before the600-second deadline. Each operation reserves six seconds (one for pacing and five for I/O), DELETE reserves twelve seconds including its absence readback, and retry waits consume the same budget. The parent resumes incomplete guardian receipts once through that same path and never converts unresolved absence into successful cleanup.

A regression in which the same settings become readable after five absent reads failed before the repair. Local checks verify bounded recovery, exhaustion and immediate failure for other errors. Cloud-executed source/JavaScript bytes are mapped in `reports/issue-1026-zero-cost-20261018/cloud-executed-snapshot/mapping.json`; `cloud-closure.json` in that directory records the result. The later readback repair is locally verified and was not accepted by this cloud execution.

Execution binds the fixed account, this authorization receipt and an exclusive start marker; changing output directories or receipt names cannot start a second window. An independent guardian cleans up after parent disconnect using the same ownership/deletion receipts, without resending unknown DELETE operations. The initial window is used and no further cloud window is authorized. Complete CPU capture and real HTTP readiness remain unproven; diagnostic status and formal qualification remain **INCONCLUSIVE**, the Goal is incomplete, and the PR stays Draft. Local reproduction uses the preceding commands and `node scripts/edge-benchmark-cloud-unit-tests.js`; unit checks never connect to the real cloud.
