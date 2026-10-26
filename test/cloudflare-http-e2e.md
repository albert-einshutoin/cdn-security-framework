# Cloudflare HTTP E2E (local workerd)

This development-only check sends real HTTP through **Node client → workerd →
separate loopback Node HTTP origin → client**. It adds no cloud charges, requires
no Cloudflare account, credentials, deployment, remote bindings or paid services.
The origin is a separate listener in the harness process; the Worker runs in its
own native workerd process. Neither the Worker handler nor its fetch is mocked.
The Artifact Verification negative service shares that process and origin, but
executes its separately generated module on a second loopback socket.

## Synthetic probe / normal traffic fixture

The fixed fixture declares `phpinfo.php`, `wp-login.php`, `wp-admin` and
`xmlrpc.php` unused for this synthetic site. Its root secret names (`.env`,
`.git`, `id_rsa`, `id_ed25519`, `server.key`, `private-key.pem`, and the two SSH
key names under `.ssh`) are rejected using explicit fixture-only path regexes.
Literal raw, encoded, case, slash, matrix and query cases require HTTP 400, a
Worker block event and zero origin arrivals. Ambiguous double-encoded dot input
also requires 400; it is not evidence that the path regex handled those bytes.
Expected paths/statuses are fixed independently before compilation.

Positive cases preserve root/normal/English/Japanese routes, `.well-known`,
`cdn-cgi`, JS/Wasm assets, `/api/required.php`, static WP uploads and boundary
names such as `.env-example`, `.github`, `phpinfo.php.txt` and
`wp-administrator`. These are synthetic origin responses, not PHP/WP execution
or Cloudflare-reserved endpoint behavior. GET, HEAD, POST and OPTIONS are
explicitly allowed in this fixture; DELETE remains 405. Requests retain the
fixture's synthetic `x-required` prerequisite; this is not a browser CORS test.
The harness checks JS/Wasm bytes and content type and HEAD's empty body. It
does not execute Wasm or measure CPU, latency or browser compatibility.

The Artifact Verification contract retains its JSON-echo body requirement;
JS/Wasm and HEAD delivery run as direct harness assertions outside that subset.
The overall harness fails if either the fixed artifact subset or these assertions fail.

Host values `fixture.example:443` and `fixture.example:8443` are logical
authority variations; both are expected to pass because this Worker Policy
has no port rule. The actual client socket and outbound origin remain bound
to loopback HTTP. `fixtureScope` records WAF execution and port enforcement
as `UNKNOWN`. These observations do not prove TLS, public DNS, Cloudflare port
filtering, WAF expression parity or deployed protection. WAF subset checks
require their own declared compiler/evidence contract.

## Run

Use a supported native workerd platform and the repository's Node >=20.17
development environment. The observed platform is macOS arm64 / Node 24.2.0.
Install dependencies once, then run:

```sh
npm ci --ignore-scripts
npm run test:cloudflare-http-e2e
# Optional explicit report location:
node scripts/cloudflare-http-e2e-tests.js --report reports/cloudflare-http-e2e.json
```

The first command requires npm registry access. After dependency preparation the
test's communication uses only `127.0.0.1`. The pinned dev dependency is
`workerd@1.20261012.1`; a missing/unsupported native runtime is an error, without
a Node handler fallback. No Miniflare cf-metadata download or Wrangler telemetry
is involved. workerd's implicit internet service is replaced with deny-all;
global outbound fetch is a native `ExternalServer` service fixed to the local
origin address. This changes transport routing, without changing Worker code or
fabricating a fetch response. See the upstream [configuration contract](https://github.com/cloudflare/workerd/blob/main/src/workerd/server/workerd.capnp).

## CI integration

`npm run test:ci` includes this suite through `test:coverage` → `test:all`.
It runs on main/release pushes, scheduled and manual full validation, PR shadow
full validation, and PR changes promoted to full validation. Selective PR plans
also select the same native harness for the Cloudflare module. Authentication,
shared compiler, runtime templates and policy changes retain full validation.
Documentation-only selective plans do not add a native run.

The harness uses disposable loopback services and synthetic credentials only.
A missing native runtime, assertion failure or cleanup failure exits nonzero and
fails its CI target. PR jobs upload `cloudflare-http-e2e-selective` or
`cloudflare-http-e2e-shadow-full` when the report exists; non-PR full validation
includes it in `full-validation-report-*`. Impact reports keep their original
artifact layout for the comparison job. These are correctness checks; elapsed
HTTP times in the report are observations, not a Worker CPU or latency budget.

The harness uses the installed repository CLI `init --platform cloudflare` to
obtain the current generated `wrangler.toml` compatibility date and flags, then
`build --target cloudflare` with a disposable schema-2 policy. It transpiles the
generated TypeScript to an ES module with the existing esbuild dependency. It
does not replace source text, patch CFG, modify the generated Worker or provide a
test Worker. Generated TS and module SHA-256, policy/compiler/harness/lock/native
runtime identity, date/flags and network configuration are in the JSON report.

## Acceptance and evidence

`reports/cloudflare-http-e2e.json` includes sent request-targets, methods,
responses, each origin's URL/method/headers/body receipt, Worker rejection events,
native runtime output, and cleanup proof. These are synthetic fixtures only.

| Requirement | Check |
| --- | --- |
| Allowed HTTP round trip | GET query normalization and POST JSON arrive once; body returned by the actual origin equals its receipt |
| Missing/incorrect auth | `/admin` without token or with incorrect synthetic token returns 401 and has zero origin arrivals |
| Correct auth | Correct token arrives once, origin response returns, protected response includes no-store |
| Representative controls | Encoded admin/raw matrix/double-slash aliases, encoded slash, dot segments, method, URI length, required header, UA deny list; spoofed XFF/edge marker removed; security response headers verified |
| Origin failures | Origin's 503/body remains 503/body; closed origin listener yields native 5xx or the explicit ECONNRESET transport error, never a successful response or a timeout accepted as success |
| HTTP parser boundary | Raw NUL header returns HTTP 400 with zero origin arrivals and no Worker event for that request ID |
| Cleanup | Child exit, both Worker listening ports and the origin port closed, origin closed and owned temporary directory removed |

`http.request({ path: ... })` sends the literal target without URL-client
normalization. workerd's Request URL can still remove dot segments before Worker
execution: sending `/public/../admin` is recorded separately from the Worker
event's `/admin`; the canonical protected destination must return 401. This is
not evidence of the Worker's raw traversal guard seeing the original bytes.
Policy rejection requires the corresponding Worker block event as well as status
and zero origin count; a parser 400 is kept as a separate layer. In particular,
the trial of a space-containing request line was not classified as parser proof:
the runtime admitted `/bad` and the Worker rejected a missing header.

Startup is bounded (10 seconds for workerd, 120-second overall abort), each HTTP
operation by 5 seconds, and shutdown by TERM/3 seconds then KILL/3 seconds. A
brief port-reservation handoff can collide with another local process; it fails
the run rather than silently selecting another environment. `finally` disposes
owned resources on assertions or communication errors. A cleanup failure makes
the report and command fail.

To exercise cleanup after startup, the following command **must exit 1** with the
injected error; this is not a passing product test:

```sh
node scripts/cloudflare-http-e2e-tests.js --fail-after-start \
  --report reports/cloudflare-http-e2e-failure.json
```

Add `--fail-cleanup` to that command to inject an error after runtime shutdown;
the other resources must still be disposed and the command must still fail.
This exercises cleanup continuation without deliberately leaving a child alive.

Verify all report `cleanup` fields are true and the recorded child PID and
temporary directory no longer exist. Keep normal and injected-failure reports
separate. No hosted CI is started by this command.

## Observed result and limits

The maintained suite also exercises B1 path variants and RS256/JWKS using real
synthetic RSA signatures. A single workerd process fetches trusted HTTPS
identification URLs through its fixed loopback outbound; this transport proves
neither public DNS nor TLS. The same listener records JWKS and application
requests separately. JWTs and private keys are never written to its reports.

JWKS admission is per configured endpoint and Worker isolate: at most two fetch
attempts (including initial load and failures) per fixed five-second window,
with shared in-flight work and a two-second fetch/body deadline. A denied miss
does not move the boundary. Healthy rotation can require up to five seconds
plus the fetch deadline, assuming requests continue and scheduling is timely.
Actual failures also honor configured negative-cache TTL; recovery can wait
until both that TTL and the fixed window permit a fetch. Throttling alone never
permits expired keys; stale keys require an actual failed fetch and remain
bounded by gate TTL plus configured stale-if-error. A TTL shorter than the
refresh window can temporarily fail closed after both attempts are spent.

The suite checks 32 and 128 consecutive unknown kids in one window, cold/fresh/
expired parallel misses, repeated kids, correct signatures, incorrect signatures
and claims, live key rotation, separate endpoints, 5xx, malformed JSON, refused
connections, hanging fetch, redirect rejection, and recovery. Deterministic
generated-runtime tests cover the exact five-second boundary independently.
The limit applies separately to every isolate; it is not a global IdP limit.
State is bounded by configured endpoints, not incoming kids; this is not a
memory-exhaustion benchmark. Historical observations below remain dated.

2026-10-12: native workerd `1.20261012.1` (`workerd 2026-10-12`), macOS arm64,
Node 24.2.0, compatibility date `2026-07-20`, flags `[]`. Normal run: 17 cases
pass. Injected startup failure: expected exit 1, all cleanup fields true; child
PID absent and temporary directory absent. The origin-unreachable check observed
ECONNRESET, rather than inventing a 500 response. Review and complete validation
results are recorded below after they finish.

This proves the listed local fixtures on that native runtime. It does not prove
Cloudflare POP routing, managed WAF rules, distributed cache, production limits,
geo/cf metadata, live JWT/JWKS, or AWS Lambda@Edge. Existing Node handler/unit
tests remain separate. This phase does not fix or waive the previously recorded
encoded-matrix/JWKS security findings in the #1024 audit, or claim exhaustive path
coverage, H01, RC GO, package publication or provider readiness.

## Validation / review record

Targeted build/types, generated-boundary and dependency audit (0 vulnerabilities)
passed. The first specialist review requested independent cleanup attempts and
structured/drained parser-event proof. Both were repaired; the subsequent
targeted normal run passes, and injected startup + cleanup errors report failure
while all resource-cleanup proofs are true. Final scoped specialist review: **ALLOW** (gpt-5.6-sol / medium).

Complete validation: `npm run test:ci` **exit 0** in an isolated disposable Git
checkout with the four scoped file snapshots copied before this result-record
section was updated, over source
`c5a0caa1e552e8a2b8c700a197da96672f574258`; the pre-existing uncommitted audit
report was preserved in the user checkout and excluded from this validation
input. The first run had one unrelated NestJS test timeout (606 pass / 1 fail);
that same test passed alone in 1.6 seconds, and one bounded complete retry
passed all 33 files / 607 tests plus the remaining full gate. Coverage: 81.23% lines, 80.63% branches, 82.89% functions.
Dependency audit: zero vulnerabilities. No test timeout, product source or CI
configuration was changed to obtain this result.

Companion Stop Review Gate: see the raw verdict in
`reports/cloudflare-http-e2e-stop-gate.json`. The first Gate detected that this
result-record section was appended after full validation; the record below now
separates tested bytes from post-validation annotations. The subsequent Gate
reviews that distinction and the unchanged executable inputs. No commit/push/PR/deploy
is part of this phase.

Provenance: the three executable inputs (`package.json`, `package-lock.json`,
`src/scripts/cloudflare-http-e2e-tests.ts`) are byte-identical to the reviewed and
full-tested snapshots. This repo-only Markdown is not compiled, imported or
packaged by those checks. Its instructions and acceptance sections are unchanged;
only this validation/review record was appended after the run. The original
validation context is preserved, rather than rewriting its digest to fit this
annotation. Binding and the section-only delta are in
`reports/cloudflare-http-e2e-validation-binding.json`. The final Gate verdict is
written separately, so recording its result does not mutate a reviewed file.

## Local Artifact Verification MVP (#1123)

The current harness also evaluates the generated artifact against a fixed,
independent HTTP contract. Its Policy and literal cases live in
`src/scripts/fixtures/cloudflare-http-cases.ts`; the internal pure matcher is
`src/contract/verification/artifact-http.ts`. The contract is frozen before the
CLI compiles anything. Existing expected statuses and literal destinations have
one source of truth. Neither compiler output, a handler nor the path normalizer
computes the expected answer. Existing Path/JWKS/parser/origin-failure regression
checks remain, with three additional ordinary `/admin/child` credential cases.

This verification covers only static-token admission, protected `no-store` and
`Vary: Authorization`, public-route noninterference, and the corresponding HTTP
status, decision event and origin method/path/body receipt. It does not model
distributed cache HIT/MISS. A matching status without the event/receipt evidence,
an empty observation set or zero findings is insufficient for VERIFIED.

`artifactVerification.normal` and `.negative` are separate report entries. The
normal generated TS and executed ESM remain unmodified. The negative Policy
deliberately omits the admin static-token gate, and the same compiler produces a
different, honestly identified TS/ESM pair. Four HTTP requests on its separate
native service detect the bypass without running the JWKS suite again. The
expected contract digest stays fixed; expected-Policy and actual compiler-input
Policy digests are recorded separately. For example, anonymous `/admin` must be
401/block/zero origin arrivals; observing 200/allow/one origin receipt is a
VIOLATED counterexample. A test that detects this negative successfully does not
make that artifact VERIFIED.

The matcher returns VERIFIED only for a nonempty, complete declared
`local-artifact-fixture`; a sufficiently observed mismatch is VIOLATED even when
other required cases are missing. Missing identity/events/cases or stale/mixed
evidence stays scoped UNKNOWN. Bad digests, duplicate or invalid case joins,
native runtime, transport and cleanup failures are Error and fail the harness.
Security verdict, Finding severity/confidence and test exit status remain separate.

Compiler instrumentation records actual file reads and loaded repository CJS
modules, including the input Policy. The harness compares those recorded hashes
to the bytes it consumes. It also checks source/execution modules, actual TS/ESM,
lockfile, workerd binary/version, generated compatibility settings and the exact
runtime config before/after execution. The current two-service config retains
deny-all internet and the fixed loopback origin. Timestamp, duration, PID,
temporary location, ports and original raw identity digests are metadata;
credential values become abstract states in the replay bundle. The owned native
process is drained and cleanup completes before the security result is accepted.

Run the same commands in the Run section. The output prints separate normal and
negative bundle digests, and the JSON contains redacted replay bundles. Internal
`replayHttpArtifact(contract, bundle, trustedDigest)` recomputes the same semantic
result without making HTTP requests. Supply the captured digest from a separately
trusted capture/manifest or verified CI artifact; do not recompute a new trusted
digest from an edited bundle. An absent trust root gives UNKNOWN; a changed bundle
under the captured root is Error. Replay attests the recorded snapshot, not a new
native execution. The fixed contract must still come from the checked-out fixture,
not `expectedStatus` fields in a measured report.

The existing `--fail-after-start --fail-cleanup` injection covers the shared
process, origin, both Worker ports and owned temporary directory. Its expected
Error/exit 1 is kept apart from the normal test and the VIOLATED negative artifact.
This internal development facility adds no public API/CLI/schema or release gate.
Historical validation records above are not evidence for the current change.

[日本語の範囲・再現・判定契約](cloudflare-http-e2e.ja.md)
