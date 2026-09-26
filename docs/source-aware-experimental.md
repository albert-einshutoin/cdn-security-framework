# Experimental Source-aware CLI (dev branch only)

`cdn-security contract source-diff` is an **unpublished Experimental** entrypoint in
the `dev/2.1-source-aware` candidate package. It is not part of published 1.4.0,
the 2.0 release candidate, or a completed standard 2.1 workflow. Use a reviewed
candidate tarball from its recorded CI run; do not substitute `npm latest`.

In an empty, disposable POSIX consumer with supported Node.js (>=20.17.0), put
the verified candidate `.tgz` in the directory and install it. Compare its
SHA-256 with the PR evidence before installation. For offline acceptance, prepare
the lock and dependency cache separately, then use the single-pack consumer lane.

```sh
shasum -a 256 candidate.tgz
npm install --ignore-scripts ./candidate.tgz
mkdir -p workspace
cat > workspace/openapi.yaml <<'YAML'
openapi: 3.0.3
info: {title: Synthetic, version: 1.0.0}
paths:
  /users:
    get:
      responses:
        '200': {description: OK}
YAML
cat > workspace/policy.yml <<'YAML'
version: 2
defaults: {mode: enforce}
request:
  allow_methods: [GET]
  block: {header_missing: []}
routes: []
response_headers: {}
YAML
./node_modules/.bin/cdn-security contract source-diff \
  --workspace-root workspace --openapi openapi.yaml --policy policy.yml \
  --target aws --current-date 2026-09-25 --format text
```

The command reads one explicit workspace. `--source tsconfig.json` requests the
existing static NestJS analyzer; without it, Source is **omitted**, and no Source
discovery runs. Use `--target aws|cloudflare`, optional bounded
`--exceptions <path>` and `--environment <name>`, `--fail-on
error|warning|never` (default `error`), and `--format text|json|sarif|summary`
(default `text`). The current date is required, including when no exceptions are
supplied. The existing Source authentication defaults apply: information they
cannot establish remains unknown or partial, never inferred as public or
authenticated. A partial result is not proof of safety.

With `--source`, `--source-auth-config <path>` reads one explicit YAML or JSON
data file relative to `--workspace-root`. For example,
[`examples/nestjs-contract/security-analyzer.yml`](../examples/nestjs-contract/security-analyzer.yml)
maps `Public`, `Roles`, and `JwtAuthGuard` in that fixture. Without the option,
existing empty Source auth defaults remain in force; an explicit file containing
all three required keys with empty arrays/map has the same meaning. The file is
validated as the existing `NestJsAuthConfig` object, with required
`public_decorators`, `roles_decorators`, and `guard_mappings` and no extra keys.
In the example, the default leaves `GET /users/{id}` and `POST /users` auth
unknown. The explicit file recognizes direct `Public` on the GET route,
`Roles('writer')` on the POST route, and the declared bearer mapping for
`JwtAuthGuard`. The unmapped `UnknownGuard` still makes its route partial;
the analyzer can then report the corresponding OpenAPI/Policy mismatch Findings.
An invalid file exits `2` before analysis with a fixed diagnostic and never
falls back to defaults. The option without `--source` also exits `2` without
reading the file. There is no discovery, include, alias/merge composition,
environment interpolation, or executable JS/TS config. The CLI reads at most
64 KiB from one regular file; workspace-local symlinks are accepted, while
symlinks outside the workspace are rejected. This input guarantee is for the
CLI file option, not every programmatic config object. POSIX/local fixtures are
verified; Windows and network filesystems are not verified. A mapped Guard name
and auth kind express a user-provided static assumption. They do not prove the
Guard body, token validation, middleware order, or runtime enforcement. Unknown
Guards and other unresolved Source facts stay partial.

For NestJS controllers, the static analyzer reads a direct
`@Controller({ path: 'users' })` object, a static `path` string array, a
project-local static string constant, or an empty object (the root path).
Parentheses and the existing safe TypeScript type wrappers are accepted.
Controller and method path arrays use the existing bounded route composition.
An empty path array does not become a root route. Without explicit URI mode,
the object may contain only the `path` field: `version`, `host`, `scope`, `durable`, unknown fields, object
aliases, spreads, computed keys, accessors, and dynamic values remain unresolved
with a diagnostic. They do not become unversioned or all-host routes, and an
unresolved Controller does not prove that its declared routes are absent.
This is static decorator-path extraction, not proof of runtime routing or
authentication. `Public`, Roles, and configured Guards retain their existing
static interpretation; unknown authentication remains unknown.

With `--source`, add `--source-global-prefix /api` when **you have confirmed**
that every compared Source route uses that one fixed global prefix. For example,
`--source tsconfig.json --source-global-prefix api` and `/api` are equivalent.
The prefix is applied once to the comparison copy after a static Controller
object path is extracted; the prefix alone does not resolve version or host constraints.
This is an explicit comparison assumption, not detection of `setGlobalPrefix`
from bootstrap code. Omitting it keeps decorator-local routes and existing
report identities. Supplying it without `--source` exits `2`, with empty stdout,
before any input is loaded. Empty, root-only, trailing/repeated slash, URL,
query, fragment, backslash, control, dot, percent, wildcard, dynamic parameter,
and whitespace forms are rejected with a fixed diagnostic; no fallback applies.
Only one or more ASCII `[A-Za-z0-9_-]` segments are accepted, with zero or one
leading slash and a maximum canonical length of 256 characters. Case is
preserved. Provider-token-like values are rejected before input loads.

| Input | Result |
| --- | --- |
| `api`, `/api` | Both use `/api` |
| `/API`, `/api/v1` | Preserve case and multiple fixed segments |
| Empty, `/`, trailing or repeated slash | Exit `2` before analysis |
| URL, encoded/dynamic/wildcard/dot segment, provider-token-like value | Exit `2` before analysis |
| Canonical length above 256 | Exit `2` before analysis |

Local `/` becomes `/api`, `/articles/{slug}` becomes
`/api/articles/{slug}`, and an existing `/api/items` becomes `/api/api/items`.

Use `--source tsconfig.json --source-versioning uri` only when the compared app
uses NestJS URI versioning with the default `v` version prefix. For example,
`@Controller({ path: 'users', version: '1' })` with `@Get(':id')` is compared as
`GET /v1/users/{id}`. With `--source-global-prefix /api`, it becomes
`GET /api/v1/users/{id}`. The prefix is applied once before the version; literal
`api` or `v1` segments in a Controller path are retained. The URI mode is an
**explicit user assumption**, not a bootstrap or environment inspection.
Without the option, existing local-route analysis and report identity remain
unchanged; omission does not prove that the app has versioning disabled.

The analyzer extracts one static string version from direct Controller options,
`@Version('2')` on a method, or a project-local constant resolved by the existing
string resolver. A method version takes precedence over its Controller version.
The exact string is preserved, including case and leading zeros. Only one
`[A-Za-z0-9_-]` segment of at most 255 characters is accepted. Version arrays,
`VERSION_NEUTRAL`, missing/dynamic/non-string values, multiple method `@Version`
decorators, and a Controller with `host` or other unsupported options remain
reasoned unresolved candidates. A method version that is present but unresolved
does not fall back to the Controller version. An unresolved missing version is a
limit of this static comparison, not a claim that NestJS returns HTTP 404.
Custom version prefixes, `prefix: false`, `defaultVersion`, Header, Media Type,
Custom versioning, global-prefix exclusions, multiple apps, and proxy rewrites
are outside this mode. Supplying `--source-versioning` without `--source`, or
supplying a value other than `uri`, exits `2` before inputs are read.

The static mapping is checked against NestJS commit
[`112450bb`](https://github.com/nestjs/nest/tree/112450bb0cbb847fbff5bec46a1c493587564305).

| NestJS behavior | This comparison mode |
| --- | --- |
| `@Controller` stores path and optional version metadata | Reads direct static options; keeps unsupported options unresolved |
| Method `@Version` stores version metadata | Uses one static string and gives it priority over Controller metadata |
| URI route factory uses the default `v` prefix | Builds `v` + the exact version string after any explicit global prefix |
| The application supplies `defaultVersion` and the versioning strategy | Does not inspect bootstrap; missing versions and other strategies remain unresolved |

The Source version metadata is AST evidence; URI mode and global prefix are
explicit assumptions. Text/JSON/SARIF/Summary and the dev CI record keep these
distinct from project and auth-config digests and from the transformed comparison
contract digest. Only Implemented–Declared and Implemented–Allowed use the
transformed routes. Declared–Allowed keeps its original meaning. A changed route
can change its Finding instanceId; an old exact exception selector does not
expand to the new route. Neither URI mode nor the auth configuration proves
runtime reachability, Guard enforcement, or authentication.

The original Source IR, input/project digest, auth configuration digest,
file/line, and unknown/partial status remain unchanged. A comparison-only copy
gets the prefix for Implemented–Declared and Implemented–Allowed; the OpenAPI
and Policy inputs and Declared–Allowed comparison are unchanged. Put OpenAPI
and Policy in the path domain you intend to compare; this option does not
reinterpret Swagger servers/basePath or proxy rewrites. The internal routing
assumption and comparison-contract digests are separate from the input and
auth digests. Text/JSON previews, SARIF properties, Summary, and the dev CI
record identify the explicit assumption safely. A prefixed route may change a
Finding instanceId, so an old exact exception selector is not broadened
automatically. This fixed-prefix mode does not support exclusions, multiple Nest apps, or reverse proxy rewrites. It does not prove
runtime route reachability, middleware/Guard enforcement, or authentication.

| Format | Explicit assumption display | Finding scope |
| --- | --- | --- |
| Text | Safe prefix in the bounded preview | Bounded Finding preview |
| JSON | Safe prefix and routing/contract digests in the internal preview | Bounded Finding preview |
| SARIF | Safe prefix and digests in internal tool properties; assumed routes on Source-derived results | Full result within reporter limits |
| Summary | Safe prefix label | Top Findings only |

The dev CI record stores the safe prefix and digests separately from the original
Source project/auth digests. The Node 24 installed-package consumer checks
prefix present/omitted/invalid, all four formats, and `--out` with the same tgz.
It also checks the explicit URI mode, compared route set, negative inputs,
auth-config, and installed CI driver run/publish/verify-stage/gate;
the package acceptance gate rejects missing evidence.

Text and JSON are bounded previews; JSON is not a stable complete public
Source-aware schema. SARIF covers the complete result within existing reporter
limits. Summary shows up to 10 Findings and 32 KiB. Findings and omissions may
therefore appear differently in each display. The exit status is `0` when the
requested processing succeeds below the Finding threshold, `1` when it succeeds
at the threshold, `2` for input/configuration or bounded-input failure, and `3`
for internal, reporter, or output failure. A failed input stage may still produce
a report with independent Findings and exit `2`. `--fail-on never` does not
turn errors into success. Reports go to stdout; fixed failure diagnostics go to
stderr. JSON and SARIF stdout each contain one JSON document and a trailing
newline. Use `--out <path>` to save those same bytes to **one new regular file**
inside the explicit workspace instead of stdout. For example, append
`--format sarif --out reports/source.sarif` to the command above after creating
`workspace/reports`. The parent directory must already exist. The CLI does not
create directories, overwrite or append to existing files, or accept `--out -`.
Choose a fresh destination name for each saved run.
An existing file, symlink, hardlink, directory, FIFO, or socket at the destination
is refused. The new file is created with restrictive owner-only permissions
(`0600` on POSIX). The `0`/`1`/`2` report status is retained after successful
save; invalid or protected destinations exit `2`, and write/cleanup failure
exits `3` with a fixed diagnostic and no report on stdout.

The destination must remain inside the workspace and outside `policy`, `dist`,
`node_modules`, and `.git`, including aliases through symlinks. It cannot
collide with an explicit or discovered OpenAPI, Policy, Source, auth-config,
exception, local-reference, tsconfig, or package-metadata input, even when an
input is missing. The guard refuses saving when an internal input stage cannot
establish sufficient protection. These checks cover the inputs observed in this
run, not an atomic snapshot of a concurrently changing workspace. A concurrent
actor changing directory entries can still cause a failed save or, in an
unrecoverable filesystem fault, leave a detectable partial new file. Do not
share the workspace with untrusted concurrent writers. POSIX/local fixtures
are verified; Windows and network filesystems are not verified.

The separate [dev-only CI example](source-aware-ci-dev.md) writes a verified
Step Summary and a normal Actions artifact for synthetic fixtures. The CLI
itself does not write to GitHub, and standard 2.1 workflow integration, Code
Scanning upload, PR posting, apply, and deploy are not provided.
Shell redirection happens before the CLI starts; never redirect a report onto
an input file.

The installed-package smoke verifies this binary. The [standard CLI reference](cli.md)
documents the 2.0 commands; a formal Source-aware workflow remains future work.
