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
