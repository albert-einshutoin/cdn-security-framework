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
newline. No `--out`, file save, GitHub Summary write/upload, PR posting,
apply, or deploy exists. Shell redirection happens before the CLI starts; never
redirect a report onto an input file.

The installed-package smoke verifies this binary. The [standard CLI reference](cli.md)
documents the 2.0 commands; the formal Source-aware workflow and GitHub upload
remain future work.
