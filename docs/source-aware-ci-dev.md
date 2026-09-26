# Experimental Source-aware CI connection (dev only)

The runnable example is the `source-aware-ci` job in the repository's
`.github/workflows/policy-lint.yml`. It runs only on a
manual dispatch of `dev/2.1-source-aware` or a `feat/source-aware-ci/` branch.
Ordinary PRs targeting `main`, scheduled runs, and release refs skip this job.
It uses only synthetic `examples/nestjs-contract` data and `contents: read`.
The standard 2.0 `examples/github-actions/contract-diff.yml` is separate.

```sh
gh workflow run policy-lint.yml --ref dev/2.1-source-aware
gh run list --workflow policy-lint.yml --branch dev/2.1-source-aware --limit 1
```

The job downloads the **same run/attempt** single-pack producer candidate,
checks source/harness/tarball/lock identity, then installs its locked consumer
dependencies with scripts disabled. It copies the synthetic target into a new
workspace and prepares a fresh `reports` directory for that run/attempt. Only
the analysis step uses a network namespace without network access. It does not
run target npm scripts, Source, JS configuration, or Guards. The internal
driver resolves from `consumer/node_modules/cdn-security-framework`; there is
no repository-source or global-package fallback, consumer rebuild, or repack.
The candidate identity and the target's analysis-evidence digest are recorded
separately.

The example passes OpenAPI, Policy, `--source`, target, a fixed date, and
`--fail-on never` through a small JSON configuration. The same internal input
path accepts the CLI's `sourceAuthConfig`, `exceptions`, and `environment`
fields for synthetic configurations. A real application workflow must choose
explicit workspace-local input paths and its own Finding threshold; `never`
does not make input, internal, save, or CI failures pass. Source omitted is
shown as omitted. Partial and unknown do not prove safety.

One shared validation/auth/exception/analysis/finalizer execution renders
Summary Markdown and complete SARIF. The existing safe new-file writer saves
them under the workspace. It never overwrites inputs or old reports. The CI
record contains candidate identity, analysis verdict, output status, relative
names, byte counts, and SHA-256 hashes; it contains no raw input, absolute
path, or stack. The workflow validates regular files, hashes, Summary UTF-8,
size/content and the pinned official SARIF schema before copying the Summary
as data to `GITHUB_STEP_SUMMARY`. The same verified Summary bytes are staged
and transferred. Before upload, `verify-stage` checks the exact staged file
list, candidate/run identity, regular-file type, size, hash, and report format
against the bounded runtime-validated CI and delivery records. The final gate
checks that stage again. Only the verified explicit file list is uploaded as a
normal Actions artifact (30-day retention). To check downloads, compare each
file's SHA-256 to `ci-record.json` and the staged hashes in `delivery.json`;
the tarball SHA-256 is separate from the Actions artifact archive digest.

An analysis exit `1` or safely reportable partial exit `2` still produces
diagnostic outputs, then fails the final gate. Missing/incomplete input
protection, internal/render/write failure, or failed verification yields a
fixed-code failure Summary; no prior report or invented clean report is used.
Summary transfer, stage verification, artifact upload, skipped/cancelled dependencies, and the
original analysis exit are checked independently. A partial save is not an
atomic transaction, and verified surviving files may be kept for diagnosis.
The final gate requires exit `0`, both verified outputs, Summary transfer,
artifact upload, and successful producer/acceptance jobs.

The save boundary assumes a trusted, exclusively managed POSIX local
workspace. It is not a guarantee against arbitrary same-privilege concurrent
renames or filesystem power loss. This dev workflow does not upload to Code
Scanning, post PR comments, publish, release, deploy, or define a stable
Source-aware JSON/public API. Human review of whether the Summary can be
understood in five minutes and evaluation on a real repository remain open
under [#611](https://github.com/albert-einshutoin/cdn-security-framework/issues/611).
