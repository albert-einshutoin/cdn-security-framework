# Selective CI testing

The Pull Request workflow uses conservative change-impact analysis to shorten feedback time without treating fewer tests as the goal. Static checks, policy linting, type checking, compilation, build validation, and focused smoke tests always run. Related unit, integration, and end-to-end targets are added only when the analyzer can justify them.

If the analyzer cannot prove that its selection is complete, it runs the full `npm run test:ci` gate. A planning error never becomes a successful CI run with no tests.

## CI lanes

- **Pull Requests:** baseline checks, always-on smoke tests, and selected related tests.
- **Shadow comparison:** for at least the first 14 days, every Pull Request also runs the full gate as a required job.
- **`main` and `release/**`:** full quality gate and the Node 20.17/22/24 package matrix.
- **Scheduled CI:** the full gate runs daily at 02:17 UTC.
- **Release:** `.github/workflows/release-npm.yml` runs the full gate before publishing.
- **Manual:** dispatching `policy-lint.yml` runs full validation.

The shadow lane is not removed automatically after 14 days. Graduation requires a reviewed change after comparison reports show no failures detected only by the full lane.

## How impact is determined

`npm run impact:analyze` performs these steps in order:

1. Resolve the latest target ref and the current head.
2. Find their Git merge base.
3. Read NUL-delimited add, modify, delete, rename, and copy records.
4. Apply centralized high-risk rules.
5. Detect projects from manifests.
6. Map changed files to modules and traverse reverse module dependencies.
7. Traverse reverse source imports to find related tests.
8. Apply explicit integration and E2E mappings.
9. Add always-on smoke targets.
10. Validate that every important change is classified and every target is executable.

The machine-readable result is written to `reports/impact/analysis.json`. Execution metrics are written to `reports/impact/execution.json` and `history.ndjson`.

## Supported adapters

| Adapter | Detection | Dependency analysis | Related test selection |
| --- | --- | --- | --- |
| JavaScript / TypeScript | `package.json` | static import, export, `require`, literal dynamic import | custom TypeScript test entrypoints and Vitest files |
| Python | `pyproject.toml`, `requirements.txt`, `Pipfile` | Python standard-library AST import graph | discovers related Python tests; an explicit project test command is required before selective execution |
| Default | known unsupported or unknown manifest | none | full validation only |

The repository itself contains a root JavaScript/TypeScript project and example packages. A source file extension alone does not create a project; a manifest or explicit project configuration is required.

## Full-test fallback

Full validation is selected for dependency and lock changes, build/test/CI/container configuration, public API and schema changes, shared compiler/security/authentication/routing code, the impact analyzer itself, deleted source, unresolved imports, incomplete graphs, unsupported affected projects, unclassified important files, or a non-documentation source change with no related tests.

It also falls back when the base revision, merge base, changed-file list, configuration, adapter, or output validation fails. If the full command itself cannot be resolved, the analyzer reports `failure` and CI exits non-zero.

Rules live in:

- `ci/impact/config/risk-rules.json`
- `ci/impact/config/module-mappings.json`
- `ci/impact/config/test-mappings.json`
- `ci/impact/config/smoke-tests.json`
- `ci/impact/config/project-settings.json`

Do not duplicate these rules in workflow YAML.

## Run locally

Use fixture-only credentials, never production values:

```bash
export EDGE_ADMIN_TOKEN=ci-build-token-not-for-deploy
export ORIGIN_SECRET=ci-origin-secret-not-for-deploy
npm ci
npm run impact:analyze -- \
  --base origin/main \
  --head HEAD \
  --output reports/impact/analysis.json
npm run impact:run -- \
  --analysis reports/impact/analysis.json \
  --output reports/impact/execution.json
```

To bypass selection and reproduce the complete gate:

```bash
npm run test:ci
```

The analyzer can also emit a forced full plan:

```bash
npm run impact:analyze -- \
  --base origin/main \
  --head HEAD \
  --force-full "manual verification"
```

## Reading CI logs

The analyzer logs the base and head revisions, detected adapters and projects, every changed file and status, affected projects and modules, selected test categories, selected/available target counts, strategy, and fallback reason.

The runner logs each target, success/failure/skip counts, wall-clock duration, summed target compute time, and optional cost. Set `CI_COST_PER_MINUTE` to include an estimated runner cost in the execution report.

During shadow mode, `impact-comparison-report` contains selection rate, wall-clock and compute reduction rates, fallback information, and `fullOnlyFailure`. A `true` full-only failure blocks graduation and requires a mapping or risk-rule fix.

## Fixing a wrong selection

- Missing reverse dependency: correct the relevant adapter graph logic.
- Source-to-test relationship not expressible as an import: add a narrow entry to `test-mappings.json`.
- Broad or dynamic shared behavior: add a reasoned rule to `risk-rules.json`.
- Incorrect layer propagation: update `module-mappings.json` dependencies.
- New mandatory smoke behavior: add an allowlisted command to `smoke-tests.json` and its ID to `project-settings.json`.

Changes to the analyzer or its configuration intentionally trigger full validation.

## Adding an adapter

1. Add manifest detection to `project-settings.json`.
2. Implement the adapter behind the `detect`, graph, test-selection, validation-command, cache-metadata, and risk-rule contract.
3. Exchange structured data with the core; do not interpolate shell command strings.
4. Add fixtures covering multiple projects, reverse dependencies, deletion, unresolved dependencies, and adapter failure.
5. Add explicit full-validation commands before enabling selective execution.
6. Document supported manifests and fallback behavior here and in the Japanese counterpart.

An adapter error or incomplete result must request full validation.

## Cache maintenance

GitHub Actions caches npm downloads by OS, Node version, and `package-lock.json`. Local generated output is disposable:

```bash
rm -f .tsbuildinfo
npm cache verify
npm ci
```

Delete the workflow cache from the repository Actions cache settings when diagnosing a corrupted remote cache. Cache misses or restore failures must lead to normal execution, not a successful skipped test.

## History and cost controls

Reports retain the commit pair, strategy, changed files, targets, outcome, and timing as CI artifacts for 30 days. The in-run NDJSON format can later feed flaky-test, failure-correlation, duration-ordering, coverage, and risk-score analysis without changing the analyzer contract.

Selective targets run on one runner with at most two child processes. Resource locks serialize targets sharing generated output, packages, or containers. The Node compatibility matrix also uses `max-parallel: 2` to avoid trading latency for uncontrolled runner cost.
