# GitHub Actions contract diff

Copy [`examples/github-actions/contract-diff.yml`](../examples/github-actions/contract-diff.yml) to `.github/workflows/contract-diff.yml`, then replace the example `--openapi` and `--policy` paths with repository-owned files. Keep `cdn-security-framework` in `package.json` and use `npm ci`; the example uses `npx --no-install` so CI never downloads an unreviewed package version.

The workflow is safe for fork pull requests: it uses `pull_request`, reads no secrets, has only `contents: read`, does not post comments, cancels obsolete runs, and pins actions to commits. It writes a bounded summary to `$GITHUB_STEP_SUMMARY` and uploads `contract-diff.json`, `cdn-security.sarif`, and `github-summary.md`. The summary excludes messages, evidence, query strings, and request bodies.

## Gate and required check

The `contract-diff` job runs with `--fail-on error`. Configure that job as a required check in the `main` branch ruleset after validating the paths on a pull request.

- Exit `0`: no finding crossed the threshold.
- Exit `1`: findings crossed the threshold; inspect the summary and artifacts.
- Exit `2`: invalid input, configuration, or output path.
- Exit `3`: unexpected tool failure.

The workflow preserves these classes in its final gate instead of treating a tool failure as a security finding.

## Optional SARIF upload

Artifact-only upload is the default and needs no write permission. If code scanning is enabled, add `security-events: write` and this step after artifact upload:

```yaml
permissions:
  contents: read
  security-events: write

- name: Upload SARIF to code scanning
  if: always() && github.event.pull_request.head.repo.full_name == github.repository
  uses: github/codeql-action/upload-sarif@42947a340483f03ba47bb1a039b2c519aab3df85 # v3
  with:
    sarif_file: reports/cdn-security.sarif
```

Keep fork pull requests artifact-only. Do not switch to `pull_request_target` or expose secrets to untrusted code.

## Exceptions

Pass a repository-owned exception file with `--exceptions`, the target scope with `--environment`, and a deterministic date with `--current-date YYYY-MM-DD`. Expired exceptions appear as `SC-GOV-001` and fail the error gate. Review owners, selectors, reasons, and expiry dates; do not create broad or permanent exceptions. See [finding exceptions](finding-exceptions.md).

## Troubleshooting

- Missing report: verify all input paths are inside `--workspace-root` and the `reports/` parent exists.
- Exit `1`: download JSON/SARIF, fix the contract or policy, or use a reviewed temporary exception.
- Exit `2`: check YAML, required arguments, target, workspace boundary, and existing output files.
- Exit `3`: rerun once with the same lockfile and report the sanitized logs and artifacts.
- SARIF upload denied: keep artifact-only mode, or grant `security-events: write` only to the trusted upload job.

Use `--force` only when a previous report exists in the same job workspace. Never print raw secrets, query values, headers, or request bodies while troubleshooting.
