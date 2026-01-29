# Scripts

Helper scripts for the CDN Security Framework. No external dependencies required for policy lint or runtime tests (Node.js only).

---

## Scripts

| Script | Purpose |
|--------|---------|
| `policy-lint.js` | Validates policy YAML structure (required keys, version). Run on `policy/base.yml` or any profile before deploying. |
| `runtime-tests.js` | Runs request→expected-status tests against the CloudFront Functions viewer-request handler. |

---

## Usage

### Policy lint

```bash
node scripts/policy-lint.js policy/base.yml
node scripts/policy-lint.js policy/profiles/balanced.yml
```

Exit code 0: valid. Non-zero: validation errors.

### Runtime tests

```bash
node scripts/runtime-tests.js
```

Runs test cases (method block, path traversal, UA block, admin gate, query limits). Exit code 0: all passed.

---

## CI

GitHub Actions workflow `.github/workflows/policy-lint.yml` runs policy lint on all policy files and runtime tests on push/PR to `main` when `policy/`, `scripts/`, or the viewer-request runtime change.

---

## Related

* [Policy and runtime sync](../docs/policy-runtime-sync.md)
* [Policy profiles](../policy/README.md)
