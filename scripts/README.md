# Scripts

Helper scripts for the CDN Security Framework.

---

## Scripts

| Script | Purpose |
|--------|---------|
| `policy-lint.js` | Validates policy YAML structure (required keys, version, auth-gate constraints). |
| `compile.js` | Builds AWS edge artifacts (`dist/edge/viewer-request.js`, `viewer-response.js`, `origin-request.js`). |
| `compile-cloudflare.js` | Builds Cloudflare Worker artifact (`dist/edge/cloudflare/index.ts`). |
| `compile-infra.js` | Builds infra Terraform JSON artifacts (`dist/infra/*.tf.json`). |
| `runtime-tests.js` | Runtime behavior tests for AWS viewer/origin templates. |
| `cloudflare-runtime-tests.js` | Cloudflare compile/template behavior tests (JWT/Signed URL/origin-auth paths). |
| `compile-unit-tests.js` | Unit tests for compiler core logic. |
| `infra-unit-tests.js` | Unit tests for infra compiler outputs (including JA3/JA4 rules). |
| `check-drift.js` | Drift check: compares generated artifacts with committed golden fixtures. |
| `fingerprint-candidates.js` | Extracts JA3/JA4 candidates from WAF JSONL logs for staged rollout. |
| `benchmark-compiler.js` | Measures baseline compiler runtime and optional package-install timings. |
| `security-baseline-check.js` | Verifies OWASP baseline references and mandatory CI guardrails. |

---

## Usage

### Build

```bash
node scripts/compile.js
node scripts/compile-cloudflare.js
node scripts/compile-infra.js
node scripts/compile-infra.js --rule-group-only
```

### Lint

```bash
node scripts/policy-lint.js policy/base.yml
node scripts/policy-lint.js policy/profiles/balanced.yml
```

### Tests

```bash
npm run test:ci

# Focused checks
npm run test:runtime
npm run test:unit
npm run test:drift
npm run test:security-baseline
```

### Fingerprint candidate extraction

```bash
npm run fingerprints:candidates -- --input waf-logs.jsonl --min-count 20 --top 50
```

### Compiler benchmarking

```bash
npm run benchmark:compiler -- --iterations 8 --warmup 1 --policy policy/base.yml
npm run benchmark:compiler -- --measure-install --iterations 5 --policy policy/base.yml
```

---

## CI

GitHub Actions workflow `.github/workflows/policy-lint.yml` runs the default quality gate on push/PR to `main` when `policy/`, `scripts/`, `templates/`, `bin/`, `tests/`, `docs/`, or top-level guidance docs (`README*`, `CONTRIBUTING*`) change:

1. policy lint (base + all profiles)
2. build (AWS + Cloudflare)
3. generated artifact existence checks
4. runtime tests (`npm run test:runtime`)
5. unit tests (`npm run test:unit`)
6. drift check (`npm run test:drift`)
7. security baseline check (`npm run test:security-baseline`)
8. coverage (`npm run test:coverage`)
9. package smoke (`npm run test:package`)

Use `npm run test:ci` for the local single-Node equivalent. The GitHub workflow
also runs package smoke on the Node-version matrix.

---

## Related

- [Policy and runtime sync](../docs/policy-runtime-sync.md)
- [Policy profiles](../policy/README.md)
