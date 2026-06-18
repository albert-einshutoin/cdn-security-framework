# Scripts

Helper scripts for the CDN Security Framework.

All files in this directory are generated from `src/scripts/*.ts` and committed outputs.
Edit only under `src/scripts/` and regenerate with `npm run build:ts`.

---

## Scripts

| Script | Purpose |
|--------|---------|
| `policy-lint.js` | Validates policy YAML structure (required keys, version, auth-gate constraints). |
| `compile.js` | Builds AWS edge artifacts (`dist/edge/viewer-request.js`, `viewer-response.js`, `origin-request.js`). |
| `compile-cloudflare.js` | Builds Cloudflare Worker artifact (`dist/edge/cloudflare/index.ts`). |
| `compile-cloudflare-waf.js` | Builds Cloudflare Worker artifact for WAF parity checks. |
| `compile-infra.js` | Builds infra Terraform JSON artifacts (`dist/infra/*.tf.json`). |
| `runtime-tests.js` | Runtime behavior tests for AWS viewer/origin templates. |
| `cloudflare-runtime-tests.js` | Cloudflare compile/template behavior tests (JWT/signed URL/origin-auth flows). |
| `api-contract-tests.js` | Contract/API compatibility validation used by package smoke CI. |
| `compile-unit-tests.js` | Unit tests for compiler core logic. |
| `infra-unit-tests.js` | Unit tests for infra compiler outputs (including JA3/JA4 rules). |
| `policy-io-unit-tests.js` | Unit tests for policy IO helpers. |
| `check-drift.js` | Drift check: compares generated artifacts with committed golden fixtures. |
| `security-baseline-check.js` | Verifies OWASP baseline references and mandatory CI guardrails. |
| `fingerprint-candidates.js` | Extracts JA3/JA4 candidates from WAF JSONL logs for rollout. |
| `package-smoke-tests.js` | Packs and installs the package for smoke verification. |
| `benchmark-compiler.js` | Measures baseline compiler runtime and optional package-install timings. |
| `fingerprint-candidates-unit-tests.js` | Unit tests for fingerprint candidate extraction helpers. |
| `schema-lint-tests.js` | Schema-level lint coverage for policy and template metadata. |

## Usage

### Build

```bash
npm run build:ts
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
npm run test:package
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

GitHub Actions workflow `.github/workflows/policy-lint.yml` runs the default quality gate on push/PR to `main` and `develop`:

1. policy lint (base + all profiles)
2. build (AWS + Cloudflare)
3. generated artifact existence checks (`npm run test:dist-exists`)
4. runtime tests (`npm run test:runtime`)
5. unit tests (`npm run test:unit`)
6. drift check (`npm run test:drift`)
7. security baseline check (`npm run test:security-baseline`)
8. coverage (`npm run test:coverage`)
9. package smoke (`npm run test:package`)

`npm run test:ci` is the local single-Node equivalent. The workflow also runs package smoke on the Node matrix (`20.17.0`, `22`, `24`).

---

## Related

- [Policy and runtime sync](../docs/policy-runtime-sync.md)
- [Policy profiles](../policy/README.md)
