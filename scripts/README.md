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
| `infra-unit-tests.js` | Unit tests for infra compiler outputs (including JA3 rules). |
| `check-drift.js` | Drift check: compares generated artifacts with committed golden fixtures. |

---

## Usage

### Build

```bash
node scripts/compile.js
node scripts/compile-cloudflare.js
node scripts/compile-infra.js
```

### Lint

```bash
node scripts/policy-lint.js policy/base.yml
node scripts/policy-lint.js policy/profiles/balanced.yml
```

### Tests

```bash
npm run test:runtime
npm run test:unit
npm run test:drift
```

---

## CI

GitHub Actions workflow `.github/workflows/policy-lint.yml` runs the default quality gate on push/PR to `main` when `policy/`, `scripts/`, `templates/`, or `bin/` change:

1. policy lint (base + all profiles)
2. build (AWS + Cloudflare)
3. generated artifact existence checks
4. runtime tests (`npm run test:runtime`)
5. unit tests (`npm run test:unit`)
6. drift check (`npm run test:drift`)

---

## Related

- [Policy and runtime sync](../docs/policy-runtime-sync.md)
- [Policy profiles](../policy/README.md)
