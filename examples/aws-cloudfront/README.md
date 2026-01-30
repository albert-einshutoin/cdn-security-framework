# Example: AWS CloudFront (E2E)

This example uses **cdn-security-framework** as a dev dependency: init → edit policy → build → deploy the generated **`dist/edge/`** code to CloudFront Functions.

---

## Prerequisites

- Node.js 18+
- AWS account with CloudFront and CloudFront Functions available
- Origin (S3 bucket or custom origin) already set up

---

## Steps

### 1. Install and init

From this directory (`examples/aws-cloudfront/`):

```bash
npm install
npm run init
```

This installs the framework from the repo root (`file:../..`) and creates `policy/security.yml` and `policy/profiles/balanced.yml`. To use the published package instead, replace the devDependency with `"cdn-security-framework": "^1.0.0"` and run `npm install` from a project that has the package on npm.

### 2. Edit policy (optional)

Edit `policy/security.yml` to adjust allowed methods, block rules, routes, etc.

### 3. Build

```bash
npm run build
```

This runs `npx cdn-security build`: validates the policy and generates **`dist/edge/viewer-request.js`** (and other Edge code when implemented). Deploy **this generated file**, not the framework’s `runtimes/` sources.

### 4. Admin token

Set `EDGE_ADMIN_TOKEN` in your environment or secrets; the build injects it at compile time when the variable is set. No manual edit of the generated JS.

### 5. Create CloudFront Functions and associate

1. CloudFront → Functions → Create function.
2. **Viewer Request**: create a function and paste the contents of **`dist/edge/viewer-request.js`**, then publish.
3. (When generated) **Viewer Response**: same for `dist/edge/viewer-response.js`.
4. Open your distribution → Behaviors → Edit the behavior → **Viewer request**: Function type = CloudFront Functions, select the Viewer Request function. **Viewer response** similarly if used. Save and wait for deployment.

### 6. Verify

```bash
# Without token: 401
curl -i https://YOUR_DISTRIBUTION_DOMAIN/admin

# With token: allowed
curl -i -H "x-edge-token: YOUR_TOKEN" https://YOUR_DISTRIBUTION_DOMAIN/admin

# Traversal / bad UA / too many query params: blocked
curl -i "https://YOUR_DISTRIBUTION_DOMAIN/foo/../bar"
```

---

## Summary

| Step   | Command / action |
|--------|-------------------|
| Install | `npm install` (uses `cdn-security-framework` from repo or npm) |
| Init    | `npm run init` → creates `policy/security.yml` |
| Build   | `npm run build` → generates `dist/edge/viewer-request.js` |
| Deploy  | Use `dist/edge/*.js` in CloudFront Functions (console, Terraform, or CDK) |

---

## See also

- [CloudFront Functions Runtime](../../runtimes/aws-cloudfront-functions/README.md)
- [Quick Start](../../docs/quickstart.md)
- [Policy and runtime sync](../../docs/policy-runtime-sync.md)
