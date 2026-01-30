# E2E Examples

These examples use **cdn-security-framework** as a dev dependency: init → edit policy → build → deploy the generated **`dist/edge/`** code.

| Example | Platform | Flow |
|---------|----------|------|
| [aws-cloudfront/](aws-cloudfront/) | AWS CloudFront Functions | `npm install` → `npm run init` → `npm run build` → deploy `dist/edge/viewer-request.js` and `viewer-response.js` |
| [cloudflare/](cloudflare/) | Cloudflare Workers | `npm install` → `npm run init` → `npm run build` → deploy `dist/edge/cloudflare/index.ts` |

Run the AWS example from `examples/aws-cloudfront/`; it installs the framework from the repo root (`file:../..`). For a published package, use `"cdn-security-framework": "^1.0.0"` in `package.json` and `npm install` from your project.
