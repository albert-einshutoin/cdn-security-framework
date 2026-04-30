# Template Injection Contract

> **Languages:** English · [日本語](./template-injection-contract.ja.md)

`cdn-security` keeps edge runtime output auditable: operators can inspect the generated `dist/edge/*.js` or `dist/edge/cloudflare/index.ts` without reading bundled/minified code.

For that reason, runtime templates intentionally keep explicit marker comments instead of switching to AST or bundler-based config embedding.

## Contract

Each runtime template must contain exactly one marker for each injected config block:

| Template | Required marker | Injected const |
| --- | --- | --- |
| `templates/aws/viewer-request.js` | `// {{INJECT_CONFIG}}` | `const CFG = ...` |
| `templates/aws/viewer-response.js` | `// {{INJECT_RESPONSE_CONFIG}}` | `const RESPONSE_CFG = ...` |
| `templates/aws/origin-request.js` | `// {{INJECT_CONFIG}}` | `const CFG = ...` |
| `templates/cloudflare/index.ts` | `// {{INJECT_CONFIG}}` | `const CFG = ...` |
| `templates/cloudflare/index.ts` | `// {{INJECT_RESPONSE_CFG}}` | `const RESPONSE_CFG = ...` |

The compiler fails if a marker is missing or appears more than once.

## Post-Injection Check

After replacement, the compiler parses the generated output and verifies that each injected config exists as exactly one top-level `const` declaration. Cloudflare Worker output is first transformed from TypeScript to JavaScript for parse-only inspection; the deployed artifact remains the generated TypeScript file.

This catches malformed injection without changing the deployment model.

## Why Not Bundler Embedding

Bundler or AST-level config embedding is not rejected forever, but it is not the default because it weakens important properties:

- auditability: generated files stay close to the source templates
- diff clarity: policy changes produce readable config diffs
- deploy-size control: CloudFront Functions keep tight size limits
- dependency restraint: runtime code generation does not require a bundling step

Revisit this only if marker-based injection causes concrete bugs that the current validation cannot catch.
