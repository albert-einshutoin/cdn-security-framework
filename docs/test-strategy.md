# Test Strategy

> **Languages:** English · [日本語](./test-strategy.ja.md)

The project keeps security-critical smoke and integration tests as standalone
Node scripts, while introducing Vitest for focused compiler contract tests.

## Runner choice

- Vitest is the default migration target for focused unit and contract tests.
  It supports TypeScript test files, watch mode, name filtering, and structured
  CI reporting without forcing the runtime smoke tests into a browser-like
  model.
- Jest was considered, but it adds more transformation and CommonJS/ESM
  surface area for this repository.
- The existing script harness remains useful for package smoke tests, drift
  checks, ReDoS fuzzing, and edge-container attack tests where process-level
  behavior matters.

## Local workflow

- Run focused Vitest checks with `npm run test:vitest`.
- Run legacy unit coverage with `npm run test:unit`.
- Run the full release gate with `npm run test:all`.

Vitest writes JUnit output to `reports/vitest-junit.xml` when `CI=true`.

## Migration policy

Move tests into Vitest when they benefit from focused runs, watch mode, or
clear assertion structure. Keep tests as standalone scripts when they verify
CLI process behavior, package installation, generated artifact drift, fuzzing,
or container-style attack flows.
