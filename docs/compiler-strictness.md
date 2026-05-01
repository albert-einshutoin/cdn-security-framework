# Compiler Strictness

> **Languages:** English · [日本語](./compiler-strictness.ja.md)

The compiler now has a dedicated strict TypeScript gate for parser, validator,
emitter, and target compile entry points:

```sh
npm run typecheck:compiler-strict
```

This gate is part of `npm run test:all`.

## Typed boundaries

- `parser` returns `Partial<CDNSecurityFrameworkPolicy> | null` from the
  schema-derived policy type.
- `validator` accepts the same policy draft shape and returns an explicit
  `ValidatePolicyResult`.
- `emitter` returns `CompileArtifactsResult`, with typed diagnostics and
  artifact lists.

## Remaining dynamic areas

Some dynamic typing remains intentionally:

- YAML parsing starts as untrusted data. The parser narrows it to a policy draft,
  and the validator owns schema enforcement.
- `origin.auth` is schema-extensible today, so the validator reads selected
  string fields with a narrow helper instead of asserting a closed object shape.
- The emitter still calls target scripts through `spawnSync` to preserve CLI and
  output compatibility while the compiler phase split stabilizes.

These areas should shrink as the policy schema becomes more discriminated and
target emitters move further in-process.
