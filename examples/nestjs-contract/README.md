# NestJS static contract example

This fixture demonstrates source-only NestJS route/auth metadata extraction and
OpenAPI/Policy drift findings. It never starts NestJS or executes decorators.

From a clean checkout:

```bash
npm ci
npm run build:ts
node examples/nestjs-contract/run-analysis.cjs
```

The script copies the fixture to an isolated temporary workspace, installs only
the checked-in type stub there, then prints a deterministic summary without
mutating the input project. Intentional cases include aliases, path aliases,
inheritance, duplicate routes, an unknown Guard, a dynamic path, an unloaded
project reference, and runtime prefix/versioning calls. See
`docs/source-analysis-nestjs.md` for support and security boundaries.
