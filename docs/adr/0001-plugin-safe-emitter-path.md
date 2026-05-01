# ADR 0001: Plugin-Safe Emitter Path

> **Status:** Proposed for v1.3.x

## Context

The current runtime compiler injects policy-derived config into auditable edge
templates with explicit marker comments such as `// {{INJECT_CONFIG}}`. The
compiler validates marker cardinality and parses generated output after
injection. That contract is stable and should remain the default for v1.3.0.

The next architecture question is how to support future plugin-provided runtime
logic, for example custom auth gates, without turning generated edge code into
unreviewable string concatenation.

## Options

### Keep the marker contract

Pros:

- Generated files remain close to source templates and easy to diff.
- CloudFront Function size and syntax constraints stay visible.
- No bundling step is required for the current CLI path.

Cons:

- It is a poor foundation for merging user-provided runtime modules.
- Config is injected as rendered source text, even with parse validation.
- It cannot perform module graph checks for plugin code.

### Use esbuild virtual modules

Pros:

- Policy config can be exposed as a generated virtual module.
- Plugin/runtime code can import typed bindings rather than relying on global
  marker replacement.
- The bundle step catches syntax and module graph failures before deployment.

Cons:

- Output shape can change, including `const` becoming `var` after bundling.
- Bundled code may be harder to audit than current templates.
- CloudFront Function size and compatibility need target-specific checks.

### Use Babel/SWC AST transforms

Pros:

- Can preserve more of the template output shape.
- Allows precise insertion of top-level declarations.

Cons:

- Adds AST manipulation complexity.
- Still needs separate module graph handling if plugins import dependencies.

## Decision

Keep marker-based injection as the production default for v1.3.0.

Add an isolated esbuild virtual-module prototype to validate a future
plugin-safe path. The prototype must not change CLI output. It exists to test
these invariants:

- generated output parses
- config bindings appear exactly once at top level
- template/plugin source cannot shadow config bindings
- failures are surfaced before runtime deployment

## Threat Model

The prototype specifically addresses:

- malformed generated edge runtime syntax
- duplicate generated config declarations
- plugin or template code shadowing generated config bindings
- accidental module graph failures before deployment

It does not yet address:

- malicious plugin package supply-chain risk
- semantic safety of arbitrary user code
- runtime resource exhaustion caused by plugin logic
- final CloudFront Function bundle-size enforcement

Those require a separate plugin permission and packaging model.

## Migration Path

1. Keep the current template injection contract.
2. Maintain the isolated bundler prototype and tests.
3. If custom runtime plugins become a product requirement, promote the
   prototype into a target-gated experimental emitter.
4. Only replace marker injection for a target after output compatibility,
   auditability, size, and deployment behavior are proven.
