#!/usr/bin/env node
/**
 * Policy lint: validates policy YAML against policy/schema.json using ajv,
 * then runs compile-core's auth-gate validator for cross-field checks that
 * JSON Schema cannot express.
 * Usage: node scripts/policy-lint.js [path/to/policy.yml]
 * Default: policy/base.yml
 */
export {};
