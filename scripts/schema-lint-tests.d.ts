#!/usr/bin/env node
/**
 * Schema lint tests: exercise `policy-lint.js` against temporary policy files
 * with numeric values that are inside/outside the bounds declared in
 * policy/schema.json. Fails if the lint gate accepts an out-of-range value or
 * rejects an in-range value.
 */
export {};
