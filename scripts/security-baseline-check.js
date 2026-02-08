#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const repoRoot = path.join(__dirname, '..');

function read(file) {
  return fs.readFileSync(path.join(repoRoot, file), 'utf8');
}

function fail(msg) {
  console.error('Baseline check failed:', msg);
  process.exit(1);
}

function ensureIncludes(file, pattern, desc) {
  const content = read(file);
  if (!content.includes(pattern)) {
    fail(`${file} is missing ${desc} (${pattern})`);
  }
}

function main() {
  // OWASP references should be documented.
  ensureIncludes('docs/threat-model.md', 'OWASP Top 10:2025', 'OWASP Top 10:2025 mapping');
  ensureIncludes('docs/threat-model.md', 'OWASP API Security Top 10 (2023)', 'OWASP API Top 10 mapping');
  ensureIncludes('docs/threat-model.ja.md', 'OWASP Top 10:2025', 'OWASP Top 10:2025 mapping');
  ensureIncludes('docs/threat-model.ja.md', 'OWASP API Security Top 10 (2023)', 'OWASP API Top 10 mapping');

  // CI quality gate should include runtime/unit/drift.
  const workflow = read('.github/workflows/policy-lint.yml');
  if (!workflow.includes('npm run test:runtime') || !workflow.includes('npm run test:unit') || !workflow.includes('npm run test:drift')) {
    fail('.github/workflows/policy-lint.yml must run runtime/unit/drift checks');
  }

  // Schema should include fingerprint controls.
  const schema = read('policy/schema.json');
  if (!schema.includes('ja3_fingerprints') || !schema.includes('ja4_fingerprints')) {
    fail('policy/schema.json must include ja3_fingerprints and ja4_fingerprints');
  }

  console.log('Security baseline check passed.');
}

main();
