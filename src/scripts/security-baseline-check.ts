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

  // Cloudflare WAF parity docs must exist and reference the fail flag, so the
  // dual-target transparency promise is not silently deleted. The drift test
  // (scripts/check-drift.js) separately enforces that the body matches the
  // generator output.
  const parityFiles = [
    { file: 'docs/cloudflare-waf-parity.md', heading: '# Cloudflare WAF parity' },
    { file: 'docs/cloudflare-waf-parity.ja.md', heading: '# Cloudflare WAF パリティ' },
  ];
  for (const p of parityFiles) {
    if (!fs.existsSync(path.join(repoRoot, p.file))) {
      fail(`${p.file} is missing — parity transparency (issue #68) requires this file to exist`);
    }
    ensureIncludes(p.file, p.heading, 'parity doc heading');
    ensureIncludes(p.file, '--fail-on-waf-approximation', 'reference to the CI gate flag');
  }

  console.log('Security baseline check passed.');
}

main();
