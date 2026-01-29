#!/usr/bin/env node
/**
 * Policy lint: validates policy YAML structure (required keys, types).
 * Usage: node scripts/policy-lint.js [path/to/policy.yml]
 * Default: policy/base.yml
 * No external dependencies; uses simple line-based checks.
 */

const fs = require('fs');
const path = require('path');

const policyPath = process.argv[2] || path.join(__dirname, '..', 'policy', 'base.yml');
let content;
try {
  content = fs.readFileSync(policyPath, 'utf8');
} catch (e) {
  if (e.code === 'ENOENT') {
    console.error('Error: policy file not found:', policyPath);
    process.exit(1);
  }
  throw e;
}

const lines = content.split(/\r?\n/);
const errors = [];

// Required top-level keys (must appear in the file)
const requiredTop = ['version', 'request', 'response_headers'];
for (const key of requiredTop) {
  if (!content.match(new RegExp('^' + key + '\\s*:', 'm'))) {
    errors.push('Missing required top-level key: ' + key);
  }
}

// version should be 1
const versionMatch = content.match(/^version\s*:\s*(.+)/m);
if (versionMatch) {
  const v = versionMatch[1].trim();
  if (v !== '1' && v !== '1.0') {
    errors.push('Unsupported policy version: ' + v + ' (expected 1)');
  }
} else if (!errors.some(e => e.includes('version'))) {
  errors.push('Could not parse version');
}

// request.allow_methods or request: must exist
if (!content.includes('request:') && !errors.some(e => e.includes('request'))) {
  errors.push('Missing request section');
}
if (content.includes('request:') && !content.match(/allow_methods\s*:/m) && !content.match(/^\s+allow_methods\s*:/m)) {
  errors.push('request section should contain allow_methods');
}

// response_headers: at least one header
if (content.includes('response_headers:') && !content.match(/response_headers:[\s\S]*?^\s+\w+:/m) && !content.match(/hsts\s*:/m)) {
  errors.push('response_headers section should define at least one header (e.g. hsts)');
}

// routes: if present, each route should have match and auth_gate or match only
// (optional check) path_patterns if block.path_patterns - should be array-like
const blockPathMatch = content.match(/path_patterns\s*:/);
if (blockPathMatch && !content.includes('- "') && !content.includes("- '") && !content.match(/path_patterns\s*:\s*\[\s*\]/)) {
  // might be empty array; allow
  const after = content.indexOf('path_patterns');
  const snippet = content.slice(after, after + 200);
  if (!snippet.includes('- ') && !snippet.includes('[]')) {
    errors.push('request.block.path_patterns should be a list (use - "pattern" lines)');
  }
}

if (errors.length > 0) {
  console.error('Policy lint failed:', policyPath);
  errors.forEach(e => console.error('  -', e));
  process.exit(1);
}

console.log('Policy lint OK:', policyPath);
process.exit(0);
