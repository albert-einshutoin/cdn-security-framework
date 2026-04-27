const assert = require('assert');
const fs = require('fs');
const path = require('path');

const repoRoot = path.join(__dirname, '..');
const api = require(path.join(repoRoot, 'lib'));

function test(name, fn) {
  try {
    fn();
    console.log(`OK: ${name}`);
  } catch (err: any) {
    console.error(`FAIL: ${name}`);
    console.error(err);
    process.exitCode = 1;
  }
}

test('api exports stable callable surface', () => {
  assert.strictEqual(typeof api.compile, 'function');
  assert.strictEqual(typeof api.emitWaf, 'function');
  assert.strictEqual(typeof api.lintPolicy, 'function');
  assert.strictEqual(typeof api.migratePolicy, 'function');
  assert.strictEqual(typeof api.runDoctor, 'function');
});

test('api compile missing policyPath returns structured error', () => {
  const result = api.compile({ outDir: 'dist', cwd: repoRoot, pkgRoot: repoRoot });
  assert.strictEqual(result.ok, false);
  assert.ok(Array.isArray(result.errors));
  assert.ok(Array.isArray(result.warnings));
  assert.ok(result.errors.includes('policyPath is required'));
});

test('api lintPolicy missing policyPath returns structured error', () => {
  const result = api.lintPolicy({ cwd: repoRoot, pkgRoot: repoRoot });
  assert.strictEqual(result.ok, false);
  assert.ok(Array.isArray(result.errors));
  assert.ok(Array.isArray(result.warnings));
});

test('cli entrypoint exists and keeps shebang', () => {
  const cliPath = path.join(repoRoot, 'bin', 'cli.js');
  const firstLine = fs.readFileSync(cliPath, 'utf8').split('\n')[0];
  assert.strictEqual(firstLine, '#!/usr/bin/env node');
});
