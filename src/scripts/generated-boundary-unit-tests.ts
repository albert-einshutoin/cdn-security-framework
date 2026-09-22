#!/usr/bin/env node

import assert = require('node:assert/strict');
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { inspectGeneratedBoundary, type OwnershipGroup, type OwnershipManifest } from './check-generated-boundary';

function test(name: string, fn: () => void): void {
  try { fn(); console.log('OK:', name); }
  catch (error: unknown) { console.error('FAIL:', name); console.error(error); process.exitCode = 1; }
}
function group(file: string): OwnershipGroup {
  return { category: 'runtime-template', files: [file], sourceOfTruth: [file], reason: 'Authored fixture source.', removalCondition: 'Retire this fixture.' };
}
function manifest(groups: OwnershipGroup[] = []): OwnershipManifest {
  return { schemaVersion: 1, sourceRoot: 'src', outputRoot: '.', groups };
}
function scan(paths: string[], groups: OwnershipGroup[] = [], symlinks: string[] = []) {
  return inspectGeneratedBoundary(paths.map((file) => ({ path: file, mode: symlinks.includes(file) ? '120000' : '100644' })), manifest(groups));
}

test('generated package outputs and new directories are rejected', () => {
  const result = scan(['src/contract/index.ts', 'contract/index.js', 'contract/index.d.ts', 'contract/index.js.map',
    'src/future-module/index.ts', 'future-module/index.js', 'future-module/index.d.ts', 'future.js', 'future.d.ts']);
  assert.equal(result.violations.length, 7);
  assert.equal(result.violations.filter((entry) => entry.code === 'TRACKED_COMPILER_OUTPUT').length, 5);
});

test('authored and schema/golden exceptions require exact metadata', () => {
  const paths = ['tests/golden/base/edge/viewer-request.js', 'templates/aws/viewer-request.js',
    'runtimes/aws-cloudfront-functions/viewer-request.js', 'src/types/policy.d.ts', 'examples/nestjs-contract/run-analysis.cjs', 'scripts/README.md'];
  assert.deepEqual(scan(paths, paths.map(group)).violations, []);
  const owned = group('contract/index.js');
  assert.equal(scan(['src/contract/index.ts', 'contract/index.js'], [owned]).violations[0].code, 'TRACKED_COMPILER_OUTPUT');
});

test('authored directories do not admit unregistered artifacts', () => {
  assert.deepEqual(scan(['templates/aws/unregistered.js', 'tests/golden/base/edge/unregistered.js']).violations.map((v) => v.path),
    ['templates/aws/unregistered.js', 'tests/golden/base/edge/unregistered.js']);
  assert.equal(scan(['examples/nestjs-contract/run-analysis.cjs.generated.js']).violations.length, 1);
});

test('orphans, unknown directories, maps and non-JS build outputs fail closed', () => {
  const paths = ['docs/stale.js', '.github/generated.cjs', 'ci/output.d.ts', 'test/generated.js',
    'future-module/index.d.ts.map', 'lib/orphan.js', 'dist/result.json', 'scripts/output.json'];
  assert.equal(scan(paths).violations.length, paths.length);
});

test('stale ownership, missing provenance and missing reasons are rejected', () => {
  assert.ok(scan([], [group('templates/deleted.js')]).violations.some((v) => v.code === 'STALE_OWNERSHIP'));
  const owned = group('templates/a.js');
  owned.sourceOfTruth = ['src/deleted.ts'];
  assert.ok(scan(owned.files, [owned]).violations.some((v) => v.code === 'MISSING_SOURCE_OF_TRUTH'));
  for (const field of ['reason', 'removalCondition'] as const) {
    const entry = group('templates/a.js'); entry[field] = '';
    assert.ok(scan(entry.files, [entry]).violations.some((v) => v.code === 'MISSING_OWNERSHIP_METADATA'));
  }
  assert.ok(scan(['templates/a.js'], [group('templates/a.js'), group('templates/a.js')]).violations.some((v) => v.code === 'DUPLICATE_OWNERSHIP'));
});

test('symlink and case collisions cannot bypass exact ownership', () => {
  const file = 'templates/aws/viewer-request.js';
  assert.ok(scan([file], [group(file)], [file]).violations.some((v) => v.code === 'TRACKED_SYMLINK'));
  assert.ok(scan([file, file.toUpperCase()], [group(file)]).violations.some((v) => v.code === 'CASE_OR_DUPLICATE_PATH'));
});

test('unsafe path diagnostics do not reproduce absolute or control-bearing input', () => {
  for (const value of ['/private/developer-secret.js', '../escape.js', 'C:\\secret.js', 'bad\nname.js']) {
    const result = scan([value]);
    assert.equal(result.violations[0].path, '<invalid-path>');
    assert.equal(JSON.stringify(result).includes(value), false);
  }
});

test('real index inventory rejects a symlink without reading its target', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'generated-boundary-'));
  const scanner = path.join(__dirname, 'check-generated-boundary.js');
  try {
    fs.mkdirSync(path.join(root, 'config'));
    fs.mkdirSync(path.join(root, 'templates'));
    fs.writeFileSync(path.join(root, 'config/artifact-ownership.json'), JSON.stringify(manifest([group('templates/a.js')])));
    fs.writeFileSync(path.join(root, 'tsconfig.json'), JSON.stringify({ compilerOptions: { rootDir: 'src', outDir: '.' } }));
    // A dangling link is sufficient: attempting to read through it would fail.
    fs.symlinkSync(path.join(root, 'never-created-target'), path.join(root, 'templates/a.js'));
    execFileSync('git', ['init', '-q', root]);
    execFileSync('git', ['-C', root, 'add', '.']);
    const result = spawnSync(process.execPath, ['-e', `require(${JSON.stringify(scanner)}).main(${JSON.stringify(root)}, true)`], { encoding: 'utf8' });
    assert.equal(result.status, 1);
    const report = JSON.parse(result.stdout);
    assert.ok(report.violations.some((v: { code: string }) => v.code === 'TRACKED_SYMLINK'));
    assert.ok(!(result.stdout + result.stderr).includes(root));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('Git/config failures use fixed diagnostics', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'boundary-private-'));
  try {
    const result = spawnSync(process.execPath, ['-e', `require(${JSON.stringify(path.join(__dirname, 'check-generated-boundary.js'))}).main(${JSON.stringify(root)})`], { encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.ok(result.stderr.includes('INVENTORY_ERROR'));
    assert.ok(!(result.stdout + result.stderr).includes(root));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('only an exact adversarial fixture symlink may be retained without following it', () => {
  const file = 'test/fixtures/openapi/malicious/symlink-escape.yaml';
  const owned = { ...group(file), category: 'adversarial-symlink-fixture' };
  assert.deepEqual(scan([file], [owned], [file]).violations, []);
  assert.ok(scan([file], [owned]).violations.some((v) => v.code === 'INVALID_SYMLINK_FIXTURE'));
  const outside = { ...owned, files: ['templates/link.js'], sourceOfTruth: ['templates/link.js'] };
  assert.ok(scan(outside.files, [outside], outside.files).violations.some((v) => v.code === 'INVALID_SYMLINK_FIXTURE'));
  assert.ok(scan([file]).violations.length === 0);
  assert.ok(scan([file], [], [file]).violations.some((v) => v.code === 'TRACKED_SYMLINK'));
});

test('oversized inventories and ownership lists fail within explicit bounds', () => {
  assert.equal(scan(Array(20001).fill('a')).violations[0].code, 'INVENTORY_LIMIT');
  assert.equal(scan([], Array(2001).fill(group('a'))).violations[0].code, 'INVENTORY_LIMIT');
  const owned = group('templates/a.js'); owned.files = Array(2001).fill('templates/a.js');
  assert.ok(scan(['templates/a.js'], [owned]).violations.some((v) => v.code === 'MISSING_OWNERSHIP_METADATA'));
});

test('resolveJsonModule copies are rejected, including root-level JSON and owned aliases', () => {
  const paths = ['src/data.json', 'data.json', 'src/future/data.json', 'future/data.json'];
  const result = scan(paths, [group('data.json')]);
  assert.deepEqual(result.violations.map((v) => [v.path, v.code]), [
    ['data.json', 'TRACKED_COMPILER_OUTPUT'], ['future/data.json', 'TRACKED_COMPILER_OUTPUT'],
  ]);
});
