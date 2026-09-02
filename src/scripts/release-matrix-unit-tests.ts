#!/usr/bin/env node

import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'release-matrix-unit-'));
try {
  const output = path.join(tempRoot, 'summary.json');
  const result = childProcess.spawnSync(process.execPath, [
    path.join(__dirname, 'release-matrix-compare.js'),
    '--input', path.join(tempRoot, 'missing'),
    '--output', output,
  ], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  const report = JSON.parse(fs.readFileSync(output, 'utf8')) as {
    status: string;
    failureCode: string;
    checks: Record<string, boolean>;
  };
  assert.equal(report.status, 'fail');
  assert.equal(report.failureCode, 'comparison_failed');
  assert.ok(Object.values(report.checks).every((value) => value === false));
  console.log('[release-matrix-unit] OK: comparison failure is machine-readable');
} finally {
  fs.rmSync(tempRoot, { recursive: true, force: true });
}
