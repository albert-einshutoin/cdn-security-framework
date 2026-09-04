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
    failureStage: string;
    checks: Record<string, boolean>;
  };
  assert.equal(report.status, 'fail');
  assert.equal(report.failureCode, 'comparison_failed');
  assert.equal(report.failureStage, 'reportCollection');
  assert.ok(Object.values(report.checks).every((value) => value === false));

  const reportsRoot = path.join(tempRoot, 'reports');
  fs.mkdirSync(reportsRoot);
  for (const nodeVersion of ['20.0.0', '22.0.0', '24.0.0']) {
    fs.writeFileSync(path.join(reportsRoot, `${nodeVersion}.json`), JSON.stringify({
      schemaVersion: 1,
      status: 'pass',
      nodeVersion,
      packageVersion: '1.4.0',
      checks: Object.fromEntries([
        'apiContract', 'packageSmoke', 'cliVersion', 'cliHelp', 'apiExports',
        'schemas', 'openApiExample', 'sourceExample', 'awsBuild', 'cloudflareBuild',
      ].map((name) => [name, true])),
      skippedChecks: [],
      apiExports: {},
      schemaDigests: {},
      artifacts: {
        aws: { aggregateSha256: 'sha256:aws', files: [] },
        cloudflare: { aggregateSha256: 'sha256:cloudflare', files: [] },
      },
    }));
  }
  const invalidFloorOutput = path.join(tempRoot, 'invalid-floor.json');
  const invalidFloor = childProcess.spawnSync(process.execPath, [
    path.join(__dirname, 'release-matrix-compare.js'),
    '--input', reportsRoot,
    '--output', invalidFloorOutput,
  ], { encoding: 'utf8' });
  assert.equal(invalidFloor.status, 1);
  const invalidFloorReport = JSON.parse(fs.readFileSync(invalidFloorOutput, 'utf8')) as {
    failureStage: string;
  };
  assert.equal(invalidFloorReport.failureStage, 'nodeVersions');

  const node20Report = JSON.parse(fs.readFileSync(path.join(reportsRoot, '20.0.0.json'), 'utf8')) as {
    nodeVersion: string;
  };
  node20Report.nodeVersion = '20.17.0';
  fs.rmSync(path.join(reportsRoot, '20.0.0.json'));
  fs.writeFileSync(path.join(reportsRoot, '20.17.0.json'), JSON.stringify(node20Report));
  const validFloorOutput = path.join(tempRoot, 'valid-floor.json');
  const validFloor = childProcess.spawnSync(process.execPath, [
    path.join(__dirname, 'release-matrix-compare.js'),
    '--input', reportsRoot,
    '--output', validFloorOutput,
  ], { encoding: 'utf8' });
  assert.equal(validFloor.status, 0, validFloor.stderr);
  assert.equal(JSON.parse(fs.readFileSync(validFloorOutput, 'utf8')).status, 'pass');

  const checkOutput = path.join(tempRoot, 'check-failure.json');
  const invalidArguments = childProcess.spawnSync(process.execPath, [
    path.join(__dirname, 'release-matrix-check.js'),
    '--unknown',
    '--output', checkOutput,
  ], { encoding: 'utf8' });
  assert.equal(invalidArguments.status, 1);
  const checkFailure = JSON.parse(fs.readFileSync(checkOutput, 'utf8')) as {
    failureStage: string;
    skippedChecks: string[];
  };
  assert.equal(checkFailure.failureStage, 'arguments');
  assert.ok(checkFailure.skippedChecks.length > 0);
  console.log('[release-matrix-unit] OK: failures identify stage and enforce the Node 20.17 floor');
} finally {
  fs.rmSync(tempRoot, { recursive: true, force: true });
}
