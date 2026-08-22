#!/usr/bin/env node
'use strict';

import assert from 'node:assert';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  generateOpenApiBenchmarkWorkloads,
  runOpenApiBenchmark,
} from './benchmark-openapi';

function digestDirectory(directory: string): string {
  const hash = createHash('sha256');
  for (const name of fs.readdirSync(directory, { recursive: true, encoding: 'utf8' }).sort()) {
    const file = path.join(directory, name);
    if (fs.statSync(file).isFile()) hash.update(name).update(fs.readFileSync(file));
  }
  return hash.digest('hex');
}

function main(): void {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-benchmark-test-'));
  try {
    const first = path.join(root, 'first');
    const second = path.join(root, 'second');
    const sizes = { small: 3, shared: 5, large: 10, repeated: 7 };
    const workloads = generateOpenApiBenchmarkWorkloads(first, sizes);
    generateOpenApiBenchmarkWorkloads(second, sizes);

    assert.strictEqual(digestDirectory(first), digestDirectory(second));
    assert.deepStrictEqual(
      workloads.map(({ id, expectedOperations }) => [id, expectedOperations]),
      [
        ['operations-100', 3],
        ['shared-refs-1000', 5],
        ['nested-refs-10000', 10],
        ['deep-schema', 1],
        ['repeated-refs', 7],
        ['early-document-limit', 0],
      ],
    );

    const report = runOpenApiBenchmark({
      iterations: 2,
      profile: 'test',
      workloadRoot: path.join(root, 'run'),
      sizes,
    });
    assert.strictEqual(report.schemaVersion, 1);
    assert.strictEqual(report.workloads.length, 6);
    assert.ok(report.workloads.every(({ samples }) => samples.length === 2));
    assert.ok(report.workloads.every(({ inputPath }) => !path.isAbsolute(inputPath)));
    const repeated = report.workloads.find(({ id }) => id === 'repeated-refs');
    assert.ok(repeated);
    assert.ok(repeated.referenceCount > repeated.resolvedDocumentCount);
    assert.strictEqual(repeated.resolvedDocumentCount, 2);
    const rejected = report.workloads.find(({ id }) => id === 'early-document-limit');
    assert.deepStrictEqual(
      { status: rejected?.status, stage: rejected?.rejection?.stage, code: rejected?.rejection?.code },
      { status: 'rejected', stage: 'parse', code: 'OPENAPI_DOCUMENT_TOO_LARGE' },
    );
    assert.ok(!JSON.stringify(report).includes(root));

    const ciRoot = path.join(root, 'ci');
    const ciReport = runOpenApiBenchmark({ profile: 'ci', workloadRoot: ciRoot, sizes });
    assert.deepStrictEqual(ciReport.workloads.map(({ id }) => id), ['shared-refs-1000']);
    assert.deepStrictEqual(fs.readdirSync(ciRoot), ['shared-refs-1000.json']);

    const baselinePath = path.join(root, 'failing-baseline.json');
    const outputPath = path.join(root, 'failed-report.json');
    fs.writeFileSync(baselinePath, JSON.stringify({
      environment: { platform: process.platform, arch: process.arch },
      maxTimeRegressionPercent: 0,
      maxHeapRegressionPercent: 0,
      nodes: {
        [process.versions.node.split('.')[0]]: {
          'shared-refs-1000': { warmMeanTotalMs: 0, peakHeapDeltaBytes: 0 },
        },
      },
    }));
    const failedGate = spawnSync(process.execPath, [
      path.join(__dirname, 'benchmark-openapi.js'),
      '--profile', 'ci',
      '--output', outputPath,
      '--baseline', baselinePath,
    ], { encoding: 'utf8' });
    assert.notStrictEqual(failedGate.status, 0);
    assert.ok(fs.existsSync(outputPath), 'regression report must exist before the gate fails');
    console.log('OK: OpenAPI benchmark workloads, metrics, cache evidence, and early rejection');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

main();
