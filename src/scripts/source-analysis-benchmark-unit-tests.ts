#!/usr/bin/env node
'use strict';

import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { generateSourceAnalysisWorkload, runSourceAnalysisBenchmark } from './benchmark-source-analysis';
import { DEFAULT_SOURCE_ANALYSIS_LIMITS } from '../source-analysis';
import { loadTypeScriptProject, TypeScriptAnalysisCache } from '../source/typescript/project-loader';

async function main(): Promise<void> {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'source-analysis-benchmark-test-'));
  try {
    const report = await runSourceAnalysisBenchmark({
      profile: 'test', controllers: 2, iterations: 2, workloadRoot: root,
    });
    assert.strictEqual(report.expectedOperations, 20);
    assert.deepStrictEqual(report.samples.map(({ projectLoadCache }) => projectLoadCache), ['cold', 'cached']);
    assert.deepStrictEqual(report.samples.map(({ cacheHits }) => cacheHits), [0, 1]);
    assert.ok(report.samples.every(({ operations, diagnostics }) => operations === 20 && diagnostics === 2));
    assert.ok(report.samples.every(({ projectLoadMs, astTraversalMs, irGenerationMs, comparisonMs }) => (
      projectLoadMs >= 0 && astTraversalMs >= 0 && irGenerationMs >= 0 && comparisonMs >= 0
    )));
    await assert.rejects(
      runSourceAnalysisBenchmark({ profile: 'test', controllers: 1, iterations: 0 }),
      /iterations must be a positive integer/u,
    );

    const invalidationRoot = path.join(root, 'invalidation');
    generateSourceAnalysisWorkload(invalidationRoot, 1);
    const cache = new TypeScriptAnalysisCache();
    const options = {
      workspaceRoot: invalidationRoot,
      tsconfigPath: 'tsconfig.json',
      limits: DEFAULT_SOURCE_ANALYSIS_LIMITS,
      cache,
    };
    await loadTypeScriptProject(options);
    await loadTypeScriptProject(options);
    fs.appendFileSync(path.join(invalidationRoot, 'src/controller-0.ts'), '\n// invalidated\n');
    const changed = await loadTypeScriptProject(options);
    assert.deepStrictEqual(changed.metrics, {
      ...changed.metrics, cacheHits: 0, cacheMisses: 1, cacheInvalidations: 1,
    });
    console.log('OK: source analysis benchmark phases, project-loader cache, and invalidation');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

void main().catch((error: unknown) => {
  console.error((error as Error).message);
  process.exitCode = 1;
});
