import assert from 'node:assert/strict';

import type { ImpactConfig } from './impact/core';
import type { AnalysisResult } from './impact/result';
import { runExecutionPlan } from './impact/runner';
import { compareImpactRuns } from './impact-compare';

async function main(): Promise<void> {
  const config: ImpactConfig = {
    version: 1,
    maxParallel: 2,
    rollout: { mode: 'shadow', minimumDays: 14 },
    supportedManifests: { 'package.json': 'javascript', 'pyproject.toml': 'python' },
    safePathPatterns: ['docs/**'],
    riskRules: [
      { id: 'impact-engine', patterns: ['ci/impact/**'], reason: 'impact changed' },
      { id: 'dependency-definition', patterns: ['package.json'], reason: 'dependency changed' },
    ],
    modules: [],
    testMappings: [],
    commands: [
      {
        id: 'pass-one',
        category: 'unit',
        command: 'node',
        args: ['-e', 'process.exit(0)'],
        resourceLocks: ['fixture'],
      },
      {
        id: 'pass-two',
        category: 'integration',
        command: 'node',
        args: ['-e', 'process.exit(0)'],
        resourceLocks: ['fixture'],
      },
      {
        id: 'fail-one',
        category: 'e2e',
        command: 'node',
        args: ['-e', 'process.exit(7)'],
      },
    ],
  };
  const analysis: AnalysisResult = {
    schemaVersion: 1,
    strategy: 'selective',
    baseRevision: 'a'.repeat(40),
    headRevision: 'b'.repeat(40),
    changedFiles: [],
    detectedProjects: [],
    affectedProjects: [],
    affectedModules: [],
    unitTestTargets: ['pass-one'],
    integrationTestTargets: ['pass-two'],
    e2eTestTargets: ['fail-one'],
    smokeTestTargets: [],
    fallback: false,
    fallbackReason: null,
    diagnostics: [],
    executionPlan: ['pass-one', 'pass-two', 'fail-one'],
    requiresPackageMatrix: false,
    selectedTestTargetCount: 3,
    availableTestTargetCount: 3,
  };

  const report = await runExecutionPlan(process.cwd(), config, analysis);
  assert.equal(report.targetCount, 3);
  assert.equal(report.successCount, 2);
  assert.equal(report.failureCount, 1);
  assert.equal(report.skippedCount, 0);
  assert.ok(report.wallClockMs > 0);
  assert.ok(report.totalComputeMs >= report.wallClockMs);
  const comparison = compareImpactRuns(
    analysis,
    { ...report, failureCount: 0, wallClockMs: 50, totalComputeMs: 60 },
    { ...report, failureCount: 1, wallClockMs: 100, totalComputeMs: 120 },
  );
  assert.equal(comparison.wallClockReductionRate, 0.5);
  assert.equal(comparison.computeReductionRate, 0.5);
  assert.equal(comparison.fullOnlyFailure, true);
  console.log('impact runner unit tests: ok');
}

void main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
