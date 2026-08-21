#!/usr/bin/env node

import { readFileSync } from 'node:fs';

import { loadImpactConfig } from './impact/config';
import { validateAnalysisResult, type AnalysisResult } from './impact/result';
import { runExecutionPlan, writeExecutionReport } from './impact/runner';

function argument(name: string, fallback?: string): string {
  const index = process.argv.indexOf(name);
  if (index < 0) {
    if (fallback !== undefined) return fallback;
    throw new Error(`missing required argument: ${name}`);
  }
  const value = process.argv[index + 1];
  if (!value) throw new Error(`missing value for argument: ${name}`);
  return value;
}

async function main(): Promise<void> {
  const repositoryRoot = process.cwd();
  const analysisPath = argument('--analysis', 'reports/impact/analysis.json');
  const outputPath = argument('--output', 'reports/impact/execution.json');
  const analysis = JSON.parse(readFileSync(analysisPath, 'utf8')) as AnalysisResult;
  validateAnalysisResult(repositoryRoot, analysis);
  const config = loadImpactConfig(repositoryRoot);
  const report = await runExecutionPlan(repositoryRoot, config, analysis);
  writeExecutionReport(repositoryRoot, outputPath, report);
  console.log('\nImpact execution summary');
  console.log(`Strategy: ${report.strategy}`);
  console.log(`Targets: ${report.targetCount}`);
  console.log(`Success: ${report.successCount}`);
  console.log(`Failures: ${report.failureCount}`);
  console.log(`Skipped: ${report.skippedCount}`);
  console.log(`Wall clock: ${report.wallClockMs.toFixed(0)} ms`);
  console.log(`Total compute: ${report.totalComputeMs.toFixed(0)} ms`);
  if (report.estimatedCost !== null) console.log(`Estimated cost: ${report.estimatedCost.toFixed(4)}`);
  if (report.failureCount > 0) process.exitCode = 1;
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Impact test execution failed closed: ${message}`);
  process.exitCode = 2;
});
