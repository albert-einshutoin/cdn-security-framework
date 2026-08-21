#!/usr/bin/env node

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import type { AnalysisResult } from './impact/result';
import type { ExecutionReport } from './impact/runner';

interface ComparisonReport {
  schemaVersion: 1;
  selectiveStrategy: AnalysisResult['strategy'];
  selectedTestTargetCount: number;
  availableTestTargetCount: number;
  selectionRate: number;
  selectiveWallClockMs: number;
  fullWallClockMs: number;
  wallClockReductionRate: number;
  selectiveComputeMs: number;
  fullComputeMs: number;
  computeReductionRate: number;
  selectiveEstimatedCost: number | null;
  fullEstimatedCost: number | null;
  fullOnlyFailure: boolean;
  fallback: boolean;
  fallbackReason: string | null;
}

function readJson<T>(filePath: string): T {
  return JSON.parse(readFileSync(filePath, 'utf8')) as T;
}

function reduction(selective: number, full: number): number {
  return full > 0 ? (full - selective) / full : 0;
}

export function compareImpactRuns(
  analysis: AnalysisResult,
  selective: ExecutionReport,
  full: ExecutionReport,
): ComparisonReport {
  return {
    schemaVersion: 1,
    selectiveStrategy: analysis.strategy,
    selectedTestTargetCount: analysis.selectedTestTargetCount,
    availableTestTargetCount: analysis.availableTestTargetCount,
    selectionRate:
      analysis.availableTestTargetCount > 0
        ? analysis.selectedTestTargetCount / analysis.availableTestTargetCount
        : 1,
    selectiveWallClockMs: selective.wallClockMs,
    fullWallClockMs: full.wallClockMs,
    wallClockReductionRate: reduction(selective.wallClockMs, full.wallClockMs),
    selectiveComputeMs: selective.totalComputeMs,
    fullComputeMs: full.totalComputeMs,
    computeReductionRate: reduction(selective.totalComputeMs, full.totalComputeMs),
    selectiveEstimatedCost: selective.estimatedCost,
    fullEstimatedCost: full.estimatedCost,
    fullOnlyFailure: selective.failureCount === 0 && full.failureCount > 0,
    fallback: analysis.fallback,
    fallbackReason: analysis.fallbackReason,
  };
}

function argument(name: string): string {
  const index = process.argv.indexOf(name);
  const value = index >= 0 ? process.argv[index + 1] : undefined;
  if (!value) throw new Error(`missing required argument: ${name}`);
  return value;
}

function main(): void {
  const analysis = readJson<AnalysisResult>(argument('--analysis'));
  const selective = readJson<ExecutionReport>(argument('--selective'));
  const full = readJson<ExecutionReport>(argument('--full'));
  const output = argument('--output');
  const comparison = compareImpactRuns(analysis, selective, full);
  mkdirSync(path.dirname(output), { recursive: true });
  writeFileSync(output, `${JSON.stringify(comparison, null, 2)}\n`);
  console.log(`Selective targets: ${comparison.selectedTestTargetCount}/${comparison.availableTestTargetCount}`);
  console.log(`Wall-clock reduction: ${(comparison.wallClockReductionRate * 100).toFixed(1)}%`);
  console.log(`Compute reduction: ${(comparison.computeReductionRate * 100).toFixed(1)}%`);
  console.log(`Full-only failure: ${comparison.fullOnlyFailure}`);
  if (comparison.fullOnlyFailure) process.exitCode = 1;
}

if (require.main === module) {
  try {
    main();
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Impact comparison failed: ${message}`);
    process.exitCode = 2;
  }
}
