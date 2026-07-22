#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { analyzeImpact } from './impact/analyzer';
import { validateAnalysisResult } from './impact/result';

interface CliOptions {
  base: string;
  head: string;
  output: string;
  forceFullReason?: string;
}

function parseArgs(argv: string[]): CliOptions {
  if (argv[0] !== 'analyze') {
    throw new Error('usage: impact-cli analyze --base <ref> --head <ref> [--output <path>] [--force-full <reason>]');
  }
  const values = new Map<string, string>();
  for (let index = 1; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith('--') || value === undefined) throw new Error(`invalid argument near ${key ?? '<end>'}`);
    values.set(key, value);
  }
  const base = values.get('--base');
  const head = values.get('--head');
  if (!base || !head) throw new Error('--base and --head are required');
  return {
    base,
    head,
    output: values.get('--output') ?? 'reports/impact/analysis.json',
    forceFullReason: values.get('--force-full'),
  };
}

function logSummary(result: ReturnType<typeof analyzeImpact>): void {
  console.log(`Test strategy: ${result.strategy}`);
  console.log(`Base revision: ${result.baseRevision}`);
  console.log(`Head revision: ${result.headRevision}`);
  console.log(`Detected projects: ${result.detectedProjects.length}`);
  console.log(`Adapters: ${[...new Set(result.detectedProjects.map((project) => project.adapter))].join(', ') || 'none'}`);
  console.log(`Changed files: ${result.changedFiles.length}`);
  for (const file of result.changedFiles) {
    console.log(`  - ${file.status}: ${file.oldPath ? `${file.oldPath} -> ` : ''}${file.path}`);
  }
  console.log(`Affected projects: ${result.affectedProjects.join(', ') || 'none'}`);
  console.log(`Affected modules: ${result.affectedModules.join(', ') || 'none'}`);
  console.log(`Unit test targets: ${result.unitTestTargets.length}`);
  console.log(`Integration test targets: ${result.integrationTestTargets.length}`);
  console.log(`E2E test targets: ${result.e2eTestTargets.length}`);
  console.log(`Smoke test targets: ${result.smokeTestTargets.length}`);
  console.log(`Selected test targets: ${result.selectedTestTargetCount}/${result.availableTestTargetCount}`);
  console.log(`Fallback: ${result.fallback}`);
  if (result.fallbackReason) console.log(`Fallback reason: ${result.fallbackReason}`);
}

function main(): void {
  const repositoryRoot = process.cwd();
  const options = parseArgs(process.argv.slice(2));
  const result = analyzeImpact({
    repositoryRoot,
    baseRef: options.base,
    headRef: options.head,
    forceFullReason: options.forceFullReason,
  });
  validateAnalysisResult(repositoryRoot, result);
  const outputPath = path.resolve(repositoryRoot, options.output);
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`);
  logSummary(result);
  if (result.strategy === 'failure') process.exitCode = 2;
}

try {
  main();
} catch (error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Impact analysis failed closed: ${message}`);
  process.exitCode = 2;
}
