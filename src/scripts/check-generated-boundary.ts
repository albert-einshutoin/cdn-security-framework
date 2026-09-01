#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import path from 'node:path';

const GENERATED_ROOTS = [
  'bin',
  'contract',
  'emitter',
  'lib',
  'openapi',
  'parser',
  'recommendation',
  'reporters',
  'scripts',
  'source',
  'source-analysis',
  'validator',
] as const;

const GENERATED_FILE = /\.(?:[cm]?js|d\.ts|map)$/u;
const GENERATED_ROOT = new RegExp(`^(?:${GENERATED_ROOTS.join('|')})(?:/|$)`, 'u');

// src/types/policy.d.ts is intentionally tracked: json2ts regenerates the
// source-side contract consumed by TypeScript and the generated status is
// already marked in .gitattributes.
export const TRACKED_GENERATED_EXCEPTIONS = new Map([
  ['src/types/policy.d.ts', 'schema-derived source contract'],
]);

export function isGeneratedPackageArtifact(filePath: string): boolean {
  const normalized = filePath.replace(/[\\/]+/gu, '/');
  return GENERATED_ROOT.test(normalized) && GENERATED_FILE.test(normalized);
}

export function findGeneratedBoundaryViolations(filePaths: readonly string[]): string[] {
  return filePaths
    .map((filePath) => filePath.replace(/[\\/]+/gu, '/'))
    .filter((filePath) => !TRACKED_GENERATED_EXCEPTIONS.has(filePath))
    .filter(isGeneratedPackageArtifact)
    .sort();
}

function trackedFiles(repoRoot: string): string[] {
  try {
    const output = execFileSync('git', ['-C', repoRoot, 'ls-files', '-z'], {
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
    });
    return output.split('\0').filter(Boolean);
  } catch (error: unknown) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`could not inspect tracked files: ${detail}`);
  }
}

export function main(repoRoot = path.join(__dirname, '..')): void {
  const files = trackedFiles(repoRoot);
  const violations = findGeneratedBoundaryViolations(files);
  if (violations.length > 0) {
    console.error('[generated-boundary] tracked compiled artifacts are not allowed:');
    for (const violation of violations) console.error(`- ${violation}`);
    process.exitCode = 1;
    return;
  }

  console.log(`[generated-boundary] OK: ${files.length} tracked files checked`);
}

if (require.main === module) main();
