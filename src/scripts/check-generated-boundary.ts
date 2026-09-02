#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import path from 'node:path';

const KNOWN_GENERATED_ROOTS = new Set([
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
]);

// These paths are intentionally authored JavaScript/type artifacts, not tsc
// output. Keep the prefixes narrow so a stale artifact in docs/ or CI cannot
// be smuggled into the package by adding a new generated root.
const AUTHORED_ARTIFACT_PREFIXES = [
  'examples/nestjs-contract/run-analysis.cjs',
  'examples/nestjs-contract/stubs/nestjs-common/',
  'runtimes/',
  'templates/',
  'tests/golden/',
];

const GENERATED_FILE = /\.(?:[cm]?js|d\.ts|map)$/u;

export function isGeneratedPackageArtifact(
  filePath: string,
  generatedRoots: ReadonlySet<string> = KNOWN_GENERATED_ROOTS,
): boolean {
  const normalized = filePath.replace(/[\\/]+/gu, '/');
  if (TRACKED_GENERATED_EXCEPTIONS.has(normalized)) return false;
  if (!GENERATED_FILE.test(normalized)) return false;
  const root = normalized.split('/', 1)[0];
  const isAuthoredArtifact = AUTHORED_ARTIFACT_PREFIXES.some(
    (prefix) => prefix.endsWith('/') ? normalized.startsWith(prefix) : normalized === prefix,
  );
  return generatedRoots.has(root) || !isAuthoredArtifact;
}

// src/types/policy.d.ts is intentionally tracked: json2ts regenerates the
// source-side contract consumed by TypeScript and the generated status is
// already marked in .gitattributes.
export const TRACKED_GENERATED_EXCEPTIONS = new Map([
  ['src/types/policy.d.ts', 'schema-derived source contract'],
]);

export function findGeneratedBoundaryViolations(filePaths: readonly string[]): string[] {
  const generatedRoots = new Set(KNOWN_GENERATED_ROOTS);
  for (const filePath of filePaths) {
    const normalized = filePath.replace(/[\\/]+/gu, '/');
    if (!normalized.startsWith('src/')) continue;
    const sourcePath = normalized.slice('src/'.length);
    if (!sourcePath.includes('/') || /\.d\.ts$/u.test(sourcePath)) continue;
    generatedRoots.add(sourcePath.split('/', 1)[0]);
  }

  return filePaths
    .map((filePath) => filePath.replace(/[\\/]+/gu, '/'))
    .filter((filePath) => !TRACKED_GENERATED_EXCEPTIONS.has(filePath))
    .filter((filePath) => isGeneratedPackageArtifact(filePath, generatedRoots))
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
