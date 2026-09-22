#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import path from 'node:path';

export interface TrackedFile { path: string; mode: string }
export interface OwnershipGroup {
  category: string;
  files: string[];
  sourceOfTruth: string[];
  reason: string;
  removalCondition: string;
}
export interface OwnershipManifest {
  schemaVersion: number;
  sourceRoot: string;
  outputRoot: string;
  groups: OwnershipGroup[];
}
export interface BoundaryViolation { path: string; code: string }

const GENERATED_FILE = /\.(?:[cm]?js|d\.ts|map)$/iu;
const CATEGORIES = new Set([
  'schema-generated-source', 'authored-source', 'fixture-example',
  'runtime-template', 'runtime-reference', 'generated-golden', 'adversarial-symlink-fixture',
]);
const GENERATED_ROOTS = ['bin', 'contract', 'emitter', 'lib', 'openapi', 'parser',
  'recommendation', 'reporters', 'scripts', 'source', 'source-analysis', 'types', 'validator'];
const TEMP_ROOTS = new Set(['dist', 'coverage', 'reports', '.nyc_output']);

function safePath(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 4096 &&
    !/[\u0000-\u001f\u007f\\:]/u.test(value) && !path.posix.isAbsolute(value) &&
    value.split('/').every((part) => part !== '' && part !== '.' && part !== '..');
}

export function inspectGeneratedBoundary(files: readonly TrackedFile[], manifest: OwnershipManifest) {
  const violations: BoundaryViolation[] = [];
  const add = (file: unknown, code: string) => violations.push({ path: safePath(file) ? file : '<invalid-path>', code });
  // Bound work independently of Git's byte limit, including direct test callers.
  if (files.length > 20000 || (Array.isArray(manifest?.groups) && manifest.groups.length > 2000)) {
    add('config/artifact-ownership.json', 'INVENTORY_LIMIT');
    return { violations, inventory: [] };
  }
  const modes = new Map(files.map((file) => [file.path, file.mode]));
  const tracked = new Set<string>();
  const cases = new Map<string, string>();
  for (const file of files) {
    if (!safePath(file.path)) { add(file.path, 'INVALID_PATH'); continue; }
    if (cases.has(file.path.toLowerCase())) add(file.path, 'CASE_OR_DUPLICATE_PATH');
    cases.set(file.path.toLowerCase(), file.path);
    tracked.add(file.path);
  }
  if (manifest?.schemaVersion !== 1 || !safePath(manifest.sourceRoot) ||
      manifest.outputRoot !== '.' || !Array.isArray(manifest.groups)) {
    add('config/artifact-ownership.json', 'INVALID_MANIFEST');
    return { violations, inventory: [] };
  }

  const owned = new Map<string, OwnershipGroup>();
  for (const group of manifest.groups) {
    if (!group || !CATEGORIES.has(group.category) || !Array.isArray(group.files) || group.files.length === 0 || group.files.length > 2000 ||
        !Array.isArray(group.sourceOfTruth) || group.sourceOfTruth.length === 0 || group.sourceOfTruth.length > 100 ||
        typeof group.reason !== 'string' || !group.reason.trim() ||
        typeof group.removalCondition !== 'string' || !group.removalCondition.trim()) {
      add('config/artifact-ownership.json', 'MISSING_OWNERSHIP_METADATA');
      continue;
    }
    for (const source of group.sourceOfTruth) {
      if (!safePath(source) || !tracked.has(source)) add(source, 'MISSING_SOURCE_OF_TRUTH');
    }
    for (const file of group.files) {
      if (!safePath(file)) { add(file, 'INVALID_OWNERSHIP_PATH'); continue; }
      if (group.category === 'adversarial-symlink-fixture' &&
          (!file.startsWith('test/fixtures/') || modes.get(file) !== '120000')) add(file, 'INVALID_SYMLINK_FIXTURE');
      if (owned.has(file)) add(file, 'DUPLICATE_OWNERSHIP');
      owned.set(file, group);
      if (!tracked.has(file)) add(file, 'STALE_OWNERSHIP');
    }
  }

  const roots = new Set(GENERATED_ROOTS);
  const generated = new Map<string, string>();
  for (const file of tracked) {
    if (!file.startsWith(`${manifest.sourceRoot}/`)) continue;
    // resolveJsonModule also copies imported JSON into the corresponding output path.
    if (file.endsWith('.json')) {
      generated.set(file.slice(manifest.sourceRoot.length + 1), file);
      continue;
    }
    if (!file.endsWith('.ts') || file.endsWith('.d.ts')) continue;
    const stem = file.slice(manifest.sourceRoot.length + 1, -3);
    if (stem.includes('/')) roots.add(stem.split('/')[0]);
    for (const suffix of ['.js', '.d.ts', '.js.map', '.d.ts.map']) generated.set(`${stem}${suffix}`, file);
  }
  const inventory = [...tracked].sort().map((file) => {
    const group = owned.get(file);
    if (modes.get(file) === '120000' && group?.category !== 'adversarial-symlink-fixture') add(file, 'TRACKED_SYMLINK');
    const root = file.split('/')[0];
    const source = generated.get(file);
    if (source) add(file, 'TRACKED_COMPILER_OUTPUT');
    else if (TEMP_ROOTS.has(root)) add(file, 'TRACKED_TEMP_OUTPUT');
    else if (!group && (roots.has(root) || GENERATED_FILE.test(file) || file.startsWith('tests/golden/') || file.startsWith('templates/'))) {
      add(file, 'ORPHAN_OR_UNREGISTERED_ARTIFACT');
    }
    return {
      path: file,
      category: source ? 'compiler-output' : group?.category ?? (file.startsWith(`${manifest.sourceRoot}/`) ? 'typescript-source' : file.startsWith('examples/') || file.startsWith('test/') ? 'fixture-example' : 'authored-asset'),
      sourceOfTruth: source ? [source] : group?.sourceOfTruth.filter(safePath) ?? [file],
    };
  });
  violations.sort((a, b) => a.path.localeCompare(b.path, 'en') || a.code.localeCompare(b.code, 'en'));
  return { violations, inventory };
}

function git(repoRoot: string, args: string[]): string {
  return execFileSync('git', ['-C', repoRoot, ...args], {
    encoding: 'utf8', maxBuffer: 4 * 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'],
  });
}

export function main(repoRoot = path.join(__dirname, '..'), json = false): void {
  try {
    const files = git(repoRoot, ['ls-files', '--stage', '-z']).split('\0').filter(Boolean).map((entry) => {
      const match = /^(\d{6}) [a-f0-9]+ 0\t([\s\S]+)$/u.exec(entry);
      if (!match) throw new Error('invalid or unmerged index');
      return { mode: match[1], path: match[2] };
    });
    // Read indexed blobs, never follow a manifest/config/source symlink outside the repository.
    const manifest = JSON.parse(git(repoRoot, ['show', ':config/artifact-ownership.json'])) as OwnershipManifest;
    const config = JSON.parse(git(repoRoot, ['show', ':tsconfig.json'])) as { compilerOptions?: { rootDir?: string; outDir?: string } };
    if (config.compilerOptions?.rootDir !== manifest.sourceRoot || config.compilerOptions?.outDir !== manifest.outputRoot) {
      throw new Error('build ownership layout mismatch');
    }
    const result = inspectGeneratedBoundary(files, manifest);
    if (json) console.log(JSON.stringify({ schemaVersion: 1, ...result }, null, 2));
    else if (result.violations.length) {
      console.error('[generated-boundary] rejected tracked artifacts; regenerate from source or correct exact ownership metadata:');
      for (const violation of result.violations) console.error(`${violation.code}: ${violation.path}`);
    } else console.log(`[generated-boundary] OK: ${files.length} tracked files classified`);
    if (result.violations.length) process.exitCode = 1;
  } catch {
    console.error('[generated-boundary] INVENTORY_ERROR: verify the Git index, staged ownership manifest and TypeScript build layout.');
    process.exitCode = 1;
  }
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args.length === 1 && args[0] !== '--json')) {
    console.error('Usage: node scripts/check-generated-boundary.js [--json]');
    process.exitCode = 1;
  } else main(undefined, args[0] === '--json');
}
