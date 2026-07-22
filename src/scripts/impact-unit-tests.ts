import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  classifyRisk,
  decideStrategy,
  detectProjects,
  matchesGlob,
  parseGitNameStatus,
  selectAffectedModules,
  type ImpactConfig,
} from './impact/core';

function fixtureConfig(): ImpactConfig {
  return {
    version: 1,
    maxParallel: 2,
    rollout: { mode: 'shadow', minimumDays: 14 },
    supportedManifests: {
      'package.json': 'javascript',
      'pyproject.toml': 'python',
      'Cargo.toml': 'unsupported',
    },
    safePathPatterns: ['docs/**', '**/*.md'],
    riskRules: [
      {
        id: 'dependency-lock',
        patterns: ['**/package-lock.json'],
        reason: 'dependency lock file changed',
      },
      {
        id: 'impact-engine',
        patterns: ['ci/impact/**', 'src/scripts/impact/**'],
        reason: 'impact analysis changed',
      },
    ],
    modules: [
      { id: 'repository', patterns: ['src/repository/**'], dependsOn: [] },
      { id: 'service', patterns: ['src/service/**'], dependsOn: ['repository'] },
      { id: 'api', patterns: ['src/api/**'], dependsOn: ['service'] },
    ],
    commands: [],
    testMappings: [],
  };
}

function testNameStatusParsing(): void {
  const parsed = parseGitNameStatus(
    Buffer.from(
      [
        'A',
        'src/new.ts',
        'M',
        'src/changed.ts',
        'D',
        'src/deleted.ts',
        'R097',
        'src/old.ts',
        'src/renamed.ts',
        'C100',
        'src/source.ts',
        'src/copied.ts',
        '',
      ].join('\0'),
    ),
  );

  assert.deepEqual(parsed, [
    { status: 'added', path: 'src/new.ts', exists: true },
    { status: 'modified', path: 'src/changed.ts', exists: true },
    { status: 'deleted', path: 'src/deleted.ts', exists: false },
    {
      status: 'renamed',
      path: 'src/renamed.ts',
      oldPath: 'src/old.ts',
      exists: true,
    },
    {
      status: 'copied',
      path: 'src/copied.ts',
      oldPath: 'src/source.ts',
      exists: true,
    },
  ]);
}

function testGlobAndRiskClassification(): void {
  assert.equal(matchesGlob('package-lock.json', '**/package-lock.json'), true);
  assert.equal(matchesGlob('packages/api/package-lock.json', '**/package-lock.json'), true);
  assert.equal(matchesGlob('docs/ci/selective.md', 'docs/**'), true);
  assert.equal(matchesGlob('src/docs.ts', 'docs/**'), false);

  const result = classifyRisk(
    [
      {
        status: 'renamed',
        oldPath: 'package-lock.json',
        path: 'package-lock.old.json',
        exists: true,
      },
    ],
    fixtureConfig(),
  );
  assert.equal(result.fallback, true);
  assert.equal(result.reason, 'dependency lock file changed');
}

function testProjectDetection(): void {
  const root = mkdtempSync(path.join(tmpdir(), 'impact-projects-'));
  mkdirSync(path.join(root, 'packages', 'web'), { recursive: true });
  mkdirSync(path.join(root, 'services', 'worker'), { recursive: true });
  mkdirSync(path.join(root, 'native'), { recursive: true });
  writeFileSync(path.join(root, 'packages', 'web', 'package.json'), '{}');
  writeFileSync(path.join(root, 'services', 'worker', 'pyproject.toml'), '[project]\nname="worker"\n');
  writeFileSync(path.join(root, 'native', 'Cargo.toml'), '[package]\nname="native"\n');

  assert.deepEqual(detectProjects(root, fixtureConfig()), [
    { id: 'native', root: 'native', adapter: 'unsupported', manifest: 'Cargo.toml' },
    {
      id: 'packages/web',
      root: 'packages/web',
      adapter: 'javascript',
      manifest: 'package.json',
    },
    {
      id: 'services/worker',
      root: 'services/worker',
      adapter: 'python',
      manifest: 'pyproject.toml',
    },
  ]);
}

function testReverseDependencySelection(): void {
  const affected = selectAffectedModules(['src/repository/users.ts'], fixtureConfig());
  assert.deepEqual(affected, ['api', 'repository', 'service']);
}

function testConservativeStrategy(): void {
  const base = {
    changedFiles: [{ status: 'modified' as const, path: 'src/service/users.ts', exists: true }],
    affectedProjects: ['root'],
    affectedModules: ['service'],
    testTargetIds: ['service-unit'],
    smokeTargetIds: ['cli-smoke'],
    diagnostics: [] as string[],
  };

  assert.deepEqual(decideStrategy(base), {
    strategy: 'selective',
    fallback: false,
    fallbackReason: null,
  });
  assert.equal(
    decideStrategy({ ...base, testTargetIds: [], smokeTargetIds: [] }).strategy,
    'full',
  );
  assert.equal(
    decideStrategy({ ...base, diagnostics: ['dependency graph incomplete'] }).strategy,
    'full',
  );
  assert.equal(
    decideStrategy({ ...base, unsupportedProjects: ['native'] }).strategy,
    'full',
  );
  assert.equal(
    decideStrategy({
      ...base,
      changedFiles: [{ status: 'modified', path: 'docs/ci.md', exists: true }],
      affectedProjects: [],
      affectedModules: [],
      testTargetIds: [],
    }).strategy,
    'selective',
  );
}

testNameStatusParsing();
testGlobAndRiskClassification();
testProjectDetection();
testReverseDependencySelection();
testConservativeStrategy();

console.log('impact analysis unit tests: ok');
