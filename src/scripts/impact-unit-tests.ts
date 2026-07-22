import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
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
import { loadImpactConfig } from './impact/config';
import { findRelatedJavaScriptTests } from './impact/adapters/javascript';
import { findRelatedPythonTests } from './impact/adapters/python';
import { collectGitChanges } from './impact/git';
import { selectMappedTargets } from './impact/selector';
import { analyzeImpact } from './impact/analyzer';
import { validateAnalysisResult } from './impact/result';
import { materializeCommand } from './impact/runner';

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

function testRepositoryConfiguration(): void {
  const config = loadImpactConfig(process.cwd());
  assert.equal(config.rollout.mode, 'shadow');
  assert.equal(config.rollout.minimumDays, 14);
  assert.ok(config.commands.some((command) => command.id === config.fullTargetId));
  assert.ok(config.smokeTargetIds?.every((id) => config.commands.some((command) => command.id === id)));
  assert.ok(config.riskRules.some((rule) => rule.id === 'impact-engine'));
}

function git(cwd: string, args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function testGitChangeCollection(): void {
  const root = mkdtempSync(path.join(tmpdir(), 'impact-git-'));
  git(root, ['init', '-q']);
  git(root, ['config', 'user.name', 'Impact Test']);
  git(root, ['config', 'user.email', 'impact@example.invalid']);
  writeFileSync(
    path.join(root, 'original.ts'),
    `${Array.from({ length: 20 }, (_, index) => `export const value${index} = ${index};`).join('\n')}\n`,
  );
  writeFileSync(path.join(root, 'deleted.ts'), 'export const deleted = true;\n');
  git(root, ['add', '.']);
  git(root, ['commit', '-qm', 'base']);
  const base = git(root, ['rev-parse', 'HEAD']);

  git(root, ['mv', 'original.ts', 'renamed.ts']);
  writeFileSync(
    path.join(root, 'renamed.ts'),
    `${Array.from({ length: 20 }, (_, index) => `export const value${index} = ${index === 0 ? 100 : index};`).join('\n')}\n`,
  );
  git(root, ['rm', '-q', 'deleted.ts']);
  writeFileSync(path.join(root, 'added.ts'), 'export const added = true;\n');
  git(root, ['add', '.']);
  git(root, ['commit', '-qm', 'head']);
  const head = git(root, ['rev-parse', 'HEAD']);

  const result = collectGitChanges(root, base, head);
  assert.equal(result.diagnostics.length, 0);
  assert.equal(result.baseRevision, base);
  assert.equal(result.headRevision, head);
  assert.ok(result.changedFiles.some((file) => file.status === 'added' && file.path === 'added.ts'));
  assert.ok(result.changedFiles.some((file) => file.status === 'deleted' && file.path === 'deleted.ts'));
  assert.ok(
    result.changedFiles.some(
      (file) => file.status === 'renamed' && file.oldPath === 'original.ts' && file.path === 'renamed.ts',
    ),
  );
}

function testMappedAndRelatedTestSelection(): void {
  const root = mkdtempSync(path.join(tmpdir(), 'impact-js-'));
  mkdirSync(path.join(root, 'src', 'service'), { recursive: true });
  mkdirSync(path.join(root, 'src', 'scripts'), { recursive: true });
  writeFileSync(path.join(root, 'src', 'service', 'users.ts'), 'export const users = [];\n');
  writeFileSync(
    path.join(root, 'src', 'scripts', 'users-unit-tests.ts'),
    "import { users } from '../service/users';\nvoid users;\n",
  );

  const related = findRelatedJavaScriptTests(root, ['src/service/users.ts']);
  assert.deepEqual(related.diagnostics, []);
  assert.deepEqual(related.testFiles, ['src/scripts/users-unit-tests.ts']);

  const config = fixtureConfig();
  config.commands.push({
    id: 'users-unit',
    category: 'unit',
    command: 'node',
    args: ['scripts/users-unit-tests.js'],
  });
  config.testMappings.push({
    id: 'users',
    patterns: ['src/service/users.ts'],
    modules: ['service'],
    targetIds: ['users-unit'],
  });
  assert.deepEqual(
    selectMappedTargets(['src/service/users.ts'], ['service'], config),
    ['users-unit'],
  );
}

function testPythonAdapterSelection(): void {
  const root = mkdtempSync(path.join(tmpdir(), 'impact-python-'));
  mkdirSync(path.join(root, 'app'), { recursive: true });
  mkdirSync(path.join(root, 'tests'), { recursive: true });
  writeFileSync(path.join(root, 'pyproject.toml'), '[project]\nname="fixture"\n');
  writeFileSync(path.join(root, 'app', '__init__.py'), '');
  writeFileSync(path.join(root, 'app', 'service.py'), 'VALUE = 1\n');
  writeFileSync(path.join(root, 'tests', 'test_service.py'), 'from app import service\nassert service.VALUE == 1\n');

  const result = findRelatedPythonTests(process.cwd(), root, '.', ['app/service.py']);
  assert.deepEqual(result.diagnostics, []);
  assert.deepEqual(result.testFiles, ['tests/test_service.py']);
}

function testRepositoryAnalysisFallsBackForAnalyzerChanges(): void {
  const result = analyzeImpact({
    repositoryRoot: process.cwd(),
    baseRef: 'origin/main',
    headRef: 'HEAD',
  });
  assert.equal(result.strategy, 'full');
  assert.equal(result.fallback, true);
  assert.match(result.fallbackReason ?? '', /impact analysis|dependency definition/u);
  assert.deepEqual(result.executionPlan, ['full-validation']);
  validateAnalysisResult(process.cwd(), result);
}

function testCommandMaterializationDoesNotUseShellInterpolation(): void {
  const command = materializeCommand(
    {
      id: 'diff-check',
      category: 'static',
      command: 'git',
      args: ['diff', '--check', '{baseRevision}', '{headRevision}', '$(touch should-not-exist)'],
    },
    {
      baseRevision: 'a'.repeat(40),
      headRevision: 'b'.repeat(40),
    },
  );
  assert.equal(command.command, 'git');
  assert.deepEqual(command.args, [
    'diff',
    '--check',
    'a'.repeat(40),
    'b'.repeat(40),
    '$(touch should-not-exist)',
  ]);
  assert.throws(
    () =>
      materializeCommand(
        { id: 'bad', category: 'unit', command: 'node', args: ['{unknown}'] },
        { baseRevision: 'a'.repeat(40), headRevision: 'b'.repeat(40) },
      ),
    /unknown command placeholder/u,
  );
}

testNameStatusParsing();
testGlobAndRiskClassification();
testProjectDetection();
testReverseDependencySelection();
testConservativeStrategy();
testRepositoryConfiguration();
testGitChangeCollection();
testMappedAndRelatedTestSelection();
testPythonAdapterSelection();
testRepositoryAnalysisFallsBackForAnalyzerChanges();
testCommandMaterializationDoesNotUseShellInterpolation();

console.log('impact analysis unit tests: ok');
