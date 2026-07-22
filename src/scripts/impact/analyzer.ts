import path from 'node:path';

import { findRelatedJavaScriptTests } from './adapters/javascript';
import { findRelatedPythonTests } from './adapters/python';
import { loadImpactConfig } from './config';
import {
  classifyRisk,
  decideStrategy,
  detectProjects,
  matchesGlob,
  selectAffectedModules,
  type ChangedFile,
  type DetectedProject,
} from './core';
import { collectGitChanges } from './git';
import type { AnalysisResult } from './result';
import { selectDirectTestTargets, selectMappedTargets } from './selector';

export interface AnalyzeImpactOptions {
  repositoryRoot: string;
  baseRef: string;
  headRef: string;
  forceFullReason?: string;
}

function normalize(value: string): string {
  return value.replaceAll('\\', '/').replace(/^\.\//u, '');
}

function pathsForClassification(changedFiles: ChangedFile[]): string[] {
  const values = new Set<string>();
  for (const changedFile of changedFiles) {
    values.add(changedFile.path);
    if (changedFile.oldPath) values.add(changedFile.oldPath);
  }
  return [...values].sort();
}

function projectContainsPath(project: DetectedProject, filePath: string): boolean {
  if (project.root === '.') return true;
  return filePath === project.root || filePath.startsWith(`${project.root}/`);
}

function relativeToProject(project: DetectedProject, filePath: string): string {
  if (project.root === '.') return filePath;
  return normalize(path.posix.relative(project.root, filePath));
}

function isSourcePath(filePath: string): boolean {
  return /\.(?:[cm]?[jt]sx?|py)$/u.test(filePath);
}

function isTestPath(filePath: string): boolean {
  return (
    /(^|\/)src\/scripts\/.*-tests\.[cm]?[jt]sx?$/u.test(filePath) ||
    /(^|\/)(test|tests)\/.*\.(test|spec)\.[cm]?[jt]sx?$/u.test(filePath) ||
    /(^|\/)(test_.*|.*_test)\.py$/u.test(filePath)
  );
}

function categoryTargets(targetIds: string[], category: string, commands: ReturnType<typeof loadImpactConfig>['commands']): string[] {
  return targetIds
    .filter((targetId) => commands.find((command) => command.id === targetId)?.category === category)
    .sort();
}

export function analyzeImpact(options: AnalyzeImpactOptions): AnalysisResult {
  const repositoryRoot = path.resolve(options.repositoryRoot);
  const config = loadImpactConfig(repositoryRoot);
  const gitChanges = collectGitChanges(repositoryRoot, options.baseRef, options.headRef);
  const changedPaths = pathsForClassification(gitChanges.changedFiles);
  const diagnostics = [...gitChanges.diagnostics];
  const detectedProjects = detectProjects(repositoryRoot, config);
  const affectedProjects = detectedProjects
    .filter((project) => changedPaths.some((filePath) => projectContainsPath(project, filePath)))
    .map((project) => project.id)
    .sort();
  const affectedProjectRecords = detectedProjects.filter((project) =>
    affectedProjects.includes(project.id),
  );
  const unsupportedProjects = affectedProjectRecords
    .filter((project) => project.adapter.startsWith('unsupported'))
    .map((project) => project.id);
  const affectedModules = selectAffectedModules(changedPaths, config);
  const selectedTargets = new Set(
    selectMappedTargets(changedPaths, affectedModules, config),
  );

  const existingJavaScriptChanges = gitChanges.changedFiles
    .filter(
      (file) => file.exists && /\.[cm]?[jt]sx?$/u.test(file.path),
    )
    .map((file) => file.path);
  if (existingJavaScriptChanges.length > 0) {
    const related = findRelatedJavaScriptTests(repositoryRoot, existingJavaScriptChanges);
    diagnostics.push(...related.diagnostics);
    const relatedTargets = selectDirectTestTargets(related.testFiles, config);
    for (const targetId of relatedTargets) selectedTargets.add(targetId);
    const unconfiguredTests = related.testFiles.filter(
      (testFile) => selectDirectTestTargets([testFile], config).length === 0,
    );
    if (unconfiguredTests.length > 0) {
      diagnostics.push(`related tests have no configured command: ${unconfiguredTests.join(', ')}`);
    }
  }

  for (const project of affectedProjectRecords.filter((candidate) => candidate.adapter === 'python')) {
    const projectChanges = gitChanges.changedFiles
      .filter((file) => file.exists && file.path.endsWith('.py') && projectContainsPath(project, file.path))
      .map((file) => relativeToProject(project, file.path));
    if (projectChanges.length === 0) continue;
    const related = findRelatedPythonTests(repositoryRoot, repositoryRoot, project.root, projectChanges);
    diagnostics.push(...related.diagnostics);
    // Python command selection is deliberately configuration-driven. A newly
    // detected Python project without an explicit executable target must fall
    // back instead of guessing pytest/unittest and possibly running nothing.
    if (related.testFiles.length > 0) {
      diagnostics.push(
        `Python project ${project.id} requires an explicit test command for: ${related.testFiles.join(', ')}`,
      );
    }
  }

  for (const changedFile of gitChanges.changedFiles) {
    if (!changedFile.exists && isSourcePath(changedFile.path)) {
      diagnostics.push(`deleted source requires full validation: ${changedFile.path}`);
    }
  }

  const safeOnly =
    changedPaths.length > 0 &&
    changedPaths.every((filePath) =>
      config.safePathPatterns.some((pattern) => matchesGlob(filePath, pattern)),
    );
  const changedNonTestSource = gitChanges.changedFiles.some(
    (file) => isSourcePath(file.path) && !isTestPath(file.path),
  );
  if (changedNonTestSource && selectedTargets.size === 0 && !safeOnly) {
    diagnostics.push('source changed but no related test target was identified');
  }

  const smokeTargetIds = config.smokeTargetIds ?? [];
  const risk = classifyRisk(gitChanges.changedFiles, config);
  let strategy = decideStrategy({
    changedFiles: gitChanges.changedFiles,
    affectedProjects,
    affectedModules,
    testTargetIds: [...selectedTargets],
    smokeTargetIds,
    diagnostics,
    unsupportedProjects,
  });
  if (risk.fallback) {
    strategy = { strategy: 'full', fallback: true, fallbackReason: risk.reason };
  }
  if (options.forceFullReason) {
    strategy = { strategy: 'full', fallback: true, fallbackReason: options.forceFullReason };
  }

  const commandIds = new Set(config.commands.map((command) => command.id));
  const selected = [...selectedTargets].filter((targetId) => commandIds.has(targetId)).sort();
  const alwaysTargets = config.commands.filter((command) => command.always).map((command) => command.id);
  const executionPlan =
    strategy.strategy === 'full'
      ? [config.fullTargetId ?? '']
      : [...new Set([...alwaysTargets, ...smokeTargetIds, ...selected])];
  if (executionPlan.some((targetId) => !targetId || !commandIds.has(targetId))) {
    return {
      schemaVersion: 1,
      strategy: 'failure',
      baseRevision: gitChanges.baseRevision,
      headRevision: gitChanges.headRevision,
      changedFiles: gitChanges.changedFiles,
      detectedProjects,
      affectedProjects,
      affectedModules,
      unitTestTargets: [],
      integrationTestTargets: [],
      e2eTestTargets: [],
      smokeTestTargets: [],
      fallback: true,
      fallbackReason: 'safe full validation command is unavailable',
      diagnostics: [...diagnostics, 'execution plan contains an unknown command'],
      executionPlan: [],
      requiresPackageMatrix: true,
    };
  }

  const packageMatrixPatterns = [
    '**/package.json',
    '**/package-lock.json',
    'src/bin/**',
    'src/lib/**',
    'src/parser/**',
    'src/validator/**',
    'src/emitter/**',
    'src/scripts/api-contract-tests.ts',
  ];

  return {
    schemaVersion: 1,
    strategy: strategy.strategy,
    baseRevision: gitChanges.baseRevision,
    headRevision: gitChanges.headRevision,
    changedFiles: gitChanges.changedFiles,
    detectedProjects,
    affectedProjects,
    affectedModules,
    unitTestTargets: categoryTargets(selected, 'unit', config.commands),
    integrationTestTargets: categoryTargets(selected, 'integration', config.commands),
    e2eTestTargets: categoryTargets(selected, 'e2e', config.commands),
    smokeTestTargets: smokeTargetIds,
    fallback: strategy.fallback,
    fallbackReason: strategy.fallbackReason,
    diagnostics: [...new Set(diagnostics)].sort(),
    executionPlan,
    requiresPackageMatrix: changedPaths.some((filePath) =>
      packageMatrixPatterns.some((pattern) => matchesGlob(filePath, pattern)),
    ),
  };
}
