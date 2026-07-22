import { readdirSync } from 'node:fs';
import path from 'node:path';

export type ChangeStatus = 'added' | 'modified' | 'deleted' | 'renamed' | 'copied';

export interface ChangedFile {
  status: ChangeStatus;
  path: string;
  oldPath?: string;
  exists: boolean;
}

export interface RiskRule {
  id: string;
  patterns: string[];
  reason: string;
}

export interface ModuleRule {
  id: string;
  patterns: string[];
  dependsOn: string[];
}

export interface CommandConfig {
  id: string;
  category: 'static' | 'build' | 'unit' | 'integration' | 'e2e' | 'smoke' | 'full';
  command: string;
  args: string[];
  resourceLocks?: string[];
  always?: boolean;
}

export interface TestMapping {
  id: string;
  patterns: string[];
  modules?: string[];
  targetIds: string[];
}

export interface ImpactConfig {
  version: number;
  maxParallel: number;
  rollout: { mode: 'shadow' | 'selective'; minimumDays: number };
  supportedManifests: Record<string, string>;
  safePathPatterns: string[];
  riskRules: RiskRule[];
  modules: ModuleRule[];
  commands: CommandConfig[];
  testMappings: TestMapping[];
  smokeTargetIds?: string[];
  fullTargetId?: string;
}

export interface DetectedProject {
  id: string;
  root: string;
  adapter: string;
  manifest: string;
}

export interface StrategyInput {
  changedFiles: ChangedFile[];
  affectedProjects: string[];
  affectedModules: string[];
  testTargetIds: string[];
  smokeTargetIds: string[];
  diagnostics: string[];
  unsupportedProjects?: string[];
}

export interface StrategyDecision {
  strategy: 'selective' | 'full';
  fallback: boolean;
  fallbackReason: string | null;
}

function normalizeRepositoryPath(value: string): string {
  return value.replaceAll('\\', '/').replace(/^\.\//, '');
}

function escapeRegexCharacter(character: string): string {
  return /[\\^$+?.()|{}[\]]/.test(character) ? `\\${character}` : character;
}

/**
 * Implements the deliberately small glob subset used by impact configuration.
 * Keeping this matcher local makes configuration behavior stable across CI
 * providers instead of inheriting subtly different shell glob semantics.
 */
export function matchesGlob(filePath: string, pattern: string): boolean {
  const normalizedPath = normalizeRepositoryPath(filePath);
  const normalizedPattern = normalizeRepositoryPath(pattern);
  let expression = '^';

  for (let index = 0; index < normalizedPattern.length; index += 1) {
    const character = normalizedPattern[index];
    const next = normalizedPattern[index + 1];

    if (character === '*' && next === '*') {
      const followedBySlash = normalizedPattern[index + 2] === '/';
      expression += followedBySlash ? '(?:.*/)?' : '.*';
      index += followedBySlash ? 2 : 1;
      continue;
    }
    if (character === '*') {
      expression += '[^/]*';
      continue;
    }
    if (character === '?') {
      expression += '[^/]';
      continue;
    }
    expression += escapeRegexCharacter(character);
  }

  return new RegExp(`${expression}$`, 'u').test(normalizedPath);
}

export function parseGitNameStatus(output: Buffer): ChangedFile[] {
  const fields = output.toString('utf8').split('\0');
  const changes: ChangedFile[] = [];
  let index = 0;

  while (index < fields.length && fields[index] !== '') {
    const rawStatus = fields[index++];
    const statusCode = rawStatus[0];
    const firstPath = fields[index++];
    if (!firstPath) {
      throw new Error(`git diff emitted a ${rawStatus} record without a path`);
    }

    if (statusCode === 'R' || statusCode === 'C') {
      const secondPath = fields[index++];
      if (!secondPath) {
        throw new Error(`git diff emitted a ${rawStatus} record without a destination path`);
      }
      changes.push({
        status: statusCode === 'R' ? 'renamed' : 'copied',
        path: normalizeRepositoryPath(secondPath),
        oldPath: normalizeRepositoryPath(firstPath),
        exists: true,
      });
      continue;
    }

    const statusByCode: Partial<Record<string, ChangeStatus>> = {
      A: 'added',
      M: 'modified',
      D: 'deleted',
      T: 'modified',
      U: 'modified',
    };
    const status = statusByCode[statusCode];
    if (!status) {
      throw new Error(`unsupported git change status: ${rawStatus}`);
    }
    changes.push({
      status,
      path: normalizeRepositoryPath(firstPath),
      exists: status !== 'deleted',
    });
  }

  return changes;
}

export function classifyRisk(
  changedFiles: ChangedFile[],
  config: ImpactConfig,
): { fallback: boolean; reason: string | null; ruleId: string | null } {
  for (const changedFile of changedFiles) {
    const paths = changedFile.oldPath
      ? [changedFile.oldPath, changedFile.path]
      : [changedFile.path];
    for (const rule of config.riskRules) {
      if (paths.some((candidate) => rule.patterns.some((pattern) => matchesGlob(candidate, pattern)))) {
        return { fallback: true, reason: rule.reason, ruleId: rule.id };
      }
    }
  }
  return { fallback: false, reason: null, ruleId: null };
}

export function detectProjects(repositoryRoot: string, config: ImpactConfig): DetectedProject[] {
  const projects: DetectedProject[] = [];
  const ignoredDirectories = new Set([
    '.git',
    'node_modules',
    'dist',
    'coverage',
    'reports',
    '__pycache__',
  ]);

  function visit(absoluteDirectory: string): void {
    for (const entry of readdirSync(absoluteDirectory, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue;
      const absoluteEntry = path.join(absoluteDirectory, entry.name);
      if (entry.isDirectory()) {
        if (!ignoredDirectories.has(entry.name)) visit(absoluteEntry);
        continue;
      }
      const adapter = config.supportedManifests[entry.name];
      if (!adapter) continue;
      const relativeRoot = normalizeRepositoryPath(path.relative(repositoryRoot, absoluteDirectory)) || '.';
      projects.push({
        id: relativeRoot === '.' ? 'root' : relativeRoot,
        root: relativeRoot,
        adapter,
        manifest: entry.name,
      });
    }
  }

  visit(repositoryRoot);
  const projectsPerRoot = new Map<string, number>();
  for (const project of projects) {
    projectsPerRoot.set(project.root, (projectsPerRoot.get(project.root) ?? 0) + 1);
  }
  return projects
    .map((project) => ({
      ...project,
      id:
        (projectsPerRoot.get(project.root) ?? 0) > 1
          ? `${project.id}:${project.adapter}`
          : project.id,
    }))
    .sort((left, right) => left.root.localeCompare(right.root) || left.adapter.localeCompare(right.adapter));
}

export function selectAffectedModules(changedPaths: string[], config: ImpactConfig): string[] {
  const affected = new Set<string>();
  for (const moduleRule of config.modules) {
    if (
      changedPaths.some((changedPath) =>
        moduleRule.patterns.some((pattern) => matchesGlob(changedPath, pattern)),
      )
    ) {
      affected.add(moduleRule.id);
    }
  }

  let changed = true;
  while (changed) {
    changed = false;
    for (const moduleRule of config.modules) {
      if (!affected.has(moduleRule.id) && moduleRule.dependsOn.some((id) => affected.has(id))) {
        affected.add(moduleRule.id);
        changed = true;
      }
    }
  }
  return [...affected].sort();
}

export function decideStrategy(input: StrategyInput): StrategyDecision {
  if (input.diagnostics.length > 0) {
    return {
      strategy: 'full',
      fallback: true,
      fallbackReason: input.diagnostics[0] ?? 'impact analysis diagnostic reported',
    };
  }
  if ((input.unsupportedProjects?.length ?? 0) > 0) {
    return {
      strategy: 'full',
      fallback: true,
      fallbackReason: `unsupported projects detected: ${input.unsupportedProjects?.join(', ')}`,
    };
  }
  if (input.changedFiles.length > 0 && input.testTargetIds.length + input.smokeTargetIds.length === 0) {
    return {
      strategy: 'full',
      fallback: true,
      fallbackReason: 'changes were detected but no test targets were selected',
    };
  }
  return { strategy: 'selective', fallback: false, fallbackReason: null };
}
