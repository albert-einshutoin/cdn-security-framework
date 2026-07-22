import { readFileSync } from 'node:fs';
import path from 'node:path';

import type { DetectedProject } from './core';

interface JavaScriptManifest {
  name?: unknown;
  dependencies?: unknown;
  devDependencies?: unknown;
  peerDependencies?: unknown;
  optionalDependencies?: unknown;
}

function contains(project: DetectedProject, filePath: string): boolean {
  return project.root === '.' || filePath === project.root || filePath.startsWith(`${project.root}/`);
}

function stringKeys(value: unknown): string[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return [];
  return Object.keys(value);
}

/**
 * Selects the most-specific project for each changed path, then follows
 * reverse package dependencies. This prevents a monorepo root manifest from
 * swallowing every nested package while still propagating shared-package
 * changes to services and applications that consume them.
 */
export function selectAffectedProjects(
  repositoryRoot: string,
  changedPaths: string[],
  projects: DetectedProject[],
): { projectIds: string[]; diagnostics: string[] } {
  const affected = new Set<string>();
  const diagnostics: string[] = [];

  for (const changedPath of changedPaths) {
    const matching = projects.filter((project) => contains(project, changedPath));
    if (matching.length === 0) continue;
    const maximumSpecificity = Math.max(
      ...matching.map((project) => (project.root === '.' ? 0 : project.root.length)),
    );
    for (const project of matching) {
      const specificity = project.root === '.' ? 0 : project.root.length;
      if (specificity === maximumSpecificity) affected.add(project.id);
    }
  }

  const packageNameToProject = new Map<string, string>();
  const dependenciesByProject = new Map<string, string[]>();
  for (const project of projects.filter(
    (candidate) => candidate.adapter === 'javascript' && candidate.manifest === 'package.json',
  )) {
    const manifestPath = path.join(repositoryRoot, project.root === '.' ? '' : project.root, 'package.json');
    try {
      const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as JavaScriptManifest;
      if (typeof manifest.name === 'string' && manifest.name.length > 0) {
        if (packageNameToProject.has(manifest.name)) {
          diagnostics.push(`duplicate JavaScript package name: ${manifest.name}`);
        } else {
          packageNameToProject.set(manifest.name, project.id);
        }
      }
      dependenciesByProject.set(project.id, [
        ...stringKeys(manifest.dependencies),
        ...stringKeys(manifest.devDependencies),
        ...stringKeys(manifest.peerDependencies),
        ...stringKeys(manifest.optionalDependencies),
      ]);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      diagnostics.push(`failed to parse ${manifestPath}: ${message}`);
    }
  }

  let changed = true;
  while (changed) {
    changed = false;
    for (const [projectId, dependencyNames] of dependenciesByProject) {
      if (affected.has(projectId)) continue;
      if (
        dependencyNames.some((dependencyName) => {
          const dependencyProject = packageNameToProject.get(dependencyName);
          return dependencyProject ? affected.has(dependencyProject) : false;
        })
      ) {
        affected.add(projectId);
        changed = true;
      }
    }
  }

  return { projectIds: [...affected].sort(), diagnostics: [...new Set(diagnostics)].sort() };
}
