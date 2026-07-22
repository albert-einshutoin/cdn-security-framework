import { matchesGlob, type ImpactConfig } from './core';

export function selectMappedTargets(
  changedPaths: string[],
  affectedModules: string[],
  config: ImpactConfig,
): string[] {
  const selected = new Set<string>();
  for (const mapping of config.testMappings) {
    const pathMatches = changedPaths.some((changedPath) =>
      mapping.patterns.some((pattern) => matchesGlob(changedPath, pattern)),
    );
    const moduleMatches = (mapping.modules ?? []).some((moduleId) =>
      affectedModules.includes(moduleId),
    );
    if (!pathMatches && !moduleMatches) continue;
    for (const targetId of mapping.targetIds) selected.add(targetId);
  }
  return [...selected].sort();
}

export function selectDirectTestTargets(testFiles: string[], config: ImpactConfig): string[] {
  const selected = new Set<string>();
  for (const testFile of testFiles) {
    if (/^test\/.*\.(test|spec)\.[cm]?[jt]sx?$/u.test(testFile)) {
      if (config.commands.some((command) => command.id === 'vitest')) selected.add('vitest');
      continue;
    }
    if (!testFile.startsWith('src/')) continue;
    const compiledPath = testFile.slice('src/'.length).replace(/\.[cm]?tsx?$/u, '.js');
    const command = config.commands.find(
      (candidate) => candidate.command === 'node' && candidate.args.includes(compiledPath),
    );
    if (command) selected.add(command.id);
  }
  return [...selected].sort();
}
