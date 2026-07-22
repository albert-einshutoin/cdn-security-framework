import { execFileSync } from 'node:child_process';

import { parseGitNameStatus, type ChangedFile } from './core';

export interface GitChangeResult {
  baseRevision: string;
  headRevision: string;
  changedFiles: ChangedFile[];
  diagnostics: string[];
}

function gitText(repositoryRoot: string, args: string[]): string {
  return execFileSync('git', args, {
    cwd: repositoryRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

function tryResolve(repositoryRoot: string, revision: string): string | null {
  try {
    return gitText(repositoryRoot, ['rev-parse', '--verify', `${revision}^{commit}`]);
  } catch {
    return null;
  }
}

function fetchBaseRef(repositoryRoot: string, baseRef: string): void {
  const remoteMatch = /^([A-Za-z0-9._-]+)\/(.+)$/u.exec(baseRef);
  if (!remoteMatch) return;
  const [, remote, branch] = remoteMatch;
  if (!remote || !branch || branch.startsWith('-')) return;
  execFileSync(
    'git',
    ['fetch', '--no-tags', remote, `refs/heads/${branch}:refs/remotes/${remote}/${branch}`],
    { cwd: repositoryRoot, stdio: 'ignore' },
  );
}

function deepenHistory(repositoryRoot: string, baseRef: string): void {
  const remoteMatch = /^([A-Za-z0-9._-]+)\/(.+)$/u.exec(baseRef);
  if (!remoteMatch) return;
  const [, remote, branch] = remoteMatch;
  if (!remote || !branch || branch.startsWith('-')) return;
  for (const deepen of ['50', '200']) {
    try {
      execFileSync('git', ['fetch', '--no-tags', `--deepen=${deepen}`, remote, branch], {
        cwd: repositoryRoot,
        stdio: 'ignore',
      });
      return;
    } catch {
      // Continue to the next conservative recovery step.
    }
  }
  execFileSync('git', ['fetch', '--no-tags', '--unshallow', remote, branch], {
    cwd: repositoryRoot,
    stdio: 'ignore',
  });
}

/**
 * Uses the merge base with the latest target ref so multi-commit PRs and merge
 * commits are compared without relying on a CI provider's synthetic merge SHA.
 * Any recovery failure is returned as a diagnostic and therefore causes full
 * validation instead of silently producing an empty change set.
 */
export function collectGitChanges(
  repositoryRoot: string,
  baseRef: string,
  headRef: string,
): GitChangeResult {
  const diagnostics: string[] = [];
  let baseRevision = tryResolve(repositoryRoot, baseRef);
  let headRevision = tryResolve(repositoryRoot, headRef);

  if (!baseRevision) {
    try {
      fetchBaseRef(repositoryRoot, baseRef);
      baseRevision = tryResolve(repositoryRoot, baseRef);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      diagnostics.push(`failed to fetch base revision ${baseRef}: ${message}`);
    }
  }
  if (!baseRevision) diagnostics.push(`base revision is unavailable: ${baseRef}`);
  if (!headRevision) diagnostics.push(`head revision is unavailable: ${headRef}`);
  if (!baseRevision || !headRevision) {
    return {
      baseRevision: baseRevision ?? baseRef,
      headRevision: headRevision ?? headRef,
      changedFiles: [],
      diagnostics,
    };
  }

  let mergeBase: string | null = null;
  try {
    mergeBase = gitText(repositoryRoot, ['merge-base', baseRevision, headRevision]);
  } catch {
    try {
      const shallow = gitText(repositoryRoot, ['rev-parse', '--is-shallow-repository']) === 'true';
      if (shallow) {
        deepenHistory(repositoryRoot, baseRef);
        baseRevision = tryResolve(repositoryRoot, baseRef) ?? baseRevision;
        headRevision = tryResolve(repositoryRoot, headRef) ?? headRevision;
        mergeBase = gitText(repositoryRoot, ['merge-base', baseRevision, headRevision]);
      }
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      diagnostics.push(`failed to recover shallow history: ${message}`);
    }
  }

  if (!mergeBase) {
    diagnostics.push(`merge base is unavailable for ${baseRef} and ${headRef}`);
    return { baseRevision, headRevision, changedFiles: [], diagnostics };
  }

  try {
    const output = execFileSync(
      'git',
      [
        'diff',
        '--name-status',
        '-z',
        '--find-renames',
        '--find-copies',
        '--diff-filter=ACDMRT',
        mergeBase,
        headRevision,
      ],
      { cwd: repositoryRoot, encoding: 'buffer', stdio: ['ignore', 'pipe', 'pipe'] },
    );
    return {
      baseRevision: mergeBase,
      headRevision,
      changedFiles: parseGitNameStatus(output),
      diagnostics,
    };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    diagnostics.push(`failed to collect changed files: ${message}`);
    return { baseRevision: mergeBase, headRevision, changedFiles: [], diagnostics };
  }
}
