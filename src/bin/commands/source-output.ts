import fs from 'node:fs';
import path from 'node:path';

import { isPathWithinWorkspace } from '../../openapi';
import type { SourceAwareWorkspaceResult } from '../../contract/source-aware-workspace';
import type { SourceAwareFinalizedResult } from '../../contract/source-aware-finalizer';
import { sameFile, writeNewSafeOutput, type OutputTarget } from './safe-output';

export class SourceOutputError extends Error {
  constructor(readonly code: string, readonly exitCode: 2 | 3) { super(code); }
}

/** Internal I/O guard. These paths never enter report evidence or public APIs. */
export function sourceOutputGuard(workspaceRoot: string) {
  const workspaceAlias = path.resolve(workspaceRoot);
  let root: string;
  let rootStat: fs.Stats;
  try {
    root = fs.realpathSync(workspaceAlias);
    rootStat = fs.statSync(root);
    if (!rootStat.isDirectory()) throw new Error('not directory');
  } catch { throw new SourceOutputError('SOURCE_DIFF_OUTPUT_INVALID', 2); }

  const inputPaths = new Set<string>();
  const sourceFiles = new Map<string, { device: number; inode: number }>();
  let incomplete = false;
  const recordInputPath = (inputPath: string) => {
    try {
      let lexical = path.resolve(root, inputPath);
      const seen = new Set<string>();
      let followedLink = false;
      while (!seen.has(lexical)) {
        seen.add(lexical);
        let actual: string;
        try {
          actual = fs.realpathSync(lexical);
          if (!isPathWithinWorkspace(root, lexical) && !isPathWithinWorkspace(root, actual)) {
            if (followedLink) incomplete = true;
            return;
          }
          inputPaths.add(lexical);
          inputPaths.add(actual);
          const stat = fs.statSync(actual);
          if (stat.isFile()) sourceFiles.set(actual, { device: stat.dev, inode: stat.ino });
          return;
        } catch {
          // Missing inputs reserve their name and any dangling symlink target.
          if (isPathWithinWorkspace(root, lexical)) inputPaths.add(lexical);
          let parent: string;
          try { parent = fs.realpathSync(path.dirname(lexical)); }
          catch (error) {
            if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
            throw error;
          }
          actual = path.join(parent, path.basename(lexical));
          if (!isPathWithinWorkspace(root, lexical) && !isPathWithinWorkspace(root, actual)) {
            if (followedLink) incomplete = true;
            return;
          }
          inputPaths.add(lexical);
          inputPaths.add(actual);
          try {
            lexical = path.resolve(path.dirname(actual), fs.readlinkSync(actual));
            followedLink = true;
          }
          catch (error) {
            if (['ENOENT', 'EINVAL'].includes((error as NodeJS.ErrnoException).code ?? '')) return;
            throw error;
          }
        }
      }
    } catch { incomplete = true; }
  };

  const prepare = (outputPath: string, result: SourceAwareWorkspaceResult,
    finalized: SourceAwareFinalizedResult): OutputTarget => {
    if (incomplete || finalized.analysis.outcome === 'internal-error'
      || [result.stages.declared.code, result.stages.implemented.code,
      result.stages.allowed.code].some((code) => code === 'OPENAPI_ANALYSIS_FAILED'
        || code === 'OPENAPI_REF_POINTER_INVALID' || code === 'POLICY_PROJECTION_FAILED'
        || code === 'SOURCE_ANALYZER_INTERNAL' || code === 'SOURCE_EVIDENCE_MISSING'
        || code === 'SOURCE_ANALYZER_TIMEOUT' || code === 'SOURCE_ANALYZER_CANCELLED')) {
      throw new SourceOutputError('SOURCE_DIFF_OUTPUT_PROTECTION_INCOMPLETE', 3);
    }
    if (!outputPath || outputPath === '-' || outputPath.endsWith(path.sep)) {
      throw new SourceOutputError('SOURCE_DIFF_OUTPUT_INVALID', 2);
    }
    let requested: string;
    let parent: string;
    let parentAlias: string;
    let parentStat: fs.Stats;
    try {
      if (!sameFile(fs.statSync(root), { device: rootStat.dev, inode: rootStat.ino })) {
        throw new Error('workspace changed');
      }
      if (fs.realpathSync(workspaceAlias) !== root) throw new Error('workspace alias changed');
      const lexical = path.resolve(root, outputPath);
      if (!isPathWithinWorkspace(root, lexical)) {
        throw new SourceOutputError('SOURCE_DIFF_OUTPUT_PROTECTED', 2);
      }
      parentAlias = path.dirname(lexical);
      parent = fs.realpathSync(parentAlias);
      parentStat = fs.statSync(parent);
      requested = path.join(parent, path.basename(lexical));
      if (!parentStat.isDirectory() || !isPathWithinWorkspace(root, requested)) {
        throw new SourceOutputError('SOURCE_DIFF_OUTPUT_PROTECTED', 2);
      }
    } catch (error) {
      if (error instanceof SourceOutputError) throw error;
      throw new SourceOutputError('SOURCE_DIFF_OUTPUT_INVALID', 2);
    }
    const protectedDirectories = ['policy', 'dist', 'node_modules', '.git'].flatMap((name) => {
      const lexical = path.join(root, name);
      try { return [lexical, fs.realpathSync(lexical)]; } catch { return [lexical]; }
    });
    if (protectedDirectories.some((directory) => isPathWithinWorkspace(directory, requested))) {
      throw new SourceOutputError('SOURCE_DIFF_OUTPUT_PROTECTED', 2);
    }
    if (inputPaths.has(requested) || inputPaths.has(path.resolve(root, outputPath))) {
      throw new SourceOutputError('SOURCE_DIFF_OUTPUT_PROTECTED', 2);
    }
    try {
      fs.lstatSync(requested);
      throw new SourceOutputError('SOURCE_DIFF_OUTPUT_EXISTS', 2);
    } catch (error) {
      if (error instanceof SourceOutputError) throw error;
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw new SourceOutputError('SOURCE_DIFF_OUTPUT_INVALID', 2);
      }
    }
    return {
      basename: path.basename(requested), parent,
      parentDevice: parentStat.dev, parentInode: parentStat.ino,
      protectedDirectories, sourceFiles: [...sourceFiles.values()], workspaceRoot: root,
      workspaceIdentity: { device: rootStat.dev, inode: rootStat.ino },
      workspaceAlias, parentAlias,
    };
  };

  const write = (target: OutputTarget, content: string) => {
    try { writeNewSafeOutput(target, content); }
    catch { throw new SourceOutputError('SOURCE_DIFF_OUTPUT_WRITE_FAILED', 3); }
  };
  return { recordInputPath, prepare, write };
}
