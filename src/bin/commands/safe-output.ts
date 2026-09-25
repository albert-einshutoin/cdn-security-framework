import fs from 'node:fs';
import path from 'node:path';
import { isPathWithinWorkspace } from '../../openapi';

export interface OutputTarget {
  basename: string;
  parent: string;
  parentDevice: number;
  parentInode: number;
  protectedDirectories: string[];
  sourceFiles: Array<{ device: number; inode: number }>;
  workspaceRoot: string;
  expected?: { device: number; inode: number };
  workspaceIdentity?: { device: number; inode: number };
  workspaceAlias?: string;
  parentAlias?: string;
}

// Source-aware output is create-only. The directory is pinned by chdir while the
// final identity/location checks run; cleanup never unlinks a replacement inode.
export function writeNewSafeOutput(target: OutputTarget, content: string): void {
  const previousDirectory = process.cwd();
  let descriptor: number | undefined;
  let created: { device: number; inode: number } | undefined;
  let failed = false;
  const locationValid = () => {
    const parent = fs.realpathSync('.');
    if (parent !== target.parent
      || !sameFile(fs.statSync('.'), { device: target.parentDevice, inode: target.parentInode })
      || (target.parentAlias && fs.realpathSync(target.parentAlias) !== target.parent)
      || (target.workspaceAlias && fs.realpathSync(target.workspaceAlias) !== target.workspaceRoot)
      || (target.workspaceIdentity && !sameFile(fs.statSync(target.workspaceRoot), target.workspaceIdentity))
      || !isPathWithinWorkspace(target.workspaceRoot, path.join(parent, target.basename))
      || target.protectedDirectories.some((directory) => (
        isPathWithinWorkspace(directory, path.join(parent, target.basename))
      ))) throw new Error('output location changed');
  };
  const cleanup = () => {
    if (!created) return;
    try {
      const current = fs.lstatSync(target.basename);
      if (sameFile(current, created)) fs.unlinkSync(target.basename);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') failed = true;
    }
  };
  try {
    process.chdir(target.parent);
    locationValid();
    descriptor = fs.openSync(target.basename,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL
        | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0), 0o600);
    const opened = fs.fstatSync(descriptor);
    created = { device: opened.dev, inode: opened.ino };
    if (!opened.isFile() || opened.nlink !== 1
      || target.sourceFiles.some((source) => sameFile(opened, source))) {
      throw new Error('output identity changed');
    }
    locationValid();
    fs.writeFileSync(descriptor, content, 'utf8');
    locationValid();
  } catch {
    failed = true;
    if (descriptor !== undefined && !created) {
      // A failed first fstat may still leave our O_EXCL file; only recover it by the open descriptor's identity.
      try {
        const opened = fs.fstatSync(descriptor);
        created = { device: opened.dev, inode: opened.ino };
      } catch { /* Identity unknown: never unlink a possible replacement. */ }
    }
  }
  finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); }
      catch {
        failed = true;
        try { fs.closeSync(descriptor); } catch { /* A failed close may already have closed it. */ }
      }
    }
    if (failed) cleanup();
    try { process.chdir(previousDirectory); }
    catch {
      failed = true;
      cleanup();
    }
  }
  if (failed) throw new Error('Report output could not be written safely.');
}

export function sameFile(left: fs.Stats, right: { device: number; inode: number }): boolean {
  return left.dev === right.device && left.ino === right.inode;
}

export function writeSafeOutput(target: OutputTarget, content: string): void {
  let descriptor: number | undefined;
  const previousDirectory = process.cwd();
  try {
    process.chdir(target.parent);
    if (!sameFile(fs.statSync('.'), { device: target.parentDevice, inode: target.parentInode })) {
      throw new Error('parent changed');
    }
    descriptor = fs.openSync(
      target.basename,
      fs.constants.O_WRONLY | fs.constants.O_CREAT
        | (target.expected ? 0 : fs.constants.O_EXCL)
        | (fs.constants.O_NOFOLLOW ?? 0)
        | (fs.constants.O_NONBLOCK ?? 0),
      0o666,
    );
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || opened.nlink > 1
      || target.sourceFiles.some((source) => sameFile(opened, source))
      || (target.expected && !sameFile(opened, target.expected))) {
      throw new Error('output changed');
    }
    const currentOutput = path.join(fs.realpathSync('.'), target.basename);
    if (!isPathWithinWorkspace(target.workspaceRoot, currentOutput)
      || target.protectedDirectories.some((directory) => isPathWithinWorkspace(directory, currentOutput))) {
      if (!target.expected) {
        const created = fs.lstatSync(target.basename);
        if (sameFile(created, { device: opened.dev, inode: opened.ino })) fs.unlinkSync(target.basename);
      }
      throw new Error('parent moved');
    }
    fs.ftruncateSync(descriptor, 0);
    fs.writeFileSync(descriptor, content, 'utf8');
  } catch {
    throw new Error('Report output could not be written safely.');
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    process.chdir(previousDirectory);
  }
}
