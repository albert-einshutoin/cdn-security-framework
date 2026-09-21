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
