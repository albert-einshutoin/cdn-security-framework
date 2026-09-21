import fs from 'node:fs';
import path from 'node:path';
import { sameFile, writeSafeOutput, type OutputTarget } from './commands/safe-output';

export class ReadinessOutputError extends Error {
  constructor(readonly code: 'READINESS_OUTPUT_PROTECTED' | 'READINESS_OUTPUT_WRITE_FAILED') {
    super(code);
  }
}

type ReadinessOutput = {
  input: string;
  source?: { device: number; inode: number };
  target: OutputTarget;
};

function inputStat(input: string): fs.Stats | undefined {
  try { return fs.statSync(input); } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    return undefined;
  }
}

// Capture before evaluation so a moved input cannot become an unprotected output.
export function prepareReadinessOutput(input: string, output: string): ReadinessOutput {
  try {
    input = path.resolve(input);
    const requested = path.resolve(output);
    if (input === requested) throw new ReadinessOutputError('READINESS_OUTPUT_PROTECTED');
    const sourceStat = inputStat(input);
    const source = sourceStat ? { device: sourceStat.dev, inode: sourceStat.ino } : undefined;
    const parent = fs.realpathSync(path.dirname(requested));
    const resolved = path.join(parent, path.basename(requested));
    if (!source) {
      // Preserve failure reports for absent policies without creating the input via a parent alias.
      let inputParent: string | undefined;
      try { inputParent = fs.realpathSync(path.dirname(input)); } catch (error: unknown) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
      if (inputParent && path.join(inputParent, path.basename(input)) === resolved) {
        throw new ReadinessOutputError('READINESS_OUTPUT_PROTECTED');
      }
      // An unresolved leaf symlink cannot establish a safe absent-input destination.
      try {
        if (fs.lstatSync(input).isSymbolicLink()) throw new Error('unresolved input alias');
      } catch (error: unknown) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
    }
    let existing: fs.Stats | undefined;
    try { existing = fs.lstatSync(resolved); } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    if (existing && (!existing.isFile() || existing.nlink > 1 || (source && sameFile(existing, source)))) {
      throw new ReadinessOutputError('READINESS_OUTPUT_PROTECTED');
    }
    const directory = fs.statSync(parent);
    return { input, source, target: {
      basename: path.basename(resolved), parent, parentDevice: directory.dev, parentInode: directory.ino,
      // Readiness accepts absolute outputs outside cwd, but pins their original parent.
      workspaceRoot: parent, protectedDirectories: [], sourceFiles: source ? [source] : [],
      expected: existing ? { device: existing.dev, inode: existing.ino } : undefined,
    } };
  } catch (error: unknown) {
    if (error instanceof ReadinessOutputError) throw error;
    throw new ReadinessOutputError('READINESS_OUTPUT_WRITE_FAILED');
  }
}

export function writeReadinessOutput(output: ReadinessOutput, content: string): void {
  try {
    const current = inputStat(output.input);
    if (output.source ? !current || !sameFile(current, output.source) : current !== undefined) {
      throw new Error('input changed');
    }
    writeSafeOutput(output.target, content);
  } catch {
    throw new ReadinessOutputError('READINESS_OUTPUT_WRITE_FAILED');
  }
}
