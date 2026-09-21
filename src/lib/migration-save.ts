import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { sameFile } from '../bin/commands/safe-output';
import { MIGRATION_MAX_BYTES, MigrationError } from './migration-transform';

type Identity = { device: number; inode: number };
const identity = (s: fs.Stats): Identity => ({ device: s.dev, inode: s.ino });
export type MigrationInput = { path: string; parent: string; directory: Identity; stat: fs.Stats; content: Buffer };

export function readMigrationInput(input: string): MigrationInput {
  if (fs.constants.O_NOFOLLOW === undefined || fs.constants.O_NONBLOCK === undefined) throw new MigrationError('MIGRATION_PLATFORM_UNSUPPORTED');
  const parent = fs.realpathSync(path.dirname(input));
  const directory = identity(fs.statSync(parent));
  let fd: number | undefined;
  try {
    fd = fs.openSync(input, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > MIGRATION_MAX_BYTES) throw new MigrationError('MIGRATION_INPUT_INVALID');
    const buffer = Buffer.alloc(MIGRATION_MAX_BYTES + 1);
    let bytes = 0;
    while (bytes < buffer.length) {
      const read = fs.readSync(fd, buffer, bytes, buffer.length - bytes, bytes);
      if (!read) break;
      bytes += read;
    }
    if (bytes > MIGRATION_MAX_BYTES) throw new MigrationError('MIGRATION_RESOURCE_LIMIT');
    if (!sameFile(fs.lstatSync(input), identity(stat)) || !sameFile(fs.statSync(parent), directory)) {
      throw new MigrationError('MIGRATION_INPUT_CHANGED');
    }
    return { path: input, parent, directory, stat, content: buffer.subarray(0, bytes) };
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}

/** Trusted, exclusively managed POSIX directory; no durability or adversarial post-check race promise. */
export function saveMigration(source: MigrationInput, content: Buffer): string[] {
  if (source.stat.mode & 0o7000) throw new MigrationError('MIGRATION_PERMISSION_UNSUPPORTED');
  if (source.stat.nlink !== 1) throw new MigrationError('MIGRATION_INPUT_ALIAS');
  const cwd = process.cwd();
  const basename = path.basename(source.path), backup = `${basename}.v1.bak`;
  const staged = `.${basename}.migration-${randomUUID()}.tmp`;
  const owned = new Map<string, Identity>();
  let committed = false;
  let failure: unknown;
  let cleanupFailed = false;
  try {
    process.chdir(source.parent);
    const checkParent = () => {
      if (!sameFile(fs.statSync('.'), source.directory)
        || !sameFile(fs.statSync(path.dirname(source.path)), source.directory)
        || fs.realpathSync('.') !== source.parent) throw new MigrationError('MIGRATION_INPUT_CHANGED');
    };
    const checkInput = () => {
      checkParent();
      const current = readMigrationInput(source.path);
      if (!sameFile(current.stat, identity(source.stat)) || current.stat.nlink !== 1
        || current.stat.mode !== source.stat.mode || !current.content.equals(source.content)) {
        throw new MigrationError('MIGRATION_INPUT_CHANGED');
      }
    };
    checkInput();
    function create(name: string, bytes: Buffer): void {
      const fd = fs.openSync(name, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
      try {
        const stat = fs.fstatSync(fd); owned.set(name, identity(stat));
        if (!stat.isFile() || stat.nlink !== 1) throw new MigrationError('MIGRATION_OUTPUT_INVALID');
        fs.writeFileSync(fd, bytes); fs.fsyncSync(fd);
      } finally { fs.closeSync(fd); }
      checkParent();
    }
    // Exclusive backup prevents overwriting an earlier rollback artifact (including any alias).
    create(backup, source.content);
    create(staged, content);
    for (const name of [backup, staged]) {
      const stat = fs.lstatSync(name);
      if (!sameFile(stat, owned.get(name)!) || !stat.isFile() || stat.nlink !== 1) throw new MigrationError('MIGRATION_OUTPUT_CHANGED');
    }
    if (!readMigrationInput(backup).content.equals(source.content) || !readMigrationInput(staged).content.equals(content)) throw new MigrationError('MIGRATION_OUTPUT_CHANGED');
    const stagedFd = fs.openSync(staged, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    try {
      const stat = fs.fstatSync(stagedFd);
      if (!sameFile(stat, owned.get(staged)!) || stat.uid !== source.stat.uid || stat.gid !== source.stat.gid) throw new MigrationError('MIGRATION_OUTPUT_CHANGED');
      fs.fchmodSync(stagedFd, source.stat.mode & 0o777);
    } finally { fs.closeSync(stagedFd); }
    checkInput();
    if (!sameFile(fs.lstatSync(staged), owned.get(staged)!) || !sameFile(fs.lstatSync(backup), owned.get(backup)!)) throw new MigrationError('MIGRATION_OUTPUT_CHANGED');
    fs.renameSync(staged, basename);
    committed = true;
  } catch (error) { failure = error; }
  finally {
    for (const [name, expected] of owned) {
      if (committed && name === backup) continue;
      try {
        const stat = fs.lstatSync(name);
        if (sameFile(stat, expected)) fs.unlinkSync(name);
        else cleanupFailed = true;
      } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') cleanupFailed = true; }
    }
    try { process.chdir(cwd); } catch { cleanupFailed = true; }
  }
  if (!committed && cleanupFailed) throw new MigrationError('MIGRATION_SAVE_FAILED_CLEANUP_INCOMPLETE');
  if (!committed) throw failure instanceof MigrationError ? failure : new MigrationError('MIGRATION_SAVE_FAILED');
  return cleanupFailed ? ['MIGRATION_CLEANUP_INCOMPLETE'] : [];
}
