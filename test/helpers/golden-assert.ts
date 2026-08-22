import fs from 'node:fs';
import path from 'node:path';
import { canonicalJson } from './canonical-json';
import { fixtureRoot } from './fixture-root';

const GOLDEN_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const SECRET_LIKE = /\b(?:Bearer|Basic)\s+\S+|\b(?:sk-(?:proj-)?|ghp_|github_pat_|AKIA)[A-Za-z0-9_-]{8,}|[?&][^=\s&#]+=[^&#\s]+|["']?(?:authorization|cookie|password|secret|client_secret|access_token|refresh_token|token|api[_-]?key)["']?\s*[=:]\s*["']?[^\s"',}]+/i;
const SENSITIVE_KEY = /^(?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|password|secret|client[-_]?secret|access[-_]?token|refresh[-_]?token|token|api[-_]?key)$/i;

function assertNoSecrets(value: unknown): void {
  const pending: unknown[] = [value];
  const seen = new WeakSet<object>();
  let nodes = 0;
  while (pending.length > 0) {
    const item = pending.pop();
    nodes += 1;
    if (nodes > 1_000_000) throw new Error('golden exceeds node limit');
    if (typeof item === 'string') {
      const compact = item.replace(/[\u0000-\u001f\u007f]/g, '');
      const separated = item.replace(/[\u0000-\u001f\u007f]/g, ' ');
      if (SECRET_LIKE.test(compact) || SECRET_LIKE.test(separated)) {
        throw new Error('golden contains secret-like value');
      }
      continue;
    }
    if (item === null || typeof item !== 'object' || seen.has(item)) continue;
    seen.add(item);
    if (Array.isArray(item)) {
      if (pending.length + item.length + nodes > 1_000_000) throw new Error('golden exceeds node limit');
      for (let index = 0; index < item.length; index += 1) pending.push(item[index]);
      continue;
    }
    const descriptors = Object.entries(Object.getOwnPropertyDescriptors(item));
    if (pending.length + descriptors.length + nodes > 1_000_000) throw new Error('golden exceeds node limit');
    for (const [key, descriptor] of descriptors) {
      if (!('value' in descriptor)) throw new Error('golden rejects accessors');
      if (SENSITIVE_KEY.test(key.replace(/[\u0000-\u001f\u007f]/g, ''))) {
        throw new Error('golden contains secret-like value');
      }
      if (typeof descriptor.value === 'string') pending.push(`${key}=${descriptor.value}`);
      else pending.push(descriptor.value);
    }
  }
}

function assertSafeGoldenPath(goldenPath: string): void {
  const expectedRoot = path.join(fixtureRoot, 'expected');
  if (fs.lstatSync(expectedRoot).isSymbolicLink()
    || fs.realpathSync(expectedRoot) !== path.resolve(expectedRoot)) {
    throw new Error('golden root must be a real directory');
  }
  try {
    if (fs.lstatSync(goldenPath).isSymbolicLink()) throw new Error('golden path must not be a symlink');
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}

export function assertGolden(name: string, actual: unknown): void {
  if (!GOLDEN_NAME.test(name)) throw new Error('invalid golden name');
  assertNoSecrets(actual);
  const serialized = canonicalJson(actual);
  const goldenPath = path.join(fixtureRoot, 'expected', `${name}.json`);

  if (process.env.UPDATE_GOLDEN === '1') {
    assertSafeGoldenPath(goldenPath);
    const descriptor = fs.openSync(
      goldenPath,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW,
      0o644,
    );
    try {
      fs.writeFileSync(descriptor, serialized, 'utf8');
    } finally {
      fs.closeSync(descriptor);
    }
    return;
  }
  if (!fs.existsSync(goldenPath) || fs.readFileSync(goldenPath, 'utf8') !== serialized) {
    throw new Error(`golden mismatch: ${name}; rerun with UPDATE_GOLDEN=1 to update`);
  }
}
