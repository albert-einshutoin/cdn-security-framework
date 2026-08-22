import fs from 'node:fs';
import path from 'node:path';

export const fixtureRoot = path.resolve(__dirname, '../fixtures/openapi');

function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

export function fixtureUri(absolutePath: string): string {
  const resolved = path.resolve(absolutePath);
  if (!isWithin(fixtureRoot, resolved)) throw new Error('fixture path is outside fixture root');
  return path.relative(fixtureRoot, resolved).split(path.sep).join('/');
}

export function resolveFixturePath(relativePath: string): string {
  if (typeof relativePath !== 'string'
    || !relativePath
    || path.isAbsolute(relativePath)
    || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(relativePath)) {
    throw new Error('invalid fixture path');
  }
  const lexical = path.resolve(fixtureRoot, relativePath);
  if (!isWithin(fixtureRoot, lexical)) throw new Error('fixture path is outside fixture root');
  const resolved = fs.realpathSync(lexical);
  if (!isWithin(fs.realpathSync(fixtureRoot), resolved)) {
    throw new Error('fixture path is outside fixture root');
  }
  return resolved;
}
