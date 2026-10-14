import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, expect, test } from 'vitest';
import { createRequire } from 'node:module';
const { validatePolicy } = createRequire(import.meta.url)('../validator');
import { runAnalyze } from '../src/bin/analyze';
const roots: string[] = [];
function directory() { const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-tooling-cache-')); roots.push(dir); return dir; }
afterEach(() => { for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });

test('schema reuse observes changed bytes, package roots, deleted and malformed schemas', () => {
  const root = directory(), second = directory();
  for (const dir of [root, second]) fs.mkdirSync(path.join(dir, 'policy'));
  const file = path.join(root, 'policy/schema.json');
  const schema = (version: number) => JSON.stringify({ type: 'object', properties: { version: { const: version } } });
  fs.writeFileSync(file, schema(2));
  expect(validatePolicy({ policy: { version: 2 }, pkgRoot: root, env: {} }).ok).toBe(true);
  fs.writeFileSync(file, schema(3));
  expect(validatePolicy({ policy: { version: 2 }, pkgRoot: root, env: {} }).ok).toBe(false);
  fs.writeFileSync(path.join(second, 'policy/schema.json'), schema(2));
  expect(validatePolicy({ policy: { version: 2 }, pkgRoot: second, env: {} }).ok).toBe(true);
  fs.writeFileSync(file, '{');
  expect(validatePolicy({ policy: { version: 2 }, pkgRoot: root, env: {} }).errors[0]).toContain('failed to load schema');
  fs.unlinkSync(file);
  expect(validatePolicy({ policy: { version: 2 }, pkgRoot: root, env: {} }).ok).toBe(false);
});

test('chunked log reading preserves UTF-8, CRLF, physical line numbers and the final unterminated line', () => {
  const file = path.join(directory(), 'events.jsonl');
  const valid = JSON.stringify({ event: 'block', status: 403, policy_route: 'public', block_reason: 'test', uri: '/日本語', method: 'GET' });
  fs.writeFileSync(file, ' '.repeat(65533 - Buffer.byteLength(valid.slice(0, valid.indexOf('日')))) + '\r\n' + valid + '\r\n\ninvalid\n' + valid);
  const result = runAnalyze({ input: file, minCount: 3, top: 3 });
  expect(result.summary).toMatchObject({ totalLines: 3, parsedLines: 2, unparseableLines: 1, blockEvents: 2 });
  expect(result.diagnostics.examples).toEqual([{ line: 4, code: 'ANALYZE_JSON_SYNTAX' }]);
  expect(result.byPolicyRoute['/public'].count).toBe(2);
});
