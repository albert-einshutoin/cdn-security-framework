import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import { afterAll, beforeAll, expect, test } from 'vitest';

const require = createRequire(import.meta.url);
const { build } = require('../scripts/lib/compile-core');
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-query-keys-'));
let code: string;
beforeAll(() => {
  build({ version: 2, request: { allow_methods: ['GET'] }, response_headers: {} }, {
    rootDir: process.cwd(), outDir: directory, env: {}, optimize: true,
  });
  code = fs.readFileSync(path.join(directory, 'edge/viewer-request.js'), 'utf8');
});
afterAll(() => fs.rmSync(directory, { recursive: true, force: true }));

test.each(['__proto__', 'constructor', 'toString'])('preserves query key %s without changing shared objects', (name) => {
  const context = vm.createContext({ console: { log() {} } });
  const handler = vm.runInContext(`${code}\nhandler`, context);
  const before = vm.runInContext('JSON.stringify([Object.getOwnPropertyNames(Object.prototype), Object.getOwnPropertyNames(Object), Object.getOwnPropertyNames(Object.prototype.toString)])', context);
  const query = Object.fromEntries([
    [name, { value: 'first', multiValue: [{ value: 'first' }, { value: 'second' }] }],
    ['keep', { value: 'normal' }], ['utm_source', { value: 'discard' }],
  ]);
  const result = handler({ request: {
    method: 'GET', uri: '/public', headers: { 'user-agent': { value: 'test' } }, querystring: query,
  } });
  expect(result.statusCode).toBeUndefined();
  expect(Object.hasOwn(result.querystring, name)).toBe(true);
  expect(JSON.parse(JSON.stringify(result.querystring))).toEqual(Object.fromEntries([
    [name, { value: 'first', multiValue: [{ value: 'first' }, { value: 'second' }] }],
    ['keep', { value: 'normal' }],
  ]));
  const after = vm.runInContext('JSON.stringify([Object.getOwnPropertyNames(Object.prototype), Object.getOwnPropertyNames(Object), Object.getOwnPropertyNames(Object.prototype.toString)])', context);
  expect(after).toBe(before);
  const next = handler({ request: {
    method: 'GET', uri: '/public', headers: { 'user-agent': { value: 'test' } },
    querystring: { keep: { value: 'next-request' } },
  } });
  expect(JSON.parse(JSON.stringify(next.querystring))).toEqual({ keep: { value: 'next-request' } });
});
