import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { expect, test } from 'vitest';
const { build } = createRequire(import.meta.url)('../scripts/lib/compile-core');
function compile(routes: unknown[], mode = 'enforce') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-auth-specialization-'));
  try {
    build({ version: 2, defaults: { mode }, routes, request: { allow_methods: ['GET'] }, response_headers: {} }, {
      rootDir: process.cwd(), outDir: dir, env: { A: 'synthetic-a', B: 'synthetic-b' }, optimize: true,
    });
    const source = fs.readFileSync(path.join(dir, 'edge/viewer-request.js'), 'utf8');
    return { source, handler: Function('console', source + '\nreturn handler;')({ log() {} }) };
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
function event(uri: string, headers: Record<string, string> = {}) {
  return { request: { method: 'GET', uri, querystring: {}, headers: Object.fromEntries(Object.entries({ 'user-agent': 'test', ...headers }).map(([key, value]) => [key, { value }])) } };
}
test('ten static-token routes fit the existing size gate and retain every protected prefix', () => {
  const { source, handler } = compile(Array.from({ length: 10 }, (_, i) => ({ name: `r${i}`, match: { path_prefixes: [`/PRIVATE${i}`] }, auth_gate: { type: 'static_token', token_env: 'A' } })));
  expect(Buffer.byteLength(source)).toBeLessThanOrEqual(10240);
  for (let i = 0; i < 10; i++) {
    expect(handler(event(`/private${i}`)).statusCode).toBe(401);
    expect(handler(event(`/private${i}`, { 'x-edge-token': 'synthetic-a' })).uri).toBe(`/private${i}`);
  }
  expect(handler(event('/private0-other')).uri).toBe('/private0-other');
});
test.each(['enforce', 'monitor'])('different overlapping credentials retain intersection and auth denial in %s', (mode) => {
  const routes = [['A', 'x-first'], ['B', 'x-second']].map(([env, header], i) => ({ name: `r${i}`, match: { path_prefixes: ['/private'] },
    auth_gate: { type: 'static_token', token_env: env, header: header } }));
  const { handler } = compile(routes, mode);
  expect(handler(event('/private', { 'x-first': 'synthetic-a' })).statusCode).toBe(401);
  expect(handler(event('/private', { 'x-first': 'synthetic-a', 'x-second': 'synthetic-b' })).uri).toBe('/private');
});
