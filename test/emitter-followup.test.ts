import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { afterEach, expect, test, vi } from 'vitest';
const { compileArtifacts } = createRequire(import.meta.url)('../emitter');
const roots: string[] = [];
afterEach(() => { vi.restoreAllMocks(); for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });

test.each(['aws', 'cloudflare'])('emitter %s reads one policy snapshot, honors caller env, and observes subsequent edits', (target) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-emitter-followup-')); roots.push(dir);
  const input = path.join(dir, 'policy.json');
  const write = (patch: object = {}) => fs.writeFileSync(input, JSON.stringify({ version: 2, request: { allow_methods: ['GET'] }, response_headers: {},
    routes: [{ name: 'auth', match: { path_prefixes: ['/private'] }, auth_gate: { type: 'static_token', token_env: 'FOLLOWUP_TOKEN' } }], ...patch }));
  write();
  const originalRead = fs.readFileSync;
  let policyReads = 0;
  vi.spyOn(fs, 'readFileSync').mockImplementation(((file: any, ...args: any[]) => {
    if (file === input) policyReads++;
    return Reflect.apply(originalRead, fs, [file, ...args]);
  }) as typeof fs.readFileSync);
  const call = (env = { FOLLOWUP_TOKEN: 'synthetic-caller-token' }) => compileArtifacts({ policyPath: input,
    outDir: path.join(dir, 'dist'), pkgRoot: process.cwd(), target, env });
  const result = call();
  expect(result.ok, result.errors.join('\n')).toBe(true);
  expect(policyReads).toBe(1);
  if (target === 'aws') expect(fs.readFileSync(result.edgeFiles[0], 'utf8')).toContain('synthetic-caller-token');
  write({ version: 999 });
  expect(call().ok).toBe(false);
  expect(policyReads).toBe(2);
});

test('in-process errors preserve policy diagnostics and never terminate the host process', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-emitter-errors-')); roots.push(dir);
  const input = path.join(dir, 'policy.json');
  fs.writeFileSync(input, JSON.stringify({ version: 2, request: { allow_methods: ['GET'] }, response_headers: {}, metadata: { risk_level: 'permissive' } }));
  const result = compileArtifacts({ policyPath: input, outDir: path.join(dir, 'dist'), pkgRoot: process.cwd(), failOnPermissive: true });
  expect(result.ok).toBe(false);
  expect(result.errors.join('\n')).toContain('--fail-on-permissive');
  expect(fs.existsSync(path.join(dir, 'dist/edge/viewer-request.js'))).toBe(false);
});

test('missing auth secrets return every route and env diagnostic without exposing provided secrets or writing artifacts', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-emitter-validation-')); roots.push(dir);
  const input = path.join(dir, 'policy.json'), outDir = path.join(dir, 'dist');
  fs.writeFileSync(input, JSON.stringify({ version: 2, request: { allow_methods: ['GET'] }, response_headers: {}, routes: [
    { name: 'configured', match: { path_prefixes: ['/configured'] }, auth_gate: { type: 'static_token', token_env: 'PROVIDED_TOKEN' } },
    { name: 'token-protected', match: { path_prefixes: ['/token'] }, auth_gate: { type: 'static_token', token_env: 'MISSING_TOKEN' } },
    { name: 'basic-protected', match: { path_prefixes: ['/basic'] }, auth_gate: { type: 'basic_auth', credentials_env: 'MISSING_CREDS' } },
  ] }));
  const secret = 'synthetic-provided-secret-not-for-deployment';
  const result = compileArtifacts({ policyPath: input, outDir, pkgRoot: process.cwd(), env: { PROVIDED_TOKEN: secret } });
  expect(result.ok).toBe(false);
  expect(result.errors).toContain('edge compile failed: Auth gate validation failed');
  expect(result.errors.some((message: string) => message.includes('Route "token-protected": static_token requires env "MISSING_TOKEN"'))).toBe(true);
  expect(result.errors.some((message: string) => message.includes('Route "basic-protected": basic_auth requires env "MISSING_CREDS"'))).toBe(true);
  expect(JSON.stringify(result)).not.toContain(secret);
  expect(result.edgeFiles).toEqual([]);
  expect(result.infraFiles).toEqual([]);
  expect(fs.existsSync(outDir)).toBe(false);
});
