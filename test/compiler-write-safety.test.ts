import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { afterEach, expect, test, vi } from 'vitest';
const require = createRequire(import.meta.url);
const { build } = require('../scripts/lib/compile-core');
const { compile } = require('../lib');
const root = process.cwd();
const scratch: string[] = [];
const env = { EDGE_ADMIN_TOKEN: 'synthetic-b5-auth-not-for-deploy', ORIGIN_SECRET: 'synthetic-b5-origin-not-for-deploy' };
const policy = { version: 2, project: 'write-safety', request: { allow_methods: ['GET'] }, response_headers: {},
  routes: [{ name: 'protected', match: { path_prefixes: ['/private'] }, auth_gate: { type: 'static_token', token_env: 'EDGE_ADMIN_TOKEN' } }],
  origin: { auth: { type: 'custom_header', header: 'x-origin-auth', secret_env: 'ORIGIN_SECRET' } } };
const names = ['viewer-request.js', 'viewer-response.js', 'origin-request.js'];
function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-write-safety-')); scratch.push(dir);
  const outDir = path.join(dir, 'out'), edge = path.join(outDir, 'edge'); fs.mkdirSync(edge, { recursive: true });
  const policyPath = path.join(dir, 'policy.json'); fs.writeFileSync(policyPath, JSON.stringify(policy));
  fs.writeFileSync(path.join(edge, '.unrelated.tmp'), 'unrelated');
  return { dir, outDir, edge, policyPath };
}
function runBuild(f: ReturnType<typeof setup>) { return build(policy, { rootDir: root, outDir: f.outDir, env, optimize: true }); }
function temps(edge: string) { return fs.readdirSync(edge).filter(n => n.startsWith('.viewer-') || n.startsWith('.origin-')); }
function safe(text: string) { return Object.values(env).every(v => !text.includes(v)); }
function caught(fn: () => unknown) { try { fn(); return null; } catch (e: any) { return e; } }
afterEach(() => { vi.restoreAllMocks(); for (const d of scratch.splice(0)) fs.rmSync(d, { recursive: true, force: true }); });
for (const target of ['viewer-request.js', 'origin-request.js']) {
  test(`real rename collision cleans only owned tmp for ${target}`, () => {
    const f = setup(); const dest = path.join(f.edge, target); fs.mkdirSync(dest); fs.writeFileSync(path.join(dest, 'keep'), 'directory marker');
    const error = caught(() => runBuild(f)); expect(error !== null).toBe(true);
    expect(temps(f.edge)).toEqual([]); expect(fs.readFileSync(path.join(dest, 'keep'), 'utf8')).toBe('directory marker');
    expect(fs.readFileSync(path.join(f.edge, '.unrelated.tmp'), 'utf8')).toBe('unrelated'); expect(safe(String(error))).toBe(true);
    if (target === 'origin-request.js') {
      expect(fs.existsSync(path.join(f.edge, 'viewer-request.js'))).toBe(true);
      expect(fs.existsSync(path.join(f.edge, 'viewer-response.js'))).toBe(true);
    }
  });
}
test('creation and successful replacement are owner-only even with umask000; generated code still authenticates', async () => {
  const f = setup(); const previous = process.umask(0); const modes: number[] = [];
  const original = fs.writeFileSync;
  vi.spyOn(fs, 'writeFileSync').mockImplementation((...args: any[]) => {
    if (typeof args[0] === 'number') modes.push(fs.fstatSync(args[0]).mode & 0o777);
    return (original as Function)(...args);
  });
  try { for (let i = 0; i < 2; i++) runBuild(f); } finally { process.umask(previous); }
  expect(modes.length >= 6).toBe(true); expect(modes.every(m => m === 0o600)).toBe(true);
  for (const n of names) expect(fs.statSync(path.join(f.edge, n)).mode & 0o777).toBe(0o600);
  expect(temps(f.edge)).toEqual([]);
  const handler = Function(fs.readFileSync(path.join(f.edge, 'viewer-request.js'), 'utf8') + ';return handler;')();
  const request = { method: 'GET', uri: '/private', querystring: {}, headers: { 'user-agent': { value: 'synthetic-test' } } };
  expect(handler({ request }).statusCode).toBe(401);
  expect(handler({ request: { ...request, headers: { ...request.headers, 'x-edge-token': { value: env.EDGE_ADMIN_TOKEN } } } }).uri).toBe('/private');
  const origin = require(path.join(f.edge, 'origin-request.js')).handler;
  expect(typeof origin).toBe('function');
  const forwarded = await origin({ Records: [{ cf: { request } }] });
  expect(forwarded.headers['x-origin-auth'][0].value === env.ORIGIN_SECRET).toBe(true);
});
for (const kind of ['file', 'symlink']) test(`exclusive tmp collision preserves existing ${kind}`, () => {
  const f = setup(); const foreign = path.join(f.dir, 'foreign'); fs.writeFileSync(foreign, 'foreign content', { mode: 0o640 });
  const open = fs.openSync; let collision = '';
  vi.spyOn(fs, 'openSync').mockImplementation((...args: any[]) => {
    if (typeof args[0] === 'string' && args[0].endsWith('.tmp') && !collision) {
      collision = args[0]; if (kind === 'symlink') fs.symlinkSync(foreign, collision); else fs.writeFileSync(collision, 'foreign content', { mode: 0o640 });
    }
    return (open as Function)(...args);
  });
  const error = caught(() => runBuild(f)); expect(error !== null).toBe(true); expect(collision !== '').toBe(true);
  expect(fs.readFileSync(foreign, 'utf8')).toBe('foreign content'); expect(fs.statSync(foreign).mode & 0o777).toBe(0o640);
  expect(fs.lstatSync(collision).isSymbolicLink()).toBe(kind === 'symlink'); expect(fs.readFileSync(collision, 'utf8')).toBe('foreign content');
});

for (const phase of ['partial-write', 'close', 'rename', 'cleanup']) test(`${phase} failure is non-success with safe diagnostics and owned cleanup`, () => {
  const f = setup(); fs.writeFileSync(path.join(f.edge, 'viewer-request.js'), 'existing artifact');
  let fd: number | undefined; let observedMode = -1; let fired = false;
  const write = fs.writeFileSync, close = fs.closeSync, rename = fs.renameSync;
  if (phase === 'partial-write') vi.spyOn(fs, 'writeFileSync').mockImplementation((...args: any[]) => {
    if (typeof args[0] === 'number' && !fired) {
      fd = args[0]; observedMode = fs.fstatSync(fd!).mode & 0o777; fired = true;
      const content = String(args[1]);
      const end = content.indexOf(env.EDGE_ADMIN_TOKEN) + env.EDGE_ADMIN_TOKEN.length;
      expect(end > env.EDGE_ADMIN_TOKEN.length).toBe(true);
      (write as Function)(fd, content.slice(0, end), 'utf8');
      throw Object.assign(new Error(env.EDGE_ADMIN_TOKEN), { code: 'ENOSPC' });
    }
    return (write as Function)(...args);
  });
  if (phase === 'close') vi.spyOn(fs, 'closeSync').mockImplementation((arg: number) => {
    if (!fired) { fired = true; fd = arg; throw Object.assign(new Error(env.EDGE_ADMIN_TOKEN), { code: 'EIO' }); }
    return close(arg);
  });
  if (phase === 'rename' || phase === 'cleanup') vi.spyOn(fs, 'renameSync').mockImplementation((...args: any[]) => {
    if (String(args[0]).endsWith('.tmp')) { fired = true; throw Object.assign(new Error(env.ORIGIN_SECRET), { code: 'EACCES' }); }
    return (rename as Function)(...args);
  });
  if (phase === 'cleanup') vi.spyOn(fs, 'unlinkSync').mockImplementation(() => { throw Object.assign(new Error(env.EDGE_ADMIN_TOKEN), { code: 'EPERM' }); });
  const error = caught(() => runBuild(f)); expect(error !== null && fired).toBe(true);
  const text = String(error) + JSON.stringify(error);
  expect(safe(text)).toBe(true); expect(text.includes('ARTIFACT_WRITE_FAILED')).toBe(true);
  expect(fs.readFileSync(path.join(f.edge, 'viewer-request.js'), 'utf8')).toBe('existing artifact');
  expect(fs.readFileSync(path.join(f.edge, '.unrelated.tmp'), 'utf8')).toBe('unrelated');
  if (phase === 'cleanup') {
    expect(temps(f.edge).length).toBe(1); expect(text.includes('cleanup=failed')).toBe(true);
    const tmp = path.join(f.edge, temps(f.edge)[0]); expect(fs.statSync(tmp).mode & 0o777).toBe(0o600);
    expect(fs.readFileSync(tmp, 'utf8').includes(env.EDGE_ADMIN_TOKEN)).toBe(true);
  } else expect(temps(f.edge)).toEqual([]);
  if (phase === 'partial-write') expect(observedMode).toBe(0o600);
  if (fd !== undefined) expect(caught(() => fs.fstatSync(fd!)) !== null).toBe(true);
});

test('cleanup does not unlink a replaced foreign staging path; target symlink is protected', () => {
  const f = setup(); let replaced = '';
  vi.spyOn(fs, 'renameSync').mockImplementation((from: fs.PathLike) => {
    replaced = String(from); fs.unlinkSync(from); fs.writeFileSync(from, 'foreign replacement');
    throw Object.assign(new Error(env.EDGE_ADMIN_TOKEN), { code: 'EACCES' });
  });
  const error = caught(() => runBuild(f)); expect(error !== null).toBe(true);
  expect(fs.readFileSync(replaced, 'utf8')).toBe('foreign replacement'); expect(String(error).includes('cleanup=ownership_lost')).toBe(true);
  vi.restoreAllMocks();
  const g = setup(); const foreign = path.join(g.dir, 'foreign'); fs.writeFileSync(foreign, 'foreign'); fs.symlinkSync(foreign, path.join(g.edge, 'viewer-request.js'));
  expect(caught(() => runBuild(g)) !== null).toBe(true); expect(fs.lstatSync(path.join(g.edge, 'viewer-request.js')).isSymbolicLink()).toBe(true);
  expect(fs.readFileSync(foreign, 'utf8')).toBe('foreign'); expect(temps(g.edge)).toEqual([]);
});
for (const target of ['viewer-request.js', 'origin-request.js']) test(`CLI/API agree on real ${target} rename failure without available artifact list`, () => {
  const f = setup(); fs.mkdirSync(path.join(f.edge, target));
  const result = compile({ policyPath: f.policyPath, outDir: f.outDir, target: 'aws', env: { ...process.env, ...env } });
  expect(result.ok).toBe(false); expect(result.edgeFiles).toEqual([]); expect(result.infraFiles).toEqual([]);
  expect(result.errors.join(' ').includes('ARTIFACT_WRITE_FAILED')).toBe(true); expect(safe(JSON.stringify(result))).toBe(true);
  expect(temps(f.edge)).toEqual([]);
  const cli = spawnSync(process.execPath, [path.join(root, 'bin/cli.js'), 'build', '--policy', f.policyPath, '--out-dir', f.outDir, '--target', 'aws'], { cwd: f.dir, env: { ...process.env, ...env }, encoding: 'utf8' });
  expect(cli.status).not.toBe(0); expect(cli.stdout.includes('SUCCESS')).toBe(false); expect(safe(cli.stdout + cli.stderr)).toBe(true);
  expect(cli.stderr.includes('cleanup=removed')).toBe(true); expect(temps(f.edge)).toEqual([]);
});
test('programmatic child reports cleanup failure safely and never calls it residue-free', () => {
  const f = setup(); fs.mkdirSync(path.join(f.edge, 'viewer-request.js'));
  const hook = path.join(f.dir, 'cleanup-fault.cjs');
  fs.writeFileSync(hook, `const fs=require('node:fs');const path=require('node:path');const unlink=fs.unlinkSync;fs.unlinkSync=function(p){if(path.basename(p).startsWith('.viewer-request.')&&String(p).endsWith('.tmp'))throw Object.assign(new Error(${JSON.stringify(env.EDGE_ADMIN_TOKEN)}),{code:'EPERM'});return unlink(p);};`);
  const result = compile({ policyPath: f.policyPath, outDir: f.outDir, target: 'aws', env: { ...process.env, ...env, NODE_OPTIONS: '--require=' + hook } });
  expect(result.ok).toBe(false); expect(result.edgeFiles).toEqual([]); expect(safe(JSON.stringify(result))).toBe(true);
  expect(result.errors.join().includes('cleanup=failed')).toBe(true); expect(temps(f.edge).length).toBe(1);
  expect(fs.statSync(path.join(f.edge, temps(f.edge)[0])).mode & 0o777).toBe(0o600);
});

test('creation failure is safe and leaves existing target and unrelated files untouched', () => {
  const f = setup(); fs.writeFileSync(path.join(f.edge, 'viewer-request.js'), 'existing'); const open = fs.openSync;
  vi.spyOn(fs, 'openSync').mockImplementation((...args: any[]) => {
    if (String(args[0]).endsWith('.tmp')) throw Object.assign(new Error(env.EDGE_ADMIN_TOKEN), { code: 'EACCES' });
    return (open as Function)(...args);
  });
  const e = caught(() => runBuild(f)); expect(e !== null).toBe(true); expect(safe(String(e))).toBe(true);
  expect(String(e).includes('phase=create')).toBe(true); expect(String(e).includes('cleanup=not_owned')).toBe(true);
  expect(fs.readFileSync(path.join(f.edge, 'viewer-request.js'), 'utf8')).toBe('existing'); expect(temps(f.edge)).toEqual([]);
});
test('persistent descriptor-close failure is observable and cannot become build success', () => {
  const f = setup(); const close = fs.closeSync; let ownedFd: number | undefined;
  vi.spyOn(fs, 'closeSync').mockImplementation((fd: number) => { ownedFd = fd; throw Object.assign(new Error(env.ORIGIN_SECRET), { code: 'EIO' }); });
  const e = caught(() => runBuild(f)); expect(e !== null && ownedFd !== undefined).toBe(true);
  expect(safe(String(e))).toBe(true); expect(String(e).includes('close=failed')).toBe(true);
  expect(String(e).includes('close_error=EIO')).toBe(true); expect(temps(f.edge)).toEqual([]);
  vi.restoreAllMocks(); if (ownedFd !== undefined) close(ownedFd);
});
