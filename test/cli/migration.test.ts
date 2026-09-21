import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { expect, test } from 'vitest';
const require = createRequire(import.meta.url);
const { migratePolicy } = require('../../lib');
const original = 'version: 1\nmetadata: { owner: team, description: "keep ${ENV}" }\nrequest: { allow_methods: [HEAD, GET] }\nresponse_headers: {}\n';
const hash = (p: string) => createHash('sha256').update(fs.readFileSync(p)).digest('hex');
function fixture(action: (root: string, input: string) => void) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'migration-'));
  const input = path.join(root, 'policy.yml'); fs.writeFileSync(input, original);
  try { action(root, input); } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
test('M01 default preview migrates v1 to v2 without changing the source', () => fixture((root, input) => {
  const before = hash(input); const result = migratePolicy({ policyPath: input });
  expect(result.ok).toBe(true); expect(result.toVersion).toBe(2); expect(result.migrated).toBe(true);
  expect(result.policy).toEqual({ version: 2, metadata: { owner: 'team', description: 'keep ${ENV}' }, request: { allow_methods: ['HEAD', 'GET'] }, response_headers: {} });
  expect(hash(input)).toBe(before); expect(fs.readFileSync(input, 'utf8')).toBe(original);
  expect(fs.readdirSync(root)).toEqual(['policy.yml']);
}));

const yaml = require('js-yaml');
const { transformPolicy } = require('../../lib/migration-transform');
const { lintPolicy, compile } = require('../../lib');
const { spawnSync } = require('node:child_process');
import { vi } from 'vitest';
const cli = path.resolve('bin/cli.js');
function cliRun(root: string, input: string, args: string[] = []) {
  const r = spawnSync(process.execPath, [cli, 'migrate', '--policy', input, ...args], { cwd: root, encoding: 'utf8', timeout: 15000 });
  expect(r.error).toBeUndefined(); expect(r.signal).toBeNull(); return r;
}
const base = () => yaml.load(original);
function unchanged(input: string, before: string, content: string) { expect(hash(input)).toBe(before); expect(fs.readFileSync(input, 'utf8')).toBe(content); }
for (const target of [undefined, 'aws', 'cloudflare']) {
  test(`M01 preview target=${target}`, () => fixture((root, input) => {
    const before = hash(input); const r = migratePolicy({ policyPath: input, target });
    expect(r).toMatchObject({ ok: true, exitCode: 0, saved: false, migrated: true });
    unchanged(input, before, original); expect(fs.readdirSync(root)).toEqual(['policy.yml']);
  }));
}
test('M02 save retains exact backup, permissions, and supports lint/build on both targets', () => fixture((root, input) => {
  fs.chmodSync(input, 0o640); const before = hash(input);
  const r = migratePolicy({ policyPath: input, write: true }); expect(r).toMatchObject({ ok: true, saved: true, exitCode: 0 });
  expect(hash(`${input}.v1.bak`)).toBe(before); expect(fs.readFileSync(`${input}.v1.bak`, 'utf8')).toBe(original);
  expect(fs.statSync(input).mode & 0o777).toBe(0o640); expect(fs.statSync(`${input}.v1.bak`).mode & 0o777).toBe(0o600);
  expect(yaml.load(fs.readFileSync(input, 'utf8'))).toEqual(r.policy); expect(lintPolicy({ policyPath: input }).ok).toBe(true);
  for (const target of ['aws', 'cloudflare']) expect(compile({ policyPath: input, outDir: path.join(root, target), target }).ok).toBe(true);
  expect(fs.readdirSync(root).filter((n) => n.endsWith('.tmp'))).toEqual([]);
}));
test('M03 pure transformation is deterministic, preserves settings and does not mutate object', () => {
  const input = base(); input.origin = { auth: { type: 'custom_header', header: 'x-origin', secret_env: 'SECRET_ENV' } };
  const before = structuredClone(input); const a = transformPolicy(input); const b = transformPolicy(input);
  expect(a).toEqual(b); expect(input).toEqual(before); expect(a.policy).toEqual({ ...before, version: 2 });
});
test('M03 YAML aliases preserve values but not source formatting', () => fixture((root, input) => {
  const text = 'version: 1\nproject: &name "keep text"\nmetadata: { description: *name }\nrequest: { allow_methods: [HEAD, GET] }\nresponse_headers: {}\n';
  fs.writeFileSync(input, text); const before = hash(input); const r = migratePolicy({ policyPath: input, write: true });
  expect(r.ok).toBe(true); expect(r.policy.metadata.description).toBe('keep text'); expect(hash(`${input}.v1.bak`)).toBe(before);
}));
for (const difficulty of [1, 4, 5, 6]) {
  test(`M04 difficulty ${difficulty}`, () => fixture((root, input) => {
    const p = base(); p.firewall = { challenge: { enabled: true, difficulty } }; const content = yaml.dump(p); fs.writeFileSync(input, content);
    const before = hash(input); const r = migratePolicy({ policyPath: input, target: 'cloudflare' });
    expect(r.exitCode).toBe(difficulty > 4 ? 2 : 0); expect(r.ok).toBe(difficulty <= 4);
    if (difficulty > 4) expect(r.errors.join()).toContain('firewall.challenge.difficulty');
    unchanged(input, before, content); expect(fs.readdirSync(root)).toEqual(['policy.yml']);
  }));
}
for (const kind of ['nonce', 'jwt', 'signed_url']) for (const target of [undefined, 'aws', 'cloudflare']) {
  test(`M05 ${kind} target=${target}`, () => fixture((root, input) => {
    const p = base();
    if (kind === 'nonce') p.response_headers.csp_nonce = true;
    else p.routes = [{ name: 'protected', match: { path_prefixes: ['/private'] }, auth_gate: { type: kind, secret_env: 'MIGRATION_TEST_SECRET', ...(kind === 'jwt' ? { algorithm: 'HS256' } : {}) } }];
    const content = yaml.dump(p); fs.writeFileSync(input, content); const before = hash(input);
    const r = migratePolicy({ policyPath: input, target }); expect(r.exitCode).toBe(target === 'cloudflare' ? 0 : 2);
    if (target === 'cloudflare') {
      expect(r.policy).toEqual({ ...p, version: 2 });
      const converted = path.join(root, 'converted.yml'); fs.writeFileSync(converted, yaml.dump(r.policy));
      const prior = process.env.MIGRATION_TEST_SECRET; process.env.MIGRATION_TEST_SECRET = 'test-only-migration-secret';
      try {
        expect(compile({ policyPath: converted, target: 'cloudflare', outDir: path.join(root, 'cf') }).ok).toBe(true);
        expect(compile({ policyPath: converted, target: 'aws', outDir: path.join(root, 'aws') }).ok).toBe(false);
      } finally { if (prior === undefined) delete process.env.MIGRATION_TEST_SECRET; else process.env.MIGRATION_TEST_SECRET = prior; }
    }
    unchanged(input, before, content);
  }));
}
for (const [version, to, exit] of [[undefined, 2, 1], ['1', 2, 1], [null, 2, 1], [3, 3, 2], [2, 1, 1], [1, 'bad-secret', 1], [1, 9, 2], [1, '2.0', 1]]) {
  test(`M06 version ${version} to ${to}`, () => fixture((root, input) => {
    const p = base(); if (version === undefined) delete p.version; else p.version = version;
    const content = yaml.dump(p); fs.writeFileSync(input, content); const before = hash(input);
    const r = migratePolicy({ policyPath: input, toVersion: to, write: true }); expect(r.exitCode).toBe(exit); expect(r.ok).toBe(false);
    expect(JSON.stringify(r)).not.toContain('bad-secret'); unchanged(input, before, content); expect(fs.readdirSync(root)).toEqual(['policy.yml']);
  }));
}
for (const version of [1, 2]) for (const valid of [true, false]) {
  test(`M07 version${version} valid=${valid} noop`, () => fixture((root, input) => {
    const p = base(); p.version = version; if (!valid) p.unrecognized = 'secret-never-log';
    const content = yaml.dump(p); fs.writeFileSync(input, content); const before = hash(input);
    const r = migratePolicy({ policyPath: input, toVersion: version, write: true }); expect(r.ok).toBe(valid); expect(r.noop).toBe(valid); expect(r.saved).toBe(false);
    expect(JSON.stringify(r)).not.toContain('secret-never-log'); unchanged(input, before, content); expect(fs.readdirSync(root)).toEqual(['policy.yml']);
  }));
}
for (const [label, content] of [
  ['bad-yaml', 'version: 1\nsecret: [secret-never-log'],
  ['duplicate', original + 'version: 1\n'],
  ['special-key', original + '__proto__: { secret: secret-never-log }\n'],
  ['cycle', 'version: 1\nproject: &a [*a]\n'],
  ['deep', 'version: 1\nx: ' + '['.repeat(80) + '0' + ']'.repeat(80)],
  ['large', original + '#'.repeat(1_048_576)],
]) test(`M08 ${label}`, () => fixture((root, input) => {
  fs.writeFileSync(input, content); const before = hash(input); const r = cliRun(root, input, ['--write']);
  expect(r.status).toBe(1); expect(r.stdout).toBe(''); expect(r.stderr).toMatch(/^\[ERROR\] MIGRATION_[A-Z_]+\n$/);
  expect(r.stderr).not.toContain('secret-never-log'); expect(r.stderr).not.toContain(root); unchanged(input, before, content);
  expect(fs.readdirSync(root)).toEqual(['policy.yml']);
}));
test('M08 invalid UTF8 does not replace configuration text', () => fixture((root, input) => {
  fs.writeFileSync(input, Buffer.concat([Buffer.from(original + 'project: '), Buffer.from([0xff])])); const before = hash(input);
  expect(migratePolicy({ policyPath: input, write: true }).ok).toBe(false); expect(hash(input)).toBe(before);
}));
test('M09 references stop without reading or flattening dependencies', () => fixture((root, input) => {
  const parent = path.join(root, 'parent.yml'); fs.writeFileSync(parent, original); const content = original + 'extends: parent.yml\n';
  fs.writeFileSync(input, content); const before = hash(input), parentHash = hash(parent);
  expect(migratePolicy({ policyPath: input, write: true }).exitCode).toBe(2); unchanged(input, before, content); expect(hash(parent)).toBe(parentHash);
}));
test('M09 core rejects mixed v2 root and v1 dependency', () => fixture((root, input) => {
  const parent = path.join(root, 'parent.yml'); fs.writeFileSync(parent, original);
  fs.writeFileSync(input, original.replace('version: 1', 'version: 2') + 'extends: parent.yml\n');
  expect(lintPolicy({ policyPath: input }).ok).toBe(false);
  fs.writeFileSync(parent, original.replace('version: 1', 'version: 2')); expect(lintPolicy({ policyPath: input }).ok).toBe(true);
}));
for (const kind of ['existing-backup', 'backup-symlink', 'backup-hardlink', 'input-symlink', 'input-hardlink']) {
  test(`M10 ${kind}`, () => fixture((root, input) => {
    const backup = `${input}.v1.bak`, alias = path.join(root, 'alias.yml');
    if (kind === 'existing-backup') fs.writeFileSync(backup, 'keep backup');
    if (kind === 'backup-symlink') fs.symlinkSync(input, backup);
    if (kind === 'backup-hardlink') fs.linkSync(input, backup);
    if (kind === 'input-symlink') fs.symlinkSync(input, alias);
    if (kind === 'input-hardlink') fs.linkSync(input, alias);
    const before = hash(input); const r = migratePolicy({ policyPath: kind === 'input-symlink' ? alias : input, write: true });
    expect(r.exitCode).toBe(1); unchanged(input, before, original);
    if (kind === 'existing-backup') expect(fs.readFileSync(backup, 'utf8')).toBe('keep backup');
    expect(fs.readdirSync(root).filter((n) => n.endsWith('.tmp'))).toEqual([]);
  }));
}
test('M10 trusted parent symlink saves correct policy and backup', () => fixture((root, input) => {
  const alias = path.join(root, 'alias'); fs.symlinkSync(root, alias, 'dir');
  const before = hash(input); expect(migratePolicy({ policyPath: path.join(alias, 'policy.yml'), write: true }).ok).toBe(true);
  expect(hash(`${input}.v1.bak`)).toBe(before);
}));
for (const stage of ['write', 'rename', 'open']) {
  test(`M11 ${stage} failure preserves original and cleans temporary files`, () => fixture((root, input) => {
    const before = hash(input); let fired = false;
    const name = stage === 'write' ? 'writeFileSync' : stage === 'rename' ? 'renameSync' : 'openSync';
    const originalFn = fs[name] as Function;
    const spy = vi.spyOn(fs, name as any).mockImplementation((...args: any[]) => {
      const hit = stage === 'write' ? typeof args[0] === 'number' : stage === 'rename' || String(args[0]).endsWith('.v1.bak');
      if (hit) { fired = true; throw Object.assign(new Error('secret-never-log'), { code: stage === 'write' ? 'ENOSPC' : 'EACCES' }); }
      return originalFn(...args);
    });
    let r; try { r = migratePolicy({ policyPath: input, write: true }); } finally { spy.mockRestore(); }
    expect(fired).toBe(true); expect(r.exitCode).toBe(1); expect(JSON.stringify(r)).not.toContain('secret-never-log');
    unchanged(input, before, original); expect(fs.readdirSync(root)).toEqual(['policy.yml']);
  }));
}
for (const change of ['identity', 'content', 'permission']) {
  test(`M11 input ${change} change before commit is rejected`, () => fixture((root, input) => {
    const before = hash(input); const write = fs.writeFileSync; let fired = false;
    const spy = vi.spyOn(fs, 'writeFileSync').mockImplementation((...args: any[]) => {
      (write as Function)(...args);
      if (!fired && typeof args[0] === 'number') {
        fired = true;
        if (change === 'identity') { fs.renameSync(input, path.join(root, 'moved.yml')); write(input, original); }
        if (change === 'content') write(input, original + '# external edit\n');
        if (change === 'permission') fs.chmodSync(input, 0o400);
      }
    });
    let r; try { r = migratePolicy({ policyPath: input, write: true }); } finally { spy.mockRestore(); }
    expect(fired).toBe(true); expect(r).toMatchObject({ ok: false, exitCode: 1 });
    if (change === 'content') expect(fs.readFileSync(input, 'utf8')).toBe(original + '# external edit\n');
    else unchanged(input, before, original);
    if (change === 'identity') expect(hash(path.join(root, 'moved.yml'))).toBe(before);
    expect(fs.readdirSync(root).filter((n) => n.endsWith('.tmp') || n.endsWith('.bak'))).toEqual([]);
  }));
}
test('M12 CLI preview and write match API, with fixed outputs', () => fixture((root, input) => {
  const before = hash(input); const preview = cliRun(root, input);
  expect(preview.status).toBe(0); expect(preview.stderr).toBe(''); expect(preview.stdout).toContain('MIGRATION_PREVIEW'); unchanged(input, before, original);
  const saved = cliRun(root, input, ['--write']); expect(saved.status).toBe(0); expect(saved.stdout).toContain('MIGRATION_SAVED'); expect(saved.stderr).toBe('');
  expect(hash(`${input}.v1.bak`)).toBe(before);
}));
for (const args of [['--to'], ['--secret-never-log'], ['--target', 'secret-never-log']]) {
  test(`M12 CLI argument failure ${args[0]}`, () => fixture((root, input) => {
    const before = hash(input); const r = cliRun(root, input, args); expect(r.status).toBe(1); expect(r.stdout).toBe('');
    expect(r.stderr).not.toContain('secret-never-log'); expect(r.stderr).not.toContain(root); unchanged(input, before, original);
  }));
}
test('M12 API never calls process.exit on invalid arguments', () => {
  const spy = vi.spyOn(process, 'exit').mockImplementation(() => { throw new Error('must not exit'); });
  try { for (const input of [null, {}, { policyPath: 42 }, { policyPath: 'missing', write: 'yes' }]) expect(migratePolicy(input).ok).toBe(false); expect(spy).not.toHaveBeenCalled(); }
  finally { spy.mockRestore(); }
});
test('M09 core lint/build reject unmigrated v1', () => fixture((root, input) => {
  const before = hash(input); expect(lintPolicy({ policyPath: input }).ok).toBe(false);
  expect(compile({ policyPath: input, outDir: path.join(root, 'out'), target: 'aws' }).ok).toBe(false);
  unchanged(input, before, original);
}));
for (const kind of ['symlink', 'hardlink']) {
  test(`M11 staging replaced by input ${kind} is not written`, () => fixture((root, input) => {
    const before = hash(input); const write = fs.writeFileSync; let writes = 0;
    const spy = vi.spyOn(fs, 'writeFileSync').mockImplementation((...args: any[]) => {
      (write as Function)(...args);
      if (typeof args[0] === 'number' && ++writes === 2) {
        const stage = path.join(root, fs.readdirSync(root).find((n) => n.endsWith('.tmp'))!);
        fs.renameSync(stage, path.join(root, 'external-retained-stage'));
        if (kind === 'symlink') fs.symlinkSync(input, stage); else fs.linkSync(input, stage);
      }
    });
    let r; try { r = migratePolicy({ policyPath: input, write: true }); } finally { spy.mockRestore(); }
    expect(writes).toBe(2); expect(r.ok).toBe(false); unchanged(input, before, original);
    expect(fs.existsSync(`${input}.v1.bak`)).toBe(false);
    // The replacement is not owned by the writer and must not be unlinked as cleanup.
    expect(fs.readdirSync(root).some((n) => n.endsWith('.tmp'))).toBe(true);
  }));
}
test('M11 parent moved during backup creation is rejected and owned backup cleaned', () => fixture((root) => {
  const parent = path.join(root, 'work'), moved = path.join(root, 'moved'); fs.mkdirSync(parent);
  const input = path.join(parent, 'policy.yml'); fs.writeFileSync(input, original); const before = hash(input);
  const write = fs.writeFileSync; let fired = false;
  const spy = vi.spyOn(fs, 'writeFileSync').mockImplementation((...args: any[]) => {
    (write as Function)(...args);
    if (!fired && typeof args[0] === 'number') { fired = true; fs.renameSync(parent, moved); fs.mkdirSync(parent); write(input, original); }
  });
  let r; try { r = migratePolicy({ policyPath: input, write: true }); } finally { spy.mockRestore(); }
  expect(fired).toBe(true); expect(r.ok).toBe(false); unchanged(input, before, original);
  expect(hash(path.join(moved, 'policy.yml'))).toBe(before); expect(fs.readdirSync(moved)).toEqual(['policy.yml']);
}));
test('M11 input retargeted to a symlink after reading is refused', () => fixture((root, input) => {
  const before = hash(input); const write = fs.writeFileSync; let fired = false;
  const spy = vi.spyOn(fs, 'writeFileSync').mockImplementation((...args: any[]) => {
    (write as Function)(...args);
    if (!fired && typeof args[0] === 'number') { fired = true; const moved = path.join(root, 'moved.yml'); fs.renameSync(input, moved); fs.symlinkSync(moved, input); }
  });
  let r; try { r = migratePolicy({ policyPath: input, write: true }); } finally { spy.mockRestore(); }
  expect(fired).toBe(true); expect(r.ok).toBe(false); unchanged(input, before, original);
  expect(fs.existsSync(`${input}.v1.bak`)).toBe(false);
}));
test('M03 non-JSON object decorations and accessors are rejected without evaluation', () => {
  const p = base(); let called = false; Object.defineProperty(p, 'secret', { enumerable: true, get() { called = true; return 'secret'; } });
  expect(transformPolicy(p).ok).toBe(false); expect(called).toBe(false);
  const q = base(); q.request.allow_methods.extra = 'hidden'; expect(transformPolicy(q).ok).toBe(false);
});
test('M11 cleanup denial is explicit while input remains uncommitted', () => fixture((root, input) => {
  const before = hash(input);
  const rename = vi.spyOn(fs, 'renameSync').mockImplementation(() => { throw new Error('commit failed'); });
  const unlink = vi.spyOn(fs, 'unlinkSync').mockImplementation(() => { throw new Error('cleanup failed'); });
  let r; try { r = migratePolicy({ policyPath: input, write: true }); } finally { rename.mockRestore(); unlink.mockRestore(); }
  expect(r.errors).toEqual(['MIGRATION_SAVE_FAILED_CLEANUP_INCOMPLETE']); unchanged(input, before, original);
  expect(fs.existsSync(`${input}.v1.bak`)).toBe(true);
}));
test('M11 post-commit cleanup warning does not claim an unchanged input', () => fixture((root, input) => {
  const before = hash(input), rename = fs.renameSync, lstat = fs.lstatSync; let committed = false;
  const renameSpy = vi.spyOn(fs, 'renameSync').mockImplementation((a, b) => { rename(a, b); committed = true; });
  const statSpy = vi.spyOn(fs, 'lstatSync').mockImplementation(((file: any, ...rest: any[]) => {
    if (committed && String(file).endsWith('.tmp')) throw Object.assign(new Error('cleanup failed'), { code: 'EACCES' });
    return (lstat as Function)(file, ...rest);
  }) as any);
  let r; try { r = migratePolicy({ policyPath: input, write: true }); } finally { renameSpy.mockRestore(); statSpy.mockRestore(); }
  expect(r).toMatchObject({ ok: true, saved: true, warnings: ['MIGRATION_CLEANUP_INCOMPLETE'] });
  expect(hash(input)).not.toBe(before); expect(hash(`${input}.v1.bak`)).toBe(before);
}));
