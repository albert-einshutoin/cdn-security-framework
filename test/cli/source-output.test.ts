import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { once } from 'node:events';
import { afterEach, describe, expect, test } from 'vitest';
import { createOfficialSarifValidator } from '../../src/scripts/official-sarif-test-validator';
import { sourceOutputGuard } from '../../src/bin/commands/source-output';
import { analyzeSourceAwareWorkspace } from '../../src/contract/source-aware-workspace';
import { finalizeSourceAwareOutput } from '../../src/contract/source-aware-output';

const cli = path.join(process.cwd(), 'bin/cli.js');
const roots: string[] = [];
const validateSarif = createOfficialSarifValidator(path.join(process.cwd(),
  'test/fixtures/sarif/sarif-schema-2.1.0.json'));

function workspace(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-source-output-'));
  roots.push(root);
  fs.writeFileSync(path.join(root, 'openapi.yaml'), 'openapi: 3.0.3\ninfo: {title: Synthetic, version: 1.0.0}\npaths: {}\n');
  fs.writeFileSync(path.join(root, 'policy.yml'), 'version: 2\ndefaults: {mode: enforce}\nrequest:\n  allow_methods: [GET]\n  block: {header_missing: []}\nroutes: []\nresponse_headers: {}\n');
  return root;
}

function invoke(root: string, extra: string[] = []) {
  return spawnSync(process.execPath, [cli, 'contract', 'source-diff', '--workspace-root', root,
    '--openapi', 'openapi.yaml', '--policy', 'policy.yml', '--target', 'aws',
    '--current-date', '2026-09-25', '--fail-on', 'never', ...extra], {
    cwd: root, encoding: 'utf8', timeout: 30_000, env: { ...process.env, NODE_PATH: '' },
  });
}

function sourceWorkspace(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-source-save-auth-'));
  roots.push(root);
  fs.cpSync(path.join(process.cwd(), 'examples/nestjs-contract'), root, { recursive: true });
  fs.mkdirSync(path.join(root, 'node_modules/@nestjs'), { recursive: true });
  fs.cpSync(path.join(root, 'stubs/nestjs-common'), path.join(root, 'node_modules/@nestjs/common'),
    { recursive: true });
  return root;
}

function invokeSource(root: string, extra: string[] = []) {
  return spawnSync(process.execPath, [cli, 'contract', 'source-diff', '--workspace-root', root,
    '--openapi', 'openapi.yaml', '--policy', 'policy/security.yml', '--target', 'aws',
    '--source', 'tsconfig.json', '--source-auth-config', 'token=opaquevalue123.yml',
    '--current-date', '2026-09-25', '--fail-on', 'never', ...extra], {
    cwd: root, encoding: 'utf8', timeout: 30_000, env: { ...process.env, NODE_PATH: '' },
  });
}

function invokeWithHook(root: string, extra: string[], hook: string) {
  const preload = path.join(root, 'test-preload.cjs');
  fs.writeFileSync(preload, hook);
  return spawnSync(process.execPath, [cli, 'contract', 'source-diff', '--workspace-root', root,
    '--openapi', 'openapi.yaml', '--policy', 'policy.yml', '--target', 'aws',
    '--current-date', '2026-09-25', '--fail-on', 'never', ...extra], {
    cwd: root, encoding: 'utf8', timeout: 30_000,
    env: { ...process.env, NODE_PATH: '', NODE_OPTIONS: `--require=${preload}` },
  });
}

async function preparedOutput(root: string, name = 'report.json') {
  const guard = sourceOutputGuard(root);
  for (const input of ['openapi.yaml', 'policy.yml']) guard.recordInputPath(input);
  const result = await analyzeSourceAwareWorkspace({ workspaceRoot: root, openapiPath: 'openapi.yaml',
    policyPath: 'policy.yml', target: 'aws', onInputPath: guard.recordInputPath });
  const finalized = finalizeSourceAwareOutput(result, { currentDate: '2026-09-25', failOn: 'never' });
  return { guard, target: guard.prepare(name, result, finalized.finalized!) };
}

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe('Experimental source-diff new-file output', () => {
  test.each(['text', 'json', 'sarif', 'summary'])('%s saves exactly the stdout bytes to one new file', (format) => {
    const root = workspace();
    const output = path.join(root, `report.${format}`);
    const stdout = invoke(root, ['--format', format]);
    expect(stdout.status).toBe(0);
    const saved = invoke(root, ['--format', format, '--out', path.basename(output)]);
    expect(saved.status).toBe(stdout.status);
    expect(saved.stdout).toBe('');
    expect(saved.stderr).toBe('');
    expect(fs.readFileSync(output, 'utf8')).toBe(stdout.stdout);
    expect(fs.statSync(output).mode & 0o077).toBe(0);
    if (format === 'json' || format === 'sarif') {
      expect(stdout.stdout.endsWith('\n')).toBe(true);
      const document = JSON.parse(fs.readFileSync(output, 'utf8'));
      if (format === 'sarif') expect(validateSarif(document)).toBe(true);
    }
  });

  test('saves a threshold report with exit 1 and a failed-stage partial report with exit 2', () => {
    const root = workspace();
    fs.writeFileSync(path.join(root, 'openapi.yaml'), 'openapi: 3.0.3\ninfo: {title: Synthetic, version: 1.0.0}\npaths:\n  /blocked:\n    post:\n      responses:\n        "200": {description: OK}\n');
    const threshold = invoke(root, ['--format', 'json', '--fail-on', 'warning']);
    expect(threshold.status).toBe(1);
    const savedThreshold = invoke(root, ['--format', 'json', '--fail-on', 'warning', '--out', 'threshold.json']);
    expect(savedThreshold.status).toBe(1);
    expect(savedThreshold.stdout).toBe('');
    expect(fs.readFileSync(path.join(root, 'threshold.json'), 'utf8')).toBe(threshold.stdout);

    fs.writeFileSync(path.join(root, 'openapi.yaml'), 'not: openapi\n');
    const partial = invoke(root, ['--format', 'json']);
    expect(partial.status).toBe(2);
    const savedPartial = invoke(root, ['--format', 'json', '--out', 'partial.json']);
    expect(savedPartial.status).toBe(2);
    expect(savedPartial.stdout).toBe('');
    expect(fs.readFileSync(path.join(root, 'partial.json'), 'utf8')).toBe(partial.stdout);
    expect(JSON.parse(partial.stdout).stages.declared.status).toBe('failed');
  });

  test('keeps independent Source-to-Policy findings when OpenAPI input fails safely', () => {
    const root = sourceWorkspace();
    fs.copyFileSync(path.join(root, 'security-analyzer.yml'), path.join(root, 'token=opaquevalue123.yml'));
    fs.unlinkSync(path.join(root, 'openapi.yaml'));
    const stdout = invokeSource(root, ['--format', 'json']);
    expect(stdout.status).toBe(2);
    const report = JSON.parse(stdout.stdout);
    expect(report.stages.declared.status).toBe('failed');
    expect(report.comparisons.implementedAllowed.status).toMatch(/complete|partial/);
    expect(report.findings.active.length).toBeGreaterThan(0);
    const saved = invokeSource(root, ['--format', 'json', '--out', 'partial.report']);
    expect(saved.status).toBe(2);
    expect(saved.stdout).toBe('');
    expect(fs.readFileSync(path.join(root, 'partial.report'), 'utf8')).toBe(stdout.stdout);
    expect(fs.existsSync(path.join(root, 'openapi.yaml'))).toBe(false);
  });

  test('rejects an existing file and never changes its bytes', () => {
    const root = workspace();
    const output = path.join(root, 'report.json');
    fs.writeFileSync(output, 'existing');
    const result = invoke(root, ['--format', 'json', '--out', 'report.json']);
    expect(result.status).toBe(2);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('SOURCE_DIFF_OUTPUT_EXISTS');
    expect(fs.readFileSync(output, 'utf8')).toBe('existing');
  });

  test('rejects every existing target type without changing inputs or links', async () => {
    const root = workspace();
    fs.writeFileSync(path.join(root, 'empty'), '');
    fs.symlinkSync('openapi.yaml', path.join(root, 'link'));
    fs.symlinkSync('missing-target', path.join(root, 'broken'));
    fs.linkSync(path.join(root, 'openapi.yaml'), path.join(root, 'hardlink'));
    fs.mkdirSync(path.join(root, 'directory'));
    const fifo = path.join(root, 'fifo');
    expect(spawnSync('mkfifo', [fifo]).status).toBe(0);
    const socket = net.createServer();
    socket.listen(path.join(root, 'socket'));
    await once(socket, 'listening');
    const original = fs.readFileSync(path.join(root, 'openapi.yaml'));
    try {
      for (const name of ['openapi.yaml', 'empty', 'link', 'broken', 'hardlink', 'directory', 'fifo', 'socket']) {
        const result = invoke(root, ['--out', name]);
        expect(result.status, name).toBe(2);
        expect(result.stdout).toBe('');
        expect(result.stderr).toMatch(/SOURCE_DIFF_OUTPUT_(EXISTS|PROTECTED)/);
      }
    } finally { await new Promise<void>((resolve) => socket.close(() => resolve())); }
    expect(fs.readFileSync(path.join(root, 'openapi.yaml'))).toEqual(original);
    expect(fs.lstatSync(path.join(root, 'broken')).isSymbolicLink()).toBe(true);
    expect(fs.statSync(path.join(root, 'empty')).size).toBe(0);
  });

  test('reserves missing declared and referenced input paths before file creation', () => {
    const root = workspace();
    fs.mkdirSync(path.join(root, 'refs'));
    const originalPolicy = fs.readFileSync(path.join(root, 'policy.yml'));
    const cases = [
      { extra: ['--openapi', 'missing.json'], output: 'missing.json' },
      { extra: ['--source', 'missing.tsconfig.json'], output: 'missing.tsconfig.json' },
    ];
    for (const { extra, output } of cases) {
      const result = invoke(root, [...extra, '--out', output]);
      expect(result.status, output).toBe(2);
      expect(result.stdout).toBe('');
      expect(result.stderr).toContain('SOURCE_DIFF_OUTPUT_PROTECTED');
      expect(fs.existsSync(path.join(root, output))).toBe(false);
    }
    const missingAuth = invoke(root, ['--source', 'missing.tsconfig.json', '--source-auth-config',
      'missing-auth.yml', '--out', 'missing-auth.yml']);
    expect(missingAuth.status).toBe(2);
    expect(fs.existsSync(path.join(root, 'missing-auth.yml'))).toBe(false);
    const missingExceptions = invoke(root, ['--exceptions', 'missing-exceptions.yml',
      '--out', 'missing-exceptions.yml']);
    expect(missingExceptions.status).toBe(2);
    expect(fs.existsSync(path.join(root, 'missing-exceptions.yml'))).toBe(false);

    fs.writeFileSync(path.join(root, 'openapi.yaml'), 'openapi: 3.0.3\ninfo: {title: Synthetic, version: 1.0.0}\npaths:\n  /x:\n    get:\n      parameters:\n        - $ref: "./refs/missing-ref.yaml#/components/parameters/Id"\n      responses:\n        "200": {description: OK}\n');
    fs.symlinkSync('refs', path.join(root, 'ref-alias'));
    const missingRef = invoke(root, ['--out', 'ref-alias/missing-ref.yaml']);
    expect(missingRef.status).toBe(2);
    expect(missingRef.stderr).toContain('SOURCE_DIFF_OUTPUT_PROTECTED');
    expect(fs.existsSync(path.join(root, 'refs/missing-ref.yaml'))).toBe(false);

    fs.writeFileSync(path.join(root, 'policy.yml'), `${originalPolicy.toString('utf8')}extends: missing-parent.yml\n`);
    const missingParent = invoke(root, ['--out', 'missing-parent.yml']);
    expect(missingParent.status).toBe(2);
    expect(missingParent.stderr).toContain('SOURCE_DIFF_OUTPUT_PROTECTED');
    expect(fs.existsSync(path.join(root, 'missing-parent.yml'))).toBe(false);
  });

  test('does not fill an unresolved Source import with a report', () => {
    const root = sourceWorkspace();
    fs.copyFileSync(path.join(root, 'security-analyzer.yml'), path.join(root, 'token=opaquevalue123.yml'));
    const source = path.join(root, 'src/users.controller.ts');
    fs.appendFileSync(source, '\nimport "./missing";\n');
    const before = createHash('sha256').update(fs.readFileSync(source)).digest('hex');
    const saved = invokeSource(root, ['--format', 'json', '--out', 'src/missing.ts']);
    expect(saved.status).toBe(2);
    expect(saved.stdout).toBe('');
    expect(saved.stderr).toContain('SOURCE_DIFF_OUTPUT_PROTECTED');
    expect(fs.existsSync(path.join(root, 'src/missing.ts'))).toBe(false);
    expect(createHash('sha256').update(fs.readFileSync(source)).digest('hex')).toBe(before);
  });

  test('does not fill a missing TypeScript project reference with a report', () => {
    const root = sourceWorkspace();
    fs.copyFileSync(path.join(root, 'security-analyzer.yml'), path.join(root, 'token=opaquevalue123.yml'));
    const configPath = path.join(root, 'tsconfig.json');
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    config.references = [{ path: './missing-reference.json' }];
    fs.writeFileSync(configPath, JSON.stringify(config));
    const saved = invokeSource(root, ['--format', 'json', '--out', 'missing-reference.json']);
    expect(saved.status).toBe(2);
    expect(saved.stdout).toBe('');
    expect(saved.stderr).toContain('SOURCE_DIFF_OUTPUT_PROTECTED');
    expect(fs.existsSync(path.join(root, 'missing-reference.json'))).toBe(false);
  });

  test('does not fill the target of a dangling TypeScript project reference symlink', () => {
    const root = sourceWorkspace();
    fs.copyFileSync(path.join(root, 'security-analyzer.yml'), path.join(root, 'token=opaquevalue123.yml'));
    fs.symlinkSync('actual-missing.json', path.join(root, 'missing-reference.json'));
    const configPath = path.join(root, 'tsconfig.json');
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    config.references = [{ path: './missing-reference.json' }];
    fs.writeFileSync(configPath, JSON.stringify(config));
    const saved = invokeSource(root, ['--format', 'json', '--out', 'actual-missing.json']);
    expect(saved.status).toBe(2);
    expect(saved.stdout).toBe('');
    expect(saved.stderr).toContain('SOURCE_DIFF_OUTPUT_PROTECTED');
    expect(fs.existsSync(path.join(root, 'actual-missing.json'))).toBe(false);
    expect(fs.lstatSync(path.join(root, 'missing-reference.json')).isSymbolicLink()).toBe(true);
  });

  test('refuses saving when a missing reference chain leaves and reenters the workspace', () => {
    const root = sourceWorkspace();
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-source-ref-chain-'));
    roots.push(outside);
    fs.copyFileSync(path.join(root, 'security-analyzer.yml'), path.join(root, 'token=opaquevalue123.yml'));
    fs.symlinkSync(path.join(outside, 'intermediate'), path.join(root, 'missing-reference.json'));
    fs.symlinkSync(path.join(root, 'actual-missing.json'), path.join(outside, 'intermediate'));
    const configPath = path.join(root, 'tsconfig.json');
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    config.references = [{ path: './missing-reference.json' }];
    fs.writeFileSync(configPath, JSON.stringify(config));
    const saved = invokeSource(root, ['--format', 'json', '--out', 'actual-missing.json']);
    expect(saved.status).toBe(3);
    expect(saved.stdout).toBe('');
    expect(saved.stderr).toContain('SOURCE_DIFF_OUTPUT_PROTECTION_INCOMPLETE');
    expect(fs.existsSync(path.join(root, 'actual-missing.json'))).toBe(false);
  });

  test('rejects outside, protected, aliased, and missing-parent destinations', () => {
    const root = workspace();
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-source-outside-'));
    roots.push(outside);
    for (const name of ['policy', 'dist', 'node_modules', '.git']) fs.mkdirSync(path.join(root, name));
    fs.symlinkSync('policy', path.join(root, 'policy-alias'));
    fs.symlinkSync(outside, path.join(root, 'outside-alias'));
    for (const name of ['../outside.json', 'policy/report.json', 'dist/report.json',
      'node_modules/report.json', '.git/report.json', 'policy-alias/report.json',
      'outside-alias/report.json', 'absent/report.json']) {
      const result = invoke(root, ['--out', name]);
      expect(result.status, name).toBe(2);
      expect(result.stdout).toBe('');
      expect(result.stderr).toMatch(/SOURCE_DIFF_OUTPUT_(PROTECTED|INVALID)/);
    }
    expect(fs.readdirSync(outside)).toEqual([]);
  });

  test.each(['open', 'write', 'close'])('fails closed on %s fault and removes its own partial file', async (kind) => {
    const root = workspace();
    const { guard, target } = await preparedOutput(root);
    const before = fs.readFileSync(path.join(root, 'openapi.yaml'));
    const previousDirectory = process.cwd();
    const originalOpen = fs.openSync;
    const originalWrite = fs.writeFileSync;
    const originalClose = fs.closeSync;
    try {
      if (kind === 'open') fs.openSync = ((...args: Parameters<typeof fs.openSync>) => {
        if (args[0] === 'report.json') throw new Error('synthetic open failure');
        return originalOpen(...args);
      }) as typeof fs.openSync;
      if (kind === 'write') fs.writeFileSync = ((...args: Parameters<typeof fs.writeFileSync>) => {
        if (typeof args[0] === 'number') {
          originalWrite(args[0], 'partial');
          throw new Error('synthetic write failure');
        }
        return originalWrite(...args);
      }) as typeof fs.writeFileSync;
      if (kind === 'close') fs.closeSync = ((descriptor: number) => {
        originalClose(descriptor);
        throw new Error('synthetic close failure');
      }) as typeof fs.closeSync;
      expect(() => guard.write(target, 'complete report')).toThrow('SOURCE_DIFF_OUTPUT_WRITE_FAILED');
    } finally {
      fs.openSync = originalOpen;
      fs.writeFileSync = originalWrite;
      fs.closeSync = originalClose;
    }
    expect(process.cwd()).toBe(previousDirectory);
    expect(fs.existsSync(path.join(root, 'report.json'))).toBe(false);
    expect(fs.readFileSync(path.join(root, 'openapi.yaml'))).toEqual(before);
  });

  test('recovers its newly created file after a transient descriptor identity fault', async () => {
    const root = workspace();
    const { guard, target } = await preparedOutput(root);
    const original = fs.fstatSync;
    let calls = 0;
    try {
      fs.fstatSync = ((descriptor: number) => {
        if (calls++ === 0) throw new Error('synthetic fstat failure');
        return original(descriptor);
      }) as typeof fs.fstatSync;
      expect(() => guard.write(target, 'report')).toThrow('SOURCE_DIFF_OUTPUT_WRITE_FAILED');
    } finally { fs.fstatSync = original; }
    expect(calls).toBeGreaterThanOrEqual(2);
    expect(fs.existsSync(path.join(root, 'report.json'))).toBe(false);
  });

  test('never removes a different file when cleanup loses its original output name', async () => {
    const root = workspace();
    const { guard, target } = await preparedOutput(root);
    const originalWrite = fs.writeFileSync;
    let replaced = false;
    try {
      fs.writeFileSync = ((...args: Parameters<typeof fs.writeFileSync>) => {
        if (typeof args[0] === 'number' && !replaced) {
          replaced = true;
          fs.renameSync('report.json', 'created-partial.json');
          originalWrite('report.json', 'replacement');
          throw new Error('synthetic replacement');
        }
        return originalWrite(...args);
      }) as typeof fs.writeFileSync;
      expect(() => guard.write(target, 'complete report')).toThrow('SOURCE_DIFF_OUTPUT_WRITE_FAILED');
    } finally { fs.writeFileSync = originalWrite; }
    expect(fs.readFileSync(path.join(root, 'report.json'), 'utf8')).toBe('replacement');
    expect(fs.existsSync(path.join(root, 'created-partial.json'))).toBe(true);
  });

  test('reports cleanup failure and leaves a detectable partial file', async () => {
    const root = workspace();
    const { guard, target } = await preparedOutput(root);
    const originalWrite = fs.writeFileSync;
    const originalUnlink = fs.unlinkSync;
    try {
      fs.writeFileSync = ((...args: Parameters<typeof fs.writeFileSync>) => {
        if (typeof args[0] === 'number') {
          originalWrite(args[0], 'partial');
          throw new Error('synthetic write failure');
        }
        return originalWrite(...args);
      }) as typeof fs.writeFileSync;
      fs.unlinkSync = ((name: fs.PathLike) => {
        if (name === 'report.json') throw new Error('synthetic cleanup failure');
        return originalUnlink(name);
      }) as typeof fs.unlinkSync;
      expect(() => guard.write(target, 'complete report')).toThrow('SOURCE_DIFF_OUTPUT_WRITE_FAILED');
    } finally { fs.writeFileSync = originalWrite; fs.unlinkSync = originalUnlink; }
    expect(fs.readFileSync(path.join(root, 'report.json'), 'utf8')).toBe('partial');
  });

  test('rejects workspace and parent alias retargets after validation', async () => {
    const root = workspace();
    const holder = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-output-alias-'));
    roots.push(holder);
    const outside = path.join(holder, 'outside');
    fs.mkdirSync(outside);
    const alias = path.join(holder, 'workspace');
    fs.symlinkSync(root, alias);
    const workspaceGuard = sourceOutputGuard(alias);
    workspaceGuard.recordInputPath('openapi.yaml');
    workspaceGuard.recordInputPath('policy.yml');
    const result = await analyzeSourceAwareWorkspace({ workspaceRoot: alias,
      openapiPath: 'openapi.yaml', policyPath: 'policy.yml', target: 'aws',
      onInputPath: workspaceGuard.recordInputPath });
    const finalized = finalizeSourceAwareOutput(result, { currentDate: '2026-09-25', failOn: 'never' });
    const workspaceTarget = workspaceGuard.prepare('report.json', result, finalized.finalized!);
    fs.unlinkSync(alias);
    fs.symlinkSync(outside, alias);
    expect(() => workspaceGuard.write(workspaceTarget, 'report')).toThrow('SOURCE_DIFF_OUTPUT_WRITE_FAILED');
    expect(fs.existsSync(path.join(root, 'report.json'))).toBe(false);
    expect(fs.readdirSync(outside)).toEqual([]);

    const parent = path.join(root, 'reports-real');
    fs.mkdirSync(parent);
    const parentAlias = path.join(root, 'reports');
    fs.symlinkSync(parent, parentAlias);
    const { guard, target } = await preparedOutput(root, 'reports/report.json');
    fs.unlinkSync(parentAlias);
    fs.symlinkSync(outside, parentAlias);
    expect(() => guard.write(target, 'report')).toThrow('SOURCE_DIFF_OUTPUT_WRITE_FAILED');
    expect(fs.readdirSync(parent)).toEqual([]);
    expect(fs.readdirSync(outside)).toEqual([]);
  });

  test('detects a pinned parent moved out of the workspace before opening', async () => {
    const root = workspace();
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-output-move-'));
    roots.push(outside);
    fs.mkdirSync(path.join(root, 'reports'));
    const { guard, target } = await preparedOutput(root, 'reports/report.json');
    const previousDirectory = process.cwd();
    const originalChdir = process.chdir;
    let moved = false;
    try {
      process.chdir = ((directory: string) => {
        originalChdir(directory);
        if (directory === target.parent && !moved) {
          moved = true;
          fs.renameSync(target.parent, path.join(outside, 'moved'));
        }
      }) as typeof process.chdir;
      expect(() => guard.write(target, 'report')).toThrow('SOURCE_DIFF_OUTPUT_WRITE_FAILED');
    } finally { process.chdir = originalChdir; }
    expect(process.cwd()).toBe(previousDirectory);
    expect(fs.readdirSync(path.join(outside, 'moved'))).toEqual([]);
  });

  test('preserves Source, auth, policy, and OpenAPI input bytes and report privacy', () => {
    const root = sourceWorkspace();
    fs.copyFileSync(path.join(root, 'security-analyzer.yml'), path.join(root, 'token=opaquevalue123.yml'));
    const inputs = ['openapi.yaml', 'policy/security.yml', 'tsconfig.json', 'tsconfig.base.json',
      'packages/shared/tsconfig.json', 'src/base.controller.ts', 'src/decorators.ts',
      'src/guards.ts', 'src/runtime-prefix.ts', 'src/users.controller.ts',
      'node_modules/@nestjs/common/package.json', 'node_modules/@nestjs/common/index.js',
      'node_modules/@nestjs/common/index.d.ts', 'token=opaquevalue123.yml'];
    const digest = (name: string) => createHash('sha256').update(fs.readFileSync(path.join(root, name)))
      .digest('hex');
    const before = inputs.map(digest);
    const stdout = invokeSource(root, ['--format', 'json']);
    expect(stdout.status).toBe(0);
    const saved = invokeSource(root, ['--format', 'json', '--out', 'report.json']);
    expect(saved.status).toBe(0);
    expect(saved.stdout).toBe('');
    expect(saved.stderr).toBe('');
    const content = fs.readFileSync(path.join(root, 'report.json'), 'utf8');
    expect(content).toBe(stdout.stdout);
    expect(content).not.toContain('opaquevalue123');
    expect(content).not.toContain('token%3Dopaquevalue123');
    expect(content).not.toContain(root);
    expect(inputs.map(digest)).toEqual(before);
  });

  test('does not import the new writer for help, version, contract diff, or no-out Source', () => {
    const root = workspace();
    const preload = path.join(root, 'reject-writer.cjs');
    fs.writeFileSync(preload, `const Module = require('node:module');
const load = Module._load;
Module._load = function(request, parent, isMain) {
  if (request.endsWith('/source-output') || request.endsWith('/source-output.js')) {
    throw Error('UNEXPECTED_SOURCE_OUTPUT_LOAD');
  }
  return load.call(this, request, parent, isMain);
};\n`);
    const run = (args: string[]) => spawnSync(process.execPath, [cli, ...args], {
      cwd: root, encoding: 'utf8', timeout: 30_000,
      env: { ...process.env, NODE_PATH: '', NODE_OPTIONS: `--require=${preload}` },
    });
    for (const args of [
      ['--version'], ['--help'], ['contract', 'diff', '--help'], ['contract', 'source-diff', '--help'],
      ['contract', 'source-diff', '--workspace-root', root, '--openapi', 'openapi.yaml',
        '--policy', 'policy.yml', '--target', 'aws', '--current-date', '2026-09-25',
        '--fail-on', 'never', '--format', 'json'],
    ]) {
      const result = run(args);
      expect(result.error).toBeUndefined();
      expect(result.signal).toBeNull();
      expect(result.status, result.stderr).toBe(0);
      expect(result.stderr).not.toContain('UNEXPECTED_SOURCE_OUTPUT_LOAD');
    }
  });

  test('reports fixed exit 3 for a real CLI write failure and leaves no partial output', () => {
    const root = workspace();
    const result = invokeWithHook(root, ['--format', 'json', '--out', 'report.json'], `
const fs = require('node:fs');
const write = fs.writeFileSync;
fs.writeFileSync = function(file, value, ...rest) {
  if (typeof file === 'number') { write(file, 'partial'); throw Error('synthetic-private-write'); }
  return write(file, value, ...rest);
};`);
    expect(result.status).toBe(3);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('SOURCE_DIFF_OUTPUT_WRITE_FAILED');
    expect(result.stderr).not.toContain('synthetic-private-write');
    expect(fs.existsSync(path.join(root, 'report.json'))).toBe(false);
  });

  test('refuses file save when an internal stage has insufficient input protection', () => {
    const root = workspace();
    const hook = `const Module=require('node:module');const load=Module._load;
Module._load=function(request,parent,isMain){const result=load.call(this,request,parent,isMain);
  if(request.endsWith('/openapi/inspect')) return {...result,
    inspectOpenApiForCli:()=>{throw Error('synthetic-private-internal')}};
  return result;};`;
    const stdout = invokeWithHook(root, ['--format', 'json'], hook);
    expect(stdout.status).toBe(3);
    expect(JSON.parse(stdout.stdout).stages.declared.status).toBe('failed');
    const saved = invokeWithHook(root, ['--format', 'json', '--out', 'report.json'], hook);
    expect(saved.status).toBe(3);
    expect(saved.stdout).toBe('');
    expect(saved.stderr).toContain('SOURCE_DIFF_OUTPUT_PROTECTION_INCOMPLETE');
    expect(saved.stderr).not.toContain('synthetic-private-internal');
    expect(fs.existsSync(path.join(root, 'report.json'))).toBe(false);
  });

  test('does not create a file when the selected reporter fails before rendering', () => {
    const root = workspace();
    const result = invokeWithHook(root, ['--format', 'sarif', '--out', 'report.sarif'], `
const Module=require('node:module');const load=Module._load;
Module._load=function(request,parent,isMain){const result=load.call(this,request,parent,isMain);
  if(request.endsWith('/reporters/sarif')) return {...result,
    renderSourceAwareSarif:()=>{throw Error('synthetic-private-render')}};
  return result;};`);
    expect(result.status).toBe(3);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('SOURCE_DIFF_REPORTER_FAILED');
    expect(result.stderr).not.toContain('synthetic-private-render');
    expect(fs.existsSync(path.join(root, 'report.sarif'))).toBe(false);
  });
});
