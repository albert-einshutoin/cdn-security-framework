import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';

import { loadSourceAuthConfig } from '../../src/bin/commands/source-auth-config';
import { formatSourceAwarePreviewJson } from '../../src/contract/source-aware-finalizer';
import { finalizeSourceAwareOutput } from '../../src/contract/source-aware-output';
import { analyzeSourceAwareWorkspace } from '../../src/contract/source-aware-workspace';
import { DEFAULT_SOURCE_ANALYSIS_LIMITS } from '../../src/source-analysis';
import { runNestJsSourceAnalysisInternal } from '../../src/source/nestjs/analyzer';

const roots: string[] = [];
const cli = path.join(process.cwd(), 'bin/cli.js');
const valid = 'public_decorators: [Public]\nroles_decorators: [Roles]\nguard_mappings:\n  JwtAuthGuard: {auth_kind: bearer}\n';

function workspace(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-auth-config-'));
  roots.push(root);
  return root;
}

function file(root: string, name: string, content: string | Buffer): string {
  const target = path.join(root, name);
  fs.writeFileSync(target, content);
  return target;
}

function invoke(root: string, extra: string[] = []) {
  return spawnSync(process.execPath, [cli, 'contract', 'source-diff', '--workspace-root', root,
    '--openapi', 'openapi.yaml', '--policy', 'policy/security.yml', '--target', 'aws',
    '--current-date', '2026-09-25', ...extra], {
    cwd: os.tmpdir(), encoding: 'utf8', env: { ...process.env, NODE_PATH: '' }, timeout: 30_000,
  });
}

function example(): string {
  const root = workspace();
  fs.cpSync(path.join(process.cwd(), 'examples/nestjs-contract'), root, { recursive: true });
  fs.mkdirSync(path.join(root, 'node_modules/@nestjs'), { recursive: true });
  fs.cpSync(path.join(root, 'stubs/nestjs-common'), path.join(root, 'node_modules/@nestjs/common'), { recursive: true });
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe('Experimental Source auth data file', () => {
  test('loads one bounded YAML or JSON snapshot and preserves raw identity', () => {
    const root = workspace();
    file(root, 'auth.yml', valid);
    file(root, 'auth.json', JSON.stringify({ guard_mappings: { JwtAuthGuard: { auth_kind: 'bearer' } },
      roles_decorators: ['Roles'], public_decorators: ['Public'] }));
    const yaml = loadSourceAuthConfig({ workspaceRoot: root, inputPath: 'auth.yml' });
    const json = loadSourceAuthConfig({ workspaceRoot: root, inputPath: 'auth.json' });
    expect(yaml.config).toEqual(json.config);
    expect(Object.isFrozen(yaml.config)).toBe(true);
    expect(yaml.rawDigest).toBe(`sha256:${createHash('sha256').update(fs.readFileSync(path.join(root, 'auth.yml'))).digest('hex')}`);
    expect(yaml.rawDigest).not.toBe(json.rawDigest);
    fs.writeFileSync(path.join(root, 'auth.yml'), 'invalid: changed\n');
    expect(yaml.config.public_decorators).toEqual(['Public']);
  });

  test.each([
    ['unknown field', `${valid}unknown: true\n`, 'yml'],
    ['missing required', 'public_decorators: []\nroles_decorators: []\n', 'yml'],
    ['unknown auth kind', valid.replace('bearer', 'unknown_kind'), 'yml'],
    ['duplicate YAML', `${valid}public_decorators: []\n`, 'yml'],
    ['duplicate JSON', '{"public_decorators":[],"roles_decorators":[],"guard_mappings":{},"guard_mappings":{}}', 'json'],
    ['multiple YAML documents', `${valid}---\npublic_decorators: []\n`, 'yml'],
    ['YAML alias', 'public_decorators: &p [Public]\nroles_decorators: *p\nguard_mappings: {}\n', 'yml'],
    ['YAML merge', 'public_decorators: []\nroles_decorators: []\nguard_mappings:\n  <<: {JwtAuthGuard: {auth_kind: bearer}}\n', 'yml'],
    ['custom tag', 'public_decorators: !danger [Public]\nroles_decorators: []\nguard_mappings: {}\n', 'yml'],
    ['deep JSON', `${'{"a":'.repeat(30)}0${'}'.repeat(30)}`, 'json'],
  ])('rejects %s without fallback', (_label, content, extension) => {
    const root = workspace();
    file(root, `auth.${extension}`, content);
    expect(() => loadSourceAuthConfig({ workspaceRoot: root, inputPath: `auth.${extension}` })).toThrow();
  });

  test('enforces path, file type, symlink and byte boundaries', () => {
    const root = workspace();
    const outside = workspace();
    file(root, 'auth.yml', valid);
    file(outside, 'outside.yml', valid);
    fs.symlinkSync('auth.yml', path.join(root, 'inside.yml'));
    fs.symlinkSync(path.join(outside, 'outside.yml'), path.join(root, 'outside.yml'));
    fs.mkdirSync(path.join(root, 'directory.yml'));
    file(root, 'limit.yml', `${valid}${' '.repeat(65_536 - Buffer.byteLength(valid))}`);
    file(root, 'oversize.yml', ' '.repeat(65_537));
    expect(loadSourceAuthConfig({ workspaceRoot: root, inputPath: 'inside.yml' }).config.public_decorators).toEqual(['Public']);
    expect(loadSourceAuthConfig({ workspaceRoot: root, inputPath: 'limit.yml' }).config.public_decorators).toEqual(['Public']);
    for (const name of ['outside.yml', '../outside.yml', 'directory.yml', 'oversize.yml', 'missing.yml']) {
      expect(() => loadSourceAuthConfig({ workspaceRoot: root, inputPath: name })).toThrow();
    }
    expect(() => loadSourceAuthConfig({ workspaceRoot: root, inputPath: 'auth.js' })).toThrow();
  });

  test('accepts valid prototype-looking Guard identifiers without pollution', () => {
    const root = workspace();
    file(root, 'names.yml', 'public_decorators: []\nroles_decorators: []\nguard_mappings:\n  __proto__: {auth_kind: bearer}\n  constructor: {auth_kind: basic}\n');
    const loaded = loadSourceAuthConfig({ workspaceRoot: root, inputPath: 'names.yml' });
    expect(Object.keys(loaded.config.guard_mappings).sort()).toEqual(['__proto__', 'constructor']);
    expect(Object.getPrototypeOf(loaded.config.guard_mappings)).toBe(Object.prototype);
    expect(({} as Record<string, unknown>).auth_kind).toBeUndefined();
  });

  test('rejects a symlink retarget or file growth detected during the read', () => {
    const root = workspace();
    const outside = workspace();
    file(root, 'auth.yml', valid);
    file(outside, 'auth.yml', valid);
    fs.symlinkSync('auth.yml', path.join(root, 'alias.yml'));
    const nativeRead = fs.readSync;
    try {
      let changed = false;
      fs.readSync = ((...args: Parameters<typeof fs.readSync>) => {
        const count = nativeRead(...args);
        if (!changed) {
          changed = true;
          fs.unlinkSync(path.join(root, 'alias.yml'));
          fs.symlinkSync(path.join(outside, 'auth.yml'), path.join(root, 'alias.yml'));
        }
        return count;
      }) as typeof fs.readSync;
      expect(() => loadSourceAuthConfig({ workspaceRoot: root, inputPath: 'alias.yml' })).toThrow();
    } finally { fs.readSync = nativeRead; }

    file(root, 'growing.yml', `${valid}${' '.repeat(65_536 - Buffer.byteLength(valid))}`);
    try {
      let changed = false;
      fs.readSync = ((...args: Parameters<typeof fs.readSync>) => {
        const count = nativeRead(...args);
        if (!changed) { changed = true; fs.appendFileSync(path.join(root, 'growing.yml'), 'x'); }
        return count;
      }) as typeof fs.readSync;
      expect(() => loadSourceAuthConfig({ workspaceRoot: root, inputPath: 'growing.yml' })).toThrow();
    } finally { fs.readSync = nativeRead; }
  });

  test('rejects auth option without Source before reading and keeps stdout empty', () => {
    const root = example();
    const result = invoke(root, ['--source-auth-config', 'missing-secret-opaquevalue123.yml']);
    expect(result.status).toBe(2);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('SOURCE_DIFF_AUTH_CONFIG_REQUIRES_SOURCE');
    expect(result.stderr).not.toContain('opaquevalue123');
    const help = invoke(root, ['--source-auth-config', 'missing-secret-opaquevalue123.yml', '--help']);
    expect(help.status).toBe(0);
    expect(help.stderr).toBe('');
  });

  test('does not load optional auth config for help, unrelated commands, or absent config', () => {
    const root = example();
    const preload = file(root, 'reject-auth-loader.cjs', `const Module = require('node:module');
const load = Module._load;
Module._load = function (request, parent, isMain) {
  if (request.endsWith('/source-auth-config') || request.endsWith('/source-auth-config.js')) {
    throw new Error('UNEXPECTED_AUTH_CONFIG_LOAD');
  }
  return load.call(this, request, parent, isMain);
};
`);
    const run = (args: string[]) => spawnSync(process.execPath, [cli, ...args], {
      cwd: root, encoding: 'utf8', timeout: 30_000,
      env: { ...process.env, NODE_PATH: '', NODE_OPTIONS: `--require=${preload}` },
    });
    const common = ['contract', 'source-diff', '--workspace-root', root, '--openapi', 'openapi.yaml',
      '--policy', 'policy/security.yml', '--target', 'aws', '--current-date', '2026-09-25'];
    for (const args of [
      ['--version'], ['--help'], ['contract', 'diff', '--help'],
      ['contract', 'source-diff', '--help'],
      [...common, '--source', 'tsconfig.json', '--format', 'json', '--fail-on', 'never'],
    ]) {
      const result = run(args);
      expect(result.error).toBeUndefined();
      expect(result.signal).toBeNull();
      expect(result.status, `${args.join(' ')}: ${result.stderr}`).toBe(0);
      expect(result.stderr).not.toContain('UNEXPECTED_AUTH_CONFIG_LOAD');
    }
    const invalid = run([...common, '--source-auth-config', 'missing.yml']);
    expect(invalid.error).toBeUndefined();
    expect(invalid.signal).toBeNull();
    expect(invalid.status).toBe(2);
    expect(invalid.stderr).toContain('SOURCE_DIFF_AUTH_CONFIG_REQUIRES_SOURCE');
    expect(invalid.stderr).not.toContain('UNEXPECTED_AUTH_CONFIG_LOAD');
  });

  test('uses the same Source project with different explicit auth facts', async () => {
    const root = example();
    file(root, 'auth-alt.json', JSON.stringify({ public_decorators: [], roles_decorators: [],
      guard_mappings: { JwtAuthGuard: { auth_kind: 'api_key' } } }));
    const configs = ['security-analyzer.yml', 'auth-alt.json'];
    const results = configs.map((name) => invoke(root, ['--source', 'tsconfig.json', '--source-auth-config', name,
      '--format', 'json', '--fail-on', 'never']));
    for (const result of results) { expect(result.status, result.stderr).toBe(0); expect(result.stderr).toBe(''); }
    const [configured, changed] = results.map((result) => JSON.parse(result.stdout));
    const expected = await analyzeSourceAwareWorkspace({ workspaceRoot: root, openapiPath: 'openapi.yaml',
      policyPath: 'policy/security.yml', target: 'aws', source: { tsconfigPath: 'tsconfig.json',
        authConfig: loadSourceAuthConfig({ workspaceRoot: root, inputPath: configs[0] }).config } });
    const expectedPreview = JSON.parse(formatSourceAwarePreviewJson(finalizeSourceAwareOutput(expected, {
      currentDate: '2026-09-25', failOn: 'never',
    }).finalized!));
    expect(configured.stages).toEqual(expectedPreview.stages);
    expect(configured.comparisons).toEqual(expectedPreview.comparisons);
    expect(configured.stages.implemented.status).toBe('partial');
    expect(configured.findings.active.map((finding: { ruleId: string; route?: { method?: string; path?: string } }) =>
      [finding.ruleId, finding.route?.method, finding.route?.path])).toContainEqual(['SC-AUTHZ-002', 'POST', '/users']);
    expect(changed.comparisons).not.toEqual(configured.comparisons);
    const absent = invoke(root, ['--source', 'tsconfig.json', '--source-auth-config', 'missing-secret-opaquevalue123.yml']);
    expect(absent.status).toBe(2);
    expect(absent.stdout).toBe('');
    expect(absent.stderr).toContain('SOURCE_DIFF_AUTH_CONFIG_INVALID');
    expect(absent.stderr).not.toContain('opaquevalue123');
    const failedSource = invoke(root, ['--source', 'missing.tsconfig.json',
      '--source-auth-config', configs[0], '--format', 'json', '--fail-on', 'never']);
    expect(failedSource.status).toBe(2);
    expect(failedSource.stderr).toBe('');
    const failedReport = JSON.parse(failedSource.stdout);
    expect(failedReport.stages.implemented.status).toBe('failed');
    expect(failedReport.comparisons.declaredAllowed.status).toMatch(/complete|partial/);
  });

  test('keeps semantic digest and real Source metadata separate from config-file bytes', async () => {
    const root = example();
    file(root, 'same.json', JSON.stringify({ guard_mappings: { JwtAuthGuard: { auth_kind: 'bearer' } },
      public_decorators: ['Public'], roles_decorators: ['Roles'] }));
    file(root, 'unrelated.yml', `${valid}  NeverPresentGuard: {auth_kind: basic}\n`.replace(
      'public_decorators: [Public]', 'public_decorators: [Public, NeverPresent]'));
    file(root, 'ordered.yml', valid.replace('[Public]', '[Public, NeverPresent]')
      .replace('[Roles]', '[Roles, NeverPresentRoles]'));
    file(root, 'reordered.json', JSON.stringify({ guard_mappings: { JwtAuthGuard: { auth_kind: 'bearer' } },
      roles_decorators: ['NeverPresentRoles', 'Roles'], public_decorators: ['NeverPresent', 'Public'] }));
    const loaded = ['security-analyzer.yml', 'same.json', 'unrelated.yml'].map((name) =>
      loadSourceAuthConfig({ workspaceRoot: root, inputPath: name }));
    const analyze = (config?: unknown) => analyzeSourceAwareWorkspace({ workspaceRoot: root,
      openapiPath: 'openapi.yaml', policyPath: 'policy/security.yml', target: 'aws',
      source: { tsconfigPath: 'tsconfig.json', ...(config === undefined ? {} : { authConfig: config }) } });
    const [defaults, equivalentEmpty, yaml, json, unrelated] = await Promise.all([
      analyze(), analyze({ public_decorators: [], roles_decorators: [], guard_mappings: {} }),
      ...loaded.map((item) => analyze(item.config)),
    ]);
    expect(defaults.evidence.source?.configDigest).toBe(equivalentEmpty.evidence.source?.configDigest);
    expect(yaml.evidence.source?.configDigest).toBe(json.evidence.source?.configDigest);
    expect(yaml.evidence.source?.projectDigest).toBe(defaults.evidence.source?.projectDigest);
    expect(yaml.evidence.source?.projectDigest).toBe(unrelated.evidence.source?.projectDigest);
    expect(loaded[0].rawDigest).not.toBe(loaded[1].rawDigest);
    expect(unrelated.evidence.source?.configDigest).not.toBe(yaml.evidence.source?.configDigest);
    expect(unrelated.comparisons).toEqual(yaml.comparisons);
    const [ordered, reordered] = await Promise.all(['ordered.yml', 'reordered.json'].map((name) =>
      analyze(loadSourceAuthConfig({ workspaceRoot: root, inputPath: name }).config)));
    expect(ordered.evidence.source?.configDigest).toBe(reordered.evidence.source?.configDigest);
    expect(ordered.comparisons).toEqual(reordered.comparisons);
    file(root, 'empty.json', '{"public_decorators":[],"roles_decorators":[],"guard_mappings":{}}');
    const defaultCli = invoke(root, ['--source', 'tsconfig.json', '--format', 'json', '--fail-on', 'never']);
    const emptyCli = invoke(root, ['--source', 'tsconfig.json', '--source-auth-config', 'empty.json',
      '--format', 'json', '--fail-on', 'never']);
    expect(defaultCli.status).toBe(0);
    expect(emptyCli.status).toBe(0);
    expect(JSON.parse(emptyCli.stdout)).toEqual(JSON.parse(defaultCli.stdout));
    const source = await runNestJsSourceAnalysisInternal({ workspaceRoot: root,
      entrypoints: ['tsconfig.json'], limits: DEFAULT_SOURCE_ANALYSIS_LIMITS, logger: { log() {} } }, loaded[0].config);
    expect(source.execution.status).toBe('success');
    if (source.execution.status !== 'success') return;
    const operations = source.execution.result.contract.operations;
    expect(operations.find((operation) => operation.routeKey === 'GET /users/{id}')?.exposure).toBe('public');
    expect(operations.find((operation) => operation.routeKey === 'POST /users')?.auth.analysis?.roles).toEqual(['writer']);
    expect(operations.find((operation) => operation.routeKey === 'PATCH /users/details')?.auth.mode).toBe('unknown');
  });

  test('keeps secret-like config path and data out of four outputs', () => {
    const root = example();
    file(root, 'token=opaquevalue123.yml', valid);
    for (const format of ['text', 'json', 'sarif', 'summary']) {
      const result = invoke(root, ['--source', 'tsconfig.json', '--source-auth-config', 'token=opaquevalue123.yml',
        '--format', format, '--fail-on', 'never']);
      expect(result.status, result.stderr).toBe(0);
      expect(`${result.stdout}${result.stderr}`).not.toContain('opaquevalue123');
      expect(`${result.stdout}${result.stderr}`).not.toContain(root);
    }
    file(root, 'token=opaquevalue123.yml', `${valid}private: secret-opaquevalue123\n`);
    for (const format of ['text', 'json', 'sarif', 'summary']) {
      const result = invoke(root, ['--source', 'tsconfig.json', '--source-auth-config', 'token=opaquevalue123.yml',
        '--format', format]);
      expect(result.status).toBe(2);
      expect(result.stdout).toBe('');
      expect(result.stderr).toContain('SOURCE_DIFF_AUTH_CONFIG_INVALID');
      expect(result.stderr).not.toContain('opaquevalue123');
      expect(result.stderr).not.toContain(root);
    }
    file(root, 'token=opaquevalue123.yml', valid);
    expect(loadSourceAuthConfig({ workspaceRoot: root, inputPath: 'token=opaquevalue123.yml' }).config.public_decorators).toEqual(['Public']);
  }, 15_000);
});
