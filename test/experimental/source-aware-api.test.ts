import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { afterEach, expect, test, vi } from 'vitest';

import { analyzeSourceDiff, type SourceDiffOptions } from '../../src/experimental/source-aware';
import { WAIVABLE_FINDING_RULE_IDS } from '../../src/contract/finding-exceptions';

const roots: string[] = [];

function workspace() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-source-api-'));
  roots.push(root);
  fs.cpSync(path.join(process.cwd(), 'test/fixtures/source-analysis/nestjs-basic'), root,
    { recursive: true });
  fs.writeFileSync(path.join(root, 'openapi.yaml'), `openapi: 3.0.3
info: {title: Synthetic, version: 1.0.0}
paths:
  /users:
    get:
      responses:
        '200': {description: OK}
`);
  fs.writeFileSync(path.join(root, 'policy.yml'), `version: 2
defaults: {mode: enforce}
request:
  allow_methods: [GET]
  limits: {max_uri_length: 100}
  block: {header_missing: []}
routes: []
response_headers: {}
`);
  return root;
}

function options(root: string, source = false): SourceDiffOptions {
  return { workspaceRoot: root, openapiPath: 'openapi.yaml', policyPath: 'policy.yml',
    target: 'aws', currentDate: '2026-09-28', failOn: 'never',
    ...(source ? { source: { tsconfigPath: 'tsconfig.json' } } : {}) };
}

function sourceWorkspace() {
  const root = workspace();
  const dependency = path.join(root, 'node_modules/@nestjs/common');
  fs.mkdirSync(dependency, { recursive: true });
  fs.writeFileSync(path.join(dependency, 'package.json'), JSON.stringify({
    name: '@nestjs/common', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
  }));
  fs.writeFileSync(path.join(dependency, 'index.js'), 'throw new Error("Source executed");\n');
  fs.writeFileSync(path.join(dependency, 'index.d.ts'), [
    'export declare function Controller(path?: string | {path?: string; version?: string}): ClassDecorator;',
    'export declare function Get(path?: string): MethodDecorator;',
    'export declare function Post(path?: string): MethodDecorator;',
    'export declare function Head(path?: string): MethodDecorator;',
  ].join('\n'));
  return root;
}

function cli(root: string, args: string[] = []) {
  return spawnSync(process.execPath, [path.join(process.cwd(), 'bin/cli.js'), 'contract',
    'source-diff', '--workspace-root', root, '--openapi', 'openapi.yaml', '--policy', 'policy.yml',
    '--target', 'aws', '--current-date', '2026-09-28', '--fail-on', 'never', '--format', 'json', ...args],
  { cwd: root, encoding: 'utf8', timeout: 30_000, env: { ...process.env, NODE_PATH: '' } });
}

function sha(file: string) {
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

test('returns complete finalized data without process or file effects', async () => {
  const root = workspace();
  const options = { workspaceRoot: root, openapiPath: 'openapi.yaml', policyPath: 'policy.yml',
    target: 'aws' as const, currentDate: '2026-09-28', failOn: 'never' as const };
  const before = ['openapi.yaml', 'policy.yml'].map((name) => fs.readFileSync(path.join(root, name)));
  const exitCode = process.exitCode;
  const cwd = process.cwd();
  const result = await analyzeSourceDiff(options);
  expect(result.kind).toBe('report');
  if (result.kind === 'report') {
    expect(result.contract).toBe('experimental-source-aware@1');
    expect(result.stages.implemented).toMatchObject({ status: 'omitted', code: 'SOURCE_NOT_REQUESTED' });
    expect(result.comparisons.declaredAllowed.status).toMatch(/complete|partial/);
    expect(result.summary.unique).toBe(result.findings.length + result.suppressedFindings.length);
    expect(result.exitCode).toBe(0);
  }
  expect(process.exitCode).toBe(exitCode);
  expect(process.cwd()).toBe(cwd);
  expect(['openapi.yaml', 'policy.yml'].map((name) => fs.readFileSync(path.join(root, name))))
    .toEqual(before);
});

test('returns a complete zero-Finding report with an unreached warning threshold', async () => {
  const root = workspace();
  fs.writeFileSync(path.join(root, 'openapi.yaml'), 'openapi: 3.0.3\ninfo: {title: Synthetic, version: 1.0.0}\npaths: {}\n');
  const result = await analyzeSourceDiff({ ...options(root), failOn: 'warning' });
  expect(result).toMatchObject({ kind: 'report', analysis: { status: 'complete', outcome: 'ok', codes: [] },
    summary: { unique: 0, active: 0, suppressed: 0, governance: 0 },
    threshold: { failOn: 'warning', reached: false }, exitCode: 0 });
});

test('rejects unknown fields and accessors without evaluating them', async () => {
  const root = workspace();
  const options = { workspaceRoot: root, openapiPath: 'openapi.yaml', policyPath: 'policy.yml',
    target: 'aws', currentDate: '2026-09-28', failOn: 'never' };
  expect(await analyzeSourceDiff({ ...options, out: 'report.json' } as never)).toMatchObject({
    kind: 'error', code: 'SOURCE_DIFF_ARGUMENT_INVALID', exitCode: 2,
  });
  let called = false;
  const accessor = Object.defineProperty({ ...options }, 'openapiPath', { get() {
    called = true;
    throw new Error('SECRET_VALUE');
  } });
  expect(await analyzeSourceDiff(accessor as never)).toMatchObject({
    kind: 'error', code: 'SOURCE_DIFF_ARGUMENT_INVALID', exitCode: 2,
  });
  expect(called).toBe(false);
  expect(await analyzeSourceDiff(new Proxy(options, { get() { called = true; throw Error('secret'); } }) as never))
    .toMatchObject({ kind: 'error', code: 'SOURCE_DIFF_ARGUMENT_INVALID', exitCode: 2 });
  expect(called).toBe(false);
  expect(await analyzeSourceDiff({ ...options, source: { tsconfigPath: 'tsconfig.json',
    strategyMapping: 'missing.yml' } } as never)).toMatchObject({
    kind: 'error', code: 'SOURCE_DIFF_ARGUMENT_INVALID', exitCode: 2,
  });
  expect(await analyzeSourceDiff({ ...options, source: { tsconfigPath: 'tsconfig.json',
    versioning: 'header' } } as never)).toMatchObject({
    kind: 'error', code: 'SOURCE_DIFF_VERSIONING_INVALID', exitCode: 2,
  });
  expect(await analyzeSourceDiff({ ...options, source: { tsconfigPath: 'tsconfig.json',
    globalPrefix: '/api' } })).toMatchObject({
    kind: 'report',
  });
});

test('matches a separate CLI run for Source stages, findings, threshold and exit data', async () => {
  const root = sourceWorkspace();
  const input = { ...options(root, true), failOn: 'warning' as const };
  const api = await analyzeSourceDiff(input);
  const command = cli(root, ['--source', 'tsconfig.json', '--fail-on', 'warning']);
  expect(api.kind).toBe('report');
  expect(command.status).toBe(api.exitCode);
  expect(command.stderr).toBe('');
  if (api.kind !== 'report') return;
  const preview = JSON.parse(command.stdout);
  expect(api.stages).toEqual(preview.stages);
  expect(api.comparisons).toEqual(preview.comparisons);
  expect(api.analysis).toEqual(preview.analysis);
  expect(api.threshold).toEqual(preview.threshold);
  expect(api.summary).toEqual(preview.summary);
  expect(api.findings.map(({ instanceId }) => instanceId)).toEqual(
    preview.findings.active.map(({ instanceId }: { instanceId: string }) => instanceId));
  expect(api.metadata.source?.projectDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
});

test('uses explicit Source settings and exceptions without fallback', async () => {
  const root = sourceWorkspace();
  fs.writeFileSync(path.join(root, 'src/controller.ts'), `import { Controller, Get } from '@nestjs/common';
    @Controller({ path: 'users', version: '1' }) class Users { @Get() read() {} }`);
  fs.writeFileSync(path.join(root, 'openapi.yaml'), `openapi: 3.0.3
info: {title: Synthetic, version: 1.0.0}
paths:
  /api/v1/users:
    get:
      responses:
        '200': {description: OK}
`);
  fs.writeFileSync(path.join(root, 'auth.json'), JSON.stringify({
    public_decorators: [], roles_decorators: [], guard_mappings: {},
  }));
  const input = { ...options(root, true), environment: 'staging', source: {
    tsconfigPath: 'tsconfig.json', authConfigPath: 'auth.json',
    globalPrefix: '/api', versioning: 'uri' as const,
  } };
  const first = await analyzeSourceDiff(input);
  expect(first.kind).toBe('report');
  if (first.kind !== 'report') return;
  expect(first.metadata.routingAssumption).toMatchObject({ globalPrefix: '/api', sourceVersioning: 'uri' });
  expect(first.metadata.sourceVersionMetadata?.total).toBeGreaterThan(0);
  expect(first.metadata.sourceVersionMetadata?.routes.some(route => route.comparisonPath === '/api/v1/users'))
    .toBe(true);
  const selected = first.findings.find(f => (WAIVABLE_FINDING_RULE_IDS as readonly string[]).includes(f.ruleId));
  expect(selected).toBeDefined();
  if (selected) {
    const exception = { version: 1, exceptions: [{ id: 'EXC-2026-API', rule_id: selected.ruleId,
      selector: { instance_id: selected.instanceId, environment: 'staging' },
      reason: 'Reviewed synthetic route.', owner: 'security-team', expires_at: '2026-12-01' }] };
    fs.writeFileSync(path.join(root, 'exceptions.json'), JSON.stringify(exception));
    const applied = await analyzeSourceDiff({ ...input, exceptionsPath: 'exceptions.json' });
    expect(applied).toMatchObject({ kind: 'report', appliedExceptionIds: ['EXC-2026-API'] });
    expect(applied.kind === 'report' && applied.suppressedFindings.some(f => f.instanceId === selected.instanceId))
      .toBe(true);
    const other = await analyzeSourceDiff({ ...input, environment: 'production', exceptionsPath: 'exceptions.json' });
    expect(other.kind === 'report' && other.appliedExceptionIds).toEqual([]);
  }
  fs.writeFileSync(path.join(root, 'bad-auth.json'), '{"public_decorators": []}');
  expect(await analyzeSourceDiff({ ...input, source: { ...input.source, authConfigPath: 'bad-auth.json' } }))
    .toMatchObject({ kind: 'error', code: 'SOURCE_DIFF_AUTH_CONFIG_INVALID', exitCode: 2 });
  expect(await analyzeSourceDiff({ ...options(root), source: { tsconfigPath: 'tsconfig.json',
    globalPrefix: '/api?token=opaquevalue123' } })).toMatchObject({
    kind: 'error', code: 'SOURCE_DIFF_PREFIX_INVALID', exitCode: 2,
  });
  expect(await analyzeSourceDiff({ ...options(root), source: { tsconfigPath: 'tsconfig.json' },
    exceptionsPath: 'missing-token=opaquevalue123.json' })).toMatchObject({
    kind: 'error', code: 'SOURCE_DIFF_EXCEPTIONS_INVALID', exitCode: 2,
  });
});

test('keeps all Findings beyond the CLI preview limit', async () => {
  const root = workspace();
  const paths = Array.from({ length: 50 }, (_, i) => `  /route-${i}:\n    get:\n      responses:\n        '200': {description: OK}`).join('\n');
  fs.writeFileSync(path.join(root, 'openapi.yaml'), `openapi: 3.0.3\ninfo: {title: Synthetic, version: 1.0.0}\npaths:\n${paths}\n`);
  const api = await analyzeSourceDiff(options(root));
  const command = cli(root);
  expect(api.kind).toBe('report');
  expect(command.status).toBe(0);
  if (api.kind !== 'report') return;
  const preview = JSON.parse(command.stdout);
  expect(api.summary.unique).toBeGreaterThan(40);
  expect(api.findings.length + api.suppressedFindings.length).toBe(api.summary.unique);
  expect(preview.omittedFindings).toBeGreaterThan(0);
  expect(preview.findings.active.length).toBeLessThan(api.findings.length);
});

test('returns a failed or partial report with independent comparisons for input-stage failures', async () => {
  const root = sourceWorkspace();
  const missingOpenapi = await analyzeSourceDiff({ ...options(root, true), openapiPath: 'missing.yaml' });
  expect(missingOpenapi.kind).toBe('report');
  if (missingOpenapi.kind !== 'report') return;
  expect(missingOpenapi.stages.declared.status).toBe('failed');
  expect(missingOpenapi.comparisons.implementedAllowed.status).toMatch(/complete|partial/);
  expect(missingOpenapi.analysis.outcome).toBe('input-error');
  expect(missingOpenapi.exitCode).toBe(2);

  const missingSource = await analyzeSourceDiff({ ...options(root, true),
    source: { tsconfigPath: 'missing-tsconfig.json' } });
  expect(missingSource.kind).toBe('report');
  if (missingSource.kind !== 'report') return;
  expect(missingSource.stages.implemented.status).toBe('failed');
  expect(missingSource.comparisons.declaredAllowed.status).toMatch(/complete|partial/);
  expect(missingSource.exitCode).toBe(2);
});

test('does not mutate process, files or later results; isolated concurrent workspaces recover after an error', async () => {
  const a = workspace(); const b = workspace();
  const files = [path.join(a, 'openapi.yaml'), path.join(a, 'policy.yml'),
    path.join(b, 'openapi.yaml'), path.join(b, 'policy.yml')];
  const hashes = files.map(sha);
  const exit = process.exitCode; const cwd = process.cwd(); const env = { ...process.env };
  const stdout = vi.spyOn(process.stdout, 'write'); const stderr = vi.spyOn(process.stderr, 'write');
  const log = vi.spyOn(console, 'log'); const warn = vi.spyOn(console, 'warn');
  try {
    expect(await analyzeSourceDiff({ ...options(a), openapiPath: 'missing.yaml' })).toMatchObject({ kind: 'report' });
    const [left, right] = await Promise.all([analyzeSourceDiff(options(a)), analyzeSourceDiff(options(b))]);
    expect(left.kind).toBe('report'); expect(right.kind).toBe('report');
    if (left.kind === 'report' && right.kind === 'report') {
      (left.findings as unknown as unknown[]).splice(0, 1);
      expect(await analyzeSourceDiff(options(a))).toMatchObject({ kind: 'report', summary: right.summary });
    }
    expect(stdout).not.toHaveBeenCalled(); expect(stderr).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled(); expect(warn).not.toHaveBeenCalled();
  } finally { stdout.mockRestore(); stderr.mockRestore(); log.mockRestore(); warn.mockRestore(); }
  expect(process.exitCode).toBe(exit); expect(process.cwd()).toBe(cwd);
  expect(process.env).toEqual(env); expect(files.map(sha)).toEqual(hashes);
});

test('does not serialize secret-like input or encoded filenames', async () => {
  const root = workspace();
  fs.mkdirSync(path.join(root, 'refs'));
  fs.writeFileSync(path.join(root, 'refs/token=opaquevalue123.yaml'), 'components: {}\n');
  fs.writeFileSync(path.join(root, 'openapi.yaml'), `openapi: 3.0.3
info: {title: Synthetic, version: 1.0.0}
paths:
  /users:
    get:
      responses:
        '200': {description: Authorization Bearer synthetic-secret-opaquevalue123}
      parameters:
        - { $ref: './refs/token%3Dopaquevalue123.yaml#/components/unknown' }
`);
  const result = await analyzeSourceDiff(options(root));
  const serialized = JSON.stringify(result);
  expect(serialized).not.toContain(root);
  expect(serialized).not.toContain('opaquevalue123');
  expect(serialized).not.toContain('token%3D');
  expect(serialized).not.toContain('synthetic-secret');
});
