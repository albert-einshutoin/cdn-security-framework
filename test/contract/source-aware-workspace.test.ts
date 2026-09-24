import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, test, vi } from 'vitest';

import { analyzeSourceAwareWorkspace } from '../../src/contract/source-aware-workspace';
import { compareSecurityContracts, projectPolicyToAllowedSurface } from '../../src/contract';
import { inspectOpenApi } from '../../src/openapi';
import * as sourceRunner from '../../src/source/nestjs/analyzer';
import * as projectLoader from '../../src/source/typescript/project-loader';
import { TypeScriptAnalysisCache } from '../../src/source/typescript/project-loader';

const roots: string[] = [];
const policy = `version: 2
defaults: {mode: enforce}
request:
  allow_methods: [GET]
  limits: {max_uri_length: 21}
  block: {header_missing: []}
routes: []
response_headers: {}
`;

function workspace(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-source-workspace-'));
  roots.push(root);
  fs.cpSync(path.join(process.cwd(), 'test/fixtures/source-analysis/nestjs-basic'), root, { recursive: true });
  const dependency = path.join(root, 'node_modules/@nestjs/common');
  fs.mkdirSync(dependency, { recursive: true });
  fs.writeFileSync(path.join(dependency, 'package.json'), JSON.stringify({ name: '@nestjs/common', version: '1.0.0', main: 'index.js', types: 'index.d.ts' }));
  fs.writeFileSync(path.join(dependency, 'index.js'), 'throw new Error("Source executed");\n');
  fs.writeFileSync(path.join(dependency, 'index.d.ts'), `export declare function Controller(path?: string): ClassDecorator;
export declare function Get(path?: string): MethodDecorator;
export declare function Post(path?: string): MethodDecorator;
export declare function Head(path?: string): MethodDecorator;\n`);
  fs.writeFileSync(path.join(root, 'policy.yml'), policy);
  fs.mkdirSync(path.join(root, 'refs'));
  fs.writeFileSync(path.join(root, 'refs/common.yaml'), 'components:\n  parameters:\n    Id:\n      name: id\n      in: path\n      required: true\n      schema: {type: string}\n');
  fs.writeFileSync(path.join(root, 'openapi.yaml'), `openapi: 3.0.3
info: {title: Synthetic, version: 1.0.0}
paths:
  /users/{id}:
    get:
      parameters:
        - $ref: './refs/common.yaml#/components/parameters/Id'
      responses:
        '200': {description: OK}
  /users:
    post:
      responses:
        '200': {description: OK}
`);
  return root;
}

function args(root: string) {
  return { workspaceRoot: root, openapiPath: 'openapi.yaml', policyPath: 'policy.yml',
    target: 'aws' as const, source: { tsconfigPath: 'tsconfig.json' } };
}

function hash(file: string): string {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe('internal single-workspace adapter', () => {
  test('uses real OpenAPI refs, schema 2 Policy and one NestJS analysis with same-run project digest', async () => {
    const root = workspace();
    const inputs = ['openapi.yaml', 'refs/common.yaml', 'policy.yml', 'tsconfig.json', 'src/controller.ts']
      .map((file) => [file, hash(path.join(root, file))] as const);
    const load = vi.spyOn(projectLoader, 'loadTypeScriptProject');
    const network = vi.spyOn(globalThis, 'fetch').mockImplementation(() => { throw new Error('network forbidden'); });
    const result = await analyzeSourceAwareWorkspace(args(root));
    expect(load).toHaveBeenCalledTimes(1);
    expect(network).not.toHaveBeenCalled();
    expect(result.stages.declared.status).toMatch(/complete|partial/);
    expect(result.stages.implemented.status).toBe('partial');
    expect(result.stages.allowed.status, JSON.stringify(result.stages.allowed)).toBe('complete');
    expect(result.stages.allowed.targetCapabilities.some(({ status }) => status !== 'supported')).toBe(true);
    expect(result.comparisons.declaredAllowed.findings).toBeDefined();
    expect(result.comparisons.implementedDeclared.findings?.length).toBeGreaterThan(0);
    expect(result.comparisons.implementedAllowed.findings?.length).toBeGreaterThan(0);
    expect(result.evidence.openapi?.sources.map(({ uri }) => uri)).toEqual(['openapi.yaml', 'refs/common.yaml']);
    expect(result.evidence.openapi?.sources[0].digest).toBe(`sha256:${hash(path.join(root, 'openapi.yaml'))}`);
    expect(result.evidence.openapi?.sources[1].digest).toBe(`sha256:${hash(path.join(root, 'refs/common.yaml'))}`);
    expect(result.evidence.policy?.sources[0].uri).toBe('policy.yml');
    expect(result.evidence.policy?.policyDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    const consumed = await load.mock.results[0].value;
    expect(result.evidence.source?.projectDigest).toBe(`sha256:${consumed.snapshotDigest}`);
    expect(result.evidence.source?.analyzer).toMatch(/^nestjs-typescript@/);
    expect(result.evidence.source?.configDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    for (const [file, before] of inputs) expect(hash(path.join(root, file))).toBe(before);
    expect(await analyzeSourceAwareWorkspace(args(root))).toEqual(result);
  });

  test('does not run Source when omitted and preserves existing Declared/Allowed comparison', async () => {
    const root = workspace();
    const runner = vi.spyOn(sourceRunner, 'runNestJsSourceAnalysisInternal');
    const { source: _source, ...input } = args(root);
    const result = await analyzeSourceAwareWorkspace(input);
    expect(runner).not.toHaveBeenCalled();
    expect(result.stages.implemented).toMatchObject({ status: 'omitted', code: 'SOURCE_NOT_REQUESTED' });
    expect(result.comparisons.implementedDeclared).toMatchObject({ status: 'omitted' });
    const declared = inspectOpenApi({ inputPath: 'openapi.yaml', workspaceRoot: root });
    const allowed = projectPolicyToAllowedSurface({
      version: 2, defaults: { mode: 'enforce' }, request: { allow_methods: ['GET'], block: { header_missing: [] } },
      routes: [], response_headers: {},
    }, { policyDigest: result.evidence.policy!.policyDigest, sourceUri: 'policy.yml' });
    expect(result.comparisons.declaredAllowed.findings).toEqual(compareSecurityContracts({
      declared: declared.contract, allowed, target: 'aws',
    }));
  });

  test('retains successful pairwise work when Source, OpenAPI or Policy fails', async () => {
    const root = workspace();
    const sourceFailed = await analyzeSourceAwareWorkspace({ ...args(root), source: { tsconfigPath: '../outside.ts' } });
    expect(sourceFailed.stages.implemented.status).toBe('failed');
    expect(sourceFailed.evidence.source).toBeUndefined();
    expect(sourceFailed.comparisons.declaredAllowed.findings).toBeDefined();
    const retry = await analyzeSourceAwareWorkspace(args(root));
    expect(retry.evidence.source?.projectDigest).toMatch(/^sha256:[a-f0-9]{64}$/);

    fs.writeFileSync(path.join(root, 'openapi.yaml'), 'not: openapi\n');
    const badOpenApi = await analyzeSourceAwareWorkspace(args(root));
    expect(badOpenApi.stages.declared.status).toBe('failed');
    expect(badOpenApi.evidence.openapi).toBeUndefined();
    expect(badOpenApi.comparisons.declaredAllowed).toMatchObject({ status: 'failed' });
    expect(badOpenApi.comparisons.implementedAllowed.findings).toBeDefined();

    fs.writeFileSync(path.join(root, 'openapi.yaml'), 'openapi: 3.0.3\ninfo: {title: Test, version: 1.0.0}\npaths: {}\n');
    fs.writeFileSync(path.join(root, 'policy.yml'), 'version: 1\n');
    const badPolicy = await analyzeSourceAwareWorkspace(args(root));
    expect(badPolicy.stages.allowed.status).toBe('failed');
    expect(badPolicy.evidence.policy).toBeUndefined();
    expect(badPolicy.comparisons.implementedDeclared.findings).toBeDefined();
    expect(badPolicy.comparisons.implementedAllowed).toMatchObject({ status: 'failed' });
  });

  test('keeps concurrent project evidence separate and preserves limit diagnostics', async () => {
    const first = workspace();
    const second = workspace();
    fs.appendFileSync(path.join(second, 'src/controller.ts'), '\nconst changed = 42;\n');
    const [one, two] = await Promise.all([
      analyzeSourceAwareWorkspace(args(first)), analyzeSourceAwareWorkspace(args(second)),
    ]);
    expect(one.evidence.source?.projectDigest).not.toBe(two.evidence.source?.projectDigest);
    expect(one.evidence.source?.projectDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(two.evidence.source?.projectDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    const limited = await analyzeSourceAwareWorkspace({
      ...args(first), source: { tsconfigPath: 'tsconfig.json', limits: { maxOperations: 1 } },
    });
    expect(limited.stages.implemented).toMatchObject({ status: 'failed', code: 'SOURCE_ANALYZER_OPERATION_LIMIT' });
    expect(limited.evidence.source).toBeUndefined();
    expect(limited.comparisons.declaredAllowed.findings).toBeDefined();
  });

  test('binds cache hits and source/config/package changes to each invocation', async () => {
    const root = workspace();
    const cache = new TypeScriptAnalysisCache();
    const load = vi.spyOn(projectLoader, 'loadTypeScriptProject');
    const input = { ...args(root), source: { tsconfigPath: 'tsconfig.json', cache } };
    const first = await analyzeSourceAwareWorkspace(input);
    const second = await analyzeSourceAwareWorkspace(input);
    expect(load).toHaveBeenCalledTimes(2);
    expect((await load.mock.results[1].value).metrics.cacheHits).toBe(1);
    expect(second.evidence.source?.projectDigest).toBe(first.evidence.source?.projectDigest);
    fs.appendFileSync(path.join(root, 'src/controller.ts'), '\n// changed source\n');
    const sourceChanged = await analyzeSourceAwareWorkspace(input);
    expect(sourceChanged.evidence.source?.projectDigest).not.toBe(second.evidence.source?.projectDigest);
    fs.appendFileSync(path.join(root, 'tsconfig.json'), '\n');
    const configChanged = await analyzeSourceAwareWorkspace(input);
    expect(configChanged.evidence.source?.projectDigest).not.toBe(sourceChanged.evidence.source?.projectDigest);
    const packageFile = path.join(root, 'node_modules/@nestjs/common/package.json');
    fs.writeFileSync(packageFile, JSON.stringify({ name: '@nestjs/common', version: '1.0.1', main: 'index.js', types: 'index.d.ts' }));
    const metadataChanged = await analyzeSourceAwareWorkspace(input);
    expect(metadataChanged.evidence.source?.projectDigest).not.toBe(configChanged.evidence.source?.projectDigest);
    expect(load).toHaveBeenCalledTimes(5);
  });

  test('keeps analyzer options and target separate from the consumed project digest', async () => {
    const root = workspace();
    const first = await analyzeSourceAwareWorkspace(args(root));
    const configured = await analyzeSourceAwareWorkspace({
      ...args(root), target: 'cloudflare', source: {
        tsconfigPath: 'tsconfig.json',
        authConfig: { public_decorators: ['Public'], roles_decorators: [], guard_mappings: {} },
      },
    });
    expect(configured.evidence.source?.projectDigest).toBe(first.evidence.source?.projectDigest);
    expect(configured.evidence.source?.configDigest).not.toBe(first.evidence.source?.configDigest);
    expect(configured.target).toBe('cloudflare');
    expect(configured.evidence.openapi?.analyzer).toBe('cdn-security-openapi-inspect@1');
    expect(configured.evidence.policy?.projector).toBe('allowed-surface@1');
  });

  test('uses one config digest for equivalent decorator sets and guard mappings', async () => {
    const root = workspace();
    const first = await analyzeSourceAwareWorkspace({
      ...args(root), source: { tsconfigPath: 'tsconfig.json', authConfig: {
        public_decorators: ['Public', 'Guest'], roles_decorators: ['Roles', 'AllowedRoles'],
        guard_mappings: { AuthGuard: { auth_kind: 'bearer' }, ApiKeyGuard: { auth_kind: 'api_key' } },
      } },
    });
    const reordered = await analyzeSourceAwareWorkspace({
      ...args(root), source: { tsconfigPath: 'tsconfig.json', authConfig: {
        roles_decorators: ['AllowedRoles', 'Roles'], public_decorators: ['Guest', 'Public'],
        guard_mappings: { ApiKeyGuard: { auth_kind: 'api_key' }, AuthGuard: { auth_kind: 'bearer' } },
      } },
    });
    expect(first.stages.implemented.status).toBe(reordered.stages.implemented.status);
    expect(first.evidence.source?.projectDigest).toBe(reordered.evidence.source?.projectDigest);
    expect(first.evidence.source?.configDigest).toBe(reordered.evidence.source?.configDigest);
  });

  test('keeps raw-byte identity distinct from decoded Source text and does not execute config', async () => {
    const root = workspace();
    const sourceFile = path.join(root, 'src/controller.ts');
    const original = fs.readFileSync(sourceFile);
    const firstBytes = Buffer.concat([original, Buffer.from([0x2f, 0x2f, 0x20, 0xff, 0x0a])]);
    const secondBytes = Buffer.concat([original, Buffer.from([0x2f, 0x2f, 0x20, 0xfe, 0x0a])]);
    fs.writeFileSync(sourceFile, firstBytes);
    const firstHash = hash(sourceFile);
    const first = await analyzeSourceAwareWorkspace(args(root));
    fs.writeFileSync(sourceFile, secondBytes);
    expect(hash(sourceFile)).not.toBe(firstHash);
    const second = await analyzeSourceAwareWorkspace(args(root));
    expect(first.evidence.source?.projectDigest).toBe(second.evidence.source?.projectDigest);
    let invoked = false;
    const invalidConfig = await analyzeSourceAwareWorkspace({
      ...args(root), source: { tsconfigPath: 'tsconfig.json', authConfig: { run: () => { invoked = true; } } },
    });
    expect(invoked).toBe(false);
    expect(invalidConfig.stages.implemented).toMatchObject({ status: 'failed', code: 'SOURCE_ANALYZER_INPUT_INVALID' });
    expect(invalidConfig.evidence.source).toBeUndefined();
  });

  test('honors cancellation and masks secret-like evidence filenames', async () => {
    const root = workspace();
    const ref = path.join(root, 'refs/common.yaml');
    const secretName = 'backup-token-opaquevalue123.yaml';
    fs.renameSync(ref, path.join(root, 'refs', secretName));
    fs.writeFileSync(path.join(root, 'openapi.yaml'), fs.readFileSync(path.join(root, 'openapi.yaml'), 'utf8')
      .replace('common.yaml', secretName));
    const controller = new AbortController();
    controller.abort();
    const result = await analyzeSourceAwareWorkspace({
      ...args(root), source: { tsconfigPath: 'tsconfig.json', cancellationSignal: controller.signal },
    });
    expect(result.stages.implemented).toMatchObject({ status: 'failed', code: 'SOURCE_ANALYZER_CANCELLED' });
    expect(result.evidence.source).toBeUndefined();
    expect(result.evidence.openapi?.sources.map(({ uri }) => uri)).toContain('refs/[REDACTED_FILENAME]');
    expect(JSON.stringify(result)).not.toContain('opaquevalue123');
  });

  test('does not expose standalone provider tokens in evidence filenames', async () => {
    const root = workspace();
    const refToken = 'sk-proj-abcdefghijklmnop';
    const policyToken = 'ghp_abcdefghijklmnop';
    const refName = `${refToken}.yaml`;
    const policyName = `${policyToken}.yml`;
    fs.renameSync(path.join(root, 'refs/common.yaml'), path.join(root, 'refs', refName));
    fs.renameSync(path.join(root, 'policy.yml'), path.join(root, policyName));
    fs.writeFileSync(path.join(root, 'openapi.yaml'), fs.readFileSync(path.join(root, 'openapi.yaml'), 'utf8')
      .replace('common.yaml', refName));
    const result = await analyzeSourceAwareWorkspace({ ...args(root), policyPath: policyName });
    expect(result.stages.declared.status).not.toBe('failed');
    expect(result.stages.allowed.status).toBe('complete');
    expect(result.evidence.openapi?.sources.map(({ uri }) => uri)).toContain('refs/[REDACTED_FILENAME]');
    expect(result.evidence.policy?.sources.map(({ uri }) => uri)).toContain('[REDACTED_FILENAME]');
    expect(JSON.stringify(result)).not.toContain(refToken);
    expect(JSON.stringify(result)).not.toContain(policyToken);
  });

  test('binds inherited Policy inputs without treating projected semantics as input bytes', async () => {
    const root = workspace();
    fs.renameSync(path.join(root, 'policy.yml'), path.join(root, 'parent.yml'));
    fs.writeFileSync(path.join(root, 'policy.yml'), 'extends: parent.yml\nversion: 2\n');
    const first = await analyzeSourceAwareWorkspace(args(root));
    expect(first.stages.allowed.status).toBe('complete');
    expect(first.evidence.policy?.sources.map(({ uri }) => uri)).toEqual(['parent.yml', 'policy.yml']);
    const parentDigest = first.evidence.policy?.sources[0].digest;
    expect(parentDigest).toBe(`sha256:${hash(path.join(root, 'parent.yml'))}`);
    expect(first.evidence.policy?.digest).not.toBe(first.evidence.policy?.policyDigest);
    fs.appendFileSync(path.join(root, 'parent.yml'), '\n# harmless source change\n');
    const second = await analyzeSourceAwareWorkspace(args(root));
    expect(second.evidence.policy?.sources[0].digest).not.toBe(parentDigest);
    expect(second.evidence.policy?.policyDigest).toBe(first.evidence.policy?.policyDigest);
  });

  test('rejects escaped refs and symlinked Policy without exposing local paths', async () => {
    const root = workspace();
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-source-outside-'));
    roots.push(outside);
    fs.writeFileSync(path.join(outside, 'policy.yml'), policy);
    fs.rmSync(path.join(root, 'policy.yml'));
    fs.symlinkSync(path.join(outside, 'policy.yml'), path.join(root, 'policy.yml'));
    fs.writeFileSync(path.join(root, 'openapi.yaml'), `openapi: 3.0.3\ninfo: {title: Test, version: 1.0.0}\npaths:\n  /x:\n    get:\n      parameters: [{\"$ref\": \"../outside.yaml#/components/x\"}]\n      responses: {'200': {description: OK}}\n`);
    const result = await analyzeSourceAwareWorkspace(args(root));
    expect(result.stages.declared.status).toBe('failed');
    expect(result.stages.allowed.status).toBe('failed');
    expect(result.evidence.openapi).toBeUndefined();
    expect(result.evidence.policy).toBeUndefined();
    expect(JSON.stringify(result)).not.toContain(root);
    expect(JSON.stringify(result)).not.toContain(outside);
  });
});
