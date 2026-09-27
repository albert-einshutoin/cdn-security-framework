import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, test, vi } from 'vitest';

import { analyzeSourceAwareWorkspace } from '../../src/contract/source-aware-workspace';
import { finalizeSourceAwareWorkspace, formatSourceAwarePreviewJson, formatSourceAwarePreviewText } from '../../src/contract/source-aware-finalizer';
import { compareSecurityContracts, createSecurityContract, projectPolicyToAllowedSurface } from '../../src/contract';
import { DEFAULT_SOURCE_ANALYSIS_LIMITS } from '../../src/source-analysis';
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
  fs.writeFileSync(path.join(dependency, 'index.d.ts'), `export declare function Controller(path?: string | { path?: string; version?: string }): ClassDecorator;
export declare function Get(path?: string): MethodDecorator;
export declare function Post(path?: string): MethodDecorator;
export declare function Head(path?: string): MethodDecorator;
export declare function Version(value: string | string[]): MethodDecorator;
export declare function Search(path?: string): MethodDecorator;
export declare const VERSION_NEUTRAL: unique symbol;\n`);
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
  test('compares a declared URI version against a static Controller version', async () => {
    const root = workspace();
    fs.writeFileSync(path.join(root, 'src/controller.ts'), `import { Controller, Get } from '@nestjs/common';
      @Controller({ path: 'users', version: '1' }) class Users { @Get(':id') read() {} }
    `);
    const openapi = path.join(root, 'openapi.yaml');
    fs.writeFileSync(openapi, fs.readFileSync(openapi, 'utf8').replace('/users/{id}', '/v2/users/{id}'));
    const result = await analyzeSourceAwareWorkspace({ ...args(root),
      source: { tsconfigPath: 'tsconfig.json', versioning: 'uri' } });
    expect(result.comparisons.implementedDeclared.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: 'SC-INVENTORY-001',
        route: expect.objectContaining({ method: 'GET', path: '/v1/users/{id}' }) }),
    ]));
    expect(result.comparisons.implementedDeclared.findings?.some((finding: any) =>
      finding.route?.path === '/users/{id}')).toBe(false);
  });

  test('keeps single Controller and method versions with original and comparison paths', async () => {
    const root = workspace();
    fs.writeFileSync(path.join(root, 'src/controller.ts'), `import { Controller, Get, Version } from '@nestjs/common';
      const FIRST = '01';
      @Controller({ path: 'users', version: FIRST }) class Users {
        @Get(':id') read() {}
        @Version('2') @Get('list') list() {}
      }
      @Controller({ version: 'A' }) class Root { @Get() root() {} }
    `);
    const local = await analyzeSourceAwareWorkspace({ ...args(root),
      source: { tsconfigPath: 'tsconfig.json', versioning: 'uri' } });
    const prefixed = await analyzeSourceAwareWorkspace({ ...args(root),
      source: { tsconfigPath: 'tsconfig.json', versioning: 'uri', globalPrefix: '/api' } });
    const resolved = prefixed.evidence.sourceVersionMetadata?.routes.filter((route) => route.status === 'resolved');
    expect(resolved?.map(({ localPath, version, origin, comparisonPath }) =>
      [localPath, version, origin, comparisonPath])).toEqual([
      ['/', 'A', 'controller', '/api/vA'],
      ['/users/{id}', '01', 'controller', '/api/v01/users/{id}'],
      ['/users/list', '2', 'method', '/api/v2/users/list'],
    ]);
    expect(prefixed.evidence.source?.projectDigest).toBe(local.evidence.source?.projectDigest);
    expect(prefixed.evidence.source?.configDigest).toBe(local.evidence.source?.configDigest);
    expect(prefixed.evidence.sourceVersionMetadata?.digest).toBe(local.evidence.sourceVersionMetadata?.digest);
    expect(prefixed.evidence.routingAssumption?.digest).not.toBe(local.evidence.routingAssumption?.digest);
    expect(prefixed.evidence.routingAssumption?.comparisonContractDigest)
      .not.toBe(local.evidence.routingAssumption?.comparisonContractDigest);
  });

  test('retains two versions of the same local route and treats unresolved method version as partial', async () => {
    const root = workspace();
    fs.writeFileSync(path.join(root, 'src/controller.ts'), `import { Controller, Get, Version } from '@nestjs/common';
      const dynamic = () => { throw new Error('Source executed'); };
      @Controller({ path: 'users', version: '1' }) class One {
        @Get() read() {}
        @Version(dynamic()) @Get('bad') bad() {}
      }
      @Controller({ path: 'users', version: '2' }) class Two { @Get() read() {} }
    `);
    const result = await analyzeSourceAwareWorkspace({ ...args(root),
      source: { tsconfigPath: 'tsconfig.json', versioning: 'uri' } });
    expect(result.evidence.sourceVersionMetadata?.routes.filter(({ status }) => status === 'resolved')
      .map(({ comparisonPath }) => comparisonPath)).toEqual(['/v1/users', '/v2/users']);
    expect(result.evidence.sourceVersionMetadata?.routes.some(({ reason }) =>
      reason === 'VERSION_UNRESOLVED')).toBe(true);
    expect(result.evidence.sourceVersionMetadata?.routes.some(({ comparisonPath }) =>
      comparisonPath === '/v1/users/bad')).toBe(false);
    expect(result.stages.implemented.status).toBe('partial');
  });

  test.each([
    "@Version(['1', '2'])",
    '@Version(VERSION_NEUTRAL)',
    "@Version('2') @Version('3')",
  ])('does not rescue unsupported method version %s with a Controller version', async (metadata) => {
    const root = workspace();
    fs.writeFileSync(path.join(root, 'src/controller.ts'), `import { Controller, Get, Version, VERSION_NEUTRAL } from '@nestjs/common';
      @Controller({ path: 'users', version: '1' }) class Users {
        ${metadata} @Get('unsafe') read() {}
      }
    `);
    const result = await analyzeSourceAwareWorkspace({ ...args(root), source: {
      tsconfigPath: 'tsconfig.json', versioning: 'uri',
    } });
    expect(result.evidence.sourceVersionMetadata?.routes).toEqual(expect.arrayContaining([
      expect.objectContaining({ status: 'unresolved', reason: 'VERSION_UNRESOLVED' }),
    ]));
    expect(result.evidence.sourceVersionMetadata?.routes.some(({ comparisonPath }) =>
      comparisonPath === '/v1/users/unsafe')).toBe(false);
  });

  test('does not infer missing versions or erase literal api and v1 segments', async () => {
    const root = workspace();
    fs.writeFileSync(path.join(root, 'src/controller.ts'), `import { Controller, Get } from '@nestjs/common';
      @Controller({ path: 'api/v1/users', version: '1' }) class Literal { @Get() read() {} }
      @Controller('plain') class Plain { @Get() read() {} }
    `);
    const result = await analyzeSourceAwareWorkspace({ ...args(root),
      source: { tsconfigPath: 'tsconfig.json', versioning: 'uri', globalPrefix: '/api' } });
    expect(result.evidence.sourceVersionMetadata?.routes.map(({ comparisonPath, reason }) =>
      comparisonPath ?? reason)).toEqual(['/api/v1/api/v1/users', 'VERSION_MISSING']);
    const withoutSource = await analyzeSourceAwareWorkspace({ ...args(root), source: undefined });
    expect(result.comparisons.declaredAllowed).toEqual(withoutSource.comparisons.declaredAllowed);
  });

  test.each([
    ["['1']", 'VERSION_UNRESOLVED'],
    ["[]", 'VERSION_UNRESOLVED'],
    ['VERSION_NEUTRAL', 'VERSION_UNRESOLVED'],
    ["''", 'VERSION_UNRESOLVED'],
    ['1', 'VERSION_UNRESOLVED'],
    ["'1/2'", 'VERSION_UNRESOLVED'],
    ['dynamic()', 'VERSION_UNRESOLVED'],
    ["'1'", 'CONTROLLER_ROUTING_UNSUPPORTED', "host: 'example.com', "],
    ["'1'", 'CONTROLLER_ROUTING_UNSUPPORTED', 'unknown: true, '],
  ])('keeps unsupported Controller version %s unresolved', async (version, reason, other = '') => {
    const root = workspace();
    fs.writeFileSync(path.join(root, 'src/controller.ts'), `import { Controller, Get, VERSION_NEUTRAL } from '@nestjs/common';
      const dynamic = () => '1';
      @Controller({ path: 'users', ${other}version: ${version} }) class Users { @Get() read() {} }
    `);
    const result = await analyzeSourceAwareWorkspace({ ...args(root),
      source: { tsconfigPath: 'tsconfig.json', versioning: 'uri' } });
    expect(result.stages.implemented.status).toBe('partial');
    expect(result.evidence.sourceVersionMetadata?.routes).toEqual(expect.arrayContaining([
      expect.objectContaining({ status: 'unresolved', reason }),
    ]));
    expect(result.evidence.sourceVersionMetadata?.routes.some(({ status }) => status === 'resolved')).toBe(false);
    expect(result.comparisons.implementedDeclared.findings?.some(({ ruleId, route }) =>
      ruleId === 'SC-INVENTORY-001' && (route?.path === '/v1/users' || route?.path === '/users'))).toBe(false);
  });

  test('does not treat a same-named local Version decorator as NestJS version metadata', async () => {
    const root = workspace();
    fs.writeFileSync(path.join(root, 'src/controller.ts'), `import { Controller, Get } from '@nestjs/common';
      function Version(_value: string): MethodDecorator { return () => {}; }
      @Controller({ path: 'users', version: '1' }) class Users {
        @Version('2') @Get() read() {}
      }
    `);
    const result = await analyzeSourceAwareWorkspace({ ...args(root),
      source: { tsconfigPath: 'tsconfig.json', versioning: 'uri' } });
    expect(result.evidence.sourceVersionMetadata?.routes.filter(({ status }) => status === 'resolved')
      .map(({ version, comparisonPath }) => [version, comparisonPath])).toEqual([['1', '/v1/users']]);
  });

  test.each([
    ["@Search('unknown') @Get('reported')", 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR'],
    ["@Get(':id(\\\\d+)')", 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR'],
  ])('keeps unsupported route evidence in URI mode for %s', async (decorators, diagnostic) => {
    const root = workspace();
    fs.writeFileSync(path.join(root, 'src/controller.ts'), `import { Controller, Get, Search } from '@nestjs/common';
      @Controller({ path: 'users', version: '1' }) class Users { ${decorators} read() {} }
    `);
    const result = await analyzeSourceAwareWorkspace({ ...args(root),
      source: { tsconfigPath: 'tsconfig.json', versioning: 'uri' } });
    expect(result.stages.implemented.status).toBe('partial');
    expect(result.evidence.sourceVersionMetadata?.routes).toEqual(expect.arrayContaining([
      expect.objectContaining({ status: 'unresolved', reason: 'ROUTE_PATH_UNRESOLVED' }),
    ]));
    expect(result.evidence.sourceVersionMetadata?.routes.some(({ status }) => status === 'resolved')).toBe(false);
    if (decorators.startsWith('@Search')) {
      expect(result.stages.implemented.diagnosticCodes).toContain(diagnostic);
    }
  });

  test('keeps route meaning when same-path versioned Controllers change order', async () => {
    const root = workspace();
    const file = path.join(root, 'src/controller.ts');
    const header = "import { Controller, Get } from '@nestjs/common';\n";
    const first = "@Controller({ path: 'users', version: '1' }) class One { @Get() read() {} }\n";
    const second = "@Controller({ path: 'users', version: '2' }) class Two { @Get() read() {} }\n";
    const inspect = async () => {
      const result = await analyzeSourceAwareWorkspace({ ...args(root),
        source: { tsconfigPath: 'tsconfig.json', versioning: 'uri' } });
      return result.evidence.sourceVersionMetadata?.routes.filter(({ status }) => status === 'resolved')
        .map(({ method, comparisonPath }) => `${method} ${comparisonPath}`).sort();
    };
    fs.writeFileSync(file, header + first + second);
    const original = await inspect();
    fs.writeFileSync(file, header + second + first);
    expect(await inspect()).toEqual(original);
    expect(original).toEqual(['GET /v1/users', 'GET /v2/users']);
  });

  test('finds a wrong declared version, method mismatch, Source-only route and Policy rejection', async () => {
    const root = workspace();
    fs.writeFileSync(path.join(root, 'src/controller.ts'), `import { Controller, Get, Post } from '@nestjs/common';
      @Controller({ path: 'users', version: '1' }) class Users {
        @Get() read() {}
        @Post('extra') write() {}
      }
    `);
    const openapi = path.join(root, 'openapi.yaml');
    fs.writeFileSync(openapi, `openapi: 3.0.3
info: {title: Version comparison, version: 1.0.0}
paths:
  /v2/users:
    get: {responses: {'200': {description: OK}}}
  /v1/users:
    post: {responses: {'200': {description: OK}}}
`);
    const result = await analyzeSourceAwareWorkspace({ ...args(root),
      source: { tsconfigPath: 'tsconfig.json', versioning: 'uri' } });
    const inventory = result.comparisons.implementedDeclared.findings ?? [];
    expect(inventory).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: 'SC-INVENTORY-001',
        route: expect.objectContaining({ method: 'POST', path: '/v1/users/extra' }) }),
      expect.objectContaining({ ruleId: 'SC-INVENTORY-003',
        route: expect.objectContaining({ method: 'GET', path: '/v2/users' }) }),
      expect.objectContaining({ ruleId: 'SC-INVENTORY-004',
        route: expect.objectContaining({ path: '/v1/users' }),
        expected: { methods: ['POST'] }, actual: { methods: ['GET'] } }),
    ]));
    expect(result.comparisons.implementedAllowed.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: 'SC-EXPOSURE-004',
        route: expect.objectContaining({ method: 'POST', path: '/v1/users/extra' }) }),
    ]));
    expect(result.comparisons.declaredAllowed.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: 'SC-EXPOSURE-002',
        route: expect.objectContaining({ method: 'POST', path: '/v1/users' }) }),
    ]));
  });

  test('matches a correctly declared version without a false inventory finding', async () => {
    const root = workspace();
    fs.writeFileSync(path.join(root, 'src/controller.ts'), `import { Controller, Get } from '@nestjs/common';
      @Controller({ path: 'users', version: '1' }) class Users { @Get(':id') read() {} }
    `);
    const file = path.join(root, 'openapi.yaml');
    fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace('/users/{id}', '/v1/users/{id}'));
    const result = await analyzeSourceAwareWorkspace({ ...args(root), source: {
      tsconfigPath: 'tsconfig.json', versioning: 'uri',
    } });
    expect(result.evidence.sourceVersionMetadata?.routes).toEqual(expect.arrayContaining([
      expect.objectContaining({ status: 'resolved', localPath: '/users/{id}',
        comparisonPath: '/v1/users/{id}' }),
    ]));
    expect(result.comparisons.implementedDeclared.findings?.some(({ ruleId, route }) =>
      ruleId.startsWith('SC-INVENTORY-') && route?.path === '/v1/users/{id}')).toBe(false);
  });

  test('separates URI invocation evidence on cached concurrent runs and preserves independent failure', async () => {
    const root = workspace();
    fs.writeFileSync(path.join(root, 'src/controller.ts'), `import { Controller, Get } from '@nestjs/common';
      @Controller({ path: 'users', version: '1' }) class Users { @Get() read() {} }
    `);
    const cache = new TypeScriptAnalysisCache();
    const before = hash(path.join(root, 'src/controller.ts'));
    const [uri, local, prefixed] = await Promise.all([
      analyzeSourceAwareWorkspace({ ...args(root), source: { tsconfigPath: 'tsconfig.json', cache,
        versioning: 'uri' } }),
      analyzeSourceAwareWorkspace({ ...args(root), source: { tsconfigPath: 'tsconfig.json', cache } }),
      analyzeSourceAwareWorkspace({ ...args(root), source: { tsconfigPath: 'tsconfig.json', cache,
        versioning: 'uri', globalPrefix: '/api' } }),
    ]);
    expect(hash(path.join(root, 'src/controller.ts'))).toBe(before);
    expect(uri.evidence.source).toEqual(local.evidence.source);
    expect(prefixed.evidence.source).toEqual(local.evidence.source);
    expect(local.evidence.routingAssumption).toBeUndefined();
    expect(uri.evidence.sourceVersionMetadata?.routes[0].comparisonPath).toBe('/v1/users');
    expect(prefixed.evidence.sourceVersionMetadata?.routes[0].comparisonPath).toBe('/api/v1/users');
    expect(uri.evidence.routingAssumption?.comparisonContractDigest)
      .not.toBe(prefixed.evidence.routingAssumption?.comparisonContractDigest);
    const failed = await analyzeSourceAwareWorkspace({ ...args(root),
      source: { tsconfigPath: '../outside.ts', versioning: 'uri' } });
    expect(failed.stages.implemented.status).toBe('failed');
    expect(failed.comparisons.declaredAllowed).toEqual(uri.comparisons.declaredAllowed);
    expect(failed.evidence.routingAssumption?.comparisonContractDigest).toBeUndefined();
  });

  test('does not extend an old exact exception selector to the URI comparison identity', async () => {
    const root = workspace();
    fs.writeFileSync(path.join(root, 'src/controller.ts'), `import { Controller, Get } from '@nestjs/common';
      @Controller({ path: 'users', version: '1' }) class Users { @Get() read() {} }
    `);
    const old = finalizeSourceAwareWorkspace(await analyzeSourceAwareWorkspace(args(root)), {
      currentDate: '2026-09-25', failOn: 'never',
    });
    const selected = old.findings.find(({ ruleId, route }) =>
      ruleId === 'SC-INVENTORY-003' && route?.path === '/users/{id}');
    expect(selected).toBeDefined();
    if (!selected) return;
    const exceptions = { version: 1 as const, exceptions: [{ id: 'EXC-2026-URI-OLD',
      rule_id: selected.ruleId, selector: { instance_id: selected.instanceId },
      reason: 'Reviewed old exact route.', owner: 'security-team', expires_at: '2026-12-01',
    }] };
    const options = { currentDate: '2026-09-25', failOn: 'never' as const, exceptions };
    expect(finalizeSourceAwareWorkspace(await analyzeSourceAwareWorkspace(args(root)), options)
      .suppressedFindings.map(({ instanceId }) => instanceId)).toContain(selected.instanceId);
    const uri = finalizeSourceAwareWorkspace(await analyzeSourceAwareWorkspace({ ...args(root),
      source: { tsconfigPath: 'tsconfig.json', versioning: 'uri' } }), options);
    expect(uri.suppressedFindings.map(({ instanceId }) => instanceId)).not.toContain(selected.instanceId);
    expect(uri.findings.some(({ ruleId, route }) =>
      ruleId === 'SC-INVENTORY-001' && route?.path === '/v1/users')).toBe(true);
  });

  test('fails URI comparison at operation limits or cancellation without losing independent work', async () => {
    const root = workspace();
    fs.writeFileSync(path.join(root, 'src/controller.ts'), `import { Controller, Get } from '@nestjs/common';
      @Controller({ path: 'users', version: '1' }) class One { @Get() read() {} }
      @Controller({ path: 'users', version: '2' }) class Two { @Get() read() {} }
    `);
    const baseline = await analyzeSourceAwareWorkspace({ ...args(root), source: undefined });
    const limited = await analyzeSourceAwareWorkspace({ ...args(root), source: {
      tsconfigPath: 'tsconfig.json', versioning: 'uri', limits: { maxOperations: 1 },
    } });
    expect(limited.stages.implemented).toMatchObject({ status: 'failed',
      code: 'SOURCE_ANALYZER_OPERATION_LIMIT' });
    expect(limited.comparisons.declaredAllowed).toEqual(baseline.comparisons.declaredAllowed);
    const controller = new AbortController(); controller.abort();
    const cancelled = await analyzeSourceAwareWorkspace({ ...args(root), source: {
      tsconfigPath: 'tsconfig.json', versioning: 'uri', cancellationSignal: controller.signal,
    } });
    expect(cancelled.stages.implemented).toMatchObject({ status: 'failed', code: 'SOURCE_ANALYZER_CANCELLED' });
    expect(cancelled.comparisons.declaredAllowed).toEqual(baseline.comparisons.declaredAllowed);
  });

  test('gives string and direct-object Controller paths the same comparison meaning', async () => {
    const stringRoot = workspace();
    const objectRoot = workspace();
    const file = path.join(objectRoot, 'src/controller.ts');
    const source = fs.readFileSync(file, 'utf8');
    expect(source).toContain('@HttpController(ROOT)');
    fs.writeFileSync(file, source.replace('@HttpController(ROOT)', '@HttpController({ path: ROOT })'));
    const direct = await analyzeSourceAwareWorkspace(args(stringRoot));
    const object = await analyzeSourceAwareWorkspace(args(objectRoot));
    const meaning = (value: typeof direct) => Object.fromEntries(Object.entries(value.comparisons).map(
      ([name, comparison]) => [name, { status: comparison.status,
        findings: comparison.findings?.map(({ ruleId, route, severity }) =>
          ({ ruleId, route, severity })) }],
    ));
    expect(meaning(object)).toEqual(meaning(direct));
    expect(object.evidence.source?.projectDigest).not.toBe(direct.evidence.source?.projectDigest);
  });

  test('compares a static Controller object once while unsupported options stay partial', async () => {
    const root = workspace();
    const source = path.join(root, 'src/controller.ts');
    fs.writeFileSync(source, `import { Controller, Get } from '@nestjs/common';
      @Controller({ path: 'users' }) class Users { @Get(':id') read() {} }
      @Controller({ path: 'versioned', version: '1' }) class Versioned { @Get() read() {} }
      throw new Error('Source executed');\n`);
    const inputNames = ['openapi.yaml', 'refs/common.yaml', 'policy.yml', 'tsconfig.json', 'src/controller.ts'];
    const before = inputNames.map((name) => hash(path.join(root, name)));
    const network = vi.spyOn(globalThis, 'fetch').mockImplementation(() => { throw new Error('network forbidden'); });
    const local = await analyzeSourceAwareWorkspace(args(root));
    const prefixed = await analyzeSourceAwareWorkspace({ ...args(root),
      source: { tsconfigPath: 'tsconfig.json', globalPrefix: '/api' } });
    expect(network).not.toHaveBeenCalled();
    expect(inputNames.map((name) => hash(path.join(root, name)))).toEqual(before);
    expect(prefixed.stages.implemented.status).toBe('partial');
    expect(prefixed.comparisons.implementedDeclared.status).toBe('partial');
    expect(prefixed.comparisons.declaredAllowed).toEqual(local.comparisons.declaredAllowed);
    expect(prefixed.evidence.source?.projectDigest).toBe(local.evidence.source?.projectDigest);
    expect(prefixed.evidence.source?.configDigest).toBe(local.evidence.source?.configDigest);
    expect(prefixed.evidence.routingAssumption?.globalPrefix).toBe('/api');
    expect(prefixed.comparisons.implementedDeclared.findings?.some(({ route }) =>
      route?.path === '/api/users/{id}')).toBe(true);
    expect(JSON.stringify(prefixed)).not.toContain('/api/versioned');
    expect(JSON.stringify(prefixed)).toContain('SOURCE_ANALYZER_UNSUPPORTED_DECORATOR');
    expect(prefixed.comparisons.implementedDeclared.findings?.some(({ message }) =>
      message.includes('absence is not proven'))).toBe(true);
  });

  test('uses one analyzed Source project for distinct explicit comparison routes', async () => {
    const root = workspace();
    const cache = new TypeScriptAnalysisCache();
    const base = await analyzeSourceAwareWorkspace({ ...args(root), source: { tsconfigPath: 'tsconfig.json', cache } });
    const prefixed = await analyzeSourceAwareWorkspace({ ...args(root),
      source: { tsconfigPath: 'tsconfig.json', cache, globalPrefix: '/api' } });
    const prefixedAgain = await analyzeSourceAwareWorkspace({ ...args(root),
      source: { tsconfigPath: 'tsconfig.json', cache, globalPrefix: 'api' } });
    expect(prefixed.evidence.source?.projectDigest).toBe(base.evidence.source?.projectDigest);
    expect(prefixed.evidence.source?.configDigest).toBe(base.evidence.source?.configDigest);
    expect(prefixed.evidence.routingAssumption?.globalPrefix).toBe('/api');
    expect(prefixed.evidence.routingAssumption?.digest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(prefixed.evidence.routingAssumption?.comparisonContractDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(prefixed.evidence.routingAssumption).toEqual(prefixedAgain.evidence.routingAssumption);
    expect(base.evidence.routingAssumption).toBeUndefined();
    expect(prefixed.comparisons.declaredAllowed).toEqual(base.comparisons.declaredAllowed);
    expect(prefixed.comparisons.implementedDeclared.findings?.some(({ route }) =>
      route?.path === '/api/users/{id}')).toBe(true);
    expect(prefixed.comparisons.implementedAllowed.findings?.some(({ route }) =>
      route?.path?.startsWith('/api/'))).toBe(true);
    const wrong = await analyzeSourceAwareWorkspace({ ...args(root),
      source: { tsconfigPath: 'tsconfig.json', cache, globalPrefix: '/other' } });
    expect(wrong.evidence.source?.projectDigest).toBe(prefixed.evidence.source?.projectDigest);
    expect(wrong.evidence.routingAssumption?.digest).not.toBe(prefixed.evidence.routingAssumption?.digest);
    expect(wrong.evidence.routingAssumption?.comparisonContractDigest)
      .not.toBe(prefixed.evidence.routingAssumption?.comparisonContractDigest);
    const [one, two] = await Promise.all(['/one', '/two'].map((globalPrefix) =>
      analyzeSourceAwareWorkspace({ ...args(root), source: { tsconfigPath: 'tsconfig.json', cache, globalPrefix } })));
    expect(one.evidence.routingAssumption?.globalPrefix).toBe('/one');
    expect(two.evidence.routingAssumption?.globalPrefix).toBe('/two');
    expect(one.comparisons.implementedDeclared.findings?.some(({ route }) =>
      route?.path === '/one/users/{id}')).toBe(true);
    expect(two.comparisons.implementedDeclared.findings?.some(({ route }) =>
      route?.path === '/two/users/{id}')).toBe(true);
  });

  test('keeps independent comparison when prefixed Source fails or a copied route exceeds limits', async () => {
    const root = workspace();
    const failed = await analyzeSourceAwareWorkspace({ ...args(root),
      source: { tsconfigPath: '../outside.ts', globalPrefix: '/api' } });
    expect(failed.comparisons.declaredAllowed.status).toMatch(/complete|partial/);
    expect(failed.stages.implemented.status).toBe('failed');
    expect(failed.evidence.routingAssumption?.comparisonContractDigest).toBeUndefined();

    const real = await sourceRunner.runNestJsSourceAnalysisInternal({ workspaceRoot: root,
      entrypoints: ['tsconfig.json'], limits: DEFAULT_SOURCE_ANALYSIS_LIMITS,
      logger: { log() {} } });
    expect(real.execution.status).toBe('success');
    if (real.execution.status !== 'success') return;
    const contract = createSecurityContract({ ...real.execution.result.contract,
      operations: real.execution.result.contract.operations.map((operation, index) =>
        index === 0 ? { ...operation, path: `/${'x'.repeat(16_380)}` } : operation) });
    vi.spyOn(sourceRunner, 'runNestJsSourceAnalysisInternal').mockResolvedValueOnce({ ...real,
      execution: { status: 'success', result: { ...real.execution.result, contract } } });
    const exceeded = await analyzeSourceAwareWorkspace({ ...args(root),
      source: { tsconfigPath: 'tsconfig.json', globalPrefix: '/api' } });
    expect(exceeded.stages.implemented).toMatchObject({ status: 'failed', code: 'SOURCE_ROUTING_TRANSFORM_FAILED' });
    expect(exceeded.comparisons.declaredAllowed.status).toMatch(/complete|partial/);
    expect(exceeded.comparisons.implementedDeclared.status).toBe('failed');
    expect(exceeded.evidence.source?.projectDigest).toBe(real.snapshotDigest && `sha256:${real.snapshotDigest}`);
    expect(exceeded.evidence.routingAssumption?.comparisonContractDigest).toBeUndefined();
  });

  test('finalizes real NestJS/OpenAPI/schema-2 workspace without changing its inputs or executing Source', async () => {
    const root = workspace();
    const names = ['openapi.yaml', 'refs/common.yaml', 'policy.yml', 'tsconfig.json', 'src/controller.ts'];
    const before = names.map((name) => hash(path.join(root, name)));
    const network = vi.spyOn(globalThis, 'fetch').mockImplementation(() => { throw new Error('network forbidden'); });
    const analyzed = await analyzeSourceAwareWorkspace(args(root));
    const final = finalizeSourceAwareWorkspace(analyzed, { currentDate: '2026-09-25', failOn: 'never' });
    const jsonText = formatSourceAwarePreviewJson(final);
    const preview = JSON.parse(jsonText);
    const text = formatSourceAwarePreviewText(final);
    expect(network).not.toHaveBeenCalled();
    expect(final.stages.implemented.status).toBe('partial');
    expect(final.analysis).toMatchObject({ status: 'partial', outcome: 'ok' });
    expect(final.exitCode).toBe(0);
    expect(final.comparisons.declaredAllowed.status).toMatch(/complete|partial/);
    expect(final.comparisons.implementedDeclared.status).toBe('partial');
    expect(final.comparisons.implementedAllowed.status).toBe('partial');
    expect(final.summary.unique).toBeGreaterThan(0);
    expect(preview.summary).toEqual(final.summary);
    expect(preview.comparisons).toEqual(final.comparisons);
    expect(preview.findings.active.map(({ ruleId }: { ruleId: string }) => ruleId))
      .toEqual(final.findings.slice(0, preview.findings.active.length).map(({ ruleId }) => ruleId));
    expect(text).toContain(`unique=${final.summary.unique}`);
    expect(jsonText).not.toContain(root);
    expect(text).not.toContain(root);
    expect(names.map((name) => hash(path.join(root, name)))).toEqual(before);
    expect(formatSourceAwarePreviewJson(final)).toBe(jsonText);

    const { source: _source, ...withoutSource } = args(root);
    const noSource = finalizeSourceAwareWorkspace(await analyzeSourceAwareWorkspace(withoutSource), {
      currentDate: '2026-09-25', failOn: 'never',
    });
    // The fixture's OpenAPI graph remains partial even when Source is intentionally absent.
    expect(noSource.stages.declared.status).toBe('partial');
    expect(noSource.analysis).toMatchObject({ status: 'partial', outcome: 'ok' });
    expect(noSource.comparisons.implementedDeclared).toEqual({ status: 'omitted', code: 'SOURCE_NOT_REQUESTED' });
    expect(noSource.summary.unique).toBe(noSource.comparisons.declaredAllowed.status === 'complete'
      || noSource.comparisons.declaredAllowed.status === 'partial' ? noSource.comparisons.declaredAllowed.count : -1);

    const sourceFailed = finalizeSourceAwareWorkspace(await analyzeSourceAwareWorkspace({
      ...args(root), source: { tsconfigPath: '../outside.ts' },
    }), { currentDate: '2026-09-25', failOn: 'never' });
    expect(sourceFailed.comparisons.declaredAllowed.status).toMatch(/complete|partial/);
    expect(sourceFailed.comparisons.implementedDeclared.status).toBe('failed');
    expect(sourceFailed.analysis).toMatchObject({ status: 'failed', outcome: 'input-error' });
    expect(sourceFailed.exitCode).toBe(2);
    expect(names.map((name) => hash(path.join(root, name)))).toEqual(before);
  });

  test('classifies an unexpected Source runner rejection as internal without leaking its message', async () => {
    const root = workspace();
    vi.spyOn(sourceRunner, 'runNestJsSourceAnalysisInternal')
      .mockRejectedValueOnce(new Error('synthetic-token-opaquevalue123'));
    const analyzed = await analyzeSourceAwareWorkspace(args(root));
    expect(analyzed.stages.implemented).toMatchObject({ status: 'failed', code: 'SOURCE_ANALYZER_INTERNAL' });
    const final = finalizeSourceAwareWorkspace(analyzed, { currentDate: '2026-09-25', failOn: 'never' });
    expect(final).toMatchObject({ analysis: { status: 'failed', outcome: 'internal-error' }, exitCode: 3 });
    expect(final.comparisons.declaredAllowed.status).toMatch(/complete|partial/);
    expect(formatSourceAwarePreviewJson(final)).not.toContain('opaquevalue123');
  });

  test('finalization retains the independent real comparison on OpenAPI, Policy or Source limit failure', async () => {
    const root = workspace();
    const openapiPath = path.join(root, 'openapi.yaml');
    const originalOpenapi = fs.readFileSync(openapiPath);
    fs.writeFileSync(openapiPath, 'not: openapi\n');
    const badOpenapiHash = hash(openapiPath);
    const badOpenapi = finalizeSourceAwareWorkspace(await analyzeSourceAwareWorkspace(args(root)), {
      currentDate: '2026-09-25', failOn: 'never',
    });
    expect(badOpenapi.comparisons.declaredAllowed.status).toBe('failed');
    expect(badOpenapi.comparisons.implementedAllowed.status).toMatch(/complete|partial/);
    expect(badOpenapi.summary.unique).toBeGreaterThan(0);
    expect(badOpenapi.analysis).toMatchObject({ status: 'failed', outcome: 'input-error' });
    expect(badOpenapi.exitCode).toBe(2);
    expect(hash(openapiPath)).toBe(badOpenapiHash);

    fs.writeFileSync(openapiPath, originalOpenapi);
    const policyPath = path.join(root, 'policy.yml');
    fs.writeFileSync(policyPath, 'version: 1\n');
    const badPolicyHash = hash(policyPath);
    const badPolicy = finalizeSourceAwareWorkspace(await analyzeSourceAwareWorkspace(args(root)), {
      currentDate: '2026-09-25', failOn: 'never',
    });
    expect(badPolicy.comparisons.implementedDeclared.status).toMatch(/complete|partial/);
    expect(badPolicy.comparisons.implementedAllowed.status).toBe('failed');
    expect(badPolicy.analysis).toMatchObject({ status: 'failed', outcome: 'input-error' });
    expect(badPolicy.exitCode).toBe(2);
    expect(hash(policyPath)).toBe(badPolicyHash);

    fs.writeFileSync(policyPath, policy);
    const limited = finalizeSourceAwareWorkspace(await analyzeSourceAwareWorkspace({
      ...args(root), source: { tsconfigPath: 'tsconfig.json', limits: { maxOperations: 1 } },
    }), { currentDate: '2026-09-25', failOn: 'never' });
    expect(limited.comparisons.declaredAllowed.status).toMatch(/complete|partial/);
    expect(limited.stages.implemented).toMatchObject({ status: 'failed', code: 'SOURCE_ANALYZER_OPERATION_LIMIT' });
    expect(limited.analysis).toMatchObject({ status: 'failed', outcome: 'input-error' });
    expect(limited.exitCode).toBe(2);
  });

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
