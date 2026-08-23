import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';

import { HTTP_METHODS } from '../../src/contract/canonical-route';
import { serializeSecurityContract } from '../../src/contract/security-ir';
import {
  DEFAULT_SOURCE_ANALYSIS_LIMITS,
  runSourceAnalyzer,
  type SourceAnalysisContext,
} from '../../src/source-analysis';
import { nestJsSourceAnalyzer } from '../../src/source/nestjs/analyzer';

const roots: string[] = [];

function write(root: string, relative: string, contents: string): void {
  const target = path.join(root, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents);
}

function installNestJsCommon(root: string, packageRoot = 'node_modules/@nestjs/common'): void {
  write(root, `${packageRoot}/package.json`, JSON.stringify({
    name: '@nestjs/common', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
  }));
  write(root, `${packageRoot}/index.js`, 'module.exports = {};\n');
  write(root, `${packageRoot}/index.d.ts`, `
    export declare function Controller(path?: string | readonly string[]): ClassDecorator;
    export declare function Get(path?: string | readonly string[]): MethodDecorator;
    export declare function Post(path?: string | readonly string[]): MethodDecorator;
    export declare function Put(path?: string | readonly string[]): MethodDecorator;
    export declare function Patch(path?: string | readonly string[]): MethodDecorator;
    export declare function Delete(path?: string | readonly string[]): MethodDecorator;
    export declare function Options(path?: string | readonly string[]): MethodDecorator;
    export declare function Head(path?: string | readonly string[]): MethodDecorator;
    export declare function All(path?: string | readonly string[]): MethodDecorator;
    export declare function Sse(path?: string | readonly string[]): MethodDecorator;
    export declare function Version(value: string): MethodDecorator & ClassDecorator;
    export declare function RequestMapping(options?: object): MethodDecorator;
    export declare function Search(path?: string): MethodDecorator;
    export declare enum RequestMethod { GET }
    export declare const fake: { Get: typeof Get };
  `);
}

function workspace(source: string): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nestjs-route-analyzer-'));
  roots.push(root);
  write(root, 'tsconfig.json', JSON.stringify({
    compilerOptions: {
      experimentalDecorators: true,
      moduleResolution: 'node',
      noLib: true,
      types: [],
    },
    files: ['src/controller.ts'],
  }));
  installNestJsCommon(root);
  write(root, 'src/controller.ts', source);
  return root;
}

function context(root: string, maxOperations = DEFAULT_SOURCE_ANALYSIS_LIMITS.maxOperations): SourceAnalysisContext {
  return {
    workspaceRoot: root,
    entrypoints: ['tsconfig.json'],
    limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxOperations },
    logger: { log() {} },
  };
}

function afterProjectLoad(action: () => void, remaining = 4): void {
  setImmediate(() => {
    if (remaining === 1) action();
    else afterProjectLoad(action, remaining - 1);
  });
}

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe('NestJS route analyzer', () => {
  test('matches the fixture Security IR golden', async () => {
    const fixture = path.join(process.cwd(), 'test/fixtures/source-analysis/nestjs-basic');
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nestjs-route-analyzer-golden-'));
    roots.push(root);
    fs.cpSync(fixture, root, { recursive: true });
    installNestJsCommon(root);
    const execution = await runSourceAnalyzer(nestJsSourceAnalyzer, context(root));
    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(serializeSecurityContract(execution.result.contract)).toBe(fs.readFileSync(
      path.join(root, 'expected/security-ir.json'), 'utf8',
    ));
  });

  test('extracts only NestJS routes without executing decorators or source', async () => {
    const root = workspace(`
      import { Controller as HttpController, Get as Read, All, Version } from '@nestjs/common';
      import * as Nest from '@nestjs/common';

      const PREFIX = 'users';
      const DETAILS = 'details' + '/view';
      function Get(_path: string) { throw new Error('local decorator must not execute'); }

      abstract class BaseController {
        @Nest.Head('inherited') inherited() {}
      }

      @HttpController('/' + PREFIX + '/') @HttpController('inner')
      class UsersController extends BaseController {
        @Read([':id', DETAILS]) list() {}
        @Nest.Post() @Nest.Put('/save/') save() {}
        @All('*') all() {}
        @Nest.Delete(process.env.ROUTE) dynamic() {}
        @Version('1') @Nest.Options('versioned') versioned() {}
        @Nest.Sse('events') events() {}
        @Get('fake') fake() {}
        @Nest.Get(':id(\\\\d+)') regex() {}
      }

      class NotAController { @Nest.Get('ignored') ignored() {} }
      throw new Error('source must not execute');
    `);

    const execution = await runSourceAnalyzer(nestJsSourceAnalyzer, context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    const { contract, diagnostics, unresolvedOperations, metrics } = execution.result;
    const routeKeys = contract.operations.map(({ routeKey }) => routeKey);
    expect(routeKeys).toEqual(expect.arrayContaining([
      'GET /users/{id}',
      'GET /users/details/view',
      'HEAD /users/inherited',
      'GET /users/events',
      'POST /users',
      ...HTTP_METHODS.map((method) => `${method} /users/*`),
    ]));
    expect(routeKeys).not.toContain('PUT /users/save');
    expect(routeKeys).not.toContain('OPTIONS /users/versioned');
    expect(routeKeys.some((routeKey) => routeKey.includes('/inner'))).toBe(false);
    expect(routeKeys.some((routeKey) => routeKey.endsWith('/fake'))).toBe(false);
    expect(routeKeys.some((routeKey) => routeKey.endsWith('/ignored'))).toBe(false);
    expect(contract.capabilities.routes).toBe('partial');
    expect(contract.operations.every(({ exposure, auth }) => (
      exposure === 'unknown' && auth.mode === 'unknown'
    ))).toBe(true);
    expect(contract.operations.every(({ provenance }) => (
      provenance[0]?.uri === 'src/controller.ts'
      && /^line:[1-9]\d*:column:[1-9]\d*$/u.test(provenance[0]?.pointer ?? '')
    ))).toBe(true);
    expect(diagnostics.map(({ code }) => code)).toEqual(expect.arrayContaining([
      'SOURCE_ANALYZER_DYNAMIC_ROUTE',
      'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR',
    ]));
    expect(unresolvedOperations).toEqual(expect.arrayContaining([
      expect.objectContaining({
        methods: ['DELETE'],
        path: null,
        reason: 'SOURCE_ANALYZER_DYNAMIC_ROUTE',
        sourceUri: 'src/controller.ts',
      }),
      expect.objectContaining({
        methods: ['GET'],
        path: null,
        reason: 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR',
        sourceUri: 'src/controller.ts',
      }),
      expect.objectContaining({
        methods: ['OPTIONS'],
        path: null,
        reason: 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR',
        sourceUri: 'src/controller.ts',
      }),
    ]));
    expect(metrics.operations).toBe(contract.operations.length
      + unresolvedOperations.reduce((total, candidate) => total + candidate.methods.length, 0));
  }, 15_000);

  test('accepts immutable tuples but rejects mutable paths and property imports', async () => {
    const root = workspace(`
      import { Controller, Get, Post, fake } from '@nestjs/common';
      const MUTABLE = ['mutable'];
      const IMMUTABLE = ((['one', 'two'] as const) satisfies readonly string[]);
      const READONLY: readonly ['three'] = ['three'];
      @Controller('items') class ItemsController {
        @Get(MUTABLE) mutable() {}
        @Post(IMMUTABLE) @Post(READONLY) immutable() {}
        @fake.Get('fake') fake() {}
      }
    `);

    const execution = await runSourceAnalyzer(nestJsSourceAnalyzer, context(root));
    expect(execution).toMatchObject({
      status: 'success',
      result: {
        contract: { operations: [
          { routeKey: 'POST /items/one' },
          { routeKey: 'POST /items/two' },
        ] },
        diagnostics: expect.arrayContaining([
          expect.objectContaining({ code: 'SOURCE_ANALYZER_DYNAMIC_ROUTE' }),
          expect.objectContaining({ code: 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR' }),
        ]),
      },
    });
  });

  test('rejects path-mapped NestJS decorator lookalikes including fake node_modules paths', async () => {
    const root = workspace(`
      import { Controller, Get } from '@nestjs/common';
      @Controller('items') class ItemsController { @Get() list() {} }
    `);
    write(root, 'tsconfig.json', JSON.stringify({
      compilerOptions: {
        baseUrl: '.', experimentalDecorators: true, moduleResolution: 'node', noLib: true, types: [],
        paths: { '@nestjs/common': ['vendor/node_modules/@nestjs/common/index.d.ts'] },
      },
      files: ['src/controller.ts', 'vendor/node_modules/@nestjs/common/index.d.ts'],
    }));
    write(root, 'vendor/node_modules/@nestjs/common/index.d.ts', `
      export declare function Controller(path?: string): ClassDecorator;
      export declare function Get(path?: string): MethodDecorator;
    `);

    const execution = await runSourceAnalyzer(nestJsSourceAnalyzer, context(root));
    expect(execution).toMatchObject({
      status: 'success',
      result: {
        contract: { operations: [] },
        diagnostics: [{ code: 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR' }],
      },
    });
  });

  test('accepts a genuine pnpm-style NestJS package location', async () => {
    const root = workspace(`
      import { Controller, Get } from '@nestjs/common';
      @Controller('items') class ItemsController { @Get() list() {} }
    `);
    const packageLink = path.join(root, 'node_modules/@nestjs/common');
    const storeRelative = 'node_modules/.pnpm/@nestjs+common@1.0.0/node_modules/@nestjs/common';
    const store = path.join(root, storeRelative);
    fs.rmSync(packageLink, { recursive: true });
    installNestJsCommon(root, storeRelative);
    fs.symlinkSync(path.relative(path.dirname(packageLink), store), packageLink, 'dir');
    write(root, 'tsconfig.json', JSON.stringify({
      compilerOptions: {
        experimentalDecorators: true, moduleResolution: 'node', noLib: true, preserveSymlinks: true, types: [],
      },
      files: ['src/controller.ts'],
    }));

    await expect(runSourceAnalyzer(nestJsSourceAnalyzer, context(root))).resolves.toMatchObject({
      status: 'success', result: { contract: { operations: [{ routeKey: 'GET /items' }] } },
    });
  });

  test('fails closed for class versions and RequestMapping routes', async () => {
    const root = workspace(`
      import { Controller, Get, RequestMapping, RequestMethod, Version } from '@nestjs/common';
      @Version('1') @Controller('users')
      class UsersController { @Get('list') list() {} }
      @Controller('system')
      class SystemController {
        @RequestMapping({ path: 'health', method: RequestMethod.GET }) health() {}
      }
    `);

    const execution = await runSourceAnalyzer(nestJsSourceAnalyzer, context(root));
    expect(execution).toMatchObject({
      status: 'success',
      result: {
        contract: { operations: [] },
        unresolvedOperations: expect.arrayContaining([
          expect.objectContaining({ methods: ['GET'], reason: 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR' }),
          expect.objectContaining({ methods: HTTP_METHODS, reason: 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR' }),
        ]),
      },
    });
  });

  test('reports unsupported Search routes instead of silently dropping them', async () => {
    const root = workspace(`
      import { Controller, Get, Search } from '@nestjs/common';
      @Controller('items') class ItemsController { @Search('actual') @Get('reported') search() {} }
    `);
    await expect(runSourceAnalyzer(nestJsSourceAnalyzer, context(root))).resolves.toMatchObject({
      status: 'success',
      result: {
        contract: { operations: [] },
        diagnostics: [{ code: 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR' }],
      },
    });
  });

  test('ignores static and abstract methods and rejects URL suffixes', async () => {
    const root = workspace(`
      import { Controller, Get } from '@nestjs/common';
      const QUOTED = 'quoted';
      const COMPUTED = 'comp' + 'uted';
      abstract class BaseController {
        @Get('abstract') abstract missing(): void;
        @Get('static') static staticRoute() {}
        @Get('overload') overloaded(value: string): void;
        overloaded(_value: string) {}
        @Get('inherited') inherited() {}
        @Get('quoted') quoted() {}
        @Get('computed') computed() {}
        @Get('abstract-shadow') abstractShadow() {}
      }
      @Controller('items') abstract class ItemsController extends BaseController {
        [QUOTED]() {}
        [COMPUTED]() {}
        abstract abstractShadow(): void;
        @Get('query?secret=value') query() {}
        @Get('hash#part') hash() {}
      }
    `);

    const execution = await runSourceAnalyzer(nestJsSourceAnalyzer, context(root));
    expect(execution).toMatchObject({
      status: 'success',
      result: {
        contract: { operations: [
          { routeKey: 'GET /items/abstract-shadow' },
          { routeKey: 'GET /items/inherited' },
        ] },
        unresolvedOperations: [
          { methods: ['GET'], reason: 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR' },
          { methods: ['GET'], reason: 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR' },
        ],
      },
    });
  });

  test('counts and orders every dynamic All method deterministically', async () => {
    const root = workspace(`
      import { All, Controller } from '@nestjs/common';
      @Controller('items') class ItemsController { @All(process.env.ROUTE) all() {} }
    `);
    const first = await runSourceAnalyzer(nestJsSourceAnalyzer, context(root, HTTP_METHODS.length));
    const second = await runSourceAnalyzer(nestJsSourceAnalyzer, context(root, HTTP_METHODS.length));
    expect(first).toMatchObject({
      status: 'success',
      result: {
        unresolvedOperations: [{ methods: HTTP_METHODS, path: null }],
        metrics: { operations: HTTP_METHODS.length },
      },
    });
    expect(second).toEqual(first);
    await expect(runSourceAnalyzer(nestJsSourceAnalyzer, context(root, HTTP_METHODS.length - 1))).resolves.toMatchObject({
      status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_OPERATION_LIMIT' }],
    });
  });

  test('bounds repeated const expansion', async () => {
    const declarations = ["const P0 = 'x';"];
    for (let index = 1; index <= 24; index += 1) {
      declarations.push(`const P${index} = P${index - 1} + P${index - 1};`);
    }
    const root = workspace(`
      import { Controller, Get } from '@nestjs/common';
      ${declarations.join('\n')}
      @Controller() class AppController { @Get(P24) index() {} }
    `);
    await expect(runSourceAnalyzer(nestJsSourceAnalyzer, context(root))).resolves.toMatchObject({
      status: 'success',
      result: { unresolvedOperations: [{ reason: 'SOURCE_ANALYZER_DYNAMIC_ROUTE' }] },
    });
  });

  test('rejects local decorators with NestJS names and enforces the operation limit', async () => {
    const root = workspace(`
      import { Controller, Get } from '@nestjs/common';
      function Post(_path?: string) { return () => {}; }
      @Controller('items')
      class ItemsController {
        @Get() one() {}
        @Post('fake') fake() {}
      }
    `);

    const execution = await runSourceAnalyzer(nestJsSourceAnalyzer, context(root, 1));
    expect(execution).toMatchObject({
      status: 'success',
      result: { contract: { operations: [{ routeKey: 'GET /items' }] } },
    });

    const reExportRoot = workspace(`
      import { Controller, Get } from './wrapper';
      @Controller('items') class ItemsController { @Get() one() {} }
    `);
    write(reExportRoot, 'src/wrapper.ts', "export { Controller, Get } from '@nestjs/common';\n");
    const reExported = await runSourceAnalyzer(nestJsSourceAnalyzer, context(reExportRoot));
    expect(reExported).toMatchObject({
      status: 'success',
      result: {
        contract: { operations: [] },
        diagnostics: [{ code: 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR' }],
      },
    });

    const limitedRoot = workspace(`
      import { Controller, Get, Post } from '@nestjs/common';
      @Controller('items') class ItemsController { @Get() one() {} @Post() two() {} }
    `);
    await expect(runSourceAnalyzer(nestJsSourceAnalyzer, context(limitedRoot, 1))).resolves.toMatchObject({
      status: 'failed',
      diagnostics: [{ code: 'SOURCE_ANALYZER_OPERATION_LIMIT' }],
    });
  }, 15_000);

  test('honors cancellation before project analysis', async () => {
    const root = workspace(`
      import { Controller, Get } from '@nestjs/common';
      @Controller() class AppController { @Get() index() {} }
    `);
    const controller = new AbortController();
    controller.abort();

    await expect(runSourceAnalyzer(nestJsSourceAnalyzer, {
      ...context(root), cancellationSignal: controller.signal,
    })).resolves.toMatchObject({
      status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_CANCELLED' }],
    });
  });

  test('honors cancellation inside a single large class', async () => {
    const root = workspace(`
      import { Controller, Get } from '@nestjs/common';
      @Controller() class AppController {
        ${Array.from({ length: 512 }, (_, index) => `@Get('${index}') route${index}() {}`).join('\n')}
      }
    `);
    const controller = new AbortController();
    const analysis = nestJsSourceAnalyzer.analyze({
      ...context(root), cancellationSignal: controller.signal,
    });
    afterProjectLoad(() => controller.abort());

    await expect(analysis).rejects.toMatchObject({ code: 'SOURCE_ANALYZER_CANCELLED' });
  });

  test('honors the analysis deadline', async () => {
    const root = workspace(`
      import { Controller, Get } from '@nestjs/common';
      @Controller() class AppController {
        ${Array.from({ length: 512 }, (_, index) => `@Get('${index}') route${index}() {}`).join('\n')}
      }
    `);
    const analysis = nestJsSourceAnalyzer.analyze({
      ...context(root), limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, timeoutMs: 1_000 },
    });
    afterProjectLoad(() => {
      const until = Date.now() + 1_050;
      while (Date.now() < until) { /* force the analyzer deadline after project loading */ }
    });

    await expect(analysis).rejects.toMatchObject({ code: 'SOURCE_ANALYZER_TIMEOUT' });
  }, 5_000);
});
