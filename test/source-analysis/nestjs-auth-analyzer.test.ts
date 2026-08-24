import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Ajv from 'ajv';
import { afterEach, describe, expect, test } from 'vitest';

import {
  DEFAULT_SOURCE_ANALYSIS_LIMITS,
  runSourceAnalyzer,
  type SourceAnalysisContext,
} from '../../src/source-analysis';
import {
  createNestJsSourceAnalyzer,
  validateNestJsAuthConfig,
} from '../../src/source/nestjs/analyzer';

const roots: string[] = [];

function write(root: string, relative: string, contents: string): void {
  const target = path.join(root, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents);
}

function workspace(source: string, extraFiles: Record<string, string> = {}): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nestjs-auth-analyzer-'));
  roots.push(root);
  write(root, 'tsconfig.json', JSON.stringify({
    compilerOptions: {
      experimentalDecorators: true,
      moduleResolution: 'node',
      noLib: true,
      types: [],
    },
    files: ['src/controller.ts', ...Object.keys(extraFiles).filter((file) => file.startsWith('src/'))],
  }));
  write(root, 'node_modules/@nestjs/common/package.json', JSON.stringify({
    name: '@nestjs/common', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
  }));
  write(root, 'node_modules/@nestjs/common/index.js', 'module.exports = {};\n');
  write(root, 'node_modules/@nestjs/common/index.d.ts', `
    export declare function Controller(path?: string): ClassDecorator;
    export declare function Get(path?: string): MethodDecorator;
    export declare function UseGuards(...guards: unknown[]): ClassDecorator & MethodDecorator;
    export declare function applyDecorators(...decorators: Array<ClassDecorator | MethodDecorator>): ClassDecorator & MethodDecorator;
    export declare function Module(metadata: { imports?: readonly unknown[]; providers?: readonly unknown[] }): ClassDecorator;
  `);
  const registersProviders = /\b(?:const|let|var)\s+providers\b/u.test(source);
  write(root, 'src/controller.ts', registersProviders ? `
    import { Module } from '@nestjs/common';
    ${source}
    @Module({ providers }) class GeneratedTestModule {}
  ` : source);
  for (const [relative, contents] of Object.entries(extraFiles)) write(root, relative, contents);
  return root;
}

function context(root: string): SourceAnalysisContext {
  return {
    workspaceRoot: root,
    entrypoints: ['tsconfig.json'],
    limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS },
    logger: { log() {} },
  };
}

const authConfig = {
  public_decorators: ['Public'],
  roles_decorators: ['Roles'],
  guard_mappings: {
    JwtAuthGuard: { auth_kind: 'bearer' },
    ApiKeyGuard: { auth_kind: 'api_key' },
    SecondGuard: { auth_kind: 'basic' },
  },
} as const;

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe('NestJS auth metadata analyzer', () => {
  test('composes class and method guards without treating their order as alternatives', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards as Guards } from '@nestjs/common';
      import { ApiKeyGuard, JwtAuthGuard, Public as Open, Roles as Permissions, SecondGuard, UnknownGuard } from './auth';

      @Controller('users')
      @Guards(JwtAuthGuard)
      @Permissions('reader')
      class UsersController {
        @Get('admin') @Guards(ApiKeyGuard) @Guards(SecondGuard)
        @Permissions(['admin', 'ops']) @Permissions('reader') admin() {}
        @Get('public') @Open() @Open('overwritten') publicRoute() {}
        @Get('unknown') @Guards(UnknownGuard) unknown() {}
      }

      @Controller('health')
      class HealthController { @Get() read() {} }
    `, {
      'src/auth.ts': `
        export class JwtAuthGuard {}
        export class ApiKeyGuard {}
        export class SecondGuard {}
        export class UnknownGuard {}
        export const Public = (..._args: unknown[]): MethodDecorator => () => {};
        export const Roles = (..._roles: unknown[]): MethodDecorator & ClassDecorator => () => {};
      `,
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    const operations = Object.fromEntries(execution.result.contract.operations.map((operation) => (
      [operation.routeKey, operation]
    )));
    expect(operations['GET /users/admin']).toMatchObject({
      exposure: 'authenticated',
      auth: {
        mode: 'alternatives',
        alternatives: [{
          anonymous: false,
          schemes: [
            { name: 'ApiKeyGuard', kind: 'api-key' },
            { name: 'SecondGuard', kind: 'basic' },
            { name: 'JwtAuthGuard', kind: 'bearer' },
          ],
        }],
        analysis: {
          guards: [
            { symbol: 'JwtAuthGuard', authKind: 'bearer' },
            { symbol: 'SecondGuard', authKind: 'basic' },
            { symbol: 'ApiKeyGuard', authKind: 'api-key' },
          ],
          explicitPublic: false,
          roles: ['admin', 'ops'],
          enforcementConfidence: 'high',
        },
      },
    });
    expect(operations['GET /users/public']).toMatchObject({
      exposure: 'public',
      auth: {
        mode: 'none',
        alternatives: [],
        analysis: { explicitPublic: true, guards: [{ symbol: 'JwtAuthGuard' }] },
      },
    });
    expect(operations['GET /users/unknown']).toMatchObject({
      exposure: 'unknown',
      auth: {
        mode: 'unknown',
        alternatives: [],
        analysis: {
          guards: [{ symbol: 'JwtAuthGuard' }, { symbol: 'UnknownGuard' }],
          enforcementConfidence: 'unknown',
        },
      },
    });
    expect(operations['GET /health']).toMatchObject({
      exposure: 'unknown',
      auth: { mode: 'unknown', analysis: { explicitPublic: false, guards: [] } },
    });
    expect(operations['GET /users/admin'].provenance).toEqual(expect.arrayContaining([
      expect.objectContaining({ capability: 'authentication' }),
      expect.objectContaining({ capability: 'authorization' }),
    ]));
    const schema = JSON.parse(fs.readFileSync(
      path.join(process.cwd(), 'schemas/security-ir-v1.schema.json'), 'utf8',
    ));
    const validate = new Ajv({ allErrors: true }).compile(schema);
    expect(validate(execution.result.contract), JSON.stringify(validate.errors)).toBe(true);
  });

  test('inherits nearest class auth metadata and fails closed on dynamic metadata', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards as NestGuards } from '@nestjs/common';
      import { JwtAuthGuard, Roles } from './auth';
      declare const dynamicRole: string;
      declare const dynamicGuard: unknown;
      const UseGuards = (..._guards: unknown[]): MethodDecorator => () => {};

      @NestGuards(JwtAuthGuard)
      class BaseController { @Get('inherited') inherited() {} }

      @Controller('items')
      class ItemsController extends BaseController {
        @Get('dynamic-role') @Roles(dynamicRole) dynamicRole() {}
        @Get('dynamic-guard') @NestGuards(dynamicGuard) dynamicGuard() {}
        @Roles(dynamicRole) helper() {}
      }

      @Controller('fake')
      class FakeController { @Get() @UseGuards(JwtAuthGuard) read() {} }
    `, {
      'src/auth.ts': `
        export class JwtAuthGuard {}
        export const Roles = (..._roles: unknown[]): MethodDecorator => () => {};
      `,
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    const operations = Object.fromEntries(execution.result.contract.operations.map((operation) => (
      [operation.routeKey, operation]
    )));
    expect(operations['GET /items/inherited']).toMatchObject({
      auth: { analysis: { guards: [{ symbol: 'JwtAuthGuard', authKind: 'bearer' }] } },
    });
    expect(operations['GET /items/dynamic-role']).toMatchObject({
      exposure: 'authenticated',
      auth: {
        mode: 'alternatives',
        alternatives: [{ schemes: [{ name: 'JwtAuthGuard', kind: 'bearer' }] }],
        analysis: { roles: [], enforcementConfidence: 'unknown' },
      },
    });
    expect(operations['GET /items/dynamic-guard']).toMatchObject({
      exposure: 'unknown', auth: { mode: 'unknown' },
    });
    expect(operations['GET /fake']).toMatchObject({
      auth: { analysis: { guards: [] } },
    });
    expect(execution.result.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_DYNAMIC_AUTH_METADATA' }),
    ]));
    expect(execution.result.diagnostics.filter(({ code }) => (
      code === 'SOURCE_ANALYZER_DYNAMIC_AUTH_METADATA'
    ))).toHaveLength(2);
  });

  test('method auth metadata overrides dynamic class Public and Roles metadata', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard, Public, Roles } from './auth';
      declare const dynamicValue: string;

      @Controller('roles') @UseGuards(JwtAuthGuard) @Roles(dynamicValue)
      class RolesController { @Get() @Roles('admin') read() {} }

      @Controller('public') @Public(dynamicValue)
      class PublicController { @Get() @Public() read() {} }
    `, {
      'src/auth.ts': `
        export class JwtAuthGuard {}
        export const Public = (..._args: unknown[]): MethodDecorator & ClassDecorator => () => {};
        export const Roles = (..._roles: unknown[]): MethodDecorator & ClassDecorator => () => {};
      `,
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    const operations = Object.fromEntries(execution.result.contract.operations.map((operation) => (
      [operation.routeKey, operation]
    )));
    expect(operations['GET /roles']).toMatchObject({
      exposure: 'authenticated',
      auth: {
        mode: 'alternatives',
        analysis: { roles: ['admin'], enforcementConfidence: 'high' },
      },
    });
    expect(operations['GET /public']).toMatchObject({
      exposure: 'public',
      auth: {
        mode: 'none',
        analysis: { explicitPublic: true, enforcementConfidence: 'high' },
      },
    });
  });

  test('recognizes a configured public decorator used without a call', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard, Public } from './auth';
      const Open = Public();
      const Roles: MethodDecorator = () => {};
      const decorators = { Public, Roles };
      const { Public: BareOpen } = decorators;
      const { Public: BareOpenAgain } = decorators;
      void decorators.Public;
      @Controller('bare') @UseGuards(JwtAuthGuard)
      class BareController {
        @Get() @Public read() {}
        @Get('precomputed') @Open precomputed() {}
        @Get('destructured') @BareOpen destructured() {}
        @Get('destructured-again') @BareOpenAgain destructuredAgain() {}
      }
    `, {
      'src/auth.ts': `
        export class JwtAuthGuard {}
        export const Public: MethodDecorator = () => {};
      `,
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer({
      ...authConfig, public_decorators: ['Public', 'Open'],
    }), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract.operations).toEqual(expect.arrayContaining([
      expect.objectContaining({
        exposure: 'public',
        auth: expect.objectContaining({
          mode: 'none', analysis: expect.objectContaining({ explicitPublic: true }),
        }),
      }),
      expect.objectContaining({
        routeKey: 'GET /bare/precomputed',
        exposure: 'public',
        auth: expect.objectContaining({
          mode: 'none', analysis: expect.objectContaining({ explicitPublic: true }),
        }),
      }),
      expect.objectContaining({
        routeKey: 'GET /bare/destructured',
        exposure: 'public',
        auth: expect.objectContaining({ mode: 'none' }),
      }),
      expect.objectContaining({
        routeKey: 'GET /bare/destructured-again',
        exposure: 'public',
        auth: expect.objectContaining({ mode: 'none' }),
      }),
    ]));
  });

  test('fails closed when a configured bare public decorator is reassigned', async () => {
    const controller = (declaration: string) => `
      import { Controller, Get, UseGuards } from '@nestjs/common';
      ${declaration}
      @Controller('mutable-public') @UseGuards(JwtAuthGuard)
      class MutablePublicController { @Get() @Public read() {} }
    `;
    const auth = (binding: string) => ({
      'src/auth.ts': `export class JwtAuthGuard {}\n${binding}`,
    });
    const mutableBindingRoot = workspace(controller(`
      import { JwtAuthGuard, Public } from './auth';
      const Other: MethodDecorator = () => {};
      const decorators = { Public };
      let { Public: Bare } = decorators;
      Bare = Other;
    `).replace('@Public', '@Bare'), auth(
      'export const Public: MethodDecorator = () => {};',
    ));
    const rootsToCheck = [
      workspace(controller(`
        import { JwtAuthGuard, Public as publicDecorator } from './auth';
        let Public = publicDecorator;
        Public = () => {};
      `), auth('export const Public: MethodDecorator = () => {};')),
      workspace(controller("import { JwtAuthGuard, Public } from './auth';"), auth(`
        export let Public: MethodDecorator = () => {};
        Public = () => {};
      `)),
      workspace(controller(`
        import { JwtAuthGuard, Public } from './auth';
        let decorators = { Public };
        decorators = { Public: () => {} };
      `).replace('@Public', '@decorators.Public'), auth(
        'export const Public: MethodDecorator = () => {};',
      )),
      workspace(controller(`
        import { JwtAuthGuard, Public as publicDecorator } from './auth';
        let decorators = { Public: publicDecorator };
        decorators = { Public: () => {} };
        const { Public } = decorators;
        const Alias = Public;
      `).replace('@Public', '@Alias'), auth('export const Public: MethodDecorator = () => {};')),
      workspace(controller(`
        import { JwtAuthGuard, Public as publicDecorator } from './auth';
        const decorators = { Public: publicDecorator };
        function mutate(value: { Public: MethodDecorator }) { value.Public = () => {}; }
        mutate(decorators);
        const { Public } = decorators;
      `), auth('export const Public: MethodDecorator = () => {};')),
      workspace(controller(`
        import { JwtAuthGuard } from './auth';
        const NotPublic: MethodDecorator = () => {};
        const { Public } = { Public: NotPublic };
      `), auth('')),
      workspace(controller(`
        import { JwtAuthGuard, Public as publicDecorator } from './auth';
        const Public = publicDecorator;
        const Other: MethodDecorator = () => {};
        const decorators = { Public, ['Public']: Other };
        const { Public: Bare } = decorators;
      `).replace('@Public', '@Bare'), auth(
        'export const Public: MethodDecorator = () => {};',
      )),
      workspace(controller(`
        import { JwtAuthGuard, Public as publicDecorator } from './auth';
        const { Public } = { get Public() { return publicDecorator; } };
      `), auth('export const Public: MethodDecorator = () => {};')),
      workspace(controller(`
        import { JwtAuthGuard, Public as publicDecorator } from './auth';
        const overrides: { Public?: MethodDecorator } = { Public: () => {} };
        const { Public } = { Public: publicDecorator, ...overrides };
      `), auth('export const Public: MethodDecorator = () => {};')),
      workspace(controller(`
        import { JwtAuthGuard, Public as publicDecorator } from './auth';
        const Other: MethodDecorator = () => {};
        const decorators = {
          Public: publicDecorator,
          mutate() { this.Public = Other; },
        };
        decorators.mutate();
        const { Public } = decorators;
      `), auth('export const Public: MethodDecorator = () => {};')),
      workspace(controller(`
        import { JwtAuthGuard, Public } from './auth';
        const Other: MethodDecorator = () => {};
        const decorators = { Public };
        for (decorators.Public of [Other]) break;
        const { Public: Bare } = decorators;
      `).replace('@Public', '@Bare'), auth(
        'export const Public: MethodDecorator = () => {};',
      )),
      workspace(controller(`
        import { JwtAuthGuard, Public } from './auth';
        const decorators = { Public };
        decorators.Public\`replace\`;
        const { Public: Bare } = decorators;
      `).replace('@Public', '@Bare'), auth(
        'export const Public: MethodDecorator = () => {};',
      )),
      workspace(`
        import { decorators, make } from './decorators';
        const Other: MethodDecorator = () => {};
        function mutate(value: { Public: MethodDecorator }) { value.Public = Other; }
        mutate(decorators);
        make();
      `, {
        ...auth('export const Public: MethodDecorator = () => {};'),
        'src/decorators.ts': `
          import { Controller, Get, UseGuards } from '@nestjs/common';
          import { JwtAuthGuard, Public } from './auth';
          export const decorators = { Public };
          export function make() {
            const { Public: Bare } = decorators;
            @Controller('cross-file') @UseGuards(JwtAuthGuard)
            class CrossFileController { @Get() @Bare read() {} }
            return CrossFileController;
          }
        `,
      }),
      workspace(controller(`
        import { JwtAuthGuard, Public as publicDecorator } from './auth';
        const Other: MethodDecorator = () => {};
        const decorators = {
          Public: publicDecorator,
          get trigger() { Object.assign(this, { Public: Other }); return true; },
        };
        void decorators.trigger;
        const { Public } = decorators;
      `), auth('export const Public: MethodDecorator = () => {};')),
    ];

    for (const root of rootsToCheck) {
      const execution = await runSourceAnalyzer(
        createNestJsSourceAnalyzer(authConfig), context(root),
      );
      expect(execution.status).toBe('success');
      if (execution.status !== 'success') continue;
      expect(execution.result.contract.operations[0]).toMatchObject({
        exposure: 'unknown',
        auth: {
          mode: 'unknown',
          analysis: { explicitPublic: false, enforcementConfidence: 'unknown' },
        },
      });
    }
    const mutableBinding = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(mutableBindingRoot),
    );
    expect(mutableBinding.status).toBe('success');
    if (mutableBinding.status === 'success') {
      expect(mutableBinding.result.contract.operations[0]).toMatchObject({
        exposure: 'authenticated',
        auth: { mode: 'alternatives', analysis: { explicitPublic: false } },
      });
    }
  });

  test('resolves a precomputed guard decorator used without a call', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { ApiKeyGuard, JwtAuthGuard } from './auth';
      const Authenticated = UseGuards(ApiKeyGuard);
      const AuthenticatedAlias = Authenticated;
      @Controller('precomputed') @UseGuards(JwtAuthGuard)
      class PrecomputedController { @Get() @AuthenticatedAlias read() {} }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\nexport class ApiKeyGuard {}\n',
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract.operations[0].auth.analysis?.guards).toEqual([
      { symbol: 'JwtAuthGuard', authKind: 'bearer' },
      { symbol: 'ApiKeyGuard', authKind: 'api-key' },
    ]);
  });

  test('accumulates inherited class guards and treats empty method UseGuards as a no-op', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { ApiKeyGuard, JwtAuthGuard, Public } from './auth';
      @UseGuards(JwtAuthGuard) class BaseController {}
      @Controller('inherited') @UseGuards(ApiKeyGuard)
      class InheritedController extends BaseController {
        @Get() @UseGuards() read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\nexport class ApiKeyGuard {}\n',
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract.operations[0]).toMatchObject({
      exposure: 'authenticated',
      auth: {
        mode: 'alternatives',
        analysis: {
          guards: [
            { symbol: 'JwtAuthGuard', authKind: 'bearer' },
            { symbol: 'ApiKeyGuard', authKind: 'api-key' },
          ],
          enforcementConfidence: 'high',
        },
      },
    });
  });

  test('extracts guards composed with applyDecorators', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards, applyDecorators } from '@nestjs/common';
      import { ApiKeyGuard, JwtAuthGuard } from './auth';
      const Auth = (): MethodDecorator => UseGuards(ApiKeyGuard);
      function FunctionAuth(): MethodDecorator { return UseGuards(ApiKeyGuard); }
      @Controller('composed') @UseGuards(JwtAuthGuard)
      class ComposedController {
        @Get() @applyDecorators(UseGuards(ApiKeyGuard)) read() {}
        @Get('wrapped') @Auth() wrapped() {}
        @Get('nested') @applyDecorators(Auth()) nested() {}
        @Get('function') @FunctionAuth() functionWrapped() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\nexport class ApiKeyGuard {}\n',
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    const operations = Object.fromEntries(execution.result.contract.operations.map((operation) => (
      [operation.routeKey, operation]
    )));
    expect(operations['GET /composed']).toMatchObject({
      exposure: 'authenticated',
      auth: {
        mode: 'alternatives',
        analysis: {
          guards: [
            { symbol: 'JwtAuthGuard', authKind: 'bearer' },
            { symbol: 'ApiKeyGuard', authKind: 'api-key' },
          ],
          enforcementConfidence: 'high',
        },
      },
    });
    for (const routeKey of [
      'GET /composed/wrapped', 'GET /composed/nested', 'GET /composed/function',
    ]) {
      expect(operations[routeKey]).toMatchObject({
        exposure: 'authenticated',
        auth: {
          mode: 'alternatives',
          analysis: {
            guards: [
              { symbol: 'JwtAuthGuard', authKind: 'bearer' },
              { symbol: 'ApiKeyGuard', authKind: 'api-key' },
            ],
            enforcementConfidence: 'high',
          },
        },
      });
    }
  });

  test('resolves decorators stored before a wrapper returns them', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { ApiKeyGuard, JwtAuthGuard, Public } from './auth';
      const storedGuard = UseGuards(ApiKeyGuard);
      const StoredGuard = (): MethodDecorator => storedGuard;
      const storedPublic = Public();
      const StoredPublic = (): MethodDecorator => storedPublic;
      @Controller('stored') @UseGuards(JwtAuthGuard)
      class StoredController {
        @Get('guard') @StoredGuard() guard() {}
        @Get('public') @StoredPublic() publicRoute() {}
      }
    `, {
      'src/auth.ts': `
        export class JwtAuthGuard {}
        export class ApiKeyGuard {}
        export const Public = (): MethodDecorator => () => {};
      `,
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    const operations = Object.fromEntries(execution.result.contract.operations.map((operation) => (
      [operation.routeKey, operation]
    )));
    expect(operations['GET /stored/guard']).toMatchObject({
      exposure: 'authenticated',
      auth: { analysis: { guards: [
        { symbol: 'JwtAuthGuard', authKind: 'bearer' },
        { symbol: 'ApiKeyGuard', authKind: 'api-key' },
      ] } },
    });
    expect(operations['GET /stored/public']).toMatchObject({
      exposure: 'public',
      auth: { mode: 'none', analysis: { explicitPublic: true } },
    });
  });

  test('fails closed on mutable, parameter-dependent, and cyclic guard wrappers', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { ApiKeyGuard, JwtAuthGuard, Public } from './auth';
      const Noop = (): MethodDecorator => () => {};
      declare const flag: boolean;
      let Mutable = (): MethodDecorator => UseGuards(ApiKeyGuard);
      Mutable = Noop;
      const Parameter = (guard: unknown): MethodDecorator => UseGuards(guard);
      const A = (): MethodDecorator => B();
      const B = (): MethodDecorator => A();
      const MultiStatement = (): MethodDecorator => {
        const decorator = UseGuards(ApiKeyGuard);
        return decorator;
      };
      const MultiPublic = (): MethodDecorator => {
        const decorator = Public();
        return decorator;
      };
      const Conditional = (): MethodDecorator => flag ? UseGuards(ApiKeyGuard) : Noop();
      const selectedFactory = flag ? (() => UseGuards(ApiKeyGuard)) : Noop;
      const UnknownCall = (): MethodDecorator => selectedFactory();
      const Identity = (decorator: MethodDecorator): MethodDecorator => decorator;
      @Controller('wrappers') @UseGuards(JwtAuthGuard)
      class WrapperController {
        @Get('mutable') @Mutable() mutable() {}
        @Get('parameter') @Parameter(ApiKeyGuard) parameter() {}
        @Get('cycle') @A() cycle() {}
        @Get('multi') @MultiStatement() multi() {}
        @Get('multi-public') @MultiPublic() multiPublic() {}
        @Get('conditional') @Conditional() conditional() {}
        @Get('unknown-call') @UnknownCall() unknownCall() {}
        @Get('identity') @Identity(UseGuards(ApiKeyGuard)) identity() {}
      }
    `, {
      'src/auth.ts': `
        export class JwtAuthGuard {}
        export class ApiKeyGuard {}
        export const Public = (): MethodDecorator => () => {};
      `,
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    for (const operation of execution.result.contract.operations) {
      expect(operation).toMatchObject({
        exposure: 'unknown',
        auth: { mode: 'unknown', analysis: { enforcementConfidence: 'unknown' } },
      });
    }
  });

  test('fails closed on object-property decorator wrappers', async () => {
    const aliases = ["const key3000 = 'Public' as const;"];
    for (let index = 2_999; index >= 0; index -= 1) {
      aliases.push(`const key${index} = key${index + 1};`);
    }
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { ApiKeyGuard, JwtAuthGuard, Public } from './auth';
      const Shorthand = (): MethodDecorator => Public();
      const wrappers = {
        Auth: (): MethodDecorator => UseGuards(ApiKeyGuard),
        MethodAuth(): MethodDecorator { return Public(); },
        Shorthand,
      };
      declare const flag: boolean;
      const named = {
        Public: (): MethodDecorator => Public(),
        Trace: (): MethodDecorator => () => {},
      };
      const staticKey = 'Public' as const;
      const dynamicKey = flag ? 'Public' : 'Trace';
      declare const dynamicNumber: number;
      const unaryNamed = {
        '': (): MethodDecorator => () => {},
        1: (): MethodDecorator => Public(),
      };
      ${aliases.join('\n')}
      @Controller('objects') @UseGuards(JwtAuthGuard)
      class ObjectWrapperController {
        @Get('property') @wrappers.Auth() property() {}
        @Get('method') @wrappers.MethodAuth() method() {}
        @Get('shorthand') @wrappers.Shorthand() shorthand() {}
        @Get('element') @(named['Public']()) element() {}
        @Get('static-element') @(named[staticKey]()) staticElement() {}
        @Get('dynamic-element') @(named[dynamicKey]()) dynamicElement() {}
        @Get('long-alias') @(named[key0]()) longAlias() {}
        @Get('dynamic-unary') @(unaryNamed[+dynamicNumber]()) dynamicUnary() {}
      }
    `, {
      'src/auth.ts': `
        export class JwtAuthGuard {}
        export class ApiKeyGuard {}
        export const Public = (): MethodDecorator => () => {};
      `,
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    for (const operation of execution.result.contract.operations) {
      expect(operation).toMatchObject({
        exposure: 'unknown',
        auth: { mode: 'unknown', analysis: { enforcementConfidence: 'unknown' } },
      });
    }
  });

  test('keeps namespace-import decorator properties static', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import * as auth from './auth';
      @Controller('namespace') @UseGuards(auth.JwtAuthGuard)
      class NamespaceController {
        @Get('public') @auth.Public() publicRoute() {}
        @Get('roles') @auth.Roles('admin') roles() {}
      }
    `, {
      'src/auth.ts': `
        declare const metadata: (...values: unknown[]) => MethodDecorator;
        export class JwtAuthGuard {}
        export const Public = (): MethodDecorator => metadata('public');
        export const Roles = (...roles: string[]): MethodDecorator => metadata('roles', roles);
      `,
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    const operations = Object.fromEntries(execution.result.contract.operations.map((operation) => (
      [operation.routeKey, operation]
    )));
    expect(operations['GET /namespace/public']).toMatchObject({
      exposure: 'public', auth: { mode: 'none' },
    });
    expect(operations['GET /namespace/roles']).toMatchObject({
      exposure: 'authenticated',
      auth: { mode: 'alternatives', analysis: { roles: ['admin'] } },
    });
  });

  test('fails closed on indirect Nest auth decorator imports', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { IndirectUseGuards } from './barrel';
      import { ApiKeyGuard, JwtAuthGuard } from './auth';
      @Controller('indirect') @UseGuards(JwtAuthGuard)
      class IndirectController { @Get() @IndirectUseGuards(ApiKeyGuard) read() {} }
      @Controller('indirect-class') @IndirectUseGuards(ApiKeyGuard)
      class IndirectClassController { @Get() @UseGuards(JwtAuthGuard) read() {} }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\nexport class ApiKeyGuard {}\n',
      'src/barrel.ts': "export { UseGuards as IndirectUseGuards } from '@nestjs/common';\n",
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    for (const operation of execution.result.contract.operations) {
      expect(operation).toMatchObject({
        exposure: 'unknown',
        auth: { mode: 'unknown', analysis: { enforcementConfidence: 'unknown' } },
      });
    }
  });

  test('does not analyze auth metadata for an untrusted composed controller', async () => {
    const root = workspace(`
      import { Controller, Get, applyDecorators } from '@nestjs/common';
      import { Roles } from './auth';
      declare const dynamicRole: string;
      @applyDecorators(Controller('untrusted')) @Roles(dynamicRole)
      class UntrustedController { @Get() read() {} }
    `, {
      'src/auth.ts': 'export const Roles = (..._roles: unknown[]): ClassDecorator => () => {};\n',
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract.operations).toEqual([]);
    expect(execution.result.diagnostics).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_DYNAMIC_AUTH_METADATA' }),
    ]));
  });

  test('reports APP_GUARD as a partial global capability without executing module code', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { GLOBAL_GUARD } from './global-guard';
      const GUARD_TOKEN = GLOBAL_GUARD;
      const keys = { provider: 'provide' } as const;
      export const providers = [{ [keys.provider]: GUARD_TOKEN, useClass: JwtAuthGuard }];
      @Controller('global') class GlobalController { @Get() @UseGuards(JwtAuthGuard) read() {} }
      throw new Error('must not execute');
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'src/global-guard.ts': "export { APP_GUARD as GLOBAL_GUARD } from '@nestjs/core';\n",
      'node_modules/@nestjs/core/index.d.ts': 'export declare const APP_GUARD: unique symbol;\n',
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract.capabilities.authentication).toBe('partial');
    expect(execution.result.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
    expect(execution.result.contract.operations[0]).toMatchObject({
      auth: {
        mode: 'unknown',
        analysis: {
          enforcementConfidence: 'unknown',
          capabilityReasons: expect.arrayContaining(['Global NestJS guards are not analyzed.']),
        },
      },
    });
  });

  test('ignores APP_GUARD-shaped objects outside provider registration', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      const unused = { provide: APP_GUARD, useClass: JwtAuthGuard };
      @Controller('local') class LocalController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': 'export declare const APP_GUARD: unique symbol;\n',
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.diagnostics).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
    expect(execution.result.contract.operations[0]).toMatchObject({
      auth: { mode: 'alternatives', analysis: { enforcementConfidence: 'high' } },
    });

    for (const [index, providers] of [
      `const authProviders = [{ provide: APP_GUARD, useClass: JwtAuthGuard }];
       @Module({ providers: authProviders }) class AppModule {}`,
      `const globalGuard = { provide: APP_GUARD, useClass: JwtAuthGuard };
       @Module({ providers: [globalGuard] }) class AppModule {}`,
      `declare const enabled: boolean;
       const providers = enabled ? [{ provide: APP_GUARD, useClass: JwtAuthGuard }] : [];
       @Module({ providers }) class AppModule {}`,
      `declare const configured: unknown[] | undefined;
       @Module({
         providers: configured ?? [{ provide: APP_GUARD, useClass: JwtAuthGuard }],
       }) class AppModule {}`,
      `function make() {
         const provider = { provide: APP_GUARD, useClass: JwtAuthGuard };
         return [provider];
       }
       @Module({ providers: make() }) class AppModule {}`,
      `const make = () => [{ provide: APP_GUARD, useClass: JwtAuthGuard }];
       @Module({ providers: make() }) class AppModule {}`,
      `const metadata = {
         providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }],
       };
       @Module(metadata) class AppModule {}`,
      `const metadata = {
         providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }],
       };
       @Module({ ...metadata }) class AppModule {}`,
      `const base = { provide: APP_GUARD };
       @Module({ providers: [{ ...base, useClass: JwtAuthGuard }] }) class AppModule {}`,
      `const NestModule = Module;
       @NestModule({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
       class AppModule {}`,
      `@Module({
         get providers() { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; },
       }) class AppModule {}`,
      `const providers: unknown[] = [];
       providers.push({ provide: APP_GUARD, useClass: JwtAuthGuard });
       @Module({ providers }) class AppModule {}`,
      `const providers: unknown[] = [];
       providers.push(...[{ provide: APP_GUARD, useClass: JwtAuthGuard }]);
       @Module({ providers }) class AppModule {}`,
      `const providers: unknown[] = [];
       providers['push']({ provide: APP_GUARD, useClass: JwtAuthGuard });
       @Module({ providers }) class AppModule {}`,
      `const providers: unknown[] = [];
       const alias = providers;
       alias.push({ provide: APP_GUARD, useClass: JwtAuthGuard });
       @Module({ providers }) class AppModule {}`,
      `const providers: unknown[] = [];
       const alias = providers as unknown[];
       alias.push({ provide: APP_GUARD, useClass: JwtAuthGuard });
       @Module({ providers }) class AppModule {}`,
      `declare const enabled: boolean;
       const TOKEN = enabled ? APP_GUARD : Symbol('other');
       const providers: unknown[] = [];
       providers.push({ provide: TOKEN, useClass: JwtAuthGuard });
       @Module({ providers }) class AppModule {}`,
      `@Module({ providers: [{
         get provide() { return APP_GUARD; },
         set provide(_value: unknown) {},
         useClass: JwtAuthGuard,
       }] }) class AppModule {}`,
      `@Module({
         get providers() {
           try { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
           finally {}
         },
       }) class AppModule {}`,
    ].entries()) {
      const aliasRoot = workspace(`
        import { Controller, Get, Module, UseGuards } from '@nestjs/common';
        import { APP_GUARD } from '@nestjs/core';
        import { JwtAuthGuard } from './auth';
        ${providers}
        @Controller('module-alias') class AliasController {
          @Get() @UseGuards(JwtAuthGuard) read() {}
        }
      `, {
        'src/auth.ts': 'export class JwtAuthGuard {}\n',
        'node_modules/@nestjs/core/index.d.ts': 'export declare const APP_GUARD: unique symbol;\n',
        'node_modules/@nestjs/core/package.json': JSON.stringify({
          name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
        }),
        'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
      });
      const aliasExecution = await runSourceAnalyzer(
        createNestJsSourceAnalyzer(authConfig), context(aliasRoot),
      );
      expect(aliasExecution.status).toBe('success');
      if (aliasExecution.status !== 'success') continue;
      expect(aliasExecution.result.diagnostics, `provider registration fixture ${index}`).toEqual(expect.arrayContaining([
        expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
      ]));
      expect(aliasExecution.result.contract.operations[0].auth.mode).toBe('unknown');
    }

    const readOnlyRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      const providers: unknown[] = [];
      const configured: unknown[] = [];
      providers.includes(APP_GUARD);
      providers.with(0, { provide: APP_GUARD, useClass: JwtAuthGuard });
      providers.toSpliced(0, 0, { provide: APP_GUARD, useClass: JwtAuthGuard });
      @Module({ providers }) class AppModule {}
      @Module({
        providers: configured || [{ provide: APP_GUARD, useClass: JwtAuthGuard }],
      }) class ConfiguredModule {}
      @Module({
        providers: undefined && [{ provide: APP_GUARD, useClass: JwtAuthGuard }],
      }) class UndefinedModule {}
      @Module({
        providers: (true && []) || [{ provide: APP_GUARD, useClass: JwtAuthGuard }],
      }) class NestedLogicalModule {}
      @Controller('read-only') class ReadOnlyController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': 'export declare const APP_GUARD: unique symbol;\n',
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
    });
    const readOnlyExecution = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(readOnlyRoot),
    );
    expect(readOnlyExecution.status).toBe('success');
    if (readOnlyExecution.status === 'success') {
      expect(readOnlyExecution.result.diagnostics).not.toEqual(expect.arrayContaining([
        expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
      ]));
      expect(readOnlyExecution.result.contract.operations[0].auth.mode).toBe('alternatives');
    }

    for (const [index, { setup, expected }] of [
      {
        setup: `declare const enabled: boolean;
          const guarded = { providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] };
          @Module({ ...(enabled ? guarded : {}) }) class AppModule {}`,
        expected: 'unknown',
      },
      {
        setup: `const guarded = { providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] };
          @Module({ ...guarded, providers: [] }) class AppModule {}`,
        expected: 'alternatives',
      },
      {
        setup: `const guarded = { provide: APP_GUARD };
          const OTHER_TOKEN = Symbol('other');
          @Module({ providers: [{ ...guarded, provide: OTHER_TOKEN, useClass: JwtAuthGuard }] })
          class AppModule {}`,
        expected: 'alternatives',
      },
      {
        setup: `const guarded = { provide: APP_GUARD };
          @Module({ providers: [{ ...guarded, set provide(_value: unknown) {}, useClass: JwtAuthGuard }] })
          class AppModule {}`,
        expected: 'alternatives',
      },
      {
        setup: `@Module({
          get providers() {
            if (false) return [{ provide: APP_GUARD, useClass: JwtAuthGuard }];
            return [];
          },
        }) class AppModule {}`,
        expected: 'alternatives',
      },
    ].entries()) {
      const overrideRoot = workspace(`
        import { Controller, Get, Module, UseGuards } from '@nestjs/common';
        import { APP_GUARD } from '@nestjs/core';
        import { JwtAuthGuard } from './auth';
        ${setup}
        @Controller('spread-${index}') class SpreadController {
          @Get() @UseGuards(JwtAuthGuard) read() {}
        }
      `, {
        'src/auth.ts': 'export class JwtAuthGuard {}\n',
        'node_modules/@nestjs/core/index.d.ts': 'export declare const APP_GUARD: unique symbol;\n',
        'node_modules/@nestjs/core/package.json': JSON.stringify({
          name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
        }),
        'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
      });
      const overrideExecution = await runSourceAnalyzer(
        createNestJsSourceAnalyzer(authConfig), context(overrideRoot),
      );
      expect(overrideExecution.status, JSON.stringify(overrideExecution)).toBe('success');
      if (overrideExecution.status === 'success') {
        expect(overrideExecution.result.contract.operations[0].auth.mode, `spread fixture ${index}`)
          .toBe(expected);
      }
    }

    const unreachableRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      function makeProviders() {
        if (true as const) return [];
        else return [{ provide: APP_GUARD, useClass: JwtAuthGuard }];
      }
      @Module({ providers: makeProviders() }) class AppModule {}
      @Controller('unreachable-provider') class UnreachableController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': 'export declare const APP_GUARD: unique symbol;\n',
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
    });
    const unreachableExecution = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(unreachableRoot),
    );
    expect(unreachableExecution.status).toBe('success');
    if (unreachableExecution.status === 'success') {
      expect(unreachableExecution.result.diagnostics).not.toEqual(expect.arrayContaining([
        expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
      ]));
      expect(unreachableExecution.result.contract.operations[0].auth.mode).toBe('alternatives');
    }
  });

  test('detects direct-import shorthand APP_GUARD without trusting mutable bindings', async () => {
    const nestCoreFiles = {
      'node_modules/@nestjs/core/index.d.ts': 'export declare const APP_GUARD: unique symbol;\n',
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
    };
    const directRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD as provide } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      export const providers = [{ provide, useClass: JwtAuthGuard }];
      @Controller('direct') class DirectController { @Get() @UseGuards(JwtAuthGuard) read() {} }
    `, nestCoreFiles);
    const mutableRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      let provide: unknown = APP_GUARD;
      provide = {};
      export const providers = [{ provide, useClass: JwtAuthGuard }];
      @Controller('mutable') class MutableController { @Get() @UseGuards(JwtAuthGuard) read() {} }
    `, nestCoreFiles);
    const destructuredShorthandRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      const [provide] = [APP_GUARD];
      export const providers = [{ provide, useClass: JwtAuthGuard }];
      @Controller('destructured') class DestructuredController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const computedRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const enabled: boolean;
      declare const OTHER_TOKEN: unique symbol;
      const TOKEN = enabled ? APP_GUARD : OTHER_TOKEN;
      export const providers = [{ provide: TOKEN, useClass: JwtAuthGuard }];
      @Controller('computed') class ComputedController { @Get() @UseGuards(JwtAuthGuard) read() {} }
    `, nestCoreFiles);
    const iifeRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      export const providers = [{ provide: (() => APP_GUARD)(), useClass: JwtAuthGuard }];
      @Controller('iife') class IifeController { @Get() @UseGuards(JwtAuthGuard) read() {} }
    `, nestCoreFiles);
    const parameterizedIifeRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      export const providers = [
        { provide: ((token) => token)(APP_GUARD), useClass: JwtAuthGuard },
      ];
      @Controller('parameterized-iife') class ParameterizedIifeController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const defaultIifeRoots = ['', 'undefined', 'void 0', 'maybe', 'supplied'].map((argument) => workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const maybe: unknown;
      const supplied = undefined as unknown as typeof APP_GUARD;
      export const providers = [
        { provide: ((token = APP_GUARD) => token)(${argument}), useClass: JwtAuthGuard },
      ];
      @Controller('default-iife') class DefaultIifeController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles));
    const bypassedDefaultRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const OTHER_TOKEN: unique symbol;
      export const providers = [
        { provide: ((token = APP_GUARD) => token)(OTHER_TOKEN), useClass: JwtAuthGuard },
      ];
      @Controller('bypassed-default') class BypassedDefaultController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const logicalRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const enabled: boolean;
      export const providers = [{ provide: enabled && APP_GUARD, useClass: JwtAuthGuard }];
      @Controller('logical') class LogicalController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const bypassedLogicalRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const enabled: boolean;
      declare const OTHER_TOKEN: unique symbol;
      const maybeGuard = enabled ? APP_GUARD : undefined;
      export const providers = [{ provide: maybeGuard && OTHER_TOKEN, useClass: JwtAuthGuard }];
      @Controller('bypassed-logical') class BypassedLogicalController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const typedBindingRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const OTHER_TOKEN: unique symbol;
      const TOKEN = ((x: undefined) => x ? APP_GUARD : OTHER_TOKEN)(APP_GUARD as any);
      export const providers = [{ provide: TOKEN, useClass: JwtAuthGuard }];
      @Controller('typed-binding') class TypedBindingController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const mutableTypedRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const OTHER_TOKEN: unique symbol;
      let enabled: undefined = APP_GUARD as any;
      export const providers = [{
        provide: enabled ? APP_GUARD : OTHER_TOKEN,
        useClass: JwtAuthGuard,
      }];
      @Controller('mutable-typed') class MutableTypedController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const nullishRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const override: unknown;
      export const providers = [{ provide: override ?? APP_GUARD, useClass: JwtAuthGuard }];
      @Controller('nullish') class NullishController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const bypassedNullishRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const OTHER_TOKEN: unique symbol;
      export const providers = [{ provide: OTHER_TOKEN ?? APP_GUARD, useClass: JwtAuthGuard }];
      @Controller('bypassed-nullish') class BypassedNullishController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const assertedNullishRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      const supplied = undefined as unknown as typeof APP_GUARD;
      export const providers = [{ provide: supplied ?? APP_GUARD, useClass: JwtAuthGuard }];
      @Controller('asserted-nullish') class AssertedNullishController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const functionTokenRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      export const providers = [{ provide: () => APP_GUARD, useClass: JwtAuthGuard }];
      @Controller('function-token') class FunctionTokenController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const destructuredIifeRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const OTHER_TOKEN: unique symbol;
      export const providers = [{
        provide: (({ token }) => token)({ token: OTHER_TOKEN }),
        useClass: JwtAuthGuard,
      }];
      @Controller('destructured-iife') class DestructuredIifeController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const destructuredGuardRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const enabled: boolean;
      declare const OTHER_TOKEN: unique symbol;
      const TOKEN = enabled ? APP_GUARD : OTHER_TOKEN;
      export const providers = [{
        provide: (({ token }) => token)({ token: TOKEN }),
        useClass: JwtAuthGuard,
      }];
      @Controller('destructured-guard') class DestructuredGuardController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const numericKeyRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      const n = 1n;
      const z = 0;
      const big = 1n;
      export const providers = [
        { [0]: APP_GUARD, useClass: JwtAuthGuard },
        { [-0]: APP_GUARD, useClass: JwtAuthGuard },
        { [0x10n]: APP_GUARD, useClass: JwtAuthGuard },
        { [-1n]: APP_GUARD, useClass: JwtAuthGuard },
        { [-n]: APP_GUARD, useClass: JwtAuthGuard },
        { [-(z as const)]: APP_GUARD, useClass: JwtAuthGuard },
        { [+big]: APP_GUARD, useClass: JwtAuthGuard },
        { [(-n as bigint)]: APP_GUARD, useClass: JwtAuthGuard },
        { [((+big))]: APP_GUARD, useClass: JwtAuthGuard },
        { [(-n satisfies bigint)]: APP_GUARD, useClass: JwtAuthGuard },
      ];
      @Controller('numeric-key') class NumericKeyController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const discardedTokenRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const OTHER_TOKEN: unique symbol;
      export const providers = [{ provide: (APP_GUARD, OTHER_TOKEN), useClass: JwtAuthGuard }];
      @Controller('discarded-token') class DiscardedTokenController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const unreachableTokenRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const OTHER_TOKEN: unique symbol;
      export const providers = [
        { provide: false ? APP_GUARD : OTHER_TOKEN, useClass: JwtAuthGuard },
        { provide: undefined ? APP_GUARD : OTHER_TOKEN, useClass: JwtAuthGuard },
        { provide: (void 0) ? APP_GUARD : OTHER_TOKEN, useClass: JwtAuthGuard },
      ];
      @Controller('unreachable-token') class UnreachableTokenController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const shadowedUndefinedRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const OTHER_TOKEN: unique symbol;
      export const providers = [{
        provide: (() => {
          const { undefined } = { undefined: APP_GUARD as any };
          return undefined ? APP_GUARD : OTHER_TOKEN;
        })(),
        useClass: JwtAuthGuard,
      }];
      @Controller('shadowed-undefined') class ShadowedUndefinedController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const unreachableReturnRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const OTHER_TOKEN: unique symbol;
      export const providers = [
        { provide: (() => { if (false) return APP_GUARD; return OTHER_TOKEN; })(), useClass: JwtAuthGuard },
        { provide: (() => { return OTHER_TOKEN; return APP_GUARD; })(), useClass: JwtAuthGuard },
      ];
      @Controller('unreachable-return') class UnreachableReturnController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const deepBlockRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      export const providers = [{
        provide: (() => { ${'{'.repeat(70)} return APP_GUARD; ${'}'.repeat(70)} })(),
        useClass: JwtAuthGuard,
      }];
      @Controller('deep-block') class DeepBlockController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    let nestedCandidate = 'p18';
    for (let index = 18; index > 0; index -= 1) {
      nestedCandidate = `((p${index} = p${index - 1}) => ${nestedCandidate})(p${index - 1})`;
    }
    const candidateExpansionRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const maybe: unknown;
      export const providers = [{
        provide: ((p0 = APP_GUARD) => ${nestedCandidate})(maybe),
        useClass: JwtAuthGuard,
      }];
      @Controller('candidate-expansion') class CandidateExpansionController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const unrelatedSpreadRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const OTHER_TOKEN: unique symbol;
      export const providers = [{
        provide: ((token: unknown) => token)(...([OTHER_TOKEN] as const)),
        useClass: JwtAuthGuard,
      }];
      @Controller('unrelated-spread') class UnrelatedSpreadController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const suppliedDefaultSpreadRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const OTHER_TOKEN: unique symbol;
      export const providers = [{
        provide: ((token: unknown = APP_GUARD) => token)(...([OTHER_TOKEN] as const)),
        useClass: JwtAuthGuard,
      }];
      @Controller('supplied-default-spread') class SuppliedDefaultSpreadController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const deferredIifeRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      export const providers = [
        { provide: (async () => APP_GUARD)(), useClass: JwtAuthGuard },
        { provide: (function* () { return APP_GUARD; })(), useClass: JwtAuthGuard },
      ];
      @Controller('deferred-iife') class DeferredIifeController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const assignmentRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      let token: unknown;
      export const providers = [{ provide: (token = APP_GUARD), useClass: JwtAuthGuard }];
      @Controller('assignment') class AssignmentController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const logicalAssignmentRoots = [
      ['let token: typeof APP_GUARD | false = false;', 'token ||= APP_GUARD'],
      ['let token: typeof APP_GUARD | true = true;', 'token &&= APP_GUARD'],
      ['let token: typeof APP_GUARD | undefined;', 'token ??= APP_GUARD'],
    ].map(([declaration, assignment]) => workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      ${declaration}
      export const providers = [{ provide: (${assignment}), useClass: JwtAuthGuard }];
      @Controller('logical-assignment') class LogicalAssignmentController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles));
    const memberAliasRoots = [
      ['', '({ token: OTHER_TOKEN }).token', 'alternatives'],
      ['', '({ token: OTHER_TOKEN, token: APP_GUARD }).token', 'unknown'],
      ['', '({ token: APP_GUARD, token: OTHER_TOKEN }).token', 'alternatives'],
      [
        'declare const extra: { token: unknown };',
        '({ token: OTHER_TOKEN, ...extra }).token',
        'unknown',
      ],
      [
        'const proto = { token: APP_GUARD }; const TOKENS = { __proto__: proto };',
        '(TOKENS as any).token',
        'unknown',
      ],
      [
        'const proto = { token: APP_GUARD } as { token: typeof APP_GUARD } & {}; const TOKENS = { __proto__: proto };',
        '(TOKENS as any).token',
        'unknown',
      ],
      ['declare const x: any; declare const dynamicKey: string; x[dynamicKey];', '({ token: OTHER_TOKEN }).token', 'alternatives'],
      ['', '([APP_GUARD] as const)[0]', 'unknown'],
      ['', '[APP_GUARD][0]', 'unknown'],
      ['const TOKENS = [APP_GUARD];', 'TOKENS[0]', 'unknown'],
      ['', '[...[], OTHER_TOKEN][0]', 'alternatives'],
      ['declare const runtimeIndex: number;', '[APP_GUARD, OTHER_TOKEN][runtimeIndex]', 'unknown'],
      ['declare const tokens: unknown[]; declare const runtimeIndex: number;', '[...tokens][runtimeIndex]', 'unknown'],
      ['declare const runtimeKey: string;', '({ a: APP_GUARD, b: OTHER_TOKEN })[runtimeKey]', 'unknown'],
      [
        'declare const runtimeKey: string;',
        '({ factory: () => APP_GUARD, other: OTHER_TOKEN })[runtimeKey]',
        'alternatives',
      ],
      [
        'declare const runtimeKey: string;',
        '({ get guard() { return APP_GUARD; }, other: OTHER_TOKEN })[runtimeKey]',
        'unknown',
      ],
      [
        'declare const runtimeKey: string; const TOKENS = { guard: APP_GUARD, other: OTHER_TOKEN };',
        'TOKENS[runtimeKey]',
        'unknown',
      ],
      [
        'declare const runtimeKey: string; const TOKENS = { guard: OTHER_TOKEN }; TOKENS.guard = APP_GUARD;',
        'TOKENS[runtimeKey]',
        'unknown',
      ],
      [
        "declare const runtimeKey: string; const key = 'guard' as const;",
        '({ guard: APP_GUARD, [key]: OTHER_TOKEN })[runtimeKey]',
        'alternatives',
      ],
      [
        'declare const runtimeKey: PropertyKey;',
        '({ 16: APP_GUARD, 0x10: OTHER_TOKEN })[runtimeKey]',
        'alternatives',
      ],
      [
        'declare const runtimeKey: PropertyKey;',
        '({ __proto__: APP_GUARD, other: OTHER_TOKEN })[runtimeKey]',
        'alternatives',
      ],
      [
        `declare const runtimeKey: string; const alias0 = { other: OTHER_TOKEN }; ${Array.from(
          { length: 70 }, (_, index) => `const alias${index + 1} = alias${index};`,
        ).join(' ')}`,
        'alias70[runtimeKey]',
        'unknown',
      ],
      ['', '({ get token() { return APP_GUARD; } }).token', 'unknown'],
      ['', '({} ? OTHER_TOKEN : APP_GUARD)', 'alternatives'],
      ['', '(-1 ? OTHER_TOKEN : APP_GUARD)', 'alternatives'],
      ['', '(() => { try { return APP_GUARD; } finally { return OTHER_TOKEN; } })()', 'alternatives'],
      [
        '',
        '(() => { switch (1) { case 0: return APP_GUARD; case 1: return OTHER_TOKEN; } })()',
        'alternatives',
      ],
      ['', '(() => { for (const token of [APP_GUARD]) return token; return OTHER_TOKEN; })()', 'unknown'],
      [
        '',
        '(() => { switch (1) { case 1: { break; } case 2: return APP_GUARD; } return OTHER_TOKEN; })()',
        'alternatives',
      ],
      [
        '',
        '(() => { for (const token of [OTHER_TOKEN]) { break; return APP_GUARD; } return OTHER_TOKEN; })()',
        'alternatives',
      ],
      ['', '(() => { for (const token of [OTHER_TOKEN]) { break; } return APP_GUARD; })()', 'unknown'],
      [
        'declare const enabled: boolean;',
        '(() => { switch (1) { case 1: if (enabled) break; else return OTHER_TOKEN; } return APP_GUARD; })()',
        'unknown',
      ],
      ['function pick() { return APP_GUARD; }', 'pick()', 'unknown'],
      ['const identity = (token: unknown) => token;', 'identity(APP_GUARD)', 'unknown'],
      ['let pick = () => OTHER_TOKEN; pick = () => APP_GUARD;', 'pick()', 'unknown'],
      ['function pick() { return OTHER_TOKEN; } pick = () => APP_GUARD;', 'pick()', 'unknown'],
      [
        'function pick(token: string): unknown; function pick(token: unknown) { return APP_GUARD; }',
        "pick('token')",
        'unknown',
      ],
      ['function pick() { return arguments[0]; }', 'pick(APP_GUARD)', 'unknown'],
      ['function pick() { return (() => arguments[0])(); }', 'pick(APP_GUARD)', 'unknown'],
      [
        'function pick() { return ({ arguments: OTHER_TOKEN }).arguments; }',
        'pick()',
        'alternatives',
      ],
      [
        'function pick() { const { arguments: value } = { arguments: OTHER_TOKEN }; return value; }',
        'pick()',
        'alternatives',
      ],
      ['', '(function (token: unknown) { return token; }).call(null, APP_GUARD)', 'unknown'],
      ['', '({ pick() { return APP_GUARD; } }).pick()', 'unknown'],
      ['', "(function () { return APP_GUARD; }).bind(null)", 'alternatives'],
      ['', "(async function () { return APP_GUARD; }).call(null)", 'alternatives'],
      ['', "(function* () { return APP_GUARD; }).apply(null)", 'alternatives'],
      [
        "const key = 'pick' as const;",
        '({ pick() { return OTHER_TOKEN; }, [key]() { return APP_GUARD; } }).pick()',
        'unknown',
      ],
      ['', '({ pick: () => APP_GUARD }).pick()', 'unknown'],
      [
        'declare const extra: { pick(): unknown };',
        '({ pick() { return OTHER_TOKEN; }, ...extra }).pick()',
        'unknown',
      ],
      ['', '({ get pick() { return () => APP_GUARD; } }).pick()', 'unknown'],
      ['', 'await APP_GUARD', 'unknown'],
      ['', 'await Promise.resolve(APP_GUARD)', 'unknown'],
      ['async function token() { return APP_GUARD; }', 'await token()', 'unknown'],
      [
        'async function token(value = APP_GUARD) { return value; }',
        'await token(undefined)',
        'unknown',
      ],
      [
        'let token = async () => OTHER_TOKEN; token = async () => APP_GUARD;',
        'await token()',
        'unknown',
      ],
      ['', 'await { then(resolve: (value: unknown) => void) { resolve(APP_GUARD); } }', 'unknown'],
      ['', 'await OTHER_TOKEN', 'alternatives'],
      ['', 'await 123', 'alternatives'],
      ['', '(function (token = APP_GUARD) { return token; }).call(null)', 'unknown'],
      ['', '({ pick(token = APP_GUARD) { return token; } }).pick()', 'unknown'],
      [
        '',
        '(function (token = APP_GUARD) { return token; }).call(null, OTHER_TOKEN)',
        'alternatives',
      ],
      ['', '({ pick(token = APP_GUARD) { return token; } }).pick(OTHER_TOKEN)', 'alternatives'],
      ['', '(function (token = APP_GUARD) { return token; }).apply(null, [OTHER_TOKEN])', 'alternatives'],
      ['', '(function (token = APP_GUARD) { return token; }).apply(null, [])', 'unknown'],
      [
        'declare const args: unknown[];',
        '(function (token: unknown) { return token; }).apply(null, args)',
        'unknown',
      ],
      [
        'declare const args: unknown[];',
        '(function (token: unknown) { return token; }).apply(null, [...args])',
        'unknown',
      ],
      ['', '({ token: APP_GUARD, pick() { return this.token; } }).pick()', 'unknown'],
      ['', '({ token: APP_GUARD, pick(value = this.token) { return value; } }).pick()', 'unknown'],
      [
        'const factories = { token: () => APP_GUARD };',
        'factories.token()',
        'unknown',
      ],
      [
        'class Factory { make() { return APP_GUARD; } } const factory = new Factory();',
        'factory.make()',
        'unknown',
      ],
      [
        'let api = { pick() { return OTHER_TOKEN; } }; api = { pick() { return APP_GUARD; } };',
        'api.pick()',
        'unknown',
      ],
      ['function token(_strings: TemplateStringsArray) { return APP_GUARD; }', 'token`x`', 'unknown'],
      ['function token(_strings: TemplateStringsArray) { return OTHER_TOKEN; }', 'token`x`', 'alternatives'],
      [
        'function token(_strings: TemplateStringsArray) { if (false) return APP_GUARD; return OTHER_TOKEN; }',
        'token`x`',
        'alternatives',
      ],
      [
        'function token(_strings: TemplateStringsArray) { while (false) return APP_GUARD; return OTHER_TOKEN; }',
        'token`x`',
        'alternatives',
      ],
      [
        'function token(_strings: TemplateStringsArray) { try { return APP_GUARD; } finally { return OTHER_TOKEN; } }',
        'token`x`',
        'alternatives',
      ],
      [
        'function token(_strings: TemplateStringsArray, value: unknown) { value = APP_GUARD; return value; }',
        'token`${OTHER_TOKEN}`',
        'unknown',
      ],
      [
        'function token(_strings: TemplateStringsArray, value: unknown) { function mutate() { value = APP_GUARD; } mutate(); return value; }',
        'token`${OTHER_TOKEN}`',
        'unknown',
      ],
      ['function token(_strings: TemplateStringsArray, value = APP_GUARD) { return value; }', 'token`x`', 'unknown'],
      ['const tags = { token() { return APP_GUARD; } };', 'tags.token`x`', 'unknown'],
      ['async function token() { return APP_GUARD; }', 'token`x`', 'alternatives'],
      ['function* token() { return APP_GUARD; }', 'token`x`', 'alternatives'],
      ['function token() { return APP_GUARD; }', '(0, token)()', 'unknown'],
      [
        'declare const enabled: boolean; const identity = (value: unknown) => value; const other = () => OTHER_TOKEN;',
        '(enabled ? identity : other)(APP_GUARD)',
        'unknown',
      ],
      [
        'declare const enabled: boolean; const app = () => APP_GUARD; const other = () => OTHER_TOKEN;',
        '(enabled ? app : other)()',
        'unknown',
      ],
      [
        'declare const enabled: boolean; function app(value = APP_GUARD) { return value; } function other() { return OTHER_TOKEN; }',
        '(enabled ? app : other)()',
        'unknown',
      ],
      [
        'declare const enabled: boolean; async function app() { return APP_GUARD; } function other() { return OTHER_TOKEN; }',
        '(enabled ? app : other)()',
        'alternatives',
      ],
      [
        'declare const enabled: boolean; const identity = (value: unknown) => value; const other = () => OTHER_TOKEN;',
        '(enabled ? identity : other)(...[APP_GUARD])',
        'unknown',
      ],
      [
        'declare const enabled: boolean; const app = async (value: unknown) => value; const other = async () => OTHER_TOKEN;',
        '(enabled ? app : other)(APP_GUARD)',
        'alternatives',
      ],
      [
        'declare const enabled: boolean; const api = { app() { return APP_GUARD; } }; const other = () => OTHER_TOKEN;',
        '(enabled ? api.app : other)()',
        'unknown',
      ],
      [
        'declare const enabled: boolean; const api = { group: { app() { return APP_GUARD; } } }; const other = () => OTHER_TOKEN;',
        '(enabled ? api.group.app : other)()',
        'unknown',
      ],
      ['const api = { group: { app() { return APP_GUARD; } } };', 'api.group.app()', 'unknown'],
      ['', '({ pick() { const unused = APP_GUARD; return OTHER_TOKEN; } }).pick()', 'alternatives'],
      ['', '({ pick() { return OTHER_TOKEN; return APP_GUARD; } }).pick()', 'alternatives'],
      ['', '({ pick() { try { return APP_GUARD; } finally { return OTHER_TOKEN; } } }).pick()', 'alternatives'],
      ['', '(function () { return APP_GUARD; }).bind(null)()', 'unknown'],
      ['', '[APP_GUARD].at(0)', 'unknown'],
      ['', '[OTHER_TOKEN, APP_GUARD].pop()', 'unknown'],
      [
        'function pick(token: unknown) { token = APP_GUARD; return token; }',
        'pick(OTHER_TOKEN)',
        'unknown',
      ],
      ['', '(() => { while (false) return APP_GUARD; return OTHER_TOKEN; })()', 'alternatives'],
      ['', '(() => { for (; false;) return APP_GUARD; return OTHER_TOKEN; })()', 'alternatives'],
      [
        'declare function explode(): void;',
        '(() => { try { for (explode(); false;) {} return OTHER_TOKEN; } catch { return APP_GUARD; } })()',
        'unknown',
      ],
      [
        '',
        '(() => { try { for (const { x } = null as any; false;) {} return OTHER_TOKEN; } catch { return APP_GUARD; } })()',
        'unknown',
      ],
      ['', '(({ x }) => APP_GUARD)({ x: OTHER_TOKEN })', 'unknown'],
      ['', '(() => { let token = APP_GUARD; return token; })()', 'unknown'],
      ['', '(() => { try { throw APP_GUARD; } catch (token) { return token; } })()', 'unknown'],
      ['', "(() => { try { return APP_GUARD; } finally { throw new Error('stop'); } })()", 'alternatives'],
      ['', "(() => { try { return 'OTHER_TOKEN'; } catch { return APP_GUARD; } })()", 'alternatives'],
      ['', '(() => { try { if ((undefined as any).x) return OTHER_TOKEN; return OTHER_TOKEN; } catch { return APP_GUARD; } })()', 'unknown'],
      ['', "(() => { class Exploding {} try { if (new Exploding()) return 'OTHER_TOKEN'; } catch { return APP_GUARD; } })()", 'unknown'],
      ['', '(() => { try { return token; } catch { return APP_GUARD; } const token = OTHER_TOKEN; })()', 'unknown'],
      ["const TOKENS = { global: APP_GUARD };", 'TOKENS.global', 'unknown'],
      ['const [TOKEN] = [APP_GUARD];', 'TOKEN', 'unknown'],
      ["const TOKENS = { global: APP_GUARD, other: OTHER_TOKEN };", 'TOKENS.other', 'alternatives'],
      ["const TOKENS: { global: symbol } = { global: OTHER_TOKEN };", 'TOKENS.global', 'alternatives'],
      ["const TOKENS: { global: unknown } = { global: APP_GUARD };", 'TOKENS.global', 'unknown'],
      ["const TOKENS: any = { global: APP_GUARD };", 'TOKENS.global', 'unknown'],
      ['', '({ global: APP_GUARD } as any).global', 'unknown'],
      ['class Tokens { static global = APP_GUARD; }', 'Tokens.global', 'unknown'],
      [
        "const extra = { global: APP_GUARD }; const TOKENS: { global: unknown } = { global: OTHER_TOKEN, ...extra };",
        'TOKENS.global',
        'unknown',
      ],
      [
        "const key = 'global' as const; const TOKENS: { global: unknown } = { global: OTHER_TOKEN, [key]: APP_GUARD };",
        'TOKENS.global',
        'unknown',
      ],
      ["const TOKENS = { global: OTHER_TOKEN }; const same = TOKENS === TOKENS; if (TOKENS) {} typeof TOKENS;", 'TOKENS.global', 'alternatives'],
      ["const TOKENS = { global: OTHER_TOKEN, other: OTHER_TOKEN }; TOKENS.other = APP_GUARD;", 'TOKENS.global', 'alternatives'],
      ["const TOKENS = { global: OTHER_TOKEN }; TOKENS.global = APP_GUARD;", 'TOKENS.global', 'unknown'],
      [
        'const TOKENS: { global?: unknown } = { global: APP_GUARD }; delete TOKENS.global;',
        'TOKENS.global',
        'alternatives',
      ],
      ["const TOKENS = { global: OTHER_TOKEN }; for (TOKENS.global of [APP_GUARD]) {}", 'TOKENS.global', 'unknown'],
      ["const TOKENS = { nested: { global: OTHER_TOKEN } }; TOKENS['nested'].global = APP_GUARD;", "TOKENS['nested'].global", 'unknown'],
      ["function tokens(): { global: unknown } { return { global: OTHER_TOKEN }; }", 'tokens().global', 'unknown'],
      ['const [, TOKEN] = [...[OTHER_TOKEN, APP_GUARD], OTHER_TOKEN];', 'TOKEN', 'unknown'],
      ['const global = APP_GUARD; const TOKENS = { global };', 'TOKENS.global', 'unknown'],
      ["const TOKENS = { global: OTHER_TOKEN }; [TOKENS.global] = [APP_GUARD];", 'TOKENS.global', 'unknown'],
      ['const [TOKEN = APP_GUARD] = [undefined];', 'TOKEN', 'unknown'],
      ["let TOKEN: string = 'ordinary';", 'TOKEN', 'alternatives'],
      [
        'let TOKEN: unknown = OTHER_TOKEN; if (false) TOKEN = APP_GUARD;',
        'TOKEN',
        'alternatives',
      ],
      [
        'let TOKEN: unknown = OTHER_TOKEN; TOKEN = OTHER_TOKEN; TOKEN = APP_GUARD;',
        'TOKEN',
        'unknown',
      ],
      ['let TOKEN: any = OTHER_TOKEN; TOKEN &&= APP_GUARD;', 'TOKEN', 'unknown'],
      ['let TOKEN: unknown; [TOKEN] = [APP_GUARD];', 'TOKEN', 'unknown'],
      ['let TOKEN: unknown; for (TOKEN of [APP_GUARD]) {}', 'TOKEN', 'unknown'],
      [
        'let TOKEN: unknown = APP_GUARD; const observed = make(); TOKEN = OTHER_TOKEN; function make() { return TOKEN; }',
        'make()',
        'unknown',
      ],
      [
        'let TOKEN: unknown = OTHER_TOKEN; const value = TOKEN; TOKEN = APP_GUARD;',
        'value',
        'alternatives',
      ],
      [
        'let TOKEN: unknown = OTHER_TOKEN; const object: any = {}; object[TOKEN as any] = 1;',
        'TOKEN',
        'alternatives',
      ],
      ['const global = APP_GUARD; const { global: TOKEN } = { global };', 'TOKEN', 'unknown'],
      [
        'const { nested: { global: TOKEN } } = { nested: { global: APP_GUARD } };',
        'TOKEN',
        'unknown',
      ],
      [
        'const TOKENS = { global: OTHER_TOKEN }; const mutate = (...xs: any[]) => { xs[0].global = APP_GUARD; }; mutate(...[TOKENS]);',
        'TOKENS.global',
        'unknown',
      ],
      [
        'const TOKENS = { global: OTHER_TOKEN }; let alias: any; alias = TOKENS; alias.global = APP_GUARD;',
        'TOKENS.global',
        'unknown',
      ],
      [
        'const TOKENS = { global: OTHER_TOKEN }; function expose(): any { return TOKENS; } const alias = expose(); alias.global = APP_GUARD;',
        'TOKENS.global',
        'unknown',
      ],
      [
        'const TOKENS = { global: OTHER_TOKEN }; const WRAP = { TOKENS };',
        'WRAP.TOKENS.global',
        'alternatives',
      ],
      [
        'const TOKENS: { global: symbol } = { global: APP_GUARD }; TOKENS.global = OTHER_TOKEN;',
        'TOKENS.global',
        'alternatives',
      ],
      [
        'const TOKENS = { global: OTHER_TOKEN }; if (false) TOKENS.global = APP_GUARD;',
        'TOKENS.global',
        'alternatives',
      ],
      [
        'const TOKENS = { global: OTHER_TOKEN }; const WRAP = { TOKENS }; WRAP.TOKENS.global = APP_GUARD;',
        'TOKENS.global',
        'unknown',
      ],
      [
        'const TOKENS = { global: OTHER_TOKEN }; const WRAP = { TOKENS }; const alias = WRAP.TOKENS; alias.global = APP_GUARD;',
        'TOKENS.global',
        'unknown',
      ],
      [
        'const TOKENS = { global: OTHER_TOKEN }; const WRAP = { TOKENS }; const first = WRAP.TOKENS; const second = first; second.global = APP_GUARD;',
        'TOKENS.global',
        'unknown',
      ],
      [
        'const TOKENS = { global: OTHER_TOKEN }; const WRAP = { TOKENS }; const { TOKENS: alias } = WRAP; alias.global = APP_GUARD;',
        'TOKENS.global',
        'unknown',
      ],
      [
        "declare const key: string; const TOKENS = { first: OTHER_TOKEN, second: OTHER_TOKEN };",
        'TOKENS[key]',
        'alternatives',
      ],
      [
        "declare const key: string; const TOKENS = { value: APP_GUARD, value: OTHER_TOKEN };",
        'TOKENS[key]',
        'alternatives',
      ],
      [
        "declare const key: string; const TOKENS = { ordinary() { return OTHER_TOKEN; }, set value(_token: unknown) {}, other: OTHER_TOKEN };",
        'TOKENS[key]',
        'alternatives',
      ],
      [
        'const TOKENS = { global: OTHER_TOKEN }; const WRAP = { TOKENS }; function mutate(value: any) { value.TOKENS.global = APP_GUARD; } mutate(WRAP);',
        'TOKENS.global',
        'unknown',
      ],
      [
        'const TOKENS = { global: OTHER_TOKEN }; const WRAP = { tokens: TOKENS }; WRAP.tokens.global = APP_GUARD;',
        'TOKENS.global',
        'unknown',
      ],
      [
        'const TOKENS = { global: OTHER_TOKEN }; const WRAP = { tokens: TOKENS }; const { tokens: alias } = WRAP; alias.global = APP_GUARD;',
        'TOKENS.global',
        'unknown',
      ],
      [
        'const TOKENS = { global: OTHER_TOKEN }; const WRAP: any = { tokens: TOKENS }; const alias = WRAP.tokens; alias.global = APP_GUARD;',
        'TOKENS.global',
        'unknown',
      ],
      [
        "const TOKENS = { global: OTHER_TOKEN }; const WRAP = { tokens: TOKENS, tokens: { global: OTHER_TOKEN } }; const { tokens: alias } = WRAP; alias.global = APP_GUARD;",
        'TOKENS.global',
        'alternatives',
      ],
      [
        'const TOKENS = { global: OTHER_TOKEN }; const WRAP = { TOKENS, unrelated: { global: OTHER_TOKEN } }; const { unrelated: alias } = WRAP; alias.global = APP_GUARD;',
        'TOKENS.global',
        'alternatives',
      ],
      [
        'const { token: TOKEN } = { token: APP_GUARD, token: OTHER_TOKEN };',
        'TOKEN',
        'alternatives',
      ],
      [
        'declare const external: object; declare function consume(value: unknown): void; const TOKENS = { global: OTHER_TOKEN }; const unrelated = { ...external }; consume(unrelated);',
        'TOKENS.global',
        'alternatives',
      ],
      ["const TOKENS = [OTHER_TOKEN] as const;", 'TOKENS[0]', 'alternatives'],
      [
        'const TOKENS = [OTHER_TOKEN]; TOKENS.splice(0, 1, APP_GUARD);',
        'TOKENS[0]',
        'unknown',
      ],
      [
        'const TOKENS = [OTHER_TOKEN]; [TOKENS[0]] = [APP_GUARD];',
        'TOKENS[0]',
        'unknown',
      ],
      [
        'const TOKENS = [OTHER_TOKEN]; for (TOKENS[0] of [APP_GUARD]) { break; }',
        'TOKENS[0]',
        'unknown',
      ],
      [
        'const TOKENS: any[] = [function(this: any[]) { this[0] = APP_GUARD; }]; TOKENS[0]();',
        'TOKENS[0]',
        'unknown',
      ],
      [
        'const TOKENS: any[] = [function() { return OTHER_TOKEN; }]; const identity = (value: any) => value; identity(TOKENS[0])();',
        'TOKENS[0]',
        'alternatives',
      ],
      ["const TOKENS = [...[OTHER_TOKEN], OTHER_TOKEN] as const;", 'TOKENS[0]', 'alternatives'],
      [
        'const factory = { make: () => OTHER_TOKEN, unused: APP_GUARD };',
        'factory.make()',
        'alternatives',
      ],
      [
        'const factory = { make: () => OTHER_TOKEN }; factory.make = () => APP_GUARD;',
        'factory.make()',
        'unknown',
      ],
      [
        'const factory = { make: () => OTHER_TOKEN }; [factory.make] = [() => APP_GUARD];',
        'factory.make()',
        'unknown',
      ],
      [
        'const factory = { make: () => OTHER_TOKEN, mutate() { this.make = () => APP_GUARD; } }; factory.mutate();',
        'factory.make()',
        'unknown',
      ],
      [
        'const proto = { global: APP_GUARD }; const TOKENS = Object.create(proto);',
        'TOKENS.global',
        'unknown',
      ],
      ['', '(() => APP_GUARD).name', 'alternatives'],
      ['', '(() => APP_GUARD).bind(null)', 'alternatives'],
      ['', 'APP_GUARD.valueOf()', 'unknown'],
      ['', '(APP_GUARD as any).toString()', 'alternatives'],
      ['', '(APP_GUARD as any).includes("never")', 'alternatives'],
      [
        'function token() { return OTHER_TOKEN; } const alias = token;',
        'token()',
        'alternatives',
      ],
      ['const TOKENS = { nested: { ordinary: OTHER_TOKEN } };', 'TOKENS.nested.ordinary', 'alternatives'],
      [
        'const TOKENS = { global: OTHER_TOKEN, get self(): any { return this; } }; const alias: any = TOKENS.self; alias.global = APP_GUARD;',
        'TOKENS.global',
        'unknown',
      ],
      [
        'const mutate = function(this: any) { this.global = APP_GUARD; }; const TOKENS = { global: OTHER_TOKEN, mutate }; (TOKENS.mutate as any)();',
        'TOKENS.global',
        'unknown',
      ],
    ].map(([declaration, expression, expected]) => ({
      expected,
      root: workspace(`
        import { Controller, Get, UseGuards } from '@nestjs/common';
        import { APP_GUARD } from '@nestjs/core';
        import { JwtAuthGuard } from './auth';
        declare const OTHER_TOKEN: unique symbol;
        ${declaration}
        export const providers = [{ provide: ${expression}, useClass: JwtAuthGuard }];
        @Controller('member-alias') class MemberAliasController {
          @Get() @UseGuards(JwtAuthGuard) read() {}
        }
      `, nestCoreFiles),
    }));
    const delayedDeleteRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      const TOKENS: { global?: unknown } = { global: APP_GUARD };
      export const providers = make();
      delete TOKENS.global;
      function make() { return [{ provide: TOKENS.global, useClass: JwtAuthGuard }]; }
      @Controller('delayed-delete') class DelayedDeleteController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, nestCoreFiles);
    const crossFileMutationRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { TOKENS } from './tokens';
      import './mutate';
      export const providers = [{ provide: TOKENS.global, useClass: JwtAuthGuard }];
      @Controller('cross-file-mutation') class CrossFileMutationController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      ...nestCoreFiles,
      'src/tokens.ts': `
        import { APP_GUARD } from '@nestjs/core';
        declare const OTHER_TOKEN: unique symbol;
        export const TOKENS = { global: OTHER_TOKEN };
      `,
      'src/mutate.ts': `
        import { APP_GUARD } from '@nestjs/core';
        import { TOKENS } from './tokens';
        TOKENS.global = APP_GUARD;
      `,
    });

    const direct = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(directRoot));
    const mutable = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(mutableRoot));
    const destructuredShorthand = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(destructuredShorthandRoot),
    );
    const computed = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(computedRoot));
    const iife = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(iifeRoot));
    const parameterizedIife = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(parameterizedIifeRoot),
    );
    const defaultIifes = await Promise.all(defaultIifeRoots.map((root) => (
      runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root))
    )));
    const bypassedDefault = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(bypassedDefaultRoot),
    );
    const logical = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(logicalRoot),
    );
    const bypassedLogical = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(bypassedLogicalRoot),
    );
    const typedBinding = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(typedBindingRoot),
    );
    const mutableTyped = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(mutableTypedRoot),
    );
    const nullish = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(nullishRoot),
    );
    const bypassedNullish = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(bypassedNullishRoot),
    );
    const assertedNullish = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(assertedNullishRoot),
    );
    const functionToken = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(functionTokenRoot),
    );
    const destructuredIife = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(destructuredIifeRoot),
    );
    const destructuredGuard = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(destructuredGuardRoot),
    );
    const numericKey = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(numericKeyRoot),
    );
    const discardedToken = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(discardedTokenRoot),
    );
    const unreachableToken = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(unreachableTokenRoot),
    );
    const shadowedUndefined = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(shadowedUndefinedRoot),
    );
    const unreachableReturn = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(unreachableReturnRoot),
    );
    const deepBlock = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(deepBlockRoot),
    );
    const expansionContext = context(candidateExpansionRoot);
    const candidateExpansion = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), {
        ...expansionContext,
        limits: { ...expansionContext.limits, timeoutMs: 500 },
      },
    );
    const unrelatedSpread = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(unrelatedSpreadRoot),
    );
    const suppliedDefaultSpread = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(suppliedDefaultSpreadRoot),
    );
    const deferredIife = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(deferredIifeRoot),
    );
    const assignment = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(assignmentRoot),
    );
    const logicalAssignments = await Promise.all(logicalAssignmentRoots.map((root) => (
      runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root))
    )));
    const memberAliases = await Promise.all(memberAliasRoots.map(async ({ root, expected }) => ({
      expected,
      result: await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root)),
    })));
    const delayedDelete = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(delayedDeleteRoot),
    );
    const crossFileMutation = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(crossFileMutationRoot),
    );
    expect(direct.status).toBe('success');
    expect(mutable.status).toBe('success');
    expect(destructuredShorthand.status).toBe('success');
    expect(computed.status).toBe('success');
    expect(iife.status).toBe('success');
    expect(parameterizedIife.status).toBe('success');
    expect(defaultIifes.every((result) => result.status === 'success')).toBe(true);
    expect(bypassedDefault.status).toBe('success');
    expect(logical.status).toBe('success');
    expect(bypassedLogical.status).toBe('success');
    expect(typedBinding.status).toBe('success');
    expect(mutableTyped.status).toBe('success');
    expect(nullish.status).toBe('success');
    expect(bypassedNullish.status).toBe('success');
    expect(assertedNullish.status).toBe('success');
    expect(functionToken.status).toBe('success');
    expect(destructuredIife.status).toBe('success');
    expect(destructuredGuard.status).toBe('success');
    expect(numericKey.status).toBe('success');
    expect(discardedToken.status).toBe('success');
    expect(unreachableToken.status).toBe('success');
    expect(shadowedUndefined.status).toBe('success');
    expect(unreachableReturn.status).toBe('success');
    expect(deepBlock.status).toBe('success');
    expect(candidateExpansion.status).toBe('success');
    expect(unrelatedSpread.status).toBe('success');
    expect(suppliedDefaultSpread.status).toBe('success');
    expect(deferredIife.status).toBe('success');
    expect(assignment.status).toBe('success');
    expect(logicalAssignments.every((result) => result.status === 'success')).toBe(true);
    for (const [index, { result }] of memberAliases.entries()) {
      expect(result.status, `member alias fixture ${index}: ${JSON.stringify(result)}`).toBe('success');
    }
    expect(delayedDelete.status).toBe('success');
    expect(crossFileMutation.status).toBe('success');
    if (direct.status !== 'success' || mutable.status !== 'success'
      || destructuredShorthand.status !== 'success' || computed.status !== 'success'
      || iife.status !== 'success' || parameterizedIife.status !== 'success'
      || defaultIifes.some((result) => result.status !== 'success')
      || bypassedDefault.status !== 'success' || logical.status !== 'success'
      || bypassedLogical.status !== 'success' || nullish.status !== 'success'
      || typedBinding.status !== 'success'
      || mutableTyped.status !== 'success'
      || bypassedNullish.status !== 'success'
      || assertedNullish.status !== 'success' || functionToken.status !== 'success'
      || destructuredIife.status !== 'success' || destructuredGuard.status !== 'success'
      || numericKey.status !== 'success' || discardedToken.status !== 'success'
      || unreachableToken.status !== 'success' || shadowedUndefined.status !== 'success') return;
    if (unreachableReturn.status !== 'success') return;
    if (deepBlock.status !== 'success') return;
    if (candidateExpansion.status !== 'success') return;
    if (unrelatedSpread.status !== 'success') return;
    if (suppliedDefaultSpread.status !== 'success') return;
    if (deferredIife.status !== 'success') return;
    if (assignment.status !== 'success') return;
    if (logicalAssignments.some((result) => result.status !== 'success')) return;
    if (memberAliases.some(({ result }) => result.status !== 'success')) return;
    if (delayedDelete.status !== 'success') return;
    if (crossFileMutation.status !== 'success') return;
    expect(direct.result.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
    expect(direct.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(mutable.result.diagnostics).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
    expect(mutable.result.contract.operations[0].auth.mode).toBe('alternatives');
    expect(destructuredShorthand.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(computed.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(computed.result.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
    expect(iife.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(parameterizedIife.result.contract.operations[0].auth.mode).toBe('unknown');
    for (const result of defaultIifes) {
      if (result.status === 'success') expect(result.result.contract.operations[0].auth.mode).toBe('unknown');
    }
    expect(bypassedDefault.result.contract.operations[0].auth.mode).toBe('alternatives');
    expect(bypassedDefault.result.diagnostics).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
    expect(logical.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(bypassedLogical.result.contract.operations[0].auth.mode).toBe('alternatives');
    expect(bypassedLogical.result.diagnostics).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
    expect(typedBinding.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(mutableTyped.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(nullish.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(assertedNullish.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(bypassedNullish.result.contract.operations[0].auth.mode).toBe('alternatives');
    expect(bypassedNullish.result.diagnostics).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
    expect(functionToken.result.contract.operations[0].auth.mode).toBe('alternatives');
    expect(destructuredIife.result.contract.operations[0].auth.mode).toBe('alternatives');
    expect(destructuredGuard.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(numericKey.result.contract.operations[0].auth.mode).toBe('alternatives');
    expect(numericKey.result.diagnostics).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
    expect(discardedToken.result.contract.operations[0].auth.mode).toBe('alternatives');
    expect(discardedToken.result.diagnostics).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
    expect(unreachableToken.result.contract.operations[0].auth.mode).toBe('alternatives');
    expect(unreachableToken.result.diagnostics).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
    expect(shadowedUndefined.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(unreachableReturn.result.contract.operations[0].auth.mode).toBe('alternatives');
    expect(unreachableReturn.result.diagnostics).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
    expect(deepBlock.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(candidateExpansion.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(unrelatedSpread.result.contract.operations[0].auth.mode).toBe('alternatives');
    expect(suppliedDefaultSpread.result.contract.operations[0].auth.mode).toBe('alternatives');
    expect(deferredIife.result.contract.operations[0].auth.mode).toBe('alternatives');
    expect(assignment.result.contract.operations[0].auth.mode).toBe('unknown');
    for (const result of logicalAssignments) {
      if (result.status === 'success') expect(result.result.contract.operations[0].auth.mode).toBe('unknown');
    }
    for (const [index, { expected, result }] of memberAliases.entries()) {
      if (result.status === 'success') {
        expect(result.result.contract.operations[0].auth.mode, `member alias fixture ${index}`).toBe(expected);
      }
    }
    expect(delayedDelete.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(crossFileMutation.result.contract.operations[0].auth.mode).toBe('unknown');
  });

  test('fails closed on bootstrap global guards and external controller inheritance', async () => {
    const globalRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare class AppModule {}
      const app = NestFactory.create(AppModule);
      app['useGlobalGuards'](new JwtAuthGuard());
      @Controller('bootstrap') class BootstrapController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export interface INestApplication { useGlobalGuards(...guards: unknown[]): this; }
        export declare const NestFactory: { create(module: unknown): INestApplication };
      `,
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
    });
    const unrelatedRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      declare const helper: { useGlobalGuards(...guards: unknown[]): void };
      helper.useGlobalGuards('not a Nest application');
      @Controller('helper') class HelperController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });
    const optionalRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import type { INestApplication } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const app: INestApplication | undefined;
      app?.useGlobalGuards(new JwtAuthGuard());
      @Controller('optional') class OptionalController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export interface INestApplication { useGlobalGuards(...guards: unknown[]): this; }
      `,
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
    });
    const externalRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { ExternalController } from 'external-base';
      import { JwtAuthGuard } from './auth';
      @Controller('external') @UseGuards(JwtAuthGuard)
      class LocalController extends ExternalController { @Get() read() {} }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-base/package.json': JSON.stringify({
        name: 'external-base', version: '1.0.0', types: 'index.d.ts',
      }),
      'node_modules/external-base/index.d.ts': 'export declare class ExternalController {}\n',
    });
    const dynamicBaseRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { ApiKeyGuard, JwtAuthGuard } from './auth';
      declare const enabled: boolean;
      @UseGuards(ApiKeyGuard) class GuardedBase {}
      class PlainBase {}
      @Controller('dynamic-base') @UseGuards(JwtAuthGuard)
      class LocalController extends (enabled ? GuardedBase : PlainBase) { @Get() read() {} }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\nexport class ApiKeyGuard {}\n',
    });
    const mutablePropertyBaseRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { ApiKeyGuard } from './auth';
      @UseGuards(ApiKeyGuard) class GuardedBase {}
      class PlainBase {}
      let holder: { Base: typeof GuardedBase } = { Base: GuardedBase };
      holder.Base = PlainBase;
      @Controller('mutable-base')
      class LocalController extends holder.Base { @Get() read() {} }
    `, { 'src/auth.ts': 'export class ApiKeyGuard {}\n' });
    const mutableIdentifierBaseRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { ApiKeyGuard } from './auth';
      @UseGuards(ApiKeyGuard) class GuardedBase {}
      class PlainBase {}
      let Base: typeof GuardedBase = GuardedBase;
      Base = PlainBase;
      @Controller('mutable-identifier-base')
      class LocalController extends Base { @Get() read() {} }
    `, { 'src/auth.ts': 'export class ApiKeyGuard {}\n' });
    const staticClassBaseRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { ApiKeyGuard } from './auth';
      @UseGuards(ApiKeyGuard) class GuardedBase {}
      @Controller('static-base')
      class LocalController extends (class extends GuardedBase {}) { @Get() read() {} }
    `, { 'src/auth.ts': 'export class ApiKeyGuard {}\n' });
    const namespaceBaseRoot = workspace(`
      import { Controller, Get } from '@nestjs/common';
      import * as bases from './bases';
      @Controller('namespace-base')
      class LocalController extends bases.GuardedBase { @Get() read() {} }
    `, {
      'src/auth.ts': 'export class ApiKeyGuard {}\n',
      'src/bases.ts': `
        import { UseGuards } from '@nestjs/common';
        import { ApiKeyGuard } from './auth';
        @UseGuards(ApiKeyGuard) export class GuardedBase {}
      `,
    });
    const constClassAliasBaseRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { ApiKeyGuard } from './auth';
      @UseGuards(ApiKeyGuard) class GuardedBase {}
      const Base = class extends GuardedBase { @Get('inherited') read() {} };
      @Controller('const-base') class LocalController extends Base {}
    `, { 'src/auth.ts': 'export class ApiKeyGuard {}\n' });
    const inheritedDynamicControllerRoot = workspace(`
      import { Controller, Get } from '@nestjs/common';
      declare const enabled: boolean;
      @Controller('guarded') class ControllerBase {}
      class PlainBase {}
      class LocalController extends (enabled ? ControllerBase : PlainBase) {
        @Get() read() {}
      }
    `);
    const inheritedDynamicMethodRoot = workspace(`
      import { Controller, Get } from '@nestjs/common';
      declare const enabled: boolean;
      class RouteBase { @Get('inherited') read() {} }
      class PlainBase {}
      @Controller('dynamic-method')
      class LocalController extends (enabled ? RouteBase : PlainBase) {}
    `);
    const nonNestDynamicBaseRoot = workspace(`
      declare const enabled: boolean;
      class FirstBase {}
      class SecondBase {}
      class DataTransferObject extends (enabled ? FirstBase : SecondBase) {}
    `);
    const inheritedDynamicAuthOverrideRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { ApiKeyGuard, Public } from './auth';
      declare const enabled: boolean;
      @Controller('auth-override') @UseGuards(ApiKeyGuard)
      class SecuredBase { @Get() read() {} }
      class PlainBase {}
      @Public() class LocalController extends (enabled ? SecuredBase : PlainBase) {}
    `, {
      'src/auth.ts': `
        export class ApiKeyGuard {}
        export const Public = (): ClassDecorator => () => {};
      `,
    });

    const global = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(globalRoot));
    const unrelated = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(unrelatedRoot));
    const optional = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(optionalRoot));
    const external = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(externalRoot));
    const dynamicBase = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(dynamicBaseRoot),
    );
    const mutablePropertyBase = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(mutablePropertyBaseRoot),
    );
    const mutableIdentifierBase = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(mutableIdentifierBaseRoot),
    );
    const staticClassBase = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(staticClassBaseRoot),
    );
    const namespaceBase = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(namespaceBaseRoot),
    );
    const constClassAliasBase = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(constClassAliasBaseRoot),
    );
    const inheritedDynamicController = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(inheritedDynamicControllerRoot),
    );
    const inheritedDynamicMethod = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(inheritedDynamicMethodRoot),
    );
    const nonNestDynamicBase = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(nonNestDynamicBaseRoot),
    );
    const inheritedDynamicAuthOverride = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(inheritedDynamicAuthOverrideRoot),
    );
    expect(global.status).toBe('success');
    expect(unrelated.status).toBe('success');
    expect(optional.status).toBe('success');
    expect(external.status).toBe('success');
    expect(dynamicBase.status).toBe('success');
    expect(mutablePropertyBase.status).toBe('success');
    expect(mutableIdentifierBase.status).toBe('success');
    expect(staticClassBase.status).toBe('success');
    expect(namespaceBase.status).toBe('success');
    expect(constClassAliasBase.status).toBe('success');
    expect(inheritedDynamicController.status).toBe('success');
    expect(inheritedDynamicMethod.status).toBe('success');
    expect(nonNestDynamicBase.status).toBe('success');
    expect(inheritedDynamicAuthOverride.status).toBe('success');
    if (global.status !== 'success' || unrelated.status !== 'success'
      || optional.status !== 'success' || external.status !== 'success'
      || dynamicBase.status !== 'success' || mutablePropertyBase.status !== 'success'
      || mutableIdentifierBase.status !== 'success' || staticClassBase.status !== 'success'
      || namespaceBase.status !== 'success' || constClassAliasBase.status !== 'success') return;
    if (inheritedDynamicController.status !== 'success'
      || inheritedDynamicMethod.status !== 'success'
      || nonNestDynamicBase.status !== 'success'
      || inheritedDynamicAuthOverride.status !== 'success') return;
    expect(global.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(global.result.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
    expect(unrelated.result.contract.operations[0].auth.mode).toBe('alternatives');
    expect(unrelated.result.diagnostics).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
    expect(optional.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(external.result.contract.operations[0]).toMatchObject({
      exposure: 'unknown',
      auth: { mode: 'unknown', analysis: { enforcementConfidence: 'unknown' } },
    });
    expect(dynamicBase.result.contract.operations[0]).toMatchObject({
      exposure: 'unknown',
      auth: { mode: 'unknown', analysis: { enforcementConfidence: 'unknown' } },
    });
    expect(mutablePropertyBase.result.contract.operations[0]).toMatchObject({
      exposure: 'unknown',
      auth: { mode: 'unknown', analysis: { enforcementConfidence: 'unknown' } },
    });
    expect(mutableIdentifierBase.result.contract.operations[0]).toMatchObject({
      exposure: 'unknown',
      auth: { mode: 'unknown', analysis: { enforcementConfidence: 'unknown' } },
    });
    expect(staticClassBase.result.contract.operations[0]).toMatchObject({
      exposure: 'authenticated',
      auth: { mode: 'alternatives', analysis: { enforcementConfidence: 'high' } },
    });
    expect(namespaceBase.result.contract.operations[0]).toMatchObject({
      exposure: 'authenticated',
      auth: { mode: 'alternatives', analysis: { enforcementConfidence: 'high' } },
    });
    expect(constClassAliasBase.result.contract.operations[0]).toMatchObject({
      routeKey: 'GET /const-base/inherited',
      exposure: 'authenticated',
      auth: { mode: 'alternatives', analysis: { enforcementConfidence: 'high' } },
    });
    expect(inheritedDynamicController.result.unresolvedOperations).toEqual(expect.arrayContaining([
      expect.objectContaining({ methods: ['GET'], reason: 'SOURCE_ANALYZER_DYNAMIC_ROUTE' }),
      expect.objectContaining({
        methods: expect.arrayContaining(['GET', 'POST']),
        reason: 'SOURCE_ANALYZER_DYNAMIC_ROUTE',
      }),
    ]));
    expect(inheritedDynamicMethod.result.unresolvedOperations).toEqual(expect.arrayContaining([
      expect.objectContaining({
        methods: expect.arrayContaining(['GET', 'POST']),
        reason: 'SOURCE_ANALYZER_DYNAMIC_ROUTE',
      }),
    ]));
    expect(nonNestDynamicBase.result.unresolvedOperations).toEqual([]);
    expect(nonNestDynamicBase.result.diagnostics).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_DYNAMIC_ROUTE' }),
    ]));
    expect(inheritedDynamicAuthOverride.result.unresolvedOperations).toEqual(expect.arrayContaining([
      expect.objectContaining({
        methods: expect.arrayContaining(['GET', 'POST']),
        reason: 'SOURCE_ANALYZER_DYNAMIC_ROUTE',
      }),
    ]));
    expect(inheritedDynamicAuthOverride.result.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_DYNAMIC_ROUTE' }),
      expect.objectContaining({ code: 'SOURCE_ANALYZER_DYNAMIC_AUTH_METADATA' }),
    ]));
  });

  test('fails closed on synchronous provider factories and external module imports', async () => {
    const iifeRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({ providers: (() => [{ provide: APP_GUARD, useClass: JwtAuthGuard }])() })
      class AppModule {}
      @Controller('iife') class IifeController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': 'export declare const APP_GUARD: unique symbol;\n',
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
    });
    const externalRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { ExternalModule } from 'external-module';
      import { JwtAuthGuard } from './auth';
      @Module({ imports: [ExternalModule] }) class AppModule {}
      @Controller('external-module') class ExternalModuleController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-module/index.d.ts': 'export declare class ExternalModule {}\n',
      'node_modules/external-module/package.json': JSON.stringify({
        name: 'external-module', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const factoryRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { ExternalModule } from 'external-module';
      import { JwtAuthGuard } from './auth';
      function createImports() { return [ExternalModule]; }
      @Module({ imports: createImports() }) class AppModule {}
      @Controller('factory-module') class FactoryModuleController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-module/index.d.ts': 'export declare class ExternalModule {}\n',
      'node_modules/external-module/package.json': JSON.stringify({
        name: 'external-module', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const mutableRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { ExternalModule } from 'external-module';
      import { JwtAuthGuard } from './auth';
      let moduleImports = [ExternalModule];
      @Module({ imports: moduleImports }) class AppModule {}
      @Controller('mutable-module') class MutableModuleController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-module/index.d.ts': 'export declare class ExternalModule {}\n',
      'node_modules/external-module/package.json': JSON.stringify({
        name: 'external-module', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const logicalRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { ExternalModule } from 'external-module';
      import { JwtAuthGuard } from './auth';
      declare const enabled: boolean;
      @Module({ imports: [enabled && ExternalModule] }) class AppModule {}
      @Controller('logical-module') class LogicalModuleController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-module/index.d.ts': 'export declare class ExternalModule {}\n',
      'node_modules/external-module/package.json': JSON.stringify({
        name: 'external-module', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const branchFactoryRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const enabled: boolean;
      function createProviders() {
        if (enabled) return [];
        else return [{ provide: APP_GUARD, useClass: JwtAuthGuard }];
      }
      @Module({ providers: createProviders() }) class AppModule {}
      @Controller('branch-factory') class BranchFactoryController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': 'export declare const APP_GUARD: unique symbol;\n',
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
    });

    for (const [name, root] of [
      ['iife', iifeRoot], ['external', externalRoot], ['factory', factoryRoot],
      ['mutable', mutableRoot], ['logical', logicalRoot], ['branch-factory', branchFactoryRoot],
    ] as const) {
      const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));
      expect(execution.status, `${name}: ${JSON.stringify(execution)}`).toBe('success');
      if (execution.status !== 'success') continue;
      expect(execution.result.contract.operations[0].auth.mode, name).toBe('unknown');
      expect(execution.result.diagnostics).toEqual(expect.arrayContaining([
        expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
      ]));
    }

    const namespaceRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import * as Features from './features';
      import { JwtAuthGuard } from './auth';
      @Module({ imports: [Features.FeatureModule] }) class AppModule {}
      @Controller('namespace-module') class NamespaceModuleController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'src/features.ts': 'export class FeatureModule {}\n',
    });
    const namespaceExecution = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(namespaceRoot),
    );
    expect(namespaceExecution.status).toBe('success');
    if (namespaceExecution.status === 'success') {
      expect(namespaceExecution.result.contract.operations[0].auth.mode).toBe('alternatives');
    }

    const unreachableRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { ExternalModule } from 'external-module';
      import { JwtAuthGuard } from './auth';
      class LocalModule {}
      const selected = LocalModule;
      @Module({ imports: [
        false && ExternalModule,
        true || ExternalModule,
        true ? LocalModule : ExternalModule,
        LocalModule || ExternalModule,
        LocalModule ? LocalModule : ExternalModule,
        selected || ExternalModule,
      ] }) class AppModule {}
      @Controller('unreachable-module') class UnreachableModuleController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-module/index.d.ts': 'export declare class ExternalModule {}\n',
      'node_modules/external-module/package.json': JSON.stringify({
        name: 'external-module', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const unreachableExecution = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(unreachableRoot),
    );
    expect(unreachableExecution.status).toBe('success');
    if (unreachableExecution.status === 'success') {
      expect(unreachableExecution.result.contract.operations[0].auth.mode).toBe('alternatives');
      expect(unreachableExecution.result.diagnostics).not.toEqual(expect.arrayContaining([
        expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
      ]));
    }
  });

  test('fails closed on a bound useGlobalGuards alias', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import type { INestApplication } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const app: INestApplication;
      declare const guard: unknown;
      const register = app.useGlobalGuards.bind(app);
      const registerAlias = register;
      registerAlias(guard);
      @Controller('bound') class BoundController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export interface INestApplication { useGlobalGuards(...guards: unknown[]): this; }
      `,
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(execution.result.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
  });

  test('fails closed when duplicate routes have conflicting auth metadata', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard, Public } from './auth';
      @Controller('same') class GuardedController { @Get() @UseGuards(JwtAuthGuard) read() {} }
      @Controller('same') class PublicController { @Get() @Public() read() {} }
    `, {
      'src/auth.ts': `
        export class JwtAuthGuard {}
        export const Public = (): MethodDecorator => () => {};
      `,
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract.operations).toHaveLength(1);
    expect(execution.result.contract.operations[0]).toMatchObject({
      exposure: 'unknown',
      auth: {
        mode: 'unknown',
        analysis: {
          enforcementConfidence: 'unknown',
          capabilityReasons: expect.arrayContaining([
            'Conflicting NestJS auth metadata was found for the same route.',
          ]),
        },
      },
    });
  });

  test('does not conflict on duplicate routes with reordered set-valued auth metadata', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard, Roles } from './auth';
      @Controller('same') class FirstController {
        @Get() @UseGuards(JwtAuthGuard) @Roles('admin', 'ops') read() {}
      }
      @Controller('same') class SecondController {
        @Get() @UseGuards(JwtAuthGuard) @Roles('ops', 'admin') read() {}
      }
    `, {
      'src/auth.ts': `
        export class JwtAuthGuard {}
        export const Roles = (..._roles: unknown[]): MethodDecorator => () => {};
      `,
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract.operations).toHaveLength(1);
    expect(execution.result.contract.operations[0]).toMatchObject({
      exposure: 'authenticated',
      auth: {
        mode: 'alternatives',
        analysis: {
          roles: ['admin', 'ops'],
          enforcementConfidence: 'high',
        },
      },
    });
    expect(execution.result.contract.operations[0].auth.analysis?.capabilityReasons).not.toContain(
      'Conflicting NestJS auth metadata was found for the same route.',
    );
  });

  test('rejects invalid or executable-shaped programmatic config', () => {
    expect(() => validateNestJsAuthConfig({ ...authConfig, extra: true })).toThrow();
    const accessor = Object.defineProperty({}, 'public_decorators', { get() { throw new Error('executed'); } });
    expect(() => validateNestJsAuthConfig(accessor)).toThrowError(/invalid NestJS auth config/i);
    let executions = 0;
    const accessorArray: string[] = [];
    Object.defineProperty(accessorArray, '0', {
      enumerable: true,
      get() { executions += 1; return 'Public'; },
    });
    accessorArray.length = 1;
    expect(() => validateNestJsAuthConfig({
      ...authConfig, public_decorators: accessorArray,
    })).toThrowError(/invalid NestJS auth config/i);
    const executableArray = ['Public'];
    Object.defineProperty(executableArray, Symbol.iterator, {
      value() { executions += 1; return [][Symbol.iterator](); },
    });
    expect(() => validateNestJsAuthConfig({
      ...authConfig, public_decorators: executableArray,
    })).toThrowError(/invalid NestJS auth config/i);
    const proxy = new Proxy({}, {
      getPrototypeOf() { executions += 1; throw new Error('executed'); },
      ownKeys() { executions += 1; throw new Error('executed'); },
    });
    expect(() => validateNestJsAuthConfig({
      ...authConfig, guard_mappings: proxy,
    })).toThrowError(/invalid NestJS auth config/i);
    expect(executions).toBe(0);
    expect(() => validateNestJsAuthConfig({
      ...authConfig,
      guard_mappings: { JwtAuthGuard: { auth_kind: 'jwt' } },
    })).toThrow();
    const schema = JSON.parse(fs.readFileSync(
      path.join(process.cwd(), 'schemas/nestjs-source-analysis-options.schema.json'), 'utf8',
    ));
    const validate = new Ajv({ allErrors: true }).compile(schema);
    expect(validate(authConfig), JSON.stringify(validate.errors)).toBe(true);
    expect(validate({ ...authConfig, extra: true })).toBe(false);
  });
});
