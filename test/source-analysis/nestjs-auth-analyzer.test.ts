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
  `);
  write(root, 'src/controller.ts', source);
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
      @Controller('bare') @UseGuards(JwtAuthGuard)
      class BareController { @Get() @Public read() {} }
    `, {
      'src/auth.ts': `
        export class JwtAuthGuard {}
        export const Public: MethodDecorator = () => {};
      `,
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract.operations[0]).toMatchObject({
      exposure: 'public',
      auth: { mode: 'none', analysis: { explicitPublic: true } },
    });
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
      @Controller('composed') @UseGuards(JwtAuthGuard)
      class ComposedController {
        @Get() @applyDecorators(UseGuards(ApiKeyGuard)) read() {}
        @Get('wrapped') @Auth() wrapped() {}
        @Get('nested') @applyDecorators(Auth()) nested() {}
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
    for (const routeKey of ['GET /composed/wrapped', 'GET /composed/nested']) {
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
    const computedRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      const providerKey = 'provide';
      export const providers = [{ [providerKey]: APP_GUARD, useClass: JwtAuthGuard }];
      @Controller('computed') class ComputedController { @Get() @UseGuards(JwtAuthGuard) read() {} }
    `, nestCoreFiles);

    const direct = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(directRoot));
    const mutable = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(mutableRoot));
    const computed = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(computedRoot));
    expect(direct.status).toBe('success');
    expect(mutable.status).toBe('success');
    expect(computed.status).toBe('success');
    if (direct.status !== 'success' || mutable.status !== 'success' || computed.status !== 'success') return;
    expect(direct.result.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
    expect(direct.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(mutable.result.diagnostics).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
    expect(mutable.result.contract.operations[0].auth.mode).toBe('alternatives');
    expect(computed.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(computed.result.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
  });

  test('fails closed on bootstrap global guards and external controller inheritance', async () => {
    const globalRoot = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare class AppModule {}
      const app = NestFactory.create(AppModule);
      app.useGlobalGuards(new JwtAuthGuard());
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

    const global = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(globalRoot));
    const unrelated = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(unrelatedRoot));
    const external = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(externalRoot));
    expect(global.status).toBe('success');
    expect(unrelated.status).toBe('success');
    expect(external.status).toBe('success');
    if (global.status !== 'success' || unrelated.status !== 'success' || external.status !== 'success') return;
    expect(global.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(global.result.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
    expect(unrelated.result.contract.operations[0].auth.mode).toBe('alternatives');
    expect(unrelated.result.diagnostics).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
    expect(external.result.contract.operations[0]).toMatchObject({
      exposure: 'unknown',
      auth: { mode: 'unknown', analysis: { enforcementConfidence: 'unknown' } },
    });
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
