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

  test('reports APP_GUARD as a partial global capability without executing module code', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { GLOBAL_GUARD } from './global-guard';
      const GUARD_TOKEN = GLOBAL_GUARD;
      export const providers = [{ provide: GUARD_TOKEN, useClass: JwtAuthGuard }];
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
