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
    const deepReflectAlias = Array.from(
      { length: 65 }, (_, index) => `const invoke${index + 1} = invoke${index};`,
    ).join(' ');
    const root = workspace(`
      import { Controller, Get, UseGuards as Guards } from '@nestjs/common';
      import { ApiKeyGuard, JwtAuthGuard, Public as Open, Roles as Permissions, SecondGuard, UnknownGuard } from './auth';
      const invoke = Reflect.apply;
      let mutableInvoke = Reflect.apply;
      const invoke0 = Reflect.apply;
      ${deepReflectAlias}
      const audit = (..._args: unknown[]): MethodDecorator => () => {};
      let lateInvoke: any = audit;
      let earlyInvoke: any = audit;
      earlyInvoke = Reflect.apply;

      @Controller('users')
      @Guards(JwtAuthGuard)
      @Permissions('reader')
      class UsersController {
        @Get('admin') @Guards(ApiKeyGuard) @Guards(SecondGuard)
        @Permissions(['admin', 'ops']) @Permissions('reader') admin() {}
        @Get('call') @Guards.call(undefined, ApiKeyGuard) callGuard() {}
        @Get('apply') @Guards.apply(undefined, [ApiKeyGuard]) applyGuard() {}
        @Get('reflect-apply') @Reflect.apply(Guards, undefined, [ApiKeyGuard]) reflectApplyGuard() {}
        @Get('aliased-reflect-apply') @invoke(Guards, undefined, [ApiKeyGuard]) aliasedReflectApplyGuard() {}
        @Get('mutable-aliased-reflect-apply')
        @mutableInvoke(Guards, undefined, [ApiKeyGuard]) mutableAliasedReflectApplyGuard() {}
        @Get('deep-aliased-reflect-apply')
        @invoke65(Guards, undefined, [ApiKeyGuard]) deepAliasedReflectApplyGuard() {}
        @Get('late-reflect-write')
        @lateInvoke(Guards, undefined, [ApiKeyGuard]) lateReflectWriteGuard() {}
        @Get('early-reflect-write')
        @earlyInvoke(Guards, undefined, [ApiKeyGuard]) earlyReflectWriteGuard() {}
        @Get('global-reflect-apply')
        @globalThis.Reflect.apply(Guards, undefined, [ApiKeyGuard]) globalReflectApplyGuard() {}
        @Get('reflect-construct') @Reflect.construct(Guards, [ApiKeyGuard]) reflectConstructGuard() {}
        @Get('function-prototype')
        @Function.prototype.apply.call(Guards, undefined, [ApiKeyGuard]) functionPrototypeGuard() {}
        @Get('public') @Open() @Open('overwritten') publicRoute() {}
        @Get('unknown') @Guards(UnknownGuard) unknown() {}
      }

      @Controller('health')
      class HealthController { @Get() read() {} }
      lateInvoke = Reflect.apply;
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
    for (const route of [
      'GET /users/call', 'GET /users/apply', 'GET /users/reflect-apply',
      'GET /users/aliased-reflect-apply',
      'GET /users/mutable-aliased-reflect-apply',
      'GET /users/deep-aliased-reflect-apply',
      'GET /users/early-reflect-write',
      'GET /users/global-reflect-apply', 'GET /users/reflect-construct',
      'GET /users/function-prototype',
    ]) {
      expect(operations[route]).toMatchObject({
        exposure: 'unknown',
        auth: { mode: 'unknown', analysis: { enforcementConfidence: 'unknown' } },
      });
    }
    expect(operations['GET /users/late-reflect-write']).toMatchObject({
      exposure: 'authenticated',
      auth: { mode: 'alternatives', analysis: { enforcementConfidence: 'high' } },
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

  test('fails closed for indirectly invoked configured auth decorators', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard, Public, Roles } from './auth';
      @Controller('indirect-public') @UseGuards(JwtAuthGuard)
      class IndirectPublicController {
        @Get('call') @Public.call(undefined) call() {}
        @Get('reflect') @Reflect.apply(Public, undefined, []) reflect() {}
        @Get('roles') @Roles.call(undefined, 'admin') roles() {}
      }
    `, {
      'src/auth.ts': `
        export class JwtAuthGuard {}
        export const Public = (): MethodDecorator => () => {};
        export const Roles = (..._roles: string[]): MethodDecorator => () => {};
      `,
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer({
      ...authConfig, public_decorators: ['Public'],
    }), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract.operations).toEqual(expect.arrayContaining([
      expect.objectContaining({ routeKey: 'GET /indirect-public/call', exposure: 'unknown' }),
      expect.objectContaining({ routeKey: 'GET /indirect-public/reflect', exposure: 'unknown' }),
      expect.objectContaining({
        routeKey: 'GET /indirect-public/roles',
        auth: expect.objectContaining({
          mode: 'alternatives',
          analysis: expect.objectContaining({ roles: [], enforcementConfidence: 'unknown' }),
        }),
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
      declare const enabled: boolean;
      const Audit: MethodDecorator = () => {};
      const Authenticated = UseGuards(ApiKeyGuard);
      const AuthenticatedAlias = Authenticated;
      const ConditionalAuthenticated = enabled ? UseGuards(ApiKeyGuard) : Audit;
      const StaticAudit = true ? Audit : UseGuards(ApiKeyGuard);
      const LogicalAudit = Audit || UseGuards(ApiKeyGuard);
      const ConditionOnlyAudit = UseGuards(ApiKeyGuard) ? Audit : Audit;
      function MutableAudit(): MethodDecorator { return () => {}; }
      MutableAudit = undefined as any;
      const ReassignedLogical = MutableAudit || UseGuards(ApiKeyGuard);
      @Controller('precomputed') @UseGuards(JwtAuthGuard)
      class PrecomputedController {
        @Get() @AuthenticatedAlias read() {}
        @Get('conditional') @ConditionalAuthenticated conditional() {}
        @Get('static-audit') @StaticAudit staticAudit() {}
        @Get('logical-audit') @LogicalAudit logicalAudit() {}
        @Get('condition-only-audit') @ConditionOnlyAudit conditionOnlyAudit() {}
        @Get('reassigned-logical') @ReassignedLogical reassignedLogical() {}
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
    expect(operations['GET /precomputed'].auth.analysis?.guards).toEqual([
      { symbol: 'JwtAuthGuard', authKind: 'bearer' },
      { symbol: 'ApiKeyGuard', authKind: 'api-key' },
    ]);
    expect(operations['GET /precomputed/conditional'].auth).toMatchObject({
      mode: 'unknown', analysis: { enforcementConfidence: 'unknown' },
    });
    expect(operations['GET /precomputed/reassigned-logical'].auth).toMatchObject({
      mode: 'unknown', analysis: { enforcementConfidence: 'unknown' },
    });
    for (const route of [
      'GET /precomputed/static-audit',
      'GET /precomputed/logical-audit',
      'GET /precomputed/condition-only-audit',
    ]) {
      expect(operations[route].auth).toMatchObject({
        mode: 'alternatives', analysis: { enforcementConfidence: 'high' },
      });
    }
  });

  test('fails closed on a mutable precomputed guard decorator', async () => {
    const deepAliases = ["const alias99 = UseGuards(ApiKeyGuard);"];
    for (let index = 98; index >= 0; index -= 1) deepAliases.push(`const alias${index} = alias${index + 1};`);
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { ApiKeyGuard, JwtAuthGuard } from './auth';
      let Authenticated: MethodDecorator;
      Authenticated = UseGuards(ApiKeyGuard);
      let Audit: MethodDecorator = () => {};
      const table: Record<PropertyKey, unknown> = {};
      table[Audit as unknown as PropertyKey] = UseGuards(ApiKeyGuard);
      declare const enabled: boolean;
      let ConditionalAuth: MethodDecorator = Audit;
      ConditionalAuth = enabled ? UseGuards(ApiKeyGuard) : Audit;
      let DestructuredAuth: MethodDecorator = Audit;
      [DestructuredAuth] = [UseGuards(ApiKeyGuard)];
      let DefaultAuth: MethodDecorator = Audit;
      [DefaultAuth = Audit] = [UseGuards(ApiKeyGuard)];
      let ForOfAuth: MethodDecorator = Audit;
      for (ForOfAuth of [UseGuards(ApiKeyGuard)]) {}
      function identity<T>(value: T): T { return value; }
      let SpreadAuth: MethodDecorator = Audit;
      SpreadAuth = identity(...([UseGuards(ApiKeyGuard)] as const));
      function makeAuth(): MethodDecorator { return UseGuards(ApiKeyGuard); }
      let FactoryAuth: MethodDecorator;
      FactoryAuth = makeAuth();
      let mutableFactory = (): MethodDecorator => Audit;
      mutableFactory = (): MethodDecorator => UseGuards(ApiKeyGuard);
      let MutableFactoryAuth: MethodDecorator;
      MutableFactoryAuth = mutableFactory();
      function reassignedFactory(): MethodDecorator { return Audit; }
      reassignedFactory = (): MethodDecorator => UseGuards(ApiKeyGuard);
      let ReassignedFactoryAuth: MethodDecorator;
      ReassignedFactoryAuth = reassignedFactory();
      let MutableAlias: MethodDecorator = Audit;
      MutableAlias = UseGuards(ApiKeyGuard);
      let AliasedAuth: MethodDecorator;
      AliasedAuth = MutableAlias;
      let destructuredFactory = (): MethodDecorator => Audit;
      [destructuredFactory] = [(): MethodDecorator => UseGuards(ApiKeyGuard)];
      let DestructuredFactoryAuth: MethodDecorator;
      DestructuredFactoryAuth = destructuredFactory();
      let SlotAuth: MethodDecorator = Audit;
      let ignoredSlot: MethodDecorator = Audit;
      [SlotAuth, ignoredSlot] = [Audit, UseGuards(ApiKeyGuard)];
      let cleanFactory = (): MethodDecorator => Audit;
      let guardedFactory = (): MethodDecorator => Audit;
      [cleanFactory, guardedFactory] = [
        (): MethodDecorator => Audit,
        (): MethodDecorator => UseGuards(ApiKeyGuard),
      ];
      let CleanFactoryAuth: MethodDecorator;
      CleanFactoryAuth = cleanFactory();
      let MissingArrayAuth: MethodDecorator = Audit;
      [MissingArrayAuth = Audit] = [];
      let MissingObjectAuth: MethodDecorator = Audit;
      ({ auth: MissingObjectAuth = Audit } = {});
      const Noop: MethodDecorator = () => {};
      let PresentArrayAuth: MethodDecorator = Audit;
      [PresentArrayAuth = UseGuards(ApiKeyGuard)] = [Noop];
      let PresentObjectAuth: MethodDecorator = Audit;
      ({ auth: PresentObjectAuth = UseGuards(ApiKeyGuard) } = { auth: Noop });
      const holder = { Auth: Audit };
      holder.Auth = UseGuards(ApiKeyGuard);
      const PropertyAliasAuth = holder.Auth;
      interface Wrapper { Auth: MethodDecorator }
      const localHolder: Wrapper = { Auth: Audit };
      const otherHolder: Wrapper = { Auth: Audit };
      otherHolder.Auth = UseGuards(ApiKeyGuard);
      const aliasedHolder: Wrapper = { Auth: Audit };
      let mutableHolderAlias = aliasedHolder;
      mutableHolderAlias.Auth = UseGuards(ApiKeyGuard);
      const assignedHolder = { Auth: Audit };
      Object.assign(assignedHolder, { Auth: UseGuards(ApiKeyGuard) });
      const nestedAssignedHolder = { Auth: Audit };
      declare function mutate(value: unknown): void;
      mutate({ target: [nestedAssignedHolder] });
      const shorthandAssignedHolder = { Auth: Audit };
      mutate({ shorthandAssignedHolder });
      const conditionalHolder = { Auth: enabled ? UseGuards(ApiKeyGuard) : Audit };
      ${deepAliases.join('\n')}
      let DeepAuth: MethodDecorator = alias0;
      const decoratorFactories = {
        make(): MethodDecorator { return UseGuards(ApiKeyGuard); },
      };
      let MethodFactoryAuth: MethodDecorator;
      MethodFactoryAuth = decoratorFactories.make();
      const makeMethodAuth = decoratorFactories.make;
      let AliasedMethodFactoryAuth: MethodDecorator;
      AliasedMethodFactoryAuth = makeMethodAuth();
      const makeArrowAuth = (): MethodDecorator => UseGuards(ApiKeyGuard);
      let ArrowFactoryAuth: MethodDecorator;
      ArrowFactoryAuth = makeArrowAuth();
      @Controller('mutable-precomputed') @UseGuards(JwtAuthGuard)
      class MutablePrecomputedController {
        @Get() @Authenticated read() {}
        @Get('audit') @Audit audit() {}
        @Get('conditional') @ConditionalAuth conditional() {}
        @Get('destructured') @DestructuredAuth destructured() {}
        @Get('default') @DefaultAuth defaultTarget() {}
        @Get('for-of') @ForOfAuth forOf() {}
        @Get('spread') @SpreadAuth spread() {}
        @Get('factory') @FactoryAuth factory() {}
        @Get('mutable-factory') @MutableFactoryAuth mutableFactory() {}
        @Get('reassigned-factory') @ReassignedFactoryAuth reassignedFactory() {}
        @Get('mutable-alias') @AliasedAuth mutableAlias() {}
        @Get('destructured-factory') @DestructuredFactoryAuth destructuredFactory() {}
        @Get('slot') @SlotAuth slot() {}
        @Get('clean-factory') @CleanFactoryAuth cleanFactory() {}
        @Get('missing-array') @MissingArrayAuth missingArray() {}
        @Get('missing-object') @MissingObjectAuth missingObject() {}
        @Get('present-array') @PresentArrayAuth presentArray() {}
        @Get('present-object') @PresentObjectAuth presentObject() {}
        @Get('property-assignment') @holder.Auth propertyAssignment() {}
        @Get('property-alias') @PropertyAliasAuth propertyAlias() {}
        @Get('other-property-assignment') @localHolder.Auth otherPropertyAssignment() {}
        @Get('mutable-property-alias') @aliasedHolder.Auth mutablePropertyAlias() {}
        @Get('assigned-property') @assignedHolder.Auth assignedProperty() {}
        @Get('nested-assigned-property') @nestedAssignedHolder.Auth nestedAssignedProperty() {}
        @Get('shorthand-assigned-property') @shorthandAssignedHolder.Auth shorthandAssignedProperty() {}
        @Get('conditional-property') @conditionalHolder.Auth conditionalProperty() {}
        @Get('deep') @DeepAuth deep() {}
        @Get('method-factory') @MethodFactoryAuth methodFactory() {}
        @Get('aliased-method-factory') @AliasedMethodFactoryAuth aliasedMethodFactory() {}
        @Get('arrow-factory') @ArrowFactoryAuth arrowFactory() {}
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
    expect(operations['GET /mutable-precomputed']).toMatchObject({
      exposure: 'unknown',
      auth: { mode: 'unknown', analysis: { enforcementConfidence: 'unknown' } },
    });
    expect(operations['GET /mutable-precomputed/audit']).toMatchObject({
      exposure: 'authenticated',
      auth: { mode: 'alternatives', analysis: { enforcementConfidence: 'high' } },
    });
    for (const routeKey of [
      'GET /mutable-precomputed/slot', 'GET /mutable-precomputed/clean-factory',
      'GET /mutable-precomputed/missing-array', 'GET /mutable-precomputed/missing-object',
      'GET /mutable-precomputed/present-array', 'GET /mutable-precomputed/present-object',
    ]) {
      expect(operations[routeKey], routeKey).toMatchObject({
        exposure: 'authenticated',
        auth: { mode: 'alternatives', analysis: { enforcementConfidence: 'high' } },
      });
    }
    for (const routeKey of [
      'GET /mutable-precomputed/conditional', 'GET /mutable-precomputed/destructured',
      'GET /mutable-precomputed/default',
      'GET /mutable-precomputed/for-of', 'GET /mutable-precomputed/deep',
      'GET /mutable-precomputed/spread',
      'GET /mutable-precomputed/factory',
      'GET /mutable-precomputed/mutable-factory',
      'GET /mutable-precomputed/reassigned-factory', 'GET /mutable-precomputed/mutable-alias',
      'GET /mutable-precomputed/destructured-factory',
      'GET /mutable-precomputed/property-assignment',
      'GET /mutable-precomputed/property-alias',
      'GET /mutable-precomputed/other-property-assignment',
      'GET /mutable-precomputed/mutable-property-alias',
      'GET /mutable-precomputed/assigned-property',
      'GET /mutable-precomputed/nested-assigned-property',
      'GET /mutable-precomputed/shorthand-assigned-property',
      'GET /mutable-precomputed/conditional-property',
      'GET /mutable-precomputed/method-factory',
      'GET /mutable-precomputed/aliased-method-factory',
      'GET /mutable-precomputed/arrow-factory',
    ]) {
      expect(operations[routeKey]).toMatchObject({
        exposure: 'unknown',
        auth: { mode: 'unknown', analysis: { enforcementConfidence: 'unknown' } },
      });
    }
  });

  test('fails closed when a guard class binding is reassigned', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      class ApiKeyGuard {}
      class OtherGuard {}
      ApiKeyGuard = OtherGuard;
      @Controller('mutable-guard') class MutableGuardController {
        @Get() @UseGuards(ApiKeyGuard) read() {}
      }
    `);
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(execution.result.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_DYNAMIC_AUTH_METADATA' }),
    ]));
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

  test('fails closed when namespace guard members are reassigned', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import Auth = require('./auth');
      import { OtherGuard } from './other';
      (Auth as any).JwtAuthGuard = OtherGuard;
      @Controller('namespace-write') class NamespaceWriteController {
        @Get() @UseGuards(Auth.JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'src/other.ts': 'export class OtherGuard {}\n',
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status === 'success') {
      expect(execution.result.contract.operations[0].auth.mode).toBe('unknown');
    }
  });

  test('fails closed on branching and deeply nested namespace guard wrappers', async () => {
    const deepBody = `${'if (flag) {'.repeat(40)}return UseGuards(ApiKeyGuard);${'}'.repeat(40)} return () => {};`;
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import * as auth from './auth';
      import { JwtAuthGuard } from './guards';
      declare const flag: boolean;
      @Controller('namespace-flow') @UseGuards(JwtAuthGuard)
      class NamespaceFlowController {
        @Get('loop') @auth.Loop(flag) loop() {}
        @Get('deep') @auth.Deep(flag) deep() {}
        @Get('stored') @auth.Stored stored() {}
        @Get('returned') @auth.Returned() returned() {}
        @Get('tagged') @auth.Tagged() tagged() {}
        @Get('constructed') @auth.Constructed() constructed() {}
      }
    `, {
      'src/guards.ts': 'export class JwtAuthGuard {}\n',
      'src/auth.ts': `
        import { UseGuards } from '@nestjs/common';
        import { ApiKeyGuard } from './api-key';
        export function Loop(flag: boolean): MethodDecorator {
          do {
            if (flag) break;
            return () => {};
          } while (false);
          return UseGuards(ApiKeyGuard);
        }
        export function Deep(flag: boolean): MethodDecorator { ${deepBody} }
        export let Stored: MethodDecorator = () => {};
        function install(value: MethodDecorator) { Stored = value; }
        install(UseGuards(ApiKeyGuard));
        export const Returned = (): MethodDecorator => (target, key, descriptor) => {
          UseGuards(ApiKeyGuard)(target, key!, descriptor!);
        };
        declare const tag: (strings: TemplateStringsArray) => MethodDecorator;
        declare const Decorator: { new(): MethodDecorator };
        export const Tagged = (): MethodDecorator => tag\`guard\`;
        export const Constructed = (): MethodDecorator => new Decorator();
      `,
      'src/api-key.ts': 'export class ApiKeyGuard {}\n',
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

  test('recognizes a literal APP_GUARD provider token', async () => {
    for (const provider of [
      "{ provide: 'APP_GUARD', useClass: JwtAuthGuard }",
      "{ provide, useClass: JwtAuthGuard }",
    ]) {
      const root = workspace(`
        import { Controller, Get, Module, UseGuards } from '@nestjs/common';
        import { JwtAuthGuard } from './auth';
        const provide = 'APP_GUARD';
        @Module({ providers: [${provider}] }) class AppModule {}
        @Controller('literal-global') class GlobalController {
          @Get() @UseGuards(JwtAuthGuard) read() {}
        }
      `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });
      const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

      expect(execution.status).toBe('success');
      if (execution.status !== 'success') continue;
      expect(execution.result.contract.operations[0].auth.mode).toBe('unknown');
      expect(execution.result.diagnostics).toEqual(expect.arrayContaining([
        expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
      ]));
    }

    const conditionalRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      declare const enabled: boolean;
      @Module({
        providers: enabled ? [{ provide: 'APP_GUARD', useClass: JwtAuthGuard }] : [],
      }) class AppModule {}
      @Controller('conditional-literal-global') class GlobalController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });
    const conditional = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(conditionalRoot),
    );

    expect(conditional.status).toBe('success');
    if (conditional.status !== 'success') return;
    expect(conditional.result.contract.operations[0].auth.mode).toBe('unknown');
    expect(conditional.result.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));

    for (const [token, expected] of [
      ["enabled ? 'APP_GUARD' : 'OTHER_TOKEN'", 'unknown'],
      ["true ? 'OTHER_TOKEN' : 'APP_GUARD'", 'alternatives'],
      ["enabled && 'APP_GUARD'", 'unknown'],
      ["({}) || 'APP_GUARD'", 'alternatives'],
      ["[] ?? 'APP_GUARD'", 'alternatives'],
    ] as const) {
      const root = workspace(`
        import { Controller, Get, Module, UseGuards } from '@nestjs/common';
        import { JwtAuthGuard } from './auth';
        declare const enabled: boolean;
        @Module({ providers: [{ provide: ${token}, useClass: JwtAuthGuard }] })
        class AppModule {}
        @Controller('branch-literal-global') class GlobalController {
          @Get() @UseGuards(JwtAuthGuard) read() {}
        }
      `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });
      const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

      expect(execution.status).toBe('success');
      if (execution.status !== 'success') continue;
      expect(execution.result.contract.operations[0].auth.mode).toBe(expected);
    }
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
      `@Module({
         get providers() {
           try { return [...(null as any)]; }
           catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
         },
       }) class AppModule {}`,
      `@Module({
         get providers() {
           try { return 'provider' in (null as any) ? [] : []; }
           catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
         },
       }) class AppModule {}`,
      `@Module({
         get providers() {
           try { return 1n / (0n); }
           catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
         },
       }) class AppModule {}`,
      `declare function explode(): never;
       @Module({
         get providers() {
           try { do {} while (explode()); return []; }
           catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
         },
       }) class AppModule {}`,
      `declare function explode(): never;
       @Module({
         get providers() {
           try { for (const value = explode(); true;) { break; } return []; }
           catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
         },
       }) class AppModule {}`,
      `declare function explode(): never;
       @Module({
         get providers() {
           try { switch (0) { case explode(): break; } return []; }
           catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
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
      {
        setup: `@Module({
          get providers() {
            try { return []; }
            catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
          },
        }) class AppModule {}`,
        expected: 'alternatives',
      },
      {
        setup: `@Module({
          get providers() {
            const providers: unknown[] = [];
            try { return providers; }
            catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
          },
        }) class AppModule {}`,
        expected: 'alternatives',
      },
      {
        setup: `@Module({
          get providers() {
            try {
              // @ts-ignore: intentionally model an undeclared runtime identifier.
              return typeof (missing as any) ? [] : [];
            }
            catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
          },
        }) class AppModule {}`,
        expected: 'alternatives',
      },
      {
        setup: `declare function explode(): never;
          @Module({
            get providers() {
              try { return []; explode(); }
              catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
            },
          }) class AppModule {}`,
        expected: 'alternatives',
      },
      {
        setup: `declare function explode(): never;
          @Module({
            get providers() {
              try { while (false as const) explode(); return []; }
              catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
            },
          }) class AppModule {}`,
        expected: 'alternatives',
      },
      {
        setup: `declare function explode(): never;
          @Module({
            get providers() {
              try { for (; false;) explode(); return []; }
              catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
            },
        }) class AppModule {}`,
        expected: 'alternatives',
      },
      {
        setup: `declare function explode(): never;
          @Module({
            get providers() {
              try { do { break; } while (explode()); return []; }
              catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
            },
          }) class AppModule {}`,
        expected: 'alternatives',
      },
      {
        setup: `declare function explode(): never;
          @Module({
            get providers() {
              try { for (; true; explode()) { break; } return []; }
              catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
            },
          }) class AppModule {}`,
        expected: 'alternatives',
      },
      {
        setup: `declare function explode(): never;
          @Module({
            get providers() {
              try { switch (0) { case 0: break; case explode(): break; } return []; }
              catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
            },
        }) class AppModule {}`,
        expected: 'alternatives',
      },
      {
        setup: `@Module({
          get providers() {
            switch (0) {
              case 0: return [];
              case 1: return [{ provide: APP_GUARD, useClass: JwtAuthGuard }];
            }
          },
        }) class AppModule {}`,
        expected: 'alternatives',
      },
      {
        setup: `@Module({
          get providers() {
            do {} while (true);
            return [{ provide: APP_GUARD, useClass: JwtAuthGuard }];
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
      const unused = { [app['useGlobalGuards'](new JwtAuthGuard()) as any]() {} };
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

  test('ignores global guard calls in provably unreachable catch clauses', async () => {
    for (const [tryBody, expected] of [
      ['', 'alternatives'],
      ["throw new Error('reachable');", 'unknown'],
      ["class Exploding { static value = (() => { throw new Error('reachable'); })(); }", 'unknown'],
      ['declare function explode(): ParameterDecorator; class Exploding { constructor(@explode() value: unknown) {} }', 'unknown'],
    ] as const) {
      const root = workspace(`
        import { Controller, Get, UseGuards } from '@nestjs/common';
        import type { INestApplication } from '@nestjs/core';
        import { JwtAuthGuard } from './auth';
        declare const app: INestApplication;
        declare const guard: unknown;
        try { ${tryBody} } catch { app.useGlobalGuards(guard); }
        @Controller('catch-guard') class CatchGuardController {
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
      if (execution.status === 'success') {
        expect(execution.result.contract.operations[0].auth.mode, tryBody).toBe(expected);
      }
    }
  });

  test('tracks global guards through widened Nest application receivers', async () => {
    for (const { declaration, expected } of [
      { declaration: 'const app: any = await NestFactory.create(AppModule);', expected: 'unknown' },
      ...['create', 'createApplicationContext', 'createMicroservice'].map((method) => ({
        declaration: `const app = await NestFactory.${method}(AppModule) as unknown as {
        useGlobalGuards(...guards: unknown[]): unknown;
      };`, expected: 'unknown',
      })),
      {
        declaration: `let Factory = NestFactory;
        const app = await Factory.createMicroservice(AppModule) as unknown as {
          useGlobalGuards(...guards: unknown[]): unknown;
        };`,
        expected: 'unknown',
      },
      {
        declaration: `const app = await moduleRef.create(AppModule) as unknown as {
          useGlobalGuards(...guards: unknown[]): unknown;
        };`,
        expected: 'alternatives',
      },
    ]) {
      const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import { ModuleRef, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare class AppModule {}
      declare const guard: unknown;
      declare const moduleRef: ModuleRef;
      async function bootstrap() {
        ${declaration}
        app.useGlobalGuards(guard);
      }
      bootstrap();
      @Controller('any-app') class AnyAppController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export interface INestApplication { useGlobalGuards(...guards: unknown[]): this; }
        export declare class ModuleRef { create(module: unknown): Promise<unknown>; }
        export declare const NestFactory: {
          create(module: unknown): Promise<INestApplication>;
          createApplicationContext(module: unknown): Promise<INestApplication>;
          createMicroservice(module: unknown): Promise<INestApplication>;
        };
      `,
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
    });
      const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

      expect(execution.status).toBe('success');
      if (execution.status !== 'success') continue;
      expect(execution.result.contract.operations[0].auth.mode).toBe(expected);
    }
  });

  test('resolves mutable NestFactory aliases at factory-call time', async () => {
    for (const { sequence, expected } of [
      {
        sequence: `let Factory = NestFactory;
          const app = Factory.create(AppModule) as unknown as StructuralApp;
          Factory = OtherFactory;`,
        expected: 'unknown',
      },
      {
        sequence: `let Factory = OtherFactory;
          const app = Factory.create(AppModule) as unknown as StructuralApp;
          Factory = NestFactory;`,
        expected: 'alternatives',
      },
      {
        sequence: `let Factory: typeof NestFactory;
          Factory = NestFactory;
          const app = Factory.create(AppModule) as unknown as StructuralApp;`,
        expected: 'unknown',
      },
    ]) {
      const root = workspace(`
        import { Controller, Get, UseGuards } from '@nestjs/common';
        import { NestFactory } from '@nestjs/core';
        import { JwtAuthGuard } from './auth';
        declare class AppModule {}
        declare const guard: unknown;
        declare const OtherFactory: typeof NestFactory;
        type StructuralApp = { useGlobalGuards(...guards: unknown[]): unknown };
        ${sequence}
        app.useGlobalGuards(guard);
        @Controller('factory-order') class FactoryOrderController {
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
      const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

      expect(execution.status).toBe('success');
      if (execution.status !== 'success') continue;
      expect(execution.result.contract.operations[0].auth.mode).toBe(expected);
    }
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
    const tryFactoryRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const enabled: boolean;
      function createProviders() {
        try {
          if (enabled) throw new Error('fallback');
          return [];
        } catch {
          return [{ provide: APP_GUARD, useClass: JwtAuthGuard }];
        }
      }
      @Module({ providers: createProviders() }) class AppModule {}
      @Controller('try-factory') class TryFactoryController {
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
    const unresolvedProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalProviders } from 'external-providers';
      @Module({ providers: externalProviders }) class AppModule {}
      @Controller('external-providers') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalProviders: unknown[];\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const unresolvedNamespaceProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import * as external from 'external-providers';
      @Module({ providers: external.providers }) class AppModule {}
      @Controller('external-namespace-providers') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const providers: unknown[];\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const unresolvedFactoryProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { makeProviders } from 'external-providers';
      @Module({ providers: makeProviders() }) class AppModule {}
      @Controller('external-factory-providers') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare function makeProviders(): unknown[];\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const unresolvedLocalFactoryProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalProviders } from 'external-providers';
      function makeProviders() { return externalProviders; }
      @Module({ providers: makeProviders() }) class AppModule {}
      @Controller('local-factory-providers') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalProviders: unknown[];\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const unresolvedMethodFactoryProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalProviders } from 'external-providers';
      const factories = { make() { return externalProviders; } };
      @Module({ providers: factories.make() }) class AppModule {}
      @Controller('method-factory-providers') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalProviders: unknown[];\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const unresolvedIdentityFactoryProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalProviders } from 'external-providers';
      function identity<T>(value: T): T { return value; }
      @Module({ providers: identity(externalProviders) }) class AppModule {}
      @Controller('identity-factory-providers') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalProviders: unknown[];\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const unresolvedReassignedMethodFactoryProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalProviders } from 'external-providers';
      const factories = { make() { return []; } };
      factories.make = () => externalProviders;
      @Module({ providers: factories.make() }) class AppModule {}
      @Controller('reassigned-method-factory-providers') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalProviders: unknown[];\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const unresolvedArrowFactoryProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalProviders } from 'external-providers';
      const makeProviders = () => externalProviders;
      @Module({ providers: makeProviders() }) class AppModule {}
      @Controller('arrow-factory-providers') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalProviders: unknown[];\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const unresolvedDeclaredFactoryProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      declare function makeProviders(): unknown[];
      @Module({ providers: makeProviders() }) class AppModule {}
      @Controller('declared-factory-providers') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });
    const unresolvedMutatedProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalProviders } from 'external-providers';
      const providers: unknown[] = [];
      const config = { providers };
      config.providers.push(externalProviders);
      @Module({ providers }) class AppModule {}
      @Controller('mutated-providers') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalProviders: unknown[];\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const unresolvedCallbackMutatedProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalProviders } from 'external-providers';
      const providers: unknown[] = [{}];
      providers.forEach((_value, _index, array) => array.push(...externalProviders));
      @Module({ providers }) class AppModule {}
      @Controller('callback-mutated-providers') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalProviders: unknown[];\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const unresolvedExternalProviderObjectRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalProvider } from 'external-providers';
      @Module({ providers: [{ ...externalProvider }] }) class AppModule {}
      @Controller('external-provider-object') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalProvider: object;\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const reassignedExternalProviderTokenRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalToken } from 'external-providers';
      const holder = { token: 'local' };
      holder.token = externalToken;
      @Module({ providers: [{ provide: holder.token, useClass: JwtAuthGuard }] }) class AppModule {}
      @Controller('reassigned-external-provider-token') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalToken: string;\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const escapedProviderTokenRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      declare function mutate(value: unknown): void;
      const holder = { token: 'local' };
      mutate({ holder });
      @Module({ providers: [{ provide: holder.token, useClass: JwtAuthGuard }] }) class AppModule {}
      @Controller('escaped-provider-token') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });
    const customDecoratorMutationRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalToken } from 'external-providers';
      const holder = { token: 'local' };
      function Mutate(value: typeof holder) { value.token = externalToken; return () => {}; }
      @Mutate(holder) @Module({ providers: [{ provide: holder.token, useClass: JwtAuthGuard }] })
      class AppModule {}
      @Controller('custom-decorator-mutation') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalToken: string;\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const assignedAliasEscapeRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      declare function mutate(value: unknown): void;
      const holder = { token: 'local' };
      let alias: unknown;
      alias = holder;
      mutate(alias);
      @Module({ providers: [{ provide: holder.token, useClass: JwtAuthGuard }] }) class AppModule {}
      @Controller('assigned-alias-escape') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });
    const receiverMethodMutationRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalToken } from 'external-providers';
      const holder = { token: 'local', set(value: string) { this.token = value; } };
      holder.set(externalToken);
      @Module({ providers: [{ provide: holder.token, useClass: JwtAuthGuard }] }) class AppModule {}
      @Controller('receiver-method-mutation') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalToken: string;\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const nestedArrowReceiverMutationRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      declare function run(callback: () => void): void;
      declare function mutate(value: unknown): void;
      const holder = { token: 'local', update() { run(() => mutate(this)); } };
      holder.update();
      @Module({ providers: [{ provide: holder.token, useClass: JwtAuthGuard }] }) class AppModule {}
      @Controller('nested-arrow-receiver') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });
    const logicalEscapeRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      declare function mutate(value: unknown): void;
      const holder = { token: 'local' };
      mutate(holder || {});
      @Module({ providers: [{ provide: holder.token, useClass: JwtAuthGuard }] }) class AppModule {}
      @Controller('logical-escape') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });
    const mutableHolderEscapeRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      declare function mutate(value: unknown): void;
      let holder = { token: 'local' };
      mutate(holder);
      @Module({ providers: [{ provide: holder.token, useClass: JwtAuthGuard }] }) class AppModule {}
      @Controller('mutable-holder-escape') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });
    const selectedHolderEscapeRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      declare function mutate(value: unknown): void;
      const holder = { token: 'local' };
      mutate(({ value: holder }).value);
      @Module({ providers: [{ provide: holder.token, useClass: JwtAuthGuard }] }) class AppModule {}
      @Controller('selected-holder-escape') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });
    const spreadSelectedHolderEscapeRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      declare function mutate(value: unknown): void;
      const holder = { token: 'local' };
      mutate(([...[], holder] as const)[0]);
      @Module({ providers: [{ provide: holder.token, useClass: JwtAuthGuard }] }) class AppModule {}
      @Controller('spread-selected-holder') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });
    const assignedPropertyEscapeRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      declare function mutate(value: unknown): void;
      const holder = { token: 'local' };
      const config: { value: unknown } = { value: {} };
      config.value = holder;
      mutate(config.value);
      @Module({ providers: [{ provide: holder.token, useClass: JwtAuthGuard }] }) class AppModule {}
      @Controller('assigned-property-escape') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });
    const nestedReceiverEscapeRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      declare function mutate(value: unknown): void;
      const outer = { inner: { token: 'local' } };
      mutate(outer);
      @Module({ providers: [{ provide: outer.inner.token, useClass: JwtAuthGuard }] }) class AppModule {}
      @Controller('nested-receiver-escape') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });
    const returnedHolderEscapeRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      declare function mutate(value: unknown): void;
      const holder = { token: 'local' };
      function expose() { return holder; }
      mutate(expose());
      @Module({ providers: [{ provide: holder.token, useClass: JwtAuthGuard }] }) class AppModule {}
      @Controller('returned-holder-escape') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });
    const unresolvedAliasedProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalProviders, makeProviders } from 'external-providers';
      const providersAlias = externalProviders;
      const factoryAlias = makeProviders;
      @Module({ providers: providersAlias }) class ListModule {}
      @Module({ providers: factoryAlias() }) class FactoryModule {}
      @Controller('external-aliased-providers') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': `
        export declare const externalProviders: unknown[];
        export declare function makeProviders(): unknown[];
      `,
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const unresolvedDestructuredProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalConfig } from 'external-providers';
      const { providers } = externalConfig;
      @Module({ providers }) class AppModule {}
      @Controller('external-destructured-providers') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalConfig: { providers: unknown[] };\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const unresolvedObjectProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalProviders } from 'external-providers';
      const config = { providers: externalProviders };
      @Module({ providers: config.providers }) class AppModule {}
      @Controller('external-object-providers') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalProviders: unknown[];\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const unresolvedSpreadObjectProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalProviders } from 'external-providers';
      const base = { providers: externalProviders };
      const config = { providers: [], ...base };
      @Module({ providers: config.providers }) class AppModule {}
      @Controller('external-spread-object-providers') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalProviders: unknown[];\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const unresolvedWrappedProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalProviders } from 'external-providers';
      declare const enabled: boolean;
      let providers = externalProviders;
      let patternProviders: unknown[] = [];
      [patternProviders] = [externalProviders];
      let objectProviders: unknown[] = [];
      ({ providers: objectProviders } = { providers: externalProviders });
      let nestedProviders: unknown[] = [];
      ({ config: { providers: nestedProviders } } = {
        config: { providers: externalProviders },
      });
      const config = { providers };
      @Module({ providers: [...externalProviders] }) class SpreadModule {}
      @Module({ providers: enabled ? [] : config.providers }) class ConditionalModule {}
      @Module({ providers: patternProviders }) class PatternModule {}
      @Module({ providers: objectProviders }) class ObjectPatternModule {}
      @Module({ providers: nestedProviders }) class NestedPatternModule {}
      @Controller('external-wrapped-providers') class ExternalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalProviders: unknown[];\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const localShorthandProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      const providers: unknown[] = [];
      const config = { providers };
      @Module({ providers: config.providers }) class AppModule {}
      @Controller('local-shorthand-providers') class LocalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });
    const parameterAssignedProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalProviders } from 'external-providers';
      let providers: unknown[] = [];
      function install(value: unknown[]) { providers = value; }
      install(externalProviders);
      @Module({ providers }) class AppModule {}
      @Controller('parameter-providers') class ParameterProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalProviders: unknown[];\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const unrelatedCallResultRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      const holder = { token: 'local' };
      console.log(Math.random());
      @Module({ providers: [{ provide: holder.token, useClass: JwtAuthGuard }] }) class AppModule {}
      @Controller('unrelated-call-result') class LocalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });

    for (const [name, root] of [
      ['iife', iifeRoot], ['external', externalRoot], ['factory', factoryRoot],
      ['mutable', mutableRoot], ['logical', logicalRoot], ['branch-factory', branchFactoryRoot],
      ['try-factory', tryFactoryRoot],
      ['unresolved-providers', unresolvedProvidersRoot],
      ['parameter-assigned-providers', parameterAssignedProvidersRoot],
      ['unresolved-namespace-providers', unresolvedNamespaceProvidersRoot],
      ['unresolved-factory-providers', unresolvedFactoryProvidersRoot],
      ['unresolved-local-factory-providers', unresolvedLocalFactoryProvidersRoot],
      ['unresolved-method-factory-providers', unresolvedMethodFactoryProvidersRoot],
      ['unresolved-identity-factory-providers', unresolvedIdentityFactoryProvidersRoot],
      ['unresolved-reassigned-method-factory-providers', unresolvedReassignedMethodFactoryProvidersRoot],
      ['unresolved-arrow-factory-providers', unresolvedArrowFactoryProvidersRoot],
      ['unresolved-declared-factory-providers', unresolvedDeclaredFactoryProvidersRoot],
      ['unresolved-mutated-providers', unresolvedMutatedProvidersRoot],
      ['unresolved-callback-mutated-providers', unresolvedCallbackMutatedProvidersRoot],
      ['unresolved-external-provider-object', unresolvedExternalProviderObjectRoot],
      ['reassigned-external-provider-token', reassignedExternalProviderTokenRoot],
      ['escaped-provider-token', escapedProviderTokenRoot],
      ['custom-decorator-mutation', customDecoratorMutationRoot],
      ['assigned-alias-escape', assignedAliasEscapeRoot],
      ['receiver-method-mutation', receiverMethodMutationRoot],
      ['nested-arrow-receiver-mutation', nestedArrowReceiverMutationRoot],
      ['logical-escape', logicalEscapeRoot],
      ['mutable-holder-escape', mutableHolderEscapeRoot],
      ['selected-holder-escape', selectedHolderEscapeRoot],
      ['spread-selected-holder-escape', spreadSelectedHolderEscapeRoot],
      ['assigned-property-escape', assignedPropertyEscapeRoot],
      ['nested-receiver-escape', nestedReceiverEscapeRoot],
      ['returned-holder-escape', returnedHolderEscapeRoot],
      ['unresolved-aliased-providers', unresolvedAliasedProvidersRoot],
      ['unresolved-destructured-providers', unresolvedDestructuredProvidersRoot],
      ['unresolved-object-providers', unresolvedObjectProvidersRoot],
      ['unresolved-spread-object-providers', unresolvedSpreadObjectProvidersRoot],
      ['unresolved-wrapped-providers', unresolvedWrappedProvidersRoot],
    ] as const) {
      const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));
      expect(execution.status, `${name}: ${JSON.stringify(execution)}`).toBe('success');
      if (execution.status !== 'success') continue;
      expect(execution.result.contract.operations[0].auth.mode, name).toBe('unknown');
      expect(execution.result.diagnostics).toEqual(expect.arrayContaining([
        expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
      ]));
    }

    const localShorthandExecution = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(localShorthandProvidersRoot),
    );
    expect(localShorthandExecution.status).toBe('success');
    if (localShorthandExecution.status === 'success') {
      expect(localShorthandExecution.result.contract.operations[0].auth.mode).toBe('alternatives');
    }
    const unrelatedCallResultExecution = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(unrelatedCallResultRoot),
    );
    expect(unrelatedCallResultExecution.status).toBe('success');
    if (unrelatedCallResultExecution.status === 'success') {
      expect(unrelatedCallResultExecution.result.contract.operations[0].auth.mode).toBe('alternatives');
    }

    const unreachableExternalProvidersRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalProviders } from 'external-providers';
      @Module({ providers: true ? [] : externalProviders }) class AppModule {}
      @Controller('unreachable-provider') class LocalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalProviders: unknown[];\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const unreachableProviderExecution = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(unreachableExternalProvidersRoot),
    );
    expect(unreachableProviderExecution.status).toBe('success');
    if (unreachableProviderExecution.status === 'success') {
      expect(unreachableProviderExecution.result.contract.operations[0].auth.mode).toBe('alternatives');
    }

    const deferredProviderTokenRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      import { externalProviders } from 'external-providers';
      const DeferredProvider = function () { return externalProviders; };
      @Module({ providers: [DeferredProvider] }) class AppModule {}
      @Controller('deferred-provider') class LocalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare const externalProviders: unknown[];\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const deferredProviderExecution = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(deferredProviderTokenRoot),
    );
    expect(deferredProviderExecution.status).toBe('success');
    if (deferredProviderExecution.status === 'success') {
      expect(deferredProviderExecution.result.contract.operations[0].auth.mode).toBe('alternatives');
    }

    const externalClassProviderRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { ConfigService } from 'external-providers';
      import { JwtAuthGuard } from './auth';
      @Module({ providers: [ConfigService] }) class AppModule {}
      @Controller('external-class-provider') class LocalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare class ConfigService {}\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const externalClassExecution = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(externalClassProviderRoot),
    );
    expect(externalClassExecution.status).toBe('success');
    if (externalClassExecution.status === 'success') {
      expect(externalClassExecution.result.contract.operations[0].auth.mode).toBe('alternatives');
    }

    const externalNamespaceClassProviderRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import * as external from 'external-providers';
      import { JwtAuthGuard } from './auth';
      @Module({ providers: [external.ConfigService] }) class AppModule {}
      @Controller('external-namespace-class-provider') class LocalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-providers/index.d.ts': 'export declare class ConfigService {}\n',
      'node_modules/external-providers/package.json': JSON.stringify({
        name: 'external-providers', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const externalNamespaceClassExecution = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(externalNamespaceClassProviderRoot),
    );
    expect(externalNamespaceClassExecution.status).toBe('success');
    if (externalNamespaceClassExecution.status === 'success') {
      expect(externalNamespaceClassExecution.result.contract.operations[0].auth.mode).toBe('alternatives');
    }

    const overloadedLocalFactoryRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      function makeProviders(): [];
      function makeProviders() { return []; }
      @Module({ providers: makeProviders() }) class AppModule {}
      @Controller('overloaded-local-factory') class LocalProvidersController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });
    const overloadedLocalFactoryExecution = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(overloadedLocalFactoryRoot),
    );
    expect(overloadedLocalFactoryExecution.status).toBe('success');
    if (overloadedLocalFactoryExecution.status === 'success') {
      expect(overloadedLocalFactoryExecution.result.contract.operations[0].auth.mode).toBe('alternatives');
    }

    const localImportFactoryRoot = workspace(`
      import { Controller, forwardRef, Get, Module, UseGuards } from '@nestjs/common';
      import { JwtAuthGuard } from './auth';
      class LocalModule {}
      function localModule() { return LocalModule; }
      @Module({ imports: [forwardRef(() => LocalModule), localModule()] }) class AppModule {}
      @Controller('local-import-factory') class LocalImportFactoryController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, { 'src/auth.ts': 'export class JwtAuthGuard {}\n' });
    const localImportFactoryExecution = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(localImportFactoryRoot),
    );
    expect(localImportFactoryExecution.status).toBe('success');
    if (localImportFactoryExecution.status === 'success') {
      expect(localImportFactoryExecution.result.contract.operations[0].auth.mode).toBe('alternatives');
    }

    const reassignedImportFactoryRoot = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { ExternalModule } from 'external-module';
      import { JwtAuthGuard } from './auth';
      class LocalModule {}
      function pick() { return LocalModule; }
      pick = () => ExternalModule;
      @Module({ imports: [pick()] }) class AppModule {}
      @Controller('reassigned-import-factory') class ReassignedImportFactoryController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/external-module/index.d.ts': 'export declare class ExternalModule {}\n',
      'node_modules/external-module/package.json': JSON.stringify({
        name: 'external-module', version: '1.0.0', types: 'index.d.ts',
      }),
    });
    const reassignedImportFactoryExecution = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(reassignedImportFactoryRoot),
    );
    expect(reassignedImportFactoryExecution.status).toBe('success');
    if (reassignedImportFactoryExecution.status === 'success') {
      expect(reassignedImportFactoryExecution.result.contract.operations[0].auth.mode).toBe('unknown');
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

  test('resolves provider factory try flows conservatively', async () => {
    for (const { before, after, body, expected } of [
      { before: '', after: '', expected: 'alternatives', body: `
        try { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
        finally { return []; }
      ` },
      { before: '', after: '', expected: 'alternatives', body: `
        try { return []; }
        catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
      ` },
      { before: 'declare function dangerous(): void;', after: '', expected: 'alternatives', body: `
        try { return [() => dangerous()]; }
        catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
      ` },
      { before: 'declare const providers: unknown[];', after: '', expected: 'unknown', body: `
        try { return providers; }
        catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
      ` },
      { before: '', after: 'const providers: unknown[] = [];', expected: 'unknown', body: `
        try { return providers; }
        catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
      ` },
      { before: '', after: '', expected: 'alternatives', body: `
        const providers: unknown[] = [];
        try { return providers; }
        catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
      ` },
      { before: '', after: '', expected: 'alternatives', body: `
        try { return providers; }
        catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
        var providers: unknown[] = [];
      ` },
      { before: '', after: '', expected: 'alternatives', body: `
        let providers: unknown[];
        try { return providers; }
        catch { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
      ` },
    ]) {
      const root = workspace(`
        import { Controller, Get, Module, UseGuards } from '@nestjs/common';
        import { APP_GUARD } from '@nestjs/core';
        import { JwtAuthGuard } from './auth';
        ${before}
        function createProviders() { ${body} }
        @Module({ providers: createProviders() }) class AppModule {}
        ${after}
        @Controller('provider-flow') class ProviderFlowController {
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
      if (execution.status === 'success') {
        expect(execution.result.contract.operations[0].auth.mode).toBe(expected);
      }
    }
  });

  test('resolves reachable switch returns in provider factories', async () => {
    for (const { setup, expected } of [
      {
        setup: `switch (1) {
          case 0: return [];
          case 1: return [{ provide: APP_GUARD, useClass: JwtAuthGuard }];
        }`,
        expected: 'unknown',
      },
      {
        setup: `switch (1) {
          case 1: while (true) { return [{ provide: APP_GUARD, useClass: JwtAuthGuard }]; }
        }`,
        expected: 'unknown',
      },
      {
        setup: `switch (1) {
          case 1: { break; }
          case 2: return [{ provide: APP_GUARD, useClass: JwtAuthGuard }];
        }
        return [];`,
        expected: 'alternatives',
      },
      {
        setup: `declare const enabled: boolean;
        switch (1) {
          case 1: if (enabled) break;
          case 2: return [{ provide: APP_GUARD, useClass: JwtAuthGuard }];
        }
        return [];`,
        expected: 'unknown',
      },
      {
        setup: `const selected = 1;
        switch (selected) {
          case 0: return [{ provide: APP_GUARD, useClass: JwtAuthGuard }];
          case 1: return [];
        }`,
        expected: 'alternatives',
      },
    ]) {
      const root = workspace(`
        import { Controller, Get, Module, UseGuards } from '@nestjs/common';
        import { APP_GUARD } from '@nestjs/core';
        import { JwtAuthGuard } from './auth';
        function createProviders() { ${setup} }
        @Module({ providers: createProviders() }) class AppModule {}
        @Controller('switch-factory') class SwitchFactoryController {
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
      const execution = await runSourceAnalyzer(
        createNestJsSourceAnalyzer(authConfig), context(root),
      );

      expect(execution.status).toBe('success');
      if (execution.status === 'success') {
        expect(execution.result.contract.operations[0].auth.mode).toBe(expected);
      }
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
      const prebound = app.useGlobalGuards.bind(app, guard);
      prebound();
      prebound.call(undefined);
      prebound.apply(undefined, []);
      const unbound = app.useGlobalGuards;
      unbound.call(app, guard);
      let mutableUnchanged = app.useGlobalGuards;
      mutableUnchanged.call(app, guard);
      let { useGlobalGuards } = app;
      useGlobalGuards.call(app, guard);
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

  test('tracks top-level mutable useGlobalGuards aliases at the call position', async () => {
    const aliases = [
      `let register = app.useGlobalGuards;
       register.call(app, guard);
       register = () => app;`,
      `let register = () => app;
       register = app.useGlobalGuards;
       register.call(app, guard);`,
      `let { useGlobalGuards: register } = app;
       register.call(app, guard);
       register = () => app;`,
      `let { useGlobalGuards: register } = app;
       register = app.useGlobalGuards;
       register.call(app, guard);`,
      `let canonical = app.useGlobalGuards;
       let register = () => app;
       if (enabled) register = canonical;
       register.call(app, guard);`,
      `let register = () => app;
       ({ register } = { register: app.useGlobalGuards });
       register.call(app, guard);`,
      `let register = () => app;
       [register] = [app.useGlobalGuards];
       register.call(app, guard);`,
      `let register = () => app;
       [register = app.useGlobalGuards] = [undefined];
       register.call(app, guard);`,
      `let register = () => app;
       ({ x: register = app.useGlobalGuards } = { x: undefined });
       register.call(app, guard);`,
      `let register = () => app;
       ({ register } = { register: () => app, ['register']: app.useGlobalGuards });
       register.call(app, guard);`,
      `let register = () => app;
       ({ register } = { get register() { return app.useGlobalGuards; } });
       register.call(app, guard);`,
      `let candidate = () => app;
       ({ candidate } = { get candidate() { return app.useGlobalGuards; } });
       let register = () => app;
       if (enabled) register = candidate;
       register.call(app, guard);`,
    ];
    for (const [index, alias] of aliases.entries()) {
      const root = workspace(`
        import { Controller, Get, UseGuards } from '@nestjs/common';
        import type { INestApplication } from '@nestjs/core';
        import { JwtAuthGuard } from './auth';
        declare const app: INestApplication;
        declare const guard: unknown;
        declare const enabled: boolean;
        ${alias}
        @Controller('mutable-alias') class MutableAliasController {
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
      if (execution.status === 'success') {
        expect(execution.result.contract.operations[0].auth.mode, `mutable alias fixture ${index}`).toBe('unknown');
      }
    }
  });

  test('does not treat a shadowed undefined value as a destructuring default', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import type { INestApplication } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const app: INestApplication;
      declare const guard: unknown;
      const undefined = () => app;
      let register = () => app;
      [register = app.useGlobalGuards] = [undefined];
      register.call(app, guard);
      @Controller('shadowed-undefined') class ShadowedUndefinedController {
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
    expect(
      execution.result.contract.operations[0].auth.mode,
      JSON.stringify(execution.result.diagnostics),
    ).toBe('alternatives');
  });

  test('fails closed on call/apply useGlobalGuards registrations', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import type { INestApplication } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const app: INestApplication;
      declare const guard: unknown;
      app.useGlobalGuards.call(app, guard);
      app.useGlobalGuards.apply(app, [guard]);
      app.useGlobalGuards(...[,]);
      app.useGlobalGuards.apply(app, [,] as never);
      app.useGlobalGuards.call.call(app.useGlobalGuards, app, guard);
      const [register] = [app.useGlobalGuards];
      register.call(app, guard);
      (0, app.useGlobalGuards).call(app, guard);
      app[('useGlobal' + 'Guards') as 'useGlobalGuards'](guard);
      @Controller('call-apply') class CallApplyController {
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

  test('resolves stable array-destructured global-guard aliases', async () => {
    for (const { setup, expected } of [
      { setup: 'const [register] = [app.useGlobalGuards];', expected: 'unknown' },
      { setup: 'const [register] = [audit];', expected: 'alternatives' },
      { setup: 'const [register = app.useGlobalGuards] = [];', expected: 'unknown' },
      { setup: 'const [register = app.useGlobalGuards] = [undefined];', expected: 'unknown' },
      { setup: 'const [register = app.useGlobalGuards] = [audit];', expected: 'alternatives' },
      {
        setup: 'declare const candidate: unknown; const [register = app.useGlobalGuards] = [candidate as any];',
        expected: 'unknown',
      },
      {
        setup: 'declare const holder: { register?: typeof app.useGlobalGuards }; const [register = app.useGlobalGuards] = [holder.register];',
        expected: 'unknown',
      },
      {
        setup: 'function candidate() {} candidate = undefined as any; const [register = app.useGlobalGuards] = [candidate];',
        expected: 'unknown',
      },
      {
        setup: 'const values = [app.useGlobalGuards]; const [register] = values;',
        expected: 'unknown',
      },
    ]) {
      const root = workspace(`
        import { Controller, Get, UseGuards } from '@nestjs/common';
        import type { INestApplication } from '@nestjs/core';
        import { JwtAuthGuard } from './auth';
        declare const app: INestApplication;
        declare const guard: unknown;
        function audit(..._values: unknown[]) {}
        ${setup}
        register.call(app, guard);
        @Controller('array-alias') class ArrayAliasController {
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
      if (execution.status !== 'success') continue;
      expect(execution.result.contract.operations[0].auth.mode, setup).toBe(expected);
    }
  });

  test('handles Function.prototype useGlobalGuards invocations', async () => {
    for (const [registration, expected] of [
      ['Function.prototype.apply.call(app.useGlobalGuards, app, [guard]);', 'unknown'],
      ['const hooks = { register: app.useGlobalGuards }; hooks.register.call(app, guard);', 'unknown'],
      ['const base = { register: app.useGlobalGuards }; const hooks = { ...base }; hooks.register.call(app, guard);', 'unknown'],
      ['const hooks = { register: app.useGlobalGuards, register: audit }; hooks.register.call(app, guard);', 'alternatives'],
      ['const hooks = { register: audit, register: app.useGlobalGuards }; hooks.register.call(app, guard);', 'unknown'],
      ['const hooks = { register: audit }; hooks.register = app.useGlobalGuards; hooks.register.call(app, guard);', 'unknown'],
      ['const hooks = { register: app.useGlobalGuards }; hooks.register = audit; hooks.register.call(app, guard);', 'alternatives'],
      ['const hooks = { register: audit }; Object.assign(hooks, { register: app.useGlobalGuards }); hooks.register.call(app, guard);', 'unknown'],
      ['declare function mutate(value: { register: (...args: unknown[]) => unknown }): void; const hooks = { register: audit }; mutate(hooks); hooks.register.call(app, guard);', 'unknown'],
      ['const hooks = { register: audit, mutate() { this.register = app.useGlobalGuards; } }; hooks.mutate(); hooks.register.call(app, guard);', 'unknown'],
      ['const hooks = { register: audit, mutate() { this.register = app.useGlobalGuards; } }; (hooks.mutate as any)(); hooks.register.call(app, guard);', 'unknown'],
      ['const hooks = { register: audit, mutate: () => { hooks.register = app.useGlobalGuards; } }; const mutate = hooks.mutate; mutate(); hooks.register.call(app, guard);', 'unknown'],
      ['const hooks = { register: audit, mutate() { Object.assign(hooks, { register: app.useGlobalGuards }); } }; hooks.register.call(app, guard);', 'alternatives'],
      ['const hooks = { register: audit, mutate() { this.register = app.useGlobalGuards; } }; (0, hooks.mutate)(); hooks.register.call(app, guard);', 'unknown'],
      ['const hooks = { register: audit, mutate() { this.register = app.useGlobalGuards; } }; (hooks.mutate || audit)(); hooks.register.call(app, guard);', 'unknown'],
      ['const hooks = { register: audit, mutate() { this.register = app.useGlobalGuards; } }; (hooks.mutate && audit)(); hooks.register.call(app, guard);', 'alternatives'],
      ['const hooks = { register: audit, mutate() { this.register = app.useGlobalGuards; } }; (true ? audit : hooks.mutate)(); hooks.register.call(app, guard);', 'alternatives'],
      ['const hooks = { register: audit, mutate() { this.register = app.useGlobalGuards; } }; (true || hooks.mutate); (false && hooks.mutate); (0 ? hooks.mutate : audit)(); hooks.register.call(app, guard);', 'alternatives'],
      ['const hooks = { register: audit, get mutate() { hooks.register = app.useGlobalGuards; return audit; } }; (true ? audit : hooks.mutate)(); hooks.register.call(app, guard);', 'alternatives'],
      ['const hooks = { register: audit, get mutate() { this.register = app.useGlobalGuards; return true; } }; void hooks.mutate; hooks.register.call(app, guard);', 'unknown'],
      ['const hooks = { register: audit, nested: { get trigger() { hooks.register = app.useGlobalGuards; return true; } } }; if (hooks.nested.trigger) {} hooks.register.call(app, guard);', 'unknown'],
      ['const hooks: { register: typeof audit; nested: { trigger: boolean } } = { register: audit, nested: { get trigger() { hooks.register = app.useGlobalGuards; return true; } } }; if (hooks.nested.trigger) {} hooks.register.call(app, guard);', 'unknown'],
      ['const hooks = { register: app.useGlobalGuards }; delete hooks.register; hooks.register.call(app, guard);', 'unknown'],
      ['const hooks = { register: audit }; if (hooks) hooks.register.call(app, guard);', 'alternatives'],
      ['declare function mutate(value: { register: (...args: unknown[]) => unknown }): void; const hooks = { register: audit }; mutate(false || hooks); hooks.register.call(app, guard);', 'unknown'],
      ['const hooks = { register: audit }; if (hooks && hooks) hooks.register.call(app, guard);', 'alternatives'],
      ['const hooks = { register: audit }; if ((0, hooks)) hooks.register.call(app, guard);', 'alternatives'],
      ['const enabled = false; if (enabled) app.useGlobalGuards(guard);', 'alternatives'],
      ['const selected = 1; switch (selected) { case 1: break; case 2: app.useGlobalGuards(guard); }', 'alternatives'],
      ['const hooks = { register: audit }; void hooks; typeof hooks; hooks === hooks; hooks.register.call(app, guard);', 'alternatives'],
      ['interface H { register: (...args: unknown[]) => unknown } const a: H = { register: app.useGlobalGuards }; const b: H = { register: audit }; b.register = audit; a.register.call(app, guard);', 'unknown'],
      ['interface H { register: (...args: unknown[]) => unknown } const a: H = { register: audit }; const b: H = { register: audit }; b.register = app.useGlobalGuards; a.register.call(app, guard);', 'alternatives'],
      ['const hooks = { register: audit, ...42 }; hooks.register.call(app, guard);', 'alternatives'],
      [`const a0 = { register: audit }; ${Array.from({ length: 128 }, (_, index) => `const a${index + 1} = a${index};`).join(' ')} a128.register.call(app, guard);`, 'alternatives'],
      ['Function.prototype.apply.call(app.useGlobalGuards, app, null);', 'alternatives'],
    ] as const) {
      const root = workspace(`
        import { Controller, Get, UseGuards } from '@nestjs/common';
        import type { INestApplication } from '@nestjs/core';
        import { JwtAuthGuard } from './auth';
        declare const app: INestApplication;
        declare const guard: unknown;
        declare const audit: (...args: unknown[]) => void;
        ${registration}
        @Controller('function-prototype') class FunctionPrototypeController {
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
      if (execution.status === 'success') {
        expect(execution.result.contract.operations[0].auth.mode, registration).toBe(expected);
      }
    }
  });

  test('fails closed on Reflect.apply useGlobalGuards registrations', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import type { INestApplication } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const app: INestApplication;
      declare const guard: unknown;
      const invoke = Reflect.apply;
      Reflect.apply(app.useGlobalGuards, app, [guard]);
      globalThis.Reflect.apply(app.useGlobalGuards, app, [guard]);
      invoke(app.useGlobalGuards, app, [guard]);
      @Controller('reflect-apply') class ReflectApplyController {
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

  test('ignores discarded members in deep comma-expression guard targets', async () => {
    const target = Array.from(
      { length: 65 }, (_, index) => index,
    ).reduce((right) => `(app.useGlobalGuards, ${right})`, 'other');
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import type { INestApplication } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const app: INestApplication;
      declare const guard: unknown;
      declare const other: (...args: unknown[]) => void;
      (${target}).call(app, guard);
      @Controller('deep-comma') class DeepCommaController {
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
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), {
      ...context(root),
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxAnalysisDepth: 1_024 },
    });

    expect(execution.status, JSON.stringify(execution)).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract.operations[0].auth.mode).toBe('alternatives');
  });

  test('ignores empty useGlobalGuards registrations', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import type { INestApplication } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const app: INestApplication;
      if (false) app.useGlobalGuards({});
      switch (1) { case 2: app.useGlobalGuards({}); }
      function unreachable() {
        return;
        app.useGlobalGuards({});
      }
      function unused() { app.useGlobalGuards({}); }
      const unusedCallback = () => app.useGlobalGuards({});
      class UnusedInstaller {
        constructor() { app.useGlobalGuards({}); }
        install() { app.useGlobalGuards({}); }
      }
      const unusedInstallers = {
        install() { app.useGlobalGuards({}); },
        callback: () => app.useGlobalGuards({}),
      };
      switch (1) {
        case 2: app.useGlobalGuards({}); break;
        case 1: break;
      }
      switch (1) { case 1: break; case 2: app.useGlobalGuards({}); }
      switch (1) { case 1: {} case 2: break; case 3: app.useGlobalGuards({}); }
      app.useGlobalGuards();
      app.useGlobalGuards(...[]);
      app.useGlobalGuards.call(app);
      app.useGlobalGuards.call(app, ...[]);
      app.useGlobalGuards.call.call(app.useGlobalGuards, app);
      app.useGlobalGuards.call.bind(app.useGlobalGuards, app)();
      app.useGlobalGuards.apply(app, []);
      app.useGlobalGuards.apply(app, null as never);
      app.useGlobalGuards.apply(app, undefined as never);
      let { useGlobalGuards } = app;
      useGlobalGuards = (..._guards: unknown[]) => app;
      useGlobalGuards({});
      @Controller('empty-global') class EmptyGlobalController {
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
    expect(execution.result.contract.operations[0].auth.mode).toBe('alternatives');
    expect(execution.result.diagnostics).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
  });

  test('ignores providers from modules outside the bootstrapped import graph', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class UnusedModule {}
      async function bootstrap() { await NestFactory.create(AppModule); }
      void bootstrap();
      @Controller('active') class ActiveController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
      `,
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract.operations[0].auth.mode).toBe('alternatives');
    expect(execution.result.diagnostics).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
    ]));
  });

  test('falls back safely when the bootstrapped module graph is incomplete', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const flag: boolean;
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      void NestFactory.create(AppModule);
      void NestFactory.create(flag ? GuardModule : AppModule);
      @Controller('conditional-root') class ConditionalRootController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('does not treat arbitrary callback factories as forwardRef', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      function selectModule(_callback: () => unknown) { return GuardModule; }
      void NestFactory.create(selectModule(() => AppModule));
      @Controller('callback-factory') class CallbackFactoryController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('falls back for indirect NestFactory bootstrap calls', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      void NestFactory.create(AppModule);
      const boot = NestFactory.create;
      const { create: destructuredBoot } = NestFactory;
      const key = 'create' as const;
      const { [key]: computedBoot } = NestFactory;
      void boot.call(NestFactory, GuardModule);
      void destructuredBoot.bind(NestFactory)(GuardModule);
      void computedBoot.apply(NestFactory, [GuardModule]);
      @Controller('indirect-bootstrap') class IndirectBootstrapController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('falls back for directly invoked NestFactory aliases', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      void NestFactory.create(AppModule);
      const { create: boot } = NestFactory;
      void boot(GuardModule);
      class Bootstrap { static start = NestFactory.create; }
      void Bootstrap.start(GuardModule);
      @Controller('direct-bootstrap-alias') class DirectBootstrapAliasController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('falls back for bootstrap functions returned by local factories', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      function getFactory(factory = NestFactory.create) { return factory; }
      declare const externalConfig: object;
      declare function thirdParty(config: object): void;
      void NestFactory.create(AppModule);
      void getFactory()(GuardModule);
      @Controller('returned-bootstrap') class ReturnedBootstrapController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('fails closed for ambiguous local bootstrap factory control flow', async () => {
    const cases = [
      `function getFactory(factory = NestFactory.create) { return factory; }
       const missing = undefined;
       void getFactory(void 0)(GuardModule);
       void getFactory(missing)(GuardModule);`,
      `function getFactory(factory = audit) { factory = NestFactory.create; return factory; }
       void getFactory()(GuardModule);`,
      `async function getFactory() { return NestFactory.create; }
       async function bootstrap() { void (await getFactory())(GuardModule); }
       void bootstrap();`,
      `async function getFactory() { return (() => NestFactory.create)(); }
       async function bootstrap() { void (await getFactory())(GuardModule); }
       void bootstrap();`,
      `function select(factory = NestFactory.create) { return factory; }
       async function getFactory() { return select(); }
       async function bootstrap() { void (await getFactory())(GuardModule); }
       void bootstrap();`,
      `const helpers = { getFactory() { return NestFactory.create; } };
       async function getFactory() { return helpers.getFactory(); }
       async function bootstrap() { void (await getFactory())(GuardModule); }
       void bootstrap();`,
      `const helpers: any = { getFactory() { return NestFactory.create; } };
       async function getFactory() { return helpers.getFactory(); }
       async function bootstrap() { void (await getFactory())(GuardModule); }
       void bootstrap();`,
      `async function getFactory() {
         return ({ getFactory() { return NestFactory.create; } } as any).getFactory();
       }
       async function bootstrap() { void (await getFactory())(GuardModule); }
       void bootstrap();`,
      `const base: any = { getFactory() { return NestFactory.create; } };
       const helpers: any = { ...base };
       async function getFactory() { return helpers.getFactory(); }
       async function bootstrap() { void (await getFactory())(GuardModule); }
       void bootstrap();`,
      `declare const dynamic: any;
       const helpers: any = { getFactory() { return audit; }, ...dynamic };
       async function getFactory() { return helpers.getFactory(); }
       async function bootstrap() { void (await getFactory())(GuardModule); }
       void bootstrap();`,
      `let helpers = { getFactory() { return audit; } };
       helpers = { getFactory() { return NestFactory.create; } };
       async function getFactory() { return helpers.getFactory(); }
       async function bootstrap() { void (await getFactory())(GuardModule); }
       void bootstrap();`,
      `const helpers = { getFactory() { return audit; } };
       helpers.getFactory = NestFactory.create;
       async function getFactory() { return helpers.getFactory(); }
       async function bootstrap() { void (await getFactory())(GuardModule); }
       void bootstrap();`,
      `declare function mutate(value: unknown): void;
       const helpers = { getFactory() { return audit; } };
       mutate(helpers);
       async function getFactory() { return helpers.getFactory(); }
       async function bootstrap() { void (await getFactory())(GuardModule); }
       void bootstrap();`,
      `function getFactory(factory = audit) {
         const nested = () => NestFactory.create;
         factory = nested();
         return factory;
       }
       void getFactory()(GuardModule);`,
      `function unused() { return NestFactory.create(GuardModule); }
       void unused;`,
    ];
    for (const localFactory of cases) {
      const root = workspace(`
        import { Controller, Get, Module, UseGuards } from '@nestjs/common';
        import { APP_GUARD, NestFactory } from '@nestjs/core';
        import { JwtAuthGuard } from './auth';
        @Module({}) class AppModule {}
        @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
        class GuardModule {}
        const audit = () => undefined;
        void NestFactory.create(AppModule);
        ${localFactory}
        @Controller('ambiguous-factory') class AmbiguousFactoryController {
          @Get() @UseGuards(JwtAuthGuard) read() {}
        }
      `, {
        'src/auth.ts': 'export class JwtAuthGuard {}\n',
        'node_modules/@nestjs/core/index.d.ts': `
          export declare const APP_GUARD: unique symbol;
          export declare const NestFactory: { create(module: unknown): Promise<unknown> };
        `,
        'node_modules/@nestjs/core/package.json': JSON.stringify({
          name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
        }),
        'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
      });
      const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

      expect(execution.status, localFactory).toBe('success');
      if (execution.status === 'success') {
        expect(execution.result.contract.operations[0].auth.mode).toBe('unknown');
      }
    }
  });

  test('does not widen the graph for unrelated local call ambiguity', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class UnusedModule {}
      async function audit() { return 1; }
      function normalize(value: number) { value++; return value; }
      function getFactory(factory = NestFactory.create) { return factory; }
      let helpers = { getFactory() { return audit; } };
      helpers = { getFactory() { return audit; } };
      async function useHelpers() { return helpers.getFactory(); }
      const chosen = (NestFactory.create, audit);
      void NestFactory.create(AppModule);
      console.log(
        audit(), normalize(1), chosen(), useHelpers(),
        true ? audit : NestFactory.create,
        true || NestFactory.create,
        undefined && NestFactory.create,
      );
      thirdParty({ noop() {}, ...externalConfig });
      const unrelatedBuild = { imports: [] as unknown[] };
      let externalCall = (_value: unknown) => undefined;
      externalCall = (_value: unknown) => undefined;
      externalCall(unrelatedBuild.imports);
      const nestedHolder = { holder: { inner: { boot: audit } } };
      thirdParty({ get factory() { return (nestedHolder.holder as any).inner.boot; } });
      try { getFactory(null as any)(UnusedModule); } catch {}
      @Controller('unrelated-call') class UnrelatedCallController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
      `,
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status === 'success') {
      expect(execution.result.contract.operations[0].auth.mode).toBe('alternatives');
    }
  });

  test('fails closed when module escape indexing reaches its bound', async () => {
    const calls = Array.from({ length: 4_100 }, (_, index) => `observe(${index});`).join('\n');
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare function observe(value: unknown): void;
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      void NestFactory.create(AppModule);
      ${calls}
      @Controller('bounded-escape') class BoundedEscapeController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
      `,
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status === 'success') {
      expect(execution.result.contract.operations[0].auth.mode).toBe('unknown');
    }
  });

  test('falls back when NestFactory bootstrap functions are passed to higher-order calls', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare function start(factory: object, module: unknown): void;
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      void NestFactory.create(AppModule);
      start(NestFactory.create as unknown as object, GuardModule);
      start({ factory: NestFactory.create, module: GuardModule } as unknown as object, GuardModule);
      start({ get boot() { return () => NestFactory.create(GuardModule); } } as unknown as object, GuardModule);
      start({ get boot() { return () => () => NestFactory.create(GuardModule); } } as unknown as object, GuardModule);
      const returnedBoot = () => NestFactory.create(GuardModule);
      start({ get boot() { return returnedBoot; } } as unknown as object, GuardModule);
      let assignedBoot = () => undefined;
      assignedBoot = NestFactory.create;
      start({ get boot() { return assignedBoot; } } as unknown as object, GuardModule);
      const { create: destructuredBoot } = NestFactory;
      start({ get boot() { return destructuredBoot; } } as unknown as object, GuardModule);
      class ReturnedBootstrap { static boot = NestFactory.create; }
      start({ get boot() { return ReturnedBootstrap.boot; } } as unknown as object, GuardModule);
      let returnedHolder = { boot: audit };
      returnedHolder = { boot: NestFactory.create };
      start({ get boot() { return returnedHolder.boot; } } as unknown as object, GuardModule);
      function boot(module: unknown) { return NestFactory.create(module); }
      start(boot as unknown as object, GuardModule);
      void (0, NestFactory.create)(GuardModule);
      function helper(factory = NestFactory.create) { return factory; }
      start(helper as unknown as object, GuardModule);
      start((() => NestFactory.create) as unknown as object, GuardModule);
      @Controller('higher-order-bootstrap') class HigherOrderBootstrapController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('falls back when bootstrap callbacks are passed through tuple spreads', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare function start(factory: (module: unknown) => unknown, module: unknown): void;
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      void NestFactory.create(AppModule);
      start(...([NestFactory.create, GuardModule] as const));
      @Controller('spread-bootstrap') class SpreadBootstrapController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('falls back for mutated higher-order argument spreads', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const other: (module: unknown) => unknown;
      declare function start(factory: unknown, module: unknown): void;
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      void NestFactory.create(AppModule);
      const args: [unknown, unknown] = [other, GuardModule];
      args[0] = NestFactory.create;
      start(...args);
      @Controller('mutated-spread-bootstrap') class MutatedSpreadBootstrapController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('falls back for dynamic NestFactory bootstrap method selection', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const method: 'create' | 'createMicroservice';
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      void NestFactory.create(AppModule);
      void NestFactory[method](GuardModule);
      @Controller('dynamic-bootstrap-method') class DynamicBootstrapMethodController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: {
          create(module: unknown): Promise<unknown>;
          createMicroservice(module: unknown): Promise<unknown>;
        };
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
  });

  test('falls back for dynamic selection from local bootstrap alias objects', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const key: 'boot' | 'audit';
      declare const audit: (module: unknown) => unknown;
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      void NestFactory.create(AppModule);
      const methods = { boot: NestFactory.create, audit };
      void (methods[key] as any)(GuardModule);
      @Controller('dynamic-bootstrap-object') class DynamicBootstrapObjectController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('falls back for call on dynamically selected bootstrap aliases', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const key: 'boot' | 'other';
      declare const other: (module: unknown) => unknown;
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      void NestFactory.create(AppModule);
      const methods = { boot: NestFactory.create, other };
      void (methods[key] as any).call(NestFactory, GuardModule);
      @Controller('dynamic-bootstrap-call') class DynamicBootstrapCallController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('falls back for mutated local bootstrap alias objects', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const other: (module: unknown) => unknown;
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      void NestFactory.create(AppModule);
      const methods = { boot: other };
      methods.boot = NestFactory.create;
      void methods.boot(GuardModule);
      @Controller('mutated-bootstrap-object') class MutatedBootstrapObjectController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('falls back for mutable local bootstrap alias objects', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const flag: boolean;
      declare const other: (module: unknown) => unknown;
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      void NestFactory.create(AppModule);
      const initial = { boot: NestFactory.create };
      let methods = flag ? initial : { boot: other };
      void methods.boot(GuardModule);
      @Controller('mutable-bootstrap-object') class MutableBootstrapObjectController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('does not widen the graph for known non-bootstrap destructuring keys', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class UnusedModule {}
      void NestFactory.create(AppModule);
      const { 0: unrelated } = NestFactory;
      // @ts-ignore -- the fixture target predates bigint, but the parser supports this property key.
      const { 1n: bigintKey } = NestFactory;
      unrelated?.call(null);
      bigintKey?.call(null);
      @Controller('numeric-bootstrap-key') class NumericBootstrapKeyController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
      `,
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract.operations[0].auth.mode).toBe('alternatives');
  });

  test('does not treat unused bootstrap references as invoked aliases', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class UnusedModule {}
      void NestFactory.create(AppModule);
      const helper = (_module: unknown) => NestFactory.create;
      const helpers = { run() {}, unused: NestFactory.create };
      let mutableHelper = (_module: unknown) => undefined;
      let logger = { log(_message: string) {} };
      helper(UnusedModule);
      helpers.run();
      mutableHelper.call(null, UnusedModule);
      logger.log('ready');
      @Controller('unused-bootstrap-reference') class UnusedBootstrapReferenceController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
      `,
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract.operations[0].auth.mode).toBe('alternatives');
  });

  test('fails closed for excessively nested forwardRef roots', async () => {
    const nestedRoot = `${'forwardRef(() => '.repeat(80)}AppModule${')'.repeat(80)}`;
    const root = workspace(`
      import { Controller, forwardRef, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      void NestFactory.create(${nestedRoot});
      @Controller('deep-forward-ref') class DeepForwardRefController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
      `,
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), {
      ...context(root),
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxAnalysisDepth: 1_024 },
    });

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract.operations[0].auth.mode).toBe('unknown');
  });

  test('includes createMicroservice roots in conservative global guard analysis', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({}) class HttpModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class WorkerModule {}
      void NestFactory.create(HttpModule);
      void NestFactory.createMicroservice(WorkerModule);
      @Controller('multi-app') class MultiAppController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: {
          create(module: unknown): Promise<unknown>;
          createMicroservice(module: unknown): Promise<unknown>;
        };
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
  });

  test('includes inherited module metadata in the active graph', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      @Module({}) class AppModule extends GuardModule {}
      void NestFactory.create(AppModule);
      @Controller('inherited-module') class InheritedModuleController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('does not widen the graph for resolved plain base classes', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      class PlainBase {}
      @Module({}) class AppModule extends PlainBase {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class UnusedModule {}
      void NestFactory.create(AppModule);
      @Controller('plain-base') class PlainBaseController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
      `,
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract.operations[0].auth.mode).toBe('alternatives');
  });

  test('follows only reachable conditional module imports', async () => {
    for (const { preamble, condition, expected } of [
      { preamble: '', condition: 'true ? SafeModule : GuardModule', expected: 'alternatives' },
      { preamble: '', condition: 'false ? GuardModule : SafeModule', expected: 'alternatives' },
      { preamble: '', condition: 'flag ? SafeModule : GuardModule', expected: 'unknown' },
      {
        preamble: 'function enabled() {} enabled = false as any;',
        condition: 'enabled ? SafeModule : GuardModule',
        expected: 'unknown',
      },
      {
        preamble: 'function enabled() {} enabled++;',
        condition: 'enabled ? SafeModule : GuardModule',
        expected: 'unknown',
      },
    ]) {
      const root = workspace(`
        import { Controller, Get, Module, UseGuards } from '@nestjs/common';
        import { APP_GUARD, NestFactory } from '@nestjs/core';
        import { JwtAuthGuard } from './auth';
        declare const flag: boolean;
        ${preamble}
        @Module({}) class SafeModule {}
        @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
        class GuardModule {}
        @Module({ imports: [${condition}] }) class AppModule {}
        void NestFactory.create(AppModule);
        @Controller('conditional-import') class ConditionalImportController {
          @Get() @UseGuards(JwtAuthGuard) read() {}
        }
      `, {
        'src/auth.ts': 'export class JwtAuthGuard {}\n',
        'node_modules/@nestjs/core/index.d.ts': `
          export declare const APP_GUARD: unique symbol;
          export declare const NestFactory: { create(module: unknown): Promise<unknown> };
        `,
        'node_modules/@nestjs/core/package.json': JSON.stringify({
          name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
        }),
        'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
      });
      const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

      expect(execution.status).toBe('success');
      if (execution.status !== 'success') continue;
      expect(execution.result.contract.operations[0].auth.mode).toBe(expected);
    }
  });

  test('fails closed for excessively deep local module inheritance', async () => {
    const bases = Array.from({ length: 300 }, (_, index) => (
      `class Base${index} extends ${index === 0 ? 'Object' : `Base${index - 1}`} {}`
    )).join('\n');
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      ${bases}
      @Module({}) class AppModule extends Base299 {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      void NestFactory.create(AppModule);
      @Controller('deep-module-inheritance') class DeepModuleInheritanceController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('falls back safely when bootstrapped module metadata is unresolved', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const flag: boolean;
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      @Module(flag ? { imports: [GuardModule] } : {}) class AppModule {}
      void NestFactory.create(AppModule);
      @Controller('unresolved-metadata') class UnresolvedMetadataController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('falls back safely when bootstrapped module metadata is mutated', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      const metadata: { imports: unknown[] } = { imports: [] };
      metadata.imports.push(GuardModule);
      @Module(metadata) class AppModule {}
      void NestFactory.create(AppModule);
      @Controller('mutated-metadata') class MutatedMetadataController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('falls back safely when module imports metadata is reassigned', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      const metadata: { imports: unknown[] } = { imports: [] };
      metadata.imports = [GuardModule];
      @Module(metadata) class AppModule {}
      void NestFactory.create(AppModule);
      @Controller('reassigned-imports') class ReassignedImportsController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('fails closed when module imports are mutated through a property alias', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      const metadata = { imports: [] as unknown[] };
      const imports = metadata.imports;
      imports.push(GuardModule);
      @Module(metadata) class AppModule {}
      void NestFactory.create(AppModule);
      @Controller('aliased-imports') class AliasedImportsController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
      `,
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status === 'success') {
      expect(execution.result.contract.operations[0].auth.mode).toBe('unknown');
    }
  });

  test('fails closed for destructured imports and duplicate Module metadata', async () => {
    const modules = [
      `const metadata = { imports: [] as unknown[] };
       const { imports } = metadata;
       imports.push(GuardModule);
       @Module(metadata) class AppModule {}`,
      `const key = 'imports' as const;
       const metadata = { imports: [] as unknown[] };
       const { [key]: imports } = metadata;
       imports.push(GuardModule);
       @Module(metadata) class AppModule {}`,
      `const source = {} as { imports?: unknown[] };
       const metadata = { imports: [] as unknown[] };
       const { imports = metadata.imports } = source;
       imports.push(GuardModule);
       @Module(metadata) class AppModule {}`,
      `const metadata = { imports: [] as unknown[] };
       function add(values: unknown[]) { values.push(GuardModule); }
       add(metadata.imports);
       @Module(metadata) class AppModule {}`,
      `const metadata = { imports: [] as unknown[] };
       function add(values = metadata.imports) { values.push(GuardModule); }
       add();
       @Module(metadata) class AppModule {}`,
      `const metadata = { imports: [] as unknown[] };
       function add(values: unknown[]) { values.push(GuardModule); }
       add(...[metadata.imports]);
       @Module(metadata) class AppModule {}`,
      `const metadata = { imports: [] as unknown[] };
       function add(values: unknown[]): void;
       function add(values: unknown[]) { values.push(GuardModule); }
       add(metadata.imports);
       @Module(metadata) class AppModule {}`,
      `const metadata = { imports: [] as unknown[] };
       function add(values: unknown[]) { values.push(GuardModule); }
       const alias = add;
       alias(metadata.imports);
       @Module(metadata) class AppModule {}`,
      `const metadata = { imports: [] as unknown[] };
       function add(values: unknown[]) { values.push(GuardModule); }
       const alias = add as typeof add;
       alias(metadata.imports);
       @Module(metadata) class AppModule {}`,
      `declare const externalMutator: (values: unknown[]) => void;
       const metadata = { imports: [] as unknown[] };
       const values = metadata.imports;
       let add = (_values: unknown[]) => undefined;
       add = externalMutator;
       add(values);
       @Module(metadata) class AppModule {}`,
      `const imports: unknown[] = [];
       const metadata = { imports };
       function add(values: unknown[]) { values.push(GuardModule); }
       add(imports);
       @Module(metadata) class AppModule {}`,
      `const metadata = { imports: [] as unknown[] };
       let imports: unknown[];
       imports = (metadata.imports as unknown[]);
       imports.push(GuardModule);
       @Module(metadata) class AppModule {}`,
      `const metadata = { imports: [] as unknown[] };
       let imports = (metadata.imports as unknown[]);
       imports.push(GuardModule);
       @Module(metadata) class AppModule {}`,
      `declare const key: string;
       const metadata: Record<string, unknown[]> = { imports: [] };
       const imports = metadata[key];
       imports.push(GuardModule);
       @Module(metadata) class AppModule {}`,
      `declare const key: string;
       const metadata = { imports: [] as unknown[] };
       const holder: Record<string, unknown[]> = { x: metadata.imports };
       const imports = holder[key];
       imports.push(GuardModule);
       @Module(metadata) class AppModule {}`,
      `declare const flag: boolean;
       const source = {} as { imports?: unknown[] };
       const metadata = { imports: [] as unknown[] };
       const { imports = flag ? metadata.imports : [] } = source;
       imports.push(GuardModule);
       @Module(metadata) class AppModule {}`,
      `const source = {} as { imports?: unknown[] };
       const metadata = { imports: [] as unknown[] };
       const holder = { imports: metadata.imports };
       const { imports = holder.imports } = source;
       imports.push(GuardModule);
       @Module(metadata) class AppModule {}`,
      `declare const flag: boolean;
       const source = {} as { imports?: unknown[] };
       const metadata = { imports: [] as unknown[] };
       const holder = flag ? { imports: metadata.imports } : { imports: [] as unknown[] };
       const { imports = holder.imports } = source;
       imports.push(GuardModule);
       @Module(metadata) class AppModule {}`,
      `@Module({ imports: [GuardModule] }) @Module({}) class AppModule {}`,
    ];
    for (const moduleSource of modules) {
      const root = workspace(`
        import { Controller, Get, Module, UseGuards } from '@nestjs/common';
        import { APP_GUARD, NestFactory } from '@nestjs/core';
        import { JwtAuthGuard } from './auth';
        @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
        class GuardModule {}
        ${moduleSource}
        void NestFactory.create(AppModule);
        @Controller('conservative-modules') class ConservativeModulesController {
          @Get() @UseGuards(JwtAuthGuard) read() {}
        }
      `, {
        'src/auth.ts': 'export class JwtAuthGuard {}\n',
        'node_modules/@nestjs/core/index.d.ts': `
          export declare const APP_GUARD: unique symbol;
          export declare const NestFactory: { create(module: unknown): Promise<unknown> };
        `,
        'node_modules/@nestjs/core/package.json': JSON.stringify({
          name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
        }),
        'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
      });
      const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

      expect(execution.status).toBe('success');
      if (execution.status === 'success') {
        expect(execution.result.contract.operations[0].auth.mode).toBe('unknown');
      }
    }
  });

  test('does not activate graph-external guards for unrelated dynamic collection mutation', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      const metadata = { imports: [] as unknown[] };
      @Module(metadata) class AppModule {}
      declare const key: string;
      const holder: Record<string, unknown[]> = {
        x: metadata.imports,
        ...{ x: [] as unknown[] },
      };
      const values = holder[key];
      values.push('audit');
      void NestFactory.create(AppModule);
      @Controller('unrelated-dynamic') class UnrelatedDynamicController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
      `,
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '10.0.0', types: 'index.d.ts',
      }),
    });

    const execution = await runSourceAnalyzer(
      createNestJsSourceAnalyzer(authConfig), context(root),
    );

    expect(execution.status).toBe('success');
    if (execution.status === 'success') {
      expect(execution.result.contract.operations[0].auth.mode).toBe('alternatives');
      expect(execution.result.diagnostics).not.toEqual(expect.arrayContaining([
        expect.objectContaining({ code: 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' }),
      ]));
    }
  });

  test('does not link a used destructuring default back to absent imports metadata', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class UnusedModule {}
      const metadata = {} as { imports?: unknown[] };
      const { imports = [] } = metadata;
      imports.push(UnusedModule);
      @Module(metadata) class AppModule {}
      void NestFactory.create(AppModule);
      @Controller('default-imports') class DefaultImportsController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
      `,
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status === 'success') {
      expect(execution.result.contract.operations[0].auth.mode).toBe('alternatives');
    }
  });

  test('does not widen the graph for unrelated module metadata assignments', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      const metadata = { imports: [], label: 'a' };
      let imports = metadata.imports;
      imports = [];
      metadata.label = 'b';
      @Module(metadata) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class UnusedModule {}
      const bootstrap = async () => { await NestFactory.create(AppModule); };
      void bootstrap();
      @Controller('metadata-label') class MetadataLabelController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
      `,
      'node_modules/@nestjs/core/package.json': JSON.stringify({
        name: '@nestjs/core', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
      }),
      'node_modules/@nestjs/core/index.js': 'throw new Error("must not load");\n',
    });
    const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(authConfig), context(root));

    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract.operations[0].auth.mode).toBe('alternatives');
  });

  test('does not treat a generator call as an executed bootstrap', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      const bootstrap = function* () { yield NestFactory.create(AppModule); };
      void bootstrap();
      @Controller('generator-bootstrap') class GeneratorBootstrapController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('does not narrow the module graph from unreachable bootstrap calls', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD, NestFactory } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({}) class AppModule {}
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class GuardModule {}
      if (0) void NestFactory.create(AppModule);
      false && NestFactory.create(AppModule);
      true || NestFactory.create(AppModule);
      false ? NestFactory.create(AppModule) : undefined;
      if (false) {
        const bootstrap = () => NestFactory.create(AppModule);
        void bootstrap;
      }
      while (false) NestFactory.create(AppModule);
      for (; false;) NestFactory.create(AppModule);
      while (true) { break; NestFactory.create(AppModule); }
      while (true) { continue; NestFactory.create(AppModule); }
      switch (1) { case 1: break; NestFactory.create(AppModule); }
      void ({} ?? NestFactory.create(AppModule));
      @Controller('dead-bootstrap') class DeadBootstrapController {
        @Get() @UseGuards(JwtAuthGuard) read() {}
      }
    `, {
      'src/auth.ts': 'export class JwtAuthGuard {}\n',
      'node_modules/@nestjs/core/index.d.ts': `
        export declare const APP_GUARD: unique symbol;
        export declare const NestFactory: { create(module: unknown): Promise<unknown> };
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
  });

  test('fails closed for APP_GUARD providers in anonymous modules', async () => {
    const root = workspace(`
      import { Controller, Get, Module, UseGuards } from '@nestjs/common';
      import { APP_GUARD } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      export default class {}
      @Controller('anonymous-module') class AnonymousModuleController {
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
    expect(execution.result.contract.operations[0].auth.mode).toBe('unknown');
  });

  test('keeps reachable nested global-guard calls inside their function boundary', async () => {
    const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import type { INestApplication } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const app: INestApplication;
      declare const guard: unknown;
      declare function invoke(callback: () => void): void;
      function outer() {
        invoke(inner);
        return;
        function inner() { app.useGlobalGuards(guard); }
      }
      outer();
      @Controller('nested-call') class NestedCallController {
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
  });

  test('distinguishes definition-time effects from unused class instance effects', async () => {
    for (const { member, expected } of [
      { member: 'field = app.useGlobalGuards(guard);', expected: 'alternatives' },
      { member: 'constructor(value = app.useGlobalGuards(guard)) {}', expected: 'alternatives' },
      { member: 'method(value = app.useGlobalGuards(guard)) {}', expected: 'alternatives' },
      { member: 'set value(input = app.useGlobalGuards(guard)) {}', expected: 'alternatives' },
      { member: '[app.useGlobalGuards(guard) as any] = 1;', expected: 'unknown' },
    ]) {
      const root = workspace(`
      import { Controller, Get, UseGuards } from '@nestjs/common';
      import type { INestApplication } from '@nestjs/core';
      import { JwtAuthGuard } from './auth';
      declare const app: INestApplication;
      declare const guard: unknown;
      class Unused {
        ${member}
        static register() { app.useGlobalGuards(guard); }
      }
      type UnusedType = Unused;
      type UnusedValueType = typeof Unused;
      @Controller('unused-static') class UnusedStaticController {
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
      if (execution.status !== 'success') continue;
      expect(execution.result.contract.operations[0].auth.mode).toBe(expected);
    }
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
