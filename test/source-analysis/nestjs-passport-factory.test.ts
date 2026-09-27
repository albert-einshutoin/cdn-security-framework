import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, expect, test } from 'vitest';

import { DEFAULT_SOURCE_ANALYSIS_LIMITS } from '../../src/source-analysis';
import { runNestJsSourceAnalysisInternal } from '../../src/source/nestjs/analyzer';
import { TypeScriptAnalysisCache } from '../../src/source/typescript/project-loader';
import { previewPassportStrategyObservation } from '../../src/contract/passport-strategy-observation';

const roots: string[] = [];

function fixture(source: string, extraFiles: Record<string, string> = {},
  definitelyTypedJwt = false): { root: string; sentinel: string } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-passport-factory-'));
  roots.push(root);
  const write = (relative: string, value: string) => {
    const file = path.join(root, relative);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, value);
  };
  write('tsconfig.json', JSON.stringify({ compilerOptions: {
    experimentalDecorators: true, moduleResolution: 'node', noLib: true, types: [],
  }, files: ['src/controller.ts'] }));
  write('src/controller.ts', source);
  for (const [name, contents] of Object.entries(extraFiles)) write(name, contents);
  write('node_modules/@nestjs/common/package.json', JSON.stringify({
    name: '@nestjs/common', version: '11.1.18', main: 'index.js', types: 'index.d.ts',
  }));
  write('node_modules/@nestjs/common/index.js', 'module.exports = {};');
  write('node_modules/@nestjs/common/index.d.ts', `
    export declare function Controller(path?: string | { path: string; version?: string }): ClassDecorator;
    export declare function Get(path?: string): MethodDecorator;
    export declare function UseGuards(...guards: unknown[]): ClassDecorator & MethodDecorator;
    export declare function Module(metadata: { providers?: unknown[] }): ClassDecorator;
  `);
  write('node_modules/@nestjs/passport/package.json', JSON.stringify({
    name: '@nestjs/passport', version: '11.0.5', main: 'index.js', types: 'index.d.ts',
  }));
  write('node_modules/@nestjs/passport/index.d.ts', `
    export declare function AuthGuard(strategy: string): unknown;
    export declare function PassportStrategy(base: unknown, name?: string): new (...args: any[]) => any;
  `);
  write('node_modules/passport-jwt/package.json', JSON.stringify({
    name: 'passport-jwt', version: '4.0.1', main: 'index.js', types: 'index.d.ts',
  }));
  write('node_modules/passport-jwt/index.d.ts', `
    export declare class Strategy {}
    export declare const ExtractJwt: { fromAuthHeaderAsBearerToken(): unknown };
  `);
  if (definitelyTypedJwt) {
    fs.rmSync(path.join(root, 'node_modules/passport-jwt/index.d.ts'));
    write('node_modules/passport-jwt/package.json', JSON.stringify({
      name: 'passport-jwt', version: '4.0.1', main: 'index.js',
    }));
    write('node_modules/@types/passport-jwt/package.json', JSON.stringify({
      name: '@types/passport-jwt', version: '4.0.1', types: 'index.d.ts',
    }));
    write('node_modules/@types/passport-jwt/index.d.ts', `
      export declare class Strategy {}
      export declare const ExtractJwt: { fromAuthHeaderAsBearerToken(): unknown };
    `);
  }
  write('node_modules/passport-jwt/index.js', `require('node:fs').writeFileSync(${JSON.stringify(path.join(root, 'executed'))}, 'bad');`);
  const sentinel = path.join(root, 'executed');
  write('node_modules/@nestjs/passport/index.js', `require('node:fs').writeFileSync(${JSON.stringify(sentinel)}, 'bad');`);
  return { root, sentinel };
}

async function observe(source: string, config?: unknown, extraFiles?: Record<string, string>,
  versioning: 'uri' | 'none' = 'uri', definitelyTypedJwt = false) {
  const { root, sentinel } = fixture(source, extraFiles, definitelyTypedJwt);
  const analyzed = await runNestJsSourceAnalysisInternal({
    workspaceRoot: root, entrypoints: ['tsconfig.json'],
    limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS }, logger: { log() {} },
  }, config, undefined, undefined, versioning === 'uri' ? 'uri' : undefined);
  expect(analyzed.execution.status).toBe('success');
  expect(fs.existsSync(sentinel)).toBe(false);
  return analyzed;
}

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

test('links the observed factory to a direct strategy, extractor call, and provider declaration', async () => {
  const analyzed = await observe(`
    import { Controller, Get, UseGuards, Module } from '@nestjs/common';
    import { AuthGuard, PassportStrategy } from '@nestjs/passport';
    import { Strategy, ExtractJwt } from 'passport-jwt';
    class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
      constructor() { super({ jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken() }); }
    }
    @Module({ providers: [JwtStrategy] }) class AuthModule {}
    @Controller({ path: 'users', version: '1' }) @UseGuards(AuthGuard('jwt')) class UsersController {
      @Get() list() {}
    }
  `);
  const links = analyzed.passportStrategyObservation;
  expect(links?.definitions).toMatchObject([{
    strategy: 'jwt', className: 'JwtStrategy', baseModule: 'passport-jwt',
    extractor: { status: 'observed', kind: 'bearer-header-call' },
  }]);
  expect(links?.providers).toMatchObject([{ moduleClass: 'AuthModule' }]);
  expect(links?.matches).toMatchObject([{ strategy: 'jwt', status: 'one' }]);
  expect(links?.matches[0].candidateIds).toEqual([links?.definitions[0].id]);
  expect(analyzed.uriComparison?.contract.operations[0].auth.mode).toBe('unknown');
});

test('authenticates passport-jwt runtime imports backed by DefinitelyTyped declarations', async () => {
  const analyzed = await observe(`
    import { Controller, Get, UseGuards, Module } from '@nestjs/common';
    import { AuthGuard, PassportStrategy } from '@nestjs/passport';
    import { Strategy, ExtractJwt } from 'passport-jwt';
    class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
      constructor() { super({ jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken() }); }
    }
    @Module({ providers: [JwtStrategy] }) class AuthModule {}
    @Controller({ path: 'users', version: '1' }) @UseGuards(AuthGuard('jwt')) class UsersController {
      @Get() list() {}
    }
  `, undefined, undefined, 'uri', true);
  expect(analyzed.passportStrategyObservation?.definitions).toMatchObject([{
    baseStatus: 'verified', baseModule: 'passport-jwt', extractor: { status: 'observed' },
  }]);
});

test('keeps same-name unverified bases as ambiguous candidates', async () => {
  const analyzed = await observe(`
    import { Controller, Get, UseGuards, Module } from '@nestjs/common';
    import { AuthGuard, PassportStrategy as P } from '@nestjs/passport';
    import * as Jwt from 'passport-jwt';
    function PassportStrategy(base: unknown, name: string): any { throw Error('not executed'); }
    class Trusted extends P(Jwt.Strategy, 'jwt') {
      constructor() { super({ jwtFromRequest: Jwt.ExtractJwt.fromAuthHeaderAsBearerToken() }); }
    }
    class Unverified extends PassportStrategy(Jwt.Strategy, 'jwt') {}
    @Module({ providers: [Trusted] }) class AuthModule {}
    @Controller({ path: 'users', version: '1' }) @UseGuards(AuthGuard('jwt')) class Users {
      @Get() list() {}
    }
  `);
  const links = analyzed.passportStrategyObservation!;
  expect(links.definitions.map(({ baseStatus }) => baseStatus).sort())
    .toEqual(['unverified', 'verified']);
  expect(links.matches).toMatchObject([{ status: 'multiple', candidateIds: expect.arrayContaining(
    links.definitions.map(({ id }) => id),
  ) }]);
  expect(links.providers).toHaveLength(1);
  expect(links.providers[0].definitionId).toBe(links.definitions.find(({ className }) =>
    className === 'Trusted')?.id);
  expect(links.definitions.find(({ className }) => className === 'Trusted')?.extractor.status)
    .toBe('observed');
});

test('verifies only stable direct namespace members for strategy and extractor', async () => {
  const source = (extra: string) => `
    import { Controller, Get, UseGuards, Module } from '@nestjs/common';
    import * as Passport from '@nestjs/passport';
    import * as Jwt from 'passport-jwt';
    ${extra}
    class JwtStrategy extends Passport.PassportStrategy(Jwt.Strategy, 'jwt') {
      constructor() { super({jwtFromRequest: Jwt.ExtractJwt.fromAuthHeaderAsBearerToken()}); }
    }
    @Module({providers: [JwtStrategy]}) class AuthModule {}
    @Controller({path: 'users', version: '1'}) @UseGuards(Passport.AuthGuard('jwt'))
    class Users { @Get() list() {} }
  `;
  const stable = await observe(source(''));
  expect(stable.passportStrategyObservation?.definitions).toMatchObject([{
    baseStatus: 'verified', extractor: { status: 'observed' },
  }]);
  expect(stable.passportStrategyObservation?.matches[0].status).toBe('one');
  const escaped = await observe(source('const escapedJwt = Jwt;'));
  expect(escaped.passportStrategyObservation?.definitions).toMatchObject([{
    baseStatus: 'unverified', extractor: { status: 'unconfirmed' },
  }]);
  const mutated = await observe(source('Jwt.ExtractJwt.fromAuthHeaderAsBearerToken = () => null;'));
  expect(mutated.passportStrategyObservation?.definitions).toMatchObject([{
    baseStatus: 'unverified', extractor: { status: 'unconfirmed' },
  }]);
});

test.each([
  ['name-only', 'class A extends PassportStrategy(Strategy, "jwt") {}'],
  ['different-extractor', 'class A extends PassportStrategy(Strategy, "jwt") { constructor() { super({jwtFromRequest: ExtractJwt.fromExtractors([])}); } }'],
  ['spread', 'class A extends PassportStrategy(Strategy, "jwt") { constructor() { super({...{}, jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken()}); } }'],
  ['getter', 'class A extends PassportStrategy(Strategy, "jwt") { constructor() { super({get jwtFromRequest() { return ExtractJwt.fromAuthHeaderAsBearerToken(); }}); } }'],
  ['duplicate', 'class A extends PassportStrategy(Strategy, "jwt") { constructor() { super({jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), jwtFromRequest: null}); } }'],
])('does not turn %s extractor syntax into a Bearer observation', async (_name, declaration) => {
  const analyzed = await observe(`
    import { Controller, Get, UseGuards } from '@nestjs/common';
    import { AuthGuard, PassportStrategy } from '@nestjs/passport';
    import { Strategy, ExtractJwt } from 'passport-jwt';
    ${declaration}
    @Controller({ path: 'users', version: '1' }) @UseGuards(AuthGuard('jwt')) class Users {
      @Get() list() {}
    }
  `);
  expect(analyzed.passportStrategyObservation?.definitions).toMatchObject([{
    strategy: 'jwt', extractor: { status: 'unconfirmed' },
  }]);
  expect(analyzed.passportStrategyObservation?.matches[0].status).toBe('one');
});

test('distinguishes no observed candidate from a factory with no safe literal name', async () => {
  const analyzed = await observe(`
    import { Controller, Get, UseGuards } from '@nestjs/common';
    import { AuthGuard } from '@nestjs/passport';
    declare const runtimeName: string;
    @Controller({ path: 'users', version: '1' }) @UseGuards(AuthGuard('missing')) class Users {
      @Get() list() {}
      @Get('dynamic') @UseGuards(AuthGuard(runtimeName)) dynamic() {}
    }
  `);
  expect(analyzed.passportStrategyObservation?.matches.map(({ status }) => status).sort())
    .toEqual(['none', 'unmatchable']);
});

test('does not claim absence when a direct PassportStrategy declaration has an unknown name', async () => {
  const analyzed = await observe(`
    import { Controller, Get, UseGuards } from '@nestjs/common';
    import { AuthGuard, PassportStrategy } from '@nestjs/passport';
    import { Strategy } from 'passport-jwt';
    declare const runtimeName: string;
    class Dynamic extends PassportStrategy(Strategy, runtimeName) {}
    @Controller({ path: 'users', version: '1' }) @UseGuards(AuthGuard('jwt')) class Users {
      @Get() list() {}
    }
  `);
  expect(analyzed.passportStrategyObservation).toMatchObject({
    incompleteDefinitionNames: 1, definitions: [],
    matches: [{ strategy: 'jwt', status: 'unmatchable', reason: 'definition-name-unverified' }],
  });
});

test('redacts strategy evidence only after full candidate matching', async () => {
  const analyzed = await observe(`
    import { Controller, Get, UseGuards } from '@nestjs/common';
    import { AuthGuard, PassportStrategy } from '@nestjs/passport';
    import { Strategy } from 'passport-jwt';
    class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {}
    @Controller({ path: 'items', version: '1' }) @UseGuards(AuthGuard('jwt')) class Items {
      @Get() read() {}
    }
  `);
  const observation = structuredClone(analyzed.passportStrategyObservation!);
  observation.definitions[0].className = 'AKIA1234567890';
  observation.definitions[0].sourceUri = 'src/sk-synthetic-secret.ts';
  const preview = previewPassportStrategyObservation(observation);
  expect(observation.matches[0].candidateIds).toEqual([observation.definitions[0].id]);
  expect(preview.matches[0].candidateIds).toEqual([observation.definitions[0].id]);
  expect(preview.definitions[0].className).toBe('[REDACTED_NAME]');
  expect(preview.definitions[0].sourceUri).toBe('[REDACTED_URI]');
  expect(JSON.stringify(preview)).not.toContain('sk-synthetic-secret');
});

test('observes direct Passport call sites separately from URI operations without promoting auth', async () => {
  const analyzed = await observe(`
    import { Controller, Get, UseGuards } from '@nestjs/common';
    import { AuthGuard as Guard } from '@nestjs/passport';
    import * as Passport from '@nestjs/passport';
    @Controller({ path: 'users', version: '1' })
    @UseGuards(Passport.AuthGuard('jwt'))
    class UsersController {
      @Get() list() {}
      @Get(':id') read() {}
      @Get('refresh') @UseGuards(Guard('jwt-refresh')) refresh() {}
    }
  `);
  const observation = analyzed.passportFactoryObservation;
  expect(observation?.callSites.map(({ scope, strategy }) => [scope, strategy]))
    .toEqual([['class', 'jwt'], ['method', 'jwt-refresh']]);
  expect(observation?.associations.map(({ callSiteId, method, comparisonPath }) => (
    [observation.callSites.find(({ id }) => id === callSiteId)?.strategy, method, comparisonPath]
  )).sort()).toEqual([
    ['jwt', 'GET', '/v1/users'], ['jwt', 'GET', '/v1/users/{id}'],
    ['jwt', 'GET', '/v1/users/refresh'], ['jwt-refresh', 'GET', '/v1/users/refresh'],
  ].sort());
  expect(analyzed.uriComparison?.contract.operations.every(({ auth }) => auth.mode === 'unknown')).toBe(true);
});

test('merges Passport status and auth mode for duplicate Source routes', async () => {
  const analyzed = await observe(`
    import { Controller, Get, UseGuards } from '@nestjs/common';
    import { AuthGuard } from '@nestjs/passport';
    import { Public, JwtAuthGuard } from './auth';
    @Controller({ path: 'same', version: '1' }) class Guarded {
      @Get() @UseGuards(AuthGuard('jwt'), JwtAuthGuard) read() {}
    }
    @Controller({ path: 'same', version: '1' }) class PublicRoute {
      @Get() @Public() read() {}
    }
  `, { public_decorators: ['Public'], roles_decorators: [],
    guard_mappings: { JwtAuthGuard: { auth_kind: 'bearer' } } }, {
    'src/auth.ts': 'export function Public(): MethodDecorator { return () => {}; } export class JwtAuthGuard {}',
  });
  const operation = analyzed.uriComparison?.contract.operations[0];
  expect(operation).toMatchObject({ auth: { mode: 'unknown' }, exposure: 'unknown' });
  expect(analyzed.passportFactoryObservation?.associations).toMatchObject([{
    comparisonPath: '/v1/same', authMode: 'unknown',
  }]);
  expect(analyzed.passportFactoryObservation?.operations).toEqual([{
    method: 'GET', comparisonPath: '/v1/same', status: 'observed', authMode: 'unknown',
  }]);
});

test('keeps an unsupported direct factory visible beside a duplicate route without one', async () => {
  const analyzed = await observe(`
    import { Controller, Get, UseGuards } from '@nestjs/common';
    import { AuthGuard } from '@nestjs/passport';
    declare const dynamicStrategy: string;
    @Controller({ path: 'same', version: '1' }) class Dynamic {
      @Get() @UseGuards(AuthGuard(dynamicStrategy)) read() {}
    }
    @Controller({ path: 'same', version: '1' }) class Plain { @Get() read() {} }
  `);
  expect(analyzed.passportFactoryObservation?.callSites).toMatchObject([
    { reason: 'strategy-not-literal' },
  ]);
  expect(analyzed.passportFactoryObservation?.operations).toMatchObject([
    { status: 'unsupported', authMode: analyzed.uriComparison?.contract.operations[0].auth.mode },
  ]);
});

test.each([false, true])('keeps mixed direct factory routes unsupported in either order (%s)', async (reverse) => {
  const observed = `@Controller({ path: 'same', version: '1' }) class Observed {
    @Get() @UseGuards(AuthGuard('jwt')) read() {}
  }`;
  const unsupported = `@Controller({ path: 'same', version: '1' }) class Unsupported {
    @Get() @UseGuards(AuthGuard(dynamicStrategy)) read() {}
  }`;
  const analyzed = await observe(`
    import { Controller, Get, UseGuards } from '@nestjs/common';
    import { AuthGuard } from '@nestjs/passport';
    declare const dynamicStrategy: string;
    ${reverse ? `${unsupported}\n${observed}` : `${observed}\n${unsupported}`}
  `);
  expect(analyzed.passportFactoryObservation?.callSites).toHaveLength(2);
  expect(analyzed.passportFactoryObservation?.associations).toHaveLength(1);
  expect(analyzed.passportFactoryObservation?.operations).toMatchObject([
    { comparisonPath: '/v1/same', status: 'unsupported' },
  ]);
});

test('merges duplicate unversioned routes against the finalized Source operation', async () => {
  const analyzed = await observe(`
    import { Controller, Get, UseGuards } from '@nestjs/common';
    import { AuthGuard } from '@nestjs/passport';
    @Controller('same') class Guarded { @Get() @UseGuards(AuthGuard('jwt')) read() {} }
    @Controller('same') class Plain { @Get() read() {} }
  `, undefined, undefined, 'none');
  if (analyzed.execution.status !== 'success') return;
  const authMode = analyzed.execution.result.contract.operations[0].auth.mode;
  expect(analyzed.passportFactoryObservation?.operations).toMatchObject([
    { comparisonPath: '/same', status: 'observed', authMode },
  ]);
});

test.each([
  ["AuthGuard('jwt')", "function AuthGuard(_name: string) { return {}; }", 'factory-origin-unverified'],
  ["AuthGuard('jwt')", "import { AuthGuard } from './barrel';", 'factory-origin-unverified'],
  ["AuthGuard(runtimeStrategy)", "import { AuthGuard } from '@nestjs/passport'; declare const runtimeStrategy: string;", 'strategy-not-literal'],
  ["AuthGuard()", "import { AuthGuard } from '@nestjs/passport';", 'factory-arguments-unsupported'],
  ["AuthGuard('jwt', 'other')", "import { AuthGuard } from '@nestjs/passport';", 'factory-arguments-unsupported'],
  ["AuthGuard('sk-secretvalue123')", "import { AuthGuard } from '@nestjs/passport';", 'strategy-unsafe'],
  ["Passport.AuthGuard('jwt')", "import * as Passport from '@nestjs/passport'; Passport.AuthGuard = (() => ({})) as any;", 'factory-origin-unverified'],
] as const)('does not trust unsupported Passport input %#', async (guard, declaration, reason) => {
  const analyzed = await observe(`
    import { Controller, Get, UseGuards } from '@nestjs/common';
    ${declaration}
    @Controller({ path: 'items', version: '1' }) class Items { @Get() @UseGuards(${guard}) read() {} }
  `);
  expect(analyzed.passportFactoryObservation?.callSites).toMatchObject([{ reason }]);
  expect(analyzed.passportFactoryObservation?.associations).toEqual([]);
  expect(analyzed.passportFactoryObservation?.operations[0].status).toBe('unsupported');
});

test('does not resolve indirect guard arrays or treat a guard class as a Passport factory', async () => {
  const analyzed = await observe(`
    import { Controller, Get, UseGuards } from '@nestjs/common';
    import { AuthGuard } from '@nestjs/passport';
    class GuardClass {}
    const guards = [AuthGuard('jwt')];
    @Controller({ path: 'items', version: '1' }) class Items {
      @Get() @UseGuards(...guards) spread() {}
      @Get('class') @UseGuards(GuardClass) plain() {}
    }
  `);
  expect(analyzed.passportFactoryObservation?.callSites).toEqual([]);
  expect(analyzed.passportFactoryObservation?.associations).toEqual([]);
  expect(analyzed.passportFactoryObservation?.operations.map(item => item.status).sort())
    .toEqual(['no-direct-factory', 'no-direct-factory']);
});

test('ignores unrelated guard factories and associates a class site with inherited routes', async () => {
  const analyzed = await observe(`
    import { Controller, Get, UseGuards } from '@nestjs/common';
    import { AuthGuard } from '@nestjs/passport';
    function ThrottlerGuard() { return {}; }
    class Base { @Get() list() {} }
    @Controller({ path: 'items', version: '1' })
    @UseGuards(AuthGuard('jwt'))
    class Items extends Base { @Get('other') @UseGuards(ThrottlerGuard()) other() {} }
  `);
  expect(analyzed.passportFactoryObservation?.callSites.map(site => site.strategy)).toEqual(['jwt']);
  expect(analyzed.passportFactoryObservation?.associations.map(item => item.comparisonPath).sort())
    .toEqual(['/v1/items', '/v1/items/other']);
  expect(analyzed.passportFactoryObservation?.operations.every(item => item.status === 'observed'))
    .toBe(true);
});

test('binds the observation digest to the source snapshot', async () => {
  const source = (strategy: string) => `
    import { Controller, Get, UseGuards } from '@nestjs/common';
    import { AuthGuard } from '@nestjs/passport';
    @Controller('items') class Items { @Get() @UseGuards(AuthGuard('${strategy}')) read() {} }
  `;
  const first = await observe(source('jwt'));
  const second = await observe(source('session'));
  expect(first.passportFactoryObservation?.digest).not.toBe(second.passportFactoryObservation?.digest);
});

test('keeps concurrent and cached Passport observations scoped to their inputs', async () => {
  const source = (strategy: string) => `
    import { Controller, Get, UseGuards } from '@nestjs/common';
    import { AuthGuard } from '@nestjs/passport';
    @Controller({ path: 'items', version: '1' })
    class Items { @Get() @UseGuards(AuthGuard('${strategy}')) read() {} }
  `;
  const first = fixture(source('jwt'));
  const second = fixture(source('session'));
  const cache = new TypeScriptAnalysisCache();
  const analyze = (root: string) => runNestJsSourceAnalysisInternal({
    workspaceRoot: root, entrypoints: ['tsconfig.json'],
    limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS }, logger: { log() {} },
  }, undefined, cache, undefined, 'uri');
  const [jwt, session] = await Promise.all([analyze(first.root), analyze(second.root)]);
  expect(jwt.passportFactoryObservation?.callSites[0].strategy).toBe('jwt');
  expect(session.passportFactoryObservation?.callSites[0].strategy).toBe('session');
  expect((await analyze(first.root)).passportFactoryObservation?.digest)
    .toBe(jwt.passportFactoryObservation?.digest);
  fs.writeFileSync(path.join(first.root, 'src/controller.ts'), source('jwt-refresh'));
  const changed = await analyze(first.root);
  expect(changed.passportFactoryObservation?.callSites[0].strategy).toBe('jwt-refresh');
  expect(changed.passportFactoryObservation?.digest).not.toBe(jwt.passportFactoryObservation?.digest);
});

test('binds strategy evidence to changed declarations and cache-scoped inputs', async () => {
  const source = (strategy: string, provider: boolean) => `
    import { Controller, Get, UseGuards, Module } from '@nestjs/common';
    import { AuthGuard, PassportStrategy } from '@nestjs/passport';
    import { Strategy, ExtractJwt } from 'passport-jwt';
    class LocalStrategy extends PassportStrategy(Strategy, '${strategy}') {
      constructor() { super({ jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken() }); }
    }
    @Module({ providers: [${provider ? 'LocalStrategy' : ''}] }) class LocalModule {}
    @Controller({ path: 'items', version: '1' }) @UseGuards(AuthGuard('jwt')) class Items {
      @Get() read() {}
    }
  `;
  const first = fixture(source('jwt', true));
  const second = fixture(source('session', false));
  const cache = new TypeScriptAnalysisCache();
  const analyze = (root: string) => runNestJsSourceAnalysisInternal({
    workspaceRoot: root, entrypoints: ['tsconfig.json'],
    limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS }, logger: { log() {} },
  }, undefined, cache, undefined, 'uri');
  const [one, other] = await Promise.all([analyze(first.root), analyze(second.root)]);
  expect(one.passportStrategyObservation?.matches[0].status).toBe('one');
  expect(other.passportStrategyObservation?.matches[0].status).toBe('none');
  expect((await analyze(first.root)).passportStrategyObservation?.digest)
    .toBe(one.passportStrategyObservation?.digest);
  fs.writeFileSync(path.join(first.root, 'src/controller.ts'), source('jwt', false));
  const changed = await analyze(first.root);
  expect(changed.passportStrategyObservation?.providers).toEqual([]);
  expect(changed.passportStrategyObservation?.digest).not.toBe(one.passportStrategyObservation?.digest);
  expect(changed.passportStrategyObservation?.factoryDigest)
    .toBe(changed.passportFactoryObservation?.digest);
});

test('does not publish Passport evidence after cancellation or an operation limit', async () => {
  const { root } = fixture(`
    import { Controller, Get, UseGuards } from '@nestjs/common';
    import { AuthGuard } from '@nestjs/passport';
    @Controller({ path: 'items', version: '1' })
    @UseGuards(AuthGuard('jwt')) class Items { @Get() one() {} @Get('two') two() {} }
  `);
  const cancelled = new AbortController();
  cancelled.abort();
  const base = { workspaceRoot: root, entrypoints: ['tsconfig.json'],
    limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS }, logger: { log() {} } };
  const originalEntrypoints = [...base.entrypoints];
  const interrupted = await runNestJsSourceAnalysisInternal({
    ...base, cancellationSignal: cancelled.signal,
  }, undefined, undefined, undefined, 'uri');
  expect(interrupted.execution.status).toBe('failed');
  expect(interrupted.passportFactoryObservation).toBeUndefined();
  expect(interrupted.passportStrategyObservation).toBeUndefined();
  const limited = await runNestJsSourceAnalysisInternal({
    ...base, limits: { ...base.limits, maxOperations: 1 },
  }, undefined, undefined, undefined, 'uri');
  expect(limited.execution.status).toBe('failed');
  expect(limited.passportFactoryObservation).toBeUndefined();
  expect(limited.passportStrategyObservation).toBeUndefined();
  expect(base.entrypoints).toEqual(originalEntrypoints);
});
