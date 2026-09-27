import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, expect, test } from 'vitest';

import { DEFAULT_SOURCE_ANALYSIS_LIMITS } from '../../src/source-analysis';
import { runNestJsSourceAnalysisInternal } from '../../src/source/nestjs/analyzer';
import { TypeScriptAnalysisCache } from '../../src/source/typescript/project-loader';

const roots: string[] = [];

function fixture(source: string): { root: string; sentinel: string } {
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
  write('node_modules/@nestjs/common/package.json', JSON.stringify({
    name: '@nestjs/common', version: '11.1.18', main: 'index.js', types: 'index.d.ts',
  }));
  write('node_modules/@nestjs/common/index.js', 'module.exports = {};');
  write('node_modules/@nestjs/common/index.d.ts', `
    export declare function Controller(path?: string | { path: string; version?: string }): ClassDecorator;
    export declare function Get(path?: string): MethodDecorator;
    export declare function UseGuards(...guards: unknown[]): ClassDecorator & MethodDecorator;
  `);
  write('node_modules/@nestjs/passport/package.json', JSON.stringify({
    name: '@nestjs/passport', version: '11.0.5', main: 'index.js', types: 'index.d.ts',
  }));
  write('node_modules/@nestjs/passport/index.d.ts', 'export declare function AuthGuard(strategy: string): unknown;');
  const sentinel = path.join(root, 'executed');
  write('node_modules/@nestjs/passport/index.js', `require('node:fs').writeFileSync(${JSON.stringify(sentinel)}, 'bad');`);
  return { root, sentinel };
}

async function observe(source: string) {
  const { root, sentinel } = fixture(source);
  const analyzed = await runNestJsSourceAnalysisInternal({
    workspaceRoot: root, entrypoints: ['tsconfig.json'],
    limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS }, logger: { log() {} },
  }, undefined, undefined, undefined, 'uri');
  expect(analyzed.execution.status).toBe('success');
  expect(fs.existsSync(sentinel)).toBe(false);
  return analyzed;
}

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
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
  const limited = await runNestJsSourceAnalysisInternal({
    ...base, limits: { ...base.limits, maxOperations: 1 },
  }, undefined, undefined, undefined, 'uri');
  expect(limited.execution.status).toBe('failed');
  expect(limited.passportFactoryObservation).toBeUndefined();
  expect(base.entrypoints).toEqual(originalEntrypoints);
});
