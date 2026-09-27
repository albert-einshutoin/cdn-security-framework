import fs from 'node:fs';
import path from 'node:path';
import cp from 'node:child_process';
import { describe, expect, test } from 'vitest';

const root = path.join(process.cwd(), 'test/pilot/brocoders');
const expected = JSON.parse(fs.readFileSync(path.join(root, 'expectations.json'), 'utf8'));
const cases = JSON.parse(fs.readFileSync(path.join(root, 'cases.json'), 'utf8'));
const { verifyArchive, mutate, assertPassportObservation, assertStrategyObservation } = require('./pilot.cjs');
const passport = JSON.parse(fs.readFileSync(path.join(root, 'passport-expectations.json'), 'utf8'));
const strategy = JSON.parse(fs.readFileSync(path.join(root, 'strategy-expectations.json'), 'utf8'));
const archive = path.join(root, 'source.tar.gz');
const sourceLines = (name: string): string[] => cp.execFileSync('tar', ['-xOzf', archive, name],
  { encoding: 'utf8' }).split('\n');

const controllerLines: Record<string, string[]> = Object.fromEntries(
  ['src/auth/auth.controller.ts', 'src/users/users.controller.ts'].map(name =>
    [name, sourceLines(name)]),
);

describe('fixed brocoders technical Pilot inputs', () => {
  test('keeps the reviewed snapshot and all 16 code-anchored operation expectations', () => {
    expect(() => verifyArchive()).not.toThrow();
    expect(expected.operations).toHaveLength(16);
    expect(expected.operations.filter((op: any) => op.controllerPath === 'auth')).toHaveLength(11);
    expect(expected.operations.filter((op: any) => op.controllerPath === 'users')).toHaveLength(5);
    for (const op of expected.operations) {
      const lines = controllerLines[op.source];
      expect(lines[op.line - 1]).toMatch(new RegExp(`@${op.method[0]}${op.method.slice(1).toLowerCase()}\\(`));
      expect(op.uriNoPrefixPath).toBe(`/v1${op.localPath.replace(':id', '{id}')}`);
      expect(op.uriApiPrefixPath).toBe(`/api${op.uriNoPrefixPath}`);
      expect(lines[Number(op.versionOrigin.split(':').pop()) - 1]).toContain("version: '1'");
      if (op.guardSyntax) {
        const guardLine = lines[Number(op.guardOrigin.split(':').pop()) - 1];
        for (const guard of op.guardSyntax.split(' + ')) expect(guardLine).toContain(guard);
      }
      if (op.swaggerBearer) expect(lines[Number(op.swaggerOrigin.split(':').pop()) - 1]).toContain('@ApiBearerAuth');
    }
  });

  test('evaluation declarations cover precisely the scored method and path pairs', () => {
    for (const label of ['api', 'no-prefix']) {
      const openapi = JSON.parse(fs.readFileSync(path.join(root, `openapi-${label}.json`), 'utf8'));
      const actual = Object.entries(openapi.paths).flatMap(([route, methods]) =>
        Object.keys(methods as object).map(method => `${method.toUpperCase()} ${route}`)).sort();
      const wanted = expected.operations.map((op: any) =>
        `${op.method} ${label === 'api' ? op.uriApiPrefixPath : op.uriNoPrefixPath}`).sort();
      expect(actual).toEqual(wanted);
    }
    expect(cases.cases.map((item: any) => item.group).filter((group: string) => group === 'R05'))
      .toHaveLength(5);
  });

  test('controlled mutations affect one intended evaluation input each', () => {
    const base = JSON.parse(fs.readFileSync(path.join(root, 'openapi-api.json'), 'utf8'));
    const policy = fs.readFileSync(path.join(root, 'policy-api.yml'), 'utf8');
    const sourceOnly = mutate('source-only', structuredClone(base), policy);
    expect(sourceOnly.openapi.paths['/api/v1/auth/email/login']).toBeUndefined();
    expect(sourceOnly.openapi.paths['/api/v1/auth/me'].get).toBeDefined();
    const wrongVersion = mutate('wrong-version', structuredClone(base), policy);
    expect(wrongVersion.openapi.paths['/api/v1/auth/me'].get).toBeUndefined();
    expect(wrongVersion.openapi.paths['/api/v2/auth/me'].get).toBeDefined();
    const route = mutate('policy-route', structuredClone(base), policy);
    expect(route.policy).toContain('/api/v1/evaluation-only-policy');
    expect(route.policy).toContain('exact_path: true');
    expect(route.openapi).toEqual(base);
  });

  test('Passport Pilot rejects missing sites, swapped routes, wrong strategies and auth promotion', () => {
    const callSites = passport.callSites.map((site: any, index: number) => ({
      id: `site-${index}`, sourceUri: `source/${site.source}`, line: site.line,
      scope: site.scope, strategy: site.strategy, module: '@nestjs/passport', export: 'AuthGuard',
    }));
    const associations = passport.callSites.flatMap((site: any, index: number) =>
      site.operations.map((key: string) => {
        const [method, prefixedPath] = key.split(' ');
        const comparisonPath = prefixedPath.replace(/^\/api/, '');
        const op = expected.operations.find((item: any) => item.method === method
          && item.uriNoPrefixPath === comparisonPath);
        return { callSiteId: `site-${index}`, method, comparisonPath,
          localPath: op.localPath.replace(':id', '{id}'), authMode: 'unknown' };
      }));
    const operations = expected.operations.map((op: any) => ({
      method: op.method, comparisonPath: op.uriNoPrefixPath,
      status: op.guardSyntax ? 'observed' : 'no-direct-factory', authMode: 'unknown',
    }));
    const observation = { observer: 'nestjs-passport-direct-factory@1',
      digest: `sha256:${'a'.repeat(64)}`, callSites, associations, operations };
    expect(assertPassportObservation(observation).summary).toMatchObject({
      callSites: 6, operationAssociations: 10, noDirectOperations: 6, authUnknown: 16,
      strategyAssociations: { jwt: 9, 'jwt-refresh': 1 },
    });
    const changed = (edit: (value: any) => void) => {
      const value = structuredClone(observation);
      edit(value);
      expect(() => assertPassportObservation(value)).toThrow();
    };
    changed(value => value.associations.pop());
    changed(value => { value.associations[0].comparisonPath = '/v1/auth/logout'; });
    changed(value => { value.callSites[0].strategy = 'local'; });
    changed(value => { value.operations[0].authMode = 'alternatives'; });
  });

  test('strategy expectations are fixed to the archive before product analysis', () => {
    const moduleSource = sourceLines('src/auth/auth.module.ts');
    for (const item of strategy.definitions) {
      const lines = sourceLines(item.source);
      expect(lines[item.line - 1]).toContain(`class ${item.className} extends PassportStrategy(`);
      expect(lines.join('\n')).toContain(`'${item.strategy}'`);
      expect(lines[item.extractorLine - 1]).toContain('ExtractJwt.fromAuthHeaderAsBearerToken()');
      expect(moduleSource[item.providerLine - 1]).toContain(item.className);
    }
    expect(strategy.expected).toMatchObject({ definitions: 2, extractorCalls: 2,
      providerEntries: 2, callSites: 6, operationAssociations: 10,
      authUnknown: 16, routeTP: 16, controlledFindingTP: 7 });
  });

  test('strategy Pilot rejects swapped class, wrong provider, and Bearer promotion', () => {
    const definitions = strategy.definitions.map((item: any, index: number) => ({
      id: `definition-${index}`, strategy: item.strategy, className: item.className,
      sourceUri: `source/${item.source}`, line: item.line, baseStatus: 'verified',
      baseModule: item.baseModule, extractor: { status: 'observed', kind: item.extractor,
        sourceUri: `source/${item.extractorSource}`, line: item.extractorLine },
    }));
    const providers = strategy.definitions.map((item: any, index: number) => ({
      definitionId: definitions[index].id, moduleClass: item.providerModule,
      sourceUri: `source/${item.providerSource}`, line: item.providerLine,
    }));
    const callSites = passport.callSites.map((item: any, index: number) => ({
      id: `site-${index}`, strategy: item.strategy,
    }));
    const associations = passport.callSites.flatMap((item: any, index: number) =>
      item.operations.map((key: string) => {
        const [method, prefixedPath] = key.split(' ');
        return { callSiteId: `site-${index}`, method,
          comparisonPath: prefixedPath.replace(/^\/api/, ''), authMode: 'unknown' };
      }));
    callSites.push({ id: 'site-outside', strategy: 'jwt' });
    associations.push({ callSiteId: 'site-outside', method: 'GET',
      comparisonPath: '/outside', authMode: 'unknown' });
    const factory = { digest: `sha256:${'a'.repeat(64)}`, callSites, associations };
    const links = { observer: 'nestjs-passport-static-strategy-link@1',
      digest: `sha256:${'b'.repeat(64)}`, factoryDigest: factory.digest,
      definitions, providers, matches: callSites.map((site: any) => ({
        callSiteId: site.id, strategy: site.strategy, status: 'one',
        candidateIds: [definitions.find((item: any) => item.strategy === site.strategy).id],
      })) };
    expect(assertStrategyObservation(links, factory)).toMatchObject({
      definitions: 2, extractorCalls: 2, providerEntries: 2,
      callSites: 6, operationAssociations: 10,
      strategyAssociations: { jwt: 9, 'jwt-refresh': 1 },
    });
    const changed = (edit: (links: any, factory: any) => void) => {
      const value = structuredClone(links);
      const observed = structuredClone(factory);
      edit(value, observed);
      expect(() => assertStrategyObservation(value, observed)).toThrow();
    };
    changed(value => { value.matches[0].candidateIds = [definitions[1].id]; });
    changed(value => { value.providers[0].definitionId = definitions[1].id; });
    changed(value => { value.definitions[0].extractor.status = 'unconfirmed'; });
    changed((_value, observed) => { observed.associations[0].authMode = 'alternatives'; });
  });
});
