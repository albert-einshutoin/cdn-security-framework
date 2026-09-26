import { createRequire } from 'node:module';
import { describe, expect, test } from 'vitest';

const require = createRequire(import.meta.url);
const runner = require('./pilot/realworld/pilot.cjs') as {
  mutate: (name: string, openapi: any, policy: string, auth: any) =>
    { openapi: any; policy: string; auth: any };
  ruleCounts: (report: any) => Record<string, number>;
  checkExpectedCounts: (actual: Record<string, number>, expected: Record<string, number>) => void;
  verifyFindingTargets: (scenario: any, report: any) => void;
  verifyArchive: () => void;
};
const expectations = require('./pilot/realworld/expectations.json');
const cases = require('./pilot/realworld/cases.json');
const prefixCases = require('./pilot/realworld/prefix-cases.json');
const originalOpenApi = require('./pilot/realworld/openapi-evaluation.json');
const prefixedOpenApi = require('./pilot/realworld/openapi-prefixed-evaluation.json');
const originalAuth = require('./pilot/realworld/auth-evaluation.json');
const originalPolicy = 'GET, POST, PUT, DELETE';

describe('fixed public NestJS Pilot harness', () => {
  test('keeps P01 unchanged and declares P02-P05 against the fixed /api path domain', () => {
    expect(cases.cases).toHaveLength(7);
    expect(prefixCases.cases.map((entry: { name: string }) => entry.name)).toEqual([
      'P02-correct-prefix', 'P03-omitted-prefix', 'P04-wrong-prefix', 'P05-controlled-drift',
    ]);
    expect(prefixCases.cases.map((entry: { prefix: string | null }) => entry.prefix))
      .toEqual(['/api', null, '/wrong', '/api']);
    for (const operation of expectations.scope.operations) {
      expect(prefixedOpenApi.paths[`/api${operation.path}`]?.[operation.method.toLowerCase()]).toBeDefined();
    }
    const mutated = runner.mutate('controlled-prefix-drift', structuredClone(prefixedOpenApi),
      require('node:fs').readFileSync('test/pilot/realworld/policy-prefixed-evaluation.yml', 'utf8'),
      structuredClone(originalAuth));
    expect(mutated.openapi.paths['/api/articles/feed']).toHaveProperty('post');
    expect(mutated.openapi.paths).not.toHaveProperty('/api/profiles/{username}');
    expect(mutated.policy).not.toContain('DELETE');
  });

  test('keeps one fixed source snapshot and a prior independent scope', () => {
    runner.verifyArchive();
    expect(expectations.scope.operations).toHaveLength(19);
    expect(expectations.scope.evaluationOut).toHaveLength(2);
    const routes = expectations.scope.operations.map((op: { method: string; path: string }) => `${op.method} ${op.path}`);
    expect(new Set(routes).size).toBe(19);
    expect(cases.cases.map((entry: { name: string }) => entry.name)).toEqual([
      'baseline', 'method-mismatch', 'source-only', 'declared-only',
      'declared-auth-vs-policy', 'policy-method-block', 'auth-unknown-control',
    ]);
  });

  test('mutates only the evaluation contracts needed for each case', () => {
    const baseline = JSON.stringify(originalOpenApi);
    const input = () => ({ openapi: structuredClone(originalOpenApi),
      policy: originalPolicy, auth: structuredClone(originalAuth) });
    const mutated = (change: string) => {
      const { openapi, policy, auth } = input();
      return runner.mutate(change, openapi, policy, auth);
    };
    const method = mutated('method-mismatch');
    expect(method.openapi.paths['/articles/feed']).toHaveProperty('post');
    expect(method.openapi.paths['/articles/feed']).not.toHaveProperty('get');
    const sourceOnly = mutated('source-only');
    expect(sourceOnly.openapi.paths).not.toHaveProperty('/articles/feed');
    const declared = mutated('declared-only');
    expect(declared.openapi.paths).toHaveProperty('/not-implemented');
    const auth = mutated('declared-auth-vs-policy');
    expect(auth.openapi.paths['/user'].get.security).toEqual([{ BearerAuth: [] }]);
    const policy = mutated('policy-method-block');
    expect(policy.policy).not.toContain('DELETE');
    const unknown = mutated('auth-unknown-control');
    expect(unknown.auth.guard_mappings.JwtAuthGuard).toEqual({ auth_kind: 'bearer' });
    expect(JSON.stringify(originalOpenApi)).toBe(baseline);
  });

  test('fails on a missing expected finding rather than counting a successful process', () => {
    const actual = runner.ruleCounts({ version: '2.1.0', runs: [{ results: [
      { ruleId: 'SC-INVENTORY-001' }, { ruleId: 'SC-INVENTORY-001' },
    ] }] });
    expect(actual).toEqual({ 'SC-INVENTORY-001': 2 });
    expect(() => runner.checkExpectedCounts(actual, { 'SC-INVENTORY-004': 1 })).toThrow();
    expect(() => runner.checkExpectedCounts(actual, cases.baseline)).not.toThrow();
  });

  test('fails when the right rule count points to the wrong route', () => {
    const sourceLocation = (source: string, line: number) => ({
      physicalLocation: { artifactLocation: { uri: `source/${source}` }, region: { startLine: line } },
    });
    const baseline = expectations.scope.evaluationOut.map((op: { source: string; line: number }) => ({
      ruleId: 'SC-INVENTORY-001', locations: [sourceLocation(op.source, op.line)],
    }));
    const method = cases.cases.find((entry: { name: string }) => entry.name === 'method-mismatch');
    const wrong = { ruleId: 'SC-INVENTORY-004',
      locations: [sourceLocation('src/user/user.controller.ts', 21), {
        physicalLocation: { artifactLocation: { uri: 'evaluation/method-mismatch/openapi.json' } },
        logicalLocations: [{ fullyQualifiedName: '/paths/~1articles~1feed/post' }],
      }] };
    expect(() => runner.verifyFindingTargets(method, { runs: [{ results: [...baseline, wrong] }] })).toThrow();
    const right = { ...wrong, locations: [sourceLocation('src/article/article.controller.ts', 33),
      wrong.locations[1]] };
    expect(() => runner.verifyFindingTargets(method, { runs: [{ results: [...baseline, right] }] })).not.toThrow();
  });
});
