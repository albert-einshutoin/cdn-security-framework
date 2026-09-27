import fs from 'node:fs';
import path from 'node:path';
import cp from 'node:child_process';
import { describe, expect, test } from 'vitest';

const root = path.join(process.cwd(), 'test/pilot/brocoders');
const expected = JSON.parse(fs.readFileSync(path.join(root, 'expectations.json'), 'utf8'));
const cases = JSON.parse(fs.readFileSync(path.join(root, 'cases.json'), 'utf8'));
const { verifyArchive, mutate } = require('./pilot.cjs');
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
});
