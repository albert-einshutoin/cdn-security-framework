import { describe, expect, test } from 'vitest';

import { createSecurityContract } from '../../src/contract/security-ir';
import { normalizeSourceGlobalPrefix, prefixSourceContract } from '../../src/contract/source-global-prefix';

const evidence = { source: 'source-ast' as const, uri: 'src/controller.ts',
  digest: `sha256:${'a'.repeat(64)}`, analyzer: 'nestjs@1', capability: 'nestjs-routes-v1', complete: false };
const request = { contentTypes: [], requiredHeaders: [], queryParameters: [],
  pathParameters: [], headerParameters: [], cookieParameters: [] };

function contract(paths: string[]) {
  return createSecurityContract({ source: 'source-ast',
    capabilities: { routes: 'partial', parameters: 'partial', requestBodies: 'partial', authentication: 'partial' },
    operations: paths.map((route, index) => ({ method: index === 0 ? 'GET' : 'POST',
      path: route, exposure: 'unknown' as const, auth: { mode: 'unknown' as const, alternatives: [] },
      request, provenance: [evidence] })),
  });
}

describe('explicit Source comparison prefix', () => {
  test('accepts only bounded fixed segments and preserves case', () => {
    expect(normalizeSourceGlobalPrefix('api')).toBe('/api');
    expect(normalizeSourceGlobalPrefix('/api/v1')).toBe('/api/v1');
    expect(normalizeSourceGlobalPrefix('API')).toBe('/API');
    expect(normalizeSourceGlobalPrefix('a'.repeat(255))).toBe(`/${'a'.repeat(255)}`);
    for (const invalid of ['', '/', '/api/', '//api', 'api//v1', 'https://host/api',
      'api?x', 'api#x', 'api\\v1', 'api\n', '.', '..', 'a.b', 'api%2f', 'api/*',
      'api/:id', 'api/{id}', 'api name', 'sk-opaquevalue123', 'a'.repeat(256)]) {
      expect(() => normalizeSourceGlobalPrefix(invalid), invalid).toThrow();
    }
  });

  test('transforms one comparison copy and keeps route keys, provenance and input intact', () => {
    const source = contract(['/', '/articles/{slug}', '/api/items']);
    const before = JSON.stringify(source);
    const copy = prefixSourceContract(source, '/api');
    expect(copy.operations.map(({ routeKey }) => routeKey)).toEqual([
      'GET /api', 'POST /api/api/items', 'POST /api/articles/{slug}',
    ]);
    expect(copy.operations.map(({ path }) => path)).toEqual(['/api', '/api/api/items', '/api/articles/{slug}']);
    expect(copy.operations[0].provenance).toEqual(source.operations[0].provenance);
    expect(copy.capabilities).toEqual(source.capabilities);
    expect(JSON.stringify(source)).toBe(before);
    expect(prefixSourceContract(source, '/API').operations[0].routeKey).toBe('GET /API');
  });

  test('fails closed on a transformed route over the canonical route limit', () => {
    const source = contract([`/${'a'.repeat(16_380)}`]);
    expect(() => prefixSourceContract(source, '/api')).toThrow();
  });
});
