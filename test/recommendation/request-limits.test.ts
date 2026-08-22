import { describe, expect, test } from 'vitest';

import type { SecurityContractV1, ValueConstraintsV1 } from '../../src/contract';
import {
  applySafetyMargin,
  recommendRequestLimits,
} from '../../src/recommendation/request-limits';

const evidence = {
  source: 'openapi' as const,
  uri: 'openapi.yaml',
  pointer: '/paths/~1items~1{id}/post',
  digest: 'sha256:test',
  analyzer: 'openapi-test',
  capability: 'openapi-operations-v1',
  complete: true,
};

function contract(body?: ValueConstraintsV1): SecurityContractV1 {
  return {
    schemaVersion: 1,
    source: 'openapi',
    capabilities: {
      routes: 'complete', parameters: 'complete', requestBodies: 'complete', authentication: 'complete',
    },
    operations: [{
      routeKey: 'POST /items/{id}',
      method: 'POST',
      path: '/items/{id}',
      exposure: 'public',
      auth: { mode: 'none', alternatives: [] },
      request: {
        contentTypes: body ? ['application/json'] : [],
        requiredHeaders: ['x-tenant'],
        queryParameters: [
          { name: 'a', required: true, constraints: { type: 'string', maxLength: 2 }, unsupportedReasons: [] },
          { name: 'optional', required: false, constraints: { type: 'boolean' }, unsupportedReasons: [] },
          { name: '検索', required: false, constraints: { type: 'string', maxLength: 1 }, unsupportedReasons: [] },
        ],
        pathParameters: [{
          name: 'id', required: true, constraints: { type: 'string', maxLength: 2 }, unsupportedReasons: [],
        }],
        headerParameters: [],
        cookieParameters: [],
        ...(body ? { body: { required: true, constraints: body, unsupportedReasons: [] } } : {}),
      },
      provenance: [evidence],
    }],
  };
}

describe('request limit recommendations', () => {
  test('includes optional query values, names, separators, and worst-case URL encoding', () => {
    const [route] = recommendRequestLimits(contract(), { margin: { absolute: 0, ratio: 0 } }).routes;
    const operation = route.operations[0];

    expect(route.allowedMethods.value).toEqual(['POST']);
    expect(operation.requiredHeaders.value).toEqual(['x-tenant']);
    expect(operation.maxQueryParams.value).toBe(3);
    expect(operation.maxQueryLength.value).toBe(91);
    expect(operation.maxUriLength.value).toBe(41);
    expect(operation.maxQueryLength).toMatchObject({
      estimateKind: 'upper-bound',
      basis: ['/paths/~1items~1{id}/post'],
      unsupportedReasons: [],
    });

    const unicodePath = contract();
    unicodePath.operations[0].path = '/検索/{id}';
    unicodePath.operations[0].routeKey = 'POST /検索/{id}';
    expect(recommendRequestLimits(unicodePath, { margin: { absolute: 0, ratio: 0 } })
      .routes[0].operations[0].maxUriLength.value).toBe(44);

    const repeated = contract();
    repeated.operations[0].path = '/items/{id}/{id}';
    repeated.operations[0].routeKey = 'POST /items/{id}/{id}';
    expect(recommendRequestLimits(repeated, { margin: { absolute: 0, ratio: 0 } })
      .routes[0].operations[0].maxUriLength.value).toBe(66);
  });

  test('estimates fixed JSON objects and bounded arrays but not unbounded shapes', () => {
    const fixedObject: ValueConstraintsV1 = {
      type: 'object',
      additionalProperties: false,
      requiredProperties: ['name'],
      properties: {
        active: { type: 'boolean' },
        name: { type: 'string', maxLength: 2 },
      },
    };
    expect(recommendRequestLimits(contract(fixedObject), { margin: { absolute: 0, ratio: 0 } })
      .routes[0].operations[0].maxBodyBytes.value).toBe(160);

    const boundedArray: ValueConstraintsV1 = {
      type: 'array', maxItems: 3, items: { type: 'boolean' },
    };
    expect(recommendRequestLimits(contract(boundedArray), { margin: { absolute: 0, ratio: 0 } })
      .routes[0].operations[0].maxBodyBytes.value).toBe(19);

    const unknown = recommendRequestLimits(contract({ type: 'array', items: { type: 'boolean' } }))
      .routes[0].operations[0].maxBodyBytes;
    expect(unknown.value).toBeNull();
    expect(unknown.estimateKind).toBe('unknown');
    expect(unknown.unsupportedReasons).toContain('body:unbounded-array');
  });

  test('keeps unbounded paths unknown and validates margin inputs and overflow', () => {
    const input = contract();
    input.operations[0].request.pathParameters[0].constraints = { type: 'string' };
    expect(recommendRequestLimits(input).routes[0].operations[0].maxUriLength)
      .toMatchObject({ value: null, estimateKind: 'unknown' });

    expect(applySafetyMargin(100, { absolute: 10, ratio: 0.1 })).toEqual({
      absolute: 10, ratio: 0.1, before: 100, after: 120,
    });
    expect(() => applySafetyMargin(1, { absolute: -1 })).toThrow('invalid safety margin');
    expect(() => applySafetyMargin(1, { ratio: 11 })).toThrow('invalid safety margin');
    expect(() => applySafetyMargin(Number.MAX_SAFE_INTEGER, { ratio: 1 })).toThrow('safety margin overflow');

    const oversized = contract({ type: 'string', maxLength: Number.MAX_SAFE_INTEGER });
    expect(() => recommendRequestLimits(oversized)).not.toThrow();
    expect(recommendRequestLimits(oversized).routes[0].operations[0].maxBodyBytes.value).toBeNull();
  });

  test('returns unknown for composed schemas and multipart uploads without throwing', () => {
    const composed = contract({ type: 'unknown' });
    composed.operations[0].request.body!.unsupportedReasons = ['schema:oneOf'];
    expect(recommendRequestLimits(composed).routes[0].operations[0].maxBodyBytes)
      .toMatchObject({ value: null, estimateKind: 'unknown', unsupportedReasons: ['schema:oneOf'] });

    const multipart = contract({ type: 'string', maxLength: 10 });
    multipart.operations[0].request.contentTypes = ['multipart/form-data'];
    expect(recommendRequestLimits(multipart).routes[0].operations[0].maxBodyBytes)
      .toMatchObject({ value: null, estimateKind: 'unknown', unsupportedReasons: ['body:multipart'] });

    const exploded = contract();
    exploded.operations[0].request.queryParameters.push({
      name: 'tags', required: false,
      constraints: { type: 'array', maxItems: 4, items: { type: 'string', maxLength: 2 } },
      unsupportedReasons: [],
    });
    expect(recommendRequestLimits(exploded, { margin: { absolute: 0, ratio: 0 } })
      .routes[0].operations[0].maxQueryParams.value).toBe(7);
    exploded.operations[0].request.queryParameters[3].constraints.maxItems = undefined;
    expect(recommendRequestLimits(exploded).routes[0].operations[0].maxQueryParams.value).toBeNull();
  });

  test('keeps the complete candidate calculation stable', async () => {
    const result = recommendRequestLimits(contract({
      type: 'object',
      additionalProperties: false,
      properties: { name: { type: 'string', maxLength: 2 } },
    }), { margin: { absolute: 0, ratio: 0 } });
    await expect(`${JSON.stringify(result, null, 2)}\n`).toMatchFileSnapshot(
      '../fixtures/recommendation/expected/request-limits.json',
    );
  });
});
