import fs from 'node:fs';
import path from 'node:path';
import Ajv from 'ajv';
import { describe, expect, test } from 'vitest';

import {
  createSecurityContract,
  serializeSecurityContract,
  type ApiOperationContractV1,
  type SecurityContractInputV1,
  type ValueConstraintsV1,
} from '../../src/contract/security-ir';
import {
  canonicalizePath,
  createRouteKey,
  normalizeHttpMethod,
} from '../../src/contract/canonical-route';

const evidence = {
  source: 'openapi' as const,
  uri: 'spec/openapi.yaml',
  pointer: '/paths/~1users/get',
  digest: 'sha256:openapi',
  analyzer: 'openapi@1',
  capability: 'openapi-operations-v1',
  complete: true,
};

function operation(
  method: string,
  routePath: string,
  overrides: Partial<ApiOperationContractV1> = {},
): ApiOperationContractV1 {
  return {
    routeKey: `${method.toUpperCase()} ${routePath}`,
    method: method.toUpperCase() as ApiOperationContractV1['method'],
    path: routePath,
    exposure: 'unknown',
    auth: { mode: 'unknown', alternatives: [] },
    request: {
      contentTypes: [],
      requiredHeaders: [],
      queryParameters: [],
      pathParameters: [],
      headerParameters: [],
      cookieParameters: [],
    },
    provenance: [evidence],
    ...overrides,
  };
}

const baseInput: SecurityContractInputV1 = {
  source: 'openapi',
  capabilities: {
    routes: 'complete',
    parameters: 'complete',
    requestBodies: 'partial',
    authentication: 'unsupported',
  },
  operations: [
    operation('post', '/users', {
      exposure: 'public',
      auth: { mode: 'none', alternatives: [] },
      request: {
        contentTypes: ['Application/JSON; charset=utf-8', 'application/json'],
        requiredHeaders: ['X-Tenant-ID', 'x-tenant-id'],
        queryParameters: [{
          name: 'page',
          required: false,
          constraints: { type: 'integer', minimum: 1, maximum: 100 },
          unsupportedReasons: [],
        }],
        pathParameters: [],
        headerParameters: [],
        cookieParameters: [],
        body: {
          required: true,
          constraints: { type: 'object', maxProperties: 20 },
          unsupportedReasons: [],
        },
      },
      metadata: { deprecated: false, tags: ['users', 'write', 'users'] },
    }),
    operation('get', '/users//{id}', {
      operationId: 'getUser',
      request: {
        contentTypes: [],
        requiredHeaders: [],
        queryParameters: [],
        pathParameters: [{
          name: 'id',
          required: true,
          constraints: { type: 'string', minLength: 1, maxLength: 64 },
          unsupportedReasons: [],
        }],
        headerParameters: [],
        cookieParameters: [],
      },
    }),
  ],
};

describe('Security IR canonical routes', () => {
  test('normalizes known methods and paths without losing template names', () => {
    expect(normalizeHttpMethod('get')).toBe('GET');
    expect(canonicalizePath('users//{userId}')).toBe('/users/{userId}');
    expect(createRouteKey('get', 'users//{userId}')).toBe('GET /users/{userId}');
  });

  test('rejects unknown methods, query strings, and dot segments', () => {
    expect(() => normalizeHttpMethod('FETCH')).toThrow('unknown HTTP method');
    expect(() => canonicalizePath('/users?admin=true')).toThrow('invalid route path');
    expect(() => canonicalizePath('/users/../admin')).toThrow('invalid route path');
    expect(() => canonicalizePath('/%2e%2e/admin')).toThrow('invalid route path');
    expect(() => canonicalizePath('/admin%2Fsettings')).toThrow('invalid route path');
    expect(() => canonicalizePath('x'.repeat(16_384))).toThrow('invalid route path');
  });
});

describe('Security IR v1', () => {
  test('normalizes invariants and produces a JSON-Schema-valid contract', () => {
    const contract = createSecurityContract(baseInput);
    const schema = JSON.parse(fs.readFileSync(
      path.join(process.cwd(), 'schemas/security-ir-v1.schema.json'),
      'utf8',
    ));
    const validate = new Ajv({ allErrors: true }).compile(schema);

    expect(validate(contract), JSON.stringify(validate.errors)).toBe(true);
    expect(contract.operations.map(({ routeKey }) => routeKey)).toEqual([
      'GET /users/{id}',
      'POST /users',
    ]);
    expect(contract.operations[1].request.contentTypes).toEqual(['application/json']);
    expect(contract.operations[1].request.requiredHeaders).toEqual(['x-tenant-id']);
    expect(contract.operations[1].metadata?.tags).toEqual(['users', 'write']);
  });

  test('keeps unknown distinct from explicitly public and rejects duplicate routes', () => {
    const contract = createSecurityContract(baseInput);
    expect(contract.operations[0]).toMatchObject({
      exposure: 'unknown',
      auth: { mode: 'unknown' },
    });
    expect(contract.operations[1]).toMatchObject({
      exposure: 'public',
      auth: { mode: 'none' },
    });

    expect(() => createSecurityContract({
      ...baseInput,
      operations: [operation('get', '/users'), operation('GET', '/users')],
    })).toThrow('duplicate route');

    expect(() => createSecurityContract({
      ...baseInput,
      operations: [operation('get', '/users', { exposure: 'public' })],
    })).toThrow('authentication and exposure are inconsistent');

    const anonymousOrBearer = operation('get', '/optional-auth', {
      exposure: 'public',
      auth: {
        mode: 'alternatives',
        alternatives: [
          { anonymous: true, schemes: [] },
          {
            anonymous: false,
            schemes: [{ name: 'bearerAuth', kind: 'bearer', scopes: [], capability: 'supported' }],
          },
        ],
      },
    });
    expect(createSecurityContract({ ...baseInput, operations: [anonymousOrBearer] })
      .operations[0].auth.alternatives).toHaveLength(2);
  });

  test('preserves Guard execution order and validates source auth analysis', () => {
    const input = structuredClone(baseInput);
    input.operations[0].auth.analysis = {
      guards: [
        { symbol: 'JwtAuthGuard', authKind: 'bearer' },
        { symbol: 'ApiKeyGuard', authKind: 'api-key' },
      ],
      explicitPublic: true,
      roles: ['ops', 'admin', 'ops'],
      enforcementConfidence: 'high',
      capabilityReasons: [],
    };
    const contract = createSecurityContract(input);
    expect(contract.operations.find(({ routeKey }) => routeKey === 'POST /users')?.auth.analysis).toEqual({
      guards: [
        { symbol: 'JwtAuthGuard', authKind: 'bearer' },
        { symbol: 'ApiKeyGuard', authKind: 'api-key' },
      ],
      explicitPublic: true,
      roles: ['admin', 'ops'],
      enforcementConfidence: 'high',
      capabilityReasons: [],
    });

    const invalidKind = structuredClone(input) as any;
    invalidKind.operations[0].auth.analysis.guards[0].authKind = 'jwt';
    expect(() => createSecurityContract(invalidKind)).toThrow('invalid authentication guard analysis');
    const secretRole = structuredClone(input);
    secretRole.operations[0].auth.analysis!.roles = ['secret=do-not-emit'];
    expect(() => createSecurityContract(secretRole)).toThrow('secret-like value is not allowed');
  });

  test('serializes equivalent inputs identically regardless of set and provenance order', () => {
    const first = createSecurityContract(baseInput);
    const reversed: SecurityContractInputV1 = {
      ...baseInput,
      operations: [...baseInput.operations].reverse().map((item) => ({
        ...item,
        provenance: [...item.provenance].reverse(),
        request: {
          ...item.request,
          contentTypes: [...item.request.contentTypes].reverse(),
          requiredHeaders: [...item.request.requiredHeaders].reverse(),
        },
      })),
    };

    expect(serializeSecurityContract(createSecurityContract(reversed)))
      .toBe(serializeSecurityContract(first));
    expect(serializeSecurityContract(first)).not.toContain('generatedAt');
  });

  test('does not retain raw source objects and rejects secret-like enum values', () => {
    const withRaw = {
      ...baseInput,
      rawOpenApi: { description: 'must-not-survive' },
    } as SecurityContractInputV1;
    expect(serializeSecurityContract(createSecurityContract(withRaw))).not.toContain('must-not-survive');

    const unsafe = structuredClone(baseInput);
    unsafe.operations[0].request.queryParameters[0].constraints.enum = ['Bearer actual-secret'];
    expect(() => createSecurityContract(unsafe)).toThrow('secret-like value');

    for (const token of ['sk-proj-', 'ghp_', 'github_pat_', 'AKIA'].map((prefix) => `${prefix}${'a'.repeat(8)}`)) {
      const prefixed = structuredClone(baseInput);
      prefixed.operations[0].request.queryParameters[0].constraints.enum = [token];
      expect(() => createSecurityContract(prefixed)).toThrow('secret-like value');
    }

    const invalid = structuredClone(baseInput);
    invalid.operations[0].request.body!.constraints.maxProperties = -1;
    expect(() => createSecurityContract(invalid)).toThrow('invalid constraint maxProperties');

    const nonFinite = structuredClone(baseInput);
    nonFinite.operations[0].request.queryParameters[0].constraints.enum = [Number.NaN];
    expect(() => createSecurityContract(nonFinite)).toThrow('invalid constraint enum');

    const secret = structuredClone(baseInput);
    secret.operations[0].operationId = 'Authorization: Basic dXNlcjpwYXNz';
    expect(() => createSecurityContract(secret)).toThrow('secret-like value');

    const pointerQuery = structuredClone(baseInput);
    pointerQuery.operations[0].provenance[0].pointer = '/paths/~1users?session=credential';
    expect(() => createSecurityContract(pointerQuery)).toThrow('invalid provenance pointer');

    for (const auth of [
      { name: 'unknown', kind: 'unknown', scopes: [], capability: 'supported' },
      { name: 'oauth', kind: 'oauth2', scopes: [], flows: [], capability: 'supported' },
    ]) {
      const invalidAuth = structuredClone(baseInput) as any;
      invalidAuth.operations[0].exposure = 'authenticated';
      invalidAuth.operations[0].auth = {
        mode: 'alternatives', alternatives: [{ anonymous: false, schemes: [auth] }],
      };
      expect(() => createSecurityContract(invalidAuth)).toThrow('invalid authentication scheme');
    }

    const legacyContracts = [];
    for (const auth of [
      { name: 'key', kind: 'api-key', location: 'header', scopes: [], capability: 'supported' },
      { name: 'oauth', kind: 'oauth2', scopes: [], capability: 'supported' },
    ]) {
      const legacy = structuredClone(baseInput) as any;
      legacy.operations[0].exposure = 'authenticated';
      legacy.operations[0].auth = {
        mode: 'alternatives', alternatives: [{ anonymous: false, schemes: [auth] }],
      };
      legacyContracts.push(createSecurityContract(legacy));
    }
    const schema = JSON.parse(fs.readFileSync(
      path.join(process.cwd(), 'schemas/security-ir-v1.schema.json'),
      'utf8',
    ));
    const validate = new Ajv({ allErrors: true }).compile(schema);
    for (const contract of legacyContracts) {
      expect(validate(contract), JSON.stringify(validate.errors)).toBe(true);
    }
  });

  test('rejects cyclic and excessively deep constraint shapes deterministically', () => {
    const cyclic: ValueConstraintsV1 = { type: 'array' };
    cyclic.items = cyclic;
    const cyclicInput = structuredClone(baseInput);
    cyclicInput.operations[0].request.body = {
      required: true, constraints: cyclic, unsupportedReasons: [],
    };
    expect(() => createSecurityContract(cyclicInput)).toThrow('cyclic value constraints');

    let deep: ValueConstraintsV1 = { type: 'boolean' };
    for (let index = 0; index < 256; index += 1) deep = { type: 'array', items: deep, maxItems: 1 };
    const deepInput = structuredClone(baseInput);
    deepInput.operations[0].request.body = {
      required: true, constraints: deep, unsupportedReasons: [],
    };
    expect(() => createSecurityContract(deepInput)).toThrow('value constraints exceed depth limit');

    const protoInput = structuredClone(baseInput);
    protoInput.operations[0].request.body = {
      required: true,
      constraints: {
        type: 'object',
        additionalProperties: false,
        properties: Object.fromEntries([['__proto__', { type: 'boolean' }]]),
      },
      unsupportedReasons: [],
    };
    const protoContract = createSecurityContract(protoInput);
    expect(Object.prototype.hasOwnProperty.call(
      protoContract.operations.find(({ routeKey }) => routeKey === 'POST /users')
        ?.request.body?.constraints.properties,
      '__proto__',
    )).toBe(true);
  });

  test('sorts 1000 operations and rejects a duplicate deterministically', () => {
    const operations = Array.from({ length: 1_000 }, (_, index) => (
      operation('get', `/resources/${String(999 - index).padStart(4, '0')}`)
    ));
    const contract = createSecurityContract({ ...baseInput, operations });

    expect(contract.operations).toHaveLength(1_000);
    expect(contract.operations[0].routeKey).toBe('GET /resources/0000');
    expect(contract.operations[999].routeKey).toBe('GET /resources/0999');
    expect(() => createSecurityContract({
      ...baseInput,
      operations: [...operations, operation('GET', '/resources/0000')],
    })).toThrow('duplicate route');
  });
});
