import { describe, expect, test } from 'vitest';

import {
  compareSourceOpenApiContracts,
  createSecurityContract,
  type ApiOperationInputV1,
  type SecurityContractCapabilitiesV1,
} from '../../src/contract';

const request = {
  contentTypes: [], requiredHeaders: [], queryParameters: [], pathParameters: [],
  headerParameters: [], cookieParameters: [],
};

function operation(
  source: 'openapi' | 'source-ast',
  method: string,
  path: string,
  overrides: Partial<ApiOperationInputV1> = {},
): ApiOperationInputV1 {
  return {
    method,
    path,
    exposure: 'public',
    auth: { mode: 'none', alternatives: [] },
    request,
    provenance: [{
      source,
      uri: source === 'openapi' ? 'openapi.yml' : 'src/controller.ts',
      pointer: source === 'openapi' ? `/paths/${path}/${method.toLowerCase()}` : '/controllers/0',
      digest: `sha256:${source}`,
      analyzer: `${source}@1`,
      capability: `${source}-operations-v1`,
      complete: true,
    }],
    ...overrides,
  };
}

function contract(
  source: 'openapi' | 'source-ast',
  operations: ApiOperationInputV1[],
  capabilities: Partial<SecurityContractCapabilitiesV1> = {},
) {
  return createSecurityContract({
    source,
    capabilities: {
      routes: 'complete', parameters: 'complete', requestBodies: 'complete',
      authentication: 'complete', ...capabilities,
    },
    operations,
  });
}

function input(
  declared: ApiOperationInputV1[],
  implemented: ApiOperationInputV1[],
  sourceCapabilities: Partial<SecurityContractCapabilitiesV1> = {},
) {
  return {
    declared: contract('openapi', declared),
    implemented: contract('source-ast', implemented, sourceCapabilities),
    declaredEvidence: {
      source: 'openapi' as const, uri: 'openapi.yml', digest: 'sha256:openapi',
      analyzer: 'openapi@1', capability: 'openapi-operations-v1', complete: true,
    },
    implementedEvidence: {
      source: 'source-ast' as const, uri: 'tsconfig.json', digest: 'sha256:source',
      analyzer: 'nestjs@1', capability: 'nestjs-routes-v1',
      complete: sourceCapabilities.routes !== 'partial',
    },
  };
}

const bearerAuth = {
  mode: 'alternatives' as const,
  alternatives: [{
    anonymous: false,
    schemes: [{ name: 'bearer', kind: 'bearer' as const, scopes: [], capability: 'supported' as const }],
  }],
};

const sourceBearerAuth = {
  ...bearerAuth,
  analysis: {
    guards: [{ symbol: 'JwtAuthGuard', authKind: 'bearer' as const }],
    explicitPublic: false,
    roles: [],
    enforcementConfidence: 'high' as const,
    capabilityReasons: [],
  },
};

describe('Source AST and OpenAPI drift', () => {
  test('matches equivalent route shapes while ignoring parameter names', () => {
    const comparison = input(
      [operation('openapi', 'GET', '/users/{openapiId}')],
      [operation('source-ast', 'GET', '/users/{sourceId}')],
    );
    const snapshot = structuredClone(comparison);
    const findings = compareSourceOpenApiContracts(comparison);

    expect(findings).toEqual([]);
    expect(comparison).toEqual(snapshot);
    expect(compareSourceOpenApiContracts(comparison)).toEqual(findings);
  });

  test('reports implemented-only and declared-only operations with capability gating', () => {
    const complete = compareSourceOpenApiContracts(input(
      [operation('openapi', 'POST', '/declared')],
      [operation('source-ast', 'GET', '/implemented')],
    ));
    expect(complete.map(({ ruleId, severity }) => `${ruleId}:${severity}`)).toEqual([
      'SC-INVENTORY-001:error',
      'SC-INVENTORY-003:error',
    ]);
    for (const finding of complete) {
      expect(new Set(finding.evidence.map(({ source }) => source)))
        .toEqual(new Set(['openapi', 'source-ast']));
    }

    const partial = compareSourceOpenApiContracts(input(
      [operation('openapi', 'POST', '/declared')],
      [],
      { routes: 'partial' },
    ));
    expect(partial).toEqual([expect.objectContaining({
      ruleId: 'SC-INVENTORY-003', severity: 'warning', confidence: 'heuristic',
    })]);
    expect(compareSourceOpenApiContracts(input(
      [],
      [operation('source-ast', 'GET', '/implemented')],
      { routes: 'partial' },
    ))).toEqual([expect.objectContaining({
      ruleId: 'SC-INVENTORY-001', severity: 'warning', confidence: 'heuristic',
    })]);
  });

  test('reports one method-set mismatch without duplicate inventory findings', () => {
    const declaredGet = operation('openapi', 'GET', '/users/{id}', {
      provenance: [{
        ...operation('openapi', 'GET', '/users/{id}').provenance[0], pointer: '/paths/users/get',
      }],
    });
    const declaredPost = operation('openapi', 'POST', '/users/{id}', {
      provenance: [{
        ...operation('openapi', 'POST', '/users/{id}').provenance[0], pointer: '/paths/users/post',
      }],
    });
    const findings = compareSourceOpenApiContracts(input(
      [declaredGet, declaredPost],
      [operation('source-ast', 'GET', '/users/{userId}')],
    ));

    expect(findings).toEqual([expect.objectContaining({
      ruleId: 'SC-INVENTORY-004', severity: 'error',
      expected: { methods: ['GET', 'POST'] }, actual: { methods: ['GET'] },
    })]);
    expect(findings[0].evidence.map(({ pointer }) => pointer))
      .toEqual(['/paths/users/get', '/paths/users/post', '/controllers/0']);
  });

  test('reports only explicit high-confidence authentication contradictions', () => {
    const publicDeclared = operation('openapi', 'GET', '/public');
    const guardedSource = operation('source-ast', 'GET', '/public', {
      exposure: 'authenticated', auth: sourceBearerAuth,
    });
    const authenticatedDeclared = operation('openapi', 'GET', '/private', {
      exposure: 'authenticated', auth: bearerAuth,
    });
    const explicitPublicSource = operation('source-ast', 'GET', '/private', {
      auth: {
        mode: 'none', alternatives: [], analysis: {
          guards: [], explicitPublic: true, roles: [], enforcementConfidence: 'high', capabilityReasons: [],
        },
      },
    });
    const unknownSource = operation('source-ast', 'GET', '/unknown', {
      exposure: 'unknown', auth: { mode: 'unknown', alternatives: [] },
    });
    const findings = compareSourceOpenApiContracts(input(
      [publicDeclared, authenticatedDeclared, operation('openapi', 'GET', '/unknown', {
        exposure: 'authenticated', auth: bearerAuth,
      })],
      [guardedSource, explicitPublicSource, unknownSource],
    ));

    expect(findings.map(({ ruleId, route }) => `${ruleId}:${route?.path}`)).toEqual([
      'SC-AUTHN-005:/private',
      'SC-AUTHN-005:/public',
    ]);
    expect(findings[0]?.message).toContain('does not prove Guard runtime behavior');
    expect(compareSourceOpenApiContracts(input(
      [publicDeclared], [guardedSource], { routes: 'partial' },
    ))).toEqual([expect.objectContaining({
      ruleId: 'SC-AUTHN-005', confidence: 'heuristic',
    })]);
  });

  test('matches Source auth against each OpenAPI alternative', () => {
    const declared = operation('openapi', 'GET', '/choice', {
      exposure: 'authenticated',
      auth: {
        mode: 'alternatives',
        alternatives: [
          bearerAuth.alternatives[0],
          {
            anonymous: false,
            schemes: [{
              name: 'key', kind: 'api-key', scopes: [], capability: 'supported',
              location: 'header', parameterName: 'x-api-key',
            }],
          },
        ],
      },
    });
    const basicSource = operation('source-ast', 'GET', '/choice', {
      exposure: 'authenticated',
      auth: {
        ...sourceBearerAuth,
        analysis: {
          ...sourceBearerAuth.analysis,
          guards: [{ symbol: 'BasicAuthGuard', authKind: 'basic' }],
        },
      },
    });

    expect(compareSourceOpenApiContracts(input([declared], [basicSource]))
      .map(({ ruleId }) => ruleId)).toContain('SC-AUTHN-005');
  });

  test('treats an explicit anonymous OpenAPI alternative as public', () => {
    const declared = operation('openapi', 'GET', '/optional', {
      exposure: 'public',
      auth: {
        mode: 'alternatives',
        alternatives: [
          { anonymous: true, schemes: [] },
          bearerAuth.alternatives[0],
        ],
      },
    });
    const implemented = operation('source-ast', 'GET', '/optional', {
      exposure: 'authenticated', auth: sourceBearerAuth,
    });

    expect(compareSourceOpenApiContracts(input([declared], [implemented]))
      .map(({ ruleId }) => ruleId)).toContain('SC-AUTHN-005');
  });

  test('preserves repeated auth-kind requirements', () => {
    const declared = operation('openapi', 'GET', '/keys', {
      exposure: 'authenticated',
      auth: {
        mode: 'alternatives', alternatives: [{
          anonymous: false,
          schemes: ['one', 'two'].map((name) => ({
            name, kind: 'api-key' as const, scopes: [], capability: 'supported' as const,
            location: 'header' as const, parameterName: `x-${name}`,
          })),
        }],
      },
    });
    const implemented = operation('source-ast', 'GET', '/keys', {
      exposure: 'authenticated',
      auth: {
        mode: 'alternatives', alternatives: [{
          anonymous: false,
          schemes: [{
            name: 'one', kind: 'api-key', scopes: [], capability: 'supported',
            location: 'header', parameterName: 'x-one',
          }],
        }], analysis: {
          guards: [{ symbol: 'ApiKeyGuard', authKind: 'api-key' }],
          explicitPublic: false, roles: [], enforcementConfidence: 'high', capabilityReasons: [],
        },
      },
    });

    expect(compareSourceOpenApiContracts(input([declared], [implemented]))
      .map(({ ruleId }) => ruleId)).toContain('SC-AUTHN-005');
  });

  test('bounds comparisons within duplicate normalized route groups', () => {
    const declared = Array.from({ length: 1001 }, (_, index) =>
      operation('openapi', 'GET', `/bulk/{declared${index}}`));
    const implemented = Array.from({ length: 1000 }, (_, index) =>
      operation('source-ast', 'GET', `/bulk/{implemented${index}}`));

    expect(() => compareSourceOpenApiContracts(input(declared, implemented)))
      .toThrow('source OpenAPI drift comparison exceeds visit budget');
  });

  test('charges repeated guard width within duplicate route groups', () => {
    const schemes = Array.from({ length: 1000 }, (_, index) => ({
      name: `key-${index}`, kind: 'api-key' as const, scopes: [], capability: 'supported' as const,
      location: 'header' as const, parameterName: `x-key-${index}`,
    }));
    const guards = schemes.map((_, index) => ({
      symbol: `ApiKeyGuard${index}`, authKind: 'api-key' as const,
    }));
    const declared = Array.from({ length: 30 }, (_, index) =>
      operation('openapi', 'GET', `/wide/{declared${index}}`, {
        exposure: 'authenticated',
        auth: { mode: 'alternatives', alternatives: [{ anonymous: false, schemes }] },
      }));
    const implemented = Array.from({ length: 30 }, (_, index) =>
      operation('source-ast', 'GET', `/wide/{implemented${index}}`, {
        exposure: 'authenticated',
        auth: {
          mode: 'alternatives', alternatives: [{ anonymous: false, schemes }],
          analysis: {
            guards, explicitPublic: false, roles: [],
            enforcementConfidence: 'high', capabilityReasons: [],
          },
        },
      }));

    expect(() => compareSourceOpenApiContracts(input(declared, implemented)))
      .toThrow('source OpenAPI drift comparison exceeds visit budget');
  });

  test('compares privileged roles only when explicit configuration is supplied', () => {
    const source = operation('source-ast', 'GET', '/admin', {
      exposure: 'privileged',
      auth: {
        ...sourceBearerAuth,
        analysis: { ...sourceBearerAuth.analysis, roles: ['ops'] },
      },
    });
    const comparison = input([
      operation('openapi', 'GET', '/admin', { exposure: 'authenticated', auth: bearerAuth }),
    ], [source]);

    expect(compareSourceOpenApiContracts(comparison)).toEqual([]);
    expect(compareSourceOpenApiContracts(comparison, {
      declaredPrivilegedRoles: { 'GET /admin': ['admin'] },
    })).toEqual([expect.objectContaining({
      ruleId: 'SC-AUTHZ-001', severity: 'warning', category: 'authorization',
    })]);
    expect(compareSourceOpenApiContracts(comparison, {
      declaredPrivilegedRoles: Object.create({ 'GET /admin': ['admin'] }),
    })).toEqual([]);
    expect(compareSourceOpenApiContracts(input(
      comparison.declared.operations,
      [source],
      { routes: 'partial' },
    ), {
      declaredPrivilegedRoles: { 'GET /admin': ['admin'] },
    })).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: 'SC-AUTHZ-001', confidence: 'heuristic' }),
    ]));
  });

  test('does not hide contradictions behind duplicate normalized Source routes', () => {
    const declared = operation('openapi', 'GET', '/users/{id}', {
      exposure: 'authenticated', auth: bearerAuth,
    });
    const matching = operation('source-ast', 'GET', '/users/{first}', {
      exposure: 'authenticated', auth: {
        ...sourceBearerAuth,
        analysis: { ...sourceBearerAuth.analysis, roles: ['admin'] },
      },
    });
    const contradictory = operation('source-ast', 'GET', '/users/{second}', {
      auth: {
        mode: 'none', alternatives: [], analysis: {
          guards: [], explicitPublic: true, roles: ['ops'],
          enforcementConfidence: 'high', capabilityReasons: [],
        },
      },
    });

    const findings = compareSourceOpenApiContracts(input([declared], [matching, contradictory]), {
      declaredPrivilegedRoles: { 'GET /users/{id}': ['admin'] },
    });

    expect(findings.map(({ ruleId }) => ruleId)).toEqual(['SC-AUTHN-005', 'SC-AUTHZ-001']);
  });

  test('compares role values without delimiter collisions and bounds role strings', () => {
    const declared = operation('openapi', 'GET', '/admin');
    const implemented = operation('source-ast', 'GET', '/admin', {
      auth: {
        mode: 'none', alternatives: [], analysis: {
          guards: [], explicitPublic: true, roles: ['admin\0ops'],
          enforcementConfidence: 'high', capabilityReasons: [],
        },
      },
    });
    const comparison = input([declared], [implemented]);

    expect(compareSourceOpenApiContracts(comparison, {
      declaredPrivilegedRoles: { 'GET /admin': ['admin', 'ops'] },
    }).map(({ ruleId }) => ruleId)).toContain('SC-AUTHZ-001');
    expect(() => compareSourceOpenApiContracts(comparison, {
      declaredPrivilegedRoles: { 'GET /admin': ['x'.repeat(16_385)] },
    })).toThrow('invalid declared privileged roles');
  });
});
