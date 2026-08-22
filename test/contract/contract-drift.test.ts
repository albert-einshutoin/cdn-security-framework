import { describe, expect, test } from 'vitest';

import {
  compareAuthContracts,
  comparePathMethodContracts,
  compareRequestContracts,
  compareSecurityContracts,
  createSecurityContract,
  projectPolicyToAllowedSurface,
  type ApiAuthenticationContractV1,
  type ApiOperationInputV1,
  type SecurityContractCapabilitiesV1,
} from '../../src/contract';
import type { CDNSecurityFrameworkPolicy } from '../../src/types/policy';
import { assertGolden } from '../helpers/golden-assert';

const digest = `sha256:${'a'.repeat(64)}`;
const provenance = {
  source: 'openapi' as const,
  uri: 'spec/openapi.yaml',
  pointer: '/paths/~1users/get',
  digest,
  analyzer: 'openapi@1',
  capability: 'openapi-operations-v1',
  complete: true,
};

const noAuth: ApiAuthenticationContractV1 = { mode: 'none', alternatives: [] };

function operation(
  method: string,
  path: string,
  overrides: Partial<ApiOperationInputV1> = {},
): ApiOperationInputV1 {
  return {
    method,
    path,
    exposure: 'public',
    auth: noAuth,
    request: {
      contentTypes: [],
      requiredHeaders: [],
      queryParameters: [],
      pathParameters: [],
      headerParameters: [],
      cookieParameters: [],
    },
    provenance: [{ ...provenance, pointer: `/paths/${path.replaceAll('/', '~1')}/${method.toLowerCase()}` }],
    ...overrides,
  };
}

function contract(
  operations: ApiOperationInputV1[],
  capabilities: Partial<SecurityContractCapabilitiesV1> = {},
) {
  return createSecurityContract({
    source: 'openapi',
    capabilities: {
      routes: 'complete',
      parameters: 'complete',
      requestBodies: 'complete',
      authentication: 'complete',
      ...capabilities,
    },
    operations,
  });
}

function policy(overrides: Partial<CDNSecurityFrameworkPolicy> = {}): CDNSecurityFrameworkPolicy {
  return {
    version: 1,
    defaults: { mode: 'enforce' },
    request: {
      allow_methods: ['GET'],
      block: { header_missing: [] },
      limits: { max_query_params: 30, max_query_length: 1024, max_uri_length: 2048 },
    },
    routes: [],
    response_headers: {},
    ...overrides,
  };
}

function input(
  declared: ReturnType<typeof contract>,
  policyInput: CDNSecurityFrameworkPolicy,
  target: 'aws' | 'cloudflare' = 'aws',
) {
  return {
    declared,
    allowed: projectPolicyToAllowedSurface(policyInput, {
      policyDigest: digest,
      sourceUri: 'policy/security.yml',
    }),
    target,
  } as const;
}

describe('OpenAPI and Policy contract drift', () => {
  test('classifies exact and broad route/method drift without promoting uncertainty to Error', () => {
    const findings = comparePathMethodContracts(input(
      contract([operation('POST', '/users')]),
      policy({
        request: { allow_methods: ['GET', 'DELETE'], block: { header_missing: [] } },
        routes: [
          {
            name: 'orphan-exact',
            match: { path_prefixes: ['/ghost'] },
            auth_gate: { type: 'signed_url', exact_path: true },
          },
          {
            name: 'broad-admin', match: { path_prefixes: ['/admin'] },
            auth_gate: { type: 'basic_auth' },
          },
        ],
      }),
    ));

    expect(findings.map(({ ruleId }) => ruleId)).toEqual([
      'SC-EXPOSURE-001',
      'SC-EXPOSURE-002',
      'SC-INVENTORY-002',
      'SC-EXPOSURE-003',
    ]);
    expect(findings.find(({ ruleId }) => ruleId === 'SC-EXPOSURE-003')?.severity).toBe('warning');

    const defaultAuthPrefixes = comparePathMethodContracts(input(
      contract([operation('GET', '/health')]),
      policy({ routes: [{ name: 'protected-defaults', match: {}, auth_gate: { type: 'jwt' } }] }),
    ));
    expect(defaultAuthPrefixes.filter(({ ruleId }) => ruleId === 'SC-EXPOSURE-003')
      .map(({ route }) => route?.path)).toEqual(['/admin', '/docs', '/swagger']);
    expect(defaultAuthPrefixes.find(({ ruleId, route }) => (
      ruleId === 'SC-EXPOSURE-003' && route?.path === '/admin'
    ))?.evidence.at(-1)?.pointer).toBe('/routes/0/auth_gate');

    const inertPrefix = comparePathMethodContracts(input(
      contract([operation('GET', '/health')]),
      policy({ routes: [{ name: 'placeholder', match: { path_prefixes: ['/internal'] } }] }),
    ));
    expect(inertPrefix.some(({ ruleId }) => ruleId === 'SC-EXPOSURE-003')).toBe(false);

    const renamedParameter = comparePathMethodContracts(input(
      contract([operation('GET', '/users/{openapiId}')]),
      policy({ routes: [{
        name: 'same-shape',
        match: { path_prefixes: ['/users/{policyId}'] },
        auth_gate: { type: 'signed_url', exact_path: true },
      }] }),
    ));
    expect(renamedParameter.some(({ ruleId }) => ruleId === 'SC-INVENTORY-002')).toBe(false);

    const monitorFindings = comparePathMethodContracts(input(
      contract([operation('POST', '/users')]),
      policy({ defaults: { mode: 'monitor' } }),
    ));
    expect(monitorFindings.find(({ ruleId }) => ruleId === 'SC-EXPOSURE-002')?.severity)
      .toBe('warning');

    const monitorSurface = comparePathMethodContracts(input(
      contract([operation('GET', '/users')]),
      policy({ defaults: { mode: 'monitor' } }),
    ));
    expect(monitorSurface.find(({ ruleId }) => ruleId === 'SC-EXPOSURE-001'))
      .toMatchObject({ severity: 'warning' });

    const defaultMethodsInput = input(
      contract([operation('DELETE', '/default-method')]),
      policy({ request: { block: { header_missing: [] } } }),
    );
    const defaultMethods = comparePathMethodContracts(defaultMethodsInput);
    expect(defaultMethods.find(({ ruleId }) => ruleId === 'SC-EXPOSURE-002')
      ?.evidence.at(-1)?.pointer).toBe('/request');
    delete defaultMethodsInput.allowed.defaults.methodSource;
    expect(comparePathMethodContracts(defaultMethodsInput)
      .find(({ ruleId }) => ruleId === 'SC-EXPOSURE-002')
      ?.evidence.at(-1)?.pointer).toBe('/request');

    const corsMethods = comparePathMethodContracts(input(
      contract([operation('GET', '/cors')]),
      policy({ response_headers: { cors: { allow_origins: ['https://client.example'] } } }),
    ));
    expect(corsMethods.some(({ ruleId }) => ruleId === 'SC-EXPOSURE-001')).toBe(true);

    const concreteExact = comparePathMethodContracts(input(
      contract([operation('GET', '/download/{filename}')]),
      policy({ routes: [{
        name: 'concrete-download', match: { path_prefixes: ['/download/report.pdf'] },
        auth_gate: { type: 'signed_url', exact_path: true, secret_env: 'SIGNED_URL_SECRET' },
      }] }),
    ));
    expect(concreteExact.some(({ ruleId }) => ruleId === 'SC-INVENTORY-002')).toBe(false);
  });

  test('preserves auth alternatives and refuses Bearer-to-JWT inference', () => {
    const apiKeyAuth: ApiAuthenticationContractV1 = {
      mode: 'alternatives',
      alternatives: [{
        anonymous: false,
        schemes: [{
          name: 'edgeKey', kind: 'api-key', location: 'header', parameterName: 'X-API-Key',
          scopes: [], capability: 'supported',
        }],
      }],
    };
    const bearerAuth: ApiAuthenticationContractV1 = {
      mode: 'alternatives',
      alternatives: [{
        anonymous: false,
        schemes: [{ name: 'bearer', kind: 'bearer', scopes: [], capability: 'supported' }],
      }],
    };
    const optionalAuth: ApiAuthenticationContractV1 = {
      mode: 'alternatives',
      alternatives: [
        { anonymous: true, schemes: [] },
        ...apiKeyAuth.alternatives,
      ],
    };
    const findings = compareAuthContracts(input(
      contract([
        operation('GET', '/compatible', { exposure: 'authenticated', auth: apiKeyAuth }),
        operation('GET', '/public'),
        operation('GET', '/bearer', { exposure: 'authenticated', auth: bearerAuth }),
        operation('GET', '/optional', { exposure: 'public', auth: optionalAuth }),
        operation('GET', '/stacked', { exposure: 'authenticated', auth: apiKeyAuth }),
        operation('GET', '/stacked-bearer', { exposure: 'authenticated', auth: bearerAuth }),
      ]),
      policy({
        routes: [
          {
            name: 'compatible', match: { path_prefixes: ['/compatible'] },
            auth_gate: { type: 'static_token', header: 'x-api-key' },
          },
          {
            name: 'public', match: { path_prefixes: ['/public'] },
            auth_gate: { type: 'basic_auth' },
          },
          {
            name: 'bearer', match: { path_prefixes: ['/bearer'] },
            auth_gate: { type: 'jwt', algorithm: 'HS256' },
          },
          {
            name: 'optional', match: { path_prefixes: ['/optional'] },
            auth_gate: { type: 'static_token', header: 'x-api-key' },
          },
          {
            name: 'stacked-key', match: { path_prefixes: ['/stacked'] },
            auth_gate: { type: 'static_token', header: 'x-api-key' },
          },
          {
            name: 'stacked-basic', match: { path_prefixes: ['/stacked'] },
            auth_gate: { type: 'basic_auth' },
          },
          {
            name: 'stacked-bearer-jwt', match: { path_prefixes: ['/stacked-bearer'] },
            auth_gate: { type: 'jwt', algorithm: 'HS256' },
          },
          {
            name: 'stacked-bearer-basic', match: { path_prefixes: ['/stacked-bearer'] },
            auth_gate: { type: 'basic_auth' },
          },
        ],
      }),
    ));

    expect(findings.map(({ ruleId }) => ruleId)).toEqual([
      'SC-AUTHN-002', 'SC-AUTHN-002', 'SC-AUTHN-003', 'SC-AUTHN-003', 'SC-AUTHN-004',
    ]);
    expect(findings.find(({ ruleId }) => ruleId === 'SC-AUTHN-004')?.severity).toBe('info');
    expect(findings.find(({ ruleId }) => ruleId === 'SC-AUTHN-002')?.message)
      .toContain('Application authentication is not evaluated');
    expect(findings.find(({ ruleId, route }) => (
      ruleId === 'SC-AUTHN-003' && route?.path === '/stacked'
    ))?.evidence.filter(({ source }) => source === 'policy').map(({ pointer }) => pointer))
      .toEqual(['/routes/4/auth_gate', '/routes/5/auth_gate']);

    const exactPathFindings = compareAuthContracts(input(
      contract([
        operation('GET', '/download/child'),
        operation('POST', '/download/child', { exposure: 'authenticated', auth: apiKeyAuth }),
      ]),
      policy({ routes: [{
        name: 'exact-download',
        match: { path_prefixes: ['/download'] },
        auth_gate: { type: 'signed_url', exact_path: true, secret_env: 'SIGNED_URL_SECRET' },
      }] }),
    ));
    expect(exactPathFindings.map(({ ruleId }) => ruleId)).toEqual(['SC-AUTHN-001']);
    expect(exactPathFindings[0]?.evidence.at(-1)?.pointer).toBe('/request');

    const publicOverlap = compareAuthContracts(input(
      contract([operation('GET', '/users/{id}')]),
      policy({ routes: [{
        name: 'exact-user', match: { path_prefixes: ['/users/me'] },
        auth_gate: { type: 'signed_url', exact_path: true },
      }] }),
    ));
    expect(publicOverlap.map(({ ruleId }) => ruleId)).toEqual(['SC-AUTHN-004']);

    const uncertainGateFindings = compareAuthContracts(input(
      contract([operation('GET', '/mixed', { exposure: 'authenticated', auth: apiKeyAuth })]),
      policy({ routes: [
        {
          name: 'supported', match: { path_prefixes: ['/mixed'] },
          auth_gate: { type: 'static_token', header: 'x-api-key' },
        },
        {
          name: 'unsupported', match: { path_prefixes: ['/mixed'] },
          auth_gate: { type: 'jwt', algorithm: 'ES256' },
        },
      ] }),
    ));
    expect(uncertainGateFindings.map(({ ruleId }) => ruleId)).toEqual(['SC-AUTHN-004']);

    const corsAuth = compareAuthContracts(input(
      contract([operation('OPTIONS', '/private', { exposure: 'authenticated', auth: apiKeyAuth })]),
      policy({
        routes: [{
          name: 'private', match: { path_prefixes: ['/private'] },
          auth_gate: { type: 'static_token', header: 'x-api-key' },
        }],
        response_headers: { cors: { allow_origins: ['https://client.example'] } },
      }),
    ));
    expect(corsAuth.map(({ ruleId }) => ruleId)).toEqual(['SC-AUTHN-004']);

    const emptyCorsAuth = compareAuthContracts(input(
      contract([
        operation('OPTIONS', '/private', { exposure: 'authenticated', auth: apiKeyAuth }),
        operation('OPTIONS', '/public'),
      ]),
      policy({
        routes: [
          {
            name: 'private', match: { path_prefixes: ['/private'] },
            auth_gate: { type: 'static_token', header: 'x-api-key' },
          },
          {
            name: 'public', match: { path_prefixes: ['/public'] },
            auth_gate: { type: 'static_token', header: 'x-api-key' },
          },
        ],
        response_headers: { cors: { allow_origins: [] } },
      }),
    ));
    expect(emptyCorsAuth.map(({ ruleId }) => ruleId)).toEqual(['SC-AUTHN-002']);
  });

  test('compares only finite request estimates and reports unsupported content types', () => {
    const declared = contract([operation('GET', '/items', {
      request: {
        contentTypes: ['application/json'],
        requiredHeaders: ['x-contract'],
        queryParameters: [{
          name: 'q', required: true, constraints: { type: 'string', maxLength: 4 }, unsupportedReasons: [],
        }],
        pathParameters: [],
        headerParameters: [],
        cookieParameters: [],
      },
    })]);
    const findings = compareRequestContracts(input(declared, policy({
      request: {
        allow_methods: ['GET'],
        block: { header_missing: ['x-policy'] },
        limits: { max_query_params: 1, max_query_length: 1, max_uri_length: 1 },
      },
    })));

    expect(findings.map(({ ruleId }) => ruleId)).toEqual([
      'SC-LIMIT-001', 'SC-LIMIT-001', 'SC-LIMIT-001',
      'SC-REQUEST-002', 'SC-REQUEST-001', 'SC-REQUEST-003',
    ]);
    expect(findings.filter(({ severity }) => severity === 'error')).toHaveLength(4);
    expect(() => compareRequestContracts(input(declared, policy()), {
      materiallyBroaderRatio: 0,
    })).toThrow('invalid materially broader ratio');

    const corsRequest = compareRequestContracts(input(
      contract([operation('OPTIONS', '/items', {
        request: {
          contentTypes: [], requiredHeaders: [], queryParameters: [], pathParameters: [],
          headerParameters: [], cookieParameters: [],
        },
      })]),
      policy({
        request: { block: { header_missing: ['x-policy'] } },
        response_headers: { cors: { allow_origins: ['https://client.example'] } },
      }),
    ));
    expect(corsRequest.find(({ ruleId }) => ruleId === 'SC-REQUEST-002')?.severity).toBe('warning');
    expect(corsRequest.some(({ severity }) => severity === 'error')).toBe(false);

    const declaredCorsHeader = compareRequestContracts(input(
      contract([operation('OPTIONS', '/items', {
        request: {
          contentTypes: [], requiredHeaders: ['x-policy'], queryParameters: [], pathParameters: [],
          headerParameters: [], cookieParameters: [],
        },
      })]),
      policy({
        request: { block: { header_missing: ['x-policy'] } },
        response_headers: { cors: { allow_origins: ['https://client.example'] } },
      }),
    ));
    expect(declaredCorsHeader.some(({ ruleId }) => ruleId === 'SC-REQUEST-001')).toBe(true);

    const authHeaderRequest = compareRequestContracts(input(
      contract([operation('GET', '/key', {
        exposure: 'authenticated',
        auth: {
          mode: 'alternatives',
          alternatives: [{
            anonymous: false,
            schemes: [{
              name: 'key', kind: 'api-key', location: 'header', parameterName: 'X-API-Key',
              scopes: [], capability: 'supported',
            }],
          }],
        },
      })]),
      policy({ request: { block: { header_missing: ['x-api-key'] } } }),
    ));
    expect(authHeaderRequest.some(({ ruleId }) => ruleId === 'SC-REQUEST-002')).toBe(false);

    const httpAuthHeaderRequest = compareRequestContracts(input(
      contract([operation('GET', '/bearer', {
        exposure: 'authenticated',
        auth: {
          mode: 'alternatives',
          alternatives: [{
            anonymous: false,
            schemes: [{ name: 'bearer', kind: 'bearer', scopes: [], capability: 'supported' }],
          }],
        },
      })]),
      policy({ request: { block: { header_missing: ['authorization'] } } }),
    ));
    expect(httpAuthHeaderRequest.some(({ ruleId }) => ruleId === 'SC-REQUEST-002')).toBe(false);

    const gatedHttpAuthHeader = compareRequestContracts(input(
      contract([operation('GET', '/private', {
        exposure: 'authenticated',
        auth: {
          mode: 'alternatives',
          alternatives: [{
            anonymous: false,
            schemes: [{ name: 'basic', kind: 'basic', scopes: [], capability: 'supported' }],
          }],
        },
      })]),
      policy({ routes: [{
        name: 'private', match: { path_prefixes: ['/private'] }, auth_gate: { type: 'basic_auth' },
      }] }),
    ));
    expect(gatedHttpAuthHeader.some(({ ruleId }) => ruleId === 'SC-REQUEST-001')).toBe(false);

    const fractionalRatio = compareRequestContracts(input(
      contract([operation('GET', '/ratio', {
        request: {
          contentTypes: [], requiredHeaders: [],
          queryParameters: Array.from({ length: 4 }, (_, index) => ({
            name: `q${index}`, required: false, constraints: { type: 'string', maxLength: 1 },
            unsupportedReasons: [],
          })),
          pathParameters: [], headerParameters: [], cookieParameters: [],
        },
      })]),
      policy({ request: { limits: { max_query_params: 8, max_query_length: 1024, max_uri_length: 2048 } } }),
    ), { materiallyBroaderRatio: 1.5 });
    expect(fractionalRatio.some(({ ruleId }) => ruleId === 'SC-LIMIT-002')).toBe(true);
    expect(fractionalRatio.find(({ ruleId, actual }) => (
      ruleId === 'SC-LIMIT-002' && actual.control === 'max_query_params'
    ))
      ?.evidence.at(-1)?.pointer).toBe('/request/limits/max_query_params');

    const defaultLimitInput = input(
      contract([operation('GET', '/default-limit', {
        request: {
          contentTypes: [], requiredHeaders: [],
          queryParameters: [{
            name: 'q', required: false, constraints: { type: 'string', maxLength: 5 },
            unsupportedReasons: [],
          }],
          pathParameters: [], headerParameters: [], cookieParameters: [],
        },
      })]),
      policy({ request: { allow_methods: ['GET'] } }),
    );
    const defaultLimit = compareRequestContracts(defaultLimitInput, { materiallyBroaderRatio: 1.5 });
    expect(defaultLimit.find(({ ruleId, actual }) => (
      ruleId === 'SC-LIMIT-002' && actual.control === 'max_uri_length'
    ))?.evidence.at(-1)?.pointer).toBe('/request');
    delete defaultLimitInput.allowed.defaults.limitSources;
    expect(compareRequestContracts(defaultLimitInput, { materiallyBroaderRatio: 1.5 })
      .find(({ ruleId, actual }) => (
        ruleId === 'SC-LIMIT-002' && actual.control === 'max_uri_length'
      ))?.evidence.at(-1)?.pointer).toBe('/request');

    const emptyCorsRequest = compareRequestContracts(input(
      contract([operation('OPTIONS', '/items')]),
      policy({
        request: { block: { header_missing: ['x-policy'] } },
        response_headers: { cors: { allow_origins: [] } },
      }),
    ));
    expect(emptyCorsRequest.find(({ ruleId }) => ruleId === 'SC-REQUEST-002')?.severity).toBe('error');

    const runtimeDefault = compareRequestContracts(input(
      contract([operation('GET', '/items')]), policy({ request: { allow_methods: ['GET'] } }),
    ));
    expect(runtimeDefault.find(({ ruleId }) => ruleId === 'SC-REQUEST-002')
      ?.evidence.at(-1)?.pointer).toBe('/request');
  });

  test('is deterministic, validates the comparison boundary, and matches the golden contract', () => {
    const declared = contract([operation('GET', '/health')]);
    const comparison = input(declared, policy());
    expect(compareSecurityContracts(comparison)).toEqual(compareSecurityContracts(comparison));
    expect(() => compareSecurityContracts({ ...comparison, target: 'other' as 'aws' }))
      .toThrow('invalid contract drift input');

    const legacyAllowed = structuredClone(comparison.allowed);
    delete legacyAllowed.defaults.requiredHeaders;
    const legacyAuth = policy({ routes: [{
      name: 'legacy', match: { path_prefixes: ['/private'] },
      auth_gate: { type: 'static_token', header: 'x-api-key' },
    }] });
    const legacyAuthInput = input(contract([operation('GET', '/private', {
      exposure: 'authenticated',
      auth: {
        mode: 'alternatives',
        alternatives: [{ anonymous: false, schemes: [{
          name: 'key', kind: 'api-key', location: 'header', parameterName: 'x-api-key',
          scopes: [], capability: 'supported',
        }] }],
      },
    })]), legacyAuth);
    delete legacyAuthInput.allowed.orderedRules[0].auth.credential;
    expect(compareAuthContracts(legacyAuthInput).map(({ ruleId }) => ruleId))
      .toEqual(['SC-AUTHN-004']);
    expect(() => compareRequestContracts({ ...comparison, allowed: legacyAllowed })).not.toThrow();

    const defaultExact = comparePathMethodContracts(input(contract([]), policy({ routes: [{
      name: 'default-exact', match: {},
      auth_gate: { type: 'signed_url', exact_path: true, secret_env: 'SIGNED_URL_SECRET' },
    }] })));
    expect(defaultExact.filter(({ ruleId }) => ruleId === 'SC-INVENTORY-002')).toHaveLength(3);

    const overBudget = structuredClone(legacyAuthInput);
    overBudget.declared.operations = Array(1001).fill(legacyAuthInput.declared.operations[0]);
    overBudget.allowed.orderedRules = [{
      ...overBudget.allowed.orderedRules[0],
      match: {
        ...overBudget.allowed.orderedRules[0]?.match,
        kind: 'prefix',
        values: Array(1000).fill('/x'),
        authEffectiveValues: [],
        boundary: 'path-segment',
        algorithm: 'equal-or-prefix-plus-slash',
        comparison: 'literal-no-percent-decoding',
        phase: 'normalized-path',
      },
    }];
    expect(() => comparePathMethodContracts(overBudget))
      .toThrow('contract drift comparison exceeds visit budget');

    const authOverBudget = structuredClone(legacyAuthInput);
    const scheme = authOverBudget.declared.operations[0].auth.alternatives[0].schemes[0];
    authOverBudget.declared.operations[0].auth.alternatives[0].schemes = Array(1001).fill(scheme);
    authOverBudget.allowed.orderedRules = Array(1000).fill(authOverBudget.allowed.orderedRules[0]);
    expect(() => compareAuthContracts(authOverBudget))
      .toThrow('contract drift comparison exceeds visit budget');

    const alternativeOverBudget = structuredClone(legacyAuthInput);
    const anonymous = { anonymous: true, schemes: [] };
    alternativeOverBudget.declared.operations[0].auth.alternatives = Array(1000).fill(anonymous);
    alternativeOverBudget.declared.operations = Array(1001)
      .fill(alternativeOverBudget.declared.operations[0]);
    expect(() => compareAuthContracts(alternativeOverBudget))
      .toThrow('contract drift comparison exceeds visit budget');

    const emptyOperationOverBudget = structuredClone(comparison);
    emptyOperationOverBudget.allowed.defaults.methods = [];
    emptyOperationOverBudget.allowed.defaults.requiredHeaders = undefined;
    emptyOperationOverBudget.allowed.orderedRules = [];
    emptyOperationOverBudget.declared.operations = Array(1_000_001)
      .fill(emptyOperationOverBudget.declared.operations[0]);
    expect(() => compareAuthContracts(emptyOperationOverBudget))
      .toThrow('contract drift comparison exceeds visit budget');
    assertGolden('contract-drift-rules', {
      pathMethod: comparePathMethodContracts(input(
        contract([operation('POST', '/users')]),
        policy({ request: { allow_methods: ['GET', 'DELETE'], block: { header_missing: [] } } }),
      )),
      authentication: compareAuthContracts(input(
        contract([operation('GET', '/private', {
          exposure: 'authenticated',
          auth: {
            mode: 'alternatives',
            alternatives: [{ anonymous: false, schemes: [{
              name: 'key', kind: 'api-key', location: 'header', parameterName: 'x-client-key',
              scopes: [], capability: 'supported',
            }] }],
          },
        })]),
        policy({ routes: [{
          name: 'private', match: { path_prefixes: ['/private'] },
          auth_gate: { type: 'static_token', header: 'x-edge-key' },
        }] }),
      )),
      request: compareRequestContracts(input(
        contract([operation('GET', '/content', {
          request: {
            contentTypes: ['application/json'], requiredHeaders: ['x-contract'],
            queryParameters: [], pathParameters: [], headerParameters: [], cookieParameters: [],
          },
        })]),
        policy({ request: { allow_methods: ['GET'], block: { header_missing: ['x-policy'] } } }),
      )),
    });
  });
});
