import { describe, expect, test } from 'vitest';

import {
  compareSourcePolicyContracts,
  createSecurityContract,
  projectPolicyToAllowedSurface,
  type ApiOperationInputV1,
  type SecurityContractCapabilitiesV1,
} from '../../src/contract';
import type { CDNSecurityFrameworkPolicy } from '../../src/types/policy';

const digest = `sha256:${'a'.repeat(64)}`;
const request = {
  contentTypes: [], requiredHeaders: [], queryParameters: [], pathParameters: [],
  headerParameters: [], cookieParameters: [],
};

function operation(
  method: string,
  path: string,
  overrides: Partial<ApiOperationInputV1> = {},
): ApiOperationInputV1 {
  return {
    method,
    path,
    exposure: 'unknown',
    auth: { mode: 'unknown', alternatives: [] },
    request,
    provenance: [{
      source: 'source-ast', uri: 'src/controller.ts', pointer: `/routes/${method}-${path}`,
      digest, analyzer: 'nestjs@1', capability: 'nestjs-routes-v1', complete: true,
    }],
    ...overrides,
  };
}

function source(
  operations: ApiOperationInputV1[],
  capabilities: Partial<SecurityContractCapabilitiesV1> = {},
) {
  return createSecurityContract({
    source: 'source-ast',
    capabilities: {
      routes: 'complete', parameters: 'unsupported', requestBodies: 'unsupported',
      authentication: 'partial', ...capabilities,
    },
    operations,
  });
}

function policy(overrides: Partial<CDNSecurityFrameworkPolicy> = {}): CDNSecurityFrameworkPolicy {
  return {
    version: 1,
    defaults: { mode: 'enforce' },
    request: { allow_methods: ['GET'], block: { header_missing: [] } },
    routes: [],
    response_headers: {},
    ...overrides,
  };
}

function input(
  implemented: ReturnType<typeof source>,
  policyInput: CDNSecurityFrameworkPolicy,
  target: 'aws' | 'cloudflare' = 'aws',
) {
  return {
    implemented,
    implementedEvidence: {
      source: 'source-ast' as const, uri: 'tsconfig.json', digest,
      analyzer: 'nestjs@1', capability: 'nestjs-routes-v1',
      complete: implemented.capabilities.routes === 'complete',
    },
    allowed: projectPolicyToAllowedSurface(policyInput, {
      policyDigest: digest,
      sourceUri: 'policy/security.yml',
    }),
    target,
  } as const;
}

const sourceBearerAuth = {
  mode: 'alternatives' as const,
  alternatives: [{
    anonymous: false,
    schemes: [{ name: 'bearer', kind: 'bearer' as const, scopes: [], capability: 'supported' as const }],
  }],
  analysis: {
    guards: [{ symbol: 'JwtAuthGuard', authKind: 'bearer' as const }],
    explicitPublic: false,
    roles: [],
    enforcementConfidence: 'high' as const,
    capabilityReasons: [],
  },
};

describe('Source AST and Policy drift', () => {
  test('reports implemented operations blocked by the effective method set', () => {
    const enforce = compareSourcePolicyContracts(input(
      source([operation('POST', '/users')]),
      policy(),
    ));
    expect(enforce).toEqual(expect.arrayContaining([expect.objectContaining({
      ruleId: 'SC-EXPOSURE-004', severity: 'error', confidence: 'deterministic',
      route: expect.objectContaining({ method: 'POST', path: '/users' }),
    })]));
    const blocked = enforce.find(({ ruleId }) => ruleId === 'SC-EXPOSURE-004')!;
    expect(new Set(blocked.evidence.map(({ source: evidenceSource }) => evidenceSource)))
      .toEqual(new Set(['source-ast', 'policy']));

    expect(compareSourcePolicyContracts(input(
      source([operation('POST', '/users')]),
      policy({ defaults: { mode: 'monitor' } }),
    ))).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: 'SC-EXPOSURE-004', severity: 'warning' }),
    ]));
  });

  test('aggregates methods for exact and prefix Policy routes', () => {
    expect(compareSourcePolicyContracts(input(
      source([operation('GET', '/')]),
      policy({ request: { allow_methods: ['GET', 'DELETE'], block: { header_missing: [] } } }),
    ))).toEqual([expect.objectContaining({
      ruleId: 'SC-EXPOSURE-005', severity: 'error', route: { path: '/' },
      actual: expect.objectContaining({ extraMethods: ['DELETE'] }),
    })]);

    const findings = compareSourcePolicyContracts(input(
      source([
        operation('GET', '/users'),
        operation('DELETE', '/admin/users'),
        operation('GET', '/admin/audit'),
      ]),
      policy({
        request: { allow_methods: ['GET', 'POST', 'DELETE'], block: { header_missing: [] } },
        routes: [
          {
            name: 'users-exact', match: { path_prefixes: ['/users'] },
            auth_gate: { type: 'signed_url', exact_path: true },
          },
          {
            name: 'admin-prefix', match: { path_prefixes: ['/admin'] },
            auth_gate: { type: 'basic_auth' },
          },
        ],
      }),
    ));

    expect(findings.filter(({ ruleId }) => ruleId === 'SC-EXPOSURE-005'))
      .toEqual([
        expect.objectContaining({
          severity: 'error', confidence: 'deterministic', route: { path: '/users' },
          actual: expect.objectContaining({ extraMethods: ['DELETE', 'POST'] }),
        }),
        expect.objectContaining({
          severity: 'warning', confidence: 'heuristic', route: { path: '/admin' },
          actual: expect.objectContaining({ extraMethods: ['POST'] }),
        }),
      ]);

    expect(compareSourcePolicyContracts(input(
      source([operation('GET', '/users')]),
      policy({
        defaults: { mode: 'monitor' },
        routes: [{
          name: 'users-exact', match: { path_prefixes: ['/users'] },
          auth_gate: { type: 'signed_url', exact_path: true },
        }],
      }),
    ))).toEqual(expect.arrayContaining([expect.objectContaining({
      ruleId: 'SC-EXPOSURE-005', severity: 'warning',
      actual: expect.objectContaining({ methodSurface: 'unrestricted-by-edge-in-monitor-mode' }),
    })]));
  });

  test('gates absent exact Policy routes on Source route capability', () => {
    const policyInput = policy({ routes: [{
      name: 'missing', match: { path_prefixes: ['/missing'] },
      auth_gate: { type: 'signed_url', exact_path: true },
    }] });
    const complete = compareSourcePolicyContracts(input(source([]), policyInput));
    expect(complete).toEqual(expect.arrayContaining([expect.objectContaining({
        ruleId: 'SC-INVENTORY-005', severity: 'error', confidence: 'deterministic',
      })]));
    expect(new Set(complete[0].evidence.map(({ source: evidenceSource }) => evidenceSource)))
      .toEqual(new Set(['source-ast', 'policy']));
    expect(compareSourcePolicyContracts(input(source([], { routes: 'partial' }), policyInput)))
      .toEqual(expect.arrayContaining([expect.objectContaining({
        ruleId: 'SC-INVENTORY-005', severity: 'warning', confidence: 'heuristic',
      })]));

    expect(compareSourcePolicyContracts(input(
      source([operation('GET', '/missing/{id}')]),
      policy({ routes: [{
        name: 'concrete', match: { path_prefixes: ['/missing/123'] },
        auth_gate: { type: 'signed_url', exact_path: true },
      }] }),
    ))).toEqual(expect.arrayContaining([expect.objectContaining({
      ruleId: 'SC-INVENTORY-005', severity: 'warning', confidence: 'heuristic',
    })]));
  });

  test('compares only explicit Source authentication metadata with enforceable Edge gates', () => {
    const publicOperation = operation('GET', '/public', {
      exposure: 'public',
      auth: {
        mode: 'none', alternatives: [], analysis: {
          guards: [], explicitPublic: true, roles: [], enforcementConfidence: 'high',
          capabilityReasons: [],
        },
      },
    });
    const guardedOperation = operation('GET', '/private', {
      exposure: 'authenticated', auth: sourceBearerAuth,
    });
    const protectedPolicy = policy({ routes: [{
      name: 'public-gate', match: { path_prefixes: ['/public'] }, auth_gate: { type: 'basic_auth' },
    }] });

    expect(compareSourcePolicyContracts(input(source([publicOperation]), protectedPolicy)))
      .toEqual(expect.arrayContaining([expect.objectContaining({
        ruleId: 'SC-AUTHN-006', severity: 'error', confidence: 'deterministic',
      })]));
    expect(compareSourcePolicyContracts(input(source([guardedOperation]), policy())))
      .toEqual(expect.arrayContaining([expect.objectContaining({
        ruleId: 'SC-AUTHN-006', severity: 'warning',
      })]));
    expect(compareSourcePolicyContracts(input(source([operation('GET', '/unknown')]), policy())))
      .toEqual([]);

    const unsupportedGate = policy({ routes: [{
      name: 'unsupported-jwt', match: { path_prefixes: ['/public'] },
      auth_gate: { type: 'jwt', algorithm: 'unsupported' },
    }] });
    expect(compareSourcePolicyContracts(input(source([publicOperation]), unsupportedGate))
      .some(({ ruleId }) => ruleId === 'SC-AUTHN-006')).toBe(false);

    expect(compareSourcePolicyContracts(input(
      source([publicOperation], { routes: 'partial' }), protectedPolicy,
    ))).toEqual(expect.arrayContaining([expect.objectContaining({
      ruleId: 'SC-AUTHN-006', severity: 'warning', confidence: 'heuristic',
    })]));

    const publicOptions = operation('OPTIONS', '/public', {
      exposure: 'public', auth: publicOperation.auth,
    });
    const corsGate = policy({
      request: { allow_methods: ['OPTIONS'], block: { header_missing: [] } },
      response_headers: { cors: { allow_origins: ['https://client.example'] } },
      routes: [{
        name: 'cors-gate', match: { path_prefixes: ['/public'] },
        auth_gate: { type: 'basic_auth' },
      }],
    });
    expect(compareSourcePolicyContracts(input(source([publicOptions]), corsGate))
      .some(({ ruleId }) => ruleId === 'SC-AUTHN-006')).toBe(false);

    const emptyCorsGate = policy({
      request: { allow_methods: ['OPTIONS'], block: { header_missing: [] } },
      response_headers: { cors: { allow_origins: [] } },
      routes: [{
        name: 'empty-cors-gate', match: { path_prefixes: ['/public'] },
        auth_gate: { type: 'basic_auth' },
      }],
    });
    expect(compareSourcePolicyContracts(input(source([publicOptions]), emptyCorsGate)))
      .toEqual(expect.arrayContaining([expect.objectContaining({
        ruleId: 'SC-AUTHN-006', severity: 'error',
      })]));
  });

  test('reports role metadata as a recommendation without claiming enforcement', () => {
    const roleOperation = operation('GET', '/admin', {
      exposure: 'privileged',
      auth: { ...sourceBearerAuth, analysis: { ...sourceBearerAuth.analysis, roles: ['admin'] } },
      provenance: [
        ...operation('GET', '/admin').provenance,
        {
          ...operation('GET', '/admin').provenance[0],
          pointer: '/controllers/0/roles', capability: 'authorization', complete: true,
        },
      ],
    });
    const finding = compareSourcePolicyContracts(input(
      source([roleOperation]),
      policy({ routes: [{
        name: 'admin', match: { path_prefixes: ['/admin'] }, auth_gate: { type: 'basic_auth' },
      }] }),
    )).find(({ ruleId }) => ruleId === 'SC-AUTHZ-002');

    expect(finding).toMatchObject({ severity: 'info', category: 'authorization' });
    expect(finding?.message).toContain('does not prove authorization enforcement');

    expect(compareSourcePolicyContracts(input(
      source([roleOperation], { routes: 'partial' }),
      policy({ routes: [{
        name: 'admin', match: { path_prefixes: ['/admin'] }, auth_gate: { type: 'basic_auth' },
      }] }),
    )).find(({ ruleId }) => ruleId === 'SC-AUTHZ-002'))
      .toMatchObject({ confidence: 'heuristic' });

    const roleOptions = operation('OPTIONS', '/admin', {
      exposure: 'privileged', auth: roleOperation.auth, provenance: roleOperation.provenance,
    });
    expect(compareSourcePolicyContracts(input(
      source([roleOptions]),
      policy({
        request: { allow_methods: ['OPTIONS'], block: { header_missing: [] } },
        response_headers: { cors: { allow_origins: ['https://client.example'] } },
        routes: [{
          name: 'admin', match: { path_prefixes: ['/admin'] },
          auth_gate: { type: 'basic_auth' },
        }],
      }),
    )).find(({ ruleId }) => ruleId === 'SC-AUTHZ-002'))
      .toMatchObject({ severity: 'warning', confidence: 'heuristic' });
  });

  test('deduplicates controller candidates and returns stable output', () => {
    const duplicate = operation('GET', '/duplicate', {
      provenance: [{
        ...operation('GET', '/duplicate').provenance[0], pointer: '/controllers/0',
      }, {
        ...operation('GET', '/duplicate').provenance[0], pointer: '/controllers/1',
      }],
    });
    const comparison = input(
      source([duplicate]),
      policy({ request: { allow_methods: ['GET', 'POST'], block: { header_missing: [] } } }),
    );
    const findings = compareSourcePolicyContracts(comparison);

    expect(findings).toEqual(compareSourcePolicyContracts(comparison));
    expect(new Set(findings.map(({ instanceId }) => instanceId)).size).toBe(findings.length);
    expect(findings.filter(({ ruleId }) => ruleId === 'SC-EXPOSURE-005')).toHaveLength(1);
  });

  test('bounds repeated prefix evidence output', () => {
    const implemented = source([operation('GET', '/admin')]);
    const evidence = implemented.operations[0].provenance[0];
    implemented.operations[0].provenance = new Array(1_000_001).fill(evidence);

    expect(() => compareSourcePolicyContracts(input(
      implemented,
      policy({
        request: { allow_methods: ['GET', 'POST'], block: { header_missing: [] } },
        routes: [{
          name: 'admin', match: { path_prefixes: ['/admin'] }, auth_gate: { type: 'basic_auth' },
        }],
      }),
    ))).toThrow('source Policy drift comparison exceeds visit budget');
  });
});
