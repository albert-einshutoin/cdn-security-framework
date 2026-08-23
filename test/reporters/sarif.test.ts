import Ajv from 'ajv';
import { describe, expect, test } from 'vitest';

import { createFinding, type ContractDiffReportV1 } from '../../src/contract';
import { renderFindingsAsSarif } from '../../src/reporters/sarif';
import { assertGolden } from '../helpers/golden-assert';

function report(): ContractDiffReportV1 {
  const active = createFinding({
    ruleId: 'SC-AUTHN-001',
    severity: 'error',
    confidence: 'deterministic',
    category: 'authentication',
    title: 'Authentication contract mismatch',
    message: 'The operation requires authentication but the edge policy does not enforce it.',
    route: { method: 'GET', path: '/admin' },
    evidence: [
      {
        source: 'policy',
        uri: 'policy/security.yml',
        pointer: '/routes/0/auth_gate',
        digest: 'sha256:policy',
        analyzer: 'policy@1',
        capability: 'policy-routes-v1',
        complete: true,
      },
      {
        source: 'openapi',
        uri: 'openapi.yaml',
        pointer: '/paths/~1admin/get/security',
        digest: 'sha256:openapi',
        analyzer: 'openapi@1',
        capability: 'openapi-security-v1',
        complete: true,
      },
    ],
    remediation: { summary: 'Add an enforced auth gate for this route.', safeAutoFix: false },
  });
  const suppressed = createFinding({
    ruleId: 'SC-EXPOSURE-001',
    severity: 'warning',
    confidence: 'high-confidence',
    category: 'exposure',
    title: 'Undeclared public route',
    message: 'The route is public but is not declared as public in OpenAPI.',
    evidence: [{
      source: 'openapi',
      uri: 'openapi.yaml',
      digest: 'sha256:openapi',
      analyzer: 'openapi@1',
      capability: 'openapi-security-v1',
      complete: true,
    }],
  });
  const noLocation = { ...active, ruleId: 'SC-GOV-001', instanceId: '0'.repeat(64), evidence: [] };
  return {
    schemaVersion: 1,
    inputDigests: { openapi: 'sha256:openapi', policy: 'sha256:policy', exceptions: 'sha256:exceptions' },
    target: 'aws',
    summary: {
      total: 2, error: 2, warning: 0, info: 0, suppressed: 1,
      bySeverity: { error: 2, warning: 0, info: 0 },
      byConfidence: { deterministic: 2, 'high-confidence': 0, heuristic: 0 },
      byCategory: {
        inventory: 0, exposure: 0, authentication: 1, authorization: 0,
        'resource-limit': 0, misconfiguration: 0, governance: 1, 'runtime-evidence': 0,
      },
    },
    findings: [noLocation, active],
    suppressedFindings: [suppressed],
    exceptionDiagnostics: [],
    appliedExceptionIds: ['EXC-2026-001'],
    analyzerCapabilities: {
      openapi: { operation_inventory: 'complete', security_requirements: 'complete', request_constraints: 'partial' },
      policy: [],
    },
    analyzerDiagnostics: [],
    omittedComparisons: [],
  };
}

describe('SARIF 2.1.0 reporter', () => {
  test('renders deterministic rules, locations, fingerprints, and suppressions', () => {
    const input = report();
    const before = JSON.stringify(input);
    const first = renderFindingsAsSarif(input);
    const second = renderFindingsAsSarif({
      ...input,
      findings: [...input.findings].reverse(),
      suppressedFindings: [...input.suppressedFindings].reverse(),
    });

    expect(second).toEqual(first);
    expect(JSON.stringify(second)).toBe(JSON.stringify(first));
    expect(JSON.stringify(input)).toBe(before);
    expect(first.version).toBe('2.1.0');
    expect(first.runs[0].tool.driver.rules.map(({ id }) => id)).toEqual([
      'SC-AUTHN-001', 'SC-EXPOSURE-001', 'SC-GOV-001',
    ]);
    expect(first.runs[0].results.map(({ ruleId }) => ruleId)).toEqual([
      'SC-AUTHN-001', 'SC-GOV-001', 'SC-EXPOSURE-001',
    ]);
    expect(first.runs[0].results[0].relatedLocations).toHaveLength(1);
    expect(first.runs[0].results[1].locations).toBeUndefined();
    expect(first.runs[0].results[2].suppressions).toEqual([{ kind: 'external', status: 'accepted' }]);
    const validate = new Ajv({ strict: false }).compile({
      type: 'object', required: ['$schema', 'version', 'runs'],
      properties: {
        version: { const: '2.1.0' },
        runs: {
          type: 'array', minItems: 1,
          items: {
            type: 'object', required: ['tool', 'results'],
            properties: {
              tool: {
                type: 'object', required: ['driver'],
                properties: {
                  driver: {
                    type: 'object', required: ['name', 'version', 'rules'],
                    properties: { rules: { type: 'array' } },
                  },
                },
              },
              results: {
                type: 'array',
                items: {
                  type: 'object', required: ['ruleId', 'level', 'message', 'partialFingerprints'],
                  properties: { level: { enum: ['error', 'warning', 'note'] } },
                },
              },
            },
          },
        },
      },
    });
    expect(validate(first), JSON.stringify(validate.errors)).toBe(true);
    expect(JSON.stringify(first)).not.toMatch(/timestamp|runId|\/Users\/|Authorization|Cookie/i);
    assertGolden('finding-sarif-2.1.0', first);
  });

  test.each(['/Users/alice/policy.yml', 'policy.yml?token=raw-secret', '../policy.yml'])(
    'rejects unsafe evidence URI %s',
    (uri) => {
      const input = report();
      input.findings[0] = {
        ...input.findings[0],
        evidence: [{
          source: 'policy', uri, digest: 'sha256:x',
          analyzer: 'policy@1', capability: 'policy-v1', complete: true,
        }],
      };
      expect(() => renderFindingsAsSarif(input)).toThrow(/workspace-relative/);
    },
  );
});
