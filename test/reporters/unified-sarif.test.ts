import { describe, expect, test } from 'vitest';

import { createFinding, type ContractDiffReportV1 } from '../../src/contract';
import {
  SarifReportError,
  renderUnifiedContractDiffSarif,
} from '../../src/reporters/sarif';

function report(): ContractDiffReportV1 {
  const finding = createFinding({
    ruleId: 'SC-INVENTORY-001',
    severity: 'warning',
    confidence: 'high-confidence',
    category: 'exposure',
    title: 'Route differs from the allowed surface',
    message: 'The declared route is not represented by the allowed policy.',
    route: { method: 'GET', path: '/admin' },
    evidence: [
      {
        source: 'policy', uri: 'policy/security.yml', pointer: '/routes/0', digest: 'sha256:policy',
        analyzer: 'policy@1', capability: 'policy-routes-v1', complete: true,
      },
      {
        source: 'openapi', uri: 'openapi.yaml', pointer: '/paths/~1admin/get', digest: 'sha256:openapi',
        analyzer: 'openapi@1', capability: 'openapi-routes-v1', complete: true,
      },
      {
        source: 'source-ast', uri: 'src/admin.ts', pointer: 'line:12:column:3', digest: 'sha256:source',
        analyzer: 'source@1', capability: 'source-routes-v1', complete: true,
      },
      {
        source: 'source-ast', uri: 'src/admin.ts', pointer: 'line:12:column:3', digest: 'sha256:duplicate',
        analyzer: 'source@2', capability: 'source-routes-v1', complete: true,
      },
    ],
  });
  return {
    schemaVersion: 1,
    inputDigests: { openapi: 'sha256:openapi', policy: 'sha256:policy', exceptions: null },
    target: 'aws',
    summary: {
      total: 1, error: 0, warning: 1, info: 0, suppressed: 0,
      bySeverity: { error: 0, warning: 1, info: 0 },
      byConfidence: { deterministic: 0, 'high-confidence': 1, heuristic: 0 },
      byCategory: {
        inventory: 0, exposure: 1, authentication: 0, authorization: 0,
        'resource-limit': 0, misconfiguration: 0, governance: 0, 'runtime-evidence': 0,
      },
    },
    findings: [finding],
    suppressedFindings: [],
    exceptionDiagnostics: [],
    appliedExceptionIds: [],
    analyzerCapabilities: {
      openapi: { routes: 'partial', parameters: 'complete', requestBodies: 'complete', authentication: 'complete' },
      policy: [{ id: 'request.header_limits', status: 'partial' }],
    },
    analyzerDiagnostics: [],
    omittedComparisons: ['implemented-vs-allowed:omitted'],
  };
}

describe('Unified contract SARIF adapter', () => {
  test('selects source primary, deduplicates related locations, and preserves order', () => {
    const input = report();
    const first = renderUnifiedContractDiffSarif(input);
    const second = renderUnifiedContractDiffSarif({
      ...input,
      findings: input.findings.map((finding) => ({
        ...finding,
        evidence: [...finding.evidence].reverse(),
      })),
  });

    expect(second).toEqual(first);
    const result = first.runs[0].results[0];
    expect(result.locations?.[0].physicalLocation.artifactLocation.uri).toBe('src/admin.ts');
    expect(result.locations?.[0].physicalLocation.region).toEqual({ startLine: 12, startColumn: 3 });
    expect(result.relatedLocations?.map(({ physicalLocation }) => physicalLocation.artifactLocation.uri))
      .toEqual(['openapi.yaml', 'policy/security.yml']);
    expect(first.runs[0].tool.driver.properties).toMatchObject({
      omittedComparisons: ['implemented-vs-allowed:omitted'],
      capabilities: { openapi: { routes: 'partial' } },
    });
    expect(first.runs[0].invocations?.[0].toolExecutionNotifications?.[0].descriptor.id)
      .toBe('SARIF_CAPABILITY_PARTIAL');
  });

  test('bounds related locations/results and rejects unsafe data without emitting it', () => {
    const input = report();
    const bounded = renderUnifiedContractDiffSarif(input, { maxRelatedLocations: 1, maxResults: 1 });
    expect(bounded.runs[0].results[0].relatedLocations).toHaveLength(1);

    const unsafe = {
      ...input,
      findings: input.findings.map((finding) => ({
        ...finding,
        message: 'Bearer super-secret',
        evidence: [{ ...finding.evidence[0], uri: 'https://evil.example/secret?token=leak' }],
      })),
    };
    expect(() => renderUnifiedContractDiffSarif(unsafe)).toThrowError(SarifReportError);
    try {
      renderUnifiedContractDiffSarif(unsafe);
    } catch (error) {
      expect((error as SarifReportError).code).toBe('SARIF_PRIVACY_VIOLATION');
      expect((error as Error).message).not.toContain('super-secret');
    }

    expect(() => renderUnifiedContractDiffSarif(input, { maxOutputBytes: 64 }))
      .toThrowError(/SARIF_OUTPUT_LIMIT_EXCEEDED/);
  });

  test.each([
    ['Bearer [REDACTED]actual-token', true],
    ['?token=[REDACTED]actual-token', true],
    ['Bearer [REDACTED]', false],
    ['?token=[REDACTED]', false],
  ])('handles redaction marker boundaries: %s', (message, shouldReject) => {
    const input = report();
    input.findings = input.findings.map((finding) => ({ ...finding, message }));
    if (shouldReject) {
      expect(() => renderUnifiedContractDiffSarif(input)).toThrowError(/SARIF_PRIVACY_VIOLATION/);
    } else {
      expect(() => renderUnifiedContractDiffSarif(input)).not.toThrow();
    }
    });

  test('uses a deterministic full-finding tie-breaker before maxResults', () => {
    const input = report();
    const seed = input.findings[0];
    const findingInput = {
      ruleId: seed.ruleId,
      severity: seed.severity,
      confidence: seed.confidence,
      category: seed.category,
      route: seed.route,
      evidence: seed.evidence,
    };
    const first = createFinding({ ...findingInput, title: 'First finding', message: 'First finding' });
    const second = createFinding({ ...findingInput, title: 'Second finding', message: 'Second finding' });
    expect(second.instanceId).toBe(first.instanceId);
    const result = renderUnifiedContractDiffSarif({
      ...input,
      findings: [second, first],
    }, { maxResults: 1 });

    expect(result.runs[0].results[0].message.text).toBe('First finding');
  });

  test('uses the rule-family primary-source allowlist instead of always selecting Source', () => {
    const input = report();
    const openApiPrimary = renderUnifiedContractDiffSarif({
      ...input,
      findings: [createFinding({
        ...input.findings[0],
        ruleId: 'SC-REQUEST-001',
      })],
    });
    expect(openApiPrimary.runs[0].results[0].locations?.[0].physicalLocation.artifactLocation.uri)
      .toBe('openapi.yaml');

    const policyPrimary = renderUnifiedContractDiffSarif({
      ...input,
      findings: [createFinding({
        ...input.findings[0],
        ruleId: 'SC-REQUEST-002',
      })],
    });
    expect(policyPrimary.runs[0].results[0].locations?.[0].physicalLocation.artifactLocation.uri)
      .toBe('policy/security.yml');

    const unknownRule = {
      ...input,
      findings: [createFinding({
        ...input.findings[0],
        ruleId: 'SC-TEST-001',
      })],
    };
    expect(() => renderUnifiedContractDiffSarif(unknownRule)).toThrowError(/SARIF_UNIFIED_REPORT_INVALID/);
  });
});
