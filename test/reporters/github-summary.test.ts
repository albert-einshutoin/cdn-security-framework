import { describe, expect, test } from 'vitest';

import { createFinding, type ContractDiffReportV1, type FindingInputV1 } from '../../src/contract';
import { renderContractDiffGitHubSummary } from '../../src/reporters/github-summary';

const evidence = [{
  source: 'openapi' as const,
  uri: 'openapi.yaml',
  digest: 'sha256:openapi',
  analyzer: 'openapi@1',
  capability: 'openapi-v1',
  complete: true,
}];

function finding(overrides: Partial<FindingInputV1> & Pick<FindingInputV1, 'ruleId'>) {
  return createFinding({
    severity: 'warning',
    confidence: 'deterministic',
    category: 'exposure',
    title: 'Contract drift',
    message: 'Details stay in the full artifact.',
    evidence,
    ...overrides,
  });
}

function report(): ContractDiffReportV1 {
  const findings = [
    finding({
      ruleId: 'SC-AUTHN-001', category: 'authentication', severity: 'error',
      title: 'Authentication mismatch', route: { method: 'GET', path: '/admin\u202E?token=raw-secret' },
    }),
    finding({ ruleId: 'SC-EXPOSURE-001', title: 'Extra method' }),
    finding({ ruleId: 'SC-INVENTORY-002', category: 'inventory', title: 'Removed route' }),
    finding({ ruleId: 'SC-LIMIT-001', category: 'resource-limit', title: 'Request limit mismatch' }),
    finding({ ruleId: 'SC-REQUEST-001', category: 'misconfiguration', title: 'Header mismatch' }),
    ...Array.from({ length: 7 }, (_, index) => finding({
      ruleId: `SC-RUNTIME-${String(index + 1).padStart(3, '0')}`,
      category: 'runtime-evidence', severity: 'info', title: `Runtime candidate ${index + 1}`,
    })),
  ];
  const expired = finding({
    ruleId: 'SC-GOV-001', category: 'governance', severity: 'error', title: 'Expired exception',
  });
  return {
    schemaVersion: 1,
    inputDigests: { openapi: 'sha256:o', policy: 'sha256:p', exceptions: 'sha256:e' },
    target: 'aws',
    summary: {
      total: 13, error: 2, warning: 4, info: 7, suppressed: 1,
      bySeverity: { error: 2, warning: 4, info: 7 },
      byConfidence: { deterministic: 13, 'high-confidence': 0, heuristic: 0 },
      byCategory: {
        inventory: 1, exposure: 1, authentication: 1, authorization: 0,
        'resource-limit': 1, misconfiguration: 1, governance: 1, 'runtime-evidence': 7,
      },
    },
    findings,
    suppressedFindings: [],
    exceptionDiagnostics: [expired],
    appliedExceptionIds: ['EXC-2026-001'],
    analyzerCapabilities: {
      openapi: { operation_inventory: 'complete', security_requirements: 'complete', request_constraints: 'partial' },
      policy: [],
    },
    analyzerDiagnostics: [],
    omittedComparisons: ['openapi.request_constraints:partial'],
  };
}

describe('GitHub Step Summary reporter', () => {
  test('shows bounded decision data without raw query or secret values', () => {
    const input = report();
    const before = JSON.stringify(input);
    const summary = renderContractDiffGitHubSummary(input);

    expect(JSON.stringify(input)).toBe(before);
    expect(summary).toContain('| Error | Warning | Info | Suppressed | Expired exceptions |');
    expect(summary).toContain('| 2 | 4 | 7 | 1 | 1 |');
    expect(summary).toContain('| New / removed routes | 1 |');
    expect(summary).toContain('| Extra / blocked methods | 1 |');
    expect(summary).toContain('| Authentication / authorization drift | 1 |');
    expect(summary).toContain('| Limit / header / content-type drift | 2 |');
    expect(summary).toContain('**Coverage warning:** 1 comparison(s) omitted or unknown.');
    expect(summary).toContain('`GET /admin`');
    expect(summary).not.toMatch(/raw-secret|token=|cookie=/i);
    expect(summary).not.toContain('\u202E');
    expect(summary.match(/^\| (?:error|warning|info) \|/gm)).toHaveLength(10);
    expect(summary).toContain('3 additional findings are available in the JSON and SARIF artifacts.');
    expect(summary).toContain('`contract-diff.json` and `cdn-security.sarif`');
  });

  test('is byte-identical for equivalent input ordering', () => {
    const input = report();
    expect(renderContractDiffGitHubSummary({
      ...input, findings: [...input.findings].reverse(),
    })).toBe(renderContractDiffGitHubSummary(input));
  });

  test('uses the selected failure threshold for the gate status', () => {
    const input = report();
    const warningsOnly = {
      ...input,
      summary: {
        ...input.summary,
        error: 0,
        bySeverity: { ...input.summary.bySeverity, error: 0 },
      },
    };
    expect(renderContractDiffGitHubSummary(warningsOnly, { failOn: 'warning' }))
      .toContain('**Gate: failing**');
    expect(renderContractDiffGitHubSummary(input, { failOn: 'never' }))
      .toContain('**Gate: passing**');
  });

  test('omits the coverage warning when every comparison ran', () => {
    expect(renderContractDiffGitHubSummary({ ...report(), omittedComparisons: [] }))
      .not.toContain('Coverage warning');
  });
});
