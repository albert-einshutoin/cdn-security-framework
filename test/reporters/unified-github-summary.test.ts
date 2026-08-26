import { describe, expect, test } from 'vitest';

import { createFinding, type ContractDiffReportV1 } from '../../src/contract';
import { renderUnifiedGitHubSummary } from '../../src/reporters/github-summary';

const evidence = [
  {
    source: 'openapi' as const,
    uri: 'openapi.yaml',
    pointer: '/paths/~1admin/get',
    digest: 'sha256:openapi',
    analyzer: 'openapi@1',
    capability: 'openapi-routes-v1',
    complete: true,
  },
  {
    source: 'policy' as const,
    uri: 'policy/security.yml',
    pointer: '/routes/0',
    digest: 'sha256:policy',
    analyzer: 'policy@1',
    capability: 'policy-routes-v1',
    complete: true,
  },
];

function report(includeSource = true): ContractDiffReportV1 {
  const finding = createFinding({
    ruleId: 'SC-EXPOSURE-001',
    severity: 'error',
    confidence: 'deterministic',
    category: 'exposure',
    title: '<script>alert(1)</script> | extra method',
    message: 'Full details remain in the artifact.',
    route: { method: 'GET', path: '/admin?token=raw-secret' },
    evidence: includeSource ? [...evidence, {
      source: 'source-ast' as const,
      uri: 'src/admin.ts',
      pointer: 'line:12:column:3',
      digest: 'sha256:source',
      analyzer: 'source@1',
      capability: 'source-routes-v1',
      complete: true,
    }] : evidence,
  });
  return {
    schemaVersion: 1,
    inputDigests: { openapi: 'sha256:o', policy: 'sha256:p', exceptions: null },
    target: 'aws',
    summary: {
      total: 1, error: 1, warning: 0, info: 0, suppressed: 1,
      bySeverity: { error: 1, warning: 0, info: 0 },
      byConfidence: { deterministic: 1, 'high-confidence': 0, heuristic: 0 },
      byCategory: {
        inventory: 0, exposure: 1, authentication: 0, authorization: 0,
        'resource-limit': 0, misconfiguration: 0, governance: 0, 'runtime-evidence': 0,
      },
    },
    findings: [finding],
    suppressedFindings: [],
    exceptionDiagnostics: [],
    appliedExceptionIds: ['EXC-2026-001'],
    analyzerCapabilities: {
      openapi: { routes: 'partial', parameters: 'complete' },
      policy: [{ id: 'request.header_limits', status: 'partial' }],
    },
    analyzerDiagnostics: [{
      code: 'OPENAPI_CAPABILITY_PARTIAL',
      level: 'warning',
      message: 'review <script>|token=raw-secret',
      capability: 'routes',
    }],
    omittedComparisons: ['openapi.routes:partial'],
  };
}

describe('Unified GitHub Step Summary reporter', () => {
  test('renders stable three-way status and safe top findings', () => {
    const input = report();
    const summary = renderUnifiedGitHubSummary(input, { status: 'success' });
    const reversed = renderUnifiedGitHubSummary({ ...input, findings: [...input.findings].reverse() });

    expect(summary).toBe(reversed);
    expect(summary).toContain('**Result: Passed**');
    expect(summary).toContain('## Analysis status');
    expect(summary).toContain('| Implemented (Source) | completed |');
    expect(summary).toContain('## Comparison status');
    expect(summary).toContain('| Declared vs Allowed | partial |');
    expect(summary).toContain('## Capabilities and coverage');
    expect(summary).toContain('Analyzer diagnostics:');
    expect(summary).toContain('## Exceptions');
    expect(summary).toContain('three-way');
    expect(summary).not.toMatch(/raw-secret|token=|<script>|<\/script>/i);
    expect(summary).not.toContain('\u202E');
  });

  test('distinguishes omitted source analysis from zero findings and bounds top-N', () => {
    const summary = renderUnifiedGitHubSummary(report(false), { status: 'threshold-reached', exitCode: 1 }, {
      maxFindings: 0,
    });

    expect(summary).toContain('**Result: Findings**');
    expect(summary).toContain('| Implemented (Source) | omitted | Source analysis was not requested |');
    expect(summary).toContain('| Implemented vs Declared | omitted | not evaluated |');
    expect(summary).toContain('| - | - | - | - | - | No findings | - |');
    expect(summary).toContain('1 additional findings are available');
  });

  test('does not present a failed tool as a successful report', () => {
    const summary = renderUnifiedGitHubSummary(undefined, {
      status: 'error',
      errorCode: 'OPENAPI_PARSE_ERROR',
      phase: 'openapi',
      safeMessage: 'OpenAPI document could not be parsed: /Users/alice/secret?token=raw-secret',
    });

    expect(summary).toContain('**Result: Tool Error**');
    expect(summary).toContain('`OPENAPI_PARSE_ERROR`');
    expect(summary).toContain('No report was emitted');
    expect(summary).not.toContain('## Finding counts');
    expect(summary).not.toMatch(/raw-secret|\/Users\/alice|token=/i);
  });

  test('removes URI schemes, absolute paths, and Markdown syntax from dynamic text', () => {
    const summary = renderUnifiedGitHubSummary(undefined, {
      status: 'tool-error',
      safeMessage: 'file:///etc/passwd ftp://evil.example data:text/html,<script> *bold* _italic_ #heading ![x](https://evil.example) ~strike~ \\path',
    });

    expect(summary).not.toMatch(/file:\/\/|ftp:\/\/|data:|\/etc\/passwd|<script>|\*bold\*|_italic_|#heading|!\[x\]|~strike~|\\path/i);
  });

  test('keeps output within the configured UTF-8 byte limit with a marker', () => {
    const summary = renderUnifiedGitHubSummary(report(), 'passed', { maxOutputBytes: 320 });
    expect(Buffer.byteLength(summary, 'utf8')).toBeLessThanOrEqual(320);
    expect(summary).toContain('Output truncated');
  });
});
