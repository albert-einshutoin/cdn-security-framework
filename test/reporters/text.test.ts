import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';

const { diffSecurityContracts } = require('../../contract') as typeof import('../../src/contract');
const { renderUnifiedContractDiffText } = require('../../reporters/text') as typeof import('../../src/reporters/text');

function reportFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'contract-text-'));
  const openapiPath = path.join(root, 'openapi.yaml');
  const policyPath = path.join(root, 'security.yml');
  fs.writeFileSync(openapiPath, `openapi: 3.1.0
info: { title: Contract, version: 1.0.0 }
paths:
  /health:
    get:
      security: []
      responses:
        '200': { description: OK }
`);
  fs.writeFileSync(policyPath, `version: 1
defaults: { mode: enforce }
request:
  allow_methods: [GET]
  limits: { max_uri_length: 21 }
  block: { header_missing: [] }
routes: []
response_headers: {}
`);
  return diffSecurityContracts({
    openapiPath,
    policyPath,
    target: 'aws',
    workspaceRoot: root,
    currentDate: '2026-08-23',
  });
}

function finding(instanceId: string, severity: 'error' | 'warning' | 'info') {
  return {
    schemaVersion: 1 as const,
    ruleId: `SC-TST-${instanceId.slice(-3)}`,
    instanceId,
    severity,
    confidence: 'deterministic' as const,
    category: 'exposure' as const,
    title: `Unexpected \u001b]8;;https://example.invalid\u0007route\u001b]8;;\u0007 ${instanceId}`,
    message: 'token=super-secret should never be printed',
    route: { method: 'GET', path: '/users?token=super-secret#fragment' },
    expected: { authorization: 'Bearer super-secret', safe: 'ok' },
    actual: { password: 'super-secret', count: 1 },
    evidence: [{
      source: 'openapi' as const,
      uri: 'openapi.yaml?token=super-secret',
      pointer: '/paths/~1users/get',
      digest: 'sha256:abc',
      analyzer: 'test',
      capability: 'routes',
      complete: true,
    }],
    remediation: { summary: 'Review the route policy', safeAutoFix: false },
  };
}

describe('Unified contract text reporter', () => {
  test('renders ordered analysis, comparison, capability, findings, and suppression sections', () => {
    const report = reportFixture();
    const text = renderUnifiedContractDiffText(report);

    expect(text.startsWith('Summary:')).toBe(true);
    expect(text).toContain('Input analysis:');
    expect(text).toContain('Comparison:');
    expect(text).toContain('Capabilities:');
    expect(text).toContain('Findings:');
    expect(text).toContain('evaluated=0 (no findings)');
    expect(text).toContain('not evaluated:');
    expect(text).toContain('policy.request.header_limits:partial');
    expect(text.endsWith('\n')).toBe(true);
  });

  test('keeps findings stable and does not leak query, control, or secret values', () => {
    const base = reportFixture();
    const first = finding('finding-001', 'warning');
    const second = finding('finding-002', 'error');
    const report = {
      ...base,
      summary: {
        ...base.summary,
        total: 2,
        error: 1,
        warning: 1,
        bySeverity: { ...base.summary.bySeverity, error: 1, warning: 1 },
        byCategory: { ...base.summary.byCategory, exposure: 2 },
      },
      findings: [first, second],
      omittedComparisons: ['openapi.parameters:unsupported'],
      analyzerCapabilities: {
        ...base.analyzerCapabilities,
        openapi: { routes: 'complete', parameters: 'unsupported', requestBodies: 'partial', authentication: 'complete' },
      },
    };

    const output = renderUnifiedContractDiffText(report);
    const reordered = renderUnifiedContractDiffText({ ...report, findings: [second, first] });
    expect(output).toBe(reordered);
    expect(output).not.toContain('super-secret');
    expect(output).not.toContain('token=super-secret');
    expect(output).toContain('GET /users');
    expect(output).toContain('unsupported');
    expect(output).not.toContain('\u001b]');

    const headerCredential = { ...first, message: 'authorization: Basic Zm9vOmJhcg==' };
    const headerOutput = renderUnifiedContractDiffText({ ...report, findings: [headerCredential] });
    expect(headerOutput).not.toContain('Zm9vOmJhcg==');
    expect(headerOutput).toContain('authorization=[REDACTED]');

    const schemeOutput = renderUnifiedContractDiffText({
      ...report,
      findings: [
        { ...first, message: 'Basic basic-secret' },
        { ...first, message: 'Digest username="user", response="standalone-digest-secret"' },
        { ...first, message: 'Negotiate negotiate-secret' },
        { ...first, message: 'Authorization: Digest username="user",\n response="folded-lf-secret"' },
        { ...first, message: 'Authorization: Digest username="user",\r\n signature="folded-crlf-secret"' },
      ],
    });
    expect(schemeOutput).not.toContain('basic-secret');
    expect(schemeOutput).not.toContain('standalone-digest-secret');
    expect(schemeOutput).not.toContain('negotiate-secret');
    expect(schemeOutput).not.toContain('folded-lf-secret');
    expect(schemeOutput).not.toContain('folded-crlf-secret');

    const multipartHeaders = renderUnifiedContractDiffText({
      ...report,
      findings: [
        { ...first, message: 'authorization: Digest username="user", response="digest-secret"' },
        { ...first, message: 'cookie: session=session-secret; refresh=refresh-secret' },
      ],
    });
    expect(multipartHeaders).not.toContain('digest-secret');
    expect(multipartHeaders).not.toContain('session-secret');
    expect(multipartHeaders).not.toContain('refresh-secret');

    const unsafe = { ...report, findings: [{ ...first, evidence: [{ ...first.evidence[0], uri: '/Users/private/source.yaml' }] }] };
    expect(renderUnifiedContractDiffText(unsafe)).toContain('evidence=[external]');
    const remote = { ...report, findings: [{ ...first, evidence: [{ ...first.evidence[0], uri: 'https://evil.example/secret?token=leak' }] }] };
    expect(renderUnifiedContractDiffText(remote)).toContain('evidence=[external]');
  });

  test('redacts provider tokens that cross the terminal field boundary', () => {
    const base = reportFixture();
    const item = finding('finding-005', 'warning');
    const output = renderUnifiedContractDiffText({
      ...base,
      findings: [{
        ...item,
        message: `${'x'.repeat(502)} sk-proj-syntheticvalue1234567890`,
      }],
    });

    expect(output).not.toContain('sk-proj-s');
  });

  test('redacts every value after an auth scheme delimiter', () => {
    const base = reportFixture();
    const item = finding('finding-006', 'warning');
    const output = renderUnifiedContractDiffText({
      ...base,
      findings: [{ ...item, message: 'Bearer first-secret, second-secret' }],
    });

    expect(output).not.toContain('first-secret');
    expect(output).not.toContain('second-secret');
  });

  test('distinguishes omitted comparisons and bounds findings/output', () => {
    const base = reportFixture();
    const findings = [finding('finding-001', 'error'), finding('finding-002', 'warning')];
    const report = {
      ...base,
      summary: {
        ...base.summary,
        total: 2,
        error: 1,
        warning: 1,
        bySeverity: { ...base.summary.bySeverity, error: 1, warning: 1 },
        byCategory: { ...base.summary.byCategory, exposure: 2 },
      },
      findings,
      omittedComparisons: ['openapi.parameters:unsupported'],
    };
    const output = renderUnifiedContractDiffText(report, {
      maxFindings: 1,
      maxOutputBytes: 1_300,
    });

    expect(renderUnifiedContractDiffText(report, { maxFindings: 1 }))
      .toContain('1 additional finding(s) omitted by maxFindings.');
    expect(Buffer.byteLength(output, 'utf8')).toBeLessThanOrEqual(1_300);
    expect(output).toContain('[output truncated');
  });

  test('renders suppressed findings only when requested', () => {
    const base = reportFixture();
    const suppressed = finding('finding-003', 'info');
    const report = {
      ...base,
      summary: { ...base.summary, suppressed: 1 },
      suppressedFindings: [suppressed],
    };

    expect(renderUnifiedContractDiffText(report, { includeSuppressed: false }))
      .not.toContain('Suppressed findings:');
    expect(renderUnifiedContractDiffText(report, { includeSuppressed: true }))
      .toContain('Suppressed findings:');
  });

  test('keeps ANSI opt-in and disabled output terminal-safe', () => {
    const base = reportFixture();
    const report = {
      ...base,
      summary: { ...base.summary, total: 1, warning: 1, bySeverity: { ...base.summary.bySeverity, warning: 1 } },
      findings: [finding('finding-004', 'warning')],
    };
    expect(renderUnifiedContractDiffText(report)).not.toContain('\u001b[');
    expect(renderUnifiedContractDiffText(report, { color: true })).toContain('\u001b[33mWARNING');

    const coloredFull = renderUnifiedContractDiffText(report, { color: true, maxOutputBytes: 100_000 });
    const firstAnsi = coloredFull.indexOf('\u001b[33m');
    if (firstAnsi < 0) throw new Error('Expected a colored finding in the full report');
    const truncationLimit = Array.from({ length: 128 }, (_, offset) => firstAnsi + offset)
      .find((limit) => limit - Buffer.byteLength(`\n[output truncated at ${limit} bytes]\n`, 'utf8') >= firstAnsi
        && limit - Buffer.byteLength(`\n[output truncated at ${limit} bytes]\n`, 'utf8') < firstAnsi + '\u001b[33m'.length);
    if (truncationLimit === undefined) throw new Error('Could not choose an ANSI-boundary truncation limit');
    const truncated = renderUnifiedContractDiffText(report, { color: true, maxOutputBytes: truncationLimit });
    const ansiTokens = truncated.match(/\u001b\[[0-9;]*m/g) ?? [];
    expect(truncated.replace(/\u001b\[[0-9;]*m/g, '')).not.toContain('\u001b');
    expect(ansiTokens.filter((token) => token !== '\u001b[0m')).toHaveLength(
      ansiTokens.filter((token) => token === '\u001b[0m').length,
    );
  });

  test('bounds exception diagnostics with maxFindings', () => {
    const base = reportFixture();
    const first = finding('finding-005', 'error');
    const second = finding('finding-006', 'warning');
    const output = renderUnifiedContractDiffText({
      ...base,
      exceptionDiagnostics: [first, second],
    }, { maxFindings: 0 });

    expect(output).toContain('Exception/governance diagnostics:');
    expect(output).toContain('2 additional finding(s) omitted by maxFindings.');
    expect(output).not.toContain('finding-005');
    expect(output).not.toContain('finding-006');
  });

  test('pins the no-source text contract', () => {
    const report = reportFixture();
    const output = renderUnifiedContractDiffText(report)
      .replace(/^(OpenAPI|Policy|Exceptions) digest: (?!none$).*$/gm, '$1 digest: <digest>');

    expect(output).toMatchInlineSnapshot(`
      "Summary: total=0 error=0 warning=0 info=0 suppressed=0
      Target: aws
      OpenAPI digest: <digest>
      Policy digest: <digest>
      Exceptions digest: none
      Omitted/unknown comparisons: 7
        policy.auth.route_gates:partial
        policy.request.content_type:unsupported
        policy.request.graphql_guard:warning-only
        policy.request.header_limits:partial
        policy.response.csp_nonce:unsupported
        policy.response.response_dlp:warning-only
        policy.routes.request.allow_methods:unsupported
      Input analysis:
        declared: analyzed (OpenAPI)
        implemented: not requested (source input is absent)
        allowed: analyzed (Policy)
        Exception input: not requested
      Comparison:
        status: partial
        evaluated findings: 0
        not evaluated: 7 comparison(s); absence of findings is not proof of no drift
      Capabilities:
        OpenAPI: complete (complete=4)
        Policy: unsupported (partial=2 unsupported=3 supported=6 warning-only=2)
          policy.auth.route_gates: partial (partial coverage)
          policy.request.content_type: unsupported (not evaluated)
          policy.request.graphql_guard: warning-only (warning-only)
          policy.request.header_limits: partial (partial coverage)
          policy.response.csp_nonce: unsupported (not evaluated)
          policy.response.response_dlp: warning-only (warning-only)
          policy.routes.request.allow_methods: unsupported (not evaluated)
      Analysis diagnostics:
        none
      Findings:
        evaluated=0 (no findings)
        (none)
      Limitations:
        7 comparison(s) were omitted or are unknown.
      "
    `);
  });

  test('keeps analyzer diagnostics visible as limitations', () => {
    const report = {
      ...reportFixture(),
      analyzerDiagnostics: [{
        code: 'OPENAPI_LIMIT_NEAR' as const,
        level: 'warning' as const,
        message: 'OpenAPI analysis usage is near the configured limit.',
        metric: 'operations' as const,
        used: 80,
        limit: 100,
      }],
    };
    const output = renderUnifiedContractDiffText(report);
    expect(output).toContain('Analysis diagnostics:');
    expect(output).toContain('OPENAPI_LIMIT_NEAR');
    expect(output).toContain('analyzer diagnostic(s) require attention');
    expect(output).not.toContain('Limitations:\n  none reported');
  });
});
