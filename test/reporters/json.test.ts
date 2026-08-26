import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';

const { diffSecurityContracts, formatContractDiffJson } = require('../../contract') as typeof import('../../src/contract');
const {
  JsonReportError,
  renderUnifiedContractDiffJson,
} = require('../../reporters/json') as typeof import('../../src/reporters/json');

function reportFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'contract-json-'));
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

describe('Unified contract JSON reporter', () => {
  test('keeps the current pretty JSON contract and canonicalizes order', () => {
    const report = reportFixture();
    const pretty = renderUnifiedContractDiffJson(report);
    expect(pretty).toBe(formatContractDiffJson(report));
    expect(pretty.endsWith('\n')).toBe(true);
    expect(JSON.parse(pretty)).toMatchObject(report);

    const reordered = {
      omittedComparisons: [...report.omittedComparisons].reverse(),
      analyzerDiagnostics: [...report.analyzerDiagnostics].reverse(),
      exceptionDiagnostics: [...report.exceptionDiagnostics].reverse(),
      suppressedFindings: [...report.suppressedFindings].reverse(),
      findings: [...report.findings].reverse(),
      analyzerCapabilities: {
        policy: [...report.analyzerCapabilities.policy].reverse(),
        openapi: { ...report.analyzerCapabilities.openapi },
      },
      appliedExceptionIds: [...report.appliedExceptionIds].reverse(),
      summary: { ...report.summary },
      target: report.target,
      inputDigests: { ...report.inputDigests },
      schemaVersion: report.schemaVersion,
    };
    expect(renderUnifiedContractDiffJson(reordered)).toBe(pretty);
  });

  test('supports compact output and explicit newline policy', () => {
    const report = reportFixture();
    const compact = renderUnifiedContractDiffJson(report, { pretty: false, newline: false });
    expect(JSON.parse(compact)).toMatchObject(report);
    expect(compact).not.toContain('\n');
    expect(renderUnifiedContractDiffJson(report, { pretty: false })).toBe(`${compact}\n`);
  });

  test('rejects schema-invalid, private, unsupported, and oversized reports without raw details', () => {
    const report = reportFixture();
    expect(() => renderUnifiedContractDiffJson({ ...report, target: 'invalid' as 'aws' }))
      .toThrowError(JsonReportError);
    try {
      renderUnifiedContractDiffJson({ ...report, target: 'invalid' as 'aws' });
    } catch (error) {
      expect(error).toMatchObject({ code: 'JSON_REPORT_SCHEMA_INVALID' });
      expect((error as Error).message).not.toContain('invalid');
    }

    const privateReport = {
      ...report,
      findings: [],
      summary: { ...report.summary },
      inputDigests: { ...report.inputDigests, openapi: 'sha256:' + 'a'.repeat(64) },
      analyzerDiagnostics: [],
      omittedComparisons: [],
      __private: 'Bearer super-secret',
    } as typeof report & { __private: string };
    expect(() => renderUnifiedContractDiffJson(privateReport)).toThrowError(/JSON_REPORT_SCHEMA_INVALID/);

    const cyclic = { ...report, findings: [] } as typeof report & { cycle?: unknown };
    cyclic.cycle = cyclic;
    expect(() => renderUnifiedContractDiffJson(cyclic)).toThrowError(/JSON_REPORT_INPUT_INVALID/);

    expect(() => renderUnifiedContractDiffJson(report, { maxOutputBytes: 32 }))
      .toThrowError(/JSON_REPORT_OUTPUT_LIMIT_EXCEEDED/);
  });

  test('rejects secret, query, and absolute URI values at the reporter boundary', () => {
    const report = reportFixture();
    const finding = {
      schemaVersion: 1 as const,
      ruleId: 'SC-TST-001',
      instanceId: 'a'.repeat(64),
      severity: 'error' as const,
      confidence: 'deterministic' as const,
      category: 'exposure' as const,
      title: 'unsafe',
      message: 'Bearer super-secret',
      route: { method: 'GET', path: '/users?token=super-secret' },
      evidence: [{
        source: 'openapi' as const,
        uri: 'https://evil.example/secret',
        digest: `sha256:${'a'.repeat(64)}`,
        analyzer: 'test',
        capability: 'routes',
        complete: true,
      }],
    };
    const unsafe = {
      ...report,
      findings: [finding],
      summary: {
        ...report.summary,
        total: 1,
        error: 1,
        bySeverity: { ...report.summary.bySeverity, error: 1 },
        byCategory: { ...report.summary.byCategory, exposure: 1 },
      },
    };
    expect(() => renderUnifiedContractDiffJson(unsafe)).toThrowError(JsonReportError);
    try {
      renderUnifiedContractDiffJson(unsafe);
    } catch (error) {
      expect((error as JsonReportError).code).toBe('JSON_REPORT_PRIVACY_VIOLATION');
      expect((error as Error).message).not.toContain('super-secret');
    }
  });
});
