import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';

import { analyzeSourceAwareWorkspace } from '../../src/contract/source-aware-workspace';
import type { SourceAwareWorkspaceResult } from '../../src/contract/source-aware-workspace';
import { createFinding, type FindingInputV1 } from '../../src/contract/finding';
import type { FindingExceptionSetV1 } from '../../src/contract/finding-exceptions';
import { formatSourceAwarePreviewJson, formatSourceAwarePreviewText } from '../../src/contract/source-aware-finalizer';
import { finalizeSourceAwareOutput } from '../../src/contract/source-aware-output';
import { renderSourceAwareSarif, SarifReportError } from '../../src/reporters/sarif';
import { renderSourceAwareSummary, SourceAwareSummaryError } from '../../src/reporters/source-aware-summary';
import { createOfficialSarifValidator } from '../../src/scripts/official-sarif-test-validator';
import { validateLocalSarif } from '../helpers/sarif-validation';

const roots: string[] = [];
const validateOfficialSarif = createOfficialSarifValidator(path.join(process.cwd(),
  'test/fixtures/sarif/sarif-schema-2.1.0.json'));
function fixture(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-source-output-'));
  roots.push(root);
  fs.cpSync(path.join(process.cwd(), 'test/fixtures/source-analysis/nestjs-basic'), root, { recursive: true });
  const dependency = path.join(root, 'node_modules/@nestjs/common');
  fs.mkdirSync(dependency, { recursive: true });
  fs.writeFileSync(path.join(dependency, 'package.json'), JSON.stringify({ name: '@nestjs/common', version: '1.0.0', main: 'index.js', types: 'index.d.ts' }));
  fs.writeFileSync(path.join(dependency, 'index.js'), 'throw new Error("Source executed");\n');
  fs.writeFileSync(path.join(dependency, 'index.d.ts'), 'export declare function Controller(path?: string): ClassDecorator;\nexport declare function Get(path?: string): MethodDecorator;\nexport declare function Post(path?: string): MethodDecorator;\nexport declare function Head(path?: string): MethodDecorator;\n');
  fs.writeFileSync(path.join(root, 'policy.yml'), 'version: 2\ndefaults: {mode: enforce}\nrequest:\n  allow_methods: [GET]\n  limits: {max_uri_length: 21}\n  block: {header_missing: []}\nroutes: []\nresponse_headers: {}\n');
  fs.mkdirSync(path.join(root, 'refs'));
  fs.writeFileSync(path.join(root, 'refs/common.yaml'), 'components:\n  parameters:\n    Id:\n      name: id\n      in: path\n      required: true\n      schema: {type: string}\n');
  fs.writeFileSync(path.join(root, 'openapi.yaml'), `openapi: 3.0.3
info: {title: Synthetic, version: 1.0.0}
paths:
  /users/{id}:
    get:
      parameters:
        - $ref: './refs/common.yaml#/components/parameters/Id'
      responses:
        '200': {description: OK}
  /users:
    post:
      responses:
        '200': {description: OK}
`);
  return root;
}
afterEach(() => { for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });

const options = { currentDate: '2026-09-25', failOn: 'never' as const };
const findingInput: FindingInputV1 = {
  ruleId: 'SC-AUTHN-001', severity: 'warning', confidence: 'deterministic',
  category: 'authentication', title: 'Authentication mismatch', message: 'Review GET /users.',
  route: { method: 'GET', path: '/users' },
  evidence: [{ source: 'openapi', uri: 'openapi.yaml', digest: 'sha256:synthetic',
    analyzer: 'openapi@1', capability: 'routes', complete: true }],
};
function synthetic(findings = [createFinding(findingInput)]): SourceAwareWorkspaceResult {
  return {
    target: 'aws', evidence: {}, stages: {
      declared: { status: 'complete', diagnosticCodes: [] },
      implemented: { status: 'complete', diagnosticCodes: [] },
      allowed: { status: 'complete', diagnosticCodes: [], targetCapabilities: [
        { id: 'auth.route_gates', status: 'partial' },
      ] },
    }, comparisons: {
      declaredAllowed: { status: 'complete', findings },
      implementedDeclared: { status: 'complete', findings },
      implementedAllowed: { status: 'complete', findings: [] },
    },
  };
}
function exception(instanceId: string, expiresAt = '2026-12-01'): FindingExceptionSetV1 {
  return { version: 1, exceptions: [{
    id: 'EXC-2026-ONE', rule_id: 'SC-AUTHN-001', selector: { instance_id: instanceId },
    reason: 'Temporary exception for a reviewed route.', owner: 'security-team', expires_at: expiresAt,
  }] };
}

function expectOfficialSchema(value: unknown): void {
  const serialized = JSON.parse(JSON.stringify(value));
  expect(validateOfficialSarif(serialized), JSON.stringify(validateOfficialSarif.errors)).toBe(true);
}

describe('Source-aware internal output adapters', () => {
  test('same real workspace result yields Text, JSON, full SARIF and bounded Summary without changing inputs', async () => {
    const root = fixture();
    const input = { workspaceRoot: root, openapiPath: 'openapi.yaml', policyPath: 'policy.yml', target: 'aws' as const, source: { tsconfigPath: 'tsconfig.json' } };
    const paths = ['openapi.yaml', 'refs/common.yaml', 'policy.yml', 'tsconfig.json', 'src/controller.ts'];
    const before = paths.map((name) => fs.readFileSync(path.join(root, name)));
    const analyzed = await analyzeSourceAwareWorkspace(input);
    const bundle = finalizeSourceAwareOutput(analyzed, options);
    expect(bundle.finalized).toBeDefined();
    if (!bundle.finalized) throw new Error('expected a finalized result');
    const text = formatSourceAwarePreviewText(bundle.finalized);
    const json = JSON.parse(formatSourceAwarePreviewJson(bundle.finalized));
    const sarif = renderSourceAwareSarif(bundle);
    const summary = renderSourceAwareSummary(bundle);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].results).toHaveLength(bundle.finalized.summary.active + bundle.finalized.summary.suppressed + bundle.finalized.summary.governance);
    expect(sarif.runs[0].invocations?.[0].executionSuccessful).toBe(true);
    expect(json.summary).toEqual(bundle.finalized.summary);
    expect(json.omittedFindings).toBe(0);
    expect(bundle.finalized.summary.active + bundle.finalized.summary.suppressed).toBe(bundle.finalized.summary.unique);
    const levels = { error: 'error', warning: 'warning', info: 'note' } as const;
    for (const finding of [...bundle.finalized.findings, ...bundle.finalized.suppressedFindings, ...bundle.finalized.exceptionDiagnostics]) {
      const preview = [...json.findings.active, ...json.findings.suppressed, ...json.findings.exceptionDiagnostics]
        .find((item: { instanceId: string }) => item.instanceId === finding.instanceId);
      const result = sarif.runs[0].results.find((item) => item.partialFingerprints['securityContractFinding/v1'] === finding.instanceId);
      expect(preview).toMatchObject({ ruleId: finding.ruleId, severity: finding.severity });
      expect(result).toMatchObject({ ruleId: finding.ruleId, level: levels[finding.severity] });
      expect(result?.properties.sourceAware?.comparisons).toEqual(preview.comparisons);
      expect(text).toContain(finding.instanceId);
      expect(summary).toContain(finding.instanceId);
    }
    expect(bundle.metadata.openapi?.digestKind).toBe('raw-document-graph');
    expect(bundle.metadata.policy?.digestKind).toBe('decoded-input-text');
    expect(bundle.metadata.source?.digestKind).toBe('decoded-project-text');
    expect(bundle.metadata.source?.projectDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(summary).toContain(`| Unique | ${bundle.finalized.summary.unique} |`);
    expect(summary).toContain('implementedDeclared');
    expect(text).toContain(`unique=${bundle.finalized.summary.unique}`);
    expect(JSON.stringify(sarif) + summary).not.toContain(root);
    expect(paths.map((name) => fs.readFileSync(path.join(root, name)))).toEqual(before);
    expect(renderSourceAwareSummary(bundle)).toBe(summary);
    expect(validateLocalSarif(sarif), JSON.stringify(validateLocalSarif.errors)).toBe(true);
    expectOfficialSchema(sarif);
  });

  test('different disposable roots produce the same four deterministic output meanings', async () => {
    const results = [];
    for (let i = 0; i < 2; i += 1) {
      const root = fixture();
      const analyzed = await analyzeSourceAwareWorkspace({ workspaceRoot: root,
        openapiPath: 'openapi.yaml', policyPath: 'policy.yml', target: 'aws', source: { tsconfigPath: 'tsconfig.json' } });
      const bundle = finalizeSourceAwareOutput(analyzed, options);
      if (!bundle.finalized) throw new Error('expected finalized result');
      results.push([
        formatSourceAwarePreviewText(bundle.finalized), formatSourceAwarePreviewJson(bundle.finalized),
        JSON.stringify(renderSourceAwareSarif(bundle)), renderSourceAwareSummary(bundle),
      ]);
    }
    expect(results[0]).toEqual(results[1]);
  });

  test('real malformed OpenAPI remains a tool error while independent Source/Policy findings survive', async () => {
    const root = fixture();
    const openapiPath = path.join(root, 'openapi.yaml');
    fs.writeFileSync(openapiPath, 'not: openapi\n');
    const before = fs.readFileSync(openapiPath);
    const analyzed = await analyzeSourceAwareWorkspace({ workspaceRoot: root,
      openapiPath: 'openapi.yaml', policyPath: 'policy.yml', target: 'aws', source: { tsconfigPath: 'tsconfig.json' } });
    const bundle = finalizeSourceAwareOutput(analyzed, options);
    expect(bundle.finalized?.analysis).toMatchObject({ outcome: 'input-error' });
    expect(bundle.finalized?.comparisons.implementedAllowed.status).toMatch(/complete|partial/);
    expect(bundle.finalized?.summary.unique).toBeGreaterThan(0);
    expect(renderSourceAwareSarif(bundle).runs[0].invocations?.[0].executionSuccessful).toBe(false);
    expectOfficialSchema(renderSourceAwareSarif(bundle));
    expect(renderSourceAwareSummary(bundle)).toContain('**Result: tool error**');
    expect(fs.readFileSync(openapiPath)).toEqual(before);
  });

  test('one canonical Finding retains two memberships, suppression and governance without duplicating alerts', () => {
    const workspace = synthetic();
    const id = workspace.comparisons.declaredAllowed.findings[0].instanceId;
    const bundle = finalizeSourceAwareOutput(workspace, { ...options, failOn: 'warning', exceptions: exception(id) });
    const sarif = renderSourceAwareSarif(bundle);
    expectOfficialSchema(sarif);
    expect(bundle.finalized?.summary).toMatchObject({ unique: 1, active: 0, suppressed: 1 });
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0]).toMatchObject({
      partialFingerprints: { 'securityContractFinding/v1': id },
      suppressions: [{ kind: 'external', status: 'accepted' }],
      properties: { sourceAware: { disposition: 'suppressed',
        comparisons: ['declaredAllowed', 'implementedDeclared'] } },
    });
    expect(sarif.runs[0].tool.driver.properties.sourceAware).toMatchObject({
      summary: bundle.finalized?.summary, threshold: { reached: false }, internalExitCode: 0,
    });
    expect(renderSourceAwareSummary(bundle)).toContain('| Suppressed | 1 |');
    const expired = finalizeSourceAwareOutput(workspace, { ...options, failOn: 'warning', exceptions: exception(id, '2026-01-01') });
    expect(expired.finalized?.summary).toMatchObject({ active: 1, governance: 1 });
    const expiredSarif = renderSourceAwareSarif(expired);
    expectOfficialSchema(expiredSarif);
    expect(expiredSarif.runs[0].results.map(({ ruleId }) => ruleId)).toContain('SC-GOV-001');
    const invalid = finalizeSourceAwareOutput(workspace, { ...options, exceptions: {
      version: 1, exceptions: [{ ...exception(id).exceptions[0], reason: 'short' }],
    } });
    expect(invalid.finalized?.analysis.outcome).toBe('input-error');
    const invalidSarif = renderSourceAwareSarif(invalid);
    expectOfficialSchema(invalidSarif);
    expect(invalidSarif.runs[0].invocations?.[0].executionSuccessful).toBe(false);
    const nonWaivable = createFinding({ ...findingInput, ruleId: 'SC-UNSAFE-001', category: 'misconfiguration' });
    const unsafeWorkspace = synthetic([nonWaivable]);
    const unsafeException = exception(nonWaivable.instanceId);
    unsafeException.exceptions[0].rule_id = 'SC-UNSAFE-001';
    const unsafeOutput = finalizeSourceAwareOutput(unsafeWorkspace, { ...options, exceptions: unsafeException });
    expect(unsafeOutput.finalized?.summary).toMatchObject({ active: 1, suppressed: 0 });
    const unsafeSarif = renderSourceAwareSarif(unsafeOutput);
    expectOfficialSchema(unsafeSarif);
    expect(unsafeSarif.runs[0].results[0].suppressions).toBeUndefined();
  });

  test('threshold, Source omission, partial and failed stages stay distinct from actual execution status', () => {
    const threshold = finalizeSourceAwareOutput(synthetic(), { ...options, failOn: 'warning' });
    expect(threshold.finalized?.exitCode).toBe(1);
    const thresholdSarif = renderSourceAwareSarif(threshold);
    expectOfficialSchema(thresholdSarif);
    expect(thresholdSarif.runs[0].invocations?.[0].executionSuccessful).toBe(true);
    const omitted = synthetic([]);
    omitted.stages.implemented = { status: 'omitted', code: 'SOURCE_NOT_REQUESTED', diagnosticCodes: [] };
    omitted.comparisons.implementedDeclared = { status: 'omitted', code: 'SOURCE_NOT_REQUESTED' };
    omitted.comparisons.implementedAllowed = { status: 'omitted', code: 'SOURCE_NOT_REQUESTED' };
    const noSource = finalizeSourceAwareOutput(omitted, options);
    expectOfficialSchema(renderSourceAwareSarif(noSource));
    expect(renderSourceAwareSummary(noSource)).toContain('implemented | omitted | SOURCE_NOT_REQUESTED');
    expect(renderSourceAwareSarif(noSource).runs[0].tool.driver.properties.sourceAware).toMatchObject({
      analysis: { status: 'complete', outcome: 'ok' }, summary: { unique: 0 },
    });
    const partial = synthetic();
    partial.stages.implemented = { status: 'partial', diagnosticCodes: ['SOURCE_ANALYZER_DYNAMIC_ROUTE'] };
    partial.comparisons.implementedDeclared = { status: 'partial', findings: partial.comparisons.declaredAllowed.findings };
    const partialOutput = finalizeSourceAwareOutput(partial, options);
    expectOfficialSchema(renderSourceAwareSarif(partialOutput));
    expect(renderSourceAwareSummary(partialOutput)).toContain('**Result: partial analysis**');
    const failed = synthetic();
    failed.stages.implemented = { status: 'failed', code: 'SOURCE_ANALYZER_FILE_LIMIT', diagnosticCodes: [] };
    failed.comparisons.implementedDeclared = { status: 'failed', code: 'SOURCE_ANALYZER_FILE_LIMIT' };
    failed.comparisons.implementedAllowed = { status: 'failed', code: 'SOURCE_ANALYZER_FILE_LIMIT' };
    const failedOutput = finalizeSourceAwareOutput(failed, options);
    expectOfficialSchema(renderSourceAwareSarif(failedOutput));
    expect(failedOutput.finalized?.comparisons.declaredAllowed).toMatchObject({ count: 1 });
    expect(renderSourceAwareSarif(failedOutput).runs[0]).toMatchObject({
      results: [{ ruleId: 'SC-AUTHN-001' }], invocations: [{ executionSuccessful: false }],
    });
    expect(renderSourceAwareSummary(failedOutput)).toContain('**Result: tool error**');
    failed.stages.implemented = { status: 'failed', code: 'SOURCE_ANALYZER_CANCELLED', diagnosticCodes: [] };
    failed.comparisons.implementedDeclared = { status: 'failed', code: 'SOURCE_ANALYZER_CANCELLED' };
    failed.comparisons.implementedAllowed = { status: 'failed', code: 'SOURCE_ANALYZER_CANCELLED' };
    const cancelled = finalizeSourceAwareOutput(failed, options);
    expect(cancelled.finalized?.exitCode).toBe(3);
    const cancelledSarif = renderSourceAwareSarif(cancelled);
    expectOfficialSchema(cancelledSarif);
    expect(cancelledSarif.runs[0].invocations?.[0].executionSuccessful).toBe(false);
  });

  test('fixed finalizer error exposes no stale report or raw input and synthetic Source has no invented location', () => {
    const workspace = synthetic();
    workspace.comparisons.implementedDeclared = { status: 'complete', findings: [{
      ...workspace.comparisons.declaredAllowed.findings[0], message: 'Different safe text.',
    }] };
    const bundle = finalizeSourceAwareOutput(workspace, options);
    expect(bundle.finalized).toBeUndefined();
    expect(bundle.finalizationError?.code).toBe('SOURCE_FINDING_IDENTITY_CONFLICT');
    expectOfficialSchema(renderSourceAwareSarif(bundle));
    expect(renderSourceAwareSarif(bundle).runs[0]).toMatchObject({
      results: [], invocations: [{ executionSuccessful: false }],
    });
    expect(renderSourceAwareSummary(bundle)).toContain('**Result: tool error**');
    const sourceOnly = synthetic([createFinding({ ...findingInput, ruleId: 'SC-AUTHZ-001',
      evidence: [{ source: 'source-ast', uri: 'source-project', digest: 'sha256:synthetic',
        analyzer: 'nestjs@1', capability: 'routes', complete: false }] })]);
    const sourceOutput = renderSourceAwareSarif(finalizeSourceAwareOutput(sourceOnly, options));
    expectOfficialSchema(sourceOutput);
    expect(sourceOutput.runs[0].results[0].locations).toBeUndefined();
    expect(sourceOutput.runs[0].results[0].properties.sourceAware?.omittedSyntheticSourceLocations).toBe(1);
  });

  test('full-result SARIF fails closed on count/bytes while Summary reports omission and protects fixed metadata', () => {
    const findings = Array.from({ length: 45 }, (_, i) => createFinding({
      ...findingInput, route: { method: 'GET', path: `/users/${i}` },
    }));
    const bundle = finalizeSourceAwareOutput(synthetic(findings), options);
    expect(() => renderSourceAwareSarif(bundle, { maxResults: 10 })).toThrowError(
      expect.objectContaining({ code: 'SARIF_OUTPUT_LIMIT_EXCEEDED' }),
    );
    expect(() => renderSourceAwareSarif(bundle, { maxOutputBytes: 100 })).toThrowError(
      expect.objectContaining({ code: 'SARIF_OUTPUT_LIMIT_EXCEEDED' }),
    );
    const summary = renderSourceAwareSummary(bundle);
    expect(summary).toContain('Top findings omitted: 35.');
    expect(summary).toContain('| Unique | 45 |');
    expect(renderSourceAwareSarif(bundle).runs[0].results).toHaveLength(45);
    expectOfficialSchema(renderSourceAwareSarif(bundle));
    expect(JSON.parse(formatSourceAwarePreviewJson(bundle.finalized!)).omittedFindings).toBeGreaterThan(0);
    expect(() => renderSourceAwareSummary(bundle, { maxOutputBytes: 100 })).toThrowError(
      expect.objectContaining({ code: 'SOURCE_SUMMARY_OUTPUT_LIMIT_EXCEEDED' }),
    );
    expect(SarifReportError).toBeDefined();
    expect(SourceAwareSummaryError).toBeDefined();
  });

  test('pinned official draft-04 validator rejects schema errors and validates URI formats', () => {
    const valid = JSON.parse(JSON.stringify(renderSourceAwareSarif(finalizeSourceAwareOutput(synthetic(), options))));
    expect(validateOfficialSarif(valid)).toBe(true);
    for (const mutate of [
      (value: any) => { delete value.version; },
      (value: any) => { value.version = '2.2.0'; },
      (value: any) => { value.unexpected = true; },
      (value: any) => { value.runs = 'not-an-array'; },
      (value: any) => { value.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri = 'bad uri with spaces'; },
    ]) {
      const invalid = JSON.parse(JSON.stringify(valid));
      mutate(invalid);
      expect(validateOfficialSarif(invalid)).toBe(false);
    }
  });

  test('privacy and Markdown payloads are masked or rejected before publishing any result', () => {
    const finding = createFinding({ ...findingInput,
      title: '<img src=x onerror=alert(1)> token=opaquevalue123',
      route: { method: 'GET', path: '/users?token=opaquevalue123#frag' },
      evidence: [{ source: 'openapi', uri: 'token=opaquevalue123.yaml', digest: 'sha256:synthetic',
        analyzer: 'openapi@1', capability: 'routes', complete: true }],
    });
    const bundle = finalizeSourceAwareOutput(synthetic([finding]), options);
    const summary = renderSourceAwareSummary(bundle);
    const sarif = JSON.stringify(renderSourceAwareSarif(bundle));
    expect(summary).not.toContain('opaquevalue123');
    expect(summary).not.toContain('<img');
    expect(summary).toContain('&lt;img');
    expect(summary).not.toContain('?token=');
    expect(sarif).not.toContain('opaquevalue123');
    expect(sarif).not.toContain('?token=');
    if (!bundle.finalized) throw new Error('expected finalized result');
    bundle.finalized.findings[0].message = 'Authorization: Bearer opaquevalue123';
    expect(() => renderSourceAwareSarif(bundle)).toThrowError(
      expect.objectContaining({ code: 'SARIF_PRIVACY_VIOLATION' }),
    );
    bundle.finalized.findings[0].message = 'Review this route.';
    bundle.finalized.findings[0].evidence[0].uri = 'token%3Dopaquevalue123.yaml';
    expect(() => renderSourceAwareSarif(bundle)).toThrowError(
      expect.objectContaining({ code: 'SARIF_PRIVACY_VIOLATION' }),
    );
  });
});
