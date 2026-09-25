import { describe, expect, test } from 'vitest';

import { createFinding, type FindingInputV1 } from '../../src/contract/finding';
import type { FindingExceptionSetV1 } from '../../src/contract/finding-exceptions';
import type { SourceAwareWorkspaceResult } from '../../src/contract/source-aware-workspace';
import {
  finalizeSourceAwareWorkspace, formatSourceAwarePreviewJson, formatSourceAwarePreviewText,
  SourceAwareFinalizationError,
} from '../../src/contract/source-aware-finalizer';

const base: FindingInputV1 = {
  ruleId: 'SC-AUTHN-001', severity: 'warning', confidence: 'deterministic',
  category: 'authentication', title: 'Missing authentication', message: 'Review this route.',
  route: { method: 'GET', path: '/users' },
  evidence: [{ source: 'openapi', uri: 'openapi.yaml', digest: 'sha256:synthetic',
    analyzer: 'openapi@1', capability: 'routes', complete: true }],
};

function workspace(findings = [createFinding(base)]): SourceAwareWorkspaceResult {
  return {
    target: 'aws', evidence: {},
    stages: {
      declared: { status: 'complete', diagnosticCodes: [] },
      implemented: { status: 'complete', diagnosticCodes: [] },
      allowed: { status: 'complete', diagnosticCodes: [], targetCapabilities: [] },
    },
    comparisons: {
      declaredAllowed: { status: 'complete', findings },
      implementedDeclared: { status: 'complete', findings },
      implementedAllowed: { status: 'complete', findings: [] },
    },
  };
}

const options = { currentDate: '2026-09-25', failOn: 'warning' as const };

function exception(instanceId: string, expiresAt = '2026-12-01'): FindingExceptionSetV1 {
  return { version: 1, exceptions: [{
    id: 'EXC-2026-ONE', rule_id: 'SC-AUTHN-001', selector: { instance_id: instanceId },
    reason: 'Temporary exception for a reviewed route.', owner: 'security-team', expires_at: expiresAt,
  }] };
}

describe('internal Source-aware finalizer', () => {
  test('deduplicates globally while retaining both comparison memberships and one threshold count', () => {
    const input = workspace();
    const before = structuredClone(input);
    const result = finalizeSourceAwareWorkspace(input, options);
    expect(result.summary).toMatchObject({ unique: 1, active: 1, suppressed: 0, governance: 0 });
    expect(result.comparisons.declaredAllowed).toMatchObject({ status: 'complete', count: 1, active: 1 });
    expect(result.comparisons.implementedDeclared).toMatchObject({ status: 'complete', count: 1, active: 1 });
    expect(result.memberships).toEqual([{ instanceId: input.comparisons.declaredAllowed.findings[0].instanceId,
      comparisons: ['declaredAllowed', 'implementedDeclared'] }]);
    expect(result.analysis).toMatchObject({ status: 'complete', outcome: 'ok' });
    expect(result.threshold).toEqual({ failOn: 'warning', reached: true });
    expect(result.exitCode).toBe(1);
    expect(input).toEqual(before);
    expect(finalizeSourceAwareWorkspace(input, options)).toEqual(result);
  });

  test('applies one exception result consistently across member comparisons; expiry stays active', () => {
    const input = workspace();
    const id = input.comparisons.declaredAllowed.findings[0].instanceId;
    const set = exception(id);
    const before = structuredClone(set);
    const applied = finalizeSourceAwareWorkspace(input, { ...options, exceptions: set });
    expect(applied.summary).toMatchObject({ unique: 1, active: 0, suppressed: 1, governance: 0 });
    expect(applied.comparisons.declaredAllowed).toMatchObject({ count: 1, active: 0, suppressed: 1 });
    expect(applied.comparisons.implementedDeclared).toMatchObject({ count: 1, active: 0, suppressed: 1 });
    expect(applied.appliedExceptionIds).toEqual(['EXC-2026-ONE']);
    expect(applied.exitCode).toBe(0);
    const preview = JSON.parse(formatSourceAwarePreviewJson(applied));
    expect(preview.findings.active).toEqual([]);
    expect(preview.findings.suppressed).toHaveLength(1);
    expect(preview.comparisons.implementedDeclared.suppressed).toBe(1);
    expect(formatSourceAwarePreviewText(applied)).toContain('suppressed SC-AUTHN-001');
    expect(set).toEqual(before);

    const expired = finalizeSourceAwareWorkspace(input, { ...options, exceptions: exception(id, '2026-01-01') });
    expect(expired.summary).toMatchObject({ active: 1, suppressed: 0, governance: 1 });
    expect(expired.exceptionDiagnostics.map(({ ruleId }) => ruleId)).toEqual(['SC-GOV-001']);
    expect(expired.exitCode).toBe(1);
    const invalid = finalizeSourceAwareWorkspace(input, { ...options, exceptions: { version: 1, exceptions: [{
      ...set.exceptions[0], reason: 'short',
    }] } });
    expect(invalid.analysis).toMatchObject({ status: 'failed', outcome: 'input-error', codes: ['CONTRACT_DIFF_EXCEPTIONS_INVALID'] });
    expect(invalid.exitCode).toBe(2);
  });

  test('keeps independent findings through failure, partial and intentional Source omission', () => {
    const requestedFailure = workspace();
    requestedFailure.stages.implemented = { status: 'failed', code: 'SOURCE_ANALYZER_FILE_LIMIT', diagnosticCodes: ['SOURCE_ANALYZER_FILE_LIMIT'] };
    requestedFailure.comparisons.implementedDeclared = { status: 'failed', code: 'SOURCE_ANALYZER_FILE_LIMIT' };
    requestedFailure.comparisons.implementedAllowed = { status: 'failed', code: 'SOURCE_ANALYZER_FILE_LIMIT' };
    const failed = finalizeSourceAwareWorkspace(requestedFailure, { ...options, failOn: 'never' });
    expect(failed.summary.unique).toBe(1);
    expect(failed.comparisons.declaredAllowed).toMatchObject({ status: 'complete', count: 1 });
    expect(failed.comparisons.implementedDeclared).toEqual({ status: 'failed', code: 'SOURCE_ANALYZER_FILE_LIMIT' });
    expect(failed.analysis).toMatchObject({ status: 'failed', outcome: 'input-error' });
    expect(failed.exitCode).toBe(2);

    const omitted = workspace();
    omitted.stages.implemented = { status: 'omitted', code: 'SOURCE_NOT_REQUESTED', diagnosticCodes: [] };
    omitted.comparisons.implementedDeclared = { status: 'omitted', code: 'SOURCE_NOT_REQUESTED' };
    omitted.comparisons.implementedAllowed = { status: 'omitted', code: 'SOURCE_NOT_REQUESTED' };
    expect(finalizeSourceAwareWorkspace(omitted, { ...options, failOn: 'never' })).toMatchObject({
      analysis: { status: 'complete', outcome: 'ok' }, exitCode: 0,
      comparisons: { implementedDeclared: { status: 'omitted', code: 'SOURCE_NOT_REQUESTED' } },
    });
    const partial = workspace();
    partial.stages.implemented = { status: 'partial', diagnosticCodes: ['SOURCE_ANALYZER_DYNAMIC_ROUTE'] };
    partial.comparisons.implementedDeclared = { status: 'partial', findings: partial.comparisons.declaredAllowed.findings };
    expect(finalizeSourceAwareWorkspace(partial, options).analysis.status).toBe('partial');
  });

  test('internal errors outrank threshold and conflicting IDs cannot silently choose a Finding', () => {
    const internal = workspace();
    internal.comparisons.implementedAllowed = { status: 'failed', code: 'COMPARISON_RESOURCE_LIMIT' };
    expect(finalizeSourceAwareWorkspace(internal, options)).toMatchObject({
      analysis: { status: 'failed', outcome: 'internal-error' }, exitCode: 3,
    });
    const conflicting = workspace();
    conflicting.comparisons.implementedDeclared = { status: 'complete', findings: [{
      ...conflicting.comparisons.declaredAllowed.findings[0], message: 'Different safe text.',
    }] };
    expect(() => finalizeSourceAwareWorkspace(conflicting, options)).toThrowError(
      expect.objectContaining({ code: 'SOURCE_FINDING_IDENTITY_CONFLICT', exitCode: 3 }),
    );
  });

  test('zero success, unused and non-waivable Findings remain distinct from unrun work', () => {
    const empty = workspace([]);
    const clean = finalizeSourceAwareWorkspace(empty, options);
    expect(clean).toMatchObject({ summary: { unique: 0, active: 0 },
      analysis: { status: 'complete', outcome: 'ok' }, exitCode: 0 });
    const unrun = workspace([]);
    unrun.stages.declared = { status: 'failed', code: 'OPENAPI_PARSE_ERROR', diagnosticCodes: [] };
    unrun.comparisons.declaredAllowed = { status: 'failed', code: 'OPENAPI_PARSE_ERROR' };
    unrun.comparisons.implementedDeclared = { status: 'failed', code: 'OPENAPI_PARSE_ERROR' };
    expect(finalizeSourceAwareWorkspace(unrun, options)).toMatchObject({
      summary: { unique: 0 }, analysis: { status: 'failed', outcome: 'input-error' }, exitCode: 2,
    });
    const nonWaivable = createFinding({ ...base, ruleId: 'SC-UNSAFE-001', category: 'misconfiguration' });
    const input = workspace([nonWaivable]);
    const unused = finalizeSourceAwareWorkspace(input, { ...options, exceptions: exception('0'.repeat(64)) });
    expect(unused.findings.map(({ ruleId }) => ruleId)).toEqual(['SC-UNSAFE-001']);
    expect(unused.suppressedFindings).toEqual([]);
    expect(unused.exceptionDiagnostics.map(({ ruleId }) => ruleId)).toEqual(['SC-GOV-002']);
    expect(unused.summary).toMatchObject({ active: 1, suppressed: 0, governance: 1 });
    const attemptedWaiver = exception(nonWaivable.instanceId);
    attemptedWaiver.exceptions[0].rule_id = 'SC-UNSAFE-001';
    const invalid = finalizeSourceAwareWorkspace(input, { ...options, exceptions: attemptedWaiver });
    expect(invalid).toMatchObject({
      summary: { active: 1, suppressed: 0 }, analysis: { outcome: 'input-error' }, exitCode: 2,
    });
  });

  test('cancel and unknown codes fail closed; invalid threshold is an input error', () => {
    const cancelled = workspace();
    cancelled.stages.implemented = { status: 'failed', code: 'SOURCE_ANALYZER_CANCELLED', diagnosticCodes: [] };
    cancelled.comparisons.implementedDeclared = { status: 'failed', code: 'SOURCE_ANALYZER_CANCELLED' };
    cancelled.comparisons.implementedAllowed = { status: 'failed', code: 'SOURCE_ANALYZER_CANCELLED' };
    expect(finalizeSourceAwareWorkspace(cancelled, { ...options, failOn: 'never' })).toMatchObject({
      summary: { unique: 1 }, analysis: { outcome: 'internal-error' }, exitCode: 3,
    });
    cancelled.stages.implemented = { status: 'failed', code: 'TOKEN=unsafevalue123', diagnosticCodes: [] };
    const unknown = finalizeSourceAwareWorkspace(cancelled, options);
    expect(unknown.analysis.codes).toContain('SOURCE_UNKNOWN_FAILURE');
    expect(formatSourceAwarePreviewJson(unknown)).not.toContain('unsafevalue123');
    const invalidThreshold = finalizeSourceAwareWorkspace(workspace(), {
      ...options, failOn: 'TOKEN=unsafevalue123' as 'warning',
    });
    expect(invalidThreshold).toMatchObject({
      analysis: { outcome: 'input-error', codes: ['CONTRACT_DIFF_FAIL_ON_INVALID'] }, exitCode: 2,
      threshold: { failOn: 'invalid', reached: false },
    });
    expect(formatSourceAwarePreviewText(invalidThreshold)).not.toContain('unsafevalue123');
    const unexpectedlyOmitted = workspace([]);
    unexpectedlyOmitted.comparisons.declaredAllowed = { status: 'omitted', code: 'SOURCE_NOT_REQUESTED' };
    expect(finalizeSourceAwareWorkspace(unexpectedlyOmitted, options)).toMatchObject({
      analysis: { outcome: 'internal-error', codes: ['SOURCE_COMPARISON_UNEXPECTED_OMISSION'] }, exitCode: 3,
    });
  });

  test('separate invocations do not mix exception state or mutate inputs', async () => {
    const input = workspace();
    const before = structuredClone(input);
    const id = input.comparisons.declaredAllowed.findings[0].instanceId;
    const [suppressed, active] = await Promise.all([
      Promise.resolve().then(() => finalizeSourceAwareWorkspace(input, { ...options, exceptions: exception(id) })),
      Promise.resolve().then(() => finalizeSourceAwareWorkspace(input, options)),
    ]);
    expect(suppressed.summary.suppressed).toBe(1);
    expect(active.summary.suppressed).toBe(0);
    expect(input).toEqual(before);
  });

  test('exception target and environment use explicit context without broadening a selector', () => {
    const input = workspace();
    const id = input.comparisons.declaredAllowed.findings[0].instanceId;
    const set = exception(id);
    set.exceptions[0].selector = { instance_id: id, target: 'cloudflare', environment: 'staging' };
    const unrelated = finalizeSourceAwareWorkspace(input, { ...options, environment: 'staging', exceptions: set });
    expect(unrelated.summary).toMatchObject({ active: 1, suppressed: 0, governance: 0 });
    const matching = finalizeSourceAwareWorkspace({ ...input, target: 'cloudflare' }, {
      ...options, environment: 'staging', exceptions: set,
    });
    expect(matching.summary).toMatchObject({ active: 0, suppressed: 1, governance: 0 });
    expect(matching.appliedExceptionIds).toEqual(['EXC-2026-ONE']);
  });

  test('bounded Text and JSON show equal safe meaning without changing the full result', () => {
    const findings = Array.from({ length: 70 }, (_, index) => createFinding({
      ...base, route: { method: 'GET', path: `/route-${index}` },
      evidence: [{ ...base.evidence[0], uri: 'assets/backup-token%255Fopaquevalue123.yaml' }],
    }));
    const result = finalizeSourceAwareWorkspace(workspace(findings), options);
    const jsonText = formatSourceAwarePreviewJson(result);
    const text = formatSourceAwarePreviewText(result);
    const json = JSON.parse(jsonText);
    expect(result.summary.unique).toBe(70);
    expect(json.summary.unique).toBe(70);
    expect(json.omittedFindings).toBeGreaterThan(0);
    expect(json.findings.active.map((finding: { ruleId: string }) => finding.ruleId)).toEqual(
      Array.from({ length: json.findings.active.length }, () => 'SC-AUTHN-001'),
    );
    expect(text).toContain('SC-AUTHN-001');
    expect(text).toContain(`omitted=${json.omittedFindings}`);
    for (const output of [jsonText, text]) {
      expect(Buffer.byteLength(output)).toBeLessThanOrEqual(32_768);
      expect(output).not.toContain('opaquevalue123');
      expect(output).not.toContain('%255F');
    }
  });

  test('preview does not reproduce encoded URL userinfo or query from evidence and routes', () => {
    const encoded = createFinding({ ...base,
      route: { method: 'GET', path: '/safe%3Fkey%3Dopaquevalue123' },
      evidence: [{ ...base.evidence[0], uri: 'docs/https%3A%2F%2Fuser%3Apass%40example.test%2Fsafe' }],
    });
    const result = finalizeSourceAwareWorkspace(workspace([encoded]), options);
    for (const output of [formatSourceAwarePreviewJson(result), formatSourceAwarePreviewText(result)]) {
      expect(output).not.toContain('user%3Apass');
      expect(output).not.toContain('opaquevalue123');
      expect(output).not.toContain('key%3D');
      expect(output).toContain('[REDACTED_');
    }
  });

  test('preview also bounds applied exception IDs without changing the full result', () => {
    const result = finalizeSourceAwareWorkspace(workspace([]), options);
    result.appliedExceptionIds = Array.from({ length: 1_000 }, (_, index) =>
      `EXC-2026-${String(index).padStart(64, '0')}`);
    const jsonText = formatSourceAwarePreviewJson(result);
    const json = JSON.parse(jsonText);
    const text = formatSourceAwarePreviewText(result);
    expect(json.appliedExceptionIds).toHaveLength(40);
    expect(json.omittedExceptionIds).toBe(960);
    expect(text).toContain('omittedExceptionIds=960');
    expect(result.appliedExceptionIds).toHaveLength(1_000);
    expect(Buffer.byteLength(jsonText)).toBeLessThanOrEqual(32_768);
    expect(Buffer.byteLength(text)).toBeLessThanOrEqual(32_768);
  });

  test('an invalid explicit date is a fixed input error before exception processing', () => {
    try {
      finalizeSourceAwareWorkspace(workspace(), { currentDate: 'not-a-date', failOn: 'never' });
      throw new Error('expected fixed error');
    } catch (error) {
      expect(error).toBeInstanceOf(SourceAwareFinalizationError);
      expect(error).toMatchObject({ code: 'SOURCE_FINALIZER_OPTIONS_INVALID', exitCode: 2 });
    }
  });
});
