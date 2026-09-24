import { describe, expect, test, vi } from 'vitest';

import { createFinding, type ContractDiffReportV1 } from '../../src/contract';
import { hasUnsafeSensitiveText } from '../../src/contract/sensitive-text';
import { renderUnifiedContractDiffJson } from '../../src/reporters/json';
import { renderUnifiedContractDiffText } from '../../src/reporters/text';
import { renderContractDiffGitHubSummary } from '../../src/reporters/github-summary';
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
  test.each([
    'authorization.SYNTHETIC_SECRET_890_VALUE.yaml',
    'backup-token=SYNTHETIC_SECRET_890_VALUE.yaml',
    'backup-token-opaquevalue123.yaml',
    'backup-token%2Dopaquevalue123.yaml',
    'authorization%252ESYNTHETIC_SECRET_890_VALUE.yaml',
    'nested%2Fauthorization.SYNTHETIC_SECRET_890_VALUE.yaml',
  ])('does not publish sensitive evidence filenames through report formats: %s', (uri) => {
    const input = report();
    input.inputDigests = { openapi: `sha256:${'a'.repeat(64)}`, policy: `sha256:${'b'.repeat(64)}`, exceptions: null };
    input.findings = [createFinding({
      ...input.findings[0],
      evidence: [{ ...input.findings[0].evidence[0], uri: `config/${uri}`, digest: `sha256:${'b'.repeat(64)}` }],
    })];
    expect(input.findings[0].evidence[0].uri).toBe('config/[REDACTED_FILENAME]');
    const outputs = [
      renderUnifiedContractDiffJson(input),
      renderUnifiedContractDiffText(input),
      JSON.stringify(renderUnifiedContractDiffSarif(input)),
      renderContractDiffGitHubSummary(input),
    ];
    for (const output of outputs) expect(output).not.toContain('SYNTHETIC_SECRET_890_VALUE');
    expect(outputs[0]).toContain('[REDACTED_FILENAME]');
    expect(outputs[1]).toContain('[REDACTED_FILENAME]');
    expect(outputs[2]).toContain('config/%5BREDACTED_FILENAME%5D');
  });

  test('rejects or masks a raw sensitive evidence filename at reporter boundaries', () => {
    const input = report();
    input.inputDigests = { openapi: `sha256:${'a'.repeat(64)}`, policy: `sha256:${'b'.repeat(64)}`, exceptions: null };
    input.findings[0] = {
      ...input.findings[0],
      evidence: [{ ...input.findings[0].evidence[0], uri: 'config/backup-token=SYNTHETIC_SECRET_890_VALUE.yaml', digest: `sha256:${'b'.repeat(64)}` }],
    };
    expect(() => renderUnifiedContractDiffJson(input)).toThrow('JSON_REPORT_PRIVACY_VIOLATION');
    expect(() => renderUnifiedContractDiffSarif(input)).toThrow('SARIF_PRIVACY_VIOLATION');
    expect(renderUnifiedContractDiffText(input)).not.toContain('SYNTHETIC_SECRET_890_VALUE');
    expect(renderContractDiffGitHubSummary(input)).not.toContain('SYNTHETIC_SECRET_890_VALUE');
  });

  test('rejects or masks a raw qualified hyphen credential filename at reporter boundaries', () => {
    const input = report();
    input.inputDigests = { openapi: `sha256:${'a'.repeat(64)}`, policy: `sha256:${'b'.repeat(64)}`, exceptions: null };
    input.findings[0] = {
      ...input.findings[0],
      evidence: [{ ...input.findings[0].evidence[0], uri: 'config/backup-token-opaquevalue123.yaml', digest: `sha256:${'b'.repeat(64)}` }],
    };
    expect(() => renderUnifiedContractDiffJson(input)).toThrow('JSON_REPORT_PRIVACY_VIOLATION');
    expect(() => renderUnifiedContractDiffSarif(input)).toThrow('SARIF_PRIVACY_VIOLATION');
    expect(renderUnifiedContractDiffText(input)).not.toContain('opaquevalue123');
    expect(renderContractDiffGitHubSummary(input)).not.toContain('opaquevalue123');
  });

  test.each([
    "{'credential':'ISSUE1020_VALUE','status':'failed'}",
    "{'credential':'prefix\\'ISSUE1020_VALUE','status':'failed','count':2}",
    '{"credentials":"prefix\\"ISSUE1020_VALUE","status":"failed","count":2}',
    "{'credential':'ISSUE1020_VALUE','status':'can\\'t authenticate'}",
    `{"credential":"ISSUE1020_VALUE","status":"can't authenticate"}`,
    "{'credential':'ISSUE1020_VALUE','password':'ISSUE1020_SECOND','status':'failed'}",
  ])('renders sanitized credential text through every reporter: %s', (message) => {
    const input = report();
    input.inputDigests = { openapi: `sha256:${'a'.repeat(64)}`, policy: `sha256:${'b'.repeat(64)}`, exceptions: null };
    const actual = [
      { kind: 'apiKey', credential: { location: 'header', names: ['x-client-key'] } },
      { kind: 'apiKey', credential: { location: 'query', names: ['client-key'] } },
      { kind: 'unknown', credentialStatus: 'unknown-v1-field' },
    ];
    const finding = createFinding({ ...input.findings[0], title: message, message, actual });
    input.findings = [finding];
    expect(finding.actual).toEqual(actual);
    expect(hasUnsafeSensitiveText(finding.message)).toBe(false);
    const sarif = renderUnifiedContractDiffSarif(input);
    expect(sarif.runs[0].results[0].message.text).toBe(finding.message);
    const json = renderUnifiedContractDiffJson(input);
    expect(JSON.parse(json).findings[0].actual).toEqual(actual);
    const text = renderUnifiedContractDiffText(input);
    for (const descriptor of ['header', 'query', 'x-client-key', 'client-key', 'unknown-v1-field']) {
      expect(text).toContain(descriptor);
    }
    for (const output of [JSON.stringify(sarif), json, text, renderContractDiffGitHubSummary(input)]) {
      expect(output).not.toContain('ISSUE1020_VALUE');
      expect(output).not.toContain('ISSUE1020_SECOND');
      expect(output).toContain('[REDACTED]');
    }
  });

  test.each([
    'ISSUE1020_RAW_VALUE',
    { value: 'ISSUE1020_RAW_VALUE' },
    ['ISSUE1020_RAW_VALUE'],
    { location: 'header', names: ['x-client-key'], value: 'ISSUE1020_RAW_VALUE' },
  ])('masks credential values without treating them as descriptors', (credential) => {
    const input = report();
    input.inputDigests = { openapi: `sha256:${'a'.repeat(64)}`, policy: `sha256:${'b'.repeat(64)}`, exceptions: null };
    const finding = createFinding({ ...input.findings[0], actual: { credential } });
    input.findings = [finding];
    expect(finding.actual).toEqual({ credential: '[REDACTED]' });
    for (const output of [renderUnifiedContractDiffJson(input), renderUnifiedContractDiffText(input)]) {
      expect(output).not.toContain('ISSUE1020_RAW_VALUE');
    }
    input.findings = [{ ...finding, actual: { credential } }];
    expect(renderUnifiedContractDiffText(input)).not.toContain('ISSUE1020_RAW_VALUE');
  });

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

  test('rejects percent-encoded provider tokens in evidence URIs', () => {
    const input = report();
    const seed = input.findings[0];
    const unsafeUri = 'artifacts/ghp%5Fsyntheticvalue12345678.txt';
    const normalized = createFinding({
      ...seed,
      evidence: [{
        ...seed.evidence[0],
        uri: unsafeUri,
      }],
    });
    expect(normalized.evidence[0].uri).toBe('artifacts/[REDACTED_FILENAME]');
    // Exercise the reporter's boundary with an untrusted Finding that bypassed normalization.
    input.findings = [{ ...normalized, evidence: [{ ...seed.evidence[0], uri: unsafeUri }] }];

    expect(() => renderUnifiedContractDiffSarif(input)).toThrowError(/SARIF_PRIVACY_VIOLATION/);
  });

  test('enforces the output byte limit before materializing every result', () => {
    const input = report();
    const seed = input.findings[0];
    input.findings = Array.from({ length: 100 }, (_, index) => createFinding({
      ...seed,
      title: `Finding ${index}`,
      message: `Finding ${index} is outside the allowed surface.`,
      route: { ...seed.route, path: `/admin/${index}` },
    }));
    const stringify = vi.spyOn(JSON, 'stringify');

    try {
      expect(() => renderUnifiedContractDiffSarif(input, { maxOutputBytes: 4_096 }))
        .toThrowError(/SARIF_OUTPUT_LIMIT_EXCEEDED/);
      const materializedFullOutput = stringify.mock.calls.some(([value]) => {
        if (!value || typeof value !== 'object') return false;
        const runs = (value as { runs?: Array<{ results?: unknown[] }> }).runs;
        return runs?.[0]?.results?.length === input.findings.length;
      });
      expect(materializedFullOutput).toBe(false);
    } finally {
      stringify.mockRestore();
    }
  });

  test('enforces the output byte limit before materializing diagnostic notifications', () => {
    const input = report();
    input.analyzerDiagnostics = Array.from({ length: 100 }, (_, index) => ({
      code: 'OPENAPI_LIMIT_NEAR' as const,
      level: 'warning' as const,
      message: `Diagnostic ${index}`,
    }));
    const stringify = vi.spyOn(JSON, 'stringify');

    try {
      expect(() => renderUnifiedContractDiffSarif(input, { maxOutputBytes: 4_096 }))
        .toThrowError(/SARIF_OUTPUT_LIMIT_EXCEEDED/);
      const materializedFullInvocation = stringify.mock.calls.some(([value]) => {
        if (!value || typeof value !== 'object') return false;
        const runs = (value as {
          runs?: Array<{
            invocations?: Array<{
              toolExecutionNotifications?: Array<{ descriptor?: { id?: string } }>;
            }>;
          }>;
        }).runs;
        return runs?.[0]?.invocations?.[0]?.toolExecutionNotifications
          ?.filter(({ descriptor }) => descriptor?.id === 'SARIF_ANALYZER_DIAGNOSTIC').length
          === input.analyzerDiagnostics.length;
      });
      expect(materializedFullInvocation).toBe(false);
    } finally {
      stringify.mockRestore();
    }
  });

  test('enforces the output byte limit before materializing auxiliary properties', () => {
    const input = report();
    input.omittedComparisons = Array.from({ length: 1_000 }, (_, index) => `comparison-${index}`);
    const stringify = vi.spyOn(JSON, 'stringify');

    try {
      expect(() => renderUnifiedContractDiffSarif(input, { maxOutputBytes: 4_096 }))
        .toThrowError(/SARIF_OUTPUT_LIMIT_EXCEEDED/);
      const materializedFullProperties = stringify.mock.calls.some(([value]) => {
        if (!value || typeof value !== 'object') return false;
        const runs = (value as {
          runs?: Array<{
            tool?: { driver?: { properties?: { omittedComparisons?: unknown[] } } };
          }>;
        }).runs;
        return runs?.[0]?.tool?.driver?.properties?.omittedComparisons?.length
          === input.omittedComparisons.length;
      });
      expect(materializedFullProperties).toBe(false);
    } finally {
      stringify.mockRestore();
    }
  });

  test('accepts the exact serialized output byte boundary', () => {
    const input = report();
    const output = renderUnifiedContractDiffSarif(input);
    const outputBytes = Buffer.byteLength(JSON.stringify(output), 'utf8');

    expect(renderUnifiedContractDiffSarif(input, { maxOutputBytes: outputBytes })).toEqual(output);
    expect(() => renderUnifiedContractDiffSarif(input, { maxOutputBytes: outputBytes - 1 }))
      .toThrowError(/SARIF_OUTPUT_LIMIT_EXCEEDED/);
  });

  test('escapes remediation Markdown before placing it in SARIF help', () => {
    const input = report();
    input.findings[0] = {
      ...input.findings[0],
      remediation: { summary: '[review](file:///etc/passwd)', safeAutoFix: false },
    };

    const help = renderUnifiedContractDiffSarif(input).runs[0].tool.driver.rules[0].help;
    expect(help.text).toBe('[review](file:///etc/passwd)');
    expect(help.markdown).toBe('\\[review\\]\\(file:///etc/passwd\\)');
  });

  test.each([
    ['Bearer [REDACTED]actual-token', true],
    ['Bearer [REDACTED],actual-token', true],
    ['Bearer [REDACTED], actual-token', true],
    ['Bearer [REDACTED] actual-token', true],
    ['Bearer [REDACTED]\n actual-token', true],
    ['Bearer [REDACTED]"actual-token', true],
    ['Bearer [REDACTED]" actual-token', true],
    ['Bearer [REDACTED]"}actual-token', true],
    ['Bearer [REDACTED]",actual-token', true],
    ['?token=[REDACTED]actual-token', true],
    ['?token=[REDACTED],actual-token', true],
    ['?token=[REDACTED], actual-token', true],
    ['?token=[REDACTED] actual-token', true],
    ['?token=[REDACTED]#actual-token', true],
    ['?token=[REDACTED]&actual-token', true],
    ['?token=[REDACTED]"}actual-token', true],
    ['?token=[REDACTED]",actual-token', true],
    ['token=[REDACTED],actual-token', true],
    ['token=[REDACTED], actual-token', true],
    ['token=[REDACTED] actual-token', true],
    ['token="[REDACTED]"actual-token', true],
    ['token="[REDACTED]"}actual-token', true],
    ['token="[REDACTED]",actual-token', true],
    ['Cookie: [REDACTED]&actual-token', true],
    ['Cookie: [REDACTED]\r\n session=actual-token', true],
    ['Digest [REDACTED], response=actual-token', true],
    ['password=[REDACTED]#actual-token', true],
    ['Bearer [REDACTED]', false],
    ['Bearer [REDACTED]"', false],
    ['Cookie: [REDACTED],', false],
    ['?token=[REDACTED]', false],
    ['?token=[REDACTED],', false],
    ['?token=[REDACTED]&session=[REDACTED]', false],
    ['password=[REDACTED]#', false],
    ['token="[REDACTED]",', false],
  ])('handles redaction marker boundaries: %s', (message, shouldReject) => {
    const input = report();
    input.findings = input.findings.map((finding) => ({ ...finding, message }));
    if (shouldReject) {
      expect(() => renderUnifiedContractDiffSarif(input)).toThrowError(/SARIF_PRIVACY_VIOLATION/);
    } else {
      expect(() => renderUnifiedContractDiffSarif(input)).not.toThrow();
    }
  });

  test.each([
    'Analyzer detail sk-proj-syntheticvalue123',
    'Analyzer detail ghp_syntheticvalue12345678',
    'Analyzer detail gho_syntheticvalue12345678',
    'Analyzer detail ghu_syntheticvalue12345678',
    'Analyzer detail ghs_syntheticvalue12345678',
    'Analyzer detail ghr_syntheticvalue12345678',
    'Analyzer detail ghs_APPID.eyJhbGciOiJIUzI1NiJ9.signature',
    '"token": "raw-secret"',
    'Digest username="user", response="digest-secret"',
    'Digest raw-digest-secret',
    'AWS4-HMAC-SHA256 raw-aws-secret',
    'Hawk raw-hawk-secret',
    'Signature raw-signature-secret',
    'Negotiate negotiate-secret',
  ])('rejects raw credentials outside the Finding factory: %s', (message) => {
    const input = report();
    input.findings = input.findings.map((finding) => ({ ...finding, message }));
    expect(() => renderUnifiedContractDiffSarif(input)).toThrowError(/SARIF_PRIVACY_VIOLATION/);
  });

  test('accepts a sanitized JSON value followed by a non-sensitive field', () => {
    const input = report();
    input.findings = input.findings.map((finding) => ({
      ...finding,
      message: '{"token":"[REDACTED]","status":"ok"}',
    }));

    expect(() => renderUnifiedContractDiffSarif(input)).not.toThrow();
  });

  test.each([2, 'token=actual-secret'])('rejects a report schema mismatch before output', (schemaVersion) => {
    const input = { ...report(), schemaVersion } as unknown as ContractDiffReportV1;

    expect(() => renderUnifiedContractDiffSarif(input)).toThrowError(/SARIF_UNIFIED_REPORT_INVALID/);
  });

  test.each([
    'Bearer [REDACTED]\nStatus: ok',
    'token=[REDACTED]\nstatus=ok',
    '{"token":"[REDACTED]" , "status":"ok"}',
    '{"token":"[REDACTED]" }',
  ])('accepts safe continuation after a redacted value: %s', (message) => {
    const input = report();
    input.findings = input.findings.map((finding) => ({ ...finding, message }));

    expect(() => renderUnifiedContractDiffSarif(input)).not.toThrow();
  });

  test('does not promote a generated or runtime-only evidence item to primary', () => {
    const input = report();
    const seed = input.findings[0];
    input.findings = [createFinding({
      ...seed,
      evidence: [{ ...seed.evidence[0], source: 'runtime', uri: 'runtime/events.json' }],
    })];

    const result = renderUnifiedContractDiffSarif(input).runs[0].results[0];
    expect(result.locations).toBeUndefined();
    expect(result.relatedLocations?.[0].physicalLocation.artifactLocation.uri)
      .toBe('runtime/events.json');
  });

  test('reports truncation when runtime-only evidence exceeds the related location limit', () => {
    const input = report();
    const seed = input.findings[0];
    input.findings = [createFinding({
      ...seed,
      evidence: [
        { ...seed.evidence[0], source: 'runtime', uri: 'runtime/first.json', pointer: '/events/0' },
        { ...seed.evidence[0], source: 'runtime', uri: 'runtime/second.json', pointer: '/events/1' },
      ],
    })];

    const output = renderUnifiedContractDiffSarif(input, { maxRelatedLocations: 1 });
    const notifications = output.runs[0].invocations?.[0].toolExecutionNotifications ?? [];
    expect(notifications.some(({ descriptor }) => descriptor.id === 'SARIF_OUTPUT_TRUNCATED')).toBe(true);
    expect(output.runs[0].results[0].locations).toBeUndefined();
    expect(output.runs[0].results[0].relatedLocations).toHaveLength(1);
  });

  test('deduplicates evidence after URI normalization', () => {
    const input = report();
    const seed = input.findings[0];
    input.findings = [createFinding({
      ...seed,
      evidence: [
        { ...seed.evidence[0], source: 'openapi', uri: 'specs/open api.yml', pointer: '/paths' },
        { ...seed.evidence[0], source: 'policy', uri: 'specs/open%20api.yml', pointer: ' /paths ' },
      ],
    })];

    const result = renderUnifiedContractDiffSarif(input).runs[0].results[0];
    const locations = [...(result.locations ?? []), ...(result.relatedLocations ?? [])];
    expect(locations).toHaveLength(1);
    expect(locations[0].physicalLocation.artifactLocation.uri).toBe('specs/open%20api.yml');
  });

  test('keeps the rule-family primary source when normalized locations match', () => {
    const input = report();
    const seed = input.findings[0];
    input.findings = [createFinding({
      ...seed,
      ruleId: 'SC-REQUEST-002',
      evidence: [
        { ...seed.evidence[0], source: 'openapi', uri: 'shared/evidence.yml', pointer: '/same' },
        { ...seed.evidence[0], source: 'policy', uri: 'shared/evidence.yml', pointer: '/same' },
      ],
    })];

    const result = renderUnifiedContractDiffSarif(input).runs[0].results[0];
    expect(result.properties?.evidenceSources).toEqual(['policy']);
  });

  test.each(['line:0:column:1', 'line:1:column:0', `line:${'9'.repeat(309)}:column:1`])(
    'rejects invalid source coordinates: %s',
    (pointer) => {
      const input = report();
      input.findings[0].evidence = input.findings[0].evidence.map((evidence) => ({ ...evidence, pointer }));
      expect(() => renderUnifiedContractDiffSarif(input)).toThrowError(/SARIF_LOCATION_INVALID/);
    },
  );

  test('rejects oversized evidence before unbounded sorting', () => {
    const input = report();
    const seed = input.findings[0];
    input.findings = [{
      ...seed,
      evidence: Array.from({ length: 1_025 }, (_, index) => ({
        ...seed.evidence[0],
        uri: `policy/${index}.yml`,
        pointer: `/routes/${index}`,
      })),
    }];

    expect(() => renderUnifiedContractDiffSarif(input)).toThrowError(/SARIF_UNIFIED_REPORT_INVALID/);
  });

  test('rejects oversized finding text before sorting', () => {
    const input = report();
    input.findings[0] = {
      ...input.findings[0],
      route: { ...input.findings[0].route, path: 'x'.repeat(16_385) },
    };

    expect(() => renderUnifiedContractDiffSarif(input)).toThrowError(/SARIF_UNIFIED_REPORT_INVALID/);
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
