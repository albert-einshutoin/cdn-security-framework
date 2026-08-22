import fs from 'node:fs';
import path from 'node:path';
import Ajv from 'ajv';
import { describe, expect, test } from 'vitest';

import {
  computeFindingInstanceId,
  createFinding,
  FINDING_CATEGORIES,
  FINDING_CONFIDENCES,
  FINDING_EVIDENCE_SOURCES,
  FINDING_SEVERITIES,
  sortFindings,
  type FindingInputV1,
} from '../../src/contract';

const baseInput: FindingInputV1 = {
  ruleId: 'SC-INVENTORY-001',
  severity: 'error',
  confidence: 'deterministic',
  category: 'inventory',
  title: 'Undocumented endpoint',
  message: 'The implemented route is absent from OpenAPI.',
  route: { method: 'get', path: '/users', operationId: 'listUsers' },
  evidence: [
    {
      source: 'source-ast',
      uri: 'src/routes/users.ts',
      pointer: '/routes/0',
      digest: 'sha256:source',
      analyzer: 'express@1',
      capability: 'express-routes-v1',
      complete: true,
    },
    {
      source: 'openapi',
      uri: 'openapi.yaml',
      pointer: '/paths/~1users',
      digest: 'sha256:openapi',
      analyzer: 'openapi@1',
      capability: 'openapi-contract-v1',
      complete: true,
    },
  ],
};

describe('Finding Contract v1', () => {
  test('creates a fixture accepted by the JSON Schema', () => {
    const schema = JSON.parse(fs.readFileSync(
      path.join(process.cwd(), 'schemas/finding-v1.schema.json'),
      'utf8',
    ));
    const validate = new Ajv({ allErrors: true }).compile(schema);

    expect(validate(createFinding(baseInput)), JSON.stringify(validate.errors)).toBe(true);
    expect(validate(createFinding({
      ...baseInput,
      route: undefined,
      evidence: [{
        source: 'policy',
        uri: 'policy/security.yml',
        digest: 'sha256:policy',
        analyzer: 'policy@1',
        capability: 'policy-routes-v1',
        complete: true,
      }],
    })), JSON.stringify(validate.errors)).toBe(true);

    expect(schema.properties.severity.enum).toEqual([...FINDING_SEVERITIES]);
    expect(schema.properties.confidence.enum).toEqual([...FINDING_CONFIDENCES]);
    expect(schema.properties.category.enum).toEqual([...FINDING_CATEGORIES]);
    expect(schema.definitions.evidence.properties.source.enum).toEqual([...FINDING_EVIDENCE_SOURCES]);

    const invalid = { ...createFinding(baseInput), severity: 'critical' };
    expect(validate(invalid)).toBe(false);
    expect(validate.errors?.[0]).toMatchObject({ instancePath: '/severity' });
  });

  test('keeps instance IDs stable across message, workspace, separator, and evidence order changes', () => {
    const expected = computeFindingInstanceId(baseInput);

    for (let i = 0; i < 100; i += 1) {
      const changed: FindingInputV1 = {
        ...baseInput,
        message: `Changed wording ${i}`,
        evidence: [...baseInput.evidence].reverse().map((evidence) => ({
          ...evidence,
          uri: i % 2 === 0
            ? `C:\\workspace-${i}\\${evidence.uri?.replace(/\//g, '\\')}`
            : `/different-root-${i}/${evidence.uri}`,
        })),
      };
      const workspaceRoot = i % 2 === 0 ? `C:\\workspace-${i}` : `/different-root-${i}`;
      expect(computeFindingInstanceId(changed, { workspaceRoot })).toBe(expected);
      expect(createFinding(changed, { workspaceRoot }).instanceId).toBe(expected);
    }

    expect(computeFindingInstanceId({
      ...baseInput,
      route: { ...baseInput.route, method: 'POST' },
    })).not.toBe(expected);
  });

  test('sorts by severity, rule, path, method, then instance ID without mutating input', () => {
    const findings = [
      createFinding({ ...baseInput, ruleId: 'SC-INVENTORY-002', severity: 'warning' }),
      createFinding({ ...baseInput, ruleId: 'SC-INVENTORY-001', severity: 'info' }),
      createFinding({ ...baseInput, ruleId: 'SC-INVENTORY-002', severity: 'error' }),
      createFinding({ ...baseInput, ruleId: 'SC-INVENTORY-001', severity: 'error' }),
    ];
    const before = [...findings];

    expect(sortFindings(findings).map(({ severity, ruleId }) => `${severity}:${ruleId}`)).toEqual([
      'error:SC-INVENTORY-001',
      'error:SC-INVENTORY-002',
      'warning:SC-INVENTORY-002',
      'info:SC-INVENTORY-001',
    ]);
    expect(findings).toEqual(before);
  });

  test('redacts sensitive headers and query values before returning a Finding', () => {
    const finding = createFinding({
      ...baseInput,
      message: 'Authorization: Bearer message-secret\nCookie: sid=first-secret; refresh=second-secret',
      expected: {
        headers: {
          authorization: 'Bearer object-secret',
          cookie: 'session=cookie-secret',
          'x-api-key': 'api-key-secret',
        },
        callback: 'https://example.test/callback?token=query-secret&safe=visible-secret',
      },
      actual: 'Bearer raw-secret token=token-secret password="alpha beta" {"password":"json-secret"}',
      evidence: [{
        source: 'openapi',
        uri: 'openapi.yaml?api_key=uri-secret',
        pointer: '/paths/~1users',
        digest: 'sha256:openapi',
        analyzer: 'openapi@1',
        capability: 'openapi-contract-v1',
        complete: true,
      }],
    });
    const serialized = JSON.stringify(finding);

    for (const secret of [
      'message-secret', 'object-secret', 'cookie-secret', 'api-key-secret',
      'query-secret', 'visible-secret', 'raw-secret', 'uri-secret', 'first-secret',
      'second-secret', 'token-secret', 'password-secret',
      'alpha beta', 'json-secret',
    ]) {
      expect(serialized).not.toContain(secret);
    }
    expect(serialized).toContain('[REDACTED]');
  });

  test('rejects invalid runtime fields and bounds deeply nested values', () => {
    expect(() => createFinding({ ...baseInput, severity: 'critical' } as unknown as FindingInputV1))
      .toThrow('invalid Finding fields');
    expect(() => createFinding({
      ...baseInput,
      evidence: [{ source: 'policy' }],
    } as unknown as FindingInputV1)).toThrow('invalid Finding evidence');

    const root: Record<string, unknown> = {};
    let cursor = root;
    for (let i = 0; i < 100; i += 1) {
      cursor.next = {};
      cursor = cursor.next as Record<string, unknown>;
    }
    expect(JSON.stringify(createFinding({ ...baseInput, actual: root })))
      .toContain('[REDACTED_DEPTH_LIMIT]');

    const bounded = createFinding({ ...baseInput, actual: `${'x'.repeat(100_000)} password=late-secret` });
    expect(JSON.stringify(bounded)).not.toContain('late-secret');
    expect(String(bounded.actual).length).toBeLessThan(17_000);

    const boundarySecret = createFinding({
      ...baseInput,
      actual: `password="${'secret '.repeat(3_000)}"`,
    });
    expect(String(boundarySecret.actual)).not.toContain('secret');

    const manySensitiveKeys = Object.fromEntries(
      Array.from({ length: 10_100 }, (_, index) => [`token${index}`, `value-${index}`]),
    );
    const boundedObject = createFinding({ ...baseInput, actual: manySensitiveKeys });
    expect(Object.keys(boundedObject.actual as Record<string, unknown>).length).toBeLessThanOrEqual(10_000);
  });

  test('returns inert JSON data and rejects ambiguous route and file URI inputs', () => {
    const finding = createFinding({
      ...baseInput,
      expected: {
        password: 'visible-property-secret',
        toJSON() {
          return { password: 'to-json-secret' };
        },
      },
    });
    const serialized = JSON.stringify(finding);
    expect(serialized).not.toContain('visible-property-secret');
    expect(serialized).not.toContain('to-json-secret');
    expect(serialized).toContain('[REDACTED_UNSUPPORTED]');

    expect(() => createFinding({
      ...baseInput,
      route: { method: '   ' },
    })).toThrow('invalid Finding route');
    expect(() => createFinding({
      ...baseInput,
      evidence: [{
        ...baseInput.evidence[0],
        uri: 'file:///private/workspace/openapi.yaml',
      }],
    })).toThrow('Finding file evidence uri is not supported');
  });
});
