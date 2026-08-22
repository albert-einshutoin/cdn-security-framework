import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';

import {
  applyFindingExceptions,
  createFinding,
  loadFindingExceptions,
  validateFindingExceptionSet,
  type FindingExceptionSetV1,
  type FindingInputV1,
} from '../../src/contract';

const baseFinding: FindingInputV1 = {
  ruleId: 'SC-AUTHN-001',
  severity: 'warning',
  confidence: 'deterministic',
  category: 'authentication',
  title: 'Missing Edge authentication',
  message: 'The operation has no enforced Edge auth gate.',
  route: { method: 'POST', path: '/webhooks/stripe' },
  evidence: [{
    source: 'openapi', uri: 'openapi.yaml', digest: 'sha256:openapi',
    analyzer: 'openapi@1', capability: 'openapi-contract-v1', complete: true,
  }],
};

function exceptionSet(exceptions: FindingExceptionSetV1['exceptions']): FindingExceptionSetV1 {
  return { version: 1, exceptions };
}

describe('Finding Exception Contract v1', () => {
  test('applies the most specific live exception and retains expired, unused, and duplicate evidence', () => {
    const auth = createFinding(baseFinding);
    const request = createFinding({
      ...baseFinding,
      ruleId: 'SC-REQUEST-002',
      severity: 'error',
      category: 'misconfiguration',
      route: { method: 'GET', path: '/items' },
    });
    const result = applyFindingExceptions([request, auth], exceptionSet([
      {
        id: 'EXC-2026-001', rule_id: 'SC-AUTHN-001',
        selector: { method: 'POST', path: '/webhooks/stripe', target: 'cloudflare' },
        reason: 'The application verifies the signed webhook payload.',
        owner: 'payments-team', expires_at: '2026-12-01', ticket: 'SEC-123',
      },
      {
        id: 'EXC-2026-002', rule_id: 'SC-AUTHN-001',
        selector: { instance_id: auth.instanceId, target: 'cloudflare' },
        reason: 'The application verifies the signed webhook payload.',
        owner: 'payments-team', expires_at: '2026-12-01',
      },
      {
        id: 'EXC-2026-003', rule_id: 'SC-REQUEST-002',
        selector: { method: 'GET', path: '/items' },
        reason: 'Legacy clients require a temporary compatibility window.',
        owner: 'api-team', expires_at: '2026-01-01',
      },
      {
        id: 'EXC-2026-004', rule_id: 'SC-LIMIT-001',
        selector: { method: 'GET', path: '/missing' },
        reason: 'Temporary exception while the client migration completes.',
        owner: 'api-team', expires_at: '2026-12-01',
      },
      {
        id: 'EXC-2026-005', rule_id: 'SC-AUTHN-001',
        selector: { method: 'GET', path: '/other-target', target: 'aws' },
        reason: 'This exception is evaluated only in its selected target.',
        owner: 'api-team', expires_at: '2026-12-01',
      },
    ]), {
      currentDate: '2026-08-23', target: 'cloudflare', environment: 'production',
      sourceUri: path.join(process.cwd(), 'policy/finding-exceptions.yml'),
    });

    expect(result.suppressedFindings).toEqual([auth]);
    expect(result.appliedExceptionIds).toEqual(['EXC-2026-002']);
    expect(result.findings.map(({ ruleId }) => ruleId)).toEqual([
      'SC-GOV-001', 'SC-REQUEST-002', 'SC-GOV-002', 'SC-GOV-003',
    ]);
    expect(result.summary).toEqual({ before: 2, after: 1, suppressed: 1, governance: 3 });
    expect(result.findings.filter(({ category }) => category === 'governance')
      .every(({ evidence }) => evidence[0]?.uri === 'finding-exceptions.yml')).toBe(true);
    expect(result.findings.find(({ ruleId }) => ruleId === 'SC-GOV-001')?.evidence[0]?.pointer)
      .toBe('/exceptions/2');
    expect(result.findings.find(({ ruleId }) => ruleId === 'SC-GOV-002')?.evidence[0]?.pointer)
      .toBe('/exceptions/3');
    expect(result.findings.find(({ ruleId }) => ruleId === 'SC-GOV-003')?.evidence[0]?.pointer)
      .toBeUndefined();
    expect(JSON.stringify(result)).not.toContain('signed webhook payload');
  });

  test('rejects invalid, broad, unknown, duplicate, and secret-bearing exception input', () => {
    const valid = {
      id: 'EXC-2026-001', rule_id: 'SC-AUTHN-001',
      selector: { method: 'POST', path: '/webhooks/stripe' },
      reason: 'The application verifies the signed webhook payload.',
      owner: 'payments-team', expires_at: '2026-12-01',
    };
    expect(validateFindingExceptionSet(exceptionSet([valid]), { currentDate: '2026-08-23' }))
      .toEqual({ valid: true, errors: [] });
    const broad = {
      ...valid,
      selector: {},
      allow_broad: true,
      broad_reason: 'A temporary rule-wide waiver is required during migration.',
    };
    expect(applyFindingExceptions([createFinding(baseFinding)], exceptionSet([broad]), {
      currentDate: '2026-08-23',
    }).suppressedFindings).toHaveLength(1);
    const routeWildcard = {
      ...broad,
      id: 'EXC-2026-999',
      selector: { method: '*', path: '*' },
    };
    const narrowWildcard = {
      ...broad,
      id: 'EXC-2026-002',
      selector: { method: 'POST', path: '/webhooks/*' },
    };
    expect(applyFindingExceptions(
      [createFinding(baseFinding)],
      exceptionSet([broad, routeWildcard, narrowWildcard]), {
      currentDate: '2026-08-23',
      },
    ).appliedExceptionIds).toEqual(['EXC-2026-002']);

    const invalid = exceptionSet([
      valid,
      { ...valid },
      { ...valid, id: 'EXC-2026-002', rule_id: 'SC-UNKNOWN-001' },
      {
        ...valid, id: 'EXC-2026-003', selector: {},
        reason: 'Temporary waiver because {"password":"hunter2"} remains in use.',
      },
    ] as FindingExceptionSetV1['exceptions']);
    const result = validateFindingExceptionSet(invalid, { currentDate: '2026-08-23' });
    expect(result.valid).toBe(false);
    expect(result.errors.join('\n')).toMatch(/duplicate|unknown rule|broad|sensitive/i);
  });

  test('loads bounded YAML inside the workspace and rejects duplicate mappings', () => {
    const workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'finding-exceptions-'));
    const inputPath = path.join(workspaceRoot, 'exceptions.yml');
    fs.writeFileSync(inputPath, `version: 1
exceptions:
  - id: EXC-2026-001
    rule_id: SC-AUTHN-001
    selector: { method: POST, path: /webhooks/stripe }
    reason: The application verifies the signed webhook payload.
    owner: payments-team
    expires_at: 2026-12-01
`);
    expect(loadFindingExceptions({ inputPath, workspaceRoot, currentDate: '2026-08-23' })
      .exceptions[0].id).toBe('EXC-2026-001');

    fs.writeFileSync(inputPath, 'version: 1\nversion: 1\nexceptions: []\n');
    expect(() => loadFindingExceptions({ inputPath, workspaceRoot, currentDate: '2026-08-23' }))
      .toThrow('invalid Finding exception file');
    expect(() => loadFindingExceptions({
      inputPath: path.join(workspaceRoot, '..', 'outside.yml'), workspaceRoot, currentDate: '2026-08-23',
    })).toThrow('outside workspace');

    fs.writeFileSync(inputPath, 'x'.repeat(1_048_577));
    expect(() => loadFindingExceptions({ inputPath, workspaceRoot, currentDate: '2026-08-23' }))
      .toThrow('too large');
    expect(() => loadFindingExceptions({ inputPath: workspaceRoot, workspaceRoot, currentDate: '2026-08-23' }))
      .toThrow('outside workspace');
  });

  test('rejects forged Finding IDs and excessive comparison work', () => {
    const finding = createFinding(baseFinding);
    const forged = { ...finding, route: { method: 'POST', path: '/other' } };
    expect(() => applyFindingExceptions([forged], exceptionSet([]), { currentDate: '2026-08-23' }))
      .toThrow('canonical identity');

    const broad = Array.from({ length: 10_000 }, (_, index) => ({
      id: `EXC-2026-${String(index).padStart(5, '0')}`,
      rule_id: 'SC-AUTHN-001', selector: {},
      reason: 'Temporary rule-wide waiver during a controlled migration.',
      owner: 'security-team', expires_at: '2026-12-01', allow_broad: true,
      broad_reason: 'The migration cannot yet isolate individual routes safely.',
    }));
    expect(() => applyFindingExceptions(Array(101).fill(finding), exceptionSet(broad), {
      currentDate: '2026-08-23',
    })).toThrow('visit budget');

    const excessiveEvidence = {
      ...finding,
      evidence: Array(1_000_001).fill(finding.evidence[0]),
    };
    expect(() => applyFindingExceptions([excessiveEvidence], exceptionSet([]), {
      currentDate: '2026-08-23',
    })).toThrow('visit budget');

    const accessor = { ...finding };
    Object.defineProperty(accessor, 'instanceId', { get: () => finding.instanceId });
    expect(() => applyFindingExceptions([accessor], exceptionSet([]), {
      currentDate: '2026-08-23',
    })).toThrow('invalid Finding exception input');

    const inheritedAccessor = { ...finding };
    delete inheritedAccessor.route;
    Object.setPrototypeOf(inheritedAccessor, {
      get route(): never { throw new Error('inherited getter executed'); },
    });
    expect(() => applyFindingExceptions([inheritedAccessor], exceptionSet([]), {
      currentDate: '2026-08-23',
    })).toThrow('invalid Finding exception input');

    const symbolAccessor = { ...finding };
    Object.defineProperty(symbolAccessor, Symbol('accessor'), {
      enumerable: true,
      get: () => { throw new Error('symbol getter executed'); },
    });
    expect(() => applyFindingExceptions([symbolAccessor], exceptionSet([]), {
      currentDate: '2026-08-23',
    })).toThrow('invalid Finding exception input');
  });
});
