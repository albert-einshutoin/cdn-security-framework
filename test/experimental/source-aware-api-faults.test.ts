import { expect, test, vi } from 'vitest';

vi.mock('../../src/bin/commands/source-diff', () => ({ prepareSourceDiff: vi.fn() }));

import { prepareSourceDiff } from '../../src/bin/commands/source-diff';
import { analyzeSourceDiff } from '../../src/experimental/source-aware';

const prepare = vi.mocked(prepareSourceDiff);
const options = { workspaceRoot: '/synthetic-workspace', openapiPath: 'openapi.yaml',
  policyPath: 'policy.yml', target: 'aws' as const, currentDate: '2026-09-28', failOn: 'never' as const };

test('preserves fixed input and finalizer diagnostics as errors without raw messages', async () => {
  prepare.mockResolvedValueOnce({ ok: false, code: 'SOURCE_DIFF_EXCEPTIONS_INVALID', exitCode: 2,
    message: 'secret from input' });
  expect(await analyzeSourceDiff(options)).toEqual({ kind: 'error',
    contract: 'experimental-source-aware@1', code: 'SOURCE_DIFF_EXCEPTIONS_INVALID',
    message: 'Source-aware input is invalid.', exitCode: 2 });

  prepare.mockResolvedValueOnce({ ok: false, code: 'SOURCE_FINDING_INPUT_INVALID', exitCode: 3,
    message: 'secret from finalizer' });
  expect(await analyzeSourceDiff(options)).toEqual({ kind: 'error',
    contract: 'experimental-source-aware@1', code: 'SOURCE_FINDING_INPUT_INVALID',
    message: 'Source-aware analysis failed.', exitCode: 3 });
});

test('normalizes thrown exceptions and rejects an unsafe projection', async () => {
  prepare.mockRejectedValueOnce(new Error('Bearer synthetic-secret-opaquevalue123'));
  const failure = await analyzeSourceDiff(options);
  expect(failure).toMatchObject({ kind: 'error', code: 'SOURCE_DIFF_INTERNAL', exitCode: 3 });
  expect(JSON.stringify(failure)).not.toContain('opaquevalue123');

  prepare.mockResolvedValueOnce({ ok: true,
    bundle: { finalized: { target: 'aws', stages: {}, comparisons: {}, findings: [],
      suppressedFindings: [], exceptionDiagnostics: [], appliedExceptionIds: [],
      memberships: [], summary: { unique: 0, active: 0, suppressed: 0, governance: 0 },
      analysis: { status: 'complete', outcome: 'ok', codes: [] },
      threshold: { failOn: 'never', reached: false }, exitCode: 0 },
    metadata: { targetCapabilities: [{ id: 'Bearer synthetic-secret-opaquevalue123', status: 'supported' }] } },
  } as never);
  expect(await analyzeSourceDiff(options)).toMatchObject({
    kind: 'error', code: 'SOURCE_DIFF_RESULT_UNSAFE', exitCode: 3,
  });
});
