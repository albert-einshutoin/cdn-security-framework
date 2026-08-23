import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';

import {
  DEFAULT_SOURCE_ANALYSIS_LIMITS,
  SourceAnalyzerRegistry,
  runSourceAnalyzer,
  validateSourceAnalysisLimits,
  validateSourceAnalyzerPlugin,
  type SourceAnalysisMetrics,
  type SourceAnalyzerPlugin,
} from '../../src/source-analysis';
import { fakeSourceAnalyzer } from '../fixtures/source-analysis/fake-analyzer';

const roots: string[] = [];
const logger = { log() {} };

function workspace(): { root: string; entrypoint: string } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'source-analyzer-'));
  roots.push(root);
  const entrypoint = 'src/app.ts';
  fs.mkdirSync(path.join(root, 'src'));
  fs.writeFileSync(path.join(root, entrypoint), 'export const route = "/health";\n');
  return { root, entrypoint };
}

function plugin(overrides: Partial<SourceAnalyzerPlugin> = {}): SourceAnalyzerPlugin {
  return { ...fakeSourceAnalyzer, ...overrides };
}

function context(root: string, entrypoint: string, limits = DEFAULT_SOURCE_ANALYSIS_LIMITS) {
  return { workspaceRoot: root, entrypoints: [entrypoint], limits, logger };
}

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe('Source Analyzer contract', () => {
  test('accepts a valid fake analyzer and returns normalized Security IR', async () => {
    const { root, entrypoint } = workspace();
    expect(validateSourceAnalyzerPlugin(fakeSourceAnalyzer)).toBe(fakeSourceAnalyzer);
    expect(validateSourceAnalysisLimits(DEFAULT_SOURCE_ANALYSIS_LIMITS)).toEqual(DEFAULT_SOURCE_ANALYSIS_LIMITS);

    const execution = await runSourceAnalyzer(fakeSourceAnalyzer, context(root, entrypoint));
    expect(execution.status).toBe('success');
    if (execution.status !== 'success') return;
    expect(execution.result.contract).toMatchObject({ source: 'source-ast', schemaVersion: 1 });
    expect(execution.result.contract.operations[0]).toMatchObject({ routeKey: 'GET /health' });
    expect(JSON.stringify(execution)).not.toContain(root);
  });

  test('rejects invalid plugin metadata and capabilities with stable codes', () => {
    expect(() => validateSourceAnalyzerPlugin(plugin({ version: '1.0' })))
      .toThrow(expect.objectContaining({ code: 'SOURCE_ANALYZER_INVALID_PLUGIN' }));
    for (const version of ['1.0.0-01', '1.0.0-alpha.01']) {
      expect(() => validateSourceAnalyzerPlugin(plugin({ version })))
        .toThrow(expect.objectContaining({ code: 'SOURCE_ANALYZER_INVALID_PLUGIN' }));
    }
    expect(() => validateSourceAnalyzerPlugin(plugin({
      capabilities: {
        ...fakeSourceAnalyzer.capabilities,
        authentication: { status: 'partial', reason: '' },
      },
    }))).toThrow(expect.objectContaining({ code: 'SOURCE_ANALYZER_INVALID_PLUGIN' }));
    expect(() => validateSourceAnalysisLimits({ ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxFiles: 0 }))
      .toThrow(expect.objectContaining({ code: 'SOURCE_ANALYZER_INVALID_LIMITS' }));
  });

  test('registers analyzers deterministically and rejects duplicate or unknown identities', () => {
    const second = plugin({ id: 'alpha', version: '2.0.0' });
    const registry = new SourceAnalyzerRegistry([fakeSourceAnalyzer, second]);
    expect(registry.list().map(({ id, version }) => `${id}@${version}`))
      .toEqual(['alpha@2.0.0', 'fake-typescript@1.0.0']);
    expect(registry.get('fake-typescript', '1.0.0')).toBe(fakeSourceAnalyzer);
    expect(() => new SourceAnalyzerRegistry([fakeSourceAnalyzer, fakeSourceAnalyzer]))
      .toThrow(expect.objectContaining({ code: 'SOURCE_ANALYZER_DUPLICATE' }));
    expect(() => registry.get('missing', '1.0.0'))
      .toThrow(expect.objectContaining({ code: 'SOURCE_ANALYZER_UNKNOWN' }));
  });

  test('rejects outside-root entrypoints and file byte limits before analysis', async () => {
    const { root, entrypoint } = workspace();
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'source-analyzer-outside-'));
    roots.push(outside);
    fs.writeFileSync(path.join(outside, 'outside.ts'), 'export {};\n');

    const outsideResult = await runSourceAnalyzer(fakeSourceAnalyzer, context(root, path.join(outside, 'outside.ts')));
    expect(outsideResult).toMatchObject({
      status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_INPUT_OUTSIDE_ROOT' }],
    });
    const byteResult = await runSourceAnalyzer(fakeSourceAnalyzer, context(root, entrypoint, {
      ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxFileBytes: 1,
    }));
    expect(byteResult).toMatchObject({
      status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_FILE_BYTES_LIMIT' }],
    });
  });

  test('converts throws, invalid IR, absolute evidence, and secret diagnostics to safe failure', async () => {
    const { root, entrypoint } = workspace();
    const throwing = plugin({
      async analyze() { throw new Error('token=must-not-leak'); },
    });
    const thrown = await runSourceAnalyzer(throwing, context(root, entrypoint));
    expect(thrown).toMatchObject({ status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_INTERNAL' }] });
    expect(JSON.stringify(thrown)).not.toContain('must-not-leak');

    const invalid = plugin({
      async analyze(ctx) {
        const valid = await fakeSourceAnalyzer.analyze(ctx);
        return {
          ...valid,
          contract: { ...valid.contract, source: 'openapi' },
          diagnostics: [{
            code: 'SOURCE_ANALYZER_DYNAMIC_ROUTE', safeMessage: 'token=must-not-leak',
            sourceUri: path.join(root, entrypoint), line: 1, column: 1,
          }],
        } as never;
      },
    });
    const invalidResult = await runSourceAnalyzer(invalid, context(root, entrypoint));
    expect(invalidResult).toMatchObject({
      status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_INVALID_RESULT' }],
    });
    expect(JSON.stringify(invalidResult)).not.toMatch(/must-not-leak|source-analyzer-/);

    const secretDiagnostic = plugin({
      async analyze(ctx) {
        const valid = await fakeSourceAnalyzer.analyze(ctx);
        return {
          ...valid,
          diagnostics: [{
            code: 'SOURCE_ANALYZER_DYNAMIC_ROUTE', safeMessage: 'token=must-not-leak',
            sourceUri: path.join(root, entrypoint), line: 1, column: 2,
          }],
          metrics: { ...valid.metrics, diagnostics: 1 },
        };
      },
    });
    const sanitized = await runSourceAnalyzer(secretDiagnostic, context(root, entrypoint));
    expect(sanitized).toMatchObject({
      status: 'success',
      result: {
        diagnostics: [{
          code: 'SOURCE_ANALYZER_DYNAMIC_ROUTE',
          safeMessage: 'A dynamic route expression could not be resolved statically.',
          sourceUri: entrypoint,
          line: 1,
          column: 2,
        }],
      },
    });
    expect(JSON.stringify(sanitized)).not.toMatch(/must-not-leak|source-analyzer-/);

    const absoluteEvidence = plugin({
      async analyze(ctx) {
        const valid = await fakeSourceAnalyzer.analyze(ctx);
        valid.contract.operations[0].provenance[0].uri = path.join(root, entrypoint);
        return valid;
      },
    });
    expect(await runSourceAnalyzer(absoluteEvidence, context(root, entrypoint)))
      .toMatchObject({ status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_INVALID_RESULT' }] });

    for (const provenance of [
      { analyzer: 'spoofed@9.9.9' },
      { capability: 'undeclaredCapability' },
    ]) {
      const spoofed = plugin({
        async analyze(ctx) {
          const valid = await fakeSourceAnalyzer.analyze(ctx);
          Object.assign(valid.contract.operations[0].provenance[0], provenance);
          return valid;
        },
      });
      expect(await runSourceAnalyzer(spoofed, context(root, entrypoint)))
        .toMatchObject({ status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_INVALID_RESULT' }] });
    }
  });

  test('handles cancellation before and during analysis without treating it as an empty contract', async () => {
    const { root, entrypoint } = workspace();
    const before = new AbortController();
    before.abort();
    expect(await runSourceAnalyzer(fakeSourceAnalyzer, {
      ...context(root, entrypoint), cancellationSignal: before.signal,
    })).toMatchObject({ status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_CANCELLED' }] });

    const during = new AbortController();
    const waiting = plugin({ analyze: () => new Promise(() => {}) });
    const pending = runSourceAnalyzer(waiting, {
      ...context(root, entrypoint), cancellationSignal: during.signal,
    });
    during.abort();
    expect(await pending).toMatchObject({
      status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_CANCELLED' }],
    });
  });

  test.each([
    ['files', 'maxFiles', 'SOURCE_ANALYZER_FILE_LIMIT'],
    ['totalSourceBytes', 'maxTotalSourceBytes', 'SOURCE_ANALYZER_TOTAL_BYTES_LIMIT'],
    ['largestFileBytes', 'maxFileBytes', 'SOURCE_ANALYZER_FILE_BYTES_LIMIT'],
    ['astNodes', 'maxAstNodes', 'SOURCE_ANALYZER_AST_NODE_LIMIT'],
    ['diagnostics', 'maxDiagnostics', 'SOURCE_ANALYZER_DIAGNOSTIC_LIMIT'],
    ['operations', 'maxOperations', 'SOURCE_ANALYZER_OPERATION_LIMIT'],
    ['maxDepth', 'maxAnalysisDepth', 'SOURCE_ANALYZER_DEPTH_LIMIT'],
  ] as const)('fails closed when %s exceeds %s', async (metric, limit, code) => {
    const { root, entrypoint } = workspace();
    const limited = { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, [limit]: 1 };
    const excessive = plugin({
      async analyze(ctx) {
        const valid = await fakeSourceAnalyzer.analyze(ctx);
        return { ...valid, metrics: { ...valid.metrics, [metric]: 2 } as SourceAnalysisMetrics };
      },
    });
    expect(await runSourceAnalyzer(excessive, context(root, entrypoint, limited)))
      .toMatchObject({ status: 'failed', diagnostics: [{ code }] });
  });

  test('returns a timeout code when an analyzer ignores cancellation', async () => {
    const { root, entrypoint } = workspace();
    const waiting = plugin({ analyze: () => new Promise(() => {}) });
    expect(await runSourceAnalyzer(waiting, context(root, entrypoint, {
      ...DEFAULT_SOURCE_ANALYSIS_LIMITS, timeoutMs: 10,
    }))).toMatchObject({ status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_TIMEOUT' }] });
  });
});
