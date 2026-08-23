import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
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

  test('applies file and byte limits after resolving duplicate entrypoints', async () => {
    const { root, entrypoint } = workspace();
    const sourceBytes = fs.statSync(path.join(root, entrypoint)).size;
    fs.symlinkSync(path.join(root, entrypoint), path.join(root, 'app-alias.ts'));
    const execution = await runSourceAnalyzer(fakeSourceAnalyzer, {
      ...context(root, entrypoint, {
        ...DEFAULT_SOURCE_ANALYSIS_LIMITS,
        maxFiles: 1,
        maxTotalSourceBytes: sourceBytes,
      }),
      entrypoints: [entrypoint, 'src/../src/app.ts', 'app-alias.ts'],
    });
    expect(execution.status).toBe('success');

    expect(await runSourceAnalyzer(fakeSourceAnalyzer, {
      ...context(root, entrypoint),
      entrypoints: Array.from({ length: 100_001 }, () => entrypoint),
    })).toMatchObject({ status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_FILE_LIMIT' }] });
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

    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'source-evidence-outside-'));
    roots.push(outside);
    fs.writeFileSync(path.join(outside, 'outside.ts'), 'export {};\n');
    fs.symlinkSync(outside, path.join(root, 'linked'));
    const escapedEvidence = plugin({
      async analyze(ctx) {
        const valid = await fakeSourceAnalyzer.analyze(ctx);
        valid.contract.operations[0].provenance[0].uri = 'linked/outside.ts';
        return valid;
      },
    });
    expect(await runSourceAnalyzer(escapedEvidence, context(root, entrypoint)))
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

    const unsupportedEvidence = plugin({
      capabilities: {
        ...fakeSourceAnalyzer.capabilities,
        routePaths: { status: 'unsupported', reason: 'Route extraction is not supported.' },
      },
    });
    expect(await runSourceAnalyzer(unsupportedEvidence, context(root, entrypoint)))
      .toMatchObject({ status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_INVALID_RESULT' }] });

    for (const capability of ['routePaths', 'httpMethods'] as const) {
      const unsupportedRouteClaim = plugin({
        capabilities: {
          ...fakeSourceAnalyzer.capabilities,
          [capability]: { status: 'unsupported', reason: `${capability} extraction is not supported.` },
        },
        async analyze(ctx) {
          const valid = await fakeSourceAnalyzer.analyze(ctx);
          valid.contract.operations[0].provenance[0].capability = 'sourceLocations';
          return valid;
        },
      });
      expect(await runSourceAnalyzer(unsupportedRouteClaim, context(root, entrypoint)), capability)
        .toMatchObject({ status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_INVALID_RESULT' }] });
    }
    const partialRouteClaims = plugin({
      capabilities: {
        ...fakeSourceAnalyzer.capabilities,
        routePaths: { status: 'partial', reason: 'Some route paths are supported.' },
        httpMethods: { status: 'partial', reason: 'Some HTTP methods are supported.' },
      },
    });
    expect((await runSourceAnalyzer(partialRouteClaims, context(root, entrypoint))).status).toBe('success');

    const mutableCapabilities = {
      ...fakeSourceAnalyzer.capabilities,
      routePaths: { status: 'unsupported', reason: 'Route extraction is not supported.' },
    } as SourceAnalyzerPlugin['capabilities'];
    const mutatingEvidence = plugin({
      capabilities: mutableCapabilities,
      async analyze(ctx) {
        (mutableCapabilities.routePaths as { status: string }).status = 'supported';
        return fakeSourceAnalyzer.analyze(ctx);
      },
    });
    expect(await runSourceAnalyzer(mutatingEvidence, context(root, entrypoint)))
      .toMatchObject({ status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_INVALID_RESULT' }] });
  });

  test('ignores synchronously and asynchronously rejected logger writes', async () => {
    const { root, entrypoint } = workspace();
    for (const rejectedLogger of [
      { log() { throw new Error('token=sync-logger-secret'); } },
      { async log() { throw new Error('token=async-logger-secret'); } },
    ]) {
      const execution = await runSourceAnalyzer(fakeSourceAnalyzer, {
        ...context(root, entrypoint), logger: rejectedLogger,
      });
      expect(execution.status).toBe('success');
    }
    await new Promise((resolve) => setImmediate(resolve));
  });

  test('serializes asynchronous lifecycle logger writes', async () => {
    const { root, entrypoint } = workspace();
    const events: string[] = [];
    const execution = await runSourceAnalyzer(fakeSourceAnalyzer, {
      ...context(root, entrypoint),
      logger: {
        async log(event) {
          if (event === 'SOURCE_ANALYZER_STARTED') {
            await new Promise((resolve) => setTimeout(resolve, 20));
          }
          events.push(event);
        },
      },
    });
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(execution.status).toBe('success');
    expect(events).toEqual(['SOURCE_ANALYZER_STARTED', 'SOURCE_ANALYZER_COMPLETED']);
  });

  test('rejects each overclaimed contract capability independently', async () => {
    const { root, entrypoint } = workspace();
    for (const capability of ['routes', 'parameters', 'requestBodies', 'authentication'] as const) {
      const overclaiming = plugin({
        async analyze(ctx) {
          const valid = await fakeSourceAnalyzer.analyze(ctx);
          return {
            ...valid,
            contract: {
              ...valid.contract,
              capabilities: { ...valid.contract.capabilities, [capability]: 'complete' },
              operations: [],
            },
            metrics: { ...valid.metrics, operations: 0 },
          };
        },
      });
      expect(await runSourceAnalyzer(overclaiming, context(root, entrypoint)), capability)
        .toMatchObject({ status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_INVALID_RESULT' }] });
    }

    const supported = Object.fromEntries(Object.entries(fakeSourceAnalyzer.capabilities).map(([name, value]) => (
      [name, { ...value, status: 'supported' }]
    ))) as SourceAnalyzerPlugin['capabilities'];
    for (const capability of ['routes', 'authentication'] as const) {
      const complete = plugin({
        capabilities: supported,
        async analyze(ctx) {
          const valid = await fakeSourceAnalyzer.analyze(ctx);
          return {
            ...valid,
            contract: {
              ...valid.contract,
              capabilities: { ...valid.contract.capabilities, [capability]: 'complete' },
              operations: [],
            },
            metrics: { ...valid.metrics, operations: 0 },
          };
        },
      });
      expect((await runSourceAnalyzer(complete, context(root, entrypoint))).status, capability).toBe('success');
    }
  });

  test('reserves all lifecycle events for the wrapper', async () => {
    const { root, entrypoint } = workspace();
    const events: string[] = [];
    const emitting = plugin({
      async analyze(ctx) {
        ctx.logger.log('SOURCE_ANALYZER_STARTED');
        ctx.logger.log('SOURCE_ANALYZER_COMPLETED');
        ctx.logger.log('SOURCE_ANALYZER_FAILED');
        return fakeSourceAnalyzer.analyze(ctx);
      },
    });
    expect((await runSourceAnalyzer(emitting, {
      ...context(root, entrypoint), logger: { log: (event) => events.push(event) },
    })).status).toBe('success');
    expect(events).toEqual(['SOURCE_ANALYZER_STARTED', 'SOURCE_ANALYZER_COMPLETED']);
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
    const events: string[] = [];
    const threshold = metric === 'totalSourceBytes' || metric === 'largestFileBytes' ? 100 : 1;
    const limited = { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, [limit]: threshold };
    const excessive = plugin({
      async analyze(ctx) {
        const valid = await fakeSourceAnalyzer.analyze(ctx);
        return { ...valid, metrics: { ...valid.metrics, [metric]: threshold + 1 } as SourceAnalysisMetrics };
      },
    });
    expect(await runSourceAnalyzer(excessive, {
      ...context(root, entrypoint, limited), logger: { log: (event) => events.push(event) },
    }))
      .toMatchObject({ status: 'failed', diagnostics: [{ code }] });
    expect(events).toEqual(['SOURCE_ANALYZER_STARTED', 'SOURCE_ANALYZER_FAILED']);
  });

  test('returns a timeout code when an analyzer ignores cancellation', async () => {
    const { root, entrypoint } = workspace();
    const waiting = plugin({ analyze: () => new Promise(() => {}) });
    expect(await runSourceAnalyzer(waiting, context(root, entrypoint, {
      ...DEFAULT_SOURCE_ANALYSIS_LIMITS, timeoutMs: 10,
    }))).toMatchObject({ status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_TIMEOUT' }] });
  });

  test('rejects a CPU-bound result that outlives the timeout', async () => {
    const { root, entrypoint } = workspace();
    const blocking = plugin({
      async analyze(ctx) {
        const deadline = performance.now() + 50;
        while (performance.now() < deadline) { /* Simulate synchronous parser work. */ }
        return fakeSourceAnalyzer.analyze(ctx);
      },
    });
    expect(await runSourceAnalyzer(blocking, context(root, entrypoint, {
      ...DEFAULT_SOURCE_ANALYSIS_LIMITS, timeoutMs: 10,
    }))).toMatchObject({ status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_TIMEOUT' }] });
  });

  test('keeps the timeout alive when it is the only event-loop handle', () => {
    const { root } = workspace();
    const probe = `
      const api = require('./source-analysis');
      const capabilities = Object.fromEntries(api.SOURCE_ANALYZER_CAPABILITY_NAMES
        .map((name) => [name, { status: 'unsupported', reason: 'Probe capability.' }]));
      const plugin = {
        id: 'timeout-probe', version: '1.0.0', languages: ['typescript'], frameworks: ['probe'],
        capabilities, analyze: () => new Promise(() => {}),
      };
      api.runSourceAnalyzer(plugin, {
        workspaceRoot: process.argv[1], entrypoints: ['src/app.ts'],
        limits: { ...api.DEFAULT_SOURCE_ANALYSIS_LIMITS, timeoutMs: 10 }, logger: { log() {} },
      }).then((result) => console.log(result.diagnostics[0].code));
    `;
    const result = spawnSync(process.execPath, ['-e', probe, root], {
      cwd: process.cwd(), encoding: 'utf8', timeout: 2_000,
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe('SOURCE_ANALYZER_TIMEOUT');
  });
});
