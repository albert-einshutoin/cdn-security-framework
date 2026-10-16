import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { expect, test } from 'vitest';

function run(args: string[]) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-security-bench-test-'));
  const output = path.join(dir, 'result.json');
  try {
    const child = spawnSync(process.execPath, ['scripts/benchmark-edge-security.js', '--output', output, ...args],
      { encoding: 'utf8', timeout: 25000, maxBuffer: 1048576 });
    return { code: child.status, error: child.error, text: child.stdout + child.stderr,
      report: fs.existsSync(output) ? JSON.parse(fs.readFileSync(output, 'utf8')) : undefined };
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

test('invalid budgets and an unmatched selector fail before creating a benchmark report', () => {
  for (const args of [['--samples', '0'], ['--concurrency', '33'], ['--only', 'does-not-exist']]) {
    const result = run(args);
    expect(result.code).toBe(1);
    expect(result.report).toBeUndefined();
  }
}, 30000);

test('native generated Worker benchmark validates denied and accepted authentication separately', () => {
  const result = run(['--only', 'static-', '--samples', '3', '--warmup', '1', '--concurrency', '2']);
  expect(result.error).toBeUndefined();
  expect(result.code, result.text).toBe(0);
  expect(result.report.status).toBe('passed');
  expect(result.report.results.map((r: any) => [r.id, r.observedResponse.status, r.originArrivals, r.summaryMs.count])).toEqual([
    ['static-missing', 401, 0, 3], ['static-wrong', 401, 0, 3], ['static-valid', 200, 5, 3],
  ]);
  expect(Object.values(result.report.cleanup)).toEqual([true, true, true]);
}, 30000);

test('DLP benchmark checks mask and oversized pass-through contracts in native workerd', () => {
  const result = run(['--only', 'dlp-mask-', '--samples', '2', '--warmup', '0']);
  expect(result.code, result.text).toBe(0);
  expect(result.report.results.every((r: any) => r.status === 'passed' && r.originArrivals === 3)).toBe(true);
  expect(result.report.results.find((r: any) => r.id === 'dlp-mask-bytes-65537').observedResponse.bytes).toBe(65537);
  expect(Object.values(result.report.cleanup)).toEqual([true, true, true]);
}, 30000);

test('cold parallel unknown kids share the bounded JWKS refresh work', () => {
  const result = run(['--only', 'jwks-unknown-kid-cold-parallel', '--samples', '16', '--warmup', '0', '--concurrency', '8']);
  expect(result.code, result.text).toBe(0);
  const measured = result.report.results[0];
  expect(measured.firstBurstSize).toBe(8);
  expect(measured.originArrivals).toBe(0);
  expect(measured.jwksFetchesAfter['cold-parallel']).toBe(2);
  expect(measured.summaryMs.count).toBe(16);
}, 30000);

test('selecting a stale transition primes the real cache before the fixture outage', () => {
  const result = run(['--only', 'jwks-stale-transition', '--samples', '3', '--warmup', '0']);
  expect(result.code, result.text).toBe(0);
  expect(result.report.results.map((r: any) => [r.id, r.expectedStatus, r.jwksFetchesAfter.stale])).toEqual([
    ['jwks-stale-seed', 200, 1], ['jwks-stale-transition', 200, 2],
  ]);
  expect(Object.values(result.report.cleanup)).toEqual([true, true, true]);
}, 30000);
