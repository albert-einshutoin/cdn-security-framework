import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { expect, test } from 'vitest';

test('paired concurrent HTTP comparison preserves 1MiB signatures and the final partial batch', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-http-comparison-test-'));
  const output = path.join(dir, 'result.json');
  try {
    const child = spawnSync(process.execPath, ['scripts/benchmark-edge-http.js', '--root', process.cwd(),
      '--compare-root', process.cwd(), '--output', output, '--hot-paths', '--origin-body-hash',
      '--only', 'body-forward-1048576', '--samples', '33', '--warmup', '2', '--concurrency', '16'],
      { encoding: 'utf8', timeout: 25000 });
    expect(child.status, child.stdout + child.stderr).toBe(0);
    const report = JSON.parse(fs.readFileSync(output, 'utf8'));
    expect(report.status).toBe('passed'); expect(report.originCalls).toBe(72);
    expect(report.variants[0].moduleSha256).toBe(report.variants[1].moduleSha256);
    expect(report.results[0].beforeSamplesMs).toHaveLength(33);
    expect(report.results[0].samplesMs).toHaveLength(33);
    expect(report.results[0].pairDeltasMs).toHaveLength(33);
    expect(Object.values(report.cleanup)).toEqual([true, true, true]);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}, 30000);
