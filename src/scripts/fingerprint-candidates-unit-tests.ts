#!/usr/bin/env node

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

function test(name: string, fn: () => void) {
  try {
    fn();
    console.log('OK:', name);
  } catch (e: any) {
    console.error('FAIL:', name);
    console.error(e && e.stack ? e.stack : e);
    process.exitCode = 1;
  }
}

const repoRoot = path.join(__dirname, '..');
const scriptPath = path.join(repoRoot, 'scripts', 'fingerprint-candidates.js');

function withJsonl(lines: string[], fn: (inputPath: string) => void) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fingerprint-candidates-'));
  const inputPath = path.join(tempDir, 'waf-log.jsonl');
  fs.writeFileSync(inputPath, lines.join('\n') + '\n', 'utf8');
  try {
    return fn(inputPath);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

function runCandidates(inputPath: string, args: string[] = []) {
  const stdout = execFileSync(
    process.execPath,
    [scriptPath, '--input', inputPath, ...args],
    { cwd: repoRoot, encoding: 'utf8' },
  );
  return JSON.parse(stdout);
}

test('fingerprint-candidates aggregates nested and top-level JA3/JA4 values', () => {
  withJsonl([
    JSON.stringify({ httpRequest: { ja3Fingerprint: 'ja3-a', ja4Fingerprint: 'ja4-a' } }),
    JSON.stringify({ httpRequest: { ja3Fingerprint: 'ja3-a', ja4Fingerprint: 'ja4-a' } }),
    JSON.stringify({ ja3Fingerprint: 'ja3-b', ja4Fingerprint: 'ja4-b' }),
    JSON.stringify({ ja3: 'ja3-b', ja4: 'ja4-b' }),
    'not-json',
  ], (inputPath) => {
    const result = runCandidates(inputPath, ['--min-count', '2', '--top', '10']);

    assert.strictEqual(result.min_count, 2);
    assert.strictEqual(result.top, 10);
    assert.deepStrictEqual(result.ja3_candidates, [
      { fingerprint: 'ja3-a', count: 2 },
      { fingerprint: 'ja3-b', count: 2 },
    ]);
    assert.deepStrictEqual(result.ja4_candidates, [
      { fingerprint: 'ja4-a', count: 2 },
      { fingerprint: 'ja4-b', count: 2 },
    ]);
    assert.deepStrictEqual(result.recommended_policy_patch.firewall.waf.ja3_fingerprints, ['ja3-a', 'ja3-b']);
    assert.deepStrictEqual(result.recommended_policy_patch.firewall.waf.ja4_fingerprints, ['ja4-a', 'ja4-b']);
  });
});

test('fingerprint-candidates applies min-count and top limits', () => {
  withJsonl([
    JSON.stringify({ ja3: 'high', ja4: 'one' }),
    JSON.stringify({ ja3: 'high', ja4: 'one' }),
    JSON.stringify({ ja3: 'high', ja4: 'two' }),
    JSON.stringify({ ja3: 'medium', ja4: 'two' }),
    JSON.stringify({ ja3: 'medium', ja4: 'two' }),
    JSON.stringify({ ja3: 'low', ja4: 'three' }),
  ], (inputPath) => {
    const result = runCandidates(inputPath, ['--min-count', '2', '--top', '1']);

    assert.deepStrictEqual(result.ja3_candidates, [{ fingerprint: 'high', count: 3 }]);
    assert.deepStrictEqual(result.ja4_candidates, [{ fingerprint: 'two', count: 3 }]);
    assert.deepStrictEqual(result.recommended_policy_patch.firewall.waf.ja3_fingerprints, ['high']);
    assert.deepStrictEqual(result.recommended_policy_patch.firewall.waf.ja4_fingerprints, ['two']);
  });
});

test('fingerprint-candidates prints usage and exits non-zero without input', () => {
  assert.throws(
    () => execFileSync(process.execPath, [scriptPath], { cwd: repoRoot, encoding: 'utf8', stdio: 'pipe' }),
    (err: any) => {
      assert.strictEqual(err.status, 1);
      assert.match(String(err.stderr), /Usage: node scripts\/fingerprint-candidates\.js --input/);
      return true;
    },
  );
});
