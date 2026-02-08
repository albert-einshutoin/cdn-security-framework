#!/usr/bin/env node

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const repoRoot = path.join(__dirname, '..');
const goldenRoot = path.join(repoRoot, 'tests', 'golden', 'base');
const policyPath = path.join(repoRoot, 'policy', 'base.yml');

const expectedFiles = [
  'edge/viewer-request.js',
  'edge/viewer-response.js',
  'edge/origin-request.js',
  'edge/cloudflare/index.ts',
  'infra/waf-rules.tf.json',
];

function runBuild(outDir) {
  execFileSync(process.execPath, [path.join(repoRoot, 'scripts', 'compile.js'), '--policy', policyPath, '--out-dir', outDir], {
    cwd: repoRoot,
    stdio: 'inherit',
  });
  execFileSync(process.execPath, [path.join(repoRoot, 'scripts', 'compile-cloudflare.js'), '--policy', policyPath, '--out-dir', outDir], {
    cwd: repoRoot,
    stdio: 'inherit',
  });
  execFileSync(process.execPath, [path.join(repoRoot, 'scripts', 'compile-infra.js'), '--policy', policyPath, '--out-dir', outDir], {
    cwd: repoRoot,
    stdio: 'inherit',
  });
}

function readOrNull(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch (_e) {
    return null;
  }
}

function main() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cdn-security-drift-'));
  let failed = false;

  try {
    runBuild(tmpDir);

    for (const rel of expectedFiles) {
      const generated = readOrNull(path.join(tmpDir, rel));
      const golden = readOrNull(path.join(goldenRoot, rel));

      if (generated === null) {
        console.error('Missing generated file:', rel);
        failed = true;
        continue;
      }
      if (golden === null) {
        console.error('Missing golden file:', rel);
        failed = true;
        continue;
      }
      if (generated !== golden) {
        console.error('Drift detected:', rel);
        failed = true;
      } else {
        console.log('OK (no drift):', rel);
      }
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  if (failed) {
    console.error('Drift check failed. Regenerate golden fixtures if change is intentional.');
    process.exit(1);
  }

  console.log('Drift check passed.');
}

main();
