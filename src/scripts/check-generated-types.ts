#!/usr/bin/env node

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const repoRoot = path.join(__dirname, '..');
const schemaPath = path.join(repoRoot, 'policy', 'schema.json');
const committedPath = path.join(repoRoot, 'src', 'types', 'policy.d.ts');
const json2tsPath = path.join(
  repoRoot,
  'node_modules',
  '.bin',
  process.platform === 'win32' ? 'json2ts.cmd' : 'json2ts',
);

function main() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cdn-security-types-'));
  const generatedPath = path.join(tmpDir, 'policy.d.ts');
  try {
    execFileSync(json2tsPath, [
      '-i', schemaPath,
      '-o', generatedPath,
      '--unknownAny',
    ], {
      cwd: repoRoot,
      stdio: 'inherit',
    });
    const generated = fs.readFileSync(generatedPath, 'utf8');
    const committed = fs.existsSync(committedPath)
      ? fs.readFileSync(committedPath, 'utf8')
      : null;
    if (committed !== generated) {
      console.error('[types] src/types/policy.d.ts is out of sync. Run `npm run types:gen`.');
      process.exit(1);
    }
    console.log('[types] src/types/policy.d.ts is up to date.');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

main();
