#!/usr/bin/env node

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const repositoryRoot = path.join(__dirname, '..');

function run(command: string, args: string[]): string {
  return execFileSync(command, args, {
    cwd: repositoryRoot,
    env: process.env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

assert.match(run(process.execPath, ['bin/cli.js', '--help']), /cdn-security/u);
run(process.execPath, ['bin/cli.js', 'doctor', '--no-report']);

for (const filePath of [
  'dist/edge/viewer-request.js',
  'dist/edge/viewer-response.js',
  'dist/edge/origin-request.js',
]) {
  assert.ok(existsSync(path.join(repositoryRoot, filePath)), `smoke build must create ${filePath}`);
}

const cloudflareOutput = mkdtempSync(path.join(tmpdir(), 'impact-cloudflare-smoke-'));
try {
  run(process.execPath, [
    'scripts/compile-cloudflare.js',
    '--policy',
    'policy/base.yml',
    '--out-dir',
    cloudflareOutput,
  ]);
  assert.ok(existsSync(path.join(cloudflareOutput, 'edge', 'cloudflare', 'index.ts')));
} finally {
  rmSync(cloudflareOutput, { recursive: true, force: true });
}

const viewerCode = readFileSync(path.join(repositoryRoot, 'dist', 'edge', 'viewer-request.js'), 'utf8');
const handler = Function(`${viewerCode}\nreturn handler;`)() as (event: unknown) => any;
const buildEvent = (headers: Record<string, string>) => ({
  request: {
    method: 'GET',
    uri: '/admin',
    querystring: '',
    headers: Object.fromEntries(
      Object.entries(headers).map(([key, value]) => [key.toLowerCase(), { value }]),
    ),
  },
});
const token = process.env.EDGE_ADMIN_TOKEN ?? 'INSECURE_PLACEHOLDER__REBUILD_WITH_REAL_TOKEN';
assert.equal(handler(buildEvent({ 'user-agent': 'Mozilla' })).statusCode, 401);
assert.equal(
  handler(buildEvent({ 'user-agent': 'Mozilla', 'x-edge-token': token })).uri,
  '/admin',
);

const missingEnvironment = { ...process.env };
delete missingEnvironment.EDGE_ADMIN_TOKEN;
const missingOutput = mkdtempSync(path.join(tmpdir(), 'impact-missing-config-'));
try {
  const failure = spawnSync(
    process.execPath,
    ['scripts/compile.js', '--policy', 'policy/base.yml', '--out-dir', missingOutput],
    {
      cwd: repositoryRoot,
      env: missingEnvironment,
      encoding: 'utf8',
      shell: false,
    },
  );
  assert.notEqual(failure.status, 0, 'missing required auth configuration must fail');
  assert.match(`${failure.stdout}\n${failure.stderr}`, /requires env "EDGE_ADMIN_TOKEN"/u);
} finally {
  rmSync(missingOutput, { recursive: true, force: true });
}

console.log('impact smoke tests: ok');
