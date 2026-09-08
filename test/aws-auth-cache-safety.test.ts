import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { afterEach, expect, test } from 'vitest';
import { projectPolicyToAllowedSurface } from '../src/contract';
import type { CDNSecurityFrameworkPolicy } from '../src/types/policy';

const require = createRequire(import.meta.url);
const { build } = require('../scripts/lib/compile-core');
const { compile } = require('../lib');
const root = process.cwd();
const scratch: string[] = [];
const gates = [
  { type: 'jwt', algorithm: 'HS256', secret_env: 'TEST_AUTH_SECRET' },
  { type: 'jwt', algorithm: 'RS256', jwks_url: 'https://id.example/jwks' },
  { type: 'signed_url', secret_env: 'TEST_AUTH_SECRET' },
] as const;

afterEach(() => {
  for (const dir of scratch.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function fixture(gate: unknown, mode: 'enforce' | 'monitor' = 'enforce') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aws-auth-cache-'));
  scratch.push(dir);
  const policy = {
    version: 1,
    defaults: { mode },
    request: { allow_methods: ['GET'] },
    response_headers: {},
    firewall: { jwks: { allowed_hosts: ['id.example'] } },
    routes: [{ name: 'protected', match: { path_prefixes: ['/private'] }, auth_gate: gate }],
  } as CDNSecurityFrameworkPolicy;
  const policyPath = path.join(dir, 'policy.json');
  fs.writeFileSync(policyPath, JSON.stringify(policy));
  return { dir, policy, policyPath, outDir: path.join(dir, 'out') };
}

for (const mode of ['enforce', 'monitor'] as const) {
  for (const gate of gates) {
    test(`AWS refuses ${JSON.stringify(gate)} in ${mode} before touching existing artifacts`, () => {
      const f = fixture(gate, mode);
      fs.mkdirSync(f.outDir);
      fs.writeFileSync(path.join(f.outDir, 'keep.txt'), 'unchanged');
      expect(() => build(f.policy, {
        rootDir: root, outDir: f.outDir, allowPlaceholderToken: true,
        env: { TEST_AUTH_SECRET: 'synthetic-test-only' },
      })).toThrow(/cache/i);
      const result = compile({ ...f, target: 'aws', allowPlaceholderToken: true });
      expect(result.ok).toBe(false);
      expect(result.errors.join('\n')).toMatch(/cache/i);
      expect(result.edgeFiles).toEqual([]);
      expect(result.infraFiles).toEqual([]);
      expect(fs.readdirSync(f.outDir)).toEqual(['keep.txt']);
      expect(fs.readFileSync(path.join(f.outDir, 'keep.txt'), 'utf8')).toBe('unchanged');
    });
  }
}

test.each(gates)('Cloudflare retains auth support and projection does not claim AWS enforcement: %j', (gate) => {
  const f = fixture(gate);
  const projected = projectPolicyToAllowedSurface(f.policy, {
    policyDigest: `sha256:${'0'.repeat(64)}`, sourceUri: 'policy.json',
  });
  expect(projected.orderedRules[0].auth.verifiability).toEqual({
    aws: 'unsupported-configuration', cloudflare: 'enforced',
  });
  expect(projected.targetCapabilities.aws).toContainEqual({ id: 'auth.route_gates', status: 'partial' });
  expect(projected.orderedRules[0].auth.matching.aws).toBe('static-and-basic-in-policy-order');
  expect(compile({ ...f, target: 'cloudflare' }).ok).toBe(true);
});

test.each(['jwt', 'signed_url'])('CLI build, readiness and capabilities agree on unsupported AWS %s', (type) => {
  const f = fixture({ type, algorithm: type === 'jwt' ? 'HS256' : 'HMAC-SHA256', secret_env: 'TEST_AUTH_SECRET' });
  const cli = (...args: string[]) => spawnSync(process.execPath, [path.join(root, 'bin/cli.js'), ...args], {
    cwd: f.dir, encoding: 'utf8', env: { ...process.env, TEST_AUTH_SECRET: 'synthetic-test-only' },
  });
  const built = cli('build', '--policy', f.policyPath, '--out-dir', f.outDir, '--allow-placeholder-token');
  expect(built.status).toBe(1);
  expect(built.stderr).toMatch(/cache/i);
  expect(fs.existsSync(f.outDir)).toBe(false);
  const readiness = cli('readiness', '--policy', f.policyPath, '--target', 'aws', '--json');
  expect(readiness.status).not.toBe(0);
  expect(JSON.parse(readiness.stdout).findings).toContainEqual(expect.objectContaining({
    severity: 'fail', id: 'target.aws.auth_gate.cache_unsafe',
  }));
  const capabilities = cli('capabilities', '--policy', f.policyPath, '--target', 'aws', '--json');
  expect(capabilities.status).toBe(0);
  expect(JSON.parse(capabilities.stdout).capabilities).toContainEqual(expect.objectContaining({
    id: `auth.${type}`, deploySupport: { aws: 'unsupported', cloudflare: 'supported' },
  }));
  const cfReadiness = cli('readiness', '--policy', f.policyPath, '--target', 'cloudflare', '--json');
  expect(JSON.parse(cfReadiness.stdout).findings).not.toContainEqual(expect.objectContaining({
    id: 'target.aws.auth_gate.cache_unsafe',
  }));
});

test.each(['static_token', 'basic_auth'])('AWS %s still authenticates at viewer request before cache lookup', (type) => {
  const f = fixture({ type, token_env: 'TEST_AUTH_SECRET', credentials_env: 'TEST_AUTH_SECRET' });
  build(f.policy, { rootDir: root, outDir: f.outDir, env: { TEST_AUTH_SECRET: 'dXNlcjpwYXNz' } });
  const code = fs.readFileSync(path.join(f.outDir, 'edge/viewer-request.js'), 'utf8');
  const handler = Function(`${code}\nreturn handler;`)();
  const request = { method: 'GET', uri: '/private', querystring: {}, headers: { 'user-agent': { value: 'test' } } };
  const credential = type === 'basic_auth'
    ? { authorization: { value: 'Basic dXNlcjpwYXNz' } }
    : { 'x-edge-token': { value: 'dXNlcjpwYXNz' } };
  expect(handler({ request: { ...request, headers: { ...request.headers, ...credential } } }).uri).toBe('/private');
  expect(handler({ request }).statusCode).toBe(401);
  expect(projectPolicyToAllowedSurface(f.policy, {
    policyDigest: `sha256:${'0'.repeat(64)}`, sourceUri: 'policy.json',
  }).orderedRules[0].auth.verifiability.aws).toBe('enforced');
});

test.each([
  ['--guided', '--auth', 'jwt'],
  ['--guided', '--auth', 'signed_url'],
  ['--guided', '--app-shape', 'rest-api'],
  ['--archetype', 'rest-api'],
])('init refuses unsupported AWS starter before writes: %j', (...options) => {
  const f = fixture({ type: 'jwt' });
  for (const platform of ['aws', 'cloudflare']) {
    const result = spawnSync(process.execPath, [path.join(root, 'bin/cli.js'), 'init', '--platform', platform, ...options], {
      cwd: f.dir, encoding: 'utf8',
    });
    expect(result.status).toBe(platform === 'aws' ? 1 : 0);
    expect(fs.existsSync(path.join(f.dir, 'policy/security.yml'))).toBe(platform === 'cloudflare');
    if (platform === 'aws') expect(result.stderr).toMatch(/cache/i);
  }
});
