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

test('build success diagnostics keep generated locations relative to the selected output directory', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-build-output-'));
  scratch.push(dir);
  fs.copyFileSync(path.join(root, 'policy/base.yml'), path.join(dir, 'policy.yml'));
  const result = spawnSync(process.execPath, [path.join(root, 'bin/cli.js'), 'build',
    '--policy', 'policy.yml', '--target', 'aws', '--out-dir', 'dist/aws'], {
    cwd: dir, encoding: 'utf8', env: { ...process.env,
      EDGE_ADMIN_TOKEN: 'synthetic-build-token-not-for-deploy',
      ORIGIN_SECRET: 'synthetic-origin-secret-not-for-deploy' },
  });
  expect(result.status).toBe(0);
  expect(result.stdout).toContain('Generated edge/viewer-request.js');
  expect(result.stdout).toContain('Generated infra/*.tf.json');
  expect(result.stdout).not.toContain(dir);
  expect(result.stderr).not.toContain(dir);
  expect(fs.existsSync(path.join(dir, 'dist/aws/edge/viewer-request.js'))).toBe(true);
});

function fixture(gate: unknown, mode: 'enforce' | 'monitor' = 'enforce') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aws-auth-cache-'));
  scratch.push(dir);
  const policy = {
    version: 2,
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
    const ratePlan = platform === 'cloudflare' && options.includes('--guided')
      ? ['--cloudflare-rate-limit-plan', 'business'] : [];
    const result = spawnSync(process.execPath, [path.join(root, 'bin/cli.js'), 'init', '--platform', platform, ...options, ...ratePlan], {
      cwd: f.dir, encoding: 'utf8',
    });
    expect(result.status).toBe(platform === 'aws' ? 1 : 0);
    expect(fs.existsSync(path.join(f.dir, 'policy/security.yml'))).toBe(platform === 'cloudflare');
    if (platform === 'aws') expect(result.stderr).toMatch(/cache/i);
  }
});

function compiledAwsResponse({ mode, format, entry = 'api', caseInsensitive = true, protectRoutes = true }: {
  mode: 'monitor' | 'enforce'; format: 'json' | 'text'; entry?: 'api' | 'cli';
  caseInsensitive?: boolean; protectRoutes?: boolean;
}) {
  const f = fixture({ type: 'static_token', token_env: 'TEST_AUTH_SECRET' }, mode);
  f.policy.routes![0].name = 'admin';
  if (!protectRoutes) f.policy.routes = [];
  f.policy.request!.normalize = { path: { case_insensitive: caseInsensitive } };
  f.policy.response_headers = {
    hsts: 'max-age=777', csp_public: "default-src 'self'", csp_admin: "default-src 'none'",
    clear_site_data_paths: ['/private'], force_vary_auth: false,
  };
  f.policy.observability = { log_format: format };
  fs.writeFileSync(f.policyPath, JSON.stringify(f.policy));
  const env = { ...process.env, TEST_AUTH_SECRET: 'synthetic-monitor-token' };
  if (entry === 'cli') {
    const result = spawnSync(process.execPath, [path.join(root, 'bin/cli.js'), 'build',
      '--policy', f.policyPath, '--target', 'aws', '--out-dir', f.outDir],
    { cwd: f.dir, encoding: 'utf8', env });
    expect(result.status, result.stderr).toBe(0);
  } else {
    expect(compile({ ...f, target: 'aws', env }).ok).toBe(true);
  }
  const logs: unknown[][] = [];
  const requestCode = fs.readFileSync(path.join(f.outDir, 'edge/viewer-request.js'), 'utf8');
  const responseCode = fs.readFileSync(path.join(f.outDir, 'edge/viewer-response.js'), 'utf8');
  expect(Buffer.byteLength(responseCode)).toBeLessThanOrEqual(10 * 1024);
  return {
    request: Function('console', `${requestCode}\nreturn handler;`)({ log() {} }),
    response: Function('console', `${responseCode}\nreturn handler;`)({ log: (...args: unknown[]) => logs.push(args) }),
    logs,
  };
}

test.each([
  ['api', 'json'], ['api', 'text'], ['cli', 'json'], ['cli', 'text'],
] as const)('%s AWS monitor preserves unresolved-path responses with bounded %s diagnostics', (entry, format) => {
  const pair = compiledAwsResponse({ mode: 'monitor', format, entry, protectRoutes: false });
  for (const uri of ['/public%25252561', '/%E0%A4']) {
    pair.logs.length = 0;
    const request = { method: 'GET', uri, querystring: {}, headers: { 'user-agent': { value: 'synthetic' } } };
    const forwarded = pair.request({ request });
    expect(forwarded.uri).toBe(uri);
    expect(forwarded.statusCode).toBeUndefined();
    const origin = { statusCode: 201, body: 'synthetic-origin-body', headers: {
      'cache-control': { value: 'public, max-age=300' },
      vary: { value: 'Accept-Encoding' },
    } };
    const response = pair.response({ request: forwarded, response: origin });
    expect(response.statusCode).toBe(201);
    expect(response.body).toBe('synthetic-origin-body');
    expect(response.headers['strict-transport-security'].value).toBe('max-age=777');
    expect(response.headers['content-security-policy'].value).toBe("default-src 'self'");
    expect(response.headers['cache-control'].value).toContain('no-store');
    expect(response.headers.pragma.value).toBe('no-cache');
    expect(response.headers.vary.value.split(/,\s*/)).toEqual(expect.arrayContaining([
      'Accept-Encoding', 'Authorization', 'Cookie',
    ]));
    expect(response.headers['clear-site-data']).toBeUndefined();
    expect(pair.logs).toHaveLength(1);
    const diagnostic = JSON.stringify(pair.logs);
    expect(diagnostic).toContain('response_path_unknown');
    expect(diagnostic).not.toContain(uri);
    expect(diagnostic).not.toContain('synthetic-origin-body');
    expect(diagnostic).not.toContain('synthetic-monitor-token');
    if (format === 'json') expect(JSON.parse(String(pair.logs[0][0]))).toMatchObject({
      event: 'monitor', block_reason: 'response_path_unknown', phase: 'viewer-response',
    });
    else expect(pair.logs[0][0]).toBe('[monitor]');
  }
  const normalized = pair.request({ request: { method: 'GET', uri: '/public%2fchild',
    querystring: {}, headers: { 'user-agent': { value: 'synthetic' } } } });
  expect(normalized.uri).toBe('/public/child');
});

test.each([
  ['monitor', true], ['enforce', true], ['enforce', false],
] as const)('AWS %s retains unresolved response errors with protectRoutes=%s', (mode, protectRoutes) => {
  const pair = compiledAwsResponse({ mode, format: 'json', protectRoutes });
  expect(() => pair.response({ request: { uri: '/public%25252561', headers: {} },
    response: { statusCode: 200, headers: {} } })).toThrow('Invalid response request path');
  expect(pair.logs).toEqual([]);
  const denied = pair.request({ request: { method: 'GET', uri: '/private%2fchild',
    querystring: {}, headers: { 'user-agent': { value: 'synthetic' } } } });
  expect(Number(denied.statusCode)).toBeGreaterThanOrEqual(400);
});

test.each([true, false])('AWS normal response route matching keeps case_insensitive=%s', (caseInsensitive) => {
  const pair = compiledAwsResponse({ mode: 'monitor', format: 'json', caseInsensitive });
  const response = pair.response({ request: { uri: '/Private', headers: {} },
    response: { statusCode: 200, headers: { 'cache-control': { value: 'public, max-age=300' } } } });
  expect(response.headers['content-security-policy'].value).toBe(caseInsensitive
    ? "default-src 'none'" : "default-src 'self'");
  if (caseInsensitive) expect(response.headers['cache-control'].value).toContain('no-store');
  else expect(response.headers['cache-control'].value).toBe('public, max-age=300');
  expect(pair.logs).toEqual([]);
});
