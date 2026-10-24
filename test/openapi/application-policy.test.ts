import childProcess from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import vm from 'node:vm';
import { transformSync } from 'esbuild';
import * as yaml from 'js-yaml';
import { afterEach, expect, test } from 'vitest';
import { projectPolicyToAllowedSurface } from '../../src/contract';
import { generatePolicyCandidate } from '../../src/openapi/policy-candidate';
import { inspectOpenApiForCli } from '../../src/openapi/inspect';

const directories: string[] = [];
const cli = path.resolve('bin/cli.js');
afterEach(() => directories.splice(0).forEach((directory) => fs.rmSync(directory, { recursive: true, force: true })));

function workspace(version = '14.2.24') {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-application-policy-'));
  directories.push(directory);
  fs.mkdirSync(path.join(directory, 'policy'));
  fs.writeFileSync(path.join(directory, 'openapi.json'), JSON.stringify({
    openapi: '3.1.0', info: { title: 'API', version: '1' }, paths: {
      '/api/items': { post: { parameters: [{ name: 'X-API-Only', in: 'header', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'ok' } } } },
    },
  }));
  const root = { name: 'fixture', version: '1.0.0', dependencies: { next: '^14.2.0' } };
  fs.writeFileSync(path.join(directory, 'package.json'), JSON.stringify(root));
  fs.writeFileSync(path.join(directory, 'package-lock.json'), JSON.stringify({
    name: root.name, version: root.version, lockfileVersion: 3,
    packages: { '': root, 'node_modules/next': { version, resolved: `https://registry.npmjs.org/next/-/next-${version}.tgz` } },
  }));
  return directory;
}

function generate(directory: string, extra: string[] = []) {
  return childProcess.spawnSync(process.execPath, [cli, 'openapi', 'generate-policy',
    '--workspace-root', directory, '--input', 'openapi.json', '--profile', 'balanced',
    '--out', 'policy/application.yml', '--package-json', 'package.json',
    '--package-lock', 'package-lock.json', '--deployment', 'self-hosted', ...extra,
  ], { encoding: 'utf8' });
}

test('combines exact Next.js version evidence with OpenAPI without narrowing framework routes', () => {
  const directory = workspace();
  const result = generate(directory);
  expect(result.status, result.stderr).toBe(0);
  const policy = yaml.load(fs.readFileSync(path.join(directory, 'policy/application.yml'), 'utf8')) as any;
  const metadata = JSON.parse(fs.readFileSync(path.join(directory, 'policy/application.meta.json'), 'utf8'));
  expect(policy.request.block.header_present).toEqual(['x-middleware-subrequest']);
  expect(policy.request.allow_methods).toEqual(['GET', 'HEAD', 'POST']);
  expect(policy.request.block.header_missing).toEqual(['user-agent']);
  expect(metadata.application.findings).toEqual([expect.objectContaining({
    id: 'CVE-2025-29927', status: 'mitigation-generated', version: '14.2.24',
  })]);
  expect(metadata.omittedRecommendations).toContainEqual(expect.objectContaining({
    id: 'global-allowed-methods', reason: 'openapi-does-not-cover-application-routes',
  }));
});

test.each([null, false, 0, ''])('rejects malformed application option %j instead of silently using OpenAPI-only generation', (application) => {
  const directory = workspace();
  const inspection = inspectOpenApiForCli({ inputPath: 'openapi.json', workspaceRoot: directory });
  const profilePolicy = yaml.load(fs.readFileSync(path.resolve('policy/profiles/balanced.yml'), 'utf8')) as Record<string, unknown>;
  expect(() => generatePolicyCandidate(inspection.report.contract, {
    profile: 'balanced', profilePolicy, sourceDigest: inspection.report.analyzer.sourceDigest,
    application: application as never,
  })).toThrowError(expect.objectContaining({ code: 'APPLICATION_INPUT_INVALID' }));
});

test.each(['14.2.25', '15.2.3'])('omits the virtual patch for fixed Next.js %s', (version) => {
  const directory = workspace(version);
  if (version.startsWith('15')) {
    const manifest = JSON.parse(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'));
    const lock = JSON.parse(fs.readFileSync(path.join(directory, 'package-lock.json'), 'utf8'));
    manifest.dependencies.next = '^15.0.0'; lock.packages[''].dependencies.next = '^15.0.0';
    fs.writeFileSync(path.join(directory, 'package.json'), JSON.stringify(manifest));
    fs.writeFileSync(path.join(directory, 'package-lock.json'), JSON.stringify(lock));
  }
  expect(generate(directory).status).toBe(0);
  const policy = yaml.load(fs.readFileSync(path.join(directory, 'policy/application.yml'), 'utf8')) as any;
  expect(policy.request.block.header_present).toBeUndefined();
});

test.each([
  ['--deployment', 'unknown'], ['--package-lock', 'absent.json'],
  ['--package-json', '../package.json'], ['--deployment', 'managed-guess'],
])('refuses unresolved input without partial outputs: %j', (...extra) => {
  const directory = workspace();
  expect(generate(directory, extra).status).toBe(1);
  expect(fs.readdirSync(path.join(directory, 'policy'))).toEqual([]);
});

test('protects dependency inputs, including output aliases, and does not execute scripts', () => {
  const directory = workspace();
  const manifestPath = path.join(directory, 'package.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  manifest.scripts = { prepare: 'touch SCRIPT_EXECUTED' };
  fs.writeFileSync(manifestPath, JSON.stringify(manifest));
  expect(generate(directory).status).toBe(0);
  expect(fs.existsSync(path.join(directory, 'SCRIPT_EXECUTED'))).toBe(false);
  const original = fs.readFileSync(manifestPath);
  fs.linkSync(manifestPath, path.join(directory, 'policy/alias.yml'));
  expect(generate(directory, ['--out', 'policy/alias.yml', '--force']).status).toBe(1);
  expect(fs.readFileSync(manifestPath)).toEqual(original);
  fs.copyFileSync(manifestPath, path.join(directory, 'policy/application.meta.json'));
  expect(generate(directory, ['--package-json', 'policy/application.meta.json', '--force']).status).toBe(1);
  expect(fs.readFileSync(path.join(directory, 'policy/application.meta.json'))).toEqual(original);
});

test('accepts absolute dependency inputs inside a workspace reached through a path alias', () => {
  const directory = workspace();
  expect(generate(directory, ['--package-json', path.join(directory, 'package.json'),
    '--package-lock', path.join(directory, 'package-lock.json')]).status).toBe(0);
});

test('validates forbidden header names instead of emitting unsafe configuration', () => {
  const { validatePolicy } = require('../../validator');
  for (const header of ['', 'x-bad\r\nInjected', 'bad:header', 'bad header', 'x'.repeat(257)]) {
    const policy = { version: 2, request: { allow_methods: ['GET'], block: { header_present: [header] } } };
    expect(validatePolicy({ policy, pkgRoot: process.cwd() }).ok).toBe(false);
  }
});

test('rejects outside-root symlinks, mismatched manifests and oversized files without echoing secrets', () => {
  const directory = workspace();
  const outside = workspace();
  fs.unlinkSync(path.join(directory, 'package.json'));
  fs.symlinkSync(path.join(outside, 'package.json'), path.join(directory, 'package.json'));
  expect(generate(directory).status).toBe(1);
  fs.unlinkSync(path.join(directory, 'package.json'));
  fs.writeFileSync(path.join(directory, 'package.json'), '{"dependencies":{"next":"SECRET_DO_NOT_PRINT"}}');
  const mismatch = generate(directory);
  expect(mismatch.status).toBe(1);
  expect(mismatch.stderr).not.toContain('SECRET_DO_NOT_PRINT');
  fs.writeFileSync(path.join(directory, 'package.json'), 'x'.repeat(8 * 1024 * 1024 + 1));
  expect(generate(directory).status).toBe(1);
  expect(fs.readdirSync(path.join(directory, 'policy'))).toEqual([]);
});

async function listen(server: http.Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
}

async function close(server: http.Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

test('CLI → policy → both edge artifacts reject empty/duplicate headers before preflight and never contact origin', async () => {
  const directory = workspace();
  expect(generate(directory).status).toBe(0);
  const policyPath = path.join(directory, 'policy/application.yml');
  const policy = yaml.load(fs.readFileSync(policyPath, 'utf8')) as any;
  policy.request.block.header_present = ['X-Middleware-Subrequest'];
  policy.response_headers.cors = { allow_origins: ['https://client.test'], allow_methods: ['GET', 'POST', 'OPTIONS'], allow_headers: ['*'] };
  // Isolate edge-runtime validation from unrelated managed-WAF approximations.
  policy.firewall.waf.managed_rules = [];
  const surface = projectPolicyToAllowedSurface(policy, { policyDigest: `sha256:${'0'.repeat(64)}`, sourceUri: 'policy/application.yml' });
  expect(surface.defaults.blockedHeaders).toEqual({ values: ['x-middleware-subrequest'], phase: 'before-cors-preflight' });
  expect(surface.defaults.corsPreflight.allowedOriginDecision).toBe('early-204-after-forbidden-header-check');
  fs.writeFileSync(policyPath, yaml.dump(policy));
  let originCalls = 0;
  const origin = http.createServer((_req, res) => { originCalls++; res.end('origin-ok'); });
  const originUrl = await listen(origin);
  try {
    for (const target of ['aws', 'cloudflare']) {
      const out = path.join(directory, target);
      childProcess.execFileSync(process.execPath, [cli, 'build', '--policy', policyPath, '--target', target, '--out-dir', out], { encoding: 'utf8' });
      const filename = target === 'aws' ? 'edge/viewer-request.js' : 'edge/cloudflare/index.ts';
      const code = fs.readFileSync(path.join(out, filename), 'utf8');
      const exports = {};
      const sandbox = vm.createContext({ exports, module: { exports }, Request, Response, Headers, ReadableStream, URL, crypto: globalThis.crypto,
        console: { log() {}, warn() {}, error() {} }, TextEncoder, TextDecoder, Buffer,
        fetch: (input: Request) => fetch(new Request(originUrl + new URL(input.url).pathname, input)),
      });
      vm.runInContext(target === 'aws' ? `${code}\nexports.handler = handler;` : transformSync(code, { loader: 'ts', format: 'cjs', target: 'es2022' }).code, sandbox);
      const artifacts = sandbox.module.exports as any;
      if (target === 'aws') {
        const multiValue = artifacts.handler({ request: { method: 'GET', uri: '/dashboard', querystring: '', headers: {
          'user-agent': { value: 'browser-fixture' },
          'x-middleware-subrequest': { value: '', multiValue: [{ value: '' }, { value: 'middleware' }] },
        } } });
        expect(multiValue.statusCode).toBe(403);
      }
      const edge = http.createServer(async (req, res) => {
        try {
          const headers = new Headers();
          for (const [key, value] of Object.entries(req.headers)) if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(',') : value);
          let response: Response;
          if (target === 'cloudflare') {
            response = await artifacts.default.fetch(new Request(`http://edge.test${req.url}`, { method: req.method, headers }), {});
          } else {
            const request = { method: req.method, uri: req.url, querystring: '', headers: Object.fromEntries([...headers].map(([key, value]) => [key, { value }])) };
            const result = artifacts.handler({ request });
            response = result.statusCode ? new Response(result.body, { status: result.statusCode }) : await fetch(originUrl + req.url);
          }
          res.writeHead(response.status); res.end(await response.text());
        } catch (error) { res.statusCode = 500; res.end(String(error)); }
      });
      const edgeUrl = await listen(edge);
      try {
        const before = originCalls;
        const normal = await fetch(edgeUrl + '/dashboard', { headers: { 'user-agent': 'browser-fixture' } });
        expect(normal.status, `${target}: ${await normal.text()}`).toBe(200);
        expect(originCalls).toBe(before + 1);
        for (const method of ['GET', 'OPTIONS']) {
          for (const value of ['', 'middleware:middleware', 'middleware,middleware']) {
            const blocked = await fetch(edgeUrl + '/undocumented-framework-route', { method, headers: {
              'user-agent': 'browser-fixture', 'X-Middleware-Subrequest': value,
              origin: 'https://client.test', 'access-control-request-method': 'GET',
            } });
            expect(blocked.status, `${target}: ${await blocked.text()}`).toBe(403);
          }
        }
        expect(originCalls).toBe(before + 1);
        const preflight = await fetch(edgeUrl + '/dashboard', { method: 'OPTIONS', headers: {
          origin: 'https://client.test', 'access-control-request-method': 'GET',
        } });
        expect(preflight.status).toBe(204);
      } finally { await close(edge); }
    }
  } finally { await close(origin); }
}, 20_000);
