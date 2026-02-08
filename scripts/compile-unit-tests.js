#!/usr/bin/env node

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  DEFAULT_MARKS,
  pathPatternsToMarks,
  getAuthGates,
  getAdminGate,
  validateAuthGates,
  build,
} = require('./lib/compile-core');

function test(name, fn) {
  try {
    fn();
    console.log('OK:', name);
  } catch (e) {
    console.error('FAIL:', name);
    console.error(e && e.stack ? e.stack : e);
    process.exitCode = 1;
  }
}

function withEnv(key, value, fn) {
  const prev = process.env[key];
  if (value === undefined) {
    delete process.env[key];
  } else {
    process.env[key] = value;
  }

  try {
    fn();
  } finally {
    if (prev === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = prev;
    }
  }
}

test('pathPatternsToMarks falls back to defaults', () => {
  assert.deepStrictEqual(pathPatternsToMarks(undefined), DEFAULT_MARKS);
  assert.deepStrictEqual(pathPatternsToMarks([]), DEFAULT_MARKS);
});

test('pathPatternsToMarks expands known patterns', () => {
  const marks = pathPatternsToMarks(['(?i)\\.{2}/', '(?i)%2e%2e']);
  assert.ok(marks.includes('/../'));
  assert.ok(marks.includes('..'));
  assert.ok(marks.includes('%2e%2e'));
  assert.ok(marks.includes('%2E%2E'));
});

test('pathPatternsToMarks normalizes custom patterns', () => {
  const marks = pathPatternsToMarks(['  \\.\\./very/long/custom/pattern/example  ']);
  assert.strictEqual(marks.length, 1);
  assert.strictEqual(marks[0], '../very/long/custom/');
});

test('getAuthGates resolves static token env and defaults', () => {
  withEnv('CUSTOM_EDGE_TOKEN', 'secret-token', () => {
    const policy = {
      routes: [{
        name: 'admin',
        match: { path_prefixes: ['/admin'] },
        auth_gate: {
          type: 'static_token',
          header: 'x-custom-token',
          token_env: 'CUSTOM_EDGE_TOKEN',
        },
      }],
    };

    const gates = getAuthGates(policy);
    assert.strictEqual(gates.length, 1);
    assert.deepStrictEqual(gates[0], {
      name: 'admin',
      protectedPrefixes: ['/admin'],
      type: 'static_token',
      tokenHeaderName: 'x-custom-token',
      token: 'secret-token',
    });
  });
});

test('getAuthGates resolves basic auth and default prefixes', () => {
  withEnv('BASIC_AUTH_CREDS', 'dXNlcjpwYXNz', () => {
    const policy = {
      routes: [{
        name: 'dashboard',
        auth_gate: { type: 'basic_auth' },
      }],
    };

    const gates = getAuthGates(policy);
    assert.strictEqual(gates.length, 1);
    assert.deepStrictEqual(gates[0], {
      name: 'dashboard',
      protectedPrefixes: ['/admin', '/docs', '/swagger'],
      type: 'basic_auth',
      credentials: 'dXNlcjpwYXNz',
    });
  });
});

test('getAdminGate returns enabled config when static token exists', () => {
  withEnv('EDGE_ADMIN_TOKEN', 'edge-token', () => {
    const policy = {
      routes: [{
        name: 'admin',
        match: { path_prefixes: ['/admin'] },
        auth_gate: { type: 'static_token' },
      }],
    };

    const adminGate = getAdminGate(policy);
    assert.deepStrictEqual(adminGate, {
      enabled: true,
      protectedPrefixes: ['/admin'],
      tokenHeaderName: 'x-edge-token',
      token: 'edge-token',
    });
  });
});

test('getAdminGate returns disabled config when no static token gate exists', () => {
  const policy = {
    routes: [{
      name: 'api',
      match: { path_prefixes: ['/api'] },
      auth_gate: { type: 'jwt', algorithm: 'RS256', jwks_url: 'https://example.com/.well-known/jwks.json' },
    }],
  };

  const adminGate = getAdminGate(policy);
  assert.deepStrictEqual(adminGate, {
    enabled: false,
    protectedPrefixes: [],
    tokenHeaderName: 'x-edge-token',
    token: '',
  });
});

test('validateAuthGates accepts valid jwt and signed_url gates', () => {
  const policy = {
    routes: [
      { name: 'jwt-rs', auth_gate: { type: 'jwt', algorithm: 'RS256', jwks_url: 'https://example.com/jwks.json' } },
      { name: 'jwt-hs', auth_gate: { type: 'jwt', algorithm: 'HS256', secret_env: 'JWT_SECRET' } },
      { name: 'signed', auth_gate: { type: 'signed_url', secret_env: 'URL_SIGNING_SECRET' } },
    ],
  };

  validateAuthGates(policy, { exitOnError: false });
});

test('validateAuthGates reports missing required auth fields', () => {
  const policy = {
    routes: [
      { name: 'broken-rs', auth_gate: { type: 'jwt', algorithm: 'RS256' } },
      { name: 'broken-hs', auth_gate: { type: 'jwt', algorithm: 'HS256' } },
      { name: 'broken-signed', auth_gate: { type: 'signed_url' } },
    ],
  };

  assert.throws(
    () => validateAuthGates(policy, { exitOnError: false }),
    (err) => Array.isArray(err.validationErrors)
      && err.validationErrors.length === 3
      && err.validationErrors.some((e) => e.includes('broken-rs'))
      && err.validationErrors.some((e) => e.includes('broken-hs'))
      && err.validationErrors.some((e) => e.includes('broken-signed')),
  );
});

test('build emits edge files with JWT, Signed URL, and origin auth config', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-'));
  try {
    const policy = {
      version: 1,
      project: 'unit-build',
      defaults: { mode: 'enforce' },
      request: { allow_methods: ['GET'] },
      response_headers: { hsts: 'max-age=1' },
      routes: [
        {
          name: 'api',
          match: { path_prefixes: ['/api'] },
          auth_gate: {
            type: 'jwt',
            algorithm: 'HS256',
            secret_env: 'JWT_SECRET',
            issuer: 'issuer',
            audience: 'aud',
          },
        },
        {
          name: 'assets',
          match: { path_prefixes: ['/assets'] },
          auth_gate: {
            type: 'signed_url',
            secret_env: 'URL_SIGNING_SECRET',
            expires_param: 'exp',
            signature_param: 'sig',
          },
        },
      ],
      origin: {
        auth: {
          type: 'custom_header',
          header: 'X-Origin-Verify',
          secret_env: 'ORIGIN_SECRET',
        },
      },
    };

    const outputs = build(policy, {
      outDir: tmpDir,
      rootDir: path.join(__dirname, '..'),
    });

    assert.strictEqual(outputs.length, 3);
    const originCode = fs.readFileSync(path.join(tmpDir, 'edge', 'origin-request.js'), 'utf8');
    assert.ok(originCode.includes('\"algorithm\":\"HS256\"'));
    assert.ok(originCode.includes('\"type\":\"signed_url\"'));
    assert.ok(/originAuth:\s*\{\"type\":\"custom_header\"/.test(originCode));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

if (process.exitCode) {
  process.exit(process.exitCode);
}
