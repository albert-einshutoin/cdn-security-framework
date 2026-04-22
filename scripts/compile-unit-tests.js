#!/usr/bin/env node

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  DEFAULT_CONTAINS,
  parsePathPatterns,
  regexesLiteralCode,
  getAuthGates,
  validateAuthGates,
  build,
  PLACEHOLDER_TOKEN,
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

test('parsePathPatterns returns defaults when unset or empty', () => {
  assert.deepStrictEqual(parsePathPatterns(undefined), { contains: DEFAULT_CONTAINS.slice(), regexSources: [] });
  assert.deepStrictEqual(parsePathPatterns(null), { contains: DEFAULT_CONTAINS.slice(), regexSources: [] });
  assert.deepStrictEqual(parsePathPatterns([]), { contains: DEFAULT_CONTAINS.slice(), regexSources: [] });
});

test('parsePathPatterns expands known legacy regex entries as contains (lowercased)', () => {
  const { contains, regexSources } = parsePathPatterns(['(?i)\\.{2}/', '(?i)%2e%2e']);
  assert.ok(contains.includes('/../'));
  assert.ok(contains.includes('..'));
  assert.ok(contains.includes('%2e%2e'));
  // Runtime lowercases the URI before `includes()`, so we only need the lower form.
  assert.ok(contains.every((c) => c === c.toLowerCase()));
  assert.deepStrictEqual(regexSources, []);
});

test('parsePathPatterns treats plain substrings as contains', () => {
  const { contains, regexSources } = parsePathPatterns(['/admin/internal/', '/debug/']);
  assert.deepStrictEqual(contains, ['/admin/internal/', '/debug/']);
  assert.deepStrictEqual(regexSources, []);
});

test('parsePathPatterns rejects ambiguous regex-like legacy entries', () => {
  assert.throws(
    () => parsePathPatterns(['(?i)(foo|bar).*']),
    /Ambiguous path_patterns entry/,
  );
});

test('parsePathPatterns accepts object form with contains and regex', () => {
  const { contains, regexSources } = parsePathPatterns({
    contains: ['/internal/'],
    regex: ['(?i)\\.git/', '\\.env$'],
  });
  assert.deepStrictEqual(contains, ['/internal/']);
  assert.deepStrictEqual(regexSources, ['(?i)\\.git/', '\\.env$']);
});

test('parsePathPatterns rejects invalid regex at build time', () => {
  assert.throws(
    () => parsePathPatterns({ regex: ['[unterminated'] }),
    /Invalid regex/,
  );
});

test('parsePathPatterns rejects regex-like entries under object-form contains', () => {
  assert.throws(
    () => parsePathPatterns({ contains: ['(?i)%2f\\.\\./'], regex: [] }),
    /Ambiguous path_patterns\.contains entry/,
  );
  assert.throws(
    () => parsePathPatterns({ contains: ['\\.git/'] }),
    /Ambiguous path_patterns\.contains entry/,
  );
  assert.throws(
    () => parsePathPatterns({ contains: ['(foo|bar)'] }),
    /Ambiguous path_patterns\.contains entry/,
  );
});

test('parsePathPatterns lowercases contains entries so uppercase policy survives runtime toLowerCase', () => {
  const fromObject = parsePathPatterns({ contains: ['%2E%2E', '/INTERNAL/'], regex: [] });
  assert.deepStrictEqual(fromObject.contains, ['%2e%2e', '/internal/']);

  const fromLegacy = parsePathPatterns(['/INTERNAL/', '(?i)\\.{2}/']);
  assert.ok(fromLegacy.contains.includes('/internal/'), 'plain upper entry normalized');
  assert.ok(fromLegacy.contains.every((c) => c === c.toLowerCase()), 'mapped entries normalized');
});

test('regexesLiteralCode emits real RegExp literals with flags', () => {
  assert.strictEqual(regexesLiteralCode([]), '[]');
  const code = regexesLiteralCode(['(?i)\\.git/', '\\.env$']);
  assert.ok(code.includes('/\\.git\\//i') || code.includes('/\\.git\\//gi') || code.includes('/\\.git\\//i'));
  assert.ok(code.includes('/\\.env$/'));
});

test('getAuthGates resolves static_token env', () => {
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
      tokenEnv: 'CUSTOM_EDGE_TOKEN',
      token: 'secret-token',
      tokenIsPlaceholder: false,
    });
  });
});

test('getAuthGates forces tokenHeaderName to lowercase for CFF compatibility', () => {
  withEnv('CUSTOM_EDGE_TOKEN', 'secret-token', () => {
    const policy = {
      routes: [{
        name: 'admin',
        match: { path_prefixes: ['/admin'] },
        auth_gate: {
          type: 'static_token',
          header: 'X-Edge-Token',
          token_env: 'CUSTOM_EDGE_TOKEN',
        },
      }],
    };
    const gates = getAuthGates(policy);
    assert.strictEqual(gates[0].tokenHeaderName, 'x-edge-token');
  });
});

test('getAuthGates throws for missing static_token env without placeholder flag', () => {
  withEnv('EDGE_ADMIN_TOKEN', undefined, () => {
    const policy = {
      routes: [{
        name: 'admin',
        match: { path_prefixes: ['/admin'] },
        auth_gate: { type: 'static_token' },
      }],
    };

    assert.throws(
      () => getAuthGates(policy),
      /static_token for route "admin" requires env/,
    );
  });
});

test('getAuthGates emits placeholder when allowPlaceholderToken set', () => {
  withEnv('EDGE_ADMIN_TOKEN', undefined, () => {
    const policy = {
      routes: [{
        name: 'admin',
        match: { path_prefixes: ['/admin'] },
        auth_gate: { type: 'static_token' },
      }],
    };

    const gates = getAuthGates(policy, { allowPlaceholderToken: true });
    assert.strictEqual(gates[0].token, PLACEHOLDER_TOKEN);
    assert.strictEqual(gates[0].tokenIsPlaceholder, true);
  });
});

test('getAuthGates resolves basic_auth env and default prefixes', () => {
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
      credentialsEnv: 'BASIC_AUTH_CREDS',
      credentials: 'dXNlcjpwYXNz',
      credentialsIsPlaceholder: false,
    });
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

  validateAuthGates(policy, { exitOnError: false, allowPlaceholderToken: true });
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
    () => validateAuthGates(policy, { exitOnError: false, allowPlaceholderToken: true }),
    (err) => Array.isArray(err.validationErrors)
      && err.validationErrors.length === 3
      && err.validationErrors.some((e) => e.includes('broken-rs'))
      && err.validationErrors.some((e) => e.includes('broken-hs'))
      && err.validationErrors.some((e) => e.includes('broken-signed')),
  );
});

test('validateAuthGates reports missing static_token env at build time', () => {
  withEnv('EDGE_ADMIN_TOKEN', undefined, () => {
    const policy = {
      routes: [{ name: 'admin', auth_gate: { type: 'static_token' } }],
    };

    assert.throws(
      () => validateAuthGates(policy, { exitOnError: false }),
      (err) => Array.isArray(err.validationErrors)
        && err.validationErrors.some((e) => e.includes('EDGE_ADMIN_TOKEN')),
    );
  });
});

test('validateAuthGates accepts missing static_token env with placeholder flag', () => {
  withEnv('EDGE_ADMIN_TOKEN', undefined, () => {
    const policy = {
      routes: [{ name: 'admin', auth_gate: { type: 'static_token' } }],
    };

    validateAuthGates(policy, { exitOnError: false, allowPlaceholderToken: true });
  });
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
    assert.ok(originCode.includes('"algorithm":"HS256"'));
    assert.ok(originCode.includes('"type":"signed_url"'));
    assert.ok(/originAuth:\s*\{"type":"custom_header"/.test(originCode));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('build emits blockPathContains and blockPathRegexes as RegExp literals', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-'));
  try {
    const policy = {
      version: 1,
      project: 'unit-build',
      defaults: { mode: 'enforce' },
      request: {
        block: {
          path_patterns: {
            contains: ['/internal/'],
            regex: ['(?i)\\.git/', '\\.env$'],
          },
        },
      },
      response_headers: {},
    };

    build(policy, { outDir: tmpDir, rootDir: path.join(__dirname, '..') });
    const code = fs.readFileSync(path.join(tmpDir, 'edge', 'viewer-request.js'), 'utf8');
    assert.ok(code.includes('blockPathContains: ["/internal/"]'));
    assert.ok(/blockPathRegexes:\s*\[\/\\\.git\\\//.test(code));
    assert.ok(/\/\\\.env\$\//.test(code));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('build emits allowedHosts (lowercased) and trustForwardedFor in viewer CFG', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-'));
  try {
    const policy = {
      version: 1,
      defaults: { mode: 'enforce' },
      request: {
        allow_methods: ['GET'],
        allowed_hosts: ['API.example.com', '*.cdn.example.com', '  '],
        trust_forwarded_for: true,
      },
      response_headers: {},
    };

    build(policy, { outDir: tmpDir, rootDir: path.join(__dirname, '..') });
    const code = fs.readFileSync(path.join(tmpDir, 'edge', 'viewer-request.js'), 'utf8');
    assert.ok(code.includes('allowedHosts: ["api.example.com","*.cdn.example.com"]'),
      'expected lowercased, trimmed, filtered allowedHosts; got:\n' + code.match(/allowedHosts: .*/)?.[0]);
    assert.ok(/trustForwardedFor:\s*true/.test(code));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('build defaults trustForwardedFor to false and emits empty allowedHosts when unset', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-'));
  try {
    const policy = {
      version: 1,
      defaults: { mode: 'enforce' },
      request: { allow_methods: ['GET'] },
      response_headers: {},
    };
    build(policy, { outDir: tmpDir, rootDir: path.join(__dirname, '..') });
    const code = fs.readFileSync(path.join(tmpDir, 'edge', 'viewer-request.js'), 'utf8');
    assert.ok(code.includes('allowedHosts: []'));
    assert.ok(/trustForwardedFor:\s*false/.test(code));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('build emits JWT gate with allowed_algorithms defaulting to configured algorithm and clock_skew_sec=30', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-'));
  try {
    const policy = {
      version: 1,
      defaults: { mode: 'enforce' },
      request: { allow_methods: ['GET'] },
      response_headers: {},
      routes: [{
        name: 'api',
        match: { path_prefixes: ['/api'] },
        auth_gate: { type: 'jwt', algorithm: 'RS256', jwks_url: 'https://example.com/jwks.json' },
      }],
    };

    build(policy, { outDir: tmpDir, rootDir: path.join(__dirname, '..') });
    const code = fs.readFileSync(path.join(tmpDir, 'edge', 'origin-request.js'), 'utf8');
    assert.ok(code.includes('"allowed_algorithms":["RS256"]'), 'default allowed_algorithms missing');
    assert.ok(code.includes('"clock_skew_sec":30'), 'default clock_skew_sec missing');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('build honors explicit allowed_algorithms and clock_skew_sec, rejects alg=none', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-'));
  try {
    const policy = {
      version: 1,
      defaults: { mode: 'enforce' },
      request: { allow_methods: ['GET'] },
      response_headers: {},
      routes: [{
        name: 'api',
        match: { path_prefixes: ['/api'] },
        auth_gate: {
          type: 'jwt',
          algorithm: 'RS256',
          jwks_url: 'https://example.com/jwks.json',
          allowed_algorithms: ['RS256', 'none', 'ES256'],
          clock_skew_sec: 120,
        },
      }],
    };
    build(policy, { outDir: tmpDir, rootDir: path.join(__dirname, '..') });
    const code = fs.readFileSync(path.join(tmpDir, 'edge', 'origin-request.js'), 'utf8');
    assert.ok(code.includes('"allowed_algorithms":["RS256","ES256"]'),
      'allowed_algorithms should filter out "none"; got:\n' + code.match(/"allowed_algorithms":[^,}]+/)?.[0]);
    assert.ok(code.includes('"clock_skew_sec":120'));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('build clamps clock_skew_sec to 0..600', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-'));
  try {
    const policy = {
      version: 1,
      defaults: { mode: 'enforce' },
      request: { allow_methods: ['GET'] },
      response_headers: {},
      routes: [{
        name: 'api',
        match: { path_prefixes: ['/api'] },
        auth_gate: {
          type: 'jwt',
          algorithm: 'HS256',
          secret_env: 'JWT_SECRET',
          clock_skew_sec: 99999,
        },
      }],
    };
    build(policy, { outDir: tmpDir, rootDir: path.join(__dirname, '..') });
    const code = fs.readFileSync(path.join(tmpDir, 'edge', 'origin-request.js'), 'utf8');
    assert.ok(code.includes('"clock_skew_sec":600'), 'clock_skew_sec should clamp to 600');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

if (process.exitCode) {
  process.exit(process.exitCode);
}
