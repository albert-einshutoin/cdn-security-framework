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
  validateJwksUrl,
  build,
  PLACEHOLDER_TOKEN,
  hasFailOnPermissiveFlag,
  warnIfPermissive,
  warnSignedUrlReplay,
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

test('build honors explicit allowed_algorithms matching the configured algorithm and filters alg=none', () => {
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
          allowed_algorithms: ['RS256', 'none'],
          clock_skew_sec: 120,
        },
      }],
    };
    build(policy, { outDir: tmpDir, rootDir: path.join(__dirname, '..') });
    const code = fs.readFileSync(path.join(tmpDir, 'edge', 'origin-request.js'), 'utf8');
    assert.ok(code.includes('"allowed_algorithms":["RS256"]'),
      'allowed_algorithms should filter "none" and retain only the configured algorithm; got:\n' +
        code.match(/"allowed_algorithms":[^,}]+/)?.[0]);
    assert.ok(code.includes('"clock_skew_sec":120'));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('validateAuthGates rejects allowed_algorithms that include an alg the verifier cannot validate', () => {
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
        allowed_algorithms: ['HS256'],
      },
    }],
  };
  let caught;
  try {
    validateAuthGates(policy, { exitOnError: false });
  } catch (e) {
    caught = e;
  }
  assert.ok(caught, 'validateAuthGates should throw');
  const detail = (caught.validationErrors || []).join('\n');
  assert.match(detail,
    /allowed_algorithms contains .*HS256.* but the gate only runs the "RS256" verifier/);
});

test('build filters cross-alg entries from emitted allowed_algorithms even when validateAuthGates is bypassed', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-'));
  try {
    // Simulate a future call path that forgot to run validateAuthGates first.
    // The emission must still never advertise an alg the verifier can't handle.
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
          allowed_algorithms: ['HS256', 'ES256', 'none'],
        },
      }],
    };
    build(policy, { outDir: tmpDir, rootDir: path.join(__dirname, '..') });
    const code = fs.readFileSync(path.join(tmpDir, 'edge', 'origin-request.js'), 'utf8');
    assert.ok(code.includes('"allowed_algorithms":["RS256"]'),
      'emission must fall back to configured algorithm when no entry matches; got:\n' +
        code.match(/"allowed_algorithms":[^,}]+/)?.[0]);
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

test('hasFailOnPermissiveFlag detects the flag', () => {
  assert.strictEqual(hasFailOnPermissiveFlag(['--fail-on-permissive']), true);
  assert.strictEqual(hasFailOnPermissiveFlag(['--policy', 'x', '--fail-on-permissive']), true);
  assert.strictEqual(hasFailOnPermissiveFlag(['--policy', 'x']), false);
  assert.strictEqual(hasFailOnPermissiveFlag([]), false);
  assert.strictEqual(hasFailOnPermissiveFlag(undefined), false);
  assert.strictEqual(hasFailOnPermissiveFlag(null), false);
});

test('warnIfPermissive returns no-op when metadata.risk_level is not permissive', () => {
  const captured = [];
  const logger = { error: (msg) => captured.push(msg) };
  const r1 = warnIfPermissive({}, { logger });
  const r2 = warnIfPermissive({ metadata: { risk_level: 'strict' } }, { logger });
  const r3 = warnIfPermissive({ metadata: { risk_level: 'balanced' } }, { logger });
  const r4 = warnIfPermissive(null, { logger });
  assert.deepStrictEqual(r1, { warned: false, failed: false });
  assert.deepStrictEqual(r2, { warned: false, failed: false });
  assert.deepStrictEqual(r3, { warned: false, failed: false });
  assert.deepStrictEqual(r4, { warned: false, failed: false });
  assert.strictEqual(captured.length, 0);
});

test('warnIfPermissive warns but does not fail when failOnPermissive is false', () => {
  const captured = [];
  const logger = { error: (msg) => captured.push(msg) };
  const result = warnIfPermissive({ metadata: { risk_level: 'permissive' } }, { logger });
  assert.deepStrictEqual(result, { warned: true, failed: false });
  assert.strictEqual(captured.length, 1);
  assert.match(captured[0], /metadata\.risk_level is "permissive"/);
  assert.match(captured[0], /--fail-on-permissive/);
});

test('warnIfPermissive fails when failOnPermissive is true', () => {
  const captured = [];
  const logger = { error: (msg) => captured.push(msg) };
  const result = warnIfPermissive(
    { metadata: { risk_level: 'permissive' } },
    { logger, failOnPermissive: true },
  );
  assert.deepStrictEqual(result, { warned: true, failed: true });
  assert.strictEqual(captured.length, 2);
  assert.match(captured[1], /refusing to build a permissive policy/);
});

test('validateJwksUrl accepts well-formed public https URLs', () => {
  assert.deepStrictEqual(
    validateJwksUrl('https://idp.example.com/.well-known/jwks.json').ok,
    true,
  );
  assert.deepStrictEqual(
    validateJwksUrl('https://login.microsoftonline.com/common/discovery/v2.0/keys').ok,
    true,
  );
});

test('validateJwksUrl rejects non-https schemes', () => {
  assert.strictEqual(validateJwksUrl('http://idp.example.com/jwks.json').ok, false);
  assert.strictEqual(validateJwksUrl('file:///etc/passwd').ok, false);
  assert.strictEqual(validateJwksUrl('ftp://example.com/jwks.json').ok, false);
});

test('validateJwksUrl rejects URLs with userinfo', () => {
  const r = validateJwksUrl('https://user:pass@idp.example.com/jwks.json');
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /userinfo/);
});

test('validateJwksUrl rejects loopback / private / link-local hostnames', () => {
  const cases = [
    'https://localhost/jwks.json',
    'https://127.0.0.1/jwks.json',
    'https://127.5.5.5/jwks.json',
    'https://10.0.0.1/jwks.json',
    'https://10.255.255.254/jwks.json',
    'https://192.168.1.1/jwks.json',
    'https://172.16.0.1/jwks.json',
    'https://172.31.255.255/jwks.json',
    'https://169.254.169.254/latest/meta-data/',
    'https://0.0.0.0/jwks.json',
    'https://[::1]/jwks.json',
    'https://[fe80::1]/jwks.json',
    'https://[fc00::1]/jwks.json',
    'https://[::ffff:127.0.0.1]/jwks.json',
  ];
  for (const url of cases) {
    const r = validateJwksUrl(url);
    assert.strictEqual(r.ok, false, `should reject ${url}`);
  }
});

test('validateJwksUrl enforces allowed_hosts when provided', () => {
  const allow = ['idp.example.com', 'Auth.Example.Com'];
  assert.strictEqual(validateJwksUrl('https://idp.example.com/jwks.json', allow).ok, true);
  assert.strictEqual(validateJwksUrl('https://auth.example.com/jwks.json', allow).ok, true);
  const r = validateJwksUrl('https://evil.example.com/jwks.json', allow);
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /firewall\.jwks\.allowed_hosts/);
});

test('validateAuthGates rejects jwks_url in private/loopback ranges', () => {
  const policy = {
    routes: [
      {
        name: 'metadata-ssrf',
        auth_gate: { type: 'jwt', algorithm: 'RS256', jwks_url: 'https://169.254.169.254/latest/' },
      },
    ],
  };
  assert.throws(
    () => validateAuthGates(policy, { exitOnError: false, allowPlaceholderToken: true }),
    (err) => Array.isArray(err.validationErrors)
      && err.validationErrors.some((e) => /metadata-ssrf/.test(e) && /private\/loopback/.test(e)),
  );
});

test('validateAuthGates rejects jwks_url outside firewall.jwks.allowed_hosts', () => {
  const policy = {
    firewall: { jwks: { allowed_hosts: ['idp.example.com'] } },
    routes: [
      {
        name: 'wrong-idp',
        auth_gate: { type: 'jwt', algorithm: 'RS256', jwks_url: 'https://attacker.example/jwks.json' },
      },
    ],
  };
  assert.throws(
    () => validateAuthGates(policy, { exitOnError: false, allowPlaceholderToken: true }),
    (err) => Array.isArray(err.validationErrors)
      && err.validationErrors.some((e) => /wrong-idp/.test(e) && /allowed_hosts/.test(e)),
  );
});

test('validateAuthGates accepts jwks_url on allowed_hosts (case-insensitive)', () => {
  const policy = {
    firewall: { jwks: { allowed_hosts: ['IDP.Example.COM'] } },
    routes: [
      {
        name: 'good-idp',
        auth_gate: { type: 'jwt', algorithm: 'RS256', jwks_url: 'https://idp.example.com/jwks.json' },
      },
    ],
  };
  validateAuthGates(policy, { exitOnError: false, allowPlaceholderToken: true });
});

test('warnSignedUrlReplay flags write-like signed_url gates missing nonce_param', () => {
  const captured = [];
  const logger = { error: (m) => captured.push(m) };
  const policy = {
    routes: [
      {
        name: 'write-download',
        match: { path_prefixes: ['/api/download'] },
        auth_gate: { type: 'signed_url', secret_env: 'URL_SIGNING_SECRET' },
      },
    ],
  };
  const r = warnSignedUrlReplay(policy, { logger });
  assert.strictEqual(r.warned, true);
  assert.strictEqual(r.warnings.length, 1);
  assert.match(captured[0], /write-download/);
  assert.match(captured[0], /nonce_param/);
});

test('warnSignedUrlReplay stays silent for read-only paths', () => {
  const captured = [];
  const logger = { error: (m) => captured.push(m) };
  const policy = {
    routes: [
      {
        name: 'cdn-assets',
        match: { path_prefixes: ['/assets'] },
        auth_gate: { type: 'signed_url', secret_env: 'URL_SIGNING_SECRET' },
      },
    ],
  };
  const r = warnSignedUrlReplay(policy, { logger });
  assert.strictEqual(r.warned, false);
  assert.strictEqual(captured.length, 0);
});

test('warnSignedUrlReplay stays silent when nonce_param is set', () => {
  const captured = [];
  const logger = { error: (m) => captured.push(m) };
  const policy = {
    routes: [
      {
        name: 'write-download',
        match: { path_prefixes: ['/api/download'] },
        auth_gate: { type: 'signed_url', secret_env: 'URL_SIGNING_SECRET', nonce_param: 'nonce' },
      },
    ],
  };
  const r = warnSignedUrlReplay(policy, { logger });
  assert.strictEqual(r.warned, false);
  assert.strictEqual(captured.length, 0);
});

test('build emits signed_url gate with exact_path and nonce_param fields', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-signed-'));
  try {
    const policy = {
      version: 1,
      request: { allow_methods: ['GET'] },
      response_headers: {},
      routes: [
        {
          name: 'one-time',
          match: { path_prefixes: ['/api/download/report.pdf'] },
          auth_gate: {
            type: 'signed_url',
            secret_env: 'URL_SIGNING_SECRET',
            exact_path: true,
            nonce_param: 'nonce',
          },
        },
      ],
    };
    build(policy, { outDir: tmpDir, allowPlaceholderToken: true });
    const origin = fs.readFileSync(path.join(tmpDir, 'edge', 'origin-request.js'), 'utf8');
    assert.match(origin, /"exact_path":true/);
    assert.match(origin, /"nonce_param":"nonce"/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('build defaults exact_path=false and nonce_param="" when unspecified', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-signed-def-'));
  try {
    const policy = {
      version: 1,
      request: { allow_methods: ['GET'] },
      response_headers: {},
      routes: [
        {
          name: 'legacy',
          match: { path_prefixes: ['/assets'] },
          auth_gate: { type: 'signed_url', secret_env: 'URL_SIGNING_SECRET' },
        },
      ],
    };
    build(policy, { outDir: tmpDir, allowPlaceholderToken: true });
    const origin = fs.readFileSync(path.join(tmpDir, 'edge', 'origin-request.js'), 'utf8');
    assert.match(origin, /"exact_path":false/);
    assert.match(origin, /"nonce_param":""/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('build emits jwksStaleIfErrorSec and jwksNegativeCacheSec defaults', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-jwks-default-'));
  try {
    const policy = {
      version: 1,
      request: { allow_methods: ['GET'] },
      response_headers: {},
      routes: [
        {
          name: 'api',
          match: { path_prefixes: ['/api'] },
          auth_gate: { type: 'jwt', algorithm: 'RS256', jwks_url: 'https://idp.example.com/jwks.json' },
        },
      ],
    };
    build(policy, { outDir: tmpDir, allowPlaceholderToken: true });
    const origin = fs.readFileSync(path.join(tmpDir, 'edge', 'origin-request.js'), 'utf8');
    assert.match(origin, /jwksStaleIfErrorSec:\s*3600/);
    assert.match(origin, /jwksNegativeCacheSec:\s*60/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('build honors firewall.jwks.stale_if_error_sec and negative_cache_sec', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-jwks-custom-'));
  try {
    const policy = {
      version: 1,
      request: { allow_methods: ['GET'] },
      response_headers: {},
      firewall: { jwks: { stale_if_error_sec: 7200, negative_cache_sec: 120 } },
      routes: [
        {
          name: 'api',
          match: { path_prefixes: ['/api'] },
          auth_gate: { type: 'jwt', algorithm: 'RS256', jwks_url: 'https://idp.example.com/jwks.json' },
        },
      ],
    };
    build(policy, { outDir: tmpDir, allowPlaceholderToken: true });
    const origin = fs.readFileSync(path.join(tmpDir, 'edge', 'origin-request.js'), 'utf8');
    assert.match(origin, /jwksStaleIfErrorSec:\s*7200/);
    assert.match(origin, /jwksNegativeCacheSec:\s*120/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('build clamps jwks.stale_if_error_sec and negative_cache_sec to bounds', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-jwks-clamp-'));
  try {
    const policy = {
      version: 1,
      request: { allow_methods: ['GET'] },
      response_headers: {},
      firewall: { jwks: { stale_if_error_sec: 999999, negative_cache_sec: 99999 } },
      routes: [
        {
          name: 'api',
          match: { path_prefixes: ['/api'] },
          auth_gate: { type: 'jwt', algorithm: 'RS256', jwks_url: 'https://idp.example.com/jwks.json' },
        },
      ],
    };
    build(policy, { outDir: tmpDir, allowPlaceholderToken: true });
    const origin = fs.readFileSync(path.join(tmpDir, 'edge', 'origin-request.js'), 'utf8');
    assert.match(origin, /jwksStaleIfErrorSec:\s*86400/);
    assert.match(origin, /jwksNegativeCacheSec:\s*600/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('viewer-request uses fixed-pad constant-time compare (no length short-circuit)', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-timing-'));
  try {
    const policy = {
      version: 1,
      request: { allow_methods: ['GET'] },
      response_headers: {},
      routes: [
        {
          name: 'admin',
          match: { path_prefixes: ['/admin'] },
          auth_gate: { type: 'static_token', header: 'x-admin', token_env: 'ADMIN_TOKEN' },
        },
      ],
    };
    build(policy, { outDir: tmpDir, allowPlaceholderToken: true });
    const vr = fs.readFileSync(path.join(tmpDir, 'edge', 'viewer-request.js'), 'utf8');
    // Must iterate a fixed PAD and must NOT early-exit on length
    assert.match(vr, /var\s+PAD\s*=\s*64/);
    assert.ok(!/if\s*\(\s*a\.length\s*!==?\s*b\.length\s*\)\s*return\s+false/.test(vr),
      'constantTimeEqual must not short-circuit on length');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('constantTimeEqual (compiled) returns correct boolean for matches and mismatches', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-timing-fn-'));
  try {
    const policy = {
      version: 1,
      request: { allow_methods: ['GET'] },
      response_headers: {},
      routes: [
        {
          name: 'admin',
          match: { path_prefixes: ['/admin'] },
          auth_gate: { type: 'static_token', header: 'x-admin', token_env: 'ADMIN_TOKEN' },
        },
      ],
    };
    process.env.ADMIN_TOKEN = 'not-relevant-to-unit-test';
    build(policy, { outDir: tmpDir });
    const vr = fs.readFileSync(path.join(tmpDir, 'edge', 'viewer-request.js'), 'utf8');
    // Extract the function body and eval it in isolation
    const match = vr.match(/function constantTimeEqual[\s\S]+?return diff === 0;\s*\}/);
    assert.ok(match, 'constantTimeEqual function not found in compiled output');
    const fn = new Function(match[0] + '\nreturn constantTimeEqual;')();
    assert.strictEqual(fn('abc', 'abc'), true);
    assert.strictEqual(fn('abc', 'abd'), false);
    assert.strictEqual(fn('short', 'longer-token'), false); // different lengths still false
    assert.strictEqual(fn('', ''), true);
    assert.strictEqual(fn('', 'x'), false);
    // Ensure it still works for inputs longer than PAD (64)
    const long = 'a'.repeat(70);
    assert.strictEqual(fn(long, long), true);
    assert.strictEqual(fn(long, 'a'.repeat(69) + 'b'), false);
  } finally {
    delete process.env.ADMIN_TOKEN;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('response_headers: authProtectedPrefixes is union of every auth gate prefix', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-resp-union-'));
  try {
    const policy = {
      version: 1,
      request: { allow_methods: ['GET', 'POST'] },
      response_headers: {},
      routes: [
        {
          name: 'admin',
          match: { path_prefixes: ['/admin', '/docs'] },
          auth_gate: { type: 'static_token', header: 'x-admin', token_env: 'ADMIN_TOKEN' },
        },
        {
          name: 'api',
          match: { path_prefixes: ['/api'] },
          auth_gate: {
            type: 'jwt', algorithm: 'RS256',
            jwks_url: 'https://idp.example.com/jwks.json',
          },
        },
        {
          name: 'dl',
          match: { path_prefixes: ['/download'] },
          auth_gate: {
            type: 'signed_url', secret_env: 'URL_SIGNING_SECRET',
            exact_path: true, nonce_param: 'nonce',
          },
        },
      ],
    };
    process.env.ADMIN_TOKEN = 'test';
    build(policy, { outDir: tmpDir });
    const resp = fs.readFileSync(path.join(tmpDir, 'edge', 'viewer-response.js'), 'utf8');
    assert.match(resp, /authProtectedPrefixes: \["\/admin","\/docs","\/api","\/download"\]/);
    assert.match(resp, /forceVaryAuth: true/);
  } finally {
    delete process.env.ADMIN_TOKEN;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('response_headers: force_vary_auth=false disables Vary/no-store override', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-resp-off-'));
  try {
    const policy = {
      version: 1,
      request: { allow_methods: ['GET'] },
      response_headers: { force_vary_auth: false },
      routes: [{
        name: 'admin', match: { path_prefixes: ['/admin'] },
        auth_gate: { type: 'static_token', header: 'x-admin', token_env: 'ADMIN_TOKEN' },
      }],
    };
    process.env.ADMIN_TOKEN = 'test';
    build(policy, { outDir: tmpDir });
    const resp = fs.readFileSync(path.join(tmpDir, 'edge', 'viewer-response.js'), 'utf8');
    assert.match(resp, /forceVaryAuth: false/);
  } finally {
    delete process.env.ADMIN_TOKEN;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('response_headers: emits COOP/COEP/CORP/Reporting-Endpoints when configured', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-resp-iso-'));
  try {
    const policy = {
      version: 1,
      request: { allow_methods: ['GET'] },
      response_headers: {
        coop: 'same-origin',
        coep: 'require-corp',
        corp: 'same-origin',
        reporting_endpoints: 'csp="https://r.example.com/csp"',
      },
      routes: [],
    };
    build(policy, { outDir: tmpDir, allowPlaceholderToken: true });
    const resp = fs.readFileSync(path.join(tmpDir, 'edge', 'viewer-response.js'), 'utf8');
    assert.match(resp, /coop: "same-origin"/);
    assert.match(resp, /coep: "require-corp"/);
    assert.match(resp, /corp: "same-origin"/);
    assert.match(resp, /reporting_endpoints: "csp=\\"https:\/\/r\.example\.com\/csp\\""/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('response_headers: csp_nonce=true emits substitution hook and Report-Only copy', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-resp-csp-'));
  try {
    const policy = {
      version: 1,
      request: { allow_methods: ['GET'] },
      response_headers: {
        csp_nonce: true,
        csp_public: "default-src 'self'; script-src 'self' 'nonce-PLACEHOLDER'",
        csp_report_only: "default-src 'self'; report-to csp",
      },
      routes: [],
    };
    build(policy, { outDir: tmpDir, allowPlaceholderToken: true });
    const resp = fs.readFileSync(path.join(tmpDir, 'edge', 'viewer-response.js'), 'utf8');
    assert.match(resp, /csp_nonce: true/);
    assert.match(resp, /csp_report_only: "default-src/);
    // Template must have nonce substitution hook + Report-Only emission path
    assert.match(resp, /'nonce-PLACEHOLDER'/);
    assert.match(resp, /Content-Security-Policy-Report-Only/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('request.limits.max_header_count defaults to 64 and is clamped to 1..500', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-hc-'));
  try {
    const base = { version: 1, request: { allow_methods: ['GET'] }, response_headers: {}, routes: [] };

    // Default
    build(base, { outDir: tmpDir, allowPlaceholderToken: true });
    let vr = fs.readFileSync(path.join(tmpDir, 'edge', 'viewer-request.js'), 'utf8');
    assert.match(vr, /maxHeaderCount: 64,/);

    // Custom
    build({ ...base, request: { ...base.request, limits: { max_header_count: 128 } } },
      { outDir: tmpDir, allowPlaceholderToken: true });
    vr = fs.readFileSync(path.join(tmpDir, 'edge', 'viewer-request.js'), 'utf8');
    assert.match(vr, /maxHeaderCount: 128,/);

    // Clamp high
    build({ ...base, request: { ...base.request, limits: { max_header_count: 9999 } } },
      { outDir: tmpDir, allowPlaceholderToken: true });
    vr = fs.readFileSync(path.join(tmpDir, 'edge', 'viewer-request.js'), 'utf8');
    assert.match(vr, /maxHeaderCount: 500,/);

    // Clamp low
    build({ ...base, request: { ...base.request, limits: { max_header_count: 0 } } },
      { outDir: tmpDir, allowPlaceholderToken: true });
    vr = fs.readFileSync(path.join(tmpDir, 'edge', 'viewer-request.js'), 'utf8');
    assert.match(vr, /maxHeaderCount: 1,/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('viewer-request enforces max_header_count with 431', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-hc-rt-'));
  try {
    build({
      version: 1,
      request: { allow_methods: ['GET'], limits: { max_header_count: 3 } },
      response_headers: {},
      routes: [],
    }, { outDir: tmpDir, allowPlaceholderToken: true });
    const code = fs.readFileSync(path.join(tmpDir, 'edge', 'viewer-request.js'), 'utf8');
    // Extract handler and invoke it in isolation via Function ctor
    const sandbox = { handler: null };
    const run = new Function('sandbox', code + '\nsandbox.handler = handler;');
    run(sandbox);

    const event = {
      request: {
        method: 'GET',
        uri: '/',
        querystring: '',
        headers: {
          'user-agent': { value: 'Mozilla' },
          'x-a': { value: '1' },
          'x-b': { value: '2' },
          'x-c': { value: '3' },
          'x-d': { value: '4' },
        },
      },
    };
    const result = sandbox.handler(event);
    assert.strictEqual(result.statusCode, 431);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('response_headers.clear_site_data_paths emits directive + no-store on 2xx', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-csd-'));
  try {
    build({
      version: 1,
      request: { allow_methods: ['GET'] },
      response_headers: {
        clear_site_data_paths: ['/logout', '/session/end'],
      },
      routes: [],
    }, { outDir: tmpDir, allowPlaceholderToken: true });
    const resp = fs.readFileSync(path.join(tmpDir, 'edge', 'viewer-response.js'), 'utf8');
    assert.match(resp, /clearSiteDataPaths: \["\/logout","\/session\/end"\]/);
    assert.match(resp, /clearSiteDataTypes: \["cache","cookies","storage"\]/);
    assert.match(resp, /Clear-Site-Data/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('response_headers.clear_site_data_types override honored', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compile-unit-csd-t-'));
  try {
    build({
      version: 1,
      request: { allow_methods: ['GET'] },
      response_headers: {
        clear_site_data_paths: ['/logout'],
        clear_site_data_types: ['cache', 'cookies'],
      },
      routes: [],
    }, { outDir: tmpDir, allowPlaceholderToken: true });
    const resp = fs.readFileSync(path.join(tmpDir, 'edge', 'viewer-response.js'), 'utf8');
    assert.match(resp, /clearSiteDataTypes: \["cache","cookies"\]/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

if (process.exitCode) {
  process.exit(process.exitCode);
}
