import fs from 'node:fs';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import Ajv from 'ajv';
import * as yaml from 'js-yaml';
import { describe, expect, test } from 'vitest';

import {
  projectPolicyToAllowedSurface,
  type AllowedSurfaceModelV1,
} from '../../src/contract';
import type { CDNSecurityFrameworkPolicy } from '../../src/types/policy';
import { assertGolden } from '../helpers/golden-assert';

const { build } = require('../../scripts/lib/compile-core') as {
  build: (policy: unknown, options: Record<string, unknown>) => string[];
};

function compileAws(policy: Record<string, unknown>): { viewer: string; response: string; origin: string } {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'allowed-surface-runtime-'));
  try {
    build(policy, {
      rootDir: process.cwd(),
      outDir,
      env: { FIRST_TOKEN: 'first', SECOND_CREDS: 'second' },
      allowPlaceholderToken: false,
    });
    return {
      viewer: fs.readFileSync(path.join(outDir, 'edge', 'viewer-request.js'), 'utf8'),
      response: fs.readFileSync(path.join(outDir, 'edge', 'viewer-response.js'), 'utf8'),
      origin: fs.readFileSync(path.join(outDir, 'edge', 'origin-request.js'), 'utf8'),
    };
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
}

function compileViewer(policy: Record<string, unknown>): (event: unknown) => any {
  const { viewer } = compileAws(policy);
  return Function(`${viewer}\nreturn handler;`)();
}

function compileResponse(policy: Record<string, unknown>): (event: unknown) => any {
  const { response } = compileAws(policy);
  return Function(`${response}\nreturn handler;`)();
}

function request(method: string, uri: string, headers: Record<string, string> = {}): unknown {
  return {
    request: {
      method,
      uri,
      querystring: '',
      headers: Object.fromEntries(Object.entries({
        'user-agent': 'vitest',
        ...headers,
      }).map(([name, value]) => [name, { value }])),
    },
  };
}

function isAllowed(result: any): boolean {
  return Boolean(result && result.uri !== undefined && result.statusCode === undefined);
}

function policy(mode: 'enforce' | 'monitor' = 'enforce'): Record<string, unknown> {
  return {
    version: 1,
    defaults: { mode },
    request: {
      allow_methods: ['GET'],
      block: { path_patterns: { contains: ['/never-match'] } },
      normalize: { path: { collapse_slashes: true, remove_dot_segments: true } },
    },
    routes: [
      {
        name: 'first',
        match: { path_prefixes: ['/admin'] },
        auth_gate: { type: 'static_token', header: 'x-first', token_env: 'FIRST_TOKEN' },
        request: { allow_methods: ['POST'] },
      },
      {
        name: 'second',
        match: { path_prefixes: ['/admin/users'] },
        auth_gate: { type: 'basic_auth', credentials_env: 'SECOND_CREDS' },
      },
    ],
    response_headers: {},
  };
}

describe('current runtime route semantics', () => {
  test('uses global methods, segment-boundary prefixes, normalized paths, and every matching gate in order', () => {
    const handler = compileViewer(policy());

    expect(handler(request('POST', '/admin', { 'x-first': 'first' })).statusCode).toBe(405);
    expect(isAllowed(handler(request('GET', '/administrator')))).toBe(true);
    expect(handler(request('GET', '/admin/users', { 'x-first': 'first' })).statusCode).toBe(401);
    expect(isAllowed(handler(request('GET', '/x/../admin/users', {
      'x-first': 'first',
      authorization: 'Basic second',
    })))).toBe(true);
  });

  test('monitor mode only downgrades non-auth blocks; auth failures still reject', () => {
    const handler = compileViewer(policy('monitor'));
    expect(isAllowed(handler(request('POST', '/public')))).toBe(true);
    expect(handler(request('GET', '/admin')).statusCode).toBe(401);
  });

  test('CORS bypasses the global method allowlist and auth for allowed-origin preflight', () => {
    const input = policy();
    (input.request as Record<string, unknown>).allowed_hosts = ['allowed.example'];
    (input.response_headers as Record<string, unknown>).cors = {
      allow_origins: ['https://client.example'],
      allow_methods: ['GET'],
    };
    const handler = compileViewer(input);
    expect(isAllowed(handler(request('OPTIONS', '/public', { host: 'allowed.example' })))).toBe(true);
    expect(handler(request('OPTIONS', '/admin', {
      origin: 'https://client.example',
      host: 'blocked.example',
    })).statusCode).toBe(204);
  });

  test('response prefixes use literal equal-or-prefix-plus-slash matching for root and trailing slash', () => {
    const input = policy();
    input.routes = [{
      name: 'response',
      match: { path_prefixes: ['/'] },
      response: { cache_control: 'private' },
    }];
    let handler = compileResponse(input);
    expect(handler({ request: { uri: '/' }, response: { statusCode: 200, headers: {} } })
      .headers['cache-control']?.value).toBe('private');
    expect(handler({ request: { uri: '/child' }, response: { statusCode: 200, headers: {} } })
      .headers['cache-control']).toBeUndefined();

    (input.routes as any[])[0].match.path_prefixes = ['/admin/'];
    handler = compileResponse(input);
    expect(handler({ request: { uri: '/admin/' }, response: { statusCode: 200, headers: {} } })
      .headers['cache-control']?.value).toBe('private');
    expect(handler({ request: { uri: '/admin/child' }, response: { statusCode: 200, headers: {} } })
      .headers['cache-control']).toBeUndefined();
  });

  test('AWS associates duplicate-name JWT gates with their original route by order', () => {
    const input = policy();
    input.routes = [
      {
        name: 'duplicate',
        match: { path_prefixes: ['/one'] },
        auth_gate: { type: 'jwt', algorithm: 'HS256', secret_env: 'FIRST_TOKEN' },
      },
      {
        name: 'duplicate',
        match: { path_prefixes: ['/two'] },
        auth_gate: { type: 'jwt', algorithm: 'RS256', jwks_url: 'https://id.example/jwks' },
      },
    ];
    const { origin } = compileAws(input);
    expect(origin.match(/"algorithm":\s*"(?:HS256|RS256)"/g)?.map(
      (entry) => entry.replace(/\s/g, ''),
    )).toEqual(['"algorithm":"HS256"', '"algorithm":"RS256"']);
  });

  test('preserves method casing because runtimes compare configured values exactly', () => {
    const input = policy();
    (input.request as Record<string, unknown>).allow_methods = ['get'];
    expect(compileViewer(input)(request('GET', '/public')).statusCode).toBe(405);
  });
});

describe('Allowed Surface Model v1', () => {
  const digest = `sha256:${'a'.repeat(64)}`;

  test('projects effective defaults, ignored route methods, ordered gates, and target support', () => {
    const input = policy('monitor') as CDNSecurityFrameworkPolicy;
    input.routes?.push(
      { name: 'no-gate', match: { path_prefixes: ['/public'] } },
      { name: 'implicit-static', match: { path_prefixes: ['/implicit'] }, auth_gate: {} },
      { name: 'default-prefixes', match: {}, auth_gate: { type: 'basic_auth' } },
      {
        name: 'unsupported-jwt',
        match: { path_prefixes: ['/es256'] },
        auth_gate: { type: 'jwt', algorithm: 'ES256' },
      },
      {
        name: 'cloudflare-jwks-requirement',
        match: { path_prefixes: ['/rs256'] },
        auth_gate: { type: 'jwt', algorithm: 'RS256', jwks_url: 'https://id.example/jwks' },
      },
    );
    const projected = projectPolicyToAllowedSurface(input, {
      policyDigest: digest,
      sourceUri: 'policy/security.yml',
    });

    expect(projected.defaults).toMatchObject({
      mode: 'monitor',
      requestDecision: 'would-block',
      authenticationDecision: 'block',
      methods: ['GET'],
      configuredMethods: ['GET'],
      corsOptionsBypass: false,
      corsPreflight: { allowedOriginDecision: 'not-configured', bypassScope: 'none' },
      hosts: { kind: 'any', values: [] },
      pathNormalization: { routeMatchPhase: 'normalized-path' },
      response: { adminPathMatch: { algorithm: 'equal-or-prefix-plus-slash' } },
    });
    expect(projected.orderedRules.map(({ name }) => name)).toEqual([
      'first', 'second', 'no-gate', 'implicit-static', 'default-prefixes', 'unsupported-jwt',
      'cloudflare-jwks-requirement',
    ]);
    expect(projected.orderedRules[0]).toMatchObject({
      pointer: '/routes/0',
      match: { kind: 'prefix', boundary: 'path-segment', phase: 'normalized-path' },
      methods: { source: 'global', effective: ['GET'], configuredButNotEnforced: ['POST'] },
      auth: {
        kind: 'static_token',
        typeSource: 'explicit',
        matching: {
          aws: 'static-and-basic-in-policy-order-then-jwt-then-signed-url',
          cloudflare: 'all-matching-rules-in-policy-order',
        },
        preAuthBypassMethods: [],
        preAuthBypassCondition: 'none',
        credentialEnvironmentNames: ['FIRST_TOKEN'],
      },
      response: {
        selection: 'first-auth-or-cache-rule',
        effectiveCacheControl: {
          base: 'no-store',
          authProtectedOverride: {
            value: 'no-store, no-cache, must-revalidate, private',
          },
        },
      },
    });
    expect(projected.orderedRules[2].auth).toMatchObject({ kind: 'none', typeSource: 'absent' });
    expect(projected.orderedRules[3].auth).toMatchObject({
      kind: 'static_token',
      typeSource: 'compiler-default',
    });
    expect(projected.orderedRules[4].match).toMatchObject({
      values: [],
      authEffectiveValues: ['/admin', '/docs', '/swagger'],
    });
    expect(projected.orderedRules[5].auth).toMatchObject({
      configuredAlgorithm: 'ES256',
      verifiability: { aws: 'unsupported-configuration', cloudflare: 'unsupported-configuration' },
    });
    expect(projected.orderedRules[5].auth).not.toHaveProperty('effectiveAlgorithm');
    expect(projected.orderedRules[6].auth.verifiability).toEqual({
      aws: 'enforced',
      cloudflare: 'unsupported-configuration',
    });
    expect(projected.targetCapabilities.aws).toContainEqual({
      id: 'response.csp_nonce', status: 'unsupported',
    });
    expect(projected.targetCapabilities.cloudflare).toContainEqual({
      id: 'response.csp_nonce', status: 'supported',
    });

    input.firewall = { jwks: { allowed_hosts: ['id.example'] } };
    expect(projectPolicyToAllowedSurface(input, {
      policyDigest: digest,
      sourceUri: 'policy/security.yml',
    }).orderedRules[6].auth.verifiability.cloudflare).toBe('enforced');

    input.response_headers.cors = { allow_origins: ['https://client.example'] };
    expect(projectPolicyToAllowedSurface(input, {
      policyDigest: digest,
      sourceUri: 'policy/security.yml',
    }).defaults).toMatchObject({
      methods: ['GET', 'OPTIONS'],
      configuredMethods: ['GET'],
      corsOptionsBypass: true,
      corsPreflight: {
        allowedOriginDecision: 'early-204-before-request-validation',
        bypassScope: 'all-request-validation-including-host-and-auth',
      },
    });
    expect(projectPolicyToAllowedSurface(input, {
      policyDigest: digest,
      sourceUri: 'policy/security.yml',
    }).orderedRules[0].auth).toMatchObject({
      preAuthBypassMethods: ['OPTIONS'],
      preAuthBypassCondition: 'allowed-cors-origin-preflight',
    });
  });

  test('fails closed when auth structure cannot be enforced by a target', () => {
    const input = policy() as CDNSecurityFrameworkPolicy;
    input.routes = [{
      name: 'invalid-jwks',
      match: { path_prefixes: ['/admin'] },
      auth_gate: { type: 'jwt', algorithm: 'RS256', jwks_url: 'http://127.0.0.1/jwks' },
    }];
    let projected = projectPolicyToAllowedSurface(input, {
      policyDigest: digest,
      sourceUri: 'policy/security.yml',
    });
    expect(projected.orderedRules[0].auth.verifiability).toEqual({
      aws: 'unsupported-configuration',
      cloudflare: 'unsupported-configuration',
    });

    input.routes[0].auth_gate = {
      type: 'jwt', algorithm: 'HS256', secret_env: 'JWT_SECRET', allowed_algorithms: ['RS256'],
    };
    projected = projectPolicyToAllowedSurface(input, {
      policyDigest: digest,
      sourceUri: 'policy/security.yml',
    });
    expect(projected.orderedRules[0].auth.verifiability).toEqual({
      aws: 'unsupported-configuration',
      cloudflare: 'unsupported-configuration',
    });

    input.routes[0].auth_gate = {
      type: 'jwt', algorithm: 'RS256', jwks_url: 'https://id.example/jwks',
    };
    input.firewall = { jwks: { allowed_hosts: [' '] } };
    projected = projectPolicyToAllowedSurface(input, {
      policyDigest: digest,
      sourceUri: 'policy/security.yml',
    });
    expect(projected.orderedRules[0].auth.verifiability).toEqual({
      aws: 'unsupported-configuration',
      cloudflare: 'unsupported-configuration',
    });
  });

  test('projects the force-vary no-store override as effective cache control', () => {
    const input = policy() as CDNSecurityFrameworkPolicy;
    input.routes![0].response = { cache_control: 'private, max-age=300' };
    expect(projectPolicyToAllowedSurface(input, {
      policyDigest: digest,
      sourceUri: 'policy/security.yml',
    }).orderedRules[0].response).toMatchObject({
      cacheControl: 'private, max-age=300',
      effectiveCacheControl: {
        base: 'private, max-age=300',
        authProtectedOverride: {
          value: 'no-store, no-cache, must-revalidate, private',
          pathMatch: { values: ['/admin', '/admin/users'] },
        },
      },
    });

    input.response_headers.force_vary_auth = false;
    expect(projectPolicyToAllowedSurface(input, {
      policyDigest: digest,
      sourceUri: 'policy/security.yml',
    }).orderedRules[0].response.effectiveCacheControl).toEqual({ base: 'private, max-age=300' });
  });

  test('preserves runtime method casing and exposes auth cache overrides without route containment', () => {
    const input = policy() as CDNSecurityFrameworkPolicy;
    input.request.allow_methods = ['get'];
    input.routes = [
      {
        name: 'cache-only',
        match: { path_prefixes: ['/admin'] },
        response: { cache_control: 'private, max-age=300' },
      },
      {
        name: 'auth',
        match: { path_prefixes: ['/admin'] },
        auth_gate: { type: 'static_token', token_env: 'FIRST_TOKEN' },
      },
    ];
    const projected = projectPolicyToAllowedSurface(input, {
      policyDigest: digest,
      sourceUri: 'policy/security.yml',
    });
    expect(projected.defaults.methods).toEqual(['get']);
    expect(projected.orderedRules[0].response.effectiveCacheControl).toMatchObject({
      base: 'private, max-age=300',
      authProtectedOverride: {
        value: 'no-store, no-cache, must-revalidate, private',
        pathMatch: { values: ['/admin'] },
      },
    });

    input.response_headers.clear_site_data_paths = ['/logout'];
    expect(projectPolicyToAllowedSurface(input, {
      policyDigest: digest,
      sourceUri: 'policy/security.yml',
    }).orderedRules[0].response.effectiveCacheControl).toMatchObject({
      clearSiteDataOverride: {
        when: 'matching-path-and-status-200-through-399',
        value: 'no-store',
        pathMatch: { values: ['/logout'] },
      },
    });
  });

  test('is pure, ignores credential values, and rejects unsafe evidence metadata', () => {
    const input = policy() as CDNSecurityFrameworkPolicy;
    input.request.allow_methods = ['HEAD', 'GET', 'GET'];
    input.routes![0].match.path_prefixes = ['/z', '/a'];
    const before = structuredClone(input);
    const original = process.env.FIRST_TOKEN;
    let first: AllowedSurfaceModelV1;
    let second: AllowedSurfaceModelV1;
    try {
      process.env.FIRST_TOKEN = 'must-not-be-read-one';
      first = projectPolicyToAllowedSurface(input, { policyDigest: digest, sourceUri: './policy/base.yml' });
      process.env.FIRST_TOKEN = 'must-not-be-read-two';
      const reordered = structuredClone({ response_headers: input.response_headers, ...input });
      reordered.request.allow_methods.reverse();
      reordered.routes![0].match.path_prefixes?.reverse();
      second = projectPolicyToAllowedSurface(reordered, { policyDigest: digest, sourceUri: 'policy/base.yml' });
    } finally {
      if (original === undefined) delete process.env.FIRST_TOKEN;
      else process.env.FIRST_TOKEN = original;
    }

    expect(second).toEqual(first);
    expect(input).toEqual(before);
    expect(JSON.stringify(first)).not.toContain('must-not-be-read');
    expect(() => projectPolicyToAllowedSurface(input, {
      policyDigest: 'not-a-digest', sourceUri: 'policy/base.yml',
    })).toThrow('invalid policy digest');
    expect(() => projectPolicyToAllowedSurface(input, {
      policyDigest: digest, sourceUri: '../outside.yml',
    })).toThrow('invalid policy source uri');
    expect(() => projectPolicyToAllowedSurface(input, {
      policyDigest: digest, sourceUri: 'C:\\outside.yml',
    })).toThrow('invalid policy source uri');
  });

  test('projects every built-in policy to one stable golden', () => {
    const files = [
      'policy/base.yml',
      'policy/profiles/balanced.yml',
      'policy/profiles/permissive.yml',
      'policy/profiles/strict.yml',
      'policy/archetypes/admin-panel.yml',
      'policy/archetypes/microservice-origin.yml',
      'policy/archetypes/rest-api.yml',
      'policy/archetypes/spa-static-site.yml',
    ];
    const schema = JSON.parse(fs.readFileSync('policy/schema.json', 'utf8'));
    const validate = new Ajv({ allErrors: true, strict: true, strictRequired: false }).compile(schema);
    const models: Record<string, AllowedSurfaceModelV1> = {};

    for (const file of files) {
      const bytes = fs.readFileSync(file);
      const parsed = yaml.load(bytes.toString('utf8')) as CDNSecurityFrameworkPolicy;
      expect(validate(parsed), `${file}: ${JSON.stringify(validate.errors)}`).toBe(true);
      models[file] = projectPolicyToAllowedSurface(parsed, {
        policyDigest: `sha256:${createHash('sha256').update(bytes).digest('hex')}`,
        sourceUri: file,
      });
    }
    assertGolden('allowed-surface-builtins', models);
  });
});
