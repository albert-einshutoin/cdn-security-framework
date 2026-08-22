import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';

import { DEFAULT_OPENAPI_ANALYSIS_LIMITS } from '../../src/openapi/analysis-limits';
import { loadOpenApiDocument } from '../../src/openapi/load-document';
import { normalizeOpenApiOperations } from '../../src/openapi/operation-normalizer';
import { resolveOpenApiReferences } from '../../src/openapi/ref-resolver';

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

function contractFor(document: unknown) {
  const workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-auth-'));
  temporaryDirectories.push(workspaceRoot);
  const inputPath = path.join(workspaceRoot, 'openapi.json');
  fs.writeFileSync(inputPath, JSON.stringify(document));
  const root = loadOpenApiDocument({ inputPath, workspaceRoot });
  const graph = resolveOpenApiReferences({ root, workspaceRoot, limits: DEFAULT_OPENAPI_ANALYSIS_LIMITS });
  return normalizeOpenApiOperations(graph);
}

function operation(pathName: string, security?: unknown) {
  return {
    openapi: '3.1.0',
    paths: { [pathName]: { get: {
      ...(security === undefined ? {} : { security }),
      responses: {},
    } } },
  };
}

describe('OpenAPI authentication normalization', () => {
  test('inherits global Basic and allows an operation to explicitly become public', () => {
    const contract = contractFor({
      openapi: '3.1.0',
      security: [{ basicAuth: [] }],
      paths: {
        '/private': { get: { responses: {} } },
        '/public': { get: { security: [], responses: {} } },
      },
      components: {
        securitySchemes: { basicAuth: { $ref: '#/components/x-security-schemes/basic' } },
        'x-security-schemes': { basic: { type: 'http', scheme: 'basic' } },
      },
    });
    expect(contract.capabilities.authentication).toBe('complete');
    expect(contract.operations.map(({ routeKey, exposure, auth }) => ({ routeKey, exposure, auth })))
      .toEqual([
        {
          routeKey: 'GET /private', exposure: 'authenticated',
          auth: { mode: 'alternatives', alternatives: [{
            anonymous: false,
            schemes: [{ name: 'basicAuth', kind: 'basic', scopes: [], capability: 'supported' }],
          }] },
        },
        { routeKey: 'GET /public', exposure: 'public', auth: { mode: 'none', alternatives: [] } },
      ]);
    expect(contract.operations[0]?.provenance.map(({ pointer }) => pointer))
      .toEqual(expect.arrayContaining(['/security', '/components/x-security-schemes/basic']));
  });

  test('preserves OR alternatives, AND schemes, API key locations, OAuth scopes, and flow names', () => {
    const contract = contractFor({
      openapi: '3.1.0',
      security: [{ bearer: [], tenant: [], oauth: ['write'] }, { queryKey: [] }, { cookieKey: [] }],
      paths: { '/items': { post: { responses: {} } } },
      components: { securitySchemes: {
        bearer: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
        tenant: { type: 'apiKey', in: 'header', name: 'X-Tenant-Key' },
        queryKey: { type: 'apiKey', in: 'query', name: 'api_key' },
        cookieKey: { type: 'apiKey', in: 'cookie', name: 'session' },
        oauth: { type: 'oauth2', flows: {
          clientCredentials: { tokenUrl: 'https://example.test/token', scopes: { write: 'Write' } },
        } },
      } },
    });
    const alternatives = contract.operations[0]?.auth.alternatives ?? [];
    expect(alternatives).toHaveLength(3);
    expect(alternatives.flatMap(({ schemes }) => schemes)).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: 'bearer', kind: 'bearer' }),
      expect.objectContaining({ name: 'tenant', kind: 'api-key', location: 'header', parameterName: 'x-tenant-key' }),
      expect.objectContaining({ name: 'queryKey', kind: 'api-key', location: 'query', parameterName: 'api_key' }),
      expect.objectContaining({ name: 'cookieKey', kind: 'api-key', location: 'cookie', parameterName: 'session' }),
      expect.objectContaining({ name: 'oauth', kind: 'oauth2', scopes: ['write'], flows: ['clientCredentials'] }),
    ]));
    expect(JSON.stringify(contract)).not.toContain('bearerFormat');
    expect(JSON.stringify(contract)).not.toContain('tokenUrl');
  });

  test('keeps anonymous OR authenticated public while absent security stays unknown', () => {
    const anonymous = contractFor({
      ...operation('/optional'),
      security: [{}, { bearer: [] }],
      components: { securitySchemes: { bearer: { type: 'http', scheme: 'bearer' } } },
    }).operations[0];
    expect(anonymous).toMatchObject({
      exposure: 'public',
      auth: { mode: 'alternatives', alternatives: expect.arrayContaining([
        { anonymous: true, schemes: [] },
      ]) },
    });

    const unknown = contractFor(operation('/unknown')).operations[0];
    expect(unknown).toMatchObject({ exposure: 'unknown', auth: { mode: 'unknown', alternatives: [] } });
  });

  test('retains unsupported schemes as authenticated unknowns and rejects undefined references', () => {
    const unsupported = contractFor({
      ...operation('/digest'),
      security: [{ digest: [] }],
      components: { securitySchemes: { digest: { type: 'http', scheme: 'digest' } } },
    });
    expect(unsupported.capabilities.authentication).toBe('partial');
    expect(unsupported.operations[0]).toMatchObject({
      exposure: 'authenticated',
      auth: { alternatives: [{ schemes: [{
        name: 'digest', kind: 'unknown', capability: 'unsupported',
        unsupportedReason: 'http-scheme:digest',
      }] }] },
    });

    expect(() => contractFor({ ...operation('/missing'), security: [{ missing: [] }] }))
      .toThrow(expect.objectContaining({ code: 'OPENAPI_OPERATION_INVALID' }));
    expect(() => contractFor({
      ...operation('/invalid'),
      security: [{ digest: [] }],
      paths: { '/invalid': { get: { security: null, responses: {} } } },
      components: { securitySchemes: { digest: { type: 'http', scheme: 'digest' } } },
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_OPERATION_INVALID' }));
  });

  test('does not infer JWT validation from bearerFormat', () => {
    const auth = (bearerFormat?: string) => contractFor({
      ...operation('/bearer'),
      security: [{ bearer: [] }],
      components: { securitySchemes: { bearer: {
        type: 'http', scheme: 'bearer', ...(bearerFormat ? { bearerFormat } : {}),
      } } },
    }).operations[0]?.auth;
    expect(auth('JWT')).toEqual(auth('opaque'));
    expect(auth('JWT')).toEqual(auth());
  });

  test('rejects malformed OAuth flow metadata', () => {
    for (const flow of [
      { clientCredentials: {} },
      { implicit: { authorizationUrl: 'https://example.test/auth', scopes: [] } },
      { authorizationCode: { authorizationUrl: 'https://example.test/auth', scopes: {} } },
    ]) {
      expect(() => contractFor({
        ...operation('/oauth'),
        security: [{ oauth: [] }],
        components: { securitySchemes: { oauth: { type: 'oauth2', flows: flow } } },
      })).toThrow(expect.objectContaining({ code: 'OPENAPI_OPERATION_INVALID' }));
    }
  });
});
