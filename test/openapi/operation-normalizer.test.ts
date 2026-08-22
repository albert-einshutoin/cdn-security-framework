import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';

import { serializeSecurityContract } from '../../src/contract/security-ir';
import { DEFAULT_OPENAPI_ANALYSIS_LIMITS } from '../../src/openapi/analysis-limits';
import { loadOpenApiDocument } from '../../src/openapi/load-document';
import { normalizeOpenApiOperations } from '../../src/openapi/operation-normalizer';
import { resolveOpenApiReferences } from '../../src/openapi/ref-resolver';
import { fixtureRoot } from '../helpers/fixture-root';

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

function graphFor(inputPath: string, workspaceRoot = fixtureRoot) {
  const root = loadOpenApiDocument({ inputPath, workspaceRoot });
  return resolveOpenApiReferences({ root, workspaceRoot, limits: DEFAULT_OPENAPI_ANALYSIS_LIMITS });
}

function temporaryGraph(document: unknown) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-normalize-'));
  temporaryDirectories.push(root);
  const inputPath = path.join(root, 'openapi.json');
  fs.writeFileSync(inputPath, JSON.stringify(document));
  return graphFor(inputPath, root);
}

describe('normalizeOpenApiOperations', () => {
  test('extracts request surface without interpreting authentication', () => {
    const contract = normalizeOpenApiOperations(graphFor(
      path.join(fixtureRoot, 'valid/openapi-3.0.yaml'),
    ));
    expect(contract.operations.map(({ routeKey }) => routeKey)).toEqual([
      'GET /public',
      'POST /users/{userId}',
    ]);
    const operation = contract.operations[1];
    expect(operation).toMatchObject({
      operationId: 'updateUser',
      exposure: 'unknown',
      auth: { mode: 'unknown', alternatives: [] },
      metadata: { deprecated: true, tags: ['users', 'write'] },
      request: {
        contentTypes: [
          'application/json',
          'application/x-www-form-urlencoded',
          'multipart/form-data',
          'text/plain',
        ],
        requiredHeaders: ['x-tenant-id'],
        pathParameters: [expect.objectContaining({ name: 'userId', required: true })],
        queryParameters: [expect.objectContaining({ name: 'page', required: false })],
        headerParameters: [expect.objectContaining({ name: 'x-tenant-id', required: true })],
        cookieParameters: [expect.objectContaining({ name: 'session', required: false })],
        body: expect.objectContaining({ required: true }),
      },
    });
    expect(operation?.provenance[0]).toMatchObject({
      source: 'openapi',
      uri: 'valid/openapi-3.0.yaml',
      pointer: '/paths/~1users~1{userId}/post',
    });
    expect(JSON.stringify(contract)).not.toContain('Update users');
    expect(JSON.stringify(contract)).not.toContain('description');
  });

  test('merges path parameters by in and normalized name with operation override', () => {
    const graph = temporaryGraph({
      openapi: '3.1.0',
      paths: {
        '/items/{id}': {
          parameters: [
            { name: 'id', in: 'path', required: true, schema: { type: 'string', maxLength: 50 } },
            { name: 'X-Mode', in: 'header', required: false, schema: { type: 'string' } },
            { name: 'id', in: 'query', required: false, schema: { type: 'integer' } },
          ],
          summary: 'ignored',
          'x-custom': { get: {} },
          get: {
            parameters: [
              { name: 'x-mode', in: 'header', required: true, schema: { type: 'string', enum: ['safe'] } },
              { name: 'id', in: 'path', required: true, schema: { type: 'string', maxLength: 20 } },
            ],
            responses: { 200: { description: 'ok' } },
          },
        },
      },
    });
    const [operation] = normalizeOpenApiOperations(graph).operations;
    expect(operation?.request.headerParameters).toEqual([
      expect.objectContaining({ name: 'x-mode', required: true }),
    ]);
    expect(operation?.request.pathParameters[0]?.constraints.maxLength).toBe(20);
    expect(operation?.request.queryParameters[0]?.name).toBe('id');
  });

  test('normalizes parameters and request body schemas through resolved references', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-normalize-ref-'));
    temporaryDirectories.push(root);
    fs.writeFileSync(path.join(root, 'components.json'), JSON.stringify({
      parameters: {
        Tenant: {
          name: 'X-Tenant', in: 'header', required: true,
          schema: { $ref: '#/schemas/TenantId' },
        },
      },
      schemas: {
        TenantId: { $ref: '#/schemas/TenantValue', maxLength: 12 },
        TenantValue: { type: 'string' },
        Payload: { type: 'object', maxProperties: 4 },
      },
      requestBodies: {
        Payload: {
          required: true,
          content: {
            'Application/JSON; Charset=UTF-8': { schema: { $ref: '#/schemas/Payload' } },
          },
        },
      },
    }));
    fs.writeFileSync(path.join(root, 'openapi.json'), JSON.stringify({
      openapi: '3.1.0',
      paths: { '/items': { post: {
        parameters: [{ $ref: './components.json#/parameters/Tenant' }],
        requestBody: { $ref: './components.json#/requestBodies/Payload' },
        responses: {},
      } } },
    }));
    const operation = normalizeOpenApiOperations(graphFor(path.join(root, 'openapi.json'), root)).operations[0];
    expect(operation?.request).toMatchObject({
      contentTypes: ['application/json'],
      requiredHeaders: ['x-tenant'],
      body: { required: true, constraints: { type: 'object', maxProperties: 4 } },
    });
    expect(operation?.request.headerParameters[0]?.unsupportedReasons)
      .toEqual(['schema:ref-siblings']);
  });

  test('does not decode an already-resolved percent sequence twice', () => {
    const graph = temporaryGraph({
      openapi: '3.1.0',
      components: {
        schemas: {
          'a%2Fb': { type: 'string', maxLength: 8 },
          a: { b: { type: 'integer', maximum: 99 } },
        },
      },
      paths: { '/items': { get: {
        parameters: [{
          name: 'value', in: 'query', schema: { $ref: '#/components/schemas/a%252Fb' },
        }],
        responses: {},
      } } },
    });
    expect(normalizeOpenApiOperations(graph).operations[0]?.request.queryParameters[0]?.constraints)
      .toMatchObject({ type: 'string', maxLength: 8 });
  });

  test('rejects optional path parameters and duplicate parameters at one level', () => {
    for (const parameters of [
      [{ name: 'id', in: 'path', required: false, schema: { type: 'string' } }],
      [
        { name: 'q', in: 'query', schema: { type: 'string' } },
        { name: 'q', in: 'query', schema: { type: 'string' } },
      ],
    ]) {
      const graph = temporaryGraph({
        openapi: '3.1.0',
        paths: { '/items/{id}': { get: { parameters, responses: { 200: {} } } } },
      });
      expect(() => normalizeOpenApiOperations(graph))
        .toThrow(expect.objectContaining({ code: 'OPENAPI_OPERATION_INVALID' }));
    }
  });

  test('rejects missing and extraneous path parameters', () => {
    for (const [routePath, parameters] of [
      ['/items/{id}', []],
      ['/items', [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }]],
    ] as const) {
      const graph = temporaryGraph({
        openapi: '3.1.0',
        paths: { [routePath]: { get: { parameters, responses: {} } } },
      });
      expect(() => normalizeOpenApiOperations(graph))
        .toThrow(expect.objectContaining({ code: 'OPENAPI_OPERATION_INVALID' }));
    }
  });

  test('marks unsupported schema composition and nullable unions without retaining examples', () => {
    const graph = temporaryGraph({
      openapi: '3.1.0',
      paths: {
        '/search': {
          get: {
            parameters: [{
              name: 'q', in: 'query', schema: {
                oneOf: [{ type: 'string' }, { type: 'integer' }],
                allOf: [{ type: 'string' }],
                nullable: true,
                example: 'secret-example',
              },
            }],
            responses: { 200: {} },
          },
        },
      },
    });
    const contract = normalizeOpenApiOperations(graph);
    expect(contract.capabilities.parameters).toBe('partial');
    expect(contract.operations[0]?.request.queryParameters[0]).toMatchObject({
      constraints: { type: 'unknown' },
      unsupportedReasons: ['schema:allOf', 'schema:nullable', 'schema:oneOf'],
    });
    expect(JSON.stringify(contract)).not.toContain('secret-example');
  });

  test('rejects duplicate canonical route keys and secret-like enum values', () => {
    const duplicate = temporaryGraph({
      openapi: '3.1.0',
      paths: { '/items': { get: { responses: {} }, GET: { responses: {} } } },
    });
    expect(() => normalizeOpenApiOperations(duplicate))
      .toThrow(expect.objectContaining({ code: 'OPENAPI_OPERATION_INVALID' }));

    const secret = temporaryGraph({
      openapi: '3.1.0',
      paths: { '/items': { get: { parameters: [{
        name: 'mode', in: 'query', schema: { type: 'string', enum: ['Bearer actual-secret'] },
      }], responses: {} } } },
    });
    expect(() => normalizeOpenApiOperations(secret))
      .toThrow(expect.objectContaining({ code: 'OPENAPI_OPERATION_INVALID' }));
  });

  test('normalizes all valid corpus documents to a golden result', async () => {
    const contracts = fs.readdirSync(path.join(fixtureRoot, 'valid')).sort().map((name) => ({
      name,
      contract: normalizeOpenApiOperations(graphFor(path.join(fixtureRoot, 'valid', name))),
    }));
    await expect(`${JSON.stringify(contracts, null, 2)}\n`).toMatchFileSnapshot(
      '../fixtures/openapi/expected/normalized-valid-contracts.json',
    );
  });

  test('sorts 1000 operations and enforces the operation limit', () => {
    const paths = Object.fromEntries(Array.from({ length: 1000 }, (_, index) => [
      `/resources/${String(999 - index).padStart(4, '0')}`,
      { get: { responses: { 200: {} } } },
    ]));
    const graph = temporaryGraph({ openapi: '3.1.0', paths });
    const contract = normalizeOpenApiOperations(graph, {
      limits: { ...DEFAULT_OPENAPI_ANALYSIS_LIMITS, maxOperations: 1000 },
    });
    expect(contract.operations[0]?.routeKey).toBe('GET /resources/0000');
    expect(contract.operations[999]?.routeKey).toBe('GET /resources/0999');
    expect(() => normalizeOpenApiOperations(graph, {
      limits: { ...DEFAULT_OPENAPI_ANALYSIS_LIMITS, maxOperations: 999 },
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_OPERATION_LIMIT' }));
  });

  test('produces stable serialization for input ordering differences and empty paths', () => {
    const first = temporaryGraph({
      openapi: '3.1.0',
      paths: { '/b': { post: { responses: {} } }, '/a': { get: { responses: {} } } },
    });
    const second = temporaryGraph({
      paths: { '/a': { get: { responses: {} } }, '/b': { post: { responses: {} } } },
      openapi: '3.1.0',
    });
    const withoutDigest = (graph: ResolvedOpenApiGraph) => {
      const contract = normalizeOpenApiOperations(graph);
      return JSON.stringify({
        ...contract,
        operations: contract.operations.map((operation) => ({
          ...operation,
          provenance: operation.provenance.map(({ digest: _digest, ...provenance }) => provenance),
        })),
      });
    };
    expect(withoutDigest(first)).toBe(withoutDigest(second));
    expect(normalizeOpenApiOperations(temporaryGraph({ openapi: '3.1.0', paths: {} })).operations)
      .toEqual([]);
  });
});
