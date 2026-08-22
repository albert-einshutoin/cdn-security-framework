import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, test, vi } from 'vitest';

import { DEFAULT_OPENAPI_ANALYSIS_LIMITS } from '../../src/openapi/analysis-limits';
import { loadOpenApiDocument } from '../../src/openapi/load-document';
import {
  resolveJsonPointer,
  resolveJsonPointerValue,
  resolveOpenApiReferences,
  serializeResolvedOpenApiGraph,
} from '../../src/openapi/ref-resolver';
import { fixtureRoot } from '../helpers/fixture-root';

const temporaryDirectories: string[] = [];
const refsRoot = path.join(fixtureRoot, 'refs');

afterEach(() => {
  vi.restoreAllMocks();
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

function loadFixture(relativePath: string) {
  return loadOpenApiDocument({
    inputPath: path.join(fixtureRoot, relativePath),
    workspaceRoot: fixtureRoot,
  });
}

describe('resolveJsonPointer', () => {
  test('decodes percent encoding and JSON Pointer escapes', () => {
    const target = { 'a/b': { '~key': {} } };
    expect(resolveJsonPointer(target, '#/a~1b/%7E0key', 'root.yaml')).toEqual({
      value: {},
      pointer: '/a~1b/~0key',
    });
  });

  test.each(['target', '#target', '#/%ZZ', '#/bad~2escape'])(
    'rejects invalid pointer %s',
    (pointer) => {
      expect(() => resolveJsonPointer({}, pointer, 'root.yaml'))
        .toThrow(expect.objectContaining({ code: 'OPENAPI_REF_POINTER_INVALID' }));
    },
  );

  test('distinguishes missing targets and preserves scalar schemas', () => {
    expect(() => resolveJsonPointer({}, '#/missing', 'root.yaml'))
      .toThrow(expect.objectContaining({ code: 'OPENAPI_REF_NOT_FOUND' }));
    expect(() => resolveJsonPointer({ scalar: false }, '#/scalar', 'root.yaml'))
      .toThrow(expect.objectContaining({ code: 'OPENAPI_REF_NOT_FOUND' }));
    expect(resolveJsonPointerValue({ scalar: false }, '#/scalar', 'root.yaml').value).toBe(false);
  });
});

describe('resolveOpenApiReferences', () => {
  test('resolves same-document refs with provenance', () => {
    const root = loadFixture('refs/same-document.yaml');
    const graph = resolveOpenApiReferences({
      root,
      workspaceRoot: fixtureRoot,
      limits: DEFAULT_OPENAPI_ANALYSIS_LIMITS,
    });

    expect(graph.documents).toHaveLength(1);
    expect(graph.references).toEqual([
      expect.objectContaining({
        ref: '#/components/parameters/UserId',
        target: {
          id: 'refs/same-document.yaml#/components/parameters/UserId',
          sourceUri: 'refs/same-document.yaml',
          pointer: '/components/parameters/UserId',
        },
      }),
    ]);
    expect(Object.isFrozen(graph)).toBe(true);
    expect(Object.isFrozen(graph.documents)).toBe(true);
    expect(Object.isFrozen(graph.documents[0]?.document)).toBe(true);
  });

  test('rejects forged loader results at the public boundary', () => {
    const root = loadFixture('refs/same-document.yaml');
    expect(() => resolveOpenApiReferences({
      root: { ...root, byteSize: 0 },
      workspaceRoot: fixtureRoot,
      limits: DEFAULT_OPENAPI_ANALYSIS_LIMITS,
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_INVALID_ROOT' }));
  });

  test('binds loaded roots to their original workspace and current limits', () => {
    const workspaceA = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-workspace-a-'));
    const workspaceB = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-workspace-b-'));
    temporaryDirectories.push(workspaceA, workspaceB);
    const document = JSON.stringify({ openapi: '3.1.0', paths: {}, x: 'long-value' });
    fs.writeFileSync(path.join(workspaceA, 'root.json'), document);
    fs.writeFileSync(path.join(workspaceB, 'root.json'), document);
    const root = loadOpenApiDocument({ inputPath: 'root.json', workspaceRoot: workspaceA });

    expect(() => resolveOpenApiReferences({
      root, workspaceRoot: workspaceB, limits: DEFAULT_OPENAPI_ANALYSIS_LIMITS,
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_INVALID_ROOT' }));
    expect(() => resolveOpenApiReferences({
      root,
      workspaceRoot: workspaceA,
      limits: { ...DEFAULT_OPENAPI_ANALYSIS_LIMITS, maxStringLength: 8 },
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_NODE_LIMIT' }));
  });

  test('resolves boolean schemas and encoded hashes in local filenames', () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-encoded-hash-'));
    temporaryDirectories.push(workspace);
    fs.writeFileSync(path.join(workspace, 'defs#v1.json'), JSON.stringify({ Never: false }));
    fs.writeFileSync(path.join(workspace, 'root.json'), JSON.stringify({
      openapi: '3.1.0',
      paths: {},
      components: { schemas: { Never: { $ref: 'defs%23v1.json#/Never' } } },
    }));
    const graph = resolveOpenApiReferences({
      root: loadOpenApiDocument({ inputPath: 'root.json', workspaceRoot: workspace }),
      workspaceRoot: workspace,
      limits: DEFAULT_OPENAPI_ANALYSIS_LIMITS,
    });
    expect(graph.references[0]?.target.sourceUri).toBe('defs%23v1.json');
    expect(graph.documents.find(({ sourceUri }) => sourceUri === 'defs%23v1.json')?.document)
      .toEqual({ Never: false });

    fs.writeFileSync(path.join(workspace, 'root.json'), JSON.stringify({
      openapi: '3.1.0',
      paths: {},
      components: { schemas: { Invalid: { $ref: 'defs%23v1.json#/Count' } } },
    }));
    fs.writeFileSync(path.join(workspace, 'defs#v1.json'), JSON.stringify({ Count: 1 }));
    expect(() => resolveOpenApiReferences({
      root: loadOpenApiDocument({ inputPath: 'root.json', workspaceRoot: workspace }),
      workspaceRoot: workspace,
      limits: DEFAULT_OPENAPI_ANALYSIS_LIMITS,
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_REF_NOT_FOUND' }));
  });

  test('ignores literal ref keys in schema example values', () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-literal-ref-'));
    temporaryDirectories.push(workspace);
    fs.writeFileSync(path.join(workspace, 'root.json'), JSON.stringify({
      openapi: '3.1.0',
      paths: {},
      components: { schemas: { Sample: {
        type: 'string',
        example: { $ref: '#/components/schemas/Sample/default' },
        default: { $ref: '#/components/schemas/Sample/example' },
        enum: [{ $ref: '#/components/schemas/Sample/type' }],
      } } },
    }));
    const graph = resolveOpenApiReferences({
      root: loadOpenApiDocument({ inputPath: 'root.json', workspaceRoot: workspace }),
      workspaceRoot: workspace,
      limits: DEFAULT_OPENAPI_ANALYSIS_LIMITS,
    });
    expect(graph.references).toEqual([]);
  });

  test('caches sibling documents and keeps cycles as reference identity', () => {
    const root = loadFixture('refs/sibling.yaml');
    const open = vi.spyOn(fs, 'openSync');
    const graph = resolveOpenApiReferences({
      root,
      workspaceRoot: fixtureRoot,
      limits: DEFAULT_OPENAPI_ANALYSIS_LIMITS,
    });

    expect(graph.documents.map((document) => document.sourceUri)).toEqual([
      'refs/components.json',
      'refs/cycle-a.yaml',
      'refs/cycle-b.yaml',
      'refs/nested/common.yaml',
      'refs/sibling.yaml',
    ]);
    expect(open.mock.calls.filter(([inputPath]) => String(inputPath).endsWith('components.json')))
      .toHaveLength(1);
    expect(graph.references.some(({ target }) => (
      target.id === 'refs/cycle-a.yaml#/components/schemas/NodeA'
    ))).toBe(true);
    expect(new Set(graph.references.map(({ target }) => target.id)).size)
      .toBeLessThan(graph.references.length);
  });

  test.each([
    ['malicious/traversal.yaml', 'OPENAPI_REF_OUTSIDE_ROOT'],
    ['malicious/absolute-ref.yaml', 'OPENAPI_REF_OUTSIDE_ROOT'],
    ['malicious/file-uri.yaml', 'OPENAPI_REF_OUTSIDE_ROOT'],
    ['malicious/https-ref.yaml', 'OPENAPI_REMOTE_REF_DISABLED'],
  ] as const)('rejects unsafe refs in %s', (relativePath, code) => {
    const root = loadFixture(relativePath);
    expect(() => resolveOpenApiReferences({
      root,
      workspaceRoot: fixtureRoot,
      limits: DEFAULT_OPENAPI_ANALYSIS_LIMITS,
    })).toThrow(expect.objectContaining({ code }));
  });

  test('applies document count, ref depth, and byte limits to the full graph', () => {
    const root = loadFixture('refs/sibling.yaml');
    expect(() => resolveOpenApiReferences({
      root,
      workspaceRoot: fixtureRoot,
      limits: { ...DEFAULT_OPENAPI_ANALYSIS_LIMITS, maxResolvedDocuments: 1 },
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_DOCUMENT_COUNT_LIMIT' }));
    expect(() => resolveOpenApiReferences({
      root,
      workspaceRoot: fixtureRoot,
      limits: { ...DEFAULT_OPENAPI_ANALYSIS_LIMITS, maxRefDepth: 1 },
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_REF_DEPTH_LIMIT' }));
    expect(() => resolveOpenApiReferences({
      root,
      workspaceRoot: fixtureRoot,
      limits: { ...DEFAULT_OPENAPI_ANALYSIS_LIMITS, maxGraphBytes: root.byteSize },
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_GRAPH_SIZE_LIMIT' }));
  });

  test('counts same-document reference chains even when components are also root members', () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-ref-depth-'));
    temporaryDirectories.push(workspace);
    const inputPath = path.join(workspace, 'root.yaml');
    fs.writeFileSync(inputPath, [
      'openapi: 3.1.0',
      'paths:',
      '  /items:',
      '    get:',
      "      responses: { '200': { content: { application/json: { schema: { $ref: '#/components/schemas/A' } } } } }",
      'components:',
      '  schemas:',
      "    A: { $ref: '#/components/schemas/B' }",
      '    B: { type: object }',
      '',
    ].join('\n'));
    const root = loadOpenApiDocument({ inputPath, workspaceRoot: workspace });

    expect(() => resolveOpenApiReferences({
      root,
      workspaceRoot: workspace,
      limits: { ...DEFAULT_OPENAPI_ANALYSIS_LIMITS, maxRefDepth: 1 },
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_REF_DEPTH_LIMIT' }));
  });

  test('bounds repeated walks of a shared target with the global node budget', () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-ref-budget-'));
    temporaryDirectories.push(workspace);
    const inputPath = path.join(workspace, 'root.json');
    fs.writeFileSync(inputPath, JSON.stringify({
      openapi: '3.1.0',
      paths: {
        '/a': { get: { responses: { 200: { $ref: '#/components/schemas/A' } } } },
        '/b': { get: { responses: { 200: { $ref: '#/components/schemas/A' } } } },
      },
      components: {
        schemas: {
          A: {
            type: 'object',
            properties: Object.fromEntries(Array.from({ length: 10 }, (_, index) => [
              `p${index}`,
              { type: 'string' },
            ])),
          },
        },
      },
    }));
    const root = loadOpenApiDocument({ inputPath, workspaceRoot: workspace });

    expect(() => resolveOpenApiReferences({
      root,
      workspaceRoot: workspace,
      limits: { ...DEFAULT_OPENAPI_ANALYSIS_LIMITS, maxNodes: 64 },
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_NODE_LIMIT' }));
  });

  test('rejects a local ref symlink that escapes the workspace', () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-ref-root-'));
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-ref-outside-'));
    temporaryDirectories.push(workspace, outside);
    fs.writeFileSync(path.join(workspace, 'root.yaml'), [
      'openapi: 3.1.0',
      'paths: {}',
      "components: { schemas: { Escaped: { $ref: './escape.yaml#/value' } } }",
      '',
    ].join('\n'));
    fs.writeFileSync(path.join(outside, 'outside.yaml'), 'value: {}\n');
    fs.symlinkSync(path.join(outside, 'outside.yaml'), path.join(workspace, 'escape.yaml'));
    const root = loadOpenApiDocument({ inputPath: path.join(workspace, 'root.yaml'), workspaceRoot: workspace });

    expect(() => resolveOpenApiReferences({
      root,
      workspaceRoot: workspace,
      limits: DEFAULT_OPENAPI_ANALYSIS_LIMITS,
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_REF_OUTSIDE_ROOT' }));
  });

  test('serializes the graph deterministically', async () => {
    const graph = resolveOpenApiReferences({
      root: loadFixture('refs/sibling.yaml'),
      workspaceRoot: fixtureRoot,
      limits: DEFAULT_OPENAPI_ANALYSIS_LIMITS,
    });
    await expect(`${serializeResolvedOpenApiGraph(graph)}\n`).toMatchFileSnapshot(
      '../fixtures/openapi/expected/resolved-sibling-graph.json',
    );
  });

  test('serializer rejects cyclic or non-finite forged graphs with stable errors', () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => serializeResolvedOpenApiGraph(cyclic as never))
      .toThrow(expect.objectContaining({ code: 'OPENAPI_REF_CYCLE_LIMIT' }));
    expect(() => serializeResolvedOpenApiGraph({ value: Number.POSITIVE_INFINITY } as never))
      .toThrow(expect.objectContaining({ code: 'OPENAPI_PARSE_ERROR' }));
  });

  test('serializer rejects array accessors without invoking them', () => {
    const hostile: unknown[] = [];
    Object.defineProperty(hostile, '0', {
      enumerable: true,
      get: () => { throw new Error('accessor-secret'); },
    });
    Object.defineProperty(hostile, 'length', { value: 1 });
    expect(() => serializeResolvedOpenApiGraph({ value: hostile } as never))
      .toThrow(expect.objectContaining({ code: 'OPENAPI_PARSE_ERROR' }));
  });
});
