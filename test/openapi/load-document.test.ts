import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, test, vi } from 'vitest';

import { loadOpenApiDocument } from '../../src/openapi/load-document';
import { fixtureRoot } from '../helpers/fixture-root';

const temporaryDirectories: string[] = [];

function temporaryFile(name: string, content: string): { root: string; inputPath: string } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-loader-'));
  temporaryDirectories.push(root);
  const inputPath = path.join(root, name);
  fs.writeFileSync(inputPath, content, 'utf8');
  return { root, inputPath };
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe('loadOpenApiDocument', () => {
  test.each([
    ['valid/openapi-3.0.json', '3.0'],
    ['valid/openapi-3.0.yaml', '3.0'],
    ['valid/openapi-3.1.json', '3.1'],
    ['valid/openapi-3.1.yaml', '3.1'],
  ] as const)('loads %s without resolving references', (relativePath, version) => {
    const loaded = loadOpenApiDocument({
      inputPath: path.join(fixtureRoot, relativePath),
      workspaceRoot: fixtureRoot,
    });

    expect(loaded.version).toBe(version);
    expect(loaded.sourceUri).toBe(relativePath);
    expect(loaded.refStatus).toBe('unresolved');
    expect(loaded.byteSize).toBeGreaterThan(0);
    expect(loaded.contentDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(Object.keys(loaded).sort()).toEqual([
      'byteSize', 'contentDigest', 'document', 'refStatus', 'sourceUri', 'version',
    ]);
  });

  test('preserves refs in the parsed document and hashes raw bytes', () => {
    const withLf = temporaryFile('spec.yaml', [
      'openapi: 3.1.0',
      'paths:',
      '  /users:',
      '    get:',
      "      responses: { '200': { $ref: '#/components/responses/Ok' } }",
      '',
    ].join('\n'));
    const withCrlf = temporaryFile('spec.yaml', fs.readFileSync(withLf.inputPath, 'utf8')
      .replace(/\n/g, '\r\n'));

    const first = loadOpenApiDocument({ inputPath: withLf.inputPath, workspaceRoot: withLf.root });
    const second = loadOpenApiDocument({ inputPath: withCrlf.inputPath, workspaceRoot: withCrlf.root });
    expect(JSON.stringify(first.document)).toContain('#/components/responses/Ok');
    expect(first.contentDigest).not.toBe(second.contentDigest);
  });

  test('checks file size before reading content', () => {
    const fixture = temporaryFile('large.yaml', 'openapi: 3.1.0\npaths: {}\n');
    const read = vi.spyOn(fs, 'readSync');

    expect(() => loadOpenApiDocument({
      inputPath: fixture.inputPath,
      workspaceRoot: fixture.root,
      limits: { maxDocumentBytes: 4 },
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_DOCUMENT_TOO_LARGE' }));
    expect(read).not.toHaveBeenCalled();
  });

  test('bounds descriptor reads to limit plus one byte if the file grows after stat', () => {
    const fixture = temporaryFile('growing.yaml', 'x');
    const read = vi.spyOn(fs, 'readSync').mockImplementation((
      _fd, buffer, offset, length,
    ) => {
      expect(length).toBe(11);
      (buffer as Buffer).fill(0x78, offset, offset + length);
      return length;
    });
    expect(() => loadOpenApiDocument({
      inputPath: fixture.inputPath,
      workspaceRoot: fixture.root,
      limits: { maxDocumentBytes: 10 },
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_DOCUMENT_TOO_LARGE' }));
    expect(read).toHaveBeenCalledTimes(1);
  });

  test('maps YAML alias exhaustion to its stable limit code', () => {
    const fixture = temporaryFile('aliases.yaml', [
      'openapi: 3.1.0',
      'base: &base { type: string }',
      'first: *base',
      'second: *base',
      'paths: {}',
      '',
    ].join('\n'));
    expect(() => loadOpenApiDocument({
      inputPath: fixture.inputPath,
      workspaceRoot: fixture.root,
      limits: { maxYamlAliases: 1 },
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_YAML_ALIAS_LIMIT' }));
  });

  test.each([
    ['invalid/invalid-json.json', 'OPENAPI_PARSE_ERROR'],
    ['invalid/invalid-yaml.yaml', 'OPENAPI_PARSE_ERROR'],
    ['invalid/missing-openapi.yaml', 'OPENAPI_INVALID_ROOT'],
    ['invalid/unsupported-version.yaml', 'OPENAPI_UNSUPPORTED_VERSION'],
    ['invalid/ambiguous-operation.yaml', 'OPENAPI_PARSE_ERROR'],
  ] as const)('returns a stable error for %s', (relativePath, code) => {
    expect(() => loadOpenApiDocument({
      inputPath: path.join(fixtureRoot, relativePath),
      workspaceRoot: fixtureRoot,
    })).toThrow(expect.objectContaining({ code }));
  });

  test.each(['null', '[]', '{"openapi":"3.1.0","paths":"wrong"}'])(
    'rejects invalid root shape %s',
    (content) => {
      const fixture = temporaryFile('invalid.json', content);
      expect(() => loadOpenApiDocument({
        inputPath: fixture.inputPath,
        workspaceRoot: fixture.root,
      })).toThrow(expect.objectContaining({ code: 'OPENAPI_INVALID_ROOT' }));
    },
  );

  test('rejects duplicate and prototype-pollution keys', () => {
    for (const content of [
      '{"openapi":"3.1.0","paths":{},"paths":{}}',
      '{"openapi":"3.1.0","paths":{},"__proto__":{"polluted":true}}',
      'openapi: 3.1.0\npaths: {}\nconstructor:\n  prototype:\n    polluted: true\n',
    ]) {
      const fixture = temporaryFile('hostile.txt', content);
      expect(() => loadOpenApiDocument({
        inputPath: fixture.inputPath,
        workspaceRoot: fixture.root,
      })).toThrow(expect.objectContaining({ code: 'OPENAPI_PARSE_ERROR' }));
    }
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  test('rejects outside-root, symlink escape, and remote inputs without network access', () => {
    const outside = temporaryFile('outside.yaml', 'openapi: 3.1.0\npaths: {}\n');
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-workspace-'));
    temporaryDirectories.push(root);

    expect(() => loadOpenApiDocument({ inputPath: outside.inputPath, workspaceRoot: root }))
      .toThrow(expect.objectContaining({ code: 'OPENAPI_REF_OUTSIDE_ROOT' }));
    expect(() => loadOpenApiDocument({
      inputPath: path.join(fixtureRoot, 'malicious/symlink-escape.yaml'),
      workspaceRoot: fixtureRoot,
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_REF_OUTSIDE_ROOT' }));
    expect(() => loadOpenApiDocument({
      inputPath: 'https://example.test/openapi.yaml',
      workspaceRoot: fixtureRoot,
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_REMOTE_REF_DISABLED' }));
  });

  test('rechecks workspace confinement after opening the descriptor', () => {
    const fixture = temporaryFile('inside.yaml', 'openapi: 3.1.0\npaths: {}\n');
    const outside = temporaryFile('outside.yaml', 'openapi: 3.1.0\npaths: {}\n');
    const realpathSync = fs.realpathSync.bind(fs);
    let calls = 0;
    vi.spyOn(fs, 'realpathSync').mockImplementation((inputPath) => {
      calls += 1;
      return calls === 5 ? outside.inputPath : realpathSync(inputPath);
    });

    expect(() => loadOpenApiDocument({
      inputPath: fixture.inputPath,
      workspaceRoot: fixture.root,
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_REF_OUTSIDE_ROOT' }));
  });

  test('never includes source content or example secrets in parse errors', () => {
    const fixture = temporaryFile(
      'secret.yaml',
      'openapi: 3.1.0\npaths: [\nAuthorization: Bearer parse-error-secret\n',
    );
    let error: unknown;
    try {
      loadOpenApiDocument({ inputPath: fixture.inputPath, workspaceRoot: fixture.root });
    } catch (caught) {
      error = caught;
    }
    const serialized = JSON.stringify(error);
    expect(serialized).toContain('OPENAPI_PARSE_ERROR');
    expect(serialized).not.toContain('parse-error-secret');
    expect(serialized).not.toContain('Authorization');
    expect(serialized).not.toContain('stack');
    expect(JSON.parse(serialized)).toEqual(expect.objectContaining({
      code: 'OPENAPI_PARSE_ERROR',
      line: expect.any(Number),
      column: expect.any(Number),
    }));
  });
});
