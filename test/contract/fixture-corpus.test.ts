import fs from 'node:fs';
import path from 'node:path';
import * as yaml from 'js-yaml';
import { describe, expect, test } from 'vitest';

import { OPENAPI_ANALYSIS_LIMIT_RANGES } from '../../src/openapi/analysis-limits';
import { canonicalJson } from '../helpers/canonical-json';
import { assertGolden } from '../helpers/golden-assert';
import { fixtureRoot, fixtureUri, resolveFixturePath } from '../helpers/fixture-root';

type Category = 'valid' | 'refs' | 'limits' | 'invalid' | 'malicious';
type Expected = 'parse-ok' | 'parse-error' | 'semantic-invalid' | 'reject-ref' | 'generated' | 'root-reject' | 'sensitive';

interface ManifestEntry {
  file: string;
  category: Category;
  expected: Expected;
  purpose: string;
  relatedIssue: number;
}

const manifest = JSON.parse(fs.readFileSync(
  path.join(fixtureRoot, 'fixture-manifest.json'),
  'utf8',
)) as { fixtures: ManifestEntry[] };
const categories: Category[] = ['valid', 'refs', 'limits', 'invalid', 'malicious'];
const expectations: Expected[] = [
  'parse-ok', 'parse-error', 'semantic-invalid', 'reject-ref', 'generated', 'root-reject', 'sensitive',
];

function corpusFiles(): string[] {
  const files: string[] = [];
  for (const category of categories) {
    const root = path.join(fixtureRoot, category);
    const visit = (directory: string) => {
      for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        const absolute = path.join(directory, entry.name);
        if (entry.isDirectory()) visit(absolute);
        else files.push(fixtureUri(absolute));
      }
    };
    visit(root);
  }
  return files.sort();
}

function parseFixture(file: string): unknown {
  const raw = fs.readFileSync(resolveFixturePath(file), 'utf8');
  return file.endsWith('.json') ? JSON.parse(raw) : yaml.load(raw);
}

function generateBoundaryFixture(descriptor: Record<string, unknown>): string {
  const count = Number(descriptor.count ?? descriptor.depth);
  switch (descriptor.generator) {
    case 'operations':
      return JSON.stringify({
        openapi: '3.1.0',
        paths: Object.fromEntries(Array.from({ length: count }, (_, index) => [
          `/generated/${index}`,
          { get: { responses: { 200: { description: 'OK' } } } },
        ])),
      });
    case 'parameters':
      return JSON.stringify({
        openapi: '3.1.0',
        paths: { '/generated': { get: { parameters: Array.from({ length: count }, (_, index) => ({
          name: `p${index}`, in: 'query', schema: { type: 'string' },
        })) } } },
      });
    case 'schema-depth': {
      const root: Record<string, unknown> = { type: 'object' };
      let cursor = root;
      for (let depth = 0; depth < count; depth += 1) {
        const child: Record<string, unknown> = { type: 'object' };
        cursor.properties = { child };
        cursor = child;
      }
      return JSON.stringify({
        openapi: '3.1.0',
        info: { title: 'Generated schema-depth boundary', version: '1.0.0' },
        paths: {},
        components: { schemas: { Root: root } },
      });
    }
    case 'yaml-aliases':
      return `base: &base { type: string }\naliases:\n${'  - *base\n'.repeat(count)}`;
    case 'ref-cycle':
      return JSON.stringify({ components: { schemas: Object.fromEntries(
        Array.from({ length: count }, (_, index) => [
          `Node${index}`,
          { $ref: `#/components/schemas/Node${(index + 1) % count}` },
        ]),
      ) } });
    case 'document-bytes':
      return 'x'.repeat(count);
    default:
      throw new Error('unknown fixture generator');
  }
}

describe('OpenAPI fixture corpus', () => {
  test('keeps every fixture registered exactly once in the manifest', () => {
    const registered = manifest.fixtures.map(({ file }) => file).sort();
    expect(new Set(registered).size).toBe(registered.length);
    expect(registered).toEqual(corpusFiles());
    for (const entry of manifest.fixtures) {
      expect(entry.file.startsWith(`${entry.category}/`)).toBe(true);
      expect(categories).toContain(entry.category);
      expect(expectations).toContain(entry.expected);
      expect(entry.purpose.length).toBeGreaterThan(10);
      expect(entry.relatedIssue).toBe(274);
      const stat = fs.lstatSync(path.join(fixtureRoot, entry.file));
      expect(stat.isFile() || stat.isSymbolicLink()).toBe(true);
      if (stat.isSymbolicLink()) expect(entry.expected).toBe('root-reject');
      else expect(stat.size).toBeLessThan(65_536);
    }
  });

  test('parses or rejects each fixture according to its pre-analyzer expectation', () => {
    for (const entry of manifest.fixtures) {
      if (entry.expected === 'parse-error') {
        expect(() => parseFixture(entry.file), entry.file).toThrow();
        continue;
      }
      if (entry.expected === 'root-reject') {
        expect(() => resolveFixturePath(entry.file), entry.file).toThrow('outside fixture root');
        continue;
      }
      const document = parseFixture(entry.file) as Record<string, unknown>;
      if (entry.expected === 'semantic-invalid') {
        expect(['3.0', '3.1'].some((version) => String(document?.openapi).startsWith(version)), entry.file)
          .toBe(false);
      } else if (entry.expected === 'generated') {
        expect(document).toMatchObject({ generated: true });
        expect(Number(document.count ?? document.depth)).toBeGreaterThan(0);
        expect(generateBoundaryFixture(document).length).toBeGreaterThan(0);
      } else if (entry.expected === 'sensitive') {
        expect(() => assertGolden('sensitive-fixture', document), entry.file)
          .toThrow('golden contains secret-like value');
      } else {
        expect(document).toBeTypeOf('object');
      }
    }
  });

  test('generates limit fixtures one step beyond the configured hard boundary', () => {
    const descriptors = Object.fromEntries(manifest.fixtures.filter(({ expected }) => expected === 'generated')
      .map((entry) => [entry.file, parseFixture(entry.file) as Record<string, unknown>]));
    expect(descriptors['limits/too-many-operations.fixture.json'].count)
      .toBe(OPENAPI_ANALYSIS_LIMIT_RANGES.maxOperations.max + 1);
    expect(descriptors['limits/too-many-parameters.fixture.json'].count)
      .toBe(OPENAPI_ANALYSIS_LIMIT_RANGES.maxParametersPerOperation.max + 1);
    expect(descriptors['limits/excessive-schema-depth.fixture.json'].depth)
      .toBe(OPENAPI_ANALYSIS_LIMIT_RANGES.maxSchemaDepth.max + 1);
    expect(JSON.parse(generateBoundaryFixture(
      descriptors['limits/excessive-schema-depth.fixture.json'],
    ))).toMatchObject({ openapi: '3.1.0', paths: {}, components: { schemas: { Root: {} } } });
    expect(descriptors['limits/alias-expansion.fixture.json'].count)
      .toBe(OPENAPI_ANALYSIS_LIMIT_RANGES.maxYamlAliases.max + 1);
    expect(descriptors['malicious/cycle-bomb.fixture.json'].count)
      .toBe(OPENAPI_ANALYSIS_LIMIT_RANGES.maxRefDepth.max + 1);
    expect(descriptors['malicious/large-document.fixture.json'].count)
      .toBe(OPENAPI_ANALYSIS_LIMIT_RANGES.maxDocumentBytes.max + 1);
  });

  test('canonicalizes keys and newlines, rejects cycles, and never rewrites golden files by default', () => {
    expect(canonicalJson({ z: 'a\r\nb', a: { y: 2, x: 1 } })).toBe(
      '{\n  "a": {\n    "x": 1,\n    "y": 2\n  },\n  "z": "a\\nb"\n}\n',
    );
    expect(canonicalJson({ tags: ['write', 'read', 'write'] }, { setKeys: ['tags'] }))
      .toContain('"tags": [\n    "read",\n    "write"\n  ]');
    expect(fixtureUri(path.join(fixtureRoot, 'valid', 'openapi-3.0.yaml')))
      .toBe('valid/openapi-3.0.yaml');
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalJson(cyclic)).toThrow('circular value');
    const deep: Record<string, unknown> = {};
    let cursor = deep;
    for (let depth = 0; depth < 257; depth += 1) {
      cursor.child = {};
      cursor = cursor.child as Record<string, unknown>;
    }
    expect(() => canonicalJson(deep)).toThrow('depth limit');

    const golden = resolveFixturePath('expected/canonical-basic.json');
    const before = fs.readFileSync(golden, 'utf8');
    const previousUpdateMode = process.env.UPDATE_GOLDEN;
    process.env.UPDATE_GOLDEN = '0';
    try {
      expect(() => assertGolden('canonical-basic', { b: ['x', 'y'], a: 1 })).not.toThrow();
      expect(() => assertGolden('canonical-basic', { wrong: true })).toThrow('golden mismatch');
      expect(fs.readFileSync(golden, 'utf8')).toBe(before);
      expect(() => assertGolden('../escape', {})).toThrow('invalid golden name');
      expect(() => assertGolden('secret', { client_secret: 'must-not-write' }))
        .toThrow('golden contains secret-like value');
      expect(() => assertGolden('nested-secret', { token: ['must-not-write'] }))
        .toThrow('golden contains secret-like value');
      const sparse = new Array(1_000_001);
      expect(() => canonicalJson(sparse)).toThrow('node limit');
    } finally {
      if (previousUpdateMode === undefined) delete process.env.UPDATE_GOLDEN;
      else process.env.UPDATE_GOLDEN = previousUpdateMode;
    }
  });

  test('rejects traversal, absolute, URI, and symlink escapes from the fixture root', () => {
    for (const unsafe of ['../README.md', '/etc/passwd', 'file:///etc/passwd', 'https://example.test/spec.yaml']) {
      expect(() => resolveFixturePath(unsafe), unsafe).toThrow();
    }
    expect(() => resolveFixturePath('malicious/symlink-escape.yaml')).toThrow('outside fixture root');
  });

  test('documents secret redaction without snapshotting the secret-bearing fixture', () => {
    const secretEntry = manifest.fixtures.find(({ file }) => file === 'malicious/secret-values.yaml');
    expect(secretEntry).toMatchObject({ expected: 'sensitive' });
    expect(fs.readFileSync(resolveFixturePath('README.md'), 'utf8'))
      .toContain('secret-like description/example');
  });
});
