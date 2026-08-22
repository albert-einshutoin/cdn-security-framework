import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';

import {
  relateHosts,
  relateMethods,
  relatePath,
  relateRoute,
  type OpenApiPath,
  type PolicyPathMatcher,
} from '../../src/contract';

const normalized = {
  phase: 'normalized-path' as const,
  collapseSlashes: true,
  removeDotSegments: true,
};

describe('route relation', () => {
  test('proves exact and segment-boundary prefix relations without decoding paths', () => {
    const exact = (value: string): OpenApiPath => ({ kind: 'exact', value });
    const prefix = (value: string): PolicyPathMatcher => ({ kind: 'prefix', value });

    expect(relatePath(exact('/admin'), prefix('/admin'), normalized)).toBe('definitely-covered');
    expect(relatePath(exact('/admin/users'), prefix('/admin'), normalized)).toBe('definitely-covered');
    expect(relatePath(exact('/administrator'), prefix('/admin'), normalized)).toBe('definitely-disjoint');
    expect(relatePath(exact('/admin/child'), prefix('/admin/'), normalized)).toBe('definitely-disjoint');
    expect(relatePath(exact('/'), prefix('/'), normalized)).toBe('definitely-covered');
    expect(relatePath(exact('/child'), prefix('/'), normalized)).toBe('definitely-disjoint');
    expect(relatePath(exact('/a//b'), { kind: 'exact', value: '/a/b' }, normalized))
      .toBe('definitely-covered');
    expect(relatePath(exact('/a/b'), { kind: 'prefix', value: '/a//b' }, normalized))
      .toBe('definitely-disjoint');
    expect(relatePath(exact('/a/./b'), { kind: 'exact', value: '/a/b' }, normalized))
      .toBe('definitely-covered');
    expect(relatePath(exact('/b'), { kind: 'prefix', value: '/a/../b' }, normalized))
      .toBe('definitely-disjoint');
    expect(relatePath(exact('/../b'), { kind: 'prefix', value: '/b' }, normalized))
      .toBe('unknown');
    expect(relatePath(exact('/a/%2F/b'), prefix('/a'), normalized)).toBe('unknown');
    expect(relatePath(exact('/a/%2e/b'), prefix('/a'), normalized)).toBe('unknown');
    expect(relatePath(exact('/a/%252F/b'), prefix('/a'), normalized)).toBe('definitely-covered');
  });

  test('treats an OpenAPI parameter as exactly one non-empty segment', () => {
    const template: OpenApiPath = { kind: 'template', value: '/users/{id}' };
    expect(relatePath(template, { kind: 'exact', value: '/users/42' }, normalized))
      .toBe('possibly-overlapping');
    expect(relatePath(template, { kind: 'exact', value: '/users/42/profile' }, normalized))
      .toBe('definitely-disjoint');
    expect(relatePath(template, { kind: 'prefix', value: '/users' }, normalized))
      .toBe('possibly-overlapping');
    expect(relatePath(template, { kind: 'prefix', value: '/users/admin' }, normalized))
      .toBe('possibly-overlapping');
    expect(relatePath(template, { kind: 'prefix', value: '/admins' }, normalized))
      .toBe('definitely-disjoint');
    expect(relatePath(template, { kind: 'exact', value: '/users' }, normalized))
      .toBe('possibly-overlapping');
    expect(relatePath(
      { kind: 'template', value: '/{group}/{id}' },
      { kind: 'prefix', value: '/users' },
      normalized,
    )).toBe('unknown');
  });

  test('only proves the deliberately small literal regex subset', () => {
    expect(relatePath(
      { kind: 'exact', value: '/health' },
      { kind: 'pattern', syntax: 'regex', value: '^/health$' },
      normalized,
    )).toBe('definitely-covered');
    expect(relatePath(
      { kind: 'exact', value: '/users/42' },
      { kind: 'pattern', syntax: 'regex', value: '^/users/.+$' },
      normalized,
    )).toBe('unknown');
  });

  test('combines method and host products conservatively', () => {
    expect(relateMethods(['GET'], ['GET', 'POST'])).toBe('definitely-covered');
    expect(relateMethods(['GET', 'POST'], ['GET'])).toBe('possibly-overlapping');
    expect(relateMethods(['GET'], ['POST'])).toBe('definitely-disjoint');
    expect(relateHosts(
      { kind: 'allowlist', values: ['api.example.com'] },
      { kind: 'allowlist', values: ['*.example.com'] },
    )).toBe('definitely-covered');
    expect(relateHosts(
      { kind: 'allowlist', values: ['*.example.com'] },
      { kind: 'allowlist', values: ['api.example.com'] },
    )).toBe('possibly-overlapping');
    expect(relateHosts(
      { kind: 'allowlist', values: ['api.example.com'] },
      { kind: 'allowlist', values: ['api.other.test'] },
    )).toBe('definitely-disjoint');
    expect(relateHosts(
      { kind: 'allowlist', values: ['.example.com'] },
      { kind: 'allowlist', values: ['*.example.com'] },
    )).toBe('definitely-disjoint');
    expect(relateHosts(
      { kind: 'allowlist', values: ['api.example.com'] },
      { kind: 'allowlist', values: ['api.example.com:443'] },
    )).toBe('definitely-disjoint');
    expect(relateHosts(
      { kind: 'allowlist', values: ['api.example.com:443'] },
      { kind: 'allowlist', values: ['api.example.com'] },
    )).toBe('definitely-covered');
    expect(relateMethods(Array(257).fill('GET'), ['GET'])).toBe('unknown');
    expect(relateHosts(
      { kind: 'allowlist', values: Array(257).fill('api.example.com') },
      { kind: 'any' },
    )).toBe('unknown');

    const result = relateRoute(
      {
        path: { kind: 'exact', value: '/admin' },
        methods: ['GET'],
        hosts: { kind: 'unknown' },
      },
      {
        path: { kind: 'prefix', value: '/admin' },
        methods: ['POST'],
        hosts: { kind: 'unknown' },
      },
      normalized,
    );
    expect(result).toMatchObject({
      relation: 'definitely-disjoint',
      path: 'definitely-covered',
      method: 'definitely-disjoint',
      host: 'unknown',
      isProvenDisjoint: true,
    });
  });

  test('keeps exact relation symmetry across generated samples', () => {
    const paths = ['/', '/admin', '/administrator', '/users/1', '/users/2/'];
    for (const left of paths) {
      for (const right of paths) {
        const forward = relatePath(
          { kind: 'exact', value: left }, { kind: 'exact', value: right }, normalized,
        );
        const reverse = relatePath(
          { kind: 'exact', value: right }, { kind: 'exact', value: left }, normalized,
        );
        expect(forward).toBe(reverse);
      }
    }
  });

  test('keeps directional template-prefix proofs sound across generated samples', () => {
    const paths = ['/users/a', '/users/admin', '/users/child', '/users', '/'];
    for (const prefix of ['/', '/users', '/users/a', '/admin']) {
      const relation = relatePath(
        { kind: 'template', value: '/users/{id}' },
        { kind: 'prefix', value: prefix },
        normalized,
      );
      const outcomes = paths.map((concrete) => {
        return concrete === prefix || concrete.startsWith(`${prefix}/`);
      });
      if (relation === 'definitely-covered') expect(outcomes.every(Boolean)).toBe(true);
      if (relation === 'definitely-disjoint') expect(outcomes.some(Boolean)).toBe(false);
      if (relation === 'possibly-overlapping') {
        expect(outcomes.some(Boolean)).toBe(true);
        expect(outcomes.every(Boolean)).toBe(false);
      }
    }
  });

  test('matches the compiled runtime segment-boundary sample', () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'route-relation-runtime-'));
    try {
      const { build } = require('../../scripts/lib/compile-core') as {
        build: (policy: unknown, options: Record<string, unknown>) => string[];
      };
      build({
        version: 1,
        defaults: { mode: 'enforce' },
        request: {
          allow_methods: ['GET'],
          block: { path_patterns: { contains: ['/never-match'] } },
          normalize: { path: { collapse_slashes: true, remove_dot_segments: true } },
        },
        routes: [],
        response_headers: { admin: { path_prefixes: ['/admin'] } },
      }, { rootDir: process.cwd(), outDir, env: {}, allowPlaceholderToken: false });
      const code = fs.readFileSync(path.join(outDir, 'edge', 'viewer-response.js'), 'utf8');
      const handler = Function(`${code}\nreturn handler;`)();
      const selected = (uri: string) => handler({
        request: { uri }, response: { statusCode: 200, headers: {} },
      }).headers['cache-control']?.value === 'no-store';

      for (const [uri, expected] of [['/admin', true], ['/admin/users', true], ['/administrator', false]] as const) {
        expect(selected(uri)).toBe(expected);
        expect(relatePath(
          { kind: 'exact', value: uri }, { kind: 'prefix', value: '/admin' }, normalized,
        )).toBe(expected ? 'definitely-covered' : 'definitely-disjoint');
      }
    } finally {
      fs.rmSync(outDir, { recursive: true, force: true });
    }
  });
});
