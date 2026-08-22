import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';

import {
  DEFAULT_OPENAPI_ANALYSIS_LIMITS,
  OPENAPI_ANALYSIS_LIMIT_RANGES,
  validateOpenApiAnalysisLimits,
} from '../../src/openapi/analysis-limits';
import { OpenApiAnalysisError } from '../../src/openapi/analysis-error';
import {
  isPathWithinWorkspace,
  resolveOpenApiRefPath,
} from '../../src/openapi/ref-boundary';

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe('OpenAPI analysis limits', () => {
  test('accepts defaults and every documented minimum/maximum boundary', () => {
    expect(validateOpenApiAnalysisLimits(DEFAULT_OPENAPI_ANALYSIS_LIMITS))
      .toEqual(DEFAULT_OPENAPI_ANALYSIS_LIMITS);

    for (const [name, range] of Object.entries(OPENAPI_ANALYSIS_LIMIT_RANGES)) {
      expect(validateOpenApiAnalysisLimits({
        ...DEFAULT_OPENAPI_ANALYSIS_LIMITS,
        [name]: range.min,
      })).toMatchObject({ [name]: range.min });
      expect(validateOpenApiAnalysisLimits({
        ...DEFAULT_OPENAPI_ANALYSIS_LIMITS,
        [name]: range.max,
      })).toMatchObject({ [name]: range.max });
    }

    expect(
      DEFAULT_OPENAPI_ANALYSIS_LIMITS.maxDocumentBytes
      * DEFAULT_OPENAPI_ANALYSIS_LIMITS.maxResolvedDocuments,
    ).toBe(DEFAULT_OPENAPI_ANALYSIS_LIMITS.maxGraphBytes);
    expect(
      DEFAULT_OPENAPI_ANALYSIS_LIMITS.maxOperations
      * DEFAULT_OPENAPI_ANALYSIS_LIMITS.maxParametersPerOperation,
    ).toBe(200_000);
  });

  test.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '100']) (
    'rejects invalid integer limit %p with a stable code',
    (invalid) => {
      expect(() => validateOpenApiAnalysisLimits({
        ...DEFAULT_OPENAPI_ANALYSIS_LIMITS,
        maxDocumentBytes: invalid,
      })).toThrow(expect.objectContaining({ code: 'OPENAPI_INVALID_LIMITS' }));
    },
  );

  test('rejects values over the hard maximum and unknown limit names', () => {
    expect(() => validateOpenApiAnalysisLimits({
      ...DEFAULT_OPENAPI_ANALYSIS_LIMITS,
      maxOperations: OPENAPI_ANALYSIS_LIMIT_RANGES.maxOperations.max + 1,
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_INVALID_LIMITS' }));

    expect(() => validateOpenApiAnalysisLimits({
      ...DEFAULT_OPENAPI_ANALYSIS_LIMITS,
      unexpectedLimit: 1,
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_INVALID_LIMITS' }));
  });
});

describe('OpenAPI ref boundary', () => {
  test('compares POSIX and Windows paths without prefix confusion', () => {
    expect(isPathWithinWorkspace('/repo', '/repo/specs/openapi.yaml', 'posix')).toBe(true);
    expect(isPathWithinWorkspace('/repo', '/repository/openapi.yaml', 'posix')).toBe(false);
    expect(isPathWithinWorkspace('C:\\Repo', 'c:\\repo\\specs\\openapi.yaml', 'win32')).toBe(true);
    expect(isPathWithinWorkspace('C:\\Repo', 'D:\\Repo\\openapi.yaml', 'win32')).toBe(false);
  });

  test('allows an existing local ref and rejects traversal, absolute, and remote refs', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-boundary-'));
    temporaryDirectories.push(root);
    const source = path.join(root, 'specs', 'openapi.yaml');
    const shared = path.join(root, 'shared', 'schema.yaml');
    fs.mkdirSync(path.dirname(source), { recursive: true });
    fs.mkdirSync(path.dirname(shared), { recursive: true });
    fs.writeFileSync(source, 'openapi: 3.1.0\n');
    fs.writeFileSync(shared, 'type: object\n');

    expect(resolveOpenApiRefPath({
      workspaceRoot: root,
      sourcePath: source,
      ref: '../shared/schema.yaml#/User',
    })).toBe(fs.realpathSync(shared));
    expect(resolveOpenApiRefPath({
      workspaceRoot: root,
      sourcePath: source,
      ref: '#/components/schemas/User',
    })).toBe(fs.realpathSync(source));

    for (const ref of ['../../../outside.yaml', '/etc/passwd']) {
      expect(() => resolveOpenApiRefPath({ workspaceRoot: root, sourcePath: source, ref }))
        .toThrow(expect.objectContaining({ code: 'OPENAPI_REF_OUTSIDE_ROOT' }));
    }
    for (const ref of [
      'https://example.test/openapi.yaml',
      'http://example.test/openapi.yaml',
      'ftp://example.test/openapi.yaml',
    ]) {
      expect(() => resolveOpenApiRefPath({ workspaceRoot: root, sourcePath: source, ref }))
        .toThrow(expect.objectContaining({ code: 'OPENAPI_REMOTE_REF_DISABLED' }));
    }
    expect(() => resolveOpenApiRefPath({
      workspaceRoot: root,
      sourcePath: source,
      ref: 'file:///etc/passwd',
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_REF_OUTSIDE_ROOT' }));
  });

  test('rejects a symlink that resolves outside the workspace', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-root-'));
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'openapi-outside-'));
    temporaryDirectories.push(root, outside);
    const source = path.join(root, 'openapi.yaml');
    const outsideSchema = path.join(outside, 'schema.yaml');
    fs.writeFileSync(source, 'openapi: 3.1.0\n');
    fs.writeFileSync(outsideSchema, 'type: string\n');
    fs.symlinkSync(outside, path.join(root, 'linked'));

    expect(() => resolveOpenApiRefPath({
      workspaceRoot: root,
      sourcePath: source,
      ref: './linked/schema.yaml',
    })).toThrow(expect.objectContaining({ code: 'OPENAPI_REF_OUTSIDE_ROOT' }));
  });
});

describe('OpenAPI analysis errors', () => {
  test('serializes only stable safe fields', () => {
    const error = new OpenApiAnalysisError('OPENAPI_DOCUMENT_TOO_LARGE', {
      sourceUri: '/private/workspace/openapi.yaml?token=input-secret',
      pointer: '/paths/~1users',
    });
    const serialized = JSON.stringify(error);

    expect(JSON.parse(serialized)).toEqual({
      code: 'OPENAPI_DOCUMENT_TOO_LARGE',
      safeMessage: 'OpenAPI document exceeds the configured size limit.',
      sourceUri: 'openapi.yaml',
      pointer: '/paths/~1users',
    });
    expect(serialized).not.toContain('input-secret');
    expect(serialized).not.toContain('/private/workspace');
    expect(serialized).not.toContain('stack');

    const hostile = JSON.stringify(new OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND', {
      sourceUri: 'https://user:password@example.test',
      pointer: '/paths/~1callback?token=pointer-secret',
    }));
    expect(hostile).not.toContain('user');
    expect(hostile).not.toContain('password@example');
    expect(hostile).not.toContain('pointer-secret');
    expect(JSON.parse(hostile).pointer).toBe('/paths/~1callback');

    const secretPointer = JSON.stringify(new OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND', {
      pointer: '/components/password=property-secret/schema',
    }));
    expect(secretPointer).not.toContain('property-secret');

    for (const pointer of [
      '/paths?public\nquery-secret',
      '/components/to\u0000ken=credential/schema',
    ]) {
      const controlSeparated = JSON.stringify(new OpenApiAnalysisError(
        'OPENAPI_INPUT_NOT_FOUND',
        { pointer },
      ));
      expect(controlSeparated).not.toContain('query-secret');
      expect(controlSeparated).not.toContain('credential');
    }
  });
});
