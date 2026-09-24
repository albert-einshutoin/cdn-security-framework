import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, test, vi } from 'vitest';

import {
  compareSecurityContracts, compareSourceOpenApiContracts, compareSourcePolicyContracts,
  createSecurityContract, projectPolicyToAllowedSurface,
} from '../../src/contract';
import { composeSourceAwareComparisons } from '../../src/contract/source-aware-internal';
import { inspectOpenApi } from '../../src/openapi';
import { DEFAULT_SOURCE_ANALYSIS_LIMITS, runSourceAnalyzer, type SourceAnalysisExecution } from '../../src/source-analysis';
import { nestJsSourceAnalyzer } from '../../src/source/nestjs';

let root: string;
let openapiPath: string;
let inspection: ReturnType<typeof inspectOpenApi>;
const evidenceDigest = `sha256:${'a'.repeat(64)}`;
const declaredEvidence = {
  source: 'openapi' as const, uri: 'openapi.yaml', digest: evidenceDigest,
  analyzer: 'openapi@1', capability: 'openapi-operations-v1', complete: true,
};
const implementedEvidence = {
  source: 'source-ast' as const, uri: 'tsconfig.json', digest: evidenceDigest,
  analyzer: 'nestjs@1', capability: 'nestjs-routes-v1', complete: false,
};
const allowed = projectPolicyToAllowedSurface({
  version: 2, defaults: { mode: 'enforce' },
  request: { allow_methods: ['GET'], block: { header_missing: [] } },
  routes: [], response_headers: {},
}, { policyDigest: evidenceDigest, sourceUri: 'policy/security.yml' });
const request = {
  contentTypes: [], requiredHeaders: [], queryParameters: [], pathParameters: [],
  headerParameters: [], cookieParameters: [],
};

function syntheticSource(routes: 'complete' | 'partial' = 'complete'): SourceAnalysisExecution {
  const contract = createSecurityContract({
    source: 'source-ast',
    capabilities: routes === 'complete'
      ? { routes, parameters: 'complete', requestBodies: 'complete', authentication: 'complete' }
      : { routes, parameters: 'unsupported', requestBodies: 'unsupported', authentication: 'partial' },
    operations: [{
      method: 'POST', path: '/private', exposure: 'unknown',
      auth: { mode: 'unknown', alternatives: [] }, request,
      provenance: [{ ...implementedEvidence, uri: 'src/controller.ts', complete: routes === 'complete' }],
    }],
  });
  return {
    status: 'success', result: {
      contract, diagnostics: [], unresolvedOperations: [],
      metrics: { files: 1, totalSourceBytes: 1, largestFileBytes: 1, astNodes: 1, diagnostics: 0, operations: 1, maxDepth: 1 },
    },
  };
}

function input(source?: SourceAnalysisExecution) {
  return { declared: inspection, allowed, target: 'aws' as const, declaredEvidence, source, implementedEvidence };
}

function digest(file: string) {
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-source-aware-internal-'));
  openapiPath = path.join(root, 'openapi.yaml');
  fs.writeFileSync(openapiPath, `openapi: 3.0.3
info: {title: Synthetic API, version: 1.0.0}
paths:
  /users:
    get:
      responses:
        '200': {description: OK}
`);
  inspection = inspectOpenApi({ inputPath: openapiPath, workspaceRoot: root });
});

afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

describe('internal Source-aware stage bridge', () => {
  test('reuses all three existing comparisons with stable evidence and input identity', () => {
    const before = digest(openapiPath);
    const source = syntheticSource();
    const result = composeSourceAwareComparisons(input(source));
    if (source.status !== 'success') throw new Error('synthetic Source execution must succeed');
    expect(result.stages.implemented.status).toBe('complete');
    expect(result.stages.allowed.status).toBe('complete');
    expect(result.stages.allowed.targetCapabilities.some(({ status }) => status !== 'supported')).toBe(true);
    expect(result.comparisons.declaredAllowed.findings).toBeDefined();
    expect(result.comparisons.implementedDeclared.findings?.map((finding) => finding.ruleId))
      .toContain('SC-INVENTORY-001');
    expect(result.comparisons.implementedAllowed.findings?.map((finding) => finding.ruleId))
      .toContain('SC-EXPOSURE-004');
    expect(result.comparisons.implementedDeclared.findings?.[0]?.evidence.map(({ source }) => source))
      .toContain('source-ast');
    expect(result.comparisons.declaredAllowed.findings).toEqual(compareSecurityContracts({
      declared: inspection.contract, allowed, target: 'aws',
    }));
    expect(result.comparisons.implementedDeclared.findings).toEqual(compareSourceOpenApiContracts({
      declared: inspection.contract, implemented: source.result.contract,
      declaredEvidence, implementedEvidence,
    }));
    expect(result.comparisons.implementedAllowed.findings).toEqual(compareSourcePolicyContracts({
      implemented: source.result.contract, implementedEvidence, allowed, target: 'aws',
    }));
    expect(composeSourceAwareComparisons(input(syntheticSource()))).toEqual(result);
    expect(digest(openapiPath)).toBe(before);
  });

  test('distinguishes Source omission and failure from evaluated zero Findings', () => {
    const omitted = composeSourceAwareComparisons(input());
    expect(omitted.stages.implemented).toMatchObject({ status: 'omitted', code: 'SOURCE_NOT_REQUESTED' });
    expect(omitted.comparisons.implementedDeclared).toEqual({ status: 'omitted', code: 'SOURCE_NOT_REQUESTED' });
    expect(omitted.comparisons.implementedAllowed).toEqual({ status: 'omitted', code: 'SOURCE_NOT_REQUESTED' });
    expect(omitted.comparisons.declaredAllowed.findings).toBeDefined();

    const failed = composeSourceAwareComparisons(input({
      status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_FILE_LIMIT', safeMessage: 'Source limit exceeded.' }],
    }));
    expect(failed.stages.implemented).toMatchObject({ status: 'failed', code: 'SOURCE_ANALYZER_FILE_LIMIT' });
    expect(failed.comparisons.implementedDeclared).toEqual({ status: 'failed', code: 'SOURCE_ANALYZER_FILE_LIMIT' });
    expect(failed.comparisons.implementedAllowed).toEqual({ status: 'failed', code: 'SOURCE_ANALYZER_FILE_LIMIT' });
    expect(failed.comparisons.declaredAllowed.findings).toBeDefined();
    expect(JSON.stringify(failed)).not.toContain('Source limit exceeded.');
  });

  test('reports a failed comparator without a zero-Finding success result', () => {
    const invalidAllowed = { ...allowed, schemaVersion: 2 as 1 };
    const result = composeSourceAwareComparisons({ ...input(syntheticSource()), allowed: invalidAllowed });
    expect(result.comparisons.declaredAllowed).toEqual({ status: 'failed', code: 'COMPARISON_FAILED' });
    expect(result.comparisons.implementedAllowed).toEqual({ status: 'failed', code: 'COMPARISON_FAILED' });
    expect(result.comparisons.implementedDeclared.findings).toBeDefined();
  });

  test('retains partial Source status and its bounded findings', () => {
    const result = composeSourceAwareComparisons(input(syntheticSource('partial')));
    expect(result.stages.implemented.status).toBe('partial');
    expect(result.comparisons.implementedDeclared.status).toBe('partial');
    expect(result.comparisons.implementedAllowed.status).toBe('partial');
    expect(result.comparisons.implementedDeclared.findings?.length).toBeGreaterThan(0);
  });

  test('composes real static NestJS analysis and propagates a real resource limit without executing Source', async () => {
    const fixture = path.join(process.cwd(), 'test/fixtures/source-analysis/nestjs-basic');
    const sourceRoot = path.join(root, 'source');
    fs.cpSync(fixture, sourceRoot, { recursive: true });
    const nestModule = path.join(sourceRoot, 'node_modules/@nestjs/common');
    fs.mkdirSync(nestModule, { recursive: true });
    fs.writeFileSync(path.join(nestModule, 'package.json'), JSON.stringify({ name: '@nestjs/common', version: '1.0.0', main: 'index.js', types: 'index.d.ts' }));
    fs.writeFileSync(path.join(nestModule, 'index.js'), 'module.exports = {};\n');
    fs.writeFileSync(path.join(nestModule, 'index.d.ts'), `
      export declare function Controller(path?: string): ClassDecorator;
      export declare function Get(path?: string): MethodDecorator;
      export declare function Post(path?: string): MethodDecorator;
      export declare function Head(path?: string): MethodDecorator;
    `);
    const sourceFile = path.join(sourceRoot, 'src/controller.ts');
    fs.appendFileSync(sourceFile, "\nthrow new Error('Source must not execute');\n");
    const before = [digest(openapiPath), digest(sourceFile)];
    const context = {
      workspaceRoot: sourceRoot, entrypoints: ['tsconfig.json'],
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS }, logger: { log() {} },
    };
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => { throw new Error('network forbidden'); });
    try {
      const execution = await runSourceAnalyzer(nestJsSourceAnalyzer, context);
      expect(execution.status).toBe('success');
      const realInput = {
        ...input(execution),
        declaredEvidence: { ...declaredEvidence, digest: `sha256:${before[0]}` },
        implementedEvidence: { ...implementedEvidence, uri: 'src/controller.ts', digest: `sha256:${before[1]}` },
      };
      const result = composeSourceAwareComparisons(realInput);
      expect(result.stages.implemented.status).toBe('partial');
      expect(result.comparisons.implementedDeclared.findings).toBeDefined();
      const limit = await runSourceAnalyzer(nestJsSourceAnalyzer, {
        ...context, entrypoints: ['tsconfig.json', 'src/controller.ts'],
        limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxFiles: 1 },
      });
      expect(limit).toMatchObject({ status: 'failed', diagnostics: [{ code: 'SOURCE_ANALYZER_FILE_LIMIT' }] });
      expect(composeSourceAwareComparisons({ ...realInput, source: limit }).comparisons.implementedDeclared)
        .toEqual({ status: 'failed', code: 'SOURCE_ANALYZER_FILE_LIMIT' });
      expect(fetchSpy).not.toHaveBeenCalled();
      expect([digest(openapiPath), digest(sourceFile)]).toEqual(before);
    } finally {
      fetchSpy.mockRestore();
    }
  });
});
