#!/usr/bin/env node
'use strict';

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

import ts from 'typescript';

import {
  compareSourceOpenApiContracts,
  compareSourcePolicyContracts,
  createSecurityContract,
  projectPolicyToAllowedSurface,
  type ApiOperationInputV1,
} from '../contract';
import {
  DEFAULT_SOURCE_ANALYSIS_LIMITS,
  runSourceAnalyzer,
  type SourceAnalysisResult,
} from '../source-analysis';
import { createNestJsSourceAnalyzer } from '../source/nestjs';
import { loadTypeScriptProject, TypeScriptAnalysisCache } from '../source/typescript/project-loader';
import type { CDNSecurityFrameworkPolicy } from '../types/policy';

export interface SourceAnalysisBenchmarkOptions {
  controllers?: number;
  iterations?: number;
  profile?: 'full' | 'ci' | 'test';
  workloadRoot?: string;
}

export interface SourceAnalysisBenchmarkSample {
  projectLoadCache: 'cold' | 'cached';
  projectLoadMs: number;
  astTraversalMs: number;
  irGenerationMs: number;
  comparisonMs: number;
  totalMs: number;
  heapDeltaBytes: number;
  files: number;
  astNodes: number;
  operations: number;
  diagnostics: number;
  cacheHits: 0 | 1;
  cacheMisses: 0 | 1;
  cacheInvalidations: 0 | 1;
}

export interface SourceAnalysisBenchmarkReport {
  schemaVersion: 1;
  profile: 'full' | 'ci' | 'test';
  environment: Readonly<{ node: string; platform: string; arch: string }>;
  controllers: number;
  expectedOperations: number;
  samples: SourceAnalysisBenchmarkSample[];
}

const DIGEST = `sha256:${'b'.repeat(64)}`;
const SOURCE_CONFIG = Object.freeze({
  public_decorators: Object.freeze([]),
  roles_decorators: Object.freeze([]),
  guard_mappings: Object.freeze({ BenchGuard: Object.freeze({ auth_kind: 'bearer' as const }) }),
});
const LIMITS = Object.freeze({ ...DEFAULT_SOURCE_ANALYSIS_LIMITS, timeoutMs: 60_000 });

function elapsed(start: number): number {
  return Math.round((performance.now() - start) * 1_000) / 1_000;
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isInteger(value) || value < 1) throw new Error(`${name} must be a positive integer`);
  return value;
}

function write(file: string, contents: string): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents, 'utf8');
}

export function generateSourceAnalysisWorkload(root: string, controllers = 100): void {
  if (!Number.isInteger(controllers) || controllers < 1 || controllers > 1_000) {
    throw new Error('controllers must be an integer between 1 and 1000');
  }
  write(path.join(root, 'node_modules/@nestjs/common/package.json'), JSON.stringify({
    name: '@nestjs/common', version: '0.0.0-benchmark', main: 'index.js', types: 'index.d.ts',
  }));
  write(path.join(root, 'node_modules/@nestjs/common/index.js'), "'use strict';\nmodule.exports = {};\n");
  write(path.join(root, 'node_modules/@nestjs/common/index.d.ts'), [
    'export declare function Controller(path?: string): ClassDecorator;',
    'export declare function Get(path?: string): MethodDecorator;',
    'export declare function UseGuards(...guards: unknown[]): ClassDecorator & MethodDecorator;',
  ].join('\n'));
  write(path.join(root, 'src/guard.ts'), 'export class BenchGuard {}\n');
  const files = ['src/guard.ts'];
  for (let controller = 0; controller < controllers; controller += 1) {
    const relative = `src/controller-${controller}.ts`;
    const methods = Array.from({ length: 9 }, (_, operation) => (
      `  @Read('operation-${operation}') operation${operation}(): void {}`
    ));
    write(path.join(root, relative), [
      "import { Controller as HttpController, Get as Read, UseGuards } from '@nestjs/common';",
      "import { BenchGuard } from '@app/guard';",
      'declare function runtimePath(): string;',
      `@HttpController('controller-${controller}')`,
      '@UseGuards(BenchGuard)',
      `export class Controller${controller} {`,
      ...methods,
      '  @Read(runtimePath()) dynamic(): void {}',
      '}',
    ].join('\n'));
    files.push(relative);
  }
  write(path.join(root, 'tsconfig.json'), `${JSON.stringify({
    compilerOptions: {
      experimentalDecorators: true, moduleResolution: 'node', baseUrl: '.',
      paths: { '@app/*': ['src/*'] }, noLib: true, types: [],
    },
    files,
  }, null, 2)}\n`);
}

function countNodes(project: Awaited<ReturnType<typeof loadTypeScriptProject>>): number {
  let count = 0;
  const visit = (node: ts.Node): void => {
    count += 1;
    ts.forEachChild(node, visit);
  };
  for (const sourceFile of project.sourceFiles) visit(sourceFile);
  return count;
}

function openApiContract(result: SourceAnalysisResult) {
  return createSecurityContract({
    source: 'openapi',
    capabilities: {
      routes: 'complete', parameters: 'unsupported', requestBodies: 'unsupported', authentication: 'unsupported',
    },
    operations: result.contract.operations.map((operation): ApiOperationInputV1 => ({
      ...operation,
      provenance: operation.provenance.map((evidence) => ({
        ...evidence,
        source: 'openapi' as const,
        uri: 'openapi.yaml',
        analyzer: 'benchmark-openapi@1',
        capability: 'openapi-operations-v1',
      })),
    })),
  });
}

function compare(result: SourceAnalysisResult): void {
  const implementedEvidence = {
    source: 'source-ast' as const, uri: 'tsconfig.json', digest: DIGEST,
    analyzer: 'nestjs@1', capability: 'nestjs-routes-v1', complete: false,
  };
  compareSourceOpenApiContracts({
    declared: openApiContract(result), implemented: result.contract,
    declaredEvidence: {
      source: 'openapi', uri: 'openapi.yaml', digest: DIGEST,
      analyzer: 'benchmark-openapi@1', capability: 'openapi-operations-v1', complete: true,
    },
    implementedEvidence,
  });
  const policy: CDNSecurityFrameworkPolicy = {
    version: 1,
    defaults: { mode: 'enforce' },
    request: { allow_methods: ['GET'], block: { header_missing: [] } },
    routes: [],
    response_headers: {},
  };
  compareSourcePolicyContracts({
    implemented: result.contract,
    implementedEvidence,
    allowed: projectPolicyToAllowedSurface(policy, { policyDigest: DIGEST, sourceUri: 'policy/security.yml' }),
    target: 'aws',
  });
}

export async function runSourceAnalysisBenchmark(
  options: SourceAnalysisBenchmarkOptions = {},
): Promise<SourceAnalysisBenchmarkReport> {
  const profile = options.profile ?? 'full';
  if (!['full', 'ci', 'test'].includes(profile)) throw new Error('invalid source analysis benchmark profile');
  const controllers = options.controllers ?? 100;
  const iterations = positiveInteger(options.iterations ?? (profile === 'full' ? 3 : 1), 'iterations');
  const ownedRoot = options.workloadRoot === undefined;
  const root = options.workloadRoot ?? fs.mkdtempSync(path.join(os.tmpdir(), 'source-analysis-benchmark-'));
  generateSourceAnalysisWorkload(root, controllers);
  const cache = new TypeScriptAnalysisCache();
  const samples: SourceAnalysisBenchmarkSample[] = [];
  try {
    for (let iteration = 0; iteration < iterations; iteration += 1) {
      const heapStart = process.memoryUsage().heapUsed;
      const totalStart = performance.now();
      const loadStart = performance.now();
      const project = await loadTypeScriptProject({
        workspaceRoot: root, tsconfigPath: 'tsconfig.json', limits: LIMITS, cache,
      });
      const projectLoadMs = elapsed(loadStart);
      const traversalStart = performance.now();
      const visitedNodes = countNodes(project);
      const astTraversalMs = elapsed(traversalStart);
      if (visitedNodes !== project.metrics.astNodes) throw new Error('AST node metric mismatch');
      const irStart = performance.now();
      const execution = await runSourceAnalyzer(createNestJsSourceAnalyzer(SOURCE_CONFIG), {
        workspaceRoot: root, entrypoints: ['tsconfig.json'], limits: LIMITS, logger: { log() {} },
      });
      const irGenerationMs = elapsed(irStart);
      if (execution.status !== 'success') throw new Error(execution.diagnostics[0]?.safeMessage ?? 'analysis failed');
      const comparisonStart = performance.now();
      compare(execution.result);
      const comparisonMs = elapsed(comparisonStart);
      samples.push({
        projectLoadCache: iteration === 0 ? 'cold' : 'cached',
        projectLoadMs, astTraversalMs, irGenerationMs, comparisonMs,
        totalMs: elapsed(totalStart),
        heapDeltaBytes: process.memoryUsage().heapUsed - heapStart,
        files: execution.result.metrics.files,
        astNodes: execution.result.metrics.astNodes,
        operations: execution.result.metrics.operations,
        diagnostics: execution.result.metrics.diagnostics,
        cacheHits: project.metrics.cacheHits,
        cacheMisses: project.metrics.cacheMisses,
        cacheInvalidations: project.metrics.cacheInvalidations,
      });
    }
    const report: SourceAnalysisBenchmarkReport = {
      schemaVersion: 1,
      profile,
      environment: { node: process.versions.node, platform: process.platform, arch: process.arch },
      controllers,
      expectedOperations: controllers * 10,
      samples,
    };
    if (samples.some(({ operations }) => operations !== report.expectedOperations)) {
      throw new Error('source analysis benchmark operation count mismatch');
    }
    if (profile === 'ci' && samples.some(({ totalMs }) => totalMs > 60_000)) {
      throw new Error('source analysis benchmark exceeded 60000ms CI ceiling');
    }
    return report;
  } finally {
    if (ownedRoot) fs.rmSync(root, { recursive: true, force: true });
  }
}

function argument(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

if (require.main === module) {
  const profile = (argument('--profile') ?? 'full') as SourceAnalysisBenchmarkReport['profile'];
  const controllers = Number(argument('--controllers') ?? '100');
  const iterationsValue = argument('--iterations');
  runSourceAnalysisBenchmark({
    profile,
    controllers,
    ...(iterationsValue ? { iterations: Number(iterationsValue) } : {}),
  }).then((report) => console.log(JSON.stringify(report, null, 2))).catch((error: unknown) => {
    console.error((error as Error).message);
    process.exitCode = 1;
  });
}
