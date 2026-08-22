#!/usr/bin/env node
'use strict';

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

import { serializeSecurityContract } from '../contract/security-ir';
import { OpenApiAnalysisError, type OpenApiAnalysisErrorCode } from '../openapi/analysis-error';
import {
  DEFAULT_OPENAPI_ANALYSIS_LIMITS,
  type OpenApiAnalysisLimits,
} from '../openapi/analysis-limits';
import { loadOpenApiDocument } from '../openapi/load-document';
import { normalizeOpenApiOperations } from '../openapi/operation-normalizer';
import { resolveOpenApiReferences } from '../openapi/ref-resolver';

export interface OpenApiBenchmarkSizes {
  small: number;
  shared: number;
  large: number;
  repeated: number;
}

export interface OpenApiBenchmarkWorkload {
  id: string;
  inputPath: string;
  expectedOperations: number;
  rejection?: Readonly<{ stage: 'parse'; code: OpenApiAnalysisErrorCode }>;
}

export interface OpenApiBenchmarkSample {
  mode: 'cold' | 'warm';
  parseMs: number;
  resolveMs: number;
  normalizeMs: number;
  totalMs: number;
  approximateHeapDeltaBytes: number;
  outputBytes: number;
}

export interface OpenApiBenchmarkResult {
  id: string;
  inputPath: string;
  status: 'completed' | 'rejected';
  inputBytes: number;
  operationCount: number;
  referenceCount: number;
  resolvedDocumentCount: number;
  outputBytes: number;
  samples: OpenApiBenchmarkSample[];
  rejection?: Readonly<{ stage: 'parse'; code: OpenApiAnalysisErrorCode }>;
}

export interface OpenApiBenchmarkReport {
  schemaVersion: 1;
  profile: 'full' | 'ci' | 'test';
  environment: Readonly<{ node: string; platform: string; arch: string }>;
  iterations: number;
  workloads: OpenApiBenchmarkResult[];
}

const DEFAULT_SIZES: Readonly<OpenApiBenchmarkSizes> = Object.freeze({
  small: 100,
  shared: 1_000,
  large: 10_000,
  repeated: 1_000,
});

const BENCHMARK_LIMITS: Readonly<OpenApiAnalysisLimits> = Object.freeze({
  ...DEFAULT_OPENAPI_ANALYSIS_LIMITS,
  maxDocumentBytes: 4 * 1024 * 1024,
  maxGraphBytes: 256 * 1024 * 1024,
  maxNodes: 1_000_000,
  maxOperations: 10_000,
  maxSchemaDepth: 256,
  timeoutMs: 60_000,
});

function operation(operationId: string, parameter?: Record<string, unknown>): Record<string, unknown> {
  return {
    get: {
      operationId,
      ...(parameter ? { parameters: [parameter] } : {}),
      responses: { 200: { description: 'ok' } },
    },
  };
}

function documentWithPaths(paths: Record<string, unknown>, components?: Record<string, unknown>): object {
  return {
    openapi: '3.1.0',
    info: { title: 'deterministic benchmark', version: '1.0.0' },
    paths,
    ...(components ? { components } : {}),
  };
}

function numberedPaths(count: number, parameter?: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Array.from({ length: count }, (_, index) => [
    `/items/${index}`,
    operation(`getItem${index}`, parameter),
  ]));
}

function writeJson(file: string, value: unknown): void {
  fs.writeFileSync(file, `${JSON.stringify(value)}\n`, 'utf8');
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isInteger(value) || value < 1) throw new Error(`${name} must be a positive integer`);
  return value;
}

function generateSharedRefsWorkload(workspaceRoot: string, count: number): OpenApiBenchmarkWorkload {
  fs.mkdirSync(workspaceRoot, { recursive: true });
  const inputPath = 'shared-refs-1000.json';
  const parameter = { $ref: '#/components/parameters/SharedId' };
  const components = {
    parameters: { SharedId: { name: 'id', in: 'query', schema: { type: 'string' } } },
  };
  writeJson(path.join(workspaceRoot, inputPath), documentWithPaths(numberedPaths(count, parameter), components));
  return { id: 'shared-refs-1000', inputPath, expectedOperations: count };
}

export function generateOpenApiBenchmarkWorkloads(
  workspaceRoot: string,
  sizes: OpenApiBenchmarkSizes = DEFAULT_SIZES,
): OpenApiBenchmarkWorkload[] {
  const normalized = {
    small: positiveInteger(sizes.small, 'small'),
    shared: positiveInteger(sizes.shared, 'shared'),
    large: positiveInteger(sizes.large, 'large'),
    repeated: positiveInteger(sizes.repeated, 'repeated'),
  };
  fs.mkdirSync(workspaceRoot, { recursive: true });

  const files = {
    small: 'operations-100.json',
    large: 'nested-refs-10000.json',
    deep: 'deep-schema.json',
    repeated: 'repeated-refs.json',
    repeatedComponents: 'repeated-components.json',
    rejected: 'early-document-limit.json',
  };
  writeJson(path.join(workspaceRoot, files.small), documentWithPaths(numberedPaths(normalized.small)));

  const sharedWorkload = generateSharedRefsWorkload(workspaceRoot, normalized.shared);
  const sharedParameter = { $ref: '#/components/parameters/SharedId' };
  const sharedComponents = {
    parameters: { SharedId: { name: 'id', in: 'query', schema: { type: 'string' } } },
  };

  const nestedSchemas: Record<string, unknown> = {
    Leaf: { type: 'string' },
  };
  for (let depth = 7; depth >= 0; depth -= 1) {
    nestedSchemas[`Level${depth}`] = { $ref: `#/components/schemas/${depth === 7 ? 'Leaf' : `Level${depth + 1}`}` };
  }
  writeJson(
    path.join(workspaceRoot, files.large),
    documentWithPaths(numberedPaths(normalized.large, {
      name: 'value', in: 'query', schema: { $ref: '#/components/schemas/Level0' },
    }), { schemas: nestedSchemas }),
  );

  let deepSchema: Record<string, unknown> = { type: 'string' };
  for (let depth = 0; depth < 55; depth += 1) deepSchema = { type: 'array', items: deepSchema };
  writeJson(
    path.join(workspaceRoot, files.deep),
    documentWithPaths({ '/deep': operation('getDeep', { name: 'value', in: 'query', schema: deepSchema }) }),
  );

  writeJson(path.join(workspaceRoot, files.repeatedComponents), { components: sharedComponents });
  writeJson(path.join(workspaceRoot, files.repeated), documentWithPaths(numberedPaths(
    normalized.repeated,
    { $ref: `./${files.repeatedComponents}#/components/parameters/SharedId` },
  )));

  writeJson(path.join(workspaceRoot, files.rejected), {
    ...documentWithPaths({}),
    padding: 'x'.repeat(2_048),
  });

  return [
    { id: 'operations-100', inputPath: files.small, expectedOperations: normalized.small },
    sharedWorkload,
    { id: 'nested-refs-10000', inputPath: files.large, expectedOperations: normalized.large },
    { id: 'deep-schema', inputPath: files.deep, expectedOperations: 1 },
    { id: 'repeated-refs', inputPath: files.repeated, expectedOperations: normalized.repeated },
    {
      id: 'early-document-limit',
      inputPath: files.rejected,
      expectedOperations: 0,
      rejection: { stage: 'parse', code: 'OPENAPI_DOCUMENT_TOO_LARGE' },
    },
  ];
}

function elapsed(start: number): number {
  return Math.round((performance.now() - start) * 1_000) / 1_000;
}

function runWorkload(
  workspaceRoot: string,
  workload: OpenApiBenchmarkWorkload,
  iterations: number,
): OpenApiBenchmarkResult {
  const absoluteInput = path.join(workspaceRoot, workload.inputPath);
  const samples: OpenApiBenchmarkSample[] = [];
  let operationCount = 0;
  let referenceCount = 0;
  let resolvedDocumentCount = 0;
  let outputBytes = 0;
  let rejection: OpenApiBenchmarkResult['rejection'];
  let rejectionCount = 0;

  for (let index = 0; index < iterations; index += 1) {
    const heapStart = process.memoryUsage().heapUsed;
    let heapPeak = heapStart;
    const totalStart = performance.now();
    const parseStart = performance.now();
    const limits = workload.rejection
      ? { ...BENCHMARK_LIMITS, maxDocumentBytes: 1_024 }
      : workload.id === 'deep-schema'
        ? { ...BENCHMARK_LIMITS, maxSchemaDepth: DEFAULT_OPENAPI_ANALYSIS_LIMITS.maxSchemaDepth }
        : BENCHMARK_LIMITS;
    let stage: 'parse' | 'resolve' | 'normalize' = 'parse';
    try {
      const loaded = loadOpenApiDocument({
        inputPath: absoluteInput,
        workspaceRoot,
        limits,
      });
      const parseMs = elapsed(parseStart);
      heapPeak = Math.max(heapPeak, process.memoryUsage().heapUsed);
      stage = 'resolve';
      const resolveStart = performance.now();
      const graph = resolveOpenApiReferences({ root: loaded, workspaceRoot, limits });
      const resolveMs = elapsed(resolveStart);
      heapPeak = Math.max(heapPeak, process.memoryUsage().heapUsed);
      stage = 'normalize';
      const normalizeStart = performance.now();
      const contract = normalizeOpenApiOperations(graph, { limits });
      const normalizeMs = elapsed(normalizeStart);
      const serialized = serializeSecurityContract(contract);
      heapPeak = Math.max(heapPeak, process.memoryUsage().heapUsed);
      operationCount = contract.operations.length;
      referenceCount = graph.references.length;
      resolvedDocumentCount = graph.documents.length;
      outputBytes = Buffer.byteLength(serialized);
      samples.push({
        mode: index === 0 ? 'cold' : 'warm',
        parseMs,
        resolveMs,
        normalizeMs,
        totalMs: elapsed(totalStart),
        approximateHeapDeltaBytes: Math.max(0, heapPeak - heapStart),
        outputBytes,
      });
    } catch (error: unknown) {
      if (!(error instanceof OpenApiAnalysisError)
        || !workload.rejection
        || stage !== workload.rejection.stage
        || error.code !== workload.rejection.code) throw error;
      rejection = workload.rejection;
      rejectionCount += 1;
      samples.push({
        mode: index === 0 ? 'cold' : 'warm',
        parseMs: elapsed(parseStart),
        resolveMs: 0,
        normalizeMs: 0,
        totalMs: elapsed(totalStart),
        approximateHeapDeltaBytes: Math.max(0, process.memoryUsage().heapUsed - heapStart),
        outputBytes: 0,
      });
    }
  }

  if (workload.rejection && rejectionCount !== iterations) {
    throw new Error(`${workload.id}: expected rejection in every iteration`);
  }
  if (!workload.rejection && operationCount !== workload.expectedOperations) {
    throw new Error(`${workload.id}: expected ${workload.expectedOperations} operations, received ${operationCount}`);
  }
  return {
    id: workload.id,
    inputPath: workload.inputPath,
    status: rejection ? 'rejected' : 'completed',
    inputBytes: fs.statSync(absoluteInput).size,
    operationCount,
    referenceCount,
    resolvedDocumentCount,
    outputBytes,
    samples,
    ...(rejection ? { rejection } : {}),
  };
}

export function runOpenApiBenchmark(options: {
  profile: 'full' | 'ci' | 'test';
  iterations?: number;
  workloadRoot?: string;
  sizes?: OpenApiBenchmarkSizes;
}): OpenApiBenchmarkReport {
  const iterations = positiveInteger(options.iterations ?? (options.profile === 'full' ? 3 : 1), 'iterations');
  const temporary = options.workloadRoot === undefined;
  const workloadRoot = options.workloadRoot
    ?? fs.mkdtempSync(path.join(os.tmpdir(), 'cdn-security-openapi-benchmark-'));
  try {
    const selected = options.profile === 'ci'
      ? [generateSharedRefsWorkload(
        workloadRoot,
        positiveInteger(options.sizes?.shared ?? DEFAULT_SIZES.shared, 'shared'),
      )]
      : generateOpenApiBenchmarkWorkloads(workloadRoot, options.sizes);
    return {
      schemaVersion: 1,
      profile: options.profile,
      environment: { node: process.version, platform: process.platform, arch: process.arch },
      iterations,
      workloads: selected.map((workload) => runWorkload(workloadRoot, workload, iterations)),
    };
  } finally {
    if (temporary) fs.rmSync(workloadRoot, { recursive: true, force: true });
  }
}

function parseArguments(argv: string[]): {
  profile: 'full' | 'ci';
  iterations?: number;
  output?: string;
  baseline?: string;
} {
  let profile: 'full' | 'ci' = 'full';
  let iterations: number | undefined;
  let output: string | undefined;
  let baseline: string | undefined;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--profile' && argv[index + 1] === 'ci') { profile = 'ci'; index += 1; }
    else if (argument === '--profile' && argv[index + 1] === 'full') { profile = 'full'; index += 1; }
    else if (argument === '--iterations') { iterations = Number(argv[index + 1]); index += 1; }
    else if (argument === '--output') { output = argv[index + 1]; index += 1; }
    else if (argument === '--baseline') { baseline = argv[index + 1]; index += 1; }
    else throw new Error(`Unknown argument: ${argument}`);
  }
  return { profile, iterations, output, baseline };
}

function enforceRegressionBaseline(report: OpenApiBenchmarkReport, baselinePath: string): void {
  const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8')) as {
    environment: { platform: string; arch: string };
    maxTimeRegressionPercent: number;
    maxHeapRegressionPercent: number;
    nodes: Record<string, Record<string, { warmMeanTotalMs: number; peakHeapDeltaBytes: number }>>;
  };
  if (baseline.environment.platform !== process.platform || baseline.environment.arch !== process.arch) {
    throw new Error(`OpenAPI benchmark baseline requires ${baseline.environment.platform}/${baseline.environment.arch}`);
  }
  const nodeVersion = process.versions.node;
  const expected = baseline.nodes[nodeVersion];
  if (!expected) throw new Error(`No OpenAPI benchmark baseline for Node ${nodeVersion}`);
  const failures: string[] = [];
  for (const workload of report.workloads) {
    const target = expected[workload.id];
    if (!target) throw new Error(`No baseline for workload ${workload.id}`);
    const warm = workload.samples.filter(({ mode }) => mode === 'warm');
    if (warm.length === 0) throw new Error(`No warm benchmark sample for ${workload.id}`);
    const warmMeanTotalMs = warm.reduce((sum, sample) => sum + sample.totalMs, 0) / warm.length;
    const peakHeap = Math.max(...workload.samples.map(({ approximateHeapDeltaBytes }) => approximateHeapDeltaBytes));
    const timeLimit = Math.max(
      target.warmMeanTotalMs * (1 + baseline.maxTimeRegressionPercent / 100),
      target.warmMeanTotalMs + 1,
    );
    const heapLimit = target.peakHeapDeltaBytes * (1 + baseline.maxHeapRegressionPercent / 100);
    if (warmMeanTotalMs > timeLimit) failures.push(`${workload.id} time ${warmMeanTotalMs.toFixed(3)}ms > ${timeLimit.toFixed(3)}ms`);
    if (peakHeap > heapLimit) failures.push(`${workload.id} heap ${peakHeap} > ${Math.round(heapLimit)}`);
  }
  if (failures.length > 0) throw new Error(`OpenAPI benchmark regression:\n${failures.join('\n')}`);
}

function main(): void {
  const options = parseArguments(process.argv.slice(2));
  const report = runOpenApiBenchmark(options);
  if (options.profile === 'ci') {
    const sample = report.workloads[0]?.samples[0];
    if (!sample || sample.totalMs > 15_000 || sample.approximateHeapDeltaBytes > 512 * 1024 * 1024) {
      throw new Error('OpenAPI CI benchmark exceeded the 15s / 512 MiB absolute ceiling');
    }
  }
  const json = `${JSON.stringify(report, null, 2)}\n`;
  if (options.output) fs.writeFileSync(options.output, json, { encoding: 'utf8', flag: 'wx' });
  else process.stdout.write(json);
  if (options.baseline) enforceRegressionBaseline(report, options.baseline);
}

if (require.main === module) main();
