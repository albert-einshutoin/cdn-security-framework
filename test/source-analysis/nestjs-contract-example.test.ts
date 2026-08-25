import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';

import { DEFAULT_SOURCE_ANALYSIS_LIMITS } from '../../src/source-analysis';
import { loadTypeScriptProject, TypeScriptAnalysisCache } from '../../src/source/typescript/project-loader';

const roots: string[] = [];

function copyExample(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nestjs-contract-example-'));
  roots.push(root);
  fs.cpSync(path.join(process.cwd(), 'examples/nestjs-contract'), root, { recursive: true });
  fs.mkdirSync(path.join(root, 'node_modules/@nestjs'), { recursive: true });
  fs.cpSync(path.join(root, 'stubs/nestjs-common'), path.join(root, 'node_modules/@nestjs/common'), { recursive: true });
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe('NestJS contract example', () => {
  test('matches the Analyzer to OpenAPI to Policy golden report', async () => {
    const root = copyExample();
    const dependency = path.join(root, 'node_modules/@nestjs/common/index.js');
    fs.writeFileSync(dependency, 'input dependency must not be overwritten\n');
    const { analyzeExample } = require(path.join(
      process.cwd(), 'examples/nestjs-contract/run-analysis.cjs',
    )) as {
      analyzeExample(root: string): Promise<{
        operations: Array<{ routeKey: string }>;
        diagnostics: string[];
        sourceOpenApi: Array<{
          ruleId: string;
          route?: { method?: string; path?: string };
          evidence: Array<{
            source: string;
            uri: string;
            pointer?: string;
            digest: string;
            complete: boolean;
          }>;
        }>;
        sourcePolicy: Array<{
          ruleId: string;
          route?: { method?: string; path?: string };
          evidence: Array<{ source: string; digest: string }>;
        }>;
      }>;
    };
    const report = await analyzeExample(root);
    expect(fs.readFileSync(dependency, 'utf8')).toBe('input dependency must not be overwritten\n');
    const route = ({ method, path }: { method?: string; path?: string } = {}) => (
      `${method ? `${method} ` : ''}${path ?? ''}`
    );
    const summary = {
      schemaVersion: 1,
      operationKeys: report.operations.map(({ routeKey }) => routeKey),
      diagnostics: report.diagnostics,
      sourceOpenApiRules: report.sourceOpenApi.map((finding) => `${finding.ruleId}:${route(finding.route)}`),
      sourcePolicyRules: report.sourcePolicy.map((finding) => `${finding.ruleId}:${route(finding.route)}`),
    };
    expect(summary).toEqual(JSON.parse(fs.readFileSync(
      path.join(process.cwd(), 'test/fixtures/source/nestjs/expected/golden-report.json'), 'utf8',
    )));
    const missingImplementation = report.sourceOpenApi.find(({ ruleId, route }) => (
      ruleId === 'SC-INVENTORY-003' && route?.path === '/declared-only'
    ));
    const projectEvidence = missingImplementation?.evidence.find(({ source }) => source === 'source-ast');
    expect(projectEvidence).toEqual(expect.objectContaining({
      source: 'source-ast',
      uri: 'tsconfig.json',
      digest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
      complete: false,
    }));
    expect(projectEvidence?.pointer).toBeUndefined();

    const policyDigest = report.sourcePolicy.flatMap(({ evidence }) => evidence)
      .find(({ source }) => source === 'policy')?.digest;
    const policyPath = path.join(root, 'policy/security.yml');
    fs.writeFileSync(policyPath, fs.readFileSync(policyPath, 'utf8')
      .replace('allow_methods: [GET, POST]', 'allow_methods: [GET, POST, PATCH]'));
    const changedReport = await analyzeExample(root);
    const changedPolicyDigest = changedReport.sourcePolicy.flatMap(({ evidence }) => evidence)
      .find(({ source }) => source === 'policy')?.digest;
    expect(policyDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(changedPolicyDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(changedPolicyDigest).not.toBe(policyDigest);
  });

  test('rejects symlinked fixture inputs before copying them', async () => {
    const root = copyExample();
    const openApi = path.join(root, 'openapi.yaml');
    fs.renameSync(openApi, path.join(root, 'openapi-real.yaml'));
    fs.symlinkSync('openapi-real.yaml', openApi);
    const { analyzeExample } = require(path.join(
      process.cwd(), 'examples/nestjs-contract/run-analysis.cjs',
    )) as { analyzeExample(root: string): Promise<unknown> };
    await expect(analyzeExample(root)).rejects.toThrow('fixture file must not be a symlink: openapi.yaml');
  });

  test('rejects an oversized allowlisted file before analysis', async () => {
    const root = copyExample();
    fs.writeFileSync(
      path.join(root, 'openapi.yaml'),
      Buffer.alloc(DEFAULT_SOURCE_ANALYSIS_LIMITS.maxFileBytes + 1),
    );
    const { analyzeExample } = require(path.join(
      process.cwd(), 'examples/nestjs-contract/run-analysis.cjs',
    )) as { analyzeExample(root: string): Promise<unknown> };
    await expect(analyzeExample(root)).rejects.toThrow(
      'fixture file exceeds source analysis byte limit: openapi.yaml',
    );
  });

  test('invalidates the analyzer cache after a source file change', async () => {
    const root = copyExample();
    const cache = new TypeScriptAnalysisCache();
    const options = {
      workspaceRoot: root,
      tsconfigPath: 'tsconfig.json',
      limits: DEFAULT_SOURCE_ANALYSIS_LIMITS,
      cache,
    };
    const first = await loadTypeScriptProject(options);
    const second = await loadTypeScriptProject(options);
    fs.appendFileSync(path.join(root, 'src/users.controller.ts'), '\n// cache invalidation probe\n');
    const changed = await loadTypeScriptProject(options);
    expect(first.metrics).toMatchObject({ cacheHits: 0, cacheMisses: 1, cacheInvalidations: 0 });
    expect(second.metrics).toMatchObject({ cacheHits: 1, cacheMisses: 0, cacheInvalidations: 0 });
    expect(changed.metrics).toMatchObject({ cacheHits: 0, cacheMisses: 1, cacheInvalidations: 1 });
  });
});
