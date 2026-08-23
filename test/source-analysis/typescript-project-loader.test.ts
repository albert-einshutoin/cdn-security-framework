import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import ts from 'typescript';
import { afterEach, describe, expect, test } from 'vitest';

import { DEFAULT_SOURCE_ANALYSIS_LIMITS } from '../../src/source-analysis';
import {
  TypeScriptAnalysisCache,
  TypeScriptProjectLoadError,
  loadTypeScriptProject,
  nodeTypeScriptProjectFileSystem,
} from '../../src/source/typescript/project-loader';

const roots: string[] = [];

function workspace(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'typescript-project-loader-'));
  roots.push(root);
  return root;
}

function write(root: string, relative: string, contents: string): void {
  const target = path.join(root, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents);
}

function options(root: string, overrides = {}) {
  return {
    workspaceRoot: root,
    tsconfigPath: 'tsconfig.json',
    limits: DEFAULT_SOURCE_ANALYSIS_LIMITS,
    ...overrides,
  };
}

async function expectFailure(
  execution: Promise<unknown>,
  code: string,
  root: string,
): Promise<TypeScriptProjectLoadError> {
  try {
    await execution;
    throw new Error('Expected TypeScriptProjectLoadError.');
  } catch (error) {
    expect(error).toBeInstanceOf(TypeScriptProjectLoadError);
    const typed = error as TypeScriptProjectLoadError;
    expect(typed.diagnostics[0].code).toBe(code);
    expect(JSON.stringify(typed.diagnostics)).not.toContain(root);
    return typed;
  }
}

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe('TypeScript project loader', () => {
  test('loads JSONC include/exclude/files and path aliases without executing source', async () => {
    const root = workspace();
    write(root, 'tsconfig.json', `{
      // JSONC comments and trailing commas are supported.
      "compilerOptions": { "target": "ES2022", "ignoreDeprecations": "6.0", "baseUrl": "src", "paths": { "@app/*": ["../shared/*"] }, },
      "include": ["src/**/*"],
      "exclude": ["src/ignored.ts"],
    }`);
    write(root, 'src/app.ts', 'throw new Error("source must not execute");\nexport const value = 1;\n');
    write(root, 'src/component.tsx', 'export const component = 1;\n');
    write(root, 'src/module.mts', 'export const moduleValue = 1;\n');
    write(root, 'src/common.cts', 'export const commonValue = 1;\n');
    write(root, 'src/ignored.ts', 'export const ignored = true;\n');

    const loaded = await loadTypeScriptProject(options(root));

    expect(loaded.sourceFiles.map(({ fileName }) => path.relative(fs.realpathSync(root), fileName))).toEqual([
      'src/app.ts', 'src/common.cts', 'src/component.tsx', 'src/module.mts',
    ]);
    expect(loaded.pathAliases).toEqual({ '@app/*': ['../shared/*'] });
    expect(loaded.projectReferences).toBe('supported');
    expect(loaded.diagnostics).toEqual([]);
    expect(loaded.metrics).toMatchObject({ files: 4, cacheHits: 0, cacheMisses: 1, cacheInvalidations: 0 });
  }, 15_000);

  test('builds a Program for a normal package import without reading package metadata as source', async () => {
    const root = workspace();
    write(root, 'tsconfig.json', '{ "compilerOptions": { "moduleResolution": "node" }, "files": ["src/app.ts"] }');
    write(root, 'node_modules/example/package.json', '{ "types": "dist/types.d.ts" }');
    write(root, 'node_modules/example/dist/types.d.ts', 'export declare const value: number;\n');
    write(root, 'src/app.ts', 'import { value } from "example";\nexport const result = value;\n');

    const loaded = await loadTypeScriptProject(options(root));
    expect(loaded.program.getRootFileNames()).toHaveLength(1);
    expect(loaded.sourceFiles.map(({ fileName }) => path.basename(fileName))).toContain('app.ts');
    expect(loaded.diagnostics.map(({ typescriptCode }) => typescriptCode)).not.toContain(2307);
  }, 15_000);

  test('supports local extends and rejects package, outside, and symlink escapes', async () => {
    const root = workspace();
    write(root, 'config/base.json', '{ "compilerOptions": { "strict": true }, "include": ["../src/**/*.ts"] }');
    write(root, 'tsconfig.json', '{ "extends": "./config/base.json" }');
    write(root, 'src/app.ts', 'export const value = 1;\n');
    expect((await loadTypeScriptProject(options(root))).program.getRootFileNames()).toHaveLength(1);

    write(root, 'tsconfig.json', '{ "extends": "@tsconfig/node20/tsconfig.json" }');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_EXTENDS_UNSUPPORTED', root);

    write(root, 'tsconfig.json', '{ "extends": "https://example.com/tsconfig.json" }');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_EXTENDS_UNSUPPORTED', root);

    const outside = workspace();
    write(outside, 'outside.json', '{}');
    write(root, 'tsconfig.json', `{ "extends": ${JSON.stringify(path.join(outside, 'outside.json'))} }`);
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);

    fs.symlinkSync(path.join(outside, 'outside.json'), path.join(root, 'linked.json'));
    write(root, 'tsconfig.json', '{ "extends": "./linked.json" }');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);
  });

  test('rejects outside includes and enforces file, byte, and AST node limits', async () => {
    const root = workspace();
    write(root, 'tsconfig.json', '{ "include": ["src/**/*.ts"] }');
    write(root, 'src/one.ts', 'export const one = 1;\n');
    write(root, 'src/two.ts', 'export const two = 2;\n');

    await expectFailure(loadTypeScriptProject(options(root, {
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxFiles: 1 },
    })), 'TS_PROJECT_FILE_LIMIT', root);
    await expectFailure(loadTypeScriptProject(options(root, {
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxTotalSourceBytes: 1 },
    })), 'TS_PROJECT_TOTAL_BYTES_LIMIT', root);
    await expectFailure(loadTypeScriptProject(options(root, {
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxFileBytes: 1 },
    })), 'TS_PROJECT_FILE_BYTES_LIMIT', root);
    await expectFailure(loadTypeScriptProject(options(root, {
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxAstNodes: 1 },
    })), 'TS_PROJECT_AST_NODE_LIMIT', root);

    const baseConfig = '{ "compilerOptions": { "strict": true } }';
    const rootConfig = '{ "extends": "./base.json", "files": ["src/one.ts"] }';
    write(root, 'base.json', baseConfig);
    write(root, 'tsconfig.json', rootConfig);
    await expectFailure(loadTypeScriptProject(options(root, {
      limits: {
        ...DEFAULT_SOURCE_ANALYSIS_LIMITS,
        maxTotalSourceBytes: Buffer.byteLength(baseConfig + rootConfig + 'export const one = 1;\n') - 1,
      },
    })), 'TS_PROJECT_TOTAL_BYTES_LIMIT', root);

    write(root, 'tsconfig.json', '{ "include": ["../outside.ts"] }');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);

    write(root, 'tsconfig.json', '{ "compilerOptions": { "paths": { "@outside/*": ["../outside/*"] } }, "files": ["src/one.ts"] }');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);

    const outside = workspace();
    write(outside, 'escaped.ts', 'export const escaped = true;\n');
    fs.symlinkSync(path.join(outside, 'escaped.ts'), path.join(root, 'src/linked.ts'));
    write(root, 'tsconfig.json', '{ "files": ["src/linked.ts"] }');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);

    fs.unlinkSync(path.join(root, 'src/linked.ts'));
    fs.symlinkSync(outside, path.join(root, 'src/linked'));
    write(root, 'tsconfig.json', '{ "include": ["src/**/*.ts"] }');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);
  });

  test('returns partial project-reference diagnostics without loading referenced projects', async () => {
    const root = workspace();
    write(root, 'tsconfig.json', '{ "files": ["src/app.ts"], "references": [{ "path": "./other" }] }');
    write(root, 'src/app.ts', 'export const value = 1;\n');
    write(root, 'other/tsconfig.json', '{ "files": ["secret.ts"] }');
    write(root, 'other/secret.ts', 'export const secret = "must-not-load";\n');

    const loaded = await loadTypeScriptProject(options(root));
    expect(loaded.projectReferences).toBe('partial');
    expect(loaded.diagnostics).toEqual([expect.objectContaining({ code: 'TS_PROJECT_REFERENCES_PARTIAL' })]);
    expect(loaded.sourceFiles.map(({ fileName }) => fileName)).not.toContain(path.join(root, 'other/secret.ts'));
  });

  test('uses content-based cache and invalidates it after a source change', async () => {
    const root = workspace();
    const cache = new TypeScriptAnalysisCache();
    write(root, 'tsconfig.json', '{ "files": ["src/app.ts"] }');
    write(root, 'src/app.ts', 'export const value = 1;\n');

    const first = await loadTypeScriptProject(options(root, { cache }));
    const second = await loadTypeScriptProject(options(root, { cache }));
    write(root, 'src/app.ts', 'export const value = 2;\n');
    const changed = await loadTypeScriptProject(options(root, { cache }));

    expect(first.metrics).toMatchObject({ cacheHits: 0, cacheMisses: 1, cacheInvalidations: 0 });
    expect(second.metrics).toMatchObject({ cacheHits: 1, cacheMisses: 0, cacheInvalidations: 0 });
    expect(second.program).toBe(first.program);
    expect(changed.metrics).toMatchObject({ cacheHits: 0, cacheMisses: 1, cacheInvalidations: 1 });
    expect(changed.program).not.toBe(first.program);
  }, 15_000);

  test('rejects absolute references and non-library files beside the TypeScript standard library', async () => {
    const root = workspace();
    const typescriptDeclaration = path.join(
      path.dirname(ts.getDefaultLibFilePath({})),
      'typescript.d.ts',
    );
    write(root, 'tsconfig.json', '{ "files": ["src/app.ts"] }');
    write(root, 'src/app.ts', `/// <reference path=${JSON.stringify(typescriptDeclaration)} />\nexport const value = 1;\n`);

    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);
  });

  test('checks enumeration budgets and cooperative deadlines before Program creation', async () => {
    const root = workspace();
    write(root, 'tsconfig.json', '{ "include": ["src/**/*.ts"] }');
    write(root, 'src/app.ts', 'export const value = 1;\n');

    await expectFailure(loadTypeScriptProject(options(root, {
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxFiles: 1 },
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        readDirectory() { return ['one.ts', 'two.ts']; },
      },
    })), 'TS_PROJECT_FILE_LIMIT', root);

    await expectFailure(loadTypeScriptProject(options(root, {
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, timeoutMs: 1 },
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        readDirectory(...args) {
          const until = performance.now() + 2;
          while (performance.now() < until) { /* force the cooperative deadline */ }
          return nodeTypeScriptProjectFileSystem.readDirectory(...args);
        },
      },
    })), 'TS_PROJECT_TIMEOUT', root);
  });

  test('honors cancellation and redacts malformed-config diagnostics', async () => {
    const root = workspace();
    write(root, 'tsconfig.json', '{ "files": ["src/app.ts"] }');
    write(root, 'src/app.ts', 'export const value = 1;\n');
    const cancelled = new AbortController();
    cancelled.abort();
    await expectFailure(loadTypeScriptProject(options(root, {
      cancellationSignal: cancelled.signal,
    })), 'TS_PROJECT_CANCELLED', root);

    const duringRead = new AbortController();
    await expectFailure(loadTypeScriptProject(options(root, {
      cancellationSignal: duringRead.signal,
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        readFile(filePath) {
          const text = nodeTypeScriptProjectFileSystem.readFile(filePath);
          if (filePath.endsWith('src/app.ts')) duringRead.abort();
          return text;
        },
      },
    })), 'TS_PROJECT_CANCELLED', root);

    await expectFailure(loadTypeScriptProject(options(root, {
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        readFile(filePath) {
          if (filePath.endsWith('src/app.ts')) throw new Error(`${root}/secret source failure`);
          return nodeTypeScriptProjectFileSystem.readFile(filePath);
        },
      },
    })), 'TS_PROJECT_INTERNAL', root);

    write(root, 'tsconfig.json', '{ "files": ["src/app.ts"], "compilerOptions": { "target": ');
    const error = await expectFailure(
      loadTypeScriptProject(options(root)),
      'TS_PROJECT_INVALID_CONFIG',
      root,
    );
    expect(JSON.stringify(error.diagnostics)).not.toMatch(/export const|compilerOptions/);
  });
});
