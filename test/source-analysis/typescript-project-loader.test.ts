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
    write(root, 'tsconfig.json', '{ "compilerOptions": { "moduleResolution": "node", "noLib": true }, "files": ["src/app.ts"] }');
    write(root, 'node_modules/example/package.json', '{ "types": "dist/types.d.ts" }');
    write(root, 'node_modules/example/dist/types.d.ts', 'export declare const value: number;\n');
    write(root, 'src/app.ts', 'import { value } from "example";\nexport const result = value;\n');

    const loaded = await loadTypeScriptProject(options(root));
    expect(loaded.program.getRootFileNames()).toHaveLength(1);
    expect(loaded.sourceFiles.map(({ fileName }) => path.basename(fileName))).toContain('app.ts');
    expect(loaded.diagnostics.map(({ typescriptCode }) => typescriptCode)).not.toContain(2307);
    await expectFailure(loadTypeScriptProject(options(root, {
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxFiles: 3 },
    })), 'TS_PROJECT_FILE_LIMIT', root);

    write(root, 'tsconfig.json', '{ "compilerOptions": { "module": "NodeNext", "moduleResolution": "NodeNext", "noLib": true }, "files": ["src/app.ts"] }');
    write(root, 'src/app.ts', 'import fs from "node:fs";\nexport const value = fs;\n');
    await expect(loadTypeScriptProject(options(root))).resolves.toBeDefined();
  }, 15_000);

  test('rejects hoisted packages outside the workspace', async () => {
    const standardLibraryRoot = fs.mkdtempSync(path.join(process.cwd(), '.typescript-project-loader-'));
    roots.push(standardLibraryRoot);
    write(standardLibraryRoot, 'tsconfig.json', '{ "compilerOptions": { "types": [] }, "files": ["src/app.ts"] }');
    write(standardLibraryRoot, 'src/app.ts', 'export const value: Promise<number> = Promise.resolve(1);\n');
    await expect(loadTypeScriptProject(options(standardLibraryRoot))).resolves.toBeDefined();

    const monorepo = workspace();
    const root = path.join(monorepo, 'packages/app');
    write(root, 'tsconfig.json', '{ "compilerOptions": { "moduleResolution": "node", "noLib": true }, "files": ["src/app.ts"] }');
    write(root, 'src/app.ts', 'import { value } from "example";\nexport { value };\n');
    write(monorepo, 'node_modules/example/package.json', '{ "types": "index.d.ts" }');
    write(monorepo, 'node_modules/example/index.d.ts', 'export declare const value: number;\n');

    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);
  });

  test('supports local extends and rejects package, outside, and symlink escapes', async () => {
    const root = workspace();
    write(root, 'config/base.json', '{ "compilerOptions": { "strict": true }, "include": ["../src/**/*.ts"] }');
    fs.mkdirSync(path.join(root, 'config/base'));
    write(root, 'tsconfig.json', '{ "extends": "./config/base" }');
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

  test('uses inherited baseUrl for child paths and ignores base-only project references', async () => {
    const root = workspace();
    write(root, 'config/base.json', `{
      "compilerOptions": { "baseUrl": "../src", "ignoreDeprecations": "6.0" },
      "references": [{ "path": "../../outside-project" }]
    }`);
    write(root, 'tsconfig.json', `{
      "extends": "./config/base.json",
      "compilerOptions": { "paths": { "@x/*": ["../shared/*"] } },
      "files": ["src/app.ts"]
    }`);
    write(root, 'src/app.ts', 'export const value = 1;\n');

    const loaded = await loadTypeScriptProject(options(root));
    expect(loaded.pathAliases).toEqual({ '@x/*': ['../shared/*'] });
    expect(loaded.projectReferences).toBe('supported');
    expect(loaded.diagnostics).toEqual([]);
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

    write(root, 'tsconfig.json', '{ "files": ["src/one.ts"] }');
    write(root, 'src/one.ts', 'export const = ;\nexport const = ;\n');
    await expectFailure(loadTypeScriptProject(options(root, {
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxDiagnostics: 1 },
    })), 'TS_PROJECT_DIAGNOSTIC_LIMIT', root);
    await expectFailure(loadTypeScriptProject(options(root, {
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxFileBytes: 1 },
    })), 'TS_PROJECT_FILE_BYTES_LIMIT', root);
    let oversizedSourceRead = false;
    await expectFailure(loadTypeScriptProject(options(root, {
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxFileBytes: 128 },
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        stat(filePath) {
          const stat = nodeTypeScriptProjectFileSystem.stat(filePath);
          if (filePath.endsWith('src/one.ts')) Object.defineProperty(stat, 'size', { value: 129 });
          return stat;
        },
        readFile(filePath) {
          if (filePath.endsWith('src/one.ts')) oversizedSourceRead = true;
          return nodeTypeScriptProjectFileSystem.readFile(filePath);
        },
      },
    })), 'TS_PROJECT_FILE_BYTES_LIMIT', root);
    expect(oversizedSourceRead).toBe(false);
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

    const duplicateConfig = '{ "extends": ["./base.json", "./base.json"], "compilerOptions": { "noLib": true }, "files": ["src/one.ts"] }';
    write(root, 'tsconfig.json', duplicateConfig);
    write(root, 'src/one.ts', 'export const one = 1;\n');
    await expect(loadTypeScriptProject(options(root, {
      limits: {
        ...DEFAULT_SOURCE_ANALYSIS_LIMITS,
        maxTotalSourceBytes: Buffer.byteLength(baseConfig + duplicateConfig + 'export const one = 1;\n'),
      },
    }))).resolves.toBeDefined();

    write(root, 'tsconfig.json', '{ "include": ["../outside.ts"] }');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);

    write(root, 'tsconfig.json', '{ "compilerOptions": { "paths": { "@outside/*": ["../outside/*"] } }, "files": ["src/one.ts"] }');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);

    write(root, 'tsconfig.json', '{ "compilerOptions": { "paths": { "@outside/*": ["safe/*/../../../outside"] } }, "files": ["src/one.ts"] }');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);

    write(root, 'tsconfig.json', '{ "compilerOptions": { "types": ["../outside"] }, "files": ["src/one.ts"] }');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);
    write(root, 'tsconfig.json', '{ "compilerOptions": { "types": ["pkg/../../../outside"] }, "files": ["src/one.ts"] }');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);
    write(root, 'tsconfig.json', '{ "compilerOptions": { "types": ["\\\\\\\\server\\\\share"] }, "files": ["src/one.ts"] }');
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

    fs.unlinkSync(path.join(root, 'src/linked'));
    const outsideNonSource = workspace();
    write(outsideNonSource, 'only.txt', 'outside');
    fs.symlinkSync(outsideNonSource, path.join(root, 'src/linked'));
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);
  });

  test('validates jsxImportSource without rejecting package specifiers', async () => {
    const root = workspace();
    write(root, 'src/app.tsx', 'export const node = <div />;\n');
    for (const jsxImportSource of ['react', '@scope/pkg']) {
      write(root, 'tsconfig.json', JSON.stringify({
        compilerOptions: { jsx: 'react-jsx', jsxImportSource, noLib: true },
        files: ['src/app.tsx'],
      }));
      await expect(loadTypeScriptProject(options(root))).resolves.toBeDefined();
    }

    for (const jsxImportSource of ['../../outside', 'pkg/../../../outside', '\\\\server\\share', 'C:/outside']) {
      write(root, 'tsconfig.json', JSON.stringify({
        compilerOptions: { jsx: 'react-jsx', jsxImportSource },
        files: ['src/app.tsx'],
      }));
      await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);
    }

    write(root, 'config/base.json', JSON.stringify({
      compilerOptions: { jsx: 'react-jsx', jsxImportSource: '../outside' },
    }));
    write(root, 'app.tsx', 'export const inherited = <div />;\n');
    write(root, 'tsconfig.json', '{ "extends": "./config/base.json", "files": ["app.tsx"] }');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);

    write(root, 'tsconfig.json', '{ "compilerOptions": { "jsxImportSource": 1 }, "files": ["src/app.tsx"] }');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_INVALID_CONFIG', root);
  });

  test('rejects workspace imports with unsupported program extensions', async () => {
    const root = workspace();
    write(root, 'tsconfig.json', '{ "compilerOptions": { "resolveJsonModule": true }, "files": ["src/app.ts"] }');
    write(root, 'src/app.ts', 'import data from "./data.json";\nexport const value = data.value;\n');
    write(root, 'src/data.json', '{ "value": 1 }');

    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_EXTENSION_UNSUPPORTED', root);

    write(root, 'package.json', '{ "value": 1 }');
    write(root, 'src/app.ts', 'import data from "../package.json";\nexport const value = data.value;\n');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_EXTENSION_UNSUPPORTED', root);

    write(root, 'node_modules/example/package.json', '{ "value": 1 }');
    write(root, 'src/app.ts', 'import data from "../node_modules/example/package.json";\nexport const value = data.value;\n');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_EXTENSION_UNSUPPORTED', root);
  });

  test('rejects unsupported imports that resolve outside the workspace', async () => {
    const root = workspace();
    const outside = workspace();
    write(root, 'tsconfig.json', '{ "compilerOptions": { "allowJs": true, "resolveJsonModule": true }, "files": ["src/app.ts"] }');
    write(outside, 'outside.js', 'export const value = 1;\n');
    write(root, 'src/app.ts', 'import { value } from "./outside.js";\nexport { value };\n');
    fs.symlinkSync(path.join(outside, 'outside.js'), path.join(root, 'src/outside.js'));

    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);

    fs.unlinkSync(path.join(root, 'src/outside.js'));
    write(outside, 'outside.json', '{ "value": 1 }');
    fs.symlinkSync(path.join(outside, 'outside.json'), path.join(root, 'src/outside.json'));
    write(root, 'src/app.ts', 'import data from "./outside.json";\nexport const value = data.value;\n');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);

    fs.unlinkSync(path.join(root, 'src/outside.json'));
    fs.symlinkSync(outside, path.join(root, 'src/linked'));
    write(root, 'src/app.ts', 'import { value } from "./linked/outside.js";\nexport { value };\n');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);

    fs.unlinkSync(path.join(root, 'src/linked'));
    write(outside, 'package.json', '{ "types": "index.ts" }');
    write(outside, 'index.ts', 'export const value = 1;\n');
    const outsideSpecifier = path.relative(path.join(root, 'src'), outside).replaceAll(path.sep, '/');
    write(root, 'src/app.ts', `import { value } from ${JSON.stringify(outsideSpecifier)};\nexport { value };\n`);
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);

    write(root, 'src/app.ts', `const value = require(${JSON.stringify(outsideSpecifier)});\nexport { value };\n`);
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);

    const windowsOutsideSpecifier = outsideSpecifier.replaceAll('/', '\\');
    write(root, 'src/app.ts', `import { value } from ${JSON.stringify(windowsOutsideSpecifier)};\nexport { value };\n`);
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);

    write(root, 'src/app.ts', 'import value from "\\\\server\\share";\nexport { value };\n');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);

    write(root, 'src/app.ts', '/// <reference types="../../outside" />\nexport const value = 1;\n');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);
    write(root, 'src/app.ts', '/// <reference types="pkg/../../../outside" />\nexport const value = 1;\n');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);
    write(root, 'src/app.ts', '/// <reference types="\\\\server\\share" />\nexport const value = 1;\n');
    await expectFailure(loadTypeScriptProject(options(root)), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);
  }, 15_000);

  test('rejects non-regular dependency inputs before bounded reads', async () => {
    const root = workspace();
    write(root, 'tsconfig.json', '{ "compilerOptions": { "noLib": true }, "files": ["src/app.ts"] }');
    write(root, 'src/app.ts', 'import { value } from "./dep";\nexport { value };\n');
    write(root, 'src/dep.ts', 'export const value = 1;\n');
    let dependencyRead = false;

    await expectFailure(loadTypeScriptProject(options(root, {
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        stat(filePath) {
          const stat = nodeTypeScriptProjectFileSystem.stat(filePath);
          if (filePath.endsWith('src/dep.ts')) stat.isFile = () => false;
          return stat;
        },
        readFileBounded(filePath, maxBytes) {
          if (filePath.endsWith('src/dep.ts')) dependencyRead = true;
          return nodeTypeScriptProjectFileSystem.readFileBounded(filePath, maxBytes);
        },
      },
    })), 'TS_PROJECT_INTERNAL', root);
    expect(dependencyRead).toBe(false);
  });

  test('uses bounded workspace package metadata to resolve package imports maps', async () => {
    const root = workspace();
    write(root, 'tsconfig.json', '{ "compilerOptions": { "module": "NodeNext", "moduleResolution": "NodeNext", "noLib": true }, "files": ["src/app.ts"] }');
    write(root, 'package.json', '{ "type": "module", "imports": { "#dep": "./src/dep.ts" } }');
    write(root, 'src/app.ts', 'import { value } from "#dep";\nexport { value };\n');
    write(root, 'src/dep.ts', 'export const value = 1;\n');

    const loaded = await loadTypeScriptProject(options(root));

    expect(loaded.sourceFiles.map(({ fileName }) => path.basename(fileName))).toContain('dep.ts');
    expect(loaded.diagnostics.map(({ typescriptCode }) => typescriptCode)).not.toContain(2307);
  });

  test('rejects package metadata retargeted outside before the bounded read', async () => {
    const root = workspace();
    const outside = workspace();
    write(root, 'tsconfig.json', '{ "compilerOptions": { "module": "NodeNext", "moduleResolution": "NodeNext", "noLib": true }, "files": ["src/app.ts"] }');
    write(root, 'src/package.json', '{ "type": "module", "imports": { "#dep": "./dep.ts" } }');
    write(root, 'src/app.ts', 'import { value } from "#dep";\nexport { value };\n');
    write(root, 'src/dep.ts', 'export const value = 1;\n');
    write(outside, 'package.json', '{ "type": "module", "imports": { "#dep": "./outside.ts" } }');
    write(outside, 'outside.ts', 'export const value = 2;\n');
    let retargeted = false;

    await expectFailure(loadTypeScriptProject(options(root, {
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        readFileBounded(filePath, maxBytes) {
          if (!retargeted && filePath.endsWith('src/package.json')) {
            retargeted = true;
            fs.renameSync(path.join(root, 'src'), path.join(root, 'src-safe'));
            fs.symlinkSync(outside, path.join(root, 'src'));
          }
          return nodeTypeScriptProjectFileSystem.readFileBounded(filePath, maxBytes);
        },
      },
    })), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);
    expect(retargeted).toBe(true);
  });

  test('rejects a config retargeted outside before its bounded read', async () => {
    const root = workspace();
    const outside = workspace();
    write(root, 'tsconfig.json', '{ "files": ["src/app.ts"] }');
    write(root, 'src/app.ts', 'export const value = 1;\n');
    write(outside, 'outside.json', '{ "files": ["outside.ts"] }');
    let retargeted = false;

    await expectFailure(loadTypeScriptProject(options(root, {
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        readFileBounded(filePath, maxBytes) {
          if (!retargeted && filePath.endsWith('tsconfig.json')) {
            retargeted = true;
            fs.unlinkSync(filePath);
            fs.symlinkSync(path.join(outside, 'outside.json'), filePath);
          }
          return nodeTypeScriptProjectFileSystem.readFileBounded(filePath, maxBytes);
        },
      },
    })), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);
    expect(retargeted).toBe(true);
  });

  test('fails closed on source retargets and unexpected resolution errors', async () => {
    const outside = workspace();
    write(outside, 'outside.ts', 'export const value = 2;\n');

    const root = workspace();
    write(root, 'tsconfig.json', '{ "compilerOptions": { "noLib": true }, "files": ["src/app.ts"] }');
    write(root, 'src/app.ts', 'export const value = 1;\n');
    await expectFailure(loadTypeScriptProject(options(root, {
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        readFileBounded(filePath, maxBytes) {
          if (filePath.endsWith('src/app.ts')) {
            fs.renameSync(filePath, `${filePath}.safe`);
            fs.symlinkSync(path.join(outside, 'outside.ts'), filePath);
          }
          return nodeTypeScriptProjectFileSystem.readFileBounded(filePath, maxBytes);
        },
      },
    })), 'TS_PROJECT_PATH_OUTSIDE_ROOT', root);

    const deletedRoot = workspace();
    write(deletedRoot, 'tsconfig.json', '{ "compilerOptions": { "noLib": true }, "files": ["src/app.ts"] }');
    write(deletedRoot, 'src/app.ts', 'export const value = 1;\n');
    await expectFailure(loadTypeScriptProject(options(deletedRoot, {
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        readFileBounded(filePath, maxBytes) {
          const text = nodeTypeScriptProjectFileSystem.readFileBounded(filePath, maxBytes);
          if (filePath.endsWith('src/app.ts')) fs.unlinkSync(filePath);
          return text;
        },
      },
    })), 'TS_PROJECT_INTERNAL', deletedRoot);

    const dependencyRoot = workspace();
    write(dependencyRoot, 'tsconfig.json', '{ "compilerOptions": { "noLib": true }, "files": ["src/app.ts"] }');
    write(dependencyRoot, 'src/app.ts', 'import { value } from "./dep";\nexport { value };\n');
    write(dependencyRoot, 'src/dep.ts', 'export const value = 1;\n');
    let dependencyRetargeted = false;
    await expectFailure(loadTypeScriptProject(options(dependencyRoot, {
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        readFileBounded(filePath, maxBytes) {
          if (!dependencyRetargeted && filePath.endsWith('src/dep.ts')) {
            dependencyRetargeted = true;
            fs.renameSync(filePath, `${filePath}.safe`);
            fs.symlinkSync(path.join(outside, 'outside.ts'), filePath);
          }
          return nodeTypeScriptProjectFileSystem.readFileBounded(filePath, maxBytes);
        },
      },
    })), 'TS_PROJECT_PATH_OUTSIDE_ROOT', dependencyRoot);
    expect(dependencyRetargeted).toBe(true);

    const deletedDependencyRoot = workspace();
    write(deletedDependencyRoot, 'tsconfig.json', '{ "compilerOptions": { "noLib": true }, "files": ["src/app.ts"] }');
    write(deletedDependencyRoot, 'src/app.ts', 'import { value } from "./dep";\nexport { value };\n');
    write(deletedDependencyRoot, 'src/dep.ts', 'export const value = 1;\n');
    await expectFailure(loadTypeScriptProject(options(deletedDependencyRoot, {
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        readFileBounded(filePath, maxBytes) {
          const text = nodeTypeScriptProjectFileSystem.readFileBounded(filePath, maxBytes);
          if (filePath.endsWith('src/dep.ts')) fs.unlinkSync(filePath);
          return text;
        },
      },
    })), 'TS_PROJECT_INTERNAL', deletedDependencyRoot);

    const resolutionRoot = workspace();
    write(resolutionRoot, 'tsconfig.json', '{ "compilerOptions": { "noLib": true }, "files": ["src/app.ts"] }');
    write(resolutionRoot, 'src/app.ts', 'import { value } from "./dep";\nexport { value };\n');
    write(resolutionRoot, 'src/dep.ts', 'export const value = 1;\n');
    await expectFailure(loadTypeScriptProject(options(resolutionRoot, {
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        realpath(filePath) {
          if (filePath.endsWith('src/dep.ts')) {
            throw Object.assign(new Error('denied'), { code: 'EACCES' });
          }
          return nodeTypeScriptProjectFileSystem.realpath(filePath);
        },
      },
    })), 'TS_PROJECT_INTERNAL', resolutionRoot);

    const includeRoot = workspace();
    write(includeRoot, 'tsconfig.json', '{ "compilerOptions": { "noLib": true }, "include": ["src/**/*.ts"] }');
    write(includeRoot, 'src/app.ts', 'export const value = 1;\n');
    await expectFailure(loadTypeScriptProject(options(includeRoot, {
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        realpath(filePath) {
          if (filePath.endsWith('src/app.ts')) {
            throw Object.assign(new Error('denied'), { code: 'EACCES' });
          }
          return nodeTypeScriptProjectFileSystem.realpath(filePath);
        },
      },
    })), 'TS_PROJECT_INTERNAL', includeRoot);

    const directoryRoot = workspace();
    write(directoryRoot, 'tsconfig.json', '{ "compilerOptions": { "noLib": true, "moduleResolution": "node" }, "files": ["src/app.ts"] }');
    write(directoryRoot, 'src/app.ts', 'import value from "missing";\nexport { value };\n');
    await expectFailure(loadTypeScriptProject(options(directoryRoot, {
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        realpath(filePath) {
          if (filePath.endsWith('src/node_modules')) {
            throw Object.assign(new Error('denied'), { code: 'EACCES' });
          }
          return nodeTypeScriptProjectFileSystem.realpath(filePath);
        },
      },
    })), 'TS_PROJECT_INTERNAL', directoryRoot);

    const enumerationRoot = workspace();
    write(enumerationRoot, 'tsconfig.json', '{ "compilerOptions": { "noLib": true, "types": ["*"], "typeRoots": ["types"] }, "files": ["src/app.ts"] }');
    write(enumerationRoot, 'src/app.ts', 'export const value = 1;\n');
    fs.mkdirSync(path.join(enumerationRoot, 'types/example'), { recursive: true });
    let typeRootResolutions = 0;
    await expectFailure(loadTypeScriptProject(options(enumerationRoot, {
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        realpath(filePath) {
          if (filePath.endsWith('/types') && ++typeRootResolutions === 3) {
            throw Object.assign(new Error('denied'), { code: 'EACCES' });
          }
          return nodeTypeScriptProjectFileSystem.realpath(filePath);
        },
      },
    })), 'TS_PROJECT_INTERNAL', enumerationRoot);

    const reusedRoot = workspace();
    write(reusedRoot, 'tsconfig.json', '{ "compilerOptions": { "noLib": true }, "files": ["src/app.ts"] }');
    write(reusedRoot, 'src/app.ts', 'export const value = 1;\n');
    let sourceResolutions = 0;
    await expectFailure(loadTypeScriptProject(options(reusedRoot, {
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        realpath(filePath) {
          if (filePath.endsWith('src/app.ts') && ++sourceResolutions === 5) {
            throw Object.assign(new Error('denied'), { code: 'EACCES' });
          }
          return nodeTypeScriptProjectFileSystem.realpath(filePath);
        },
      },
    })), 'TS_PROJECT_INTERNAL', reusedRoot);
  }, 15_000);

  test('enforces AST limits before loading remaining dependencies', async () => {
    const root = workspace();
    write(root, 'tsconfig.json', '{ "compilerOptions": { "noLib": true }, "files": ["src/app.ts"] }');
    write(root, 'src/app.ts', 'import { value } from "./dep";\nexport { value };\n');
    write(root, 'src/dep.ts', 'export const value = 1;\n');
    let dependencyRead = false;

    await expectFailure(loadTypeScriptProject(options(root, {
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxAstNodes: 1 },
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        readFileBounded(filePath, maxBytes) {
          if (filePath.endsWith('src/dep.ts')) dependencyRead = true;
          return nodeTypeScriptProjectFileSystem.readFileBounded(filePath, maxBytes);
        },
      },
    })), 'TS_PROJECT_AST_NODE_LIMIT', root);
    expect(dependencyRead).toBe(false);
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

    write(root, 'configs/app.json', '{ "files": ["../src/app.ts"], "references": [{ "path": ".." }] }');
    const rootReference = await loadTypeScriptProject(options(root, { tsconfigPath: 'configs/app.json' }));
    expect(rootReference.projectReferences).toBe('partial');
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
    write(root, 'scan/one.txt', 'one');
    write(root, 'scan/two.txt', 'two');
    write(root, 'scan/three.txt', 'three');
    fs.mkdirSync(path.join(root, 'scan-special'));
    for (const name of ['one', 'two', 'three']) {
      fs.symlinkSync('/dev/null', path.join(root, 'scan-special', name));
    }

    expect(() => nodeTypeScriptProjectFileSystem.readDirectory(
      path.join(root, 'scan'), ['.ts'], undefined, ['**/*'], undefined, 2,
    )).toThrow('TypeScript project file limit was exceeded.');
    expect(() => nodeTypeScriptProjectFileSystem.readDirectory(
      path.join(root, 'scan-special'), ['.ts'], undefined, ['**/*'], undefined, 2,
    )).toThrow('TypeScript project file limit was exceeded.');
    expect(() => nodeTypeScriptProjectFileSystem.readDirectory(
      path.join(root, 'missing'), ['.ts'], undefined, ['**/*'], undefined, 2,
    )).toThrow('TypeScript project loading failed unexpectedly.');

    write(root, 'tsconfig.json', '{ "compilerOptions": { "noLib": true, "types": ["*"] }, "files": ["src/app.ts"] }');
    for (const name of ['one', 'two', 'three', 'four']) {
      fs.mkdirSync(path.join(root, 'node_modules/@types', name), { recursive: true });
    }
    let compilerEnumerationLimit: number | undefined;
    await expectFailure(loadTypeScriptProject(options(root, {
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxFiles: 3 },
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        getDirectories(...args) {
          compilerEnumerationLimit = args[1];
          return nodeTypeScriptProjectFileSystem.getDirectories(...args);
        },
      },
    })), 'TS_PROJECT_FILE_LIMIT', root);
    expect(compilerEnumerationLimit).toBe(1);

    write(root, 'tsconfig.json', '{ "compilerOptions": { "noLib": true, "types": ["*"], "typeRoots": ["types/one", "types/two"] }, "files": ["src/app.ts"] }');
    for (const rootName of ['one', 'two']) {
      for (const packageName of ['a', 'b']) fs.mkdirSync(path.join(root, 'types', rootName, packageName), { recursive: true });
    }
    await expectFailure(loadTypeScriptProject(options(root, {
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxFiles: 5 },
    })), 'TS_PROJECT_FILE_LIMIT', root);

    write(root, 'tsconfig.json', '{ "include": ["src/**/*.ts"] }');
    let enumerationLimit: number | undefined;
    await expectFailure(loadTypeScriptProject(options(root, {
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxFiles: 1 },
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        readDirectory(_rootDir, _extensions, _excludes, _includes, _depth, maxEntries) {
          enumerationLimit = maxEntries;
          return ['one.ts', 'two.ts'];
        },
      },
    })), 'TS_PROJECT_FILE_LIMIT', root);
    expect(enumerationLimit).toBe(1);

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

  test('accounts for standard libraries and config size in project-wide limits', async () => {
    const root = workspace();
    const config = `{ "compilerOptions": { "strict": true }, "files": ["src/app.ts"] }${' '.repeat(64)}`;
    const source = 'export const value = 1;\n';
    write(root, 'tsconfig.json', config);
    write(root, 'src/app.ts', source);

    await expectFailure(loadTypeScriptProject(options(root, {
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxFiles: 2 },
    })), 'TS_PROJECT_FILE_LIMIT', root);
    await expectFailure(loadTypeScriptProject(options(root, {
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxFileBytes: Buffer.byteLength(config) + 1 },
    })), 'TS_PROJECT_FILE_BYTES_LIMIT', root);

    write(root, 'tsconfig.json', `{ "compilerOptions": { "noLib": true }, "files": ["src/app.ts"] }${' '.repeat(64)}`);
    const loaded = await loadTypeScriptProject(options(root));
    expect(loaded.metrics.largestFileBytes).toBe(fs.statSync(path.join(root, 'tsconfig.json')).size);

    write(root, 'tsconfig.json', config);
    const withLibrary = await loadTypeScriptProject(options(root));
    expect(withLibrary.metrics.astNodes).toBeGreaterThan(loaded.metrics.astNodes);
    await expectFailure(loadTypeScriptProject(options(root, {
      limits: { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, maxAstNodes: loaded.metrics.astNodes },
    })), 'TS_PROJECT_AST_NODE_LIMIT', root);
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
        readFileBounded(filePath, maxBytes) {
          const text = nodeTypeScriptProjectFileSystem.readFileBounded(filePath, maxBytes);
          if (filePath.endsWith('src/app.ts')) duringRead.abort();
          return text;
        },
      },
    })), 'TS_PROJECT_CANCELLED', root);

    const scheduled = new AbortController();
    await expectFailure(loadTypeScriptProject(options(root, {
      cancellationSignal: scheduled.signal,
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        readFileBounded(filePath, maxBytes) {
          const text = nodeTypeScriptProjectFileSystem.readFileBounded(filePath, maxBytes);
          if (filePath.endsWith('src/app.ts')) setTimeout(() => scheduled.abort(), 0);
          return text;
        },
      },
    })), 'TS_PROJECT_CANCELLED', root);

    await expectFailure(loadTypeScriptProject(options(root, {
      fileSystem: {
        ...nodeTypeScriptProjectFileSystem,
        readFileBounded(filePath, maxBytes) {
          if (filePath.endsWith('src/app.ts')) throw new Error(`${root}/secret source failure`);
          return nodeTypeScriptProjectFileSystem.readFileBounded(filePath, maxBytes);
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
