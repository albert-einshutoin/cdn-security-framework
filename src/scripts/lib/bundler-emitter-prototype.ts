const acorn = require('acorn');
const esbuild = require('esbuild');

export type BundlerEmitterPrototypeLoader = 'js' | 'ts';

export type BundlerEmitterPrototypeOptions = {
  source: string;
  configExports: Record<string, unknown>;
  sourcefile?: string;
  loader?: BundlerEmitterPrototypeLoader;
  configModuleName?: string;
};

export type BundlerEmitterPrototypeResult = {
  code: string;
  configNames: string[];
};

type AstNode = {
  type?: string;
  source?: { value?: string };
  specifiers?: AstNode[];
  local?: { name?: string };
  id?: AstNode | null;
  name?: string;
  params?: AstNode[];
  declarations?: AstNode[];
  body?: AstNode[] | AstNode;
  [key: string]: unknown;
};

function parseForPrototypeInspection(code: string, loader: BundlerEmitterPrototypeLoader): AstNode {
  let jsCode = code;
  if (loader === 'ts') {
    jsCode = esbuild.transformSync(code, {
      loader: 'ts',
      format: 'esm',
      target: 'es2022',
    }).code;
  }
  return acorn.parse(jsCode, {
    ecmaVersion: 'latest',
    sourceType: 'module',
  });
}

function visitNode(node: unknown, visit: (node: AstNode) => void): void {
  if (!node || typeof node !== 'object') return;
  const astNode = node as AstNode;
  visit(astNode);
  for (const [key, value] of Object.entries(astNode)) {
    if (key === 'parent') continue;
    if (Array.isArray(value)) {
      for (const item of value) visitNode(item, visit);
    } else if (value && typeof value === 'object') {
      visitNode(value, visit);
    }
  }
}

function identifierName(node: AstNode | null | undefined): string | null {
  return node && node.type === 'Identifier' && typeof node.name === 'string'
    ? node.name
    : null;
}

function collectBindingNames(node: AstNode, names: Set<string>, moduleName: string): string[] {
  const matches: string[] = [];
  visitNode(node, (entry) => {
    if (entry.type === 'ImportDeclaration') {
      if (entry.source && entry.source.value === moduleName) return;
      for (const specifier of entry.specifiers || []) {
        const local = identifierName(specifier.local || null);
        if (local && names.has(local)) matches.push(local);
      }
      return;
    }

    if (entry.type === 'VariableDeclarator') {
      const name = identifierName(entry.id || null);
      if (name && names.has(name)) matches.push(name);
      return;
    }

    if (
      entry.type === 'FunctionDeclaration' ||
      entry.type === 'FunctionExpression' ||
      entry.type === 'ArrowFunctionExpression'
    ) {
      const name = identifierName(entry.id || null);
      if (name && names.has(name)) matches.push(name);
      for (const param of entry.params || []) {
        const paramName = identifierName(param);
        if (paramName && names.has(paramName)) matches.push(paramName);
      }
      return;
    }

    if (entry.type === 'ClassDeclaration' || entry.type === 'ClassExpression') {
      const name = identifierName(entry.id || null);
      if (name && names.has(name)) matches.push(name);
    }
  });
  return matches;
}

export function assertNoConfigBindingShadow(
  source: string,
  configNames: string[],
  options: { loader?: BundlerEmitterPrototypeLoader; configModuleName?: string } = {},
): void {
  const loader = options.loader || 'js';
  const moduleName = options.configModuleName || 'cdn-security:config';
  const names = new Set(configNames);
  const ast = parseForPrototypeInspection(source, loader);
  const matches = collectBindingNames(ast, names, moduleName);
  if (matches.length > 0) {
    throw new Error(
      `Bundler emitter prototype source shadows config binding(s): ${Array.from(new Set(matches)).join(', ')}`,
    );
  }
}

export function assertBundledConfigBindings(code: string, configNames: string[]): void {
  const ast = parseForPrototypeInspection(code, 'js');
  const body = Array.isArray(ast.body) ? ast.body : [];
  for (const configName of configNames) {
    let count = 0;
    for (const node of body) {
      if (
        node.type !== 'VariableDeclaration' ||
        !Array.isArray(node.declarations)
      ) {
        continue;
      }
      for (const declaration of node.declarations) {
        if (identifierName(declaration.id || null) === configName) {
          count += 1;
        }
      }
    }
    if (count !== 1) {
      throw new Error(`Bundled config binding ${configName} must appear exactly once at top level, found ${count}`);
    }
  }
}

function renderConfigModule(configExports: Record<string, unknown>): string {
  return Object.entries(configExports)
    .map(([name, value]) => `export const ${name} = ${JSON.stringify(value)};`)
    .join('\n');
}

export async function buildBundlerEmitterPrototype(
  options: BundlerEmitterPrototypeOptions,
): Promise<BundlerEmitterPrototypeResult> {
  const loader = options.loader || 'js';
  const configModuleName = options.configModuleName || 'cdn-security:config';
  const configNames = Object.keys(options.configExports);
  assertNoConfigBindingShadow(options.source, configNames, { loader, configModuleName });

  const result = await esbuild.build({
    stdin: {
      contents: options.source,
      sourcefile: options.sourcefile || 'edge-entry.js',
      loader,
    },
    bundle: true,
    write: false,
    format: 'esm',
    platform: 'neutral',
    target: 'es2022',
    plugins: [{
      name: 'cdn-security-config-prototype',
      setup(build: any) {
        build.onResolve({ filter: new RegExp(`^${configModuleName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`) }, (args: any) => ({
          path: args.path,
          namespace: 'cdn-security-config',
        }));
        build.onLoad({ filter: /.*/, namespace: 'cdn-security-config' }, () => ({
          contents: renderConfigModule(options.configExports),
          loader: 'js',
        }));
      },
    }],
  });

  const code = result.outputFiles[0].text;
  assertBundledConfigBindings(code, configNames);
  return { code, configNames };
}
