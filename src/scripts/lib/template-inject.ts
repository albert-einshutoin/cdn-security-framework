type RuntimeLiteral = { __runtimeCode: string };
type AssertInjectedConstOptions = {
  loader?: 'js' | 'ts';
};

function runtimeCode(code: string): RuntimeLiteral {
  return { __runtimeCode: code };
}

function isRuntimeLiteral(value: unknown): value is RuntimeLiteral {
  return Boolean(
    value &&
      typeof value === 'object' &&
      typeof (value as RuntimeLiteral).__runtimeCode === 'string',
  );
}

function renderValue(value: unknown): string {
  if (isRuntimeLiteral(value)) return value.__runtimeCode;
  return JSON.stringify(value);
}

function renderConstObject(name: string, value: Record<string, unknown>): string {
  const lines = [`const ${name} = {`];
  for (const [key, entryValue] of Object.entries(value)) {
    lines.push(`  ${key}: ${renderValue(entryValue)},`);
  }
  lines.push('};');
  return lines.join('\n');
}

function injectTemplateCode(template: string, marker: string, code: string): string {
  const count = template.split(marker).length - 1;
  if (count !== 1) {
    throw new Error(`Template marker ${marker} must appear exactly once, found ${count}`);
  }
  // A callback prevents String.replace from interpreting policy-derived `$&`,
  // `$\`` and related replacement tokens.
  return template.replace(marker, () => code);
}

const CLOUDFRONT_FUNCTION_MAX_BYTES = 10 * 1024;

function optimizeCloudFrontFunction(source: string, fileName: string): string {
  const esbuild = require('esbuild');
  const transformed = esbuild.transformSync(`${source}\nexport { handler };`, {
    loader: 'js',
    format: 'esm',
    target: 'es2020',
    treeShaking: true,
    minify: true,
    legalComments: 'none',
  }).code.trim();
  const exportMatch = /export\{([A-Za-z_$][\w$]*) as handler\};?$/.exec(transformed);
  if (!exportMatch) {
    throw new Error(`Unable to preserve the CloudFront handler export in ${fileName}`);
  }
  const optimized = `${transformed.slice(0, exportMatch.index)}function handler(event){return ${exportMatch[1]}(event)}\n`;
  const bytes = Buffer.byteLength(optimized, 'utf8');
  if (bytes > CLOUDFRONT_FUNCTION_MAX_BYTES) {
    throw new Error(
      `${fileName} is ${bytes} bytes after optimization; CloudFront Functions allow at most ${CLOUDFRONT_FUNCTION_MAX_BYTES} bytes`,
    );
  }
  return optimized;
}

function parseForConstInspection(code: string, loader: 'js' | 'ts') {
  const acorn = require('acorn');
  let jsCode = code;
  if (loader === 'ts') {
    const esbuild = require('esbuild');
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

function assertInjectedConstDeclarations(
  code: string,
  constNames: string[],
  options: AssertInjectedConstOptions = {},
) {
  const loader = options.loader || 'js';
  const ast = parseForConstInspection(code, loader);
  for (const constName of constNames) {
    let count = 0;
    for (const node of ast.body || []) {
      if (node.type !== 'VariableDeclaration' || node.kind !== 'const') continue;
      for (const declaration of node.declarations || []) {
        if (
          declaration.id &&
          declaration.id.type === 'Identifier' &&
          declaration.id.name === constName
        ) {
          count += 1;
        }
      }
    }
    if (count !== 1) {
      throw new Error(`Injected config const ${constName} must appear exactly once at top level, found ${count}`);
    }
  }
}

module.exports = {
  assertInjectedConstDeclarations,
  injectTemplateCode,
  optimizeCloudFrontFunction,
  renderConstObject,
  runtimeCode,
};
