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

function specializeWorker(source: string, features: Record<string, boolean>): string {
  for (const [name, enabled] of Object.entries(features)) {
    source = injectTemplateCode(source, `/* {{FEATURE_${name}}} */ true`, String(enabled));
  }
  const boundary = source.indexOf('\n// {{RUNTIME}}\n');
  if (boundary < 0) throw new Error('Worker runtime boundary missing');
  return source.slice(0, boundary) + require('esbuild').transformSync(source.slice(boundary), {
    loader: 'ts', format: 'esm', target: 'es2022', treeShaking: true,
    minifySyntax: true, legalComments: 'none',
  }).code;
}

function minifyCloudFrontFunction(source: string, fileName: string, literals: Record<string, string>): string {
  const esbuild = require('esbuild');
  if (Object.keys(literals).length > 0) {
    const boundary = source.indexOf('\n// {{RUNTIME}}\n');
    if (boundary < 0) throw new Error('CloudFront runtime boundary missing');
    // Policy strings remain in the config prefix; only repository-owned runtime
    // expressions are specialized, so arbitrary policy text stays byte-for-byte.
    let runtime = source.slice(boundary);
    for (const [expression, literal] of Object.entries(literals)) runtime = runtime.split(expression).join(literal);
    source = source.slice(0, boundary) + runtime;
  }
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
  return optimized;
}

function optimizeCloudFrontFunction(source: string, fileName: string, literals: Record<string, string> = {}, arraySource?: () => string): string {
  let optimized = minifyCloudFrontFunction(source, fileName, literals);
  // Select one algorithm before any write. Only a measured deployment-size
  // excess can select arrays; malformed code and all other failures propagate.
  if (Buffer.byteLength(optimized, 'utf8') > CLOUDFRONT_FUNCTION_MAX_BYTES && arraySource) {
    optimized = minifyCloudFrontFunction(arraySource(), fileName, literals);
  }
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
  specializeWorker,
};
