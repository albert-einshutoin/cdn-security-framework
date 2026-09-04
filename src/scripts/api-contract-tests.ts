const assert = require('assert');
const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const repoRoot = path.join(__dirname, '..');
const api = require(path.join(repoRoot, 'lib'));

type ManifestEntrypoint = {
  status: 'stable' | 'experimental' | 'internal';
  release: 'existing' | 'additive';
  require?: string;
  default?: string;
  types?: string;
  file?: string;
  exports: string[];
};

type PackageManifest = {
  schemaVersion: number;
  packageVersion: string;
  packageVersionSource: string;
  entrypoints: Record<string, ManifestEntrypoint>;
  schemas: Array<{ path: string; status: ManifestEntrypoint['status']; release: ManifestEntrypoint['release'] }>;
  bins: Record<string, string>;
  requiredPackageFiles: string[];
  internalPaths: Array<{ path: string; reason: string }>;
};

const manifest = require(path.join(repoRoot, 'docs', 'api-manifest.json')) as PackageManifest;

function test(name: string, fn: () => void) {
  try {
    fn();
    console.log(`OK: ${name}`);
  } catch (err: unknown) {
    console.error(`FAIL: ${name}`);
    console.error(err);
    process.exitCode = 1;
  }
}

test('api exports stable callable surface', () => {
  assert.strictEqual(typeof api.compile, 'function');
  assert.strictEqual(typeof api.emitWaf, 'function');
  assert.strictEqual(typeof api.lintPolicy, 'function');
  assert.strictEqual(typeof api.migratePolicy, 'function');
  assert.strictEqual(typeof api.runDoctor, 'function');
});

test('package prepare script builds tsc artifacts on install', () => {
  const pkg = require(path.join(repoRoot, 'package.json'));
  assert.strictEqual(pkg.scripts.prepare, 'npm run build:ts');
  assert.ok(pkg.scripts['build:ts'].includes('--incremental false'));
  assert.ok(pkg.scripts['build:ts'].includes('scripts/ensure-cli-executable.js'));
});

test('package metadata exposes typed root api and bounded exports', () => {
  const pkg = require(path.join(repoRoot, 'package.json'));
  assert.strictEqual(pkg.main, 'lib/index.js');
  assert.strictEqual(pkg.types, 'lib/index.d.ts');
  assert.deepStrictEqual(Object.keys(pkg.exports).sort(), [
    '.',
    './bin/cli',
    './bin/cli.js',
    './contract',
    './contract/security-ir',
    './emitter',
    './openapi',
    './parser',
    './recommendation',
    './schemas/contract-diff-report-v1.schema.json',
    './schemas/finding-exceptions-v1.schema.json',
    './schemas/finding-v1.schema.json',
    './schemas/nestjs-source-analysis-options.schema.json',
    './schemas/openapi-inspection-v1.schema.json',
    './schemas/security-ir-v1.schema.json',
    './source-analysis',
    './source/nestjs',
    './validator',
  ]);
  assert.strictEqual(pkg.exports['.'].types, './lib/index.d.ts');
  assert.strictEqual(pkg.exports['.'].require, './lib/index.js');
  assert.strictEqual(pkg.exports['./parser'].types, './parser/index.d.ts');
  assert.strictEqual(pkg.exports['./parser'].require, './parser/index.js');
  assert.strictEqual(pkg.exports['./validator'].types, './validator/index.d.ts');
  assert.strictEqual(pkg.exports['./validator'].require, './validator/index.js');
  assert.strictEqual(pkg.exports['./emitter'].types, './emitter/index.d.ts');
  assert.strictEqual(pkg.exports['./emitter'].require, './emitter/index.js');
  assert.strictEqual(pkg.exports['./contract'].require, './contract/index.js');
  assert.strictEqual(pkg.exports['./contract/security-ir'].types, './contract/security-ir.d.ts');
  assert.strictEqual(pkg.exports['./openapi'].require, './openapi/index.js');
  assert.strictEqual(pkg.exports['./recommendation'].require, './recommendation/index.js');
  assert.strictEqual(pkg.exports['./source-analysis'].require, './source-analysis/index.js');
  assert.strictEqual(pkg.exports['./source/nestjs'].require, './source/nestjs/index.js');
  assert.strictEqual(
    pkg.exports['./schemas/finding-exceptions-v1.schema.json'],
    './schemas/finding-exceptions-v1.schema.json',
  );
  assert.strictEqual(
    pkg.exports['./schemas/security-ir-v1.schema.json'],
    './schemas/security-ir-v1.schema.json',
  );
  assert.strictEqual(
    pkg.exports['./schemas/openapi-inspection-v1.schema.json'],
    './schemas/openapi-inspection-v1.schema.json',
  );
  assert.strictEqual(
    pkg.exports['./schemas/nestjs-source-analysis-options.schema.json'],
    './schemas/nestjs-source-analysis-options.schema.json',
  );
  assert.strictEqual(pkg.exports['./bin/cli.js'], './bin/cli.js');
});

test('machine-readable package manifest matches exports, files, schemas, and bins', () => {
  const pkg = require(path.join(repoRoot, 'package.json'));
  assert.strictEqual(manifest.schemaVersion, 1);
  assert.strictEqual(manifest.packageVersion, pkg.version);
  assert.strictEqual(manifest.packageVersionSource, 'package.json');

  const manifestEntrypoints = Object.keys(manifest.entrypoints).sort();
  const exportEntrypoints = Object.keys(pkg.exports)
    .filter((key) => !key.startsWith('./schemas/'))
    .sort();
  assert.deepStrictEqual(manifestEntrypoints, exportEntrypoints);

  for (const [entrypoint, declaration] of Object.entries(manifest.entrypoints)) {
    assert.ok(['stable', 'experimental', 'internal'].includes(declaration.status));
    assert.ok(['existing', 'additive'].includes(declaration.release));
    const actual = pkg.exports[entrypoint];
    const resolvePackageFile = (file: string) => path.join(repoRoot, file.replace(/^\.\//u, ''));
    if (typeof actual === 'string') {
      if (!declaration.file) throw new Error(`${entrypoint} manifest file is missing`);
      assert.strictEqual(actual, `./${declaration.file}`);
      assert.ok(fs.existsSync(resolvePackageFile(declaration.file)), `${entrypoint} file is missing`);
      continue;
    }
    if (!declaration.require || !declaration.types) {
      throw new Error(`${entrypoint} manifest require/types are missing`);
    }
    assert.deepStrictEqual(Object.keys(actual).sort(), ['default', 'require', 'types']);
    assert.strictEqual(actual.require, declaration.require);
    assert.strictEqual(actual.default, declaration.default);
    assert.strictEqual(actual.types, declaration.types);
    assert.ok(fs.existsSync(resolvePackageFile(declaration.require)), `${entrypoint} require file is missing`);
    assert.ok(fs.existsSync(resolvePackageFile(declaration.types)), `${entrypoint} types file is missing`);
    const actualKeys = Object.keys(require(resolvePackageFile(actual.require))).sort();
    assert.deepStrictEqual(actualKeys, [...declaration.exports].sort(), `${entrypoint} export keys drifted`);
  }

  const schemaExportKeys = Object.keys(pkg.exports)
    .filter((key) => key.startsWith('./schemas/'))
    .sort();
  const manifestSchemaKeys = manifest.schemas.map((schema: { path: string }) => `./${schema.path}`).sort();
  assert.deepStrictEqual(manifestSchemaKeys, schemaExportKeys);
  for (const schema of manifest.schemas) {
    assert.ok(['stable', 'experimental', 'internal'].includes(schema.status));
    assert.ok(['existing', 'additive'].includes(schema.release));
    assert.ok(fs.existsSync(path.join(repoRoot, schema.path)), `${schema.path} is missing`);
  }

  assert.deepStrictEqual(manifest.bins, pkg.bin);
  for (const file of manifest.requiredPackageFiles) {
    assert.ok(fs.existsSync(path.join(repoRoot, file)), `${file} is missing from the source package`);
  }
  for (const internal of manifest.internalPaths) {
    assert.ok(internal.path && internal.reason);
    assert.ok(!Object.keys(pkg.exports).some((key) => key.startsWith(`./${internal.path}`)));
  }
});

test('public imports are side-effect free from an unrelated cwd', () => {
  const importPaths = Object.values(manifest.entrypoints)
    .filter((entrypoint) => entrypoint.require)
    .map((entrypoint) => path.join(repoRoot, entrypoint.require!.replace(/^\.\//u, '')));
  const script = `for (const file of ${JSON.stringify(importPaths)}) require(file); console.log('IMPORTS_COMPLETE');`;
  const result = childProcess.spawnSync(process.execPath, ['-e', script], {
    cwd: os.tmpdir(),
    env: { PATH: process.env.PATH || '' },
    encoding: 'utf8',
  });
  assert.strictEqual(result.status, 0, result.stderr);
  assert.strictEqual(result.stdout, 'IMPORTS_COMPLETE\n');
  assert.strictEqual(result.stderr, '');
});

test('phase subpath exports expose public compiler contracts', () => {
  const parser = require(path.join(repoRoot, 'parser'));
  const validator = require(path.join(repoRoot, 'validator'));
  const emitter = require(path.join(repoRoot, 'emitter'));
  const contract = require(path.join(repoRoot, 'contract'));
  const openapi = require(path.join(repoRoot, 'openapi'));
  const recommendation = require(path.join(repoRoot, 'recommendation'));
  assert.strictEqual(typeof parser.parsePolicyFile, 'function');
  assert.strictEqual(typeof validator.validatePolicy, 'function');
  assert.strictEqual(typeof emitter.compileArtifacts, 'function');
  assert.strictEqual(typeof contract.createSecurityContract, 'function');
  assert.strictEqual(typeof contract.projectPolicyToAllowedSurface, 'function');
  assert.strictEqual(typeof contract.relateRoute, 'function');
  assert.strictEqual(typeof contract.compareSecurityContracts, 'function');
  assert.strictEqual(typeof contract.compareSourcePolicyContracts, 'function');
  assert.strictEqual(typeof contract.loadFindingExceptions, 'function');
  assert.strictEqual(typeof contract.applyFindingExceptions, 'function');
  assert.strictEqual(typeof contract.diffSecurityContracts, 'function');
  assert.strictEqual(typeof contract.renderFindingsAsSarif, 'function');
  assert.strictEqual(typeof contract.contractDiffExitCode, 'function');
  assert.strictEqual(typeof openapi.loadOpenApiDocument, 'function');
  assert.strictEqual(typeof openapi.resolveOpenApiReferences, 'function');
  assert.strictEqual(typeof openapi.serializeResolvedOpenApiGraph, 'function');
  assert.strictEqual(typeof openapi.normalizeOpenApiOperations, 'function');
  assert.strictEqual(typeof openapi.inspectOpenApi, 'function');
  assert.strictEqual(typeof openapi.generatePolicyCandidate, 'function');
  assert.strictEqual(typeof recommendation.recommendRequestLimits, 'function');

  const phaseDeclarations = [
    ['parser/index.d.ts', 'parsePolicyFile'],
    ['validator/index.d.ts', 'validatePolicy'],
    ['emitter/index.d.ts', 'compileArtifacts'],
  ];
  for (const [file, name] of phaseDeclarations) {
    const dts = fs.readFileSync(path.join(repoRoot, file), 'utf8');
    assert.ok(dts.includes(`export declare function ${name}`), `${file} must declare ${name}`);
  }
  const contractDeclarations = fs.readFileSync(path.join(repoRoot, 'contract/index.d.ts'), 'utf8');
  assert.ok(contractDeclarations.includes('diffSecurityContracts'));
  assert.ok(contractDeclarations.includes('renderFindingsAsSarif'));
});

test('root type declarations expose public programmatic api', () => {
  const dts = fs.readFileSync(path.join(repoRoot, 'lib', 'index.d.ts'), 'utf8');
  for (const name of ['compile', 'emitWaf', 'lintPolicy', 'migratePolicy', 'runDoctor']) {
    assert.ok(
      dts.includes(`export declare const ${name}`),
      `lib/index.d.ts must declare ${name}`,
    );
  }
  assert.ok(dts.includes('export interface CompileOptions'));
  assert.ok(dts.includes('export interface DoctorResult'));
});

test('api compile missing policyPath returns structured error', () => {
  const result = api.compile({ outDir: 'dist', cwd: repoRoot, pkgRoot: repoRoot });
  assert.strictEqual(result.ok, false);
  assert.ok(Array.isArray(result.errors));
  assert.ok(Array.isArray(result.warnings));
  assert.ok(result.errors.includes('policyPath is required'));
});

test('api lintPolicy missing policyPath returns structured error', () => {
  const result = api.lintPolicy({ cwd: repoRoot, pkgRoot: repoRoot });
  assert.strictEqual(result.ok, false);
  assert.ok(Array.isArray(result.errors));
  assert.ok(Array.isArray(result.warnings));
});

test('cli entrypoint exists and keeps shebang', () => {
  const cliPath = path.join(repoRoot, 'bin', 'cli.js');
  const firstLine = fs.readFileSync(cliPath, 'utf8').split('\n')[0];
  assert.strictEqual(firstLine, '#!/usr/bin/env node');
});
