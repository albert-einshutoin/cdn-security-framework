const assert = require('assert');
const fs = require('fs');
const path = require('path');

const repoRoot = path.join(__dirname, '..');
const api = require(path.join(repoRoot, 'lib'));

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
