#!/usr/bin/env node

const assert = require('assert');
const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const yaml = require('js-yaml');

const repoRoot = path.join(__dirname, '..');
const packageName = require(path.join(repoRoot, 'package.json')).name;

type PackedFile = {
  path: string;
  mode: number;
  size: number;
};

type PackResult = {
  filename: string;
  files: PackedFile[];
};

function run(command: string, args: string[], options: any = {}) {
  return childProcess.execFileSync(command, args, {
    cwd: options.cwd || repoRoot,
    env: options.env || process.env,
    encoding: options.encoding || 'utf8',
    stdio: options.stdio || 'pipe',
  });
}

function assertPackedFile(files: Map<string, PackedFile>, filePath: string) {
  assert.ok(files.has(filePath), `npm package must include ${filePath}`);
}

function assertExecutable(files: Map<string, PackedFile>, filePath: string) {
  const file = files.get(filePath);
  if (!file) {
    throw new Error(`npm package must include ${filePath}`);
  }
  assert.ok((file.mode & 0o111) !== 0, `${filePath} must be executable in the npm package`);
}

type SchemaHintExpectation = { path: string; schemaPath: string; required: boolean };

const schemaHintExpectedFiles: SchemaHintExpectation[] = [
  { path: 'policy/base.yml', schemaPath: './schema.json', required: true },
  { path: 'policy/profiles/balanced.yml', schemaPath: '../schema.json', required: true },
  { path: 'policy/profiles/strict.yml', schemaPath: '../schema.json', required: true },
  { path: 'policy/profiles/permissive.yml', schemaPath: '../schema.json', required: true },
  { path: 'policy/archetypes/spa-static-site.yml', schemaPath: '../schema.json', required: true },
  { path: 'policy/archetypes/rest-api.yml', schemaPath: '../schema.json', required: true },
  { path: 'policy/archetypes/admin-panel.yml', schemaPath: '../schema.json', required: true },
  { path: 'policy/archetypes/microservice-origin.yml', schemaPath: '../schema.json', required: true },
  { path: 'examples/aws-cloudfront/policy/security.yml', schemaPath: '../../policy/schema.json', required: false },
  { path: 'examples/cloudflare/policy/security.yml', schemaPath: '../../policy/schema.json', required: false },
  { path: 'examples/aws-cloudfront/policy/profiles/balanced.yml', schemaPath: '../../policy/schema.json', required: false },
  { path: 'examples/cloudflare/policy/profiles/balanced.yml', schemaPath: '../../policy/schema.json', required: false },
];

function assertYamlSchemaHint(filePath: string, content: string, schemaPath: string) {
  const expectedLine = `# yaml-language-server: $schema=${schemaPath}`;
  assert.ok(
    content.includes(expectedLine),
    `expected ${filePath} to include ${expectedLine}`,
  );
}

function assertSchemaHints(installRoot: string) {
  schemaHintExpectedFiles.forEach((entry) => {
    const absolutePath = path.join(installRoot, entry.path);
    if (!fs.existsSync(absolutePath)) {
      if (entry.required) {
        assert.ok(false, `installed package must include ${entry.path}`);
      }
      return;
    }
    const content = fs.readFileSync(absolutePath, 'utf8');
    assertYamlSchemaHint(entry.path, content, entry.schemaPath);
  });
}

function assertContractDiffWorkflow(filePath: string) {
  const content = fs.readFileSync(filePath, 'utf8');
  const workflow = yaml.load(content, { schema: yaml.JSON_SCHEMA });
  assert.ok(workflow.on.pull_request, `${filePath} must use pull_request`);
  assert.strictEqual(workflow.permissions.contents, 'read');
  assert.strictEqual(workflow.concurrency['cancel-in-progress'], true);
  assert.ok(!content.includes('pull_request_target'));
  assert.ok(!content.includes('${{ secrets.'));
  assert.ok(!content.includes('npx '));
  assert.ok(content.includes("3) echo 'Unexpected contract diff tool failure.' >&2; exit 3 ;;"));
  const actionRefs = [...content.matchAll(/uses:\s+[^\s@]+@([^\s]+)/g)].map((match) => match[1]);
  assert.ok(actionRefs.length > 0 && actionRefs.every((ref) => /^[a-f0-9]{40}$/.test(ref)));
}

function withTempDir(prefix: string, fn: (tmpDir: string) => void) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  try {
    fn(tmpDir);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function assertPackageContents(pack: PackResult) {
  const files = new Map(pack.files.map((file) => [file.path, file]));
  [
    'package.json',
    'README.md',
    'LICENSE',
    'bin/cli.js',
    'bin/cli.d.ts',
    'bin/commands/openapi-inspect.js',
    'bin/commands/openapi-inspect.d.ts',
    'bin/commands/contract-diff.js',
    'bin/commands/contract-diff.d.ts',
    'lib/index.js',
    'lib/index.d.ts',
    'lib/compile.js',
    'lib/compile.d.ts',
    'lib/lint.js',
    'lib/lint.d.ts',
    'contract/index.js',
    'contract/index.d.ts',
    'contract/finding-exceptions.js',
    'contract/finding-exceptions.d.ts',
    'contract/contract-diff.js',
    'contract/contract-diff.d.ts',
    'reporters/sarif.js',
    'reporters/sarif.d.ts',
    'reporters/github-summary.js',
    'reporters/github-summary.d.ts',
    'contract/allowed-surface.js',
    'contract/allowed-surface.d.ts',
    'contract/drift/index.js',
    'contract/drift/index.d.ts',
    'contract/drift/path-method.js',
    'contract/drift/path-method.d.ts',
    'contract/drift/authentication.js',
    'contract/drift/authentication.d.ts',
    'contract/drift/request.js',
    'contract/drift/request.d.ts',
    'contract/drift/shared.js',
    'contract/drift/shared.d.ts',
    'contract/route-relation.js',
    'contract/route-relation.d.ts',
    'contract/security-ir.js',
    'contract/security-ir.d.ts',
    'schemas/security-ir-v1.schema.json',
    'schemas/openapi-inspection-v1.schema.json',
    'schemas/finding-exceptions-v1.schema.json',
    'schemas/finding-v1.schema.json',
    'schemas/contract-diff-report-v1.schema.json',
    'schemas/nestjs-source-analysis-options.schema.json',
    'openapi/index.js',
    'openapi/index.d.ts',
    'openapi/load-document.js',
    'openapi/load-document.d.ts',
    'openapi/document-graph.js',
    'openapi/document-graph.d.ts',
    'openapi/ref-resolver.js',
    'openapi/ref-resolver.d.ts',
    'openapi/operation-normalizer.js',
    'openapi/operation-normalizer.d.ts',
    'source-analysis/index.js',
    'source-analysis/index.d.ts',
    'source/nestjs/index.js',
    'source/nestjs/index.d.ts',
    'source/nestjs/analyzer.js',
    'source/nestjs/auth-config.js',
    'openapi/inspect.js',
    'openapi/inspect.d.ts',
    'openapi/policy-candidate.js',
    'openapi/policy-candidate.d.ts',
    'docs/openapi-policy-candidates.md',
    'docs/openapi-policy-candidates.ja.md',
    'docs/openapi-integration.md',
    'docs/openapi-integration.ja.md',
    'docs/finding-exceptions.md',
    'docs/finding-exceptions.ja.md',
    'docs/ci-integration.md',
    'docs/ci-integration.ja.md',
    'examples/openapi/README.md',
    'examples/openapi/README.ja.md',
    'examples/openapi/openapi.yaml',
    'examples/github-actions/contract-diff.yml',
    'examples/github-actions/fixtures/openapi.yaml',
    'examples/github-actions/fixtures/policy.yml',
    'scripts/compile.js',
    'scripts/compile.d.ts',
    'scripts/policy-lint.js',
    'scripts/policy-lint.d.ts',
    'scripts/lib/compile-core.js',
    'templates/aws/viewer-request.js',
    'templates/cloudflare/index.ts',
    'policy/base.yml',
    'policy/schema.json',
    'policy/profiles/balanced.yml',
    'policy/profiles/strict.yml',
    'policy/profiles/permissive.yml',
    'policy/archetypes/spa-static-site.yml',
    'policy/archetypes/rest-api.yml',
    'policy/archetypes/admin-panel.yml',
    'policy/archetypes/microservice-origin.yml',
  ].forEach((filePath) => assertPackedFile(files, filePath));
  assertExecutable(files, 'bin/cli.js');
}

function smokeInstalledPackage(tarballPath: string) {
  withTempDir('cdn-security-install-', (installDir) => {
    run('npm', ['init', '-y'], { cwd: installDir, stdio: 'ignore' });
    run(
      'npm',
      [
        'install',
        '--ignore-scripts',
        '--no-audit',
        '--no-fund',
        '--fetch-retries=1',
        '--fetch-timeout=30000',
        tarballPath,
      ],
      {
        cwd: installDir,
        stdio: 'inherit',
      },
    );

    const installedRoot = path.join(installDir, 'node_modules', packageName);
    const installedBasePolicy = path.join(installedRoot, 'policy', 'base.yml');
    assert.ok(fs.existsSync(installedBasePolicy), 'installed package must include policy/base.yml');

    const apiSmoke = `
      const assert = require('assert');
      const path = require('path');
      const pkg = require(${JSON.stringify(packageName)});
      const contract = require(${JSON.stringify(`${packageName}/contract`)});
      const securityIr = require(${JSON.stringify(`${packageName}/contract/security-ir`)});
      const schema = require(${JSON.stringify(`${packageName}/schemas/security-ir-v1.schema.json`)});
      const inspectionSchema = require(${JSON.stringify(`${packageName}/schemas/openapi-inspection-v1.schema.json`)});
      const exceptionSchema = require(${JSON.stringify(`${packageName}/schemas/finding-exceptions-v1.schema.json`)});
      const findingSchema = require(${JSON.stringify(`${packageName}/schemas/finding-v1.schema.json`)});
      const contractDiffSchema = require(${JSON.stringify(`${packageName}/schemas/contract-diff-report-v1.schema.json`)});
      const nestJsOptionsSchema = require(${JSON.stringify(`${packageName}/schemas/nestjs-source-analysis-options.schema.json`)});
      const openapi = require(${JSON.stringify(`${packageName}/openapi`)});
      const recommendation = require(${JSON.stringify(`${packageName}/recommendation`)});
      const sourceAnalysis = require(${JSON.stringify(`${packageName}/source-analysis`)});
      const nestjs = require(${JSON.stringify(`${packageName}/source/nestjs`)});
      assert.strictEqual(typeof pkg.compile, 'function');
      assert.strictEqual(typeof pkg.lintPolicy, 'function');
      assert.strictEqual(typeof contract.createSecurityContract, 'function');
      assert.strictEqual(typeof contract.projectPolicyToAllowedSurface, 'function');
      assert.strictEqual(typeof securityIr.serializeSecurityContract, 'function');
      assert.strictEqual(schema.properties.schemaVersion.const, 1);
      assert.strictEqual(inspectionSchema.properties.schemaVersion.const, 1);
      assert.strictEqual(exceptionSchema.properties.version.const, 1);
      assert.strictEqual(findingSchema.properties.schemaVersion.const, 1);
      assert.strictEqual(contractDiffSchema.properties.schemaVersion.const, 1);
      assert.strictEqual(nestJsOptionsSchema.type, 'object');
      assert.strictEqual(typeof contract.loadFindingExceptions, 'function');
      assert.strictEqual(typeof contract.applyFindingExceptions, 'function');
      assert.strictEqual(typeof contract.diffSecurityContracts, 'function');
      assert.strictEqual(typeof contract.renderFindingsAsSarif, 'function');
      assert.strictEqual(typeof contract.renderContractDiffGitHubSummary, 'function');
      assert.strictEqual(typeof openapi.loadOpenApiDocument, 'function');
      assert.strictEqual(typeof openapi.resolveOpenApiReferences, 'function');
      assert.strictEqual(typeof openapi.normalizeOpenApiOperations, 'function');
      assert.strictEqual(typeof openapi.inspectOpenApi, 'function');
      assert.strictEqual(typeof openapi.generatePolicyCandidate, 'function');
      assert.strictEqual(typeof recommendation.recommendRequestLimits, 'function');
      assert.strictEqual(typeof sourceAnalysis.runSourceAnalyzer, 'function');
      assert.strictEqual(typeof nestjs.createNestJsSourceAnalyzer, 'function');
      assert.strictEqual(typeof nestjs.validateNestJsAuthConfig, 'function');
      const pkgRoot = path.join(process.cwd(), 'node_modules', ${JSON.stringify(packageName)});
      const result = pkg.lintPolicy({
        policyPath: path.join(pkgRoot, 'policy', 'base.yml'),
        cwd: process.cwd(),
        pkgRoot,
      });
      assert.strictEqual(result.ok, true, result.errors.join('\\n'));
    `;
    run(process.execPath, ['-e', apiSmoke], { cwd: installDir, stdio: 'inherit' });

    const cliPath = path.join(installDir, 'node_modules', '.bin', 'cdn-security');
    const version = run(cliPath, ['--version'], { cwd: installDir }).trim();
    assert.strictEqual(version, require(path.join(repoRoot, 'package.json')).version);
    const openApiPath = path.join(installedRoot, 'examples', 'openapi', 'openapi.yaml');
    fs.mkdirSync(path.join(installDir, 'reports'));
    run(cliPath, [
      'openapi', 'inspect', '--input', openApiPath, '--workspace-root', installDir, '--json',
      '--out', 'reports/openapi-contract.json',
    ], { cwd: installDir });
    const inspection = JSON.parse(fs.readFileSync(
      path.join(installDir, 'reports', 'openapi-contract.json'), 'utf8',
    ));
    assert.strictEqual(inspection.schemaVersion, 1);
    assert.strictEqual(inspection.summary.operationCount, 5);
    assert.ok(fs.existsSync(path.join(installDir, 'reports', 'openapi-contract.json')));
    run(cliPath, [
      'contract', 'diff', '--openapi', openApiPath, '--policy', installedBasePolicy,
      '--target', 'aws', '--workspace-root', installDir, '--format', 'json',
      '--fail-on', 'never', '--out', 'reports/contract-diff.json',
    ], { cwd: installDir });
    const contractDiff = JSON.parse(fs.readFileSync(
      path.join(installDir, 'reports', 'contract-diff.json'), 'utf8',
    ));
    assert.strictEqual(contractDiff.schemaVersion, 1);
    run(cliPath, [
      'contract', 'diff', '--openapi', openApiPath, '--policy', installedBasePolicy,
      '--target', 'aws', '--workspace-root', installDir, '--format', 'sarif',
      '--fail-on', 'never', '--out', 'reports/cdn-security.sarif',
    ], { cwd: installDir });
    const sarif = JSON.parse(fs.readFileSync(
      path.join(installDir, 'reports', 'cdn-security.sarif'), 'utf8',
    ));
    assert.strictEqual(sarif.version, '2.1.0');
    assert.strictEqual(sarif.runs[0].tool.driver.name, 'cdn-security-framework');
    const ciOpenApi = path.join(installedRoot, 'examples', 'github-actions', 'fixtures', 'openapi.yaml');
    const ciPolicy = path.join(installedRoot, 'examples', 'github-actions', 'fixtures', 'policy.yml');
    run(cliPath, [
      'contract', 'diff', '--openapi', ciOpenApi, '--policy', ciPolicy,
      '--target', 'aws', '--workspace-root', installDir, '--format', 'github-summary',
      '--fail-on', 'error', '--out', 'reports/github-summary.md',
    ], { cwd: installDir });
    const githubSummary = fs.readFileSync(
      path.join(installDir, 'reports', 'github-summary.md'), 'utf8',
    );
    assert.ok(githubSummary.includes('# CDN Security Contract Diff'));
    assert.ok(githubSummary.includes('**Gate: passing**'));
    assertContractDiffWorkflow(path.join(installedRoot, 'examples', 'github-actions', 'contract-diff.yml'));
    run(cliPath, [
      'openapi', 'generate-policy', '--input', openApiPath, '--workspace-root', installDir,
      '--profile', 'balanced', '--out', 'openapi.candidate.yml',
    ], { cwd: installDir });
    assert.ok(fs.existsSync(path.join(installDir, 'openapi.candidate.yml')));
    assert.ok(fs.existsSync(path.join(installDir, 'openapi.candidate.meta.json')));
    assertSchemaHints(installedRoot);

    run(cliPath, [
      'build', '--policy', path.join(installDir, 'openapi.candidate.yml'), '--out-dir', 'dist',
    ], {
      cwd: installDir,
      env: {
        ...process.env,
        EDGE_ADMIN_TOKEN: process.env.EDGE_ADMIN_TOKEN || 'package-smoke-token-not-for-deploy',
        ORIGIN_SECRET: process.env.ORIGIN_SECRET || 'package-smoke-origin-secret-not-for-deploy',
      },
      stdio: 'inherit',
    });
    assert.ok(fs.existsSync(path.join(installDir, 'dist', 'edge', 'viewer-request.js')));
    assert.ok(fs.existsSync(path.join(installDir, 'dist', 'edge', 'viewer-response.js')));
    assert.ok(fs.existsSync(path.join(installDir, 'dist', 'edge', 'origin-request.js')));

    run(cliPath, [
      'build',
      '--target', 'cloudflare',
      '--policy', installedBasePolicy,
      '--out-dir', 'dist-cloudflare',
    ], {
      cwd: installDir,
      stdio: 'inherit',
    });
    assert.ok(fs.existsSync(path.join(installDir, 'dist-cloudflare', 'edge', 'cloudflare', 'index.ts')));
  });
}

assertContractDiffWorkflow(path.join(repoRoot, '.github', 'workflows', 'contract-diff.yml'));
assertContractDiffWorkflow(path.join(repoRoot, 'examples', 'github-actions', 'contract-diff.yml'));

withTempDir('cdn-security-pack-', (packDir) => {
  const packJson = run('npm', ['pack', '--json', '--pack-destination', packDir]);
  const packResults = JSON.parse(packJson);
  assert.strictEqual(packResults.length, 1, 'npm pack should produce one tarball');

  const pack = packResults[0] as PackResult;
  assertPackageContents(pack);
  smokeInstalledPackage(path.join(packDir, pack.filename));
});

console.log('Package contents and packed install smoke tests passed.');
