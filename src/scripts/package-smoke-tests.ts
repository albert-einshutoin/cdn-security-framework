#!/usr/bin/env node

const assert = require('assert');
const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
let yaml: any;

export const smokeSteps: Array<{ command: string; exit: number; expectedExit: number; durationMs: number }> = [];
let quietConsumer = false;

const repoRoot = path.join(__dirname, '..');
const packageName = require(path.join(repoRoot, 'package.json')).name;
const packageManifest = require(path.join(repoRoot, 'docs', 'api-manifest.json')) as {
  requiredPackageFiles: string[];
  packagedFiles: Record<string, string[]>;
  sizeBudget: { compressedBytes: number; uncompressedBytes: number };
};

type PackedFile = {
  path: string;
  mode: number;
  size: number;
};

type PackResult = {
  filename: string;
  files: PackedFile[];
  size: number;
  unpackedSize: number;
};

function run(command: string, args: string[], options: any = {}) {
  const start = process.hrtime.bigint();
  const result = childProcess.spawnSync(command, args, {
    cwd: options.cwd || repoRoot,
    env: options.env || process.env,
    encoding: options.encoding || 'utf8',
    stdio: quietConsumer ? 'pipe' : (options.stdio || 'pipe'),
    maxBuffer: 8 * 1024 * 1024,
  });
  if (quietConsumer) smokeSteps.push({ command: path.basename(command), exit: result.status ?? -1, expectedExit: 0,
    durationMs: Number(process.hrtime.bigint() - start) / 1e6 });
  assert.strictEqual(result.status, 0, 'package smoke command failed');
  return result.stdout;
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
  yaml ??= require('js-yaml');
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

function assertPackageInventory(files: string[]) {
  const expected = Object.values(packageManifest.packagedFiles).flat().sort();
  assert.strictEqual(new Set(expected).size, expected.length, 'duplicate package ownership');
  assert.strictEqual(new Set(files.map((file) => file.toLowerCase())).size, files.length, 'duplicate/case-collision package path');
  assert.ok(files.every((file) => !file.startsWith('/') && !file.includes('\\') && file.split('/').every((part) => part && part !== '.' && part !== '..')), 'unsafe package path');
  const actual = [...files].sort();
  assert.ok(actual.length === expected.length && actual.every((file, index) => file === expected[index]), 'unregistered or missing package file');
}

function assertPackageText(file: string, content: string, files: Set<string>) {
  // Fixed high-confidence patterns. Never echo matching content into diagnostics.
  assert.ok(!/(?:\/Users\/[^/\s]+\/|\/home\/[^/\s]+\/|[A-Z]:\\+Users\\+|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b|\bAKIA[0-9A-Z]{16}\b)/u.test(content), `sensitive content in ${file}`);
  if (!file.endsWith('.md')) return;
  for (const match of content.matchAll(/\]\(([^)\s]+)(?:\s+[^)]*)?\)/gu)) {
    const target = match[1];
    if (/^(?:[a-z][\w+.-]*:|#)/iu.test(target)) continue;
    const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(file), target.split('#')[0])).replace(/\/$/u, '');
    assert.ok(!target.startsWith('/') && !resolved.startsWith('../') &&
      (resolved === '.' || files.has(resolved) || [...files].some((entry) => entry.startsWith(`${resolved}/`))), `unresolved package documentation link in ${file}`);
  }
}

export function assertInstalledContents(root: string) {
  const entries: string[] = [];
  function walk(directory: string) {
    for (const entry of fs.readdirSync(path.join(root, directory), { withFileTypes: true })) {
      const relative = path.posix.join(directory, entry.name);
      assert.ok(!entry.isSymbolicLink(), 'package member must not be a symlink');
      if (entry.isDirectory()) walk(relative);
      else { assert.ok(entry.isFile(), 'package member must be a regular file'); entries.push(relative); }
    }
  }
  walk('');
  assertPackageInventory(entries);
  const files = new Set(entries);
  for (const file of entries) assertPackageText(file, fs.readFileSync(path.join(root, file), 'utf8'), files);
  const cli = fs.readFileSync(path.join(root, 'bin/cli.js'), 'utf8');
  assert.ok(cli.startsWith('#!/usr/bin/env node\n'), 'CLI shebang missing');
}

function assertPackageNegativeCases() {
  const files = Object.values(packageManifest.packagedFiles).flat();
  assert.throws(() => assertPackageInventory([...files, 'docs/unregistered.json']));
  assert.throws(() => assertPackageInventory(files.filter((file) => file !== 'lib/index.d.ts')));
  assert.throws(() => assertPackageInventory([...files, 'test/fixture.json']));
  assert.throws(() => assertPackageInventory([...files, 'lib/index.js.map']));
  assert.throws(() => assertPackageInventory([...files, 'LIB/INDEX.JS']));
  assert.throws(() => assertPackageText('README.md', '[missing](absent.md)', new Set(files)));
  assert.throws(() => assertPackageText('docs/record.json', JSON.stringify({ cwd: '/Users/synthetic/work' }), new Set(files)));
  assert.throws(() => assertPackageText('docs/key.txt', '-----BEGIN PRIVATE KEY-----', new Set(files)));
  assert.throws(() => assertPackageText('docs/record.json', JSON.stringify({ cwd: 'C:\\Users\\synthetic\\work' }), new Set(files)));
  assert.throws(() => assertPackageText('docs/record.txt', 'C:\\Users\\synthetic\\work', new Set(files)));
  const sentinel = 'ghp_' + 'x'.repeat(36);
  const failure = childProcess.spawnSync(process.execPath, ['-e', `
    const assert = require('node:assert');
    const data = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
    const packageManifest = { packagedFiles: { test: data.expected } };
    (${assertPackageInventory.toString()})(data.actual);
  `], { encoding: 'utf8', input: JSON.stringify({ expected: files, actual: [...files, `docs/${sentinel}.json`] }) });
  assert.strictEqual(failure.status, 1);
  assert.ok(failure.stderr.includes('unregistered or missing package file'));
  assert.ok(!(failure.stdout + failure.stderr).includes(sentinel), 'inventory diagnostics must not echo filename secrets');
  console.log('OK: 11 package inventory/content/link negative cases');
}

export function assertPackageContents(pack: PackResult) {
  assertPackageInventory(pack.files.map((file) => file.path));
  assert.ok(pack.size <= packageManifest.sizeBudget.compressedBytes, "compressed package budget exceeded");
  assert.ok(pack.unpackedSize <= packageManifest.sizeBudget.uncompressedBytes, "uncompressed package budget exceeded");
  const files = new Map(pack.files.map((file) => [file.path, file]));
  [
    'package.json',
    'README.md',
    'LICENSE',
    'docs/api-manifest.json',
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
    'examples/nestjs-contract/run-analysis.cjs',
    'examples/nestjs-contract/tsconfig.json',
    'examples/nestjs-contract/openapi.yaml',
    'examples/nestjs-contract/policy/security.yml',
    'examples/nestjs-contract/stubs/nestjs-common/index.d.ts',
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
  packageManifest.requiredPackageFiles.forEach((filePath) => assertPackedFile(files, filePath));
  assertExecutable(files, 'bin/cli.js');
  const forbidden = /(^|\/)(?:\.env(?:\..*)?|\.npmrc|credentials(?:\.[^/]*)?|[^/]*(?:secret|token)[^/]*\.(?:conf(?:ig)?|ini|json|toml|txt|ya?ml)|id_(?:dsa|ecdsa|ed25519|rsa)(?:\.pub)?|coverage(?:\/.*)?|\.nyc_output(?:\/.*)?|test-results(?:\/.*)?|junit[^/]*|(?:\.?tmp|temp)(?:\.[^/]*)?(?:\/.*)?|.*\.map|.*\.(?:cer|crt|der|jks|key|keystore|p12|pem|pfx|temp|tmp))$/iu;
  for (const filePath of [
    '.env.production', '.npmrc', 'credentials.json', 'id_ed25519', 'coverage/lcov.info',
    '.nyc_output/out.json', 'test-results/result.xml', 'tmp/out', 'dist/index.js.map', 'certs/server.crt',
    'docs/client-secret.json', 'examples/api-token.txt', 'scripts/cache.tmp', 'docs/temp.json',
  ]) {
    assert.ok(forbidden.test(filePath), `forbidden package path must be rejected: ${filePath}`);
  }
  assert.ok(!forbidden.test('docs/runbooks/secret-rotation.md'));
  for (const file of pack.files) {
    assert.ok(!forbidden.test(file.path), `npm package must not include ${file.path}`);
  }
}

export function smokeInstalledPackage(tarballPath: string, preparedConsumer?: string) {
  quietConsumer = Boolean(preparedConsumer);
  if (preparedConsumer) yaml = require('node:module').createRequire(path.join(preparedConsumer, 'node_modules', packageName, 'package.json'))('js-yaml');
  const inspect = (installDir: string) => {
    if (!preparedConsumer) {
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

    }
    const installedRoot = path.join(installDir, 'node_modules', packageName);
    const installedBasePolicy = path.join(installedRoot, 'policy', 'base.yml');
    assert.ok(fs.existsSync(installedBasePolicy), 'installed package must include policy/base.yml');

    const apiSmoke = `
      const assert = require('assert');
      const path = require('path');
      const pkgRoot = path.join(process.cwd(), 'node_modules', ${JSON.stringify(packageName)});
      const pkg = require(${JSON.stringify(packageName)});
      const manifest = require(path.join(pkgRoot, 'docs', 'api-manifest.json'));
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
      assert.strictEqual(manifest.packageVersion, require(path.join(pkgRoot, 'package.json')).version);
      assert.strictEqual(typeof pkg.lintPolicy, 'function');
      assert.strictEqual(typeof contract.createSecurityContract, 'function');
      assert.strictEqual(typeof contract.projectPolicyToAllowedSurface, 'function');
      assert.strictEqual(typeof contract.compareSourcePolicyContracts, 'function');
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
      const fs = require('fs');
      const cp = require('child_process');
      assert.strictEqual(require(path.join(pkgRoot, 'policy', 'schema.json')).properties.version.const, 2);
      const migrationInput = path.join(process.cwd(), 'migration-v1.json');
      const originalPolicy = JSON.stringify({ version: 1, metadata: { owner: 'consumer', description: 'literal environment reference' }, request: { allow_methods: ['HEAD', 'GET'] }, response_headers: {} });
      fs.writeFileSync(migrationInput, originalPolicy);
      const preview = pkg.migratePolicy({ policyPath: migrationInput });
      assert.strictEqual(preview.ok, true); assert.strictEqual(preview.saved, false);
      assert.deepStrictEqual(preview.policy, { ...JSON.parse(originalPolicy), version: 2 });
      assert.strictEqual(fs.readFileSync(migrationInput, 'utf8'), originalPolicy);
      const cliPreview = cp.execFileSync(process.execPath, [path.join(pkgRoot, 'bin', 'cli.js'), 'migrate', '--policy', migrationInput], { encoding: 'utf8' });
      assert.ok(cliPreview.includes('MIGRATION_PREVIEW'));
      const saved = pkg.migratePolicy({ policyPath: migrationInput, write: true });
      assert.strictEqual(saved.ok, true); assert.strictEqual(saved.saved, true);
      assert.strictEqual(fs.readFileSync(migrationInput + '.v1.bak', 'utf8'), originalPolicy);
      assert.strictEqual(pkg.lintPolicy({ policyPath: migrationInput }).ok, true);
      assert.strictEqual(pkg.migratePolicy({ policyPath: migrationInput, write: true }).noop, true);
      console.log('OK: packed schema2 migration preview/save/backup/CLI/noop');
      const result = pkg.lintPolicy({
        policyPath: path.join(pkgRoot, 'policy', 'base.yml'),
        cwd: process.cwd(),
        pkgRoot,
      });
      assert.strictEqual(result.ok, true, result.errors.join('\\n'));
    `;
    run(process.execPath, ['-e', apiSmoke], { cwd: installDir, stdio: 'inherit' });

    // Development-only deep-path check of the packed internal 2.1 adapter; no public export is added.
    const internalSourceSmoke = String.raw`
      const assert = require('node:assert/strict');
      const fs = require('node:fs');
      const path = require('node:path');
      const pkgRoot = path.join(process.cwd(), 'node_modules', ${JSON.stringify(packageName)});
      const { analyzeSourceAwareWorkspace } = require(path.join(pkgRoot, 'contract/source-aware-workspace.js'));
      const { finalizeSourceAwareOutput } = require(path.join(pkgRoot, 'contract/source-aware-output.js'));
      const { formatSourceAwarePreviewJson, formatSourceAwarePreviewText } = require(path.join(pkgRoot, 'contract/source-aware-finalizer.js'));
      const { renderSourceAwareSarif } = require(path.join(pkgRoot, 'reporters/sarif.js'));
      const { renderSourceAwareSummary } = require(path.join(pkgRoot, 'reporters/source-aware-summary.js'));
      const root = fs.mkdtempSync(path.join(process.cwd(), 'source-aware-'));
      (async () => {
        try {
          fs.mkdirSync(path.join(root, 'src'), { recursive: true });
          fs.mkdirSync(path.join(root, 'refs'), { recursive: true });
          const dependency = path.join(root, 'node_modules/@nestjs/common');
          fs.mkdirSync(dependency, { recursive: true });
          fs.writeFileSync(path.join(dependency, 'package.json'), JSON.stringify({ name: '@nestjs/common', version: '1.0.0', main: 'index.js', types: 'index.d.ts' }));
          fs.writeFileSync(path.join(dependency, 'index.js'), 'throw new Error("Source executed");\n');
          fs.writeFileSync(path.join(dependency, 'index.d.ts'), 'export declare function Controller(path?: string): ClassDecorator;\nexport declare function Get(path?: string): MethodDecorator;\n');
          fs.writeFileSync(path.join(root, 'tsconfig.json'), JSON.stringify({ compilerOptions: { experimentalDecorators: true, moduleResolution: 'node', noLib: true, types: [] }, files: ['src/controller.ts'] }));
          fs.writeFileSync(path.join(root, 'src/controller.ts'), 'import { Controller, Get } from "@nestjs/common";\n@Controller("users") class UsersController { @Get(":id") read() {} }\n');
          fs.writeFileSync(path.join(root, 'policy.yml'), 'version: 2\ndefaults: {mode: enforce}\nrequest:\n  allow_methods: [GET]\n  limits: {max_uri_length: 21}\n  block: {header_missing: []}\nroutes: []\nresponse_headers: {}\n');
          fs.writeFileSync(path.join(root, 'refs/common.yaml'), 'components:\n  parameters:\n    Id:\n      name: id\n      in: path\n      required: true\n      schema: {type: string}\n');
          fs.writeFileSync(path.join(root, 'openapi.yaml'), "openapi: 3.0.3\ninfo: {title: Synthetic, version: 1.0.0}\npaths:\n  /users/{id}:\n    get:\n      parameters:\n        - $ref: './refs/common.yaml#/components/parameters/Id'\n      responses:\n        '200': {description: OK}\n");
          const workspace = await analyzeSourceAwareWorkspace({ workspaceRoot: root, openapiPath: 'openapi.yaml', policyPath: 'policy.yml', target: 'aws', source: { tsconfigPath: 'tsconfig.json' } });
          const bundle = finalizeSourceAwareOutput(workspace, { currentDate: '2026-09-25', failOn: 'never' });
          assert.ok(bundle.finalized);
          assert.notEqual(bundle.finalized.stages.implemented.status, 'failed');
          const json = JSON.parse(formatSourceAwarePreviewJson(bundle.finalized));
          const text = formatSourceAwarePreviewText(bundle.finalized);
          const sarif = renderSourceAwareSarif(bundle);
          const summary = renderSourceAwareSummary(bundle);
          assert.equal(sarif.version, '2.1.0');
          assert.equal(sarif.runs[0].results.length, bundle.finalized.summary.active + bundle.finalized.summary.suppressed + bundle.finalized.summary.governance);
          assert.deepEqual(json.summary, bundle.finalized.summary);
          assert.ok(text.includes('unique=' + bundle.finalized.summary.unique));
          assert.ok(summary.includes('| Unique | ' + bundle.finalized.summary.unique + ' |'));
          assert.ok(bundle.metadata.source && bundle.metadata.openapi && bundle.metadata.policy);
          assert.ok(!(JSON.stringify(sarif) + summary).includes(root));
          console.log('OK: installed internal Source-aware workspace/finalizer/4-format smoke');
        } finally { fs.rmSync(root, { recursive: true, force: true }); }
      })().catch((error) => { console.error(error?.name ?? 'internal source smoke failed'); process.exitCode = 1; });
    `;
    run(process.execPath, ['-e', internalSourceSmoke], { cwd: installDir, stdio: 'inherit' });

    fs.writeFileSync(path.join(installDir, 'consumer.ts'), `
      import { compile, migratePolicy, type MigratePolicyResult } from '${packageName}';
      const migrated: MigratePolicyResult = migratePolicy({ policyPath: 'policy.yml', toVersion: 2, target: 'cloudflare', write: false });
      const migrationExit: 0 | 1 | 2 = migrated.exitCode;
      import { compileArtifacts } from '${packageName}/emitter';
      import { parsePolicyFile } from '${packageName}/parser';
      import { validatePolicy } from '${packageName}/validator';
      import { createSecurityContract } from '${packageName}/contract';
      import { serializeSecurityContract } from '${packageName}/contract/security-ir';
      import { inspectOpenApi } from '${packageName}/openapi';
      import { recommendRequestLimits } from '${packageName}/recommendation';
      import { runSourceAnalyzer } from '${packageName}/source-analysis';
      import { createNestJsSourceAnalyzer } from '${packageName}/source/nestjs';
      void [compile, compileArtifacts, parsePolicyFile, validatePolicy, createSecurityContract,
        serializeSecurityContract, inspectOpenApi, recommendRequestLimits, runSourceAnalyzer,
        createNestJsSourceAnalyzer];
    `);
    fs.writeFileSync(path.join(installDir, 'tsconfig.json'), JSON.stringify({
      compilerOptions: {
        module: 'Node16',
        moduleResolution: 'Node16',
        noEmit: true,
        strict: true,
        target: 'ES2022',
        types: ['node'],
      },
      files: ['consumer.ts'],
    }));
    run(process.execPath, [
      path.join(installDir, 'node_modules', 'typescript', 'bin', 'tsc'),
      '--project', path.join(installDir, 'tsconfig.json'),
    ], { cwd: installDir, stdio: 'inherit' });

    const nestReport = JSON.parse(run(process.execPath, [
      path.join(installedRoot, 'examples', 'nestjs-contract', 'run-analysis.cjs'),
    ], { cwd: installDir }));
    assert.strictEqual(nestReport.schemaVersion, 1);
    assert.deepStrictEqual(nestReport.diagnostics, ['SOURCE_ANALYZER_DYNAMIC_ROUTE']);
    assert.strictEqual(nestReport.operations.length, 6);

    const cliPath = path.join(installDir, 'node_modules', '.bin', 'cdn-security');
    const version = run(cliPath, ['--version'], { cwd: installDir }).trim();
    assert.strictEqual(version, require(path.join(repoRoot, 'package.json')).version);
    const npxCommand = process.platform === 'win32' ? 'npx.cmd' : 'npx';
    const npxHelp = run(npxCommand, ['--no-install', 'cdn-security', '--help'], { cwd: installDir });
    for (const command of ['build', 'openapi', 'contract', 'migrate']) {
      assert.ok(npxHelp.includes(command), `npx CLI help must include ${command}`);
    }
    const invalidCli = childProcess.spawnSync(cliPath, ['--definitely-invalid-option'], {
      cwd: installDir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    assert.strictEqual(invalidCli.error, undefined);
    assert.notStrictEqual(invalidCli.status, 0, 'invalid CLI input must exit nonzero');
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
    assertInstalledContents(installedRoot);
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
  };
  if (preparedConsumer) inspect(preparedConsumer);
  else withTempDir('cdn-security-install-', inspect);
}

if (require.main === module) {
assertPackageNegativeCases();

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

}
