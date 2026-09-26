#!/usr/bin/env node

const assert = require('assert');
const childProcess = require('child_process');
const crypto = require('node:crypto');
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
    'bin/commands/source-diff.js',
    'bin/commands/source-diff.d.ts',
    'bin/commands/source-auth-config.js',
    'bin/commands/source-auth-config.d.ts',
    'bin/commands/source-output.js',
    'bin/commands/source-output.d.ts',
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

export function smokeInstalledPackage(tarballPath: string, preparedConsumer: string | undefined,
  validateInstalledSarif: (value: unknown) => void) {
  quietConsumer = Boolean(preparedConsumer);
  if (preparedConsumer) yaml = require('node:module').createRequire(path.join(preparedConsumer, 'node_modules', packageName, 'package.json'))('js-yaml');
  let cliVerified = false;
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
      const cp = require('node:child_process');
      const crypto = require('node:crypto');
      const pkgRoot = path.join(process.cwd(), 'node_modules', ${JSON.stringify(packageName)});
      const { analyzeSourceAwareWorkspace } = require(path.join(pkgRoot, 'contract/source-aware-workspace.js'));
      const { finalizeSourceAwareOutput } = require(path.join(pkgRoot, 'contract/source-aware-output.js'));
      const { formatSourceAwarePreviewJson, formatSourceAwarePreviewText } = require(path.join(pkgRoot, 'contract/source-aware-finalizer.js'));
      const { renderSourceAwareSarif } = require(path.join(pkgRoot, 'reporters/sarif.js'));
      const { renderSourceAwareSummary } = require(path.join(pkgRoot, 'reporters/source-aware-summary.js'));
      const { loadSourceAuthConfig } = require(path.join(pkgRoot, 'bin/commands/source-auth-config.js'));
      const { runNestJsSourceAnalysisInternal } = require(path.join(pkgRoot, 'source/nestjs/analyzer.js'));
      const { DEFAULT_SOURCE_ANALYSIS_LIMITS } = require(path.join(pkgRoot, 'source-analysis/index.js'));
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
          fs.writeFileSync(path.join(root, 'refs/token=opaquevalue123.yaml'), 'components:\n  parameters:\n    Id:\n      name: id\n      in: path\n      required: true\n      schema: {type: string}\n');
          fs.writeFileSync(path.join(root, 'openapi.yaml'), "openapi: 3.0.3\ninfo: {title: Synthetic, version: 1.0.0}\npaths:\n  /users/{id}:\n    get:\n      parameters:\n        - $ref: './refs/token=opaquevalue123.yaml#/components/parameters/Id'\n      responses:\n        '200': {description: Authorization Bearer synthetic-secret-opaquevalue123}\n  /users:\n    post:\n      responses:\n        '200': {description: OK}\n");
          const inputNames = ['openapi.yaml', 'refs/token=opaquevalue123.yaml', 'policy.yml',
            'tsconfig.json', 'src/controller.ts',
            'node_modules/@nestjs/common/package.json',
            'node_modules/@nestjs/common/index.js', 'node_modules/@nestjs/common/index.d.ts'];
          const inputHashes = inputNames.map(name => crypto.createHash('sha256').update(fs.readFileSync(path.join(root, name))).digest('hex'));
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
          fs.writeFileSync(path.join(process.cwd(), 'source-aware-installed-sarif.json'), JSON.stringify(sarif));
          const cli = path.join(pkgRoot, 'bin/cli.js');
          const args = ['contract', 'source-diff', '--workspace-root', root, '--openapi', 'openapi.yaml',
            '--policy', 'policy.yml', '--target', 'aws', '--source', 'tsconfig.json',
            '--current-date', '2026-09-25', '--fail-on', 'never'];
          const steps = [];
          for (const format of ['text', 'json', 'sarif', 'summary']) {
            const start = process.hrtime.bigint();
            const result = cp.spawnSync(process.execPath, [cli, ...args, '--format', format], {
              cwd: root, encoding: 'utf8', env: { ...process.env, NODE_PATH: '' }, maxBuffer: 8 * 1024 * 1024,
            });
            steps.push({ command: 'cdn-security-source-diff', exit: result.status ?? -1, expectedExit: 0,
              durationMs: Number(process.hrtime.bigint() - start) / 1e6 });
            assert.equal(result.status, 0, 'installed Experimental CLI failed');
            assert.equal(result.stderr, '');
            assert.ok(!result.stdout.includes(root));
            assert.ok(!result.stdout.includes('opaquevalue123') && !result.stdout.includes('token%3Dopaquevalue123'));
            if (format === 'text') assert.ok(result.stdout.includes('unique=' + bundle.finalized.summary.unique));
            if (format === 'json') assert.deepEqual(JSON.parse(result.stdout).summary, bundle.finalized.summary);
            if (format === 'sarif') {
              const report = JSON.parse(result.stdout);
              assert.equal(report.runs[0].results.length, sarif.runs[0].results.length);
              fs.writeFileSync(path.join(process.cwd(), 'source-aware-installed-cli-sarif.json'), result.stdout);
            }
            if (format === 'summary') assert.ok(result.stdout.includes('| Unique | ' + bundle.finalized.summary.unique + ' |'));
          }
          const rejected = [
            { name: 'finding-threshold', args: [...args, '--fail-on', 'warning', '--format', 'json'], exit: 1 },
            { name: 'input-error', args: [...args, '--openapi', 'missing.yaml', '--format', 'json'], exit: 2 },
          ];
          for (const scenario of rejected) {
            const start = process.hrtime.bigint();
            const result = cp.spawnSync(process.execPath, [cli, ...scenario.args], {
              cwd: root, encoding: 'utf8', env: { ...process.env, NODE_PATH: '' }, maxBuffer: 8 * 1024 * 1024,
            });
            steps.push({ command: 'cdn-security-source-diff', exit: result.status ?? -1,
              expectedExit: scenario.exit, durationMs: Number(process.hrtime.bigint() - start) / 1e6 });
            assert.equal(result.status, scenario.exit, scenario.name);
            assert.equal(result.stderr, '');
            assert.ok(!result.stdout.includes(root));
            assert.ok(!result.stdout.includes('opaquevalue123') && !result.stdout.includes('token%3Dopaquevalue123'));
            const report = JSON.parse(result.stdout);
            assert.equal(report.exitCode, scenario.exit);
          }
          const preload = path.join(root, 'reporter-fault.cjs');
          fs.writeFileSync(preload, "const Module=require('node:module');const original=Module._load;Module._load=function(request,parent,isMain){const loaded=original.apply(this,arguments);return request.endsWith('/reporters/sarif')?{...loaded,renderSourceAwareSarif:()=>{throw Error('synthetic-private-fault')}}:loaded};");
          const failureStart = process.hrtime.bigint();
          const failure = cp.spawnSync(process.execPath, [cli, ...args, '--format', 'sarif'], {
            cwd: root, encoding: 'utf8', env: { ...process.env, NODE_PATH: '', NODE_OPTIONS: '--require=' + preload },
            maxBuffer: 8 * 1024 * 1024,
          });
          steps.push({ command: 'cdn-security-source-diff', exit: failure.status ?? -1, expectedExit: 3,
            durationMs: Number(process.hrtime.bigint() - failureStart) / 1e6 });
          assert.equal(failure.status, 3);
          assert.equal(failure.stdout, '');
          assert.ok(failure.stderr.includes('SOURCE_DIFF_REPORTER_FAILED'));
          assert.ok(!failure.stderr.includes('synthetic-private-fault') && !failure.stderr.includes(root)
            && !failure.stderr.includes('opaquevalue123') && !failure.stderr.includes('token%3Dopaquevalue123'));
          const authRoot = path.join(root, 'auth-example');
          fs.cpSync(path.join(pkgRoot, 'examples/nestjs-contract'), authRoot, { recursive: true });
          const authDependency = path.join(authRoot, 'node_modules/@nestjs/common');
          fs.mkdirSync(path.dirname(authDependency), { recursive: true });
          fs.cpSync(path.join(authRoot, 'stubs/nestjs-common'), authDependency, { recursive: true });
          fs.writeFileSync(path.join(authRoot, 'auth.json'), JSON.stringify({
            guard_mappings: { JwtAuthGuard: { auth_kind: 'bearer' } },
            roles_decorators: ['Roles'], public_decorators: ['Public'],
          }));
          fs.writeFileSync(path.join(authRoot, 'auth-alt.json'), JSON.stringify({
            guard_mappings: { JwtAuthGuard: { auth_kind: 'api_key' } },
            roles_decorators: [], public_decorators: [],
          }));
          fs.writeFileSync(path.join(authRoot, 'auth-bad.yml'),
            'public_decorators: []\nroles_decorators: []\nguard_mappings: {}\nprivate: opaquevalue123\n');
          const authInputNames = ['tsconfig.json', 'tsconfig.base.json', 'openapi.yaml', 'security-analyzer.yml',
            'policy/security.yml', 'packages/shared/tsconfig.json', 'src/base.controller.ts',
            'src/decorators.ts', 'src/guards.ts', 'src/runtime-prefix.ts', 'src/users.controller.ts',
            'node_modules/@nestjs/common/index.d.ts', 'node_modules/@nestjs/common/index.js',
            'node_modules/@nestjs/common/package.json', 'auth.json', 'auth-alt.json', 'auth-bad.yml'];
          const authInputHashes = authInputNames.map(name => crypto.createHash('sha256')
            .update(fs.readFileSync(path.join(authRoot, name))).digest('hex'));
          const loadedAuth = loadSourceAuthConfig({ workspaceRoot: authRoot, inputPath: 'security-analyzer.yml' });
          const loadedJson = loadSourceAuthConfig({ workspaceRoot: authRoot, inputPath: 'auth.json' });
          const loadedAlt = loadSourceAuthConfig({ workspaceRoot: authRoot, inputPath: 'auth-alt.json' });
          assert.deepEqual(loadedAuth.config, loadedJson.config);
          assert.notEqual(loadedAuth.rawDigest, loadedJson.rawDigest);
          const authWorkspaceOptions = { workspaceRoot: authRoot, openapiPath: 'openapi.yaml',
            policyPath: 'policy/security.yml', target: 'aws' };
          const defaultAuthWorkspace = await analyzeSourceAwareWorkspace({ ...authWorkspaceOptions,
            source: { tsconfigPath: 'tsconfig.json' } });
          const configuredWorkspace = await analyzeSourceAwareWorkspace({ ...authWorkspaceOptions,
            source: { tsconfigPath: 'tsconfig.json', authConfig: loadedAuth.config } });
          const changedWorkspace = await analyzeSourceAwareWorkspace({ ...authWorkspaceOptions,
            source: { tsconfigPath: 'tsconfig.json', authConfig: loadedAlt.config } });
          const configuredBundle = finalizeSourceAwareOutput(configuredWorkspace, { currentDate: '2026-09-25', failOn: 'never' });
          const changedBundle = finalizeSourceAwareOutput(changedWorkspace, { currentDate: '2026-09-25', failOn: 'never' });
          assert.equal(configuredWorkspace.evidence.source.projectDigest, defaultAuthWorkspace.evidence.source.projectDigest);
          assert.equal(changedWorkspace.evidence.source.projectDigest, defaultAuthWorkspace.evidence.source.projectDigest);
          assert.notEqual(configuredWorkspace.evidence.source.configDigest, defaultAuthWorkspace.evidence.source.configDigest);
          assert.notEqual(changedWorkspace.evidence.source.configDigest, configuredWorkspace.evidence.source.configDigest);
          assert.ok(configuredBundle.finalized && changedBundle.finalized);
          assert.notDeepEqual(configuredBundle.finalized.findings, changedBundle.finalized.findings);
          const expectedAuthFindings = [
            ['SC-AUTHN-006', 'GET', '/users/duplicate'],
            ['SC-AUTHN-006', 'GET', '/users/inherited'],
            ['SC-AUTHN-006', 'POST', '/users'],
            ['SC-AUTHZ-002', 'POST', '/users'],
          ];
          const authFindings = findings => findings.filter(finding =>
            ['SC-AUTHN-006', 'SC-AUTHZ-002'].includes(finding.ruleId))
            .map(finding => [finding.ruleId, finding.route?.method, finding.route?.path])
            .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
          assert.deepEqual(authFindings(configuredWorkspace.comparisons.implementedAllowed.findings), expectedAuthFindings);
          assert.deepEqual(authFindings(changedWorkspace.comparisons.implementedAllowed.findings), [
            ['SC-AUTHN-006', 'GET', '/users/duplicate'],
            ['SC-AUTHN-006', 'GET', '/users/inherited'],
            ['SC-AUTHN-006', 'POST', '/users'],
          ]);
          const sourceOptions = { workspaceRoot: authRoot, entrypoints: ['tsconfig.json'],
            limits: DEFAULT_SOURCE_ANALYSIS_LIMITS, logger: { log() {} } };
          for (const [config, expected] of [
            [loadedAuth.config, [
              ['GET /users/{id}', 'public', 'none', undefined],
              ['POST /users', 'authenticated', 'alternatives', 'bearer'],
              ['PATCH /users/details', 'unknown', 'unknown', undefined],
            ]],
            [loadedAlt.config, [
              ['GET /users/{id}', 'authenticated', 'alternatives', 'api-key'],
              ['POST /users', 'authenticated', 'alternatives', 'api-key'],
              ['PATCH /users/details', 'unknown', 'unknown', undefined],
            ]],
          ]) {
            const analyzed = await runNestJsSourceAnalysisInternal(sourceOptions, config);
            assert.equal(analyzed.execution.status, 'success');
            const operations = analyzed.execution.result.contract.operations;
            assert.deepEqual(expected.map(([route]) => {
              const operation = operations.find(item => item.routeKey === route);
              return [operation.routeKey, operation.exposure, operation.auth.mode,
                operation.auth.alternatives[0]?.schemes[0]?.kind];
            }), expected);
          }
          const authArgs = ['contract', 'source-diff', '--workspace-root', authRoot, '--openapi', 'openapi.yaml',
            '--policy', 'policy/security.yml', '--target', 'aws', '--source', 'tsconfig.json',
            '--current-date', '2026-09-25', '--fail-on', 'never'];
          const configuredExpected = JSON.parse(formatSourceAwarePreviewJson(configuredBundle.finalized));
          const changedExpected = JSON.parse(formatSourceAwarePreviewJson(changedBundle.finalized));
          const authCases = [];
          let configuredJson;
          const configuredSarif = renderSourceAwareSarif(configuredBundle);
          for (const format of ['text', 'json', 'sarif', 'summary']) {
            const start = process.hrtime.bigint();
            const result = cp.spawnSync(process.execPath, [cli, ...authArgs, '--source-auth-config', 'security-analyzer.yml', '--format', format], {
              cwd: authRoot, encoding: 'utf8', env: { ...process.env, NODE_PATH: '' }, maxBuffer: 8 * 1024 * 1024,
            });
            steps.push({ command: 'cdn-security-source-auth-config', exit: result.status ?? -1, expectedExit: 0,
              durationMs: Number(process.hrtime.bigint() - start) / 1e6 });
            authCases.push('configured-' + format);
            assert.equal(result.status, 0, 'configured installed CLI failed');
            assert.equal(result.stderr, '');
            assert.ok(!result.stdout.includes(root) && !result.stdout.includes('opaquevalue123'));
            if (format === 'json') {
              configuredJson = JSON.parse(result.stdout);
              assert.deepEqual(configuredJson, configuredExpected);
              assert.deepEqual(authFindings(configuredJson.findings.active), expectedAuthFindings);
            }
            if (format === 'sarif') {
              assert.deepEqual(JSON.parse(result.stdout), configuredSarif);
              fs.writeFileSync(path.join(process.cwd(), 'source-auth-installed-cli-sarif.json'), result.stdout);
            }
            if (format === 'text') assert.equal(result.stdout, formatSourceAwarePreviewText(configuredBundle.finalized));
            if (format === 'summary') assert.equal(result.stdout, renderSourceAwareSummary(configuredBundle));
          }
          for (const scenario of [
            { name: 'equivalent-json', config: 'auth.json', expected: configuredExpected, exit: 0 },
            { name: 'changed-config', config: 'auth-alt.json', expected: changedExpected, exit: 0 },
            { name: 'invalid-config', config: 'auth-bad.yml', exit: 2 },
          ]) {
            const start = process.hrtime.bigint();
            const result = cp.spawnSync(process.execPath, [cli, ...authArgs, '--source-auth-config', scenario.config, '--format', 'json'], {
              cwd: authRoot, encoding: 'utf8', env: { ...process.env, NODE_PATH: '' }, maxBuffer: 8 * 1024 * 1024,
            });
            steps.push({ command: 'cdn-security-source-auth-config', exit: result.status ?? -1,
              expectedExit: scenario.exit, durationMs: Number(process.hrtime.bigint() - start) / 1e6 });
            authCases.push(scenario.name);
            assert.equal(result.status, scenario.exit, scenario.name);
            assert.ok(!result.stdout.includes(root) && !result.stderr.includes(root)
              && !result.stdout.includes('opaquevalue123') && !result.stderr.includes('opaquevalue123'));
            if (scenario.exit === 0) {
              const report = JSON.parse(result.stdout);
              assert.deepEqual(report, scenario.expected);
              assert.deepEqual(authFindings(report.findings.active), scenario.name === 'changed-config' ? [
                ['SC-AUTHN-006', 'GET', '/users/duplicate'],
                ['SC-AUTHN-006', 'GET', '/users/inherited'],
                ['SC-AUTHN-006', 'POST', '/users'],
              ] : expectedAuthFindings);
            }
            else { assert.equal(result.stdout, ''); assert.ok(result.stderr.includes('SOURCE_DIFF_AUTH_CONFIG_INVALID')); }
          }
          const noSourceArgs = authArgs.filter((value, index) => value !== '--source' && authArgs[index - 1] !== '--source');
          const noSourceStart = process.hrtime.bigint();
          const noSource = cp.spawnSync(process.execPath, [cli, ...noSourceArgs,
            '--source-auth-config', 'missing-token=opaquevalue123.yml'], {
            cwd: authRoot, encoding: 'utf8', env: { ...process.env, NODE_PATH: '' }, maxBuffer: 8 * 1024 * 1024,
          });
          steps.push({ command: 'cdn-security-source-auth-config', exit: noSource.status ?? -1,
            expectedExit: 2, durationMs: Number(process.hrtime.bigint() - noSourceStart) / 1e6 });
          authCases.push('without-source');
          assert.equal(noSource.status, 2);
          assert.equal(noSource.stdout, '');
          assert.ok(noSource.stderr.includes('SOURCE_DIFF_AUTH_CONFIG_REQUIRES_SOURCE')
            && !noSource.stderr.includes(root) && !noSource.stderr.includes('opaquevalue123'));
          const saveCases = [];
          const save = (name, destinationRoot, commandArgs, format, outputName, expectedExit,
            expectedStdout, diagnostic) => {
            const outputPath = path.join(destinationRoot, outputName);
            const before = fs.existsSync(outputPath) && fs.statSync(outputPath).isFile()
              ? crypto.createHash('sha256').update(fs.readFileSync(outputPath)).digest('hex') : null;
            const start = process.hrtime.bigint();
            const result = cp.spawnSync(process.execPath,
              [cli, ...commandArgs, '--format', format, '--out', outputName], {
                cwd: destinationRoot, encoding: 'utf8', env: { ...process.env, NODE_PATH: '' },
                maxBuffer: 8 * 1024 * 1024,
              });
            steps.push({ command: 'cdn-security-source-save', exit: result.status ?? -1,
              expectedExit, durationMs: Number(process.hrtime.bigint() - start) / 1e6 });
            assert.equal(result.status, expectedExit, name);
            assert.equal(result.stdout, '', name + ' must not write stdout');
            assert.ok(!result.stderr.includes(root) && !result.stderr.includes('opaquevalue123'), name);
            if (diagnostic) assert.ok(result.stderr.includes(diagnostic), name);
            else assert.equal(result.stderr, '', name);
            let digest = null;
            if (expectedStdout !== null) {
              const bytes = fs.readFileSync(outputPath);
              assert.equal(bytes.toString('utf8'), expectedStdout, name + ' saved bytes');
              assert.equal(fs.statSync(outputPath).mode & 0o077, 0, name + ' file mode');
              digest = crypto.createHash('sha256').update(bytes).digest('hex');
            } else if (before !== null) {
              assert.equal(crypto.createHash('sha256').update(fs.readFileSync(outputPath)).digest('hex'), before);
            } else assert.equal(fs.existsSync(outputPath), false, name + ' unexpected output');
            saveCases.push({ name, exit: result.status, digest });
          };
          for (const format of ['text', 'json', 'sarif', 'summary']) {
            const stdout = cp.spawnSync(process.execPath, [cli, ...args, '--format', format], {
              cwd: root, encoding: 'utf8', env: { ...process.env, NODE_PATH: '' }, maxBuffer: 8 * 1024 * 1024,
            });
            assert.equal(stdout.status, 0);
            save('format-' + format, root, args, format, 'saved-' + format + '.report', 0, stdout.stdout);
            if (format === 'sarif') fs.writeFileSync(path.join(process.cwd(),
              'source-save-installed-cli-sarif.json'), fs.readFileSync(path.join(root, 'saved-sarif.report')));
          }
          const configuredStdout = cp.spawnSync(process.execPath, [cli, ...authArgs,
            '--source-auth-config', 'security-analyzer.yml', '--format', 'json'], {
            cwd: authRoot, encoding: 'utf8', env: { ...process.env, NODE_PATH: '' }, maxBuffer: 8 * 1024 * 1024,
          });
          assert.equal(configuredStdout.status, 0);
          save('configured-auth', authRoot, [...authArgs, '--source-auth-config', 'security-analyzer.yml'],
            'json', 'configured.report', 0, configuredStdout.stdout);
          const thresholdStdout = cp.spawnSync(process.execPath, [cli, ...args,
            '--fail-on', 'warning', '--format', 'json'], {
            cwd: root, encoding: 'utf8', env: { ...process.env, NODE_PATH: '' }, maxBuffer: 8 * 1024 * 1024,
          });
          assert.equal(thresholdStdout.status, 1);
          save('threshold', root, [...args, '--fail-on', 'warning'], 'json',
            'threshold.report', 1, thresholdStdout.stdout);
          fs.writeFileSync(path.join(root, 'existing.report'), 'original');
          save('existing', root, args, 'json', 'existing.report', 2, null, 'SOURCE_DIFF_OUTPUT_EXISTS');
          save('input-collision', root, args, 'json', 'openapi.yaml', 2, null,
            'SOURCE_DIFF_OUTPUT_PROTECTED');
          const writeFault = path.join(root, 'write-fault.cjs');
          fs.writeFileSync(writeFault, "const fs=require('node:fs');const write=fs.writeFileSync;fs.writeFileSync=function(file,value,...rest){if(typeof file==='number'){write(file,'partial');throw Error('synthetic-private-write')}return write(file,value,...rest)};");
          const faultStart = process.hrtime.bigint();
          const fault = cp.spawnSync(process.execPath, [cli, ...args, '--format', 'json',
            '--out', 'fault.report'], { cwd: root, encoding: 'utf8',
            env: { ...process.env, NODE_PATH: '', NODE_OPTIONS: '--require=' + writeFault },
            maxBuffer: 8 * 1024 * 1024 });
          steps.push({ command: 'cdn-security-source-save', exit: fault.status ?? -1,
            expectedExit: 3, durationMs: Number(process.hrtime.bigint() - faultStart) / 1e6 });
          assert.equal(fault.status, 3);
          assert.equal(fault.stdout, '');
          assert.ok(fault.stderr.includes('SOURCE_DIFF_OUTPUT_WRITE_FAILED')
            && !fault.stderr.includes('synthetic-private-write') && !fault.stderr.includes(root));
          assert.equal(fs.existsSync(path.join(root, 'fault.report')), false);
          saveCases.push({ name: 'write-fault', exit: 3, digest: null });
          assert.deepEqual(inputNames.map(name => crypto.createHash('sha256').update(fs.readFileSync(path.join(root, name))).digest('hex')), inputHashes);
          assert.deepEqual(authInputNames.map(name => crypto.createHash('sha256')
            .update(fs.readFileSync(path.join(authRoot, name))).digest('hex')), authInputHashes);
          fs.writeFileSync(path.join(process.cwd(), 'source-aware-cli-proof.json'), JSON.stringify({
            formats: ['text', 'json', 'sarif', 'summary'], steps, authCases, saveCases,
            authConfig: { rawDigest: loadedAuth.rawDigest,
              configDigest: configuredWorkspace.evidence.source.configDigest,
              projectDigest: configuredWorkspace.evidence.source.projectDigest },
          }));
          console.log('OK: installed internal Source-aware workspace/finalizer/4-format smoke');
        } finally { fs.rmSync(root, { recursive: true, force: true }); }
      })().catch((error) => {
        console.error(error?.name ?? 'internal source smoke failed',
          typeof error?.actual === 'number' ? error.actual : '',
          typeof error?.expected === 'number' ? error.expected : '');
        process.exitCode = 1;
      });
    `;
    run(process.execPath, ['-e', internalSourceSmoke], { cwd: installDir, stdio: 'inherit' });
    const installedSarifPath = path.join(installDir, 'source-aware-installed-sarif.json');
    const installedSarif = JSON.parse(fs.readFileSync(installedSarifPath, 'utf8'));
    fs.rmSync(installedSarifPath);
    validateInstalledSarif(installedSarif);
    console.log('OK: installed internal SARIF validates against pinned official schema');
    const cliProofPath = path.join(installDir, 'source-aware-cli-proof.json');
    const cliSarifPath = path.join(installDir, 'source-aware-installed-cli-sarif.json');
    const authSarifPath = path.join(installDir, 'source-auth-installed-cli-sarif.json');
    const saveSarifPath = path.join(installDir, 'source-save-installed-cli-sarif.json');
    const cliProof = JSON.parse(fs.readFileSync(cliProofPath, 'utf8'));
    assert.deepStrictEqual(cliProof.formats, ['text', 'json', 'sarif', 'summary']);
    assert.deepStrictEqual(cliProof.authCases, ['configured-text', 'configured-json', 'configured-sarif',
      'configured-summary', 'equivalent-json', 'changed-config', 'invalid-config', 'without-source']);
    assert.deepStrictEqual(cliProof.saveCases.map((item: { name: string; exit: number }) => [item.name, item.exit]),
      [['format-text', 0], ['format-json', 0], ['format-sarif', 0], ['format-summary', 0],
        ['configured-auth', 0], ['threshold', 1], ['existing', 2], ['input-collision', 2], ['write-fault', 3]]);
    assert.ok(cliProof.saveCases.slice(0, 6).every((item: { digest: string }) => /^[a-f0-9]{64}$/.test(item.digest))
      && cliProof.saveCases.slice(6).every((item: { digest: null }) => item.digest === null));
    assert.ok(cliProof.authConfig && ['rawDigest', 'configDigest', 'projectDigest'].every((key) =>
      /^sha256:[a-f0-9]{64}$/.test(cliProof.authConfig[key])), 'configured digest proof missing');
    assert.ok(Array.isArray(cliProof.steps) && cliProof.steps.length === 24
      && cliProof.steps.every((step: { command: string; exit: number; expectedExit: number; durationMs: number }, index: number) =>
        step.command === (index < 7 ? 'cdn-security-source-diff'
          : index < 15 ? 'cdn-security-source-auth-config' : 'cdn-security-source-save')
        && step.exit === step.expectedExit
        && Number.isFinite(step.durationMs) && step.durationMs >= 0), 'installed CLI proof missing');
    assert.deepStrictEqual(cliProof.steps.map((step: { expectedExit: number }) => step.expectedExit),
      [0, 0, 0, 0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 1, 2, 2, 3]);
    validateInstalledSarif(JSON.parse(fs.readFileSync(cliSarifPath, 'utf8')));
    validateInstalledSarif(JSON.parse(fs.readFileSync(authSarifPath, 'utf8')));
    validateInstalledSarif(JSON.parse(fs.readFileSync(saveSarifPath, 'utf8')));
    if (quietConsumer) smokeSteps.push(...cliProof.steps);
    fs.rmSync(cliProofPath);
    fs.rmSync(cliSarifPath);
    fs.rmSync(authSarifPath);
    fs.rmSync(saveSarifPath);
    cliVerified = true;
    console.log('OK: installed Experimental source-diff CLI validates four formats and explicit auth config');

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
  return cliVerified;
}

export type PrefixProof = { globalPrefix: '/api'; projectDigest: string; configDigest: string;
  routingDigest: string; comparisonContractDigest: string; savedSha256: string; inputSha256: string;
  unprefixedInventory: { sourceOnly: number; declaredOnly: number; methodMismatch: number };
  prefixedInventory: { sourceOnly: number; declaredOnly: number; methodMismatch: number } };

/** One representative installed Node row uses the same packed CLI for every prefix scenario. */
export function smokeInstalledPrefix(consumer: string, validateSarif: (value: unknown) => void):
  { steps: typeof smokeSteps; proof: PrefixProof } {
  const pkgRoot = path.join(consumer, 'node_modules', packageName);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-installed-prefix-'));
  const digest = (value: Buffer | string) => crypto.createHash('sha256').update(value).digest('hex');
  try {
    fs.cpSync(path.join(pkgRoot, 'examples/nestjs-contract'), root, { recursive: true });
    const dependency = path.join(root, 'node_modules/@nestjs/common');
    fs.mkdirSync(path.dirname(dependency), { recursive: true });
    fs.cpSync(path.join(root, 'stubs/nestjs-common'), dependency, { recursive: true });
    const inputNames = ['openapi.yaml', 'policy/security.yml', 'tsconfig.json',
      'src/users.controller.ts', 'src/runtime-prefix.ts'];
    const inputSha256 = digest(JSON.stringify(inputNames.map(name => digest(fs.readFileSync(path.join(root, name))))));
    const cli = path.join(pkgRoot, 'bin/cli.js');
    const args = ['contract', 'source-diff', '--workspace-root', root, '--openapi', 'openapi.yaml',
      '--policy', 'policy/security.yml', '--target', 'aws'];
    const steps: typeof smokeSteps = [];
    const invoke = (extra: string[], expectedExit: number, withSource = true) => {
      const start = process.hrtime.bigint();
      const result = childProcess.spawnSync(process.execPath, [cli, ...args,
        ...(withSource ? ['--source', 'tsconfig.json'] : []),
        '--current-date', '2026-09-25', '--fail-on', 'never', ...extra], {
        cwd: root, encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024,
        env: { ...process.env, NODE_PATH: '', NODE_OPTIONS: '' },
      });
      steps.push({ command: 'cdn-security-source-prefix', exit: result.status ?? -1,
        expectedExit, durationMs: Number(process.hrtime.bigint() - start) / 1e6 });
      assert.equal(result.error, undefined, 'installed prefix CLI process error');
      assert.equal(result.signal, null, 'installed prefix CLI signal');
      assert.equal(result.status, expectedExit, 'installed prefix CLI exit');
      assert.ok(!(result.stdout + result.stderr).includes(root), 'installed prefix CLI leaked workspace path');
      return result;
    };
    let prefixedSarif: any;
    for (const format of ['text', 'json', 'sarif', 'summary']) {
      const result = invoke(['--source-global-prefix', '/api', '--format', format], 0);
      assert.equal(result.stderr, '');
      assert.ok(result.stdout.includes('/api'), 'installed prefix missing from report');
      if (format === 'json') {
        const report = JSON.parse(result.stdout);
        assert.equal(report.routingAssumption.globalPrefix, '/api');
      }
      if (format === 'sarif') {
        prefixedSarif = JSON.parse(result.stdout);
        validateSarif(prefixedSarif);
      }
    }
    const unprefixed = invoke(['--format', 'sarif'], 0);
    const unprefixedSarif = JSON.parse(unprefixed.stdout);
    validateSarif(unprefixedSarif);
    const metadata = prefixedSarif.runs[0].tool.driver.properties.sourceAware.metadata;
    const oldMetadata = unprefixedSarif.runs[0].tool.driver.properties.sourceAware.metadata;
    assert.equal(oldMetadata.routingAssumption, undefined);
    assert.equal(metadata.routingAssumption.globalPrefix, '/api');
    assert.deepEqual(metadata.source, oldMetadata.source, 'prefix changed original Source digest');
    const inventory = (report: any) => {
      const rules = report.runs[0].results.map((result: any) => result.ruleId);
      return { sourceOnly: rules.filter((rule: string) => rule === 'SC-INVENTORY-001').length,
        declaredOnly: rules.filter((rule: string) => rule === 'SC-INVENTORY-003').length,
        methodMismatch: rules.filter((rule: string) => rule === 'SC-INVENTORY-004').length };
    };
    const unprefixedInventory = inventory(unprefixedSarif);
    const prefixedInventory = inventory(prefixedSarif);
    assert.deepEqual(unprefixedInventory, { sourceOnly: 2, declaredOnly: 1, methodMismatch: 1 },
      'installed omitted prefix changed decorator-local comparison');
    assert.deepEqual(prefixedInventory, { sourceOnly: 6, declaredOnly: 5, methodMismatch: 0 },
      'installed explicit prefix comparison changed');
    assert.ok(prefixedSarif.runs[0].results.some((result: any) =>
      result.properties?.sourceAware?.route?.path === '/api/users/{id}'),
    'installed prefix comparison route missing');
    for (const [extra, code, withSource] of [
      [['--source-global-prefix', 'api%2f'], 'SOURCE_DIFF_PREFIX_INVALID', true],
      [['--source-global-prefix', '/api'], 'SOURCE_DIFF_PREFIX_REQUIRES_SOURCE', false],
    ] as const) {
      const result = invoke([...extra], 2, withSource);
      assert.equal(result.stdout, '');
      assert.ok(result.stderr.includes(code));
      assert.ok(!result.stderr.includes('api%2f') && !result.stderr.includes(root));
    }
    const saved = invoke(['--source-global-prefix', '/api', '--format', 'json', '--out', 'prefix-report.json'], 0);
    assert.equal(saved.stdout, ''); assert.equal(saved.stderr, '');
    const savedBytes = fs.readFileSync(path.join(root, 'prefix-report.json'));
    assert.equal(JSON.parse(savedBytes.toString()).routingAssumption.globalPrefix, '/api');
    assert.equal(digest(JSON.stringify(inputNames.map(name => digest(fs.readFileSync(path.join(root, name)))))),
      inputSha256, 'installed prefix changed an input');
    return { steps, proof: { globalPrefix: '/api', projectDigest: metadata.source.projectDigest,
      configDigest: metadata.source.configDigest, routingDigest: metadata.routingAssumption.digest,
      comparisonContractDigest: metadata.routingAssumption.comparisonContractDigest,
      savedSha256: digest(savedBytes), inputSha256, unprefixedInventory, prefixedInventory } };
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

export type ControllerOptionsProof = {
  inputSha256: string; savedSha256: string; ciRecordSha256: string;
  routes: string[]; unsupportedCode: 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR';
  ciDelivery: 'CI_OK';
};

/** A small independently authored object corpus against the one installed candidate. */
export function smokeInstalledControllerOptions(consumer: string, validateSarif: (value: unknown) => void,
  environment: NodeJS.ProcessEnv = process.env):
  { steps: typeof smokeSteps; proof: ControllerOptionsProof } {
  const pkgRoot = path.join(consumer, 'node_modules', packageName);
  const candidate = path.dirname(consumer);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-installed-controller-object-'));
  const digest = (value: Buffer | string) => crypto.createHash('sha256').update(value).digest('hex');
  const write = (name: string, value: string) => {
    const file = path.join(root, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, value);
  };
  const inputNames = ['tsconfig.json', 'src/controller.ts', 'openapi.yaml', 'policy.yml'];
  try {
    write('tsconfig.json', JSON.stringify({ compilerOptions: {
      experimentalDecorators: true, moduleResolution: 'node', noLib: true, types: [],
    }, files: ['src/controller.ts'] }));
    write('src/controller.ts', `import { Controller, Get } from '@nestjs/common';
@Controller({ path: 'users' }) class Users { @Get('items') read() {} }
@Controller({ path: 'locked', version: '1' }) class Versioned { @Get() read() {} }
throw new Error('Source executed');\n`);
    write('openapi.yaml', `openapi: 3.0.3
info: {title: Object fixture, version: 1.0.0}
paths:
  /declared-only:
    get: {responses: {'200': {description: OK}}}
`);
    write('policy.yml', `version: 2
defaults: {mode: enforce}
request:
  allow_methods: [GET]
  block: {header_missing: []}
routes: []
response_headers: {}
`);
    const dependency = path.join(root, 'node_modules/@nestjs/common');
    fs.mkdirSync(dependency, { recursive: true });
    fs.writeFileSync(path.join(dependency, 'package.json'), JSON.stringify({
      name: '@nestjs/common', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
    }));
    fs.writeFileSync(path.join(dependency, 'index.js'), 'throw new Error("dependency executed");\n');
    fs.writeFileSync(path.join(dependency, 'index.d.ts'), `export declare function Controller(value?: string | {path?: string; version?: string}): ClassDecorator;
export declare function Get(path?: string): MethodDecorator;\n`);
    const inputSha256 = digest(JSON.stringify(inputNames.map(name => digest(fs.readFileSync(path.join(root, name))))));
    const steps: typeof smokeSteps = [];
    const invoke = (script: string, args: string[], expectedExit: number, env = environment) => {
      const start = process.hrtime.bigint();
      const result = childProcess.spawnSync(process.execPath, [script, ...args], {
        cwd: root, encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024,
        env: { ...env, NODE_PATH: '', NODE_OPTIONS: '' },
      });
      steps.push({ command: script.endsWith('/bin/cli.js') ? 'cdn-security-controller-options'
        : 'source-aware-ci-object', exit: result.status ?? -1, expectedExit,
      durationMs: Number(process.hrtime.bigint() - start) / 1e6 });
      assert.equal(result.error, undefined, 'installed object process error');
      assert.equal(result.signal, null, 'installed object process signal');
      assert.equal(result.status, expectedExit, `installed object command exit: ${result.stderr}`);
      assert.ok(!(result.stdout + result.stderr).includes(root), 'installed object leaked workspace path');
      return result;
    };
    const cli = path.join(pkgRoot, 'bin/cli.js');
    const base = ['contract', 'source-diff', '--workspace-root', root, '--openapi', 'openapi.yaml',
      '--policy', 'policy.yml', '--target', 'aws', '--source', 'tsconfig.json',
      '--current-date', '2026-09-25', '--fail-on', 'never'];
    let sarif: any;
    let json: any;
    let routes: string[] = [];
    let textReport = '';
    let summaryReport = '';
    for (const format of ['text', 'json', 'sarif', 'summary']) {
      const result = invoke(cli, [...base, '--format', format], 0);
      assert.equal(result.stderr, '');
      assert.ok(result.stdout.length > 0, 'missing installed object report');
      if (format === 'sarif') { sarif = JSON.parse(result.stdout); validateSarif(sarif); }
      if (format === 'json') {
        const report = JSON.parse(result.stdout);
        json = report;
        assert.equal(report.stages.implemented.status, 'partial');
        assert.equal(report.omittedFindings, 0, 'installed object report omitted findings');
        routes = report.findings.active.filter((finding: any) =>
          finding.ruleId === 'SC-INVENTORY-001').map((finding: any) =>
          `${finding.route?.method} ${finding.route?.path}`);
        assert.deepEqual(routes, ['GET /users/items'], 'installed object routes changed');
        assert.ok(!report.findings.active.some((finding: any) => finding.route?.path === '/locked'),
          'versioned Controller became an ordinary route');
      }
      if (format === 'text') textReport = result.stdout;
      if (format === 'summary') summaryReport = result.stdout;
    }
    const saved = invoke(cli, [...base, '--format', 'json', '--out', 'object-report.json'], 0);
    assert.equal(saved.stdout, ''); assert.equal(saved.stderr, '');
    const savedBytes = fs.readFileSync(path.join(root, 'object-report.json'));
    assert.equal(JSON.parse(savedBytes.toString()).stages.implemented.status, 'partial');
    invoke(cli, [...base, '--format', 'summary', '--fail-on', 'warning'], 1);
    const metadata = sarif.runs[0].tool.driver.properties.sourceAware.metadata;
    const sarifState = sarif.runs[0].tool.driver.properties.sourceAware;
    assert.ok(json.stages.implemented.diagnosticCodes.includes('SOURCE_ANALYZER_UNSUPPORTED_DECORATOR'));
    assert.equal(json.summary.suppressed, 0);
    assert.ok(textReport.includes('stage implemented=partial')
      && textReport.includes('SOURCE_ANALYZER_UNSUPPORTED_DECORATOR')
      && textReport.includes(`suppressed=${json.summary.suppressed}`));
    assert.ok(summaryReport.includes('| implemented | partial |')
      && summaryReport.includes('SOURCE_ANALYZER_UNSUPPORTED_DECORATOR')
      && summaryReport.includes(`| Suppressed | ${json.summary.suppressed} |`));
    assert.equal(sarifState.stages.implemented.status, 'partial');
    assert.ok(sarifState.stages.implemented.diagnosticCodes.includes('SOURCE_ANALYZER_UNSUPPORTED_DECORATOR'));
    assert.equal(sarifState.summary.suppressed, json.summary.suppressed);
    const results = sarif.runs[0].results;
    assert.ok(results.some((finding: any) => finding.ruleId === 'SC-INVENTORY-001'
      && finding.properties?.sourceAware?.comparisons?.includes('implementedDeclared')
      && finding.relatedLocations?.some((location: any) =>
        location.physicalLocation?.artifactLocation?.uri === 'src/controller.ts')));
    assert.ok(results.some((finding: any) => finding.ruleId === 'SC-INVENTORY-003'
      && finding.message.text.includes('absence is not proven')));
    assert.equal(results.filter((finding: any) => finding.ruleId === 'SC-INVENTORY-001').length, 1);
    assert.ok(metadata.source && !JSON.stringify(metadata).includes(root));
    const driver = path.join(pkgRoot, 'scripts/source-aware-ci.js');
    const output = path.join(root, 'ci-output');
    const stage = path.join(root, 'ci-stage');
    fs.mkdirSync(output); fs.mkdirSync(stage);
    const config = path.join(root, 'ci-config.json');
    fs.writeFileSync(config, JSON.stringify({ workspaceRoot: root, openapi: 'openapi.yaml',
      policy: 'policy.yml', target: 'aws', source: 'tsconfig.json',
      currentDate: '2026-09-25', failOn: 'never', format: 'summary' }));
    const record = path.join(output, 'ci-record.json');
    const delivery = path.join(stage, 'delivery.json');
    const summaryPath = path.join(root, 'ci-step-summary.md');
    const ciEnv = { ...environment, GITHUB_STEP_SUMMARY: summaryPath };
    invoke(driver, ['run', config, candidate, output], 0, ciEnv);
    invoke(driver, ['publish', record, candidate, stage], 0, ciEnv);
    invoke(driver, ['verify-stage', record, candidate, delivery], 0, ciEnv);
    invoke(driver, ['gate', record, candidate, delivery], 0, { ...ciEnv,
      CSF_PRODUCER_STATE: 'success', CSF_ACCEPTANCE_STATE: 'success',
      CSF_ANALYZE_OUTCOME: 'success', CSF_PUBLISH_OUTCOME: 'success',
      CSF_STAGE_OUTCOME: 'success', CSF_ARTIFACT_OUTCOME: 'success' });
    assert.equal(JSON.parse(fs.readFileSync(delivery, 'utf8')).code, 'CI_OK');
    validateSarif(JSON.parse(fs.readFileSync(path.join(output, 'source-aware.sarif'), 'utf8')));
    assert.equal(digest(JSON.stringify(inputNames.map(name => digest(fs.readFileSync(path.join(root, name)))))),
      inputSha256, 'installed object command changed input');
    return { steps, proof: { inputSha256, savedSha256: digest(savedBytes),
      ciRecordSha256: digest(fs.readFileSync(record)), routes,
      unsupportedCode: 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR', ciDelivery: 'CI_OK' } };
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
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
  const { createOfficialSarifValidator } = require('./official-sarif-test-validator') as typeof import('./official-sarif-test-validator');
  const validate = createOfficialSarifValidator(path.join(repoRoot, 'test/fixtures/sarif/sarif-schema-2.1.0.json'));
  smokeInstalledPackage(path.join(packDir, pack.filename), undefined,
    (value) => assert.ok(validate(value), 'installed internal SARIF failed pinned official schema'));
});

console.log('Package contents and packed install smoke tests passed.');

}
