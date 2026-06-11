#!/usr/bin/env node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const assert = require('assert');
const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const repoRoot = path.join(__dirname, '..');
const packageName = require(path.join(repoRoot, 'package.json')).name;
function run(command, args, options = {}) {
    return childProcess.execFileSync(command, args, {
        cwd: options.cwd || repoRoot,
        env: options.env || process.env,
        encoding: options.encoding || 'utf8',
        stdio: options.stdio || 'pipe',
    });
}
function assertPackedFile(files, filePath) {
    assert.ok(files.has(filePath), `npm package must include ${filePath}`);
}
function assertExecutable(files, filePath) {
    const file = files.get(filePath);
    if (!file) {
        throw new Error(`npm package must include ${filePath}`);
    }
    assert.ok((file.mode & 0o111) !== 0, `${filePath} must be executable in the npm package`);
}
const schemaHintExpectedFiles = [
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
function assertYamlSchemaHint(filePath, content, schemaPath) {
    const expectedLine = `# yaml-language-server: $schema=${schemaPath}`;
    assert.ok(content.includes(expectedLine), `expected ${filePath} to include ${expectedLine}`);
}
function assertSchemaHints(installRoot) {
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
function withTempDir(prefix, fn) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
    try {
        fn(tmpDir);
    }
    finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
}
function assertPackageContents(pack) {
    const files = new Map(pack.files.map((file) => [file.path, file]));
    [
        'package.json',
        'README.md',
        'LICENSE',
        'bin/cli.js',
        'bin/cli.d.ts',
        'lib/index.js',
        'lib/index.d.ts',
        'lib/compile.js',
        'lib/compile.d.ts',
        'lib/lint.js',
        'lib/lint.d.ts',
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
function smokeInstalledPackage(tarballPath) {
    withTempDir('cdn-security-install-', (installDir) => {
        run('npm', ['init', '-y'], { cwd: installDir, stdio: 'ignore' });
        run('npm', [
            'install',
            '--ignore-scripts',
            '--no-audit',
            '--no-fund',
            '--fetch-retries=1',
            '--fetch-timeout=30000',
            tarballPath,
        ], {
            cwd: installDir,
            stdio: 'inherit',
        });
        const installedRoot = path.join(installDir, 'node_modules', packageName);
        const installedBasePolicy = path.join(installedRoot, 'policy', 'base.yml');
        assert.ok(fs.existsSync(installedBasePolicy), 'installed package must include policy/base.yml');
        const apiSmoke = `
      const assert = require('assert');
      const path = require('path');
      const pkg = require(${JSON.stringify(packageName)});
      assert.strictEqual(typeof pkg.compile, 'function');
      assert.strictEqual(typeof pkg.lintPolicy, 'function');
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
        assertSchemaHints(installedRoot);
        run(cliPath, ['build', '--policy', installedBasePolicy, '--out-dir', 'dist'], {
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
    });
}
withTempDir('cdn-security-pack-', (packDir) => {
    const packJson = run('npm', ['pack', '--json', '--pack-destination', packDir]);
    const packResults = JSON.parse(packJson);
    assert.strictEqual(packResults.length, 1, 'npm pack should produce one tarball');
    const pack = packResults[0];
    assertPackageContents(pack);
    smokeInstalledPackage(path.join(packDir, pack.filename));
});
console.log('Package contents and packed install smoke tests passed.');
