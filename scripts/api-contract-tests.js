"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const repoRoot = path.join(__dirname, '..');
const api = require(path.join(repoRoot, 'lib'));
function test(name, fn) {
    try {
        fn();
        console.log(`OK: ${name}`);
    }
    catch (err) {
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
test('package metadata exposes typed root api and bounded exports', () => {
    const pkg = require(path.join(repoRoot, 'package.json'));
    assert.strictEqual(pkg.main, 'lib/index.js');
    assert.strictEqual(pkg.types, 'lib/index.d.ts');
    assert.deepStrictEqual(Object.keys(pkg.exports).sort(), ['.', './bin/cli', './bin/cli.js']);
    assert.strictEqual(pkg.exports['.'].types, './lib/index.d.ts');
    assert.strictEqual(pkg.exports['.'].require, './lib/index.js');
    assert.strictEqual(pkg.exports['./bin/cli.js'], './bin/cli.js');
});
test('root type declarations expose public programmatic api', () => {
    const dts = fs.readFileSync(path.join(repoRoot, 'lib', 'index.d.ts'), 'utf8');
    for (const name of ['compile', 'emitWaf', 'lintPolicy', 'migratePolicy', 'runDoctor']) {
        assert.ok(dts.includes(`export declare const ${name}`), `lib/index.d.ts must declare ${name}`);
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
