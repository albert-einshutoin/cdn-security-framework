#!/usr/bin/env node
"use strict";
/**
 * Programmatic API integration tests.
 *
 * These exercise the public entry `require('cdn-security-framework')` from
 * the repo (via its lib/index.js). We assert every function returns a
 * structured result object and NEVER calls process.exit — the whole point
 * of the Programmatic API is that callers decide exit behaviour.
 *
 * Coverage focus:
 *   - result shape stability (this is the contract)
 *   - lintPolicy in-process happy/error paths
 *   - compile + emitWaf backwards-compat (subprocess-backed today)
 *   - migratePolicy noop and error branches (no process.exit)
 *   - runDoctor re-export is callable
 */
Object.defineProperty(exports, "__esModule", { value: true });
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const api = require('../lib');
function test(name, fn) {
    try {
        fn();
        console.log('OK:', name);
    }
    catch (e) {
        console.error('FAIL:', name);
        console.error(e && e.stack ? e.stack : e);
        process.exitCode = 1;
    }
}
const repoRoot = path.join(__dirname, '..');
const BASIC_AWS_POLICY = `
version: 1
project: api-test
request:
  allow_methods: [GET, POST]
response_headers:
  hsts: "max-age=1"
firewall:
  waf:
    scope: CLOUDFRONT
    rate_limit: 1000
    managed_rules:
      - AWSManagedRulesCommonRuleSet
`;
const BROKEN_POLICY = `
version: 1
request:
  allow_methods: [GET]
response_headers:
  hsts: "max-age=1"
unknown_top_level_key: true
`;
function tmpProject(yamlBody) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'api-'));
    const policyDir = path.join(tmp, 'policy');
    fs.mkdirSync(policyDir);
    const policyPath = path.join(policyDir, 'security.yml');
    fs.writeFileSync(policyPath, yamlBody, 'utf8');
    return {
        tmp,
        policyPath,
        outDir: path.join(tmp, 'dist'),
        cleanup() { fs.rmSync(tmp, { recursive: true, force: true }); },
    };
}
// --- Exports surface ---
test('api exports stable surface', () => {
    assert.strictEqual(typeof api.lintPolicy, 'function');
    assert.strictEqual(typeof api.compile, 'function');
    assert.strictEqual(typeof api.emitWaf, 'function');
    assert.strictEqual(typeof api.runDoctor, 'function');
    assert.strictEqual(typeof api.migratePolicy, 'function');
});
test('api entry point matches package.json main', () => {
    const pkg = require('../package.json');
    assert.strictEqual(pkg.main, 'lib/index.js', 'package.json main must point to lib/index.js');
    // The require above would have thrown if the path was wrong, but assert anyway.
    assert.ok(fs.existsSync(path.join(repoRoot, 'lib', 'index.js')));
});
// --- lintPolicy ---
test('lintPolicy: returns ok=true for valid policy', () => {
    const ctx = tmpProject(BASIC_AWS_POLICY);
    try {
        const result = api.lintPolicy({ policyPath: ctx.policyPath });
        assert.strictEqual(result.ok, true, `lint failed: ${JSON.stringify(result.errors)}`);
        assert.ok(Array.isArray(result.errors));
        assert.ok(Array.isArray(result.warnings));
        assert.ok(result.policy && result.policy.version === 1);
    }
    finally {
        ctx.cleanup();
    }
});
test('lintPolicy: missing policyPath → structured error, no throw', () => {
    const result = api.lintPolicy({});
    assert.strictEqual(result.ok, false);
    assert.ok(result.errors.some((e) => /policyPath is required/.test(e)));
    assert.strictEqual(result.policy, null);
});
test('lintPolicy: nonexistent file → structured error', () => {
    const result = api.lintPolicy({ policyPath: '/no/such/file.yml' });
    assert.strictEqual(result.ok, false);
    assert.ok(result.errors.some((e) => /not found/i.test(e)));
});
test('lintPolicy: invalid policy surfaces schema errors', () => {
    const ctx = tmpProject(BROKEN_POLICY);
    try {
        const result = api.lintPolicy({ policyPath: ctx.policyPath });
        assert.strictEqual(result.ok, false);
        assert.ok(result.errors.length > 0, 'expected errors for invalid policy');
        assert.ok(result.policy !== null, 'policy should still be parsed');
    }
    finally {
        ctx.cleanup();
    }
});
test('lintPolicy: does not call process.exit (isolation probe)', () => {
    // If lintPolicy ever calls process.exit, Node will terminate this test
    // process before subsequent tests run. Reaching the assertion below
    // confirms non-termination for the error path.
    const result = api.lintPolicy({ policyPath: '/no/such/file.yml' });
    assert.strictEqual(result.ok, false);
});
// --- compile ---
test('compile: aws target writes edge + infra, returns file lists', () => {
    const ctx = tmpProject(BASIC_AWS_POLICY);
    try {
        const result = api.compile({
            policyPath: ctx.policyPath,
            outDir: ctx.outDir,
            target: 'aws',
            env: Object.assign({}, process.env, {
                EDGE_ADMIN_TOKEN: 'ci-build-token-not-for-deploy',
                ORIGIN_SECRET: 'ci-origin-secret-not-for-deploy',
            }),
        });
        assert.strictEqual(result.ok, true, `compile failed: ${result.errors.join(' ')}`);
        assert.strictEqual(result.target, 'aws');
        assert.ok(result.edgeFiles.length >= 3, 'aws target emits 3 edge files');
        assert.ok(result.edgeFiles.every((f) => fs.existsSync(f)), 'all edge files must exist');
        assert.ok(result.infraFiles.length > 0, 'aws target emits infra files');
        assert.ok(result.infraFiles.every((f) => fs.existsSync(f)));
    }
    finally {
        ctx.cleanup();
    }
});
test('compile: unknown target returns structured error', () => {
    const result = api.compile({
        policyPath: '/tmp/nothing.yml',
        outDir: '/tmp/out',
        target: 'gcp',
    });
    assert.strictEqual(result.ok, false);
    assert.ok(result.errors.some((e) => /unknown target/i.test(e)));
});
test('compile: missing policyPath → error, no exit', () => {
    const result = api.compile({ outDir: '/tmp', target: 'aws' });
    assert.strictEqual(result.ok, false);
    assert.ok(result.errors.some((e) => /policyPath is required/.test(e)));
});
test('compile: missing outDir → error, no exit', () => {
    const result = api.compile({ policyPath: '/tmp/x.yml', target: 'aws' });
    assert.strictEqual(result.ok, false);
    assert.ok(result.errors.some((e) => /outDir is required/.test(e)));
});
test('compile: nonexistent policy file → structured error', () => {
    const result = api.compile({
        policyPath: '/no/such/policy.yml',
        outDir: '/tmp/irrelevant-should-not-be-created',
        target: 'aws',
    });
    assert.strictEqual(result.ok, false);
    assert.ok(result.errors.some((e) => /not found/i.test(e)));
});
// --- emitWaf ---
test('emitWaf: aws emits only infra, edgeFiles empty', () => {
    const ctx = tmpProject(BASIC_AWS_POLICY);
    try {
        const result = api.emitWaf({
            policyPath: ctx.policyPath,
            outDir: ctx.outDir,
            target: 'aws',
            env: Object.assign({}, process.env, {
                EDGE_ADMIN_TOKEN: 'ci-build-token-not-for-deploy',
                ORIGIN_SECRET: 'ci-origin-secret-not-for-deploy',
            }),
        });
        assert.strictEqual(result.ok, true, `emitWaf failed: ${result.errors.join(' ')}`);
        assert.deepStrictEqual(result.edgeFiles, [], 'emit-waf must NOT emit edge files');
        assert.ok(result.infraFiles.length > 0);
        const edgeDir = path.join(ctx.outDir, 'edge');
        assert.ok(!fs.existsSync(edgeDir), 'emit-waf must not create dist/edge/');
    }
    finally {
        ctx.cleanup();
    }
});
test('emitWaf: --format cloudformation returns ok=false with formatNotImplemented flag', () => {
    const ctx = tmpProject(BASIC_AWS_POLICY);
    try {
        const result = api.emitWaf({
            policyPath: ctx.policyPath,
            outDir: ctx.outDir,
            target: 'aws',
            format: 'cloudformation',
        });
        assert.strictEqual(result.ok, false);
        assert.strictEqual(result.formatNotImplemented, true);
        assert.ok(result.errors.some((e) => /not yet implemented/i.test(e)));
    }
    finally {
        ctx.cleanup();
    }
});
test('emitWaf: unknown format → structured error', () => {
    const result = api.emitWaf({
        policyPath: '/tmp/x.yml',
        outDir: '/tmp/out',
        target: 'aws',
        format: 'pulumi',
    });
    assert.strictEqual(result.ok, false);
    assert.ok(result.errors.some((e) => /unknown --format/i.test(e)));
});
// --- migratePolicy ---
test('migratePolicy: v1 → v1 is ok+noop', () => {
    const ctx = tmpProject(BASIC_AWS_POLICY);
    try {
        const result = api.migratePolicy({ policyPath: ctx.policyPath, toVersion: 1 });
        assert.strictEqual(result.ok, true);
        assert.strictEqual(result.noop, true);
        assert.strictEqual(result.migrated, false);
        assert.strictEqual(result.fromVersion, 1);
        assert.strictEqual(result.toVersion, 1);
    }
    finally {
        ctx.cleanup();
    }
});
test('migratePolicy: no version field → ok=false with guidance error', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'migrate-'));
    try {
        const policyPath = path.join(tmp, 'policy.yml');
        fs.writeFileSync(policyPath, 'project: noversion\n', 'utf8');
        const result = api.migratePolicy({ policyPath });
        assert.strictEqual(result.ok, false);
        assert.ok(result.errors.some((e) => /no `version` field/.test(e)));
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
test('migratePolicy: unknown forward path sets reservedExit2', () => {
    const ctx = tmpProject(BASIC_AWS_POLICY);
    try {
        const result = api.migratePolicy({ policyPath: ctx.policyPath, toVersion: 99 });
        assert.strictEqual(result.ok, false);
        assert.strictEqual(result.reservedExit2, true);
    }
    finally {
        ctx.cleanup();
    }
});
test('migratePolicy: downgrade rejected', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'migrate-'));
    try {
        const policyPath = path.join(tmp, 'policy.yml');
        fs.writeFileSync(policyPath, 'version: 5\nproject: future\n', 'utf8');
        const result = api.migratePolicy({ policyPath, toVersion: 1 });
        assert.strictEqual(result.ok, false);
        assert.ok(result.errors.some((e) => /Downgrade/.test(e)));
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
// --- runDoctor re-export ---
test('runDoctor: re-export is callable and returns exitCode + report', () => {
    // Doctor needs to run in a dir with no policy to hit the "policy_exists" fail
    // path cleanly — we don't care about pass/fail here, just the shape.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'doctor-'));
    try {
        const result = api.runDoctor({
            cwd: tmp,
            pkgRoot: repoRoot,
            reportPath: null,
        });
        assert.strictEqual(typeof result.exitCode, 'number');
        assert.ok(result.report && Array.isArray(result.report.checks));
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
// --- regression: CLI still works after refactor ---
test('CLI backwards-compat: `cdn-security build --target aws` still succeeds', () => {
    // We shell out to the CLI here precisely to verify the refactored bin/cli.js
    // still honors the legacy exit-code + stdout contract. Isolated tmp dir.
    const ctx = tmpProject(BASIC_AWS_POLICY);
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const result = spawnSync(process.execPath, [
            cli, 'build',
            '-p', ctx.policyPath,
            '-o', ctx.outDir,
            '--target', 'aws',
        ], {
            cwd: ctx.tmp,
            encoding: 'utf8',
            env: Object.assign({}, process.env, {
                EDGE_ADMIN_TOKEN: 'ci-build-token-not-for-deploy',
                ORIGIN_SECRET: 'ci-origin-secret-not-for-deploy',
            }),
        });
        assert.strictEqual(result.status, 0, `CLI build failed: ${result.stderr}`);
        assert.ok(fs.existsSync(path.join(ctx.outDir, 'edge', 'viewer-request.js')));
        assert.ok(fs.existsSync(path.join(ctx.outDir, 'infra', 'waf-rules.tf.json')));
    }
    finally {
        ctx.cleanup();
    }
});
if (process.exitCode) {
    process.exit(process.exitCode);
}
