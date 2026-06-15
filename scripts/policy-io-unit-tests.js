#!/usr/bin/env node
/**
 * Unit tests for src/scripts/lib/policy-io.ts (issue #182).
 *
 * Centralizes what was previously duplicated in compile-core,
 * compile-cloudflare, compile-infra, compile-cloudflare-waf, and the
 * CLI's `resolvePolicyPath` fallback:
 *   - defaultPolicyPath(rootDir) — `<rootDir>/policy/security.yml` else
 *     `<rootDir>/policy/base.yml`
 *   - defaultOutDir(rootDir)     — `<rootDir>/dist`
 *   - parseArgs(argv, rootDir)   — compiler-style argv with the exact
 *     pre-#182 semantics (last positional wins, --policy and positional
 *     priority follows argv order, --policy without a value is ignored,
 *     --out-dir same shape, unknown/boolean flags ignored)
 *   - loadPolicy / loadPolicyWithWarnings — parse a policy file, surface
 *     ENOENT for missing files so callers can map to a friendly message
 *
 * Kept self-contained (no Jest/Mocha) to match the existing test harness.
 */
'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { defaultPolicyPath, defaultOutDir, parseArgs, parseCompilerArgs, hasFlag, loadPolicy, loadPolicyWithWarnings, reportPolicyWarnings, reportPolicyLoadError, } = require('./lib/policy-io');
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
function makeTempRoot() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'policy-io-test-'));
}
function writePolicy(rootDir, name, body) {
    const dir = path.join(rootDir, 'policy');
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, name);
    fs.writeFileSync(file, body || 'version: 1\nproject: stub\n', 'utf8');
    return file;
}
function rmTempRoot(rootDir) {
    fs.rmSync(rootDir, { recursive: true, force: true });
}
// ---------------------------------------------------------------------------
// defaultPolicyPath
// ---------------------------------------------------------------------------
test('defaultPolicyPath prefers security.yml when both files exist', () => {
    const root = makeTempRoot();
    try {
        const security = writePolicy(root, 'security.yml');
        writePolicy(root, 'base.yml');
        assert.strictEqual(defaultPolicyPath(root), security);
    }
    finally {
        rmTempRoot(root);
    }
});
test('defaultPolicyPath falls back to base.yml when security.yml is missing', () => {
    const root = makeTempRoot();
    try {
        const base = writePolicy(root, 'base.yml');
        assert.strictEqual(defaultPolicyPath(root), base);
    }
    finally {
        rmTempRoot(root);
    }
});
test('defaultPolicyPath returns base.yml path even when neither file exists', () => {
    const root = makeTempRoot();
    try {
        const expected = path.join(root, 'policy', 'base.yml');
        assert.strictEqual(defaultPolicyPath(root), expected);
    }
    finally {
        rmTempRoot(root);
    }
});
// ---------------------------------------------------------------------------
// defaultOutDir
// ---------------------------------------------------------------------------
test('defaultOutDir joins `<rootDir>/dist`', () => {
    assert.strictEqual(defaultOutDir('/abs/root'), path.join('/abs/root', 'dist'));
    assert.strictEqual(defaultOutDir('relative/root'), path.join('relative/root', 'dist'));
});
// ---------------------------------------------------------------------------
// parseArgs — defaults
// ---------------------------------------------------------------------------
test('parseArgs returns default policyPath and outDir when argv is empty', () => {
    const root = makeTempRoot();
    try {
        const security = writePolicy(root, 'security.yml');
        const { policyPath, outDir } = parseArgs([], root);
        assert.strictEqual(policyPath, security);
        assert.strictEqual(outDir, path.join(root, 'dist'));
    }
    finally {
        rmTempRoot(root);
    }
});
test('parseArgs uses base.yml fallback when security.yml is missing and argv is empty', () => {
    const root = makeTempRoot();
    try {
        const base = writePolicy(root, 'base.yml');
        const { policyPath } = parseArgs([], root);
        assert.strictEqual(policyPath, base);
    }
    finally {
        rmTempRoot(root);
    }
});
// ---------------------------------------------------------------------------
// parseArgs — --policy / positional ordering
// ---------------------------------------------------------------------------
test('parseArgs honours --policy <value> when supplied first', () => {
    const root = makeTempRoot();
    try {
        writePolicy(root, 'security.yml');
        const { policyPath, outDir } = parseArgs(['--policy', 'policy/custom.yml'], root);
        assert.strictEqual(policyPath, 'policy/custom.yml');
        assert.strictEqual(outDir, path.join(root, 'dist'));
    }
    finally {
        rmTempRoot(root);
    }
});
test('parseArgs last positional wins when no --policy is present', () => {
    const root = makeTempRoot();
    try {
        writePolicy(root, 'security.yml');
        const { policyPath } = parseArgs(['policy/a.yml', 'policy/b.yml'], root);
        assert.strictEqual(policyPath, 'policy/b.yml');
    }
    finally {
        rmTempRoot(root);
    }
});
test('parseArgs --policy and positional compete in argv order: positional after --policy wins', () => {
    const root = makeTempRoot();
    try {
        writePolicy(root, 'security.yml');
        const { policyPath } = parseArgs(['--policy', 'policy/from-flag.yml', 'policy/from-positional.yml'], root);
        assert.strictEqual(policyPath, 'policy/from-positional.yml');
    }
    finally {
        rmTempRoot(root);
    }
});
test('parseArgs --policy and positional compete in argv order: --policy after positional wins', () => {
    const root = makeTempRoot();
    try {
        writePolicy(root, 'security.yml');
        const { policyPath } = parseArgs(['policy/from-positional.yml', '--policy', 'policy/from-flag.yml'], root);
        assert.strictEqual(policyPath, 'policy/from-flag.yml');
    }
    finally {
        rmTempRoot(root);
    }
});
test('parseArgs ignores --policy when it is the last token (no following value)', () => {
    const root = makeTempRoot();
    try {
        const security = writePolicy(root, 'security.yml');
        const { policyPath } = parseArgs(['--policy'], root);
        assert.strictEqual(policyPath, security);
    }
    finally {
        rmTempRoot(root);
    }
});
test('parseArgs ignores --out-dir when it is the last token (no following value)', () => {
    const root = makeTempRoot();
    try {
        const { outDir } = parseArgs(['--out-dir'], root);
        assert.strictEqual(outDir, path.join(root, 'dist'));
    }
    finally {
        rmTempRoot(root);
    }
});
test('parseArgs --out-dir <value> updates outDir only, leaving policyPath at default', () => {
    const root = makeTempRoot();
    try {
        const security = writePolicy(root, 'security.yml');
        const { policyPath, outDir } = parseArgs(['--out-dir', '/tmp/build'], root);
        assert.strictEqual(policyPath, security);
        assert.strictEqual(outDir, '/tmp/build');
    }
    finally {
        rmTempRoot(root);
    }
});
test('parseArgs last --out-dir wins when supplied multiple times', () => {
    const root = makeTempRoot();
    try {
        const { outDir } = parseArgs(['--out-dir', '/tmp/a', '--out-dir', '/tmp/b'], root);
        assert.strictEqual(outDir, '/tmp/b');
    }
    finally {
        rmTempRoot(root);
    }
});
// ---------------------------------------------------------------------------
// parseArgs — boolean / unknown flags
// ---------------------------------------------------------------------------
test('parseArgs ignores boolean flag --allow-placeholder-token (no value)', () => {
    const root = makeTempRoot();
    try {
        const security = writePolicy(root, 'security.yml');
        const { policyPath, outDir } = parseArgs(['--allow-placeholder-token'], root);
        assert.strictEqual(policyPath, security);
        assert.strictEqual(outDir, path.join(root, 'dist'));
    }
    finally {
        rmTempRoot(root);
    }
});
test('parseArgs ignores --fail-on-permissive, --strict-origin-auth, --rule-group-only, --fail-on-waf-approximation', () => {
    const root = makeTempRoot();
    try {
        const security = writePolicy(root, 'security.yml');
        const flags = [
            '--fail-on-permissive',
            '--strict-origin-auth',
            '--rule-group-only',
            '--fail-on-waf-approximation',
        ];
        for (const flag of flags) {
            const result = parseArgs([flag], root);
            assert.strictEqual(result.policyPath, security, `flag ${flag} should not change policyPath`);
            assert.strictEqual(result.outDir, path.join(root, 'dist'), `flag ${flag} should not change outDir`);
        }
    }
    finally {
        rmTempRoot(root);
    }
});
test('parseArgs ignores unknown --flag values and still picks up positional afterwards', () => {
    const root = makeTempRoot();
    try {
        writePolicy(root, 'security.yml');
        const { policyPath } = parseArgs(['--unknown-flag', '--also-unknown', 'policy/positional.yml'], root);
        assert.strictEqual(policyPath, 'policy/positional.yml');
    }
    finally {
        rmTempRoot(root);
    }
});
test('parseArgs allows --policy <value> mixed with boolean flags', () => {
    const root = makeTempRoot();
    try {
        writePolicy(root, 'security.yml');
        const { policyPath } = parseArgs(['--allow-placeholder-token', '--policy', 'policy/picked.yml', '--fail-on-permissive'], root);
        assert.strictEqual(policyPath, 'policy/picked.yml');
    }
    finally {
        rmTempRoot(root);
    }
});
test('parseArgs consumes --output-mode <value> so the value does not leak into the positional handler', () => {
    const root = makeTempRoot();
    try {
        const security = writePolicy(root, 'security.yml');
        // Without this, 'rule-group' would be picked up as a positional and
        // overwrite policyPath — the original pre-#182 inline loops consumed
        // --output-mode the same way, so the test in scripts/infra-unit-tests
        // for `--output-mode rule-group` keeps working.
        const { policyPath, outDir } = parseArgs(['--policy', 'policy/from-flag.yml', '--out-dir', '/tmp/x', '--output-mode', 'rule-group'], root);
        assert.strictEqual(policyPath, 'policy/from-flag.yml');
        assert.strictEqual(outDir, '/tmp/x');
        // Sanity: with security.yml as the default and only --output-mode in argv,
        // policyPath stays at the default.
        const result2 = parseArgs(['--output-mode', 'rule-group'], root);
        assert.strictEqual(result2.policyPath, security);
    }
    finally {
        rmTempRoot(root);
    }
});
test('parseArgs ignores --output-mode when it is the last token (no following value)', () => {
    const root = makeTempRoot();
    try {
        const security = writePolicy(root, 'security.yml');
        const { policyPath } = parseArgs(['--output-mode'], root);
        assert.strictEqual(policyPath, security);
    }
    finally {
        rmTempRoot(root);
    }
});
test('hasFlag preserves the old exact boolean flag detection semantics', () => {
    const argv = ['--allow-placeholder-token', '--policy', 'policy/a.yml'];
    assert.strictEqual(hasFlag(argv, '--allow-placeholder-token'), true);
    assert.strictEqual(hasFlag(argv, '--fail-on-permissive'), false);
    assert.strictEqual(hasFlag('--allow-placeholder-token', '--allow-placeholder-token'), false);
});
test('parseCompilerArgs returns paths plus common compiler boolean flags', () => {
    const root = makeTempRoot();
    try {
        writePolicy(root, 'security.yml');
        const result = parseCompilerArgs([
            '--policy',
            'policy/explicit.yml',
            '--out-dir',
            '/tmp/out',
            '--allow-placeholder-token',
            '--fail-on-permissive',
            '--strict-origin-auth',
            '--fail-on-waf-approximation',
        ], root);
        assert.deepStrictEqual(result, {
            policyPath: 'policy/explicit.yml',
            outDir: '/tmp/out',
            allowPlaceholderToken: true,
            failOnPermissive: true,
            strictOriginAuth: true,
            failOnWafApproximation: true,
        });
    }
    finally {
        rmTempRoot(root);
    }
});
// ---------------------------------------------------------------------------
// loadPolicy / loadPolicyWithWarnings
// ---------------------------------------------------------------------------
test('loadPolicy returns the parsed policy object', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-io-load-'));
    try {
        const policyFile = path.join(tmp, 'p.yml');
        fs.writeFileSync(policyFile, 'version: 1\nproject: loaded\n', 'utf8');
        const policy = loadPolicy(policyFile);
        assert.ok(policy && typeof policy === 'object');
        assert.strictEqual(policy.project, 'loaded');
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
test('loadPolicyWithWarnings returns { policy, warnings } for a valid file', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-io-load-'));
    try {
        const policyFile = path.join(tmp, 'p.yml');
        fs.writeFileSync(policyFile, 'version: 1\nproject: loaded\n', 'utf8');
        const result = loadPolicyWithWarnings(policyFile);
        assert.ok(result && typeof result === 'object');
        assert.ok(Array.isArray(result.warnings));
        assert.ok(result.policy && typeof result.policy === 'object');
        assert.strictEqual(result.policy.project, 'loaded');
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
test('loadPolicy throws an Error with code ENOENT for a missing file', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-io-load-'));
    try {
        const missing = path.join(tmp, 'does-not-exist.yml');
        let caught;
        try {
            loadPolicy(missing);
        }
        catch (e) {
            caught = e;
        }
        assert.ok(caught, 'expected loadPolicy to throw for missing file');
        assert.strictEqual(caught.code, 'ENOENT');
        assert.ok(/policy file not found/.test(caught.message), `expected "policy file not found" prefix, got: ${caught.message}`);
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
test('loadPolicyWithWarnings throws an Error with code ENOENT for a missing file', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-io-load-'));
    try {
        const missing = path.join(tmp, 'does-not-exist.yml');
        let caught;
        try {
            loadPolicyWithWarnings(missing);
        }
        catch (e) {
            caught = e;
        }
        assert.ok(caught, 'expected loadPolicyWithWarnings to throw for missing file');
        assert.strictEqual(caught.code, 'ENOENT');
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
test('reportPolicyWarnings includes the policy path when provided', () => {
    const lines = [];
    const logger = { warn: (...args) => lines.push(args.map(String).join(' ')) };
    reportPolicyWarnings(['legacy extends key'], 'policy/base.yml', logger);
    assert.deepStrictEqual(lines, [
        'Policy parse warnings: policy/base.yml',
        '  - legacy extends key',
    ]);
});
test('reportPolicyWarnings preserves compile-core header when no policy path is provided', () => {
    const lines = [];
    const logger = { warn: (...args) => lines.push(args.map(String).join(' ')) };
    reportPolicyWarnings(['legacy extends key'], undefined, logger);
    assert.deepStrictEqual(lines, [
        'Policy parse warnings:',
        '  - legacy extends key',
    ]);
});
test('reportPolicyLoadError prints file-not-found errors with the friendly policy path', () => {
    const lines = [];
    const logger = { error: (...args) => lines.push(args.map(String).join(' ')) };
    const err = new Error('policy file not found: missing.yml');
    err.code = 'ENOENT';
    reportPolicyLoadError('missing.yml', err, logger);
    assert.deepStrictEqual(lines, ['Error: policy file not found: missing.yml']);
});
test('reportPolicyLoadError prints parse errors with the original message', () => {
    const lines = [];
    const logger = { error: (...args) => lines.push(args.map(String).join(' ')) };
    reportPolicyLoadError('bad.yml', new Error('bad indentation'), logger);
    assert.deepStrictEqual(lines, ['Error: failed to parse policy YAML: bad indentation']);
});
