#!/usr/bin/env node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const repoRoot = path.join(__dirname, '..');
const { parsePolicyFile } = require('../parser');
const { validatePolicy } = require('../validator');
const { listInfraArtifacts, resolveAbsolute } = require('../emitter');
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
function mktmp(prefix = 'compiler-phase-') {
    return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}
test('parser phase: parses YAML without invoking validation or emission', () => {
    const tmp = mktmp();
    const policyPath = path.join(tmp, 'policy.yml');
    fs.writeFileSync(policyPath, 'version: 1\nrequest:\n  allow_methods: [GET]\nresponse_headers: {}\n', 'utf8');
    try {
        const result = parsePolicyFile({ policyPath });
        assert.strictEqual(result.ok, true);
        assert.strictEqual(result.policy.version, 1);
        assert.deepStrictEqual(result.errors, []);
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
test('validator phase: validates an already-parsed policy without emitting files', () => {
    const tmp = mktmp();
    try {
        const result = validatePolicy({
            pkgRoot: repoRoot,
            policy: {
                version: 1,
                request: { allow_methods: ['GET'] },
                response_headers: {},
            },
        });
        assert.strictEqual(result.ok, true, result.errors.join('\n'));
        assert.deepStrictEqual(fs.readdirSync(tmp), []);
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
test('emitter phase helpers: resolve paths and list infra artifacts without parsing policy', () => {
    const tmp = mktmp();
    const infraDir = path.join(tmp, 'dist', 'infra');
    fs.mkdirSync(infraDir, { recursive: true });
    fs.writeFileSync(path.join(infraDir, 'waf-rules.tf.json'), '{}\n', 'utf8');
    fs.writeFileSync(path.join(infraDir, 'notes.txt'), 'ignore\n', 'utf8');
    try {
        assert.strictEqual(resolveAbsolute('dist', tmp), path.join(tmp, 'dist'));
        const artifacts = listInfraArtifacts(path.join(tmp, 'dist'));
        assert.deepStrictEqual(artifacts, [path.join(infraDir, 'waf-rules.tf.json')]);
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
if (process.exitCode) {
    process.exit(process.exitCode);
}
