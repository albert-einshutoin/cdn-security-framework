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
const { parseMaxRssBytes } = require('./benchmark-compiler');
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
test('parser phase: resolves transitive extends with deep merge', () => {
    const tmp = mktmp();
    const globalPath = path.join(tmp, 'global.yml');
    const basePath = path.join(tmp, 'base.yml');
    const childPath = path.join(tmp, 'child.yml');
    fs.writeFileSync(globalPath, `version: 1
defaults:
  mode: monitor
request:
  allow_methods: [GET]
  limits:
    max_query_length: 1024
response_headers:
  hsts: "max-age=31536000"\n`, 'utf8');
    fs.writeFileSync(basePath, `version: 1
extends: ./global.yml
request:
  limits:
    max_query_params: 30
response_headers:
  csp: "default-src 'self'"\n`, 'utf8');
    fs.writeFileSync(childPath, `extends: ./base.yml
defaults:
  mode: enforce
request:
  limits:
    max_query_params: 60
`, 'utf8');
    try {
        const result = parsePolicyFile({ policyPath: childPath });
        assert.strictEqual(result.ok, true);
        assert.strictEqual(result.policy.defaults.mode, 'enforce');
        assert.strictEqual(result.policy.request.limits.max_query_length, 1024);
        assert.strictEqual(result.policy.request.limits.max_query_params, 60);
        assert.deepStrictEqual(result.policy.request.allow_methods, ['GET']);
        assert.strictEqual(result.policy.response_headers.csp, "default-src 'self'");
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
test('parser phase: appends array entries from child to parent on inheritance', () => {
    const tmp = mktmp();
    const basePath = path.join(tmp, 'base.yml');
    const childPath = path.join(tmp, 'child.yml');
    fs.writeFileSync(basePath, `version: 1\nrequest:\n  allow_methods: [GET]\nresponse_headers: {}\n`, 'utf8');
    fs.writeFileSync(childPath, `version: 1\nextends: ./base.yml\nrequest:\n  allow_methods: [POST]\nresponse_headers: {}\n`, 'utf8');
    try {
        const result = parsePolicyFile({ policyPath: childPath });
        assert.strictEqual(result.ok, true);
        assert.deepStrictEqual(result.policy.request.allow_methods, ['GET', 'POST']);
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
test('parser phase: merges nested objects with child overrides', () => {
    const tmp = mktmp();
    const basePath = path.join(tmp, 'base.yml');
    const childPath = path.join(tmp, 'child.yml');
    fs.writeFileSync(basePath, `version: 1\nrequest:\n  limits:\n    max_query_length: 1024\n    max_query_params: 20\nresponse_headers: {}\n`, 'utf8');
    fs.writeFileSync(childPath, `version: 1\nextends: ./base.yml\nrequest:\n  limits:\n    max_query_params: 30\n    max_uri_length: 2048\nresponse_headers: {}\n`, 'utf8');
    try {
        const result = parsePolicyFile({ policyPath: childPath });
        assert.strictEqual(result.ok, true);
        assert.strictEqual(result.policy.request.limits.max_query_length, 1024);
        assert.strictEqual(result.policy.request.limits.max_query_params, 30);
        assert.strictEqual(result.policy.request.limits.max_uri_length, 2048);
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
test('parser phase: emits unreachable-key warning when scalar replaces subtree', () => {
    const tmp = mktmp();
    const basePath = path.join(tmp, 'base.yml');
    const childPath = path.join(tmp, 'child.yml');
    fs.writeFileSync(basePath, `version: 1\nrequest:\n  limits:\n    max_query_length: 1024\nresponse_headers: {}\n`, 'utf8');
    fs.writeFileSync(childPath, `version: 1\nextends: ./base.yml\nrequest:\n  limits: null\nresponse_headers: {}\n`, 'utf8');
    try {
        const result = parsePolicyFile({ policyPath: childPath });
        assert.strictEqual(result.ok, true);
        assert.ok(Array.isArray(result.warnings));
        assert.ok(result.warnings.some((warning) => warning.includes('request.limits')));
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
test('benchmark compiler parses max RSS units from time output', () => {
    assert.strictEqual(parseMaxRssBytes('Maximum resident set size (kbytes): 1234\n'), 1234 * 1024);
    assert.strictEqual(parseMaxRssBytes('maximum resident set size: 2048 kbytes\n'), 2048 * 1024);
    assert.strictEqual(parseMaxRssBytes('987654  maximum resident set size\n'), 987654);
});
if (process.exitCode) {
    process.exit(process.exitCode);
}
