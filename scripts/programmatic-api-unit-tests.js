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
const STATIC_TOKEN_POLICY = `
version: 1
project: token-test
request:
  allow_methods: [GET, POST]
routes:
  - name: admin
    match:
      path_prefixes: ["/admin"]
    auth_gate:
      type: static_token
      header: x-edge-token
      token_env: EDGE_ADMIN_TOKEN
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
const READINESS_AWS_POLICY = `
version: 1
project: readiness-test
metadata:
  risk_level: balanced
defaults:
  mode: enforce
request:
  allow_methods: [GET, HEAD]
response_headers:
  hsts: "max-age=31536000; includeSubDomains"
  csp_public: "default-src 'self'; frame-ancestors 'none'"
firewall:
  waf:
    scope: CLOUDFRONT
    rate_limit: 1000
    managed_rules:
      - AWSManagedRulesCommonRuleSet
      - AWSManagedRulesIPReputationList
    logging:
      enabled: true
      destination_arn_env: WAF_LOG_DESTINATION_ARN
      redacted_fields: [authorization, cookie]
`;
const CAPABILITIES_POLICY = `
version: 1
project: capabilities-test
metadata:
  risk_level: balanced
defaults:
  mode: enforce
request:
  allow_methods: [GET, POST]
  graphql_guard:
    endpoint_paths: ["/graphql"]
    max_depth: 8
response_headers:
  hsts: "max-age=31536000"
response_dlp:
  enabled: true
  action: report_only
firewall:
  challenge:
    enabled: true
    path_prefixes: ["/login"]
  waf:
    scope: CLOUDFRONT
    rate_limit: 1000
    managed_rules:
      - AWSManagedRulesCommonRuleSet
`;
const REST_RECOMMENDATION_POLICY = `
version: 1
project: recommendation-rest-api
metadata:
  risk_level: balanced
  description: "REST API protected by CDN security framework."
defaults:
  mode: enforce
request:
  allow_methods: [GET, POST, OPTIONS]
response_headers:
  hsts: "max-age=31536000"
  csp_public: "default-src 'none'; frame-ancestors 'none'"
firewall:
  waf:
    scope: CLOUDFRONT
    rate_limit: 1000
    managed_rules:
      - AWSManagedRulesCommonRuleSet
    logging:
      enabled: true
      destination_arn_env: WAF_LOG_DESTINATION_ARN
      redacted_fields: [authorization, cookie]
`;
const MALFORMED_PREFIX_RECOMMENDATION_POLICY = `
version: 1
project: malformed-admin-prefix
metadata:
  risk_level: balanced
defaults:
  mode: enforce
request:
  allow_methods: [GET, POST]
routes:
  - name: admin
    match:
      path_prefixes: ["/admin", 7]
    auth_gate:
      type: static_token
      header: x-edge-token
      token_env: EDGE_ADMIN_TOKEN
response_headers:
  hsts: "max-age=31536000"
  csp_public: "default-src 'self'"
firewall:
  waf:
    scope: CLOUDFRONT
    rate_limit: 1000
    managed_rules:
      - AWSManagedRulesCommonRuleSet
`;
const PLAYGROUND_FIXTURES = [
    {
        name: 'allow GET /',
        request: {
            method: 'GET',
            path: '/',
            headers: {
                'user-agent': 'cli-test-client',
            },
        },
    },
    {
        name: 'block PATCH',
        request: {
            method: 'PATCH',
            path: '/',
            headers: {
                'user-agent': 'cli-test-client',
            },
        },
    },
    {
        name: 'path traversal is blocked',
        request: {
            method: 'GET',
            path: '/foo/../bar',
            headers: {
                'user-agent': 'cli-test-client',
            },
        },
    },
    {
        name: 'auth missing on admin',
        request: {
            method: 'GET',
            path: '/admin',
            headers: {
                'user-agent': 'cli-test-client',
            },
        },
    },
    {
        name: 'auth placeholder passes',
        request: {
            method: 'GET',
            path: '/admin',
            headers: {
                'user-agent': 'cli-test-client',
                'x-edge-token': 'INSECURE_PLACEHOLDER__REBUILD_WITH_REAL_TOKEN',
            },
        },
    },
    {
        name: 'query is visible in output',
        request: {
            method: 'GET',
            path: '/search',
            query: { q: 'hello', utm_source: 'cli' },
            headers: {
                'user-agent': 'cli-test-client',
            },
        },
    },
];
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
test('lintPolicy: rejects wildcard CORS origin when credentials are allowed', () => {
    const ctx = tmpProject(`
version: 1
project: api-test
request:
  allow_methods: [GET]
response_headers:
  hsts: "max-age=1"
  cors:
    allow_origins: ["*"]
    allow_credentials: true
`);
    try {
        const result = api.lintPolicy({ policyPath: ctx.policyPath });
        assert.strictEqual(result.ok, false);
        assert.ok(result.errors.some((e) => /allow_origins.*allow_credentials|\*/i.test(e)));
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
test('compile: allowPlaceholderToken permits non-production build without auth env', () => {
    const ctx = tmpProject(STATIC_TOKEN_POLICY);
    try {
        const result = api.compile({
            policyPath: ctx.policyPath,
            outDir: ctx.outDir,
            target: 'aws',
            allowPlaceholderToken: true,
            env: Object.assign({}, process.env, {
                EDGE_ADMIN_TOKEN: '',
                ORIGIN_SECRET: 'ci-origin-secret-not-for-deploy',
            }),
        });
        assert.strictEqual(result.ok, true, `compile failed: ${result.errors.join(' ')}`);
        const viewer = fs.readFileSync(path.join(ctx.outDir, 'edge', 'viewer-request.js'), 'utf8');
        assert.ok(viewer.includes('INSECURE_PLACEHOLDER__REBUILD_WITH_REAL_TOKEN'));
        assert.ok(result.warnings.some((w) => /allow-placeholder-token/.test(w)));
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
test('emitWaf: --format cloudformation emits AWS CloudFormation template', () => {
    const ctx = tmpProject(BASIC_AWS_POLICY);
    try {
        const result = api.emitWaf({
            policyPath: ctx.policyPath,
            outDir: ctx.outDir,
            target: 'aws',
            format: 'cloudformation',
        });
        assert.strictEqual(result.ok, true, `emitWaf failed: ${result.errors.join(' ')}`);
        assert.strictEqual(result.formatNotImplemented, false);
        assert.ok(result.infraFiles.some((f) => f.endsWith('waf-cloudformation.json')));
        const doc = JSON.parse(fs.readFileSync(path.join(ctx.outDir, 'infra', 'waf-cloudformation.json'), 'utf8'));
        assert.ok(Object.values(doc.Resources).some((r) => r.Type === 'AWS::WAFv2::RuleGroup'));
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
test('CLI authoring DX: build --allow-placeholder-token succeeds without auth env', () => {
    const ctx = tmpProject(BASIC_AWS_POLICY);
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const result = spawnSync(process.execPath, [
            cli, 'build',
            '-p', ctx.policyPath,
            '-o', ctx.outDir,
            '--target', 'aws',
            '--allow-placeholder-token',
        ], {
            cwd: ctx.tmp,
            encoding: 'utf8',
            env: Object.assign({}, process.env, {
                EDGE_ADMIN_TOKEN: '',
                ORIGIN_SECRET: 'ci-origin-secret-not-for-deploy',
            }),
        });
        assert.strictEqual(result.status, 0, `CLI build failed: ${result.stderr}`);
        assert.ok(result.stderr.includes('Generated artifacts are NOT safe for production'));
        assert.ok(fs.existsSync(path.join(ctx.outDir, 'edge', 'viewer-request.js')));
    }
    finally {
        ctx.cleanup();
    }
});
test('CLI authoring DX: playground emits AWS + Cloudflare fixture decisions', () => {
    const ctx = tmpProject(STATIC_TOKEN_POLICY);
    try {
        const fixturePath = path.join(ctx.tmp, 'playground.fixture.json');
        fs.writeFileSync(fixturePath, JSON.stringify({ fixtures: PLAYGROUND_FIXTURES }, null, 2), 'utf8');
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const result = spawnSync(process.execPath, [
            cli, 'playground',
            '-p', ctx.policyPath,
            '-f', fixturePath,
            '--target', 'all',
            '--json',
        ], {
            cwd: ctx.tmp,
            encoding: 'utf8',
            env: Object.assign({}, process.env, {
                // playground defaults allow placeholder replacement, no runtime secrets required
                EDGE_ADMIN_TOKEN: '',
                ORIGIN_SECRET: 'ci-origin-secret-not-for-deploy',
            }),
        });
        assert.strictEqual(result.status, 0, `playground failed: ${result.stderr}`);
        const report = JSON.parse(result.stdout);
        assert.strictEqual(report.policyPath, ctx.policyPath);
        assert.strictEqual(report.targets.length, 2, 'expected aws + cloudflare results');
        const byTarget = Object.fromEntries(report.targets.map((r) => [r.target, r.fixtures]));
        assert.ok(Array.isArray(byTarget.aws), 'aws target missing');
        assert.ok(Array.isArray(byTarget.cloudflare), 'cloudflare target missing');
        const awsAllow = byTarget.aws.find((f) => f.name === 'allow GET /');
        const awsPatch = byTarget.aws.find((f) => f.name === 'block PATCH');
        const awsAuthMissing = byTarget.aws.find((f) => f.name === 'auth missing on admin');
        const awsAuthPass = byTarget.aws.find((f) => f.name === 'auth placeholder passes');
        const awsTraversal = byTarget.aws.find((f) => f.name === 'path traversal is blocked');
        const awsQuery = byTarget.aws.find((f) => f.name === 'query is visible in output');
        assert.ok(awsAllow);
        assert.ok(awsPatch);
        assert.ok(awsAuthMissing);
        assert.ok(awsAuthPass);
        assert.ok(awsTraversal);
        assert.ok(awsQuery);
        assert.strictEqual(awsAllow.decision, 'pass');
        assert.strictEqual(awsPatch.decision, 'block');
        assert.strictEqual(awsTraversal.decision, 'block');
        assert.strictEqual(awsAuthMissing.decision, 'block');
        assert.strictEqual(awsAuthPass.decision, 'pass');
        assert.ok(awsPatch.status >= 400);
        assert.ok(awsTraversal.status >= 400);
        assert.ok(awsAuthMissing.status >= 400);
        assert.strictEqual(awsAllow.status, 200);
        assert.strictEqual(awsAuthPass.status, 200);
        assert.strictEqual(awsQuery.query, 'q=hello&utm_source=cli');
        assert.ok(awsQuery.path === '/search');
        const cloudAllow = byTarget.cloudflare.find((f) => f.name === 'allow GET /');
        const cloudPatch = byTarget.cloudflare.find((f) => f.name === 'block PATCH');
        assert.ok(cloudAllow);
        assert.ok(cloudPatch);
        assert.strictEqual(cloudAllow.decision, 'pass');
        assert.strictEqual(cloudPatch.decision, 'block');
    }
    finally {
        ctx.cleanup();
    }
});
test('CLI authoring DX: analyze surfaces low-frequency block candidates', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'analyze-'));
    const logPath = path.join(tmp, 'monitor.jsonl');
    const lines = [
        { event: 'block', block_reason: 'bad_method', method: 'POST', status: 405, uri: '/api/data', target: 'aws', policy_route: '/api/data' },
        { event: 'block', block_reason: 'bad_method', method: 'PUT', status: 405, uri: '/api/data', target: 'aws', policy_route: '/api/data' },
        { event: 'block', block_reason: 'path_traversal', method: 'GET', status: 404, uri: '/assets/../etc/passwd', target: 'cloudflare', policy_route: '/assets' },
        { event: 'monitor', block_reason: 'path_traversal', method: 'GET', status: 200, uri: '/assets/favicon.ico', target: 'aws', policy_route: '/assets' },
    ];
    fs.writeFileSync(logPath, lines.map((row) => JSON.stringify(row)).join('\n') + '\n', 'utf8');
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const result = spawnSync(process.execPath, [
            cli, 'analyze',
            '--input', logPath,
            '--min-count', '2',
            '--top', '10',
            '--json',
        ], {
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(result.status, 0, `analyze failed: ${result.stderr}`);
        const report = JSON.parse(result.stdout);
        assert.strictEqual(report.summary.totalLines, 4);
        assert.strictEqual(report.summary.parsedLines, 4);
        assert.strictEqual(report.summary.unparseableLines, 0);
        assert.strictEqual(report.summary.analyzedEvents, 4);
        assert.strictEqual(report.summary.blockEvents, 3);
        assert.strictEqual(report.summary.monitorEvents, 1);
        assert.strictEqual(report.byBlockReason['bad_method']?.count, 2);
        assert.strictEqual(report.byPolicyRoute['/api/data']?.count, 2);
        const badMethod = report.candidates.find((x) => x.blockReason === 'bad_method' && x.policyRoute === '/api/data');
        assert.ok(badMethod, 'missing bad_method candidate');
        assert.strictEqual(badMethod.count, 2);
        assert.strictEqual(Array.isArray(badMethod.targets), true);
        assert.ok(badMethod.targets.includes('aws'));
        assert.strictEqual(Array.isArray(badMethod.events), true);
        assert.ok(badMethod.events.length >= 1);
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
test('CLI authoring DX: init --guided emits lintable policy with selected shape', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'guided-init-'));
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const result = spawnSync(process.execPath, [
            cli, 'init',
            '--guided',
            '--platform', 'cloudflare',
            '--app-shape', 'rest-api',
            '--auth', 'jwt',
            '--admin-paths', '/api/',
            '--cors-origins', 'https://app.example.com',
            '--waf', 'strict',
            '--geo-block', 'RU,CN',
            '--ip-allowlist', '203.0.113.0/24',
            '--deployment', 'github-actions',
            '--project', 'guided-api',
            '--force',
        ], {
            cwd: tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(result.status, 0, `guided init failed: ${result.stderr}`);
        const policyPath = path.join(tmp, 'policy', 'security.yml');
        const raw = fs.readFileSync(policyPath, 'utf8');
        assert.ok(raw.includes('Secrets are referenced by environment variable name only'));
        const policy = require('js-yaml').load(raw);
        assert.strictEqual(policy.project, 'guided-api');
        assert.strictEqual(policy.metadata.risk_level, 'strict');
        assert.strictEqual(policy.routes[0].auth_gate.type, 'jwt');
        assert.deepStrictEqual(policy.routes[0].match.path_prefixes, ['/api/']);
        assert.deepStrictEqual(policy.response_headers.cors.allow_origins, ['https://app.example.com']);
        assert.deepStrictEqual(policy.firewall.waf.managed_rules, ['AWSManagedRulesCommonRuleSet']);
        assert.deepStrictEqual(policy.firewall.geo.block_countries, ['RU', 'CN']);
        assert.deepStrictEqual(policy.firewall.ip.allowlist, ['203.0.113.0/24']);
        const lint = api.lintPolicy({ policyPath });
        assert.strictEqual(lint.ok, true, `guided policy lint failed: ${JSON.stringify(lint.errors)}`);
        const readiness = spawnSync(process.execPath, [
            cli, 'readiness',
            '-p', policyPath,
            '--target', 'cloudflare',
            '--strict',
        ], {
            cwd: tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(readiness.status, 0, `guided policy readiness failed: ${readiness.stderr}`);
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
test('CLI backwards-compat: init --profile still scaffolds existing starter flow', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'profile-init-'));
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const result = spawnSync(process.execPath, [
            cli, 'init',
            '--platform', 'aws',
            '--profile', 'balanced',
            '--force',
        ], {
            cwd: tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(result.status, 0, `profile init failed: ${result.stderr}`);
        assert.ok(fs.existsSync(path.join(tmp, 'policy', 'security.yml')));
        assert.ok(fs.existsSync(path.join(tmp, 'policy', 'profiles', 'balanced.yml')));
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
test('CLI authoring DX: init --guided non-interactive applies defaults without optional prompts', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'guided-init-defaults-'));
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const result = spawnSync(process.execPath, [
            cli, 'init',
            '--guided',
            '--app-shape', 'rest-api',
            '--auth', 'jwt',
            '--waf', 'strict',
            '--force',
        ], {
            cwd: tmp,
            encoding: 'utf8',
            env: process.env,
            input: '',
        });
        assert.strictEqual(result.status, 0, `guided init defaults failed: ${result.stderr}`);
        const raw = fs.readFileSync(path.join(tmp, 'policy', 'security.yml'), 'utf8');
        const policy = require('js-yaml').load(raw);
        assert.strictEqual(policy.project, 'guided-rest-api');
        assert.strictEqual(policy.metadata.description, 'Guided setup: rest-api on aws, auth=jwt, deployment=build-only.');
        assert.deepStrictEqual(policy.routes[0].match.path_prefixes, ['/api/']);
        assert.deepStrictEqual(policy.response_headers.cors.allow_origins, ['https://app.example.com']);
        assert.deepStrictEqual(policy.firewall.waf.managed_rules, [
            'AWSManagedRulesCommonRuleSet',
            'AWSManagedRulesKnownBadInputsRuleSet',
            'AWSManagedRulesIPReputationList',
            'AWSManagedRulesSQLiRuleSet',
            'AWSManagedRulesAnonymousIpList',
            'AWSManagedRulesBotControlRuleSet',
        ]);
        assert.deepStrictEqual(policy.firewall.waf.logging, {
            enabled: true,
            destination_arn_env: 'WAF_LOG_DESTINATION_ARN',
            redacted_fields: ['authorization', 'cookie', 'x-api-key'],
        });
        assert.strictEqual(policy.firewall.geo, undefined);
        assert.strictEqual(policy.firewall.ip, undefined);
        const readiness = spawnSync(process.execPath, [
            cli, 'readiness',
            '-p', path.join(tmp, 'policy', 'security.yml'),
            '--target', 'aws',
            '--strict',
        ], {
            cwd: tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(readiness.status, 0, `guided default policy readiness failed: ${readiness.stderr}`);
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
test('CLI authoring DX: explain summarizes policy posture', () => {
    const ctx = tmpProject(BASIC_AWS_POLICY);
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const result = spawnSync(process.execPath, [
            cli, 'explain',
            '-p', ctx.policyPath,
        ], {
            cwd: ctx.tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(result.status, 0, `explain failed: ${result.stderr}`);
        assert.ok(/Policy: api-test/.test(result.stdout));
        assert.ok(/Allowed methods: GET, POST/.test(result.stdout));
        assert.ok(/WAF:/.test(result.stdout));
    }
    finally {
        ctx.cleanup();
    }
});
test('CLI authoring DX: capabilities prints target matrix', () => {
    const { spawnSync } = require('child_process');
    const cli = path.join(repoRoot, 'bin', 'cli.js');
    const result = spawnSync(process.execPath, [
        cli, 'capabilities',
    ], {
        cwd: repoRoot,
        encoding: 'utf8',
        env: process.env,
    });
    assert.strictEqual(result.status, 0, `capabilities failed: ${result.stderr}`);
    assert.ok(/Target Capabilities Matrix/.test(result.stdout));
    assert.ok(/AWS CloudFront Functions/.test(result.stdout));
    assert.ok(/AWS Lambda@Edge/.test(result.stdout));
    assert.ok(/Cloudflare Workers/.test(result.stdout));
    assert.ok(/Terraform-backed WAF/.test(result.stdout));
    assert.ok(/response\.response_dlp/.test(result.stdout));
});
test('CLI authoring DX: capabilities JSON evaluates unsupported target controls', () => {
    const ctx = tmpProject(CAPABILITIES_POLICY);
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const result = spawnSync(process.execPath, [
            cli, 'capabilities',
            '--policy', ctx.policyPath,
            '--target', 'aws',
            '--json',
        ], {
            cwd: ctx.tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(result.status, 0, `capabilities JSON failed: ${result.stderr}`);
        const report = JSON.parse(result.stdout);
        assert.strictEqual(report.target, 'aws');
        assert.ok(report.targets.some((target) => target.key === 'cloudfront_functions'));
        assert.ok(report.capabilities.some((cap) => cap.id === 'request.graphql_guard'));
        assert.ok(report.capabilities.some((cap) => cap.id === 'response.response_dlp'));
        assert.ok(report.policyEvaluation);
        assert.ok(report.policyEvaluation.configuredControls.some((cap) => cap.id === 'request.graphql_guard'));
        assert.ok(report.policyEvaluation.configuredControls.some((cap) => cap.id === 'response.response_dlp'));
        assert.ok(report.policyEvaluation.findings.some((finding) => finding.capabilityId === 'request.graphql_guard' && finding.status === 'warning-only'));
        assert.ok(report.policyEvaluation.findings.some((finding) => finding.capabilityId === 'response.response_dlp' && finding.status === 'warning-only'));
        assert.ok(report.policyEvaluation.findings.some((finding) => finding.capabilityId === 'firewall.challenge' && finding.status === 'warning-only'));
    }
    finally {
        ctx.cleanup();
    }
});
test('CLI authoring DX: capabilities ignores disabled challenge controls', () => {
    const disabledChallengePolicy = CAPABILITIES_POLICY.replace('  challenge:\n    enabled: true', '  challenge:\n    enabled: false');
    const ctx = tmpProject(disabledChallengePolicy);
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const result = spawnSync(process.execPath, [
            cli, 'capabilities',
            '--policy', ctx.policyPath,
            '--target', 'aws',
            '--json',
        ], {
            cwd: ctx.tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(result.status, 0, `capabilities JSON failed: ${result.stderr}`);
        const report = JSON.parse(result.stdout);
        assert.ok(report.policyEvaluation);
        assert.ok(!report.policyEvaluation.configuredControls.some((cap) => cap.id === 'firewall.challenge'));
        assert.ok(!report.policyEvaluation.findings.some((finding) => finding.capabilityId === 'firewall.challenge'));
    }
    finally {
        ctx.cleanup();
    }
});
test('CLI authoring DX: readiness passes production-shaped policy and writes report', () => {
    const ctx = tmpProject(READINESS_AWS_POLICY);
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const reportPath = path.join(ctx.tmp, 'readiness-report.json');
        const result = spawnSync(process.execPath, [
            cli, 'readiness',
            '-p', ctx.policyPath,
            '--target', 'aws',
            '--report', reportPath,
        ], {
            cwd: ctx.tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(result.status, 0, `readiness failed: ${result.stderr}`);
        assert.ok(/Readiness: PASS/.test(result.stdout));
        const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
        assert.strictEqual(report.status, 'pass');
        assert.deepStrictEqual(report.summary, { fail: 0, warn: 0 });
    }
    finally {
        ctx.cleanup();
    }
});
test('CLI authoring DX: readiness ignores disabled challenge controls', () => {
    const disabledChallengePolicy = READINESS_AWS_POLICY.replace('firewall:\n  waf:', 'firewall:\n  challenge:\n    enabled: false\n  waf:');
    const ctx = tmpProject(disabledChallengePolicy);
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const result = spawnSync(process.execPath, [
            cli, 'readiness',
            '-p', ctx.policyPath,
            '--target', 'aws',
        ], {
            cwd: ctx.tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(result.status, 0, `readiness failed: ${result.stderr}`);
        assert.ok(/Readiness: PASS/.test(result.stdout));
        assert.ok(!/target\.aws\.challenge\.unsupported/.test(result.stdout + result.stderr));
    }
    finally {
        ctx.cleanup();
    }
});
test('CLI authoring DX: readiness fails when referenced build secret is missing', () => {
    const ctx = tmpProject(STATIC_TOKEN_POLICY);
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const result = spawnSync(process.execPath, [
            cli, 'readiness',
            '-p', ctx.policyPath,
            '--target', 'aws',
        ], {
            cwd: ctx.tmp,
            encoding: 'utf8',
            env: Object.assign({}, process.env, { EDGE_ADMIN_TOKEN: '' }),
        });
        assert.strictEqual(result.status, 1);
        assert.ok(/doctor\.env_vars_referenced_by_policy/.test(result.stderr));
    }
    finally {
        ctx.cleanup();
    }
});
test('CLI authoring DX: readiness strict mode fails on warnings', () => {
    const ctx = tmpProject(BASIC_AWS_POLICY);
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const result = spawnSync(process.execPath, [
            cli, 'readiness',
            '-p', ctx.policyPath,
            '--target', 'aws',
            '--strict',
        ], {
            cwd: ctx.tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(result.status, 1);
        assert.ok(/firewall\.waf\.managed_rules\.core_signal_missing/.test(result.stderr));
    }
    finally {
        ctx.cleanup();
    }
});
test('CLI authoring DX: readiness keeps weak WAF baseline as warning by default', () => {
    const ctx = tmpProject(BASIC_AWS_POLICY);
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const result = spawnSync(process.execPath, [
            cli, 'readiness',
            '-p', ctx.policyPath,
            '--target', 'aws',
            '--json',
        ], {
            cwd: ctx.tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(result.status, 0, `readiness failed: ${result.stderr}`);
        const report = JSON.parse(result.stdout);
        assert.strictEqual(report.status, 'warn');
        assert.strictEqual(report.failOnWeakWafBaseline, false);
        assert.ok(report.findings.some((finding) => finding.id === 'firewall.waf.managed_rules.core_signal_missing' &&
            finding.severity === 'warn'));
        assert.ok(report.findings.some((finding) => finding.id === 'firewall.waf.logging.missing' &&
            finding.severity === 'warn'));
    }
    finally {
        ctx.cleanup();
    }
});
test('CLI authoring DX: readiness can fail weak WAF baseline without strict mode', () => {
    const ctx = tmpProject(BASIC_AWS_POLICY);
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const result = spawnSync(process.execPath, [
            cli, 'readiness',
            '-p', ctx.policyPath,
            '--target', 'aws',
            '--fail-on-weak-waf-baseline',
            '--json',
        ], {
            cwd: ctx.tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(result.status, 1);
        const report = JSON.parse(result.stdout);
        assert.strictEqual(report.status, 'fail');
        assert.strictEqual(report.failOnWeakWafBaseline, true);
        assert.ok(report.findings.some((finding) => finding.id === 'firewall.waf.managed_rules.core_signal_missing' &&
            finding.severity === 'fail'));
        assert.ok(report.findings.some((finding) => finding.id === 'firewall.waf.logging.missing' &&
            finding.severity === 'fail'));
        assert.ok(report.findings.some((finding) => finding.id === 'policy.risk_level.missing' &&
            finding.severity === 'warn'));
    }
    finally {
        ctx.cleanup();
    }
});
test('CLI authoring DX: readiness weak WAF baseline gate passes production-shaped policy', () => {
    const ctx = tmpProject(READINESS_AWS_POLICY);
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const result = spawnSync(process.execPath, [
            cli, 'readiness',
            '-p', ctx.policyPath,
            '--target', 'aws',
            '--fail-on-weak-waf-baseline',
            '--json',
        ], {
            cwd: ctx.tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(result.status, 0, `readiness failed: ${result.stderr}`);
        const report = JSON.parse(result.stdout);
        assert.strictEqual(report.status, 'pass');
        assert.strictEqual(report.failOnWeakWafBaseline, true);
        assert.deepStrictEqual(report.summary, { fail: 0, warn: 0 });
    }
    finally {
        ctx.cleanup();
    }
});
test('CLI authoring DX: readiness has stable outcomes for built-in profiles', () => {
    const { spawnSync } = require('child_process');
    const cli = path.join(repoRoot, 'bin', 'cli.js');
    const runProfile = (name) => {
        const result = spawnSync(process.execPath, [
            cli, 'readiness',
            '-p', path.join(repoRoot, 'policy', 'profiles', `${name}.yml`),
            '--target', 'aws',
            '--json',
        ], {
            cwd: repoRoot,
            encoding: 'utf8',
            env: Object.assign({}, process.env, {
                EDGE_ADMIN_TOKEN: 'ci-build-token-not-for-deploy',
            }),
        });
        return { result, report: JSON.parse(result.stdout) };
    };
    const balanced = runProfile('balanced');
    assert.strictEqual(balanced.result.status, 0, balanced.result.stderr);
    assert.strictEqual(balanced.report.status, 'pass');
    const strict = runProfile('strict');
    assert.strictEqual(strict.result.status, 0, strict.result.stderr);
    assert.strictEqual(strict.report.status, 'warn');
    assert.ok(strict.report.findings.some((finding) => finding.id === 'firewall.waf.logging.missing' &&
        finding.severity === 'warn'));
    const permissive = runProfile('permissive');
    assert.strictEqual(permissive.result.status, 1);
    assert.strictEqual(permissive.report.status, 'fail');
    assert.ok(permissive.report.findings.some((finding) => finding.id === 'policy.risk_level.permissive' &&
        finding.severity === 'fail'));
});
test('CLI authoring DX: readiness reports target-specific unsupported controls', () => {
    const ctx = tmpProject(CAPABILITIES_POLICY);
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const aws = spawnSync(process.execPath, [
            cli, 'readiness',
            '-p', ctx.policyPath,
            '--target', 'aws',
            '--json',
        ], {
            cwd: ctx.tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(aws.status, 1);
        const awsReport = JSON.parse(aws.stdout);
        assert.ok(awsReport.findings.some((finding) => finding.id === 'target.aws.graphql_guard.unsupported'));
        assert.ok(awsReport.findings.some((finding) => finding.id === 'target.aws.challenge.unsupported'));
        assert.ok(awsReport.findings.some((finding) => finding.id === 'target.aws.response_dlp.unsupported'));
        const cloudflare = spawnSync(process.execPath, [
            cli, 'readiness',
            '-p', ctx.policyPath,
            '--target', 'cloudflare',
            '--json',
        ], {
            cwd: ctx.tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(cloudflare.status, 0, cloudflare.stderr);
        const cloudflareReport = JSON.parse(cloudflare.stdout);
        assert.ok(!cloudflareReport.findings.some((finding) => finding.id.startsWith('target.aws.')));
    }
    finally {
        ctx.cleanup();
    }
});
test('CLI authoring DX: readiness emits read-only WAF recommendations with rationale', () => {
    const ctx = tmpProject(REST_RECOMMENDATION_POLICY);
    try {
        const before = fs.readFileSync(ctx.policyPath, 'utf8');
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const result = spawnSync(process.execPath, [
            cli, 'readiness',
            '-p', ctx.policyPath,
            '--target', 'aws',
            '--json',
        ], {
            cwd: ctx.tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(result.status, 0, `readiness failed: ${result.stderr}`);
        assert.strictEqual(fs.readFileSync(ctx.policyPath, 'utf8'), before, 'readiness must not mutate policy files');
        const report = JSON.parse(result.stdout);
        assert.strictEqual(report.wafRecommendations.readOnly, true);
        assert.strictEqual(report.wafRecommendations.inferredAppShape, 'rest-api');
        const rec = report.wafRecommendations.recommendations[0];
        assert.strictEqual(rec.id, 'waf.recommendation.rest_api');
        assert.strictEqual(rec.targetSupport.aws, 'supported');
        assert.strictEqual(rec.targetSupport.cloudflare, 'partial');
        assert.ok(rec.missingRules.includes('AWSManagedRulesKnownBadInputsRuleSet'));
        assert.ok(rec.missingRules.includes('AWSManagedRulesSQLiRuleSet'));
        assert.ok(rec.missingRules.includes('AWSManagedRulesIPReputationList'));
        assert.ok(rec.settings.some((setting) => setting.includes('rate_limit_rules')));
        assert.ok(/JSON APIs/.test(rec.rationale));
        assert.ok(/costs/i.test(rec.cost));
        assert.ok(/SQLi/.test(rec.falsePositiveRisk));
    }
    finally {
        ctx.cleanup();
    }
});
test('CLI authoring DX: WAF recommendations infer all built-in archetype shapes', () => {
    const { spawnSync } = require('child_process');
    const cli = path.join(repoRoot, 'bin', 'cli.js');
    const archetypes = [
        'spa-static-site',
        'rest-api',
        'admin-panel',
        'microservice-origin',
    ];
    for (const shape of archetypes) {
        const result = spawnSync(process.execPath, [
            cli, 'readiness',
            '-p', path.join(repoRoot, 'policy', 'archetypes', `${shape}.yml`),
            '--target', 'aws',
            '--json',
        ], {
            cwd: repoRoot,
            encoding: 'utf8',
            env: Object.assign({}, process.env, {
                EDGE_ADMIN_TOKEN: 'ci-build-token-not-for-deploy',
                ORIGIN_SECRET: 'ci-origin-secret-not-for-deploy',
            }),
        });
        assert.strictEqual(result.status, 0, `${shape} readiness failed: ${result.stderr}`);
        const report = JSON.parse(result.stdout);
        assert.strictEqual(report.wafRecommendations.inferredAppShape, shape);
        assert.strictEqual(report.wafRecommendations.recommendations.length, 1);
        const rec = report.wafRecommendations.recommendations[0];
        assert.strictEqual(rec.appShape, shape);
        assert.ok(rec.rationale);
        assert.ok(rec.cost);
        assert.ok(rec.falsePositiveRisk);
        if (shape === 'admin-panel') {
            assert.strictEqual(rec.targetSupport.cloudflare, 'unsupported');
            assert.ok(/paid/.test(rec.cost));
            assert.ok(rec.rules.includes('AWSManagedRulesBotControlRuleSet'));
            assert.ok(rec.rules.includes('AWSManagedRulesATPRuleSet'));
        }
    }
});
test('CLI authoring DX: WAF recommendation inference does not mask lint errors', () => {
    const ctx = tmpProject(MALFORMED_PREFIX_RECOMMENDATION_POLICY);
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const result = spawnSync(process.execPath, [
            cli, 'readiness',
            '-p', ctx.policyPath,
            '--target', 'aws',
            '--json',
        ], {
            cwd: ctx.tmp,
            encoding: 'utf8',
            env: Object.assign({}, process.env, {
                EDGE_ADMIN_TOKEN: 'ci-build-token-not-for-deploy',
            }),
        });
        assert.strictEqual(result.status, 1);
        assert.doesNotThrow(() => JSON.parse(result.stdout));
        const report = JSON.parse(result.stdout);
        assert.ok(report.findings.some((finding) => finding.id === 'policy.lint.error' &&
            /path_prefixes/.test(finding.detail)));
        assert.strictEqual(report.wafRecommendations.inferredAppShape, 'admin-panel');
    }
    finally {
        ctx.cleanup();
    }
});
test('CLI authoring DX: deploy-template emits AWS and Cloudflare workflow templates', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'deploy-template-'));
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const outDir = path.join(tmp, '.github', 'workflows');
        const result = spawnSync(process.execPath, [
            cli, 'deploy-template',
            '--target', 'all',
            '--out-dir', outDir,
        ], {
            cwd: tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(result.status, 0, `deploy-template failed: ${result.stderr}`);
        const aws = fs.readFileSync(path.join(outDir, 'cdn-security-aws.yml'), 'utf8');
        const cloudflare = fs.readFileSync(path.join(outDir, 'cdn-security-cloudflare.yml'), 'utf8');
        assert.ok(aws.includes('cdn-security readiness --target aws --strict'));
        assert.ok(aws.includes('${{ secrets.EDGE_ADMIN_TOKEN }}'));
        assert.ok(aws.includes('cdn-security build --target aws --out-dir dist'));
        assert.ok(cloudflare.includes('cdn-security readiness --target cloudflare --strict'));
        assert.ok(cloudflare.includes('CDN_SECURITY_WORKER_SECRET_NAMES'));
        assert.ok(cloudflare.includes('CDN_SECURITY_WORKER_SECRETS_FILE'));
        assert.ok(cloudflare.includes('npx wrangler deploy dist/edge/cloudflare/index.ts --secrets-file'));
        assert.ok(cloudflare.includes('${{ secrets.CLOUDFLARE_API_TOKEN }}'));
        assert.ok(cloudflare.includes("'wrangler.toml'"));
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
test('CLI authoring DX: deploy-template refuses overwrite without --force', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'deploy-template-'));
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const outDir = path.join(tmp, '.github', 'workflows');
        fs.mkdirSync(outDir, { recursive: true });
        fs.writeFileSync(path.join(outDir, 'cdn-security-aws.yml'), 'existing\n', 'utf8');
        const result = spawnSync(process.execPath, [
            cli, 'deploy-template',
            '--target', 'aws',
            '--out-dir', outDir,
        ], {
            cwd: tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(result.status, 1);
        assert.ok(/already exists/.test(result.stderr));
        const forced = spawnSync(process.execPath, [
            cli, 'deploy-template',
            '--target', 'aws',
            '--out-dir', outDir,
            '--force',
        ], {
            cwd: tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(forced.status, 0, `forced deploy-template failed: ${forced.stderr}`);
        assert.ok(fs.readFileSync(path.join(outDir, 'cdn-security-aws.yml'), 'utf8').includes('CDN Security AWS Build'));
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
test('CLI authoring DX: deploy-template does not partially write on overwrite refusal', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'deploy-template-'));
    try {
        const { spawnSync } = require('child_process');
        const cli = path.join(repoRoot, 'bin', 'cli.js');
        const outDir = path.join(tmp, '.github', 'workflows');
        fs.mkdirSync(outDir, { recursive: true });
        fs.writeFileSync(path.join(outDir, 'cdn-security-cloudflare.yml'), 'existing\n', 'utf8');
        const result = spawnSync(process.execPath, [
            cli, 'deploy-template',
            '--target', 'all',
            '--out-dir', outDir,
        ], {
            cwd: tmp,
            encoding: 'utf8',
            env: process.env,
        });
        assert.strictEqual(result.status, 1);
        assert.ok(/already exists/.test(result.stderr));
        assert.ok(!fs.existsSync(path.join(outDir, 'cdn-security-aws.yml')));
        assert.strictEqual(fs.readFileSync(path.join(outDir, 'cdn-security-cloudflare.yml'), 'utf8'), 'existing\n');
    }
    finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
});
test('CLI authoring DX: diff detects generated output drift', () => {
    const ctx = tmpProject(BASIC_AWS_POLICY);
    const { spawnSync } = require('child_process');
    const cli = path.join(repoRoot, 'bin', 'cli.js');
    const env = Object.assign({}, process.env, {
        EDGE_ADMIN_TOKEN: 'ci-build-token-not-for-deploy',
        ORIGIN_SECRET: 'ci-origin-secret-not-for-deploy',
    });
    try {
        const buildResult = spawnSync(process.execPath, [
            cli, 'build',
            '-p', ctx.policyPath,
            '-o', ctx.outDir,
            '--target', 'aws',
        ], { cwd: ctx.tmp, encoding: 'utf8', env });
        assert.strictEqual(buildResult.status, 0, `build failed: ${buildResult.stderr}`);
        const cleanDiff = spawnSync(process.execPath, [
            cli, 'diff',
            '-p', ctx.policyPath,
            '-o', ctx.outDir,
            '--target', 'aws',
        ], { cwd: ctx.tmp, encoding: 'utf8', env });
        assert.strictEqual(cleanDiff.status, 0, `clean diff failed: ${cleanDiff.stderr}`);
        assert.ok(/matches policy/.test(cleanDiff.stdout));
        fs.appendFileSync(path.join(ctx.outDir, 'edge', 'viewer-request.js'), '\n// drift\n', 'utf8');
        const dirtyDiff = spawnSync(process.execPath, [
            cli, 'diff',
            '-p', ctx.policyPath,
            '-o', ctx.outDir,
            '--target', 'aws',
        ], { cwd: ctx.tmp, encoding: 'utf8', env });
        assert.strictEqual(dirtyDiff.status, 1);
        assert.ok(/CHANGED edge\/viewer-request\.js/.test(dirtyDiff.stdout));
    }
    finally {
        ctx.cleanup();
    }
});
if (process.exitCode) {
    process.exit(process.exitCode);
}
