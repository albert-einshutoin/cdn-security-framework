import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';

import { analyzeSourceAwareWorkspace } from '../../src/contract/source-aware-workspace';
import { finalizeSourceAwareOutput } from '../../src/contract/source-aware-output';
import { WAIVABLE_FINDING_RULE_IDS } from '../../src/contract/finding-exceptions';
import { createOfficialSarifValidator } from '../../src/scripts/official-sarif-test-validator';

const roots: string[] = [];
const cli = path.join(process.cwd(), 'bin/cli.js');
const date = '2026-09-25';
const validateSarif = createOfficialSarifValidator(path.join(process.cwd(), 'test/fixtures/sarif/sarif-schema-2.1.0.json'));

function workspace(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-source-diff-'));
  roots.push(root);
  fs.cpSync(path.join(process.cwd(), 'test/fixtures/source-analysis/nestjs-basic'), root, { recursive: true });
  const dependency = path.join(root, 'node_modules/@nestjs/common');
  fs.mkdirSync(dependency, { recursive: true });
  fs.writeFileSync(path.join(dependency, 'package.json'), JSON.stringify({
    name: '@nestjs/common', version: '1.0.0', main: 'index.js', types: 'index.d.ts',
  }));
  fs.writeFileSync(path.join(dependency, 'index.js'), 'throw new Error("Source executed");\n');
  fs.writeFileSync(path.join(dependency, 'index.d.ts'), [
    'export declare function Controller(path?: string): ClassDecorator;',
    'export declare function Get(path?: string): MethodDecorator;',
    'export declare function Post(path?: string): MethodDecorator;',
    'export declare function Head(path?: string): MethodDecorator;',
  ].join('\n'));
  fs.writeFileSync(path.join(root, 'policy.yml'), `version: 2
defaults: {mode: enforce}
request:
  allow_methods: [GET]
  limits: {max_uri_length: 21}
  block: {header_missing: []}
routes: []
response_headers: {}
`);
  fs.mkdirSync(path.join(root, 'refs'));
  fs.writeFileSync(path.join(root, 'refs/common.yaml'), `components:
  parameters:
    Id:
      name: id
      in: path
      required: true
      schema: {type: string}
`);
  fs.writeFileSync(path.join(root, 'openapi.yaml'), `openapi: 3.0.3
info: {title: Synthetic, version: 1.0.0}
paths:
  /users/{id}:
    get:
      parameters:
        - $ref: './refs/common.yaml#/components/parameters/Id'
      responses:
        '200': {description: OK}
  /users:
    post:
      responses:
        '200': {description: OK}
`);
  return root;
}

function hash(file: string): string {
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function invoke(root: string, extra: string[] = []) {
  return spawnSync(process.execPath, [cli, 'contract', 'source-diff', '--workspace-root', root,
    '--openapi', 'openapi.yaml', '--policy', 'policy.yml', '--target', 'aws', '--current-date', date, ...extra], {
    cwd: root, encoding: 'utf8', env: { ...process.env, NODE_PATH: '' }, timeout: 30_000,
  });
}

function withFault(root: string, hook: string, format = 'json') {
  const preload = path.join(root, 'test-preload.cjs');
  fs.writeFileSync(preload, hook);
  return spawnSync(process.execPath, [cli, 'contract', 'source-diff', '--workspace-root', root,
    '--openapi', 'openapi.yaml', '--policy', 'policy.yml', '--target', 'aws', '--current-date', date,
    '--format', format, '--fail-on', 'never'], {
    cwd: root, encoding: 'utf8', timeout: 30_000,
    env: { ...process.env, NODE_PATH: '', NODE_OPTIONS: `--require=${preload}` },
  });
}

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe('Experimental source-diff CLI', () => {
  test('uses one real workspace result and leaves every input unchanged', async () => {
    const root = workspace();
    const names = ['openapi.yaml', 'refs/common.yaml', 'policy.yml', 'tsconfig.json', 'src/controller.ts'];
    const before = names.map((name) => hash(path.join(root, name)));
    const expected = finalizeSourceAwareOutput(await analyzeSourceAwareWorkspace({
      workspaceRoot: root, openapiPath: 'openapi.yaml', policyPath: 'policy.yml', target: 'aws',
      source: { tsconfigPath: 'tsconfig.json' },
    }), { currentDate: date, failOn: 'never' });
    const result = invoke(root, ['--source', 'tsconfig.json', '--format', 'json', '--fail-on', 'never']);
    expect(result.status).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.stdout.endsWith('\n')).toBe(true);
    const report = JSON.parse(result.stdout);
    expect(report.summary).toEqual(expected.finalized?.summary);
    expect(report.stages).toEqual(expected.finalized?.stages);
    expect(report.comparisons).toEqual(expected.finalized?.comparisons);
    expect(report.analysis).toEqual(expected.finalized?.analysis);
    expect(result.stdout).not.toContain(root);
    expect(names.map((name) => hash(path.join(root, name)))).toEqual(before);
  });

  test('omits Source without scanning it and retains the independent comparison', () => {
    const root = workspace();
    const result = invoke(root, ['--format', 'json', '--fail-on', 'never']);
    expect(result.status).toBe(0);
    const report = JSON.parse(result.stdout);
    expect(report.stages.implemented).toMatchObject({ status: 'omitted', code: 'SOURCE_NOT_REQUESTED' });
    expect(report.comparisons.implementedDeclared).toMatchObject({ status: 'omitted' });
    expect(report.comparisons.declaredAllowed.status).toMatch(/complete|partial/);
  });

  test('distinguishes a completed zero-Finding comparison from an omitted Source stage', () => {
    const root = workspace();
    fs.writeFileSync(path.join(root, 'openapi.yaml'), 'openapi: 3.0.3\ninfo: {title: Synthetic, version: 1.0.0}\npaths: {}\n');
    const result = invoke(root, ['--format', 'json']);
    expect(result.status).toBe(0);
    const report = JSON.parse(result.stdout);
    expect(report.stages.implemented.status).toBe('omitted');
    expect(report.comparisons.implementedDeclared.status).toBe('omitted');
    expect(report.comparisons.declaredAllowed.status).toBe('complete');
    expect(report.summary.unique).toBe(0);
    expect(report.analysis.status).toBe('complete');
  });

  test('remote references and escaped Source paths fail without a network request or execution', () => {
    const root = workspace();
    const preload = path.join(root, 'block-network.cjs');
    fs.writeFileSync(preload, `
      for (const name of ['node:http', 'node:https', 'node:net']) {
        const object = require(name);
        for (const key of ['request', 'get', 'connect', 'createConnection']) {
          if (typeof object[key] === 'function') object[key] = () => { throw Error('network-called-opaquevalue123'); };
        }
      }
      globalThis.fetch = () => { throw Error('network-called-opaquevalue123'); };
    `);
    fs.writeFileSync(path.join(root, 'openapi.yaml'), fs.readFileSync(path.join(root, 'openapi.yaml'), 'utf8')
      .replace('./refs/common.yaml', 'https://example.invalid/opaquevalue123.yaml'));
    const result = spawnSync(process.execPath, [cli, 'contract', 'source-diff', '--workspace-root', root,
      '--openapi', 'openapi.yaml', '--policy', 'policy.yml', '--target', 'aws', '--source', '../outside.ts',
      '--current-date', date, '--format', 'json', '--fail-on', 'never'], {
      cwd: root, encoding: 'utf8', timeout: 30_000,
      env: { ...process.env, NODE_PATH: '', NODE_OPTIONS: `--require=${preload}` },
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toBe('');
    expect(result.stdout).not.toContain('network-called-opaquevalue123');
    expect(result.stdout).not.toContain('opaquevalue123');
    expect(result.stdout).not.toContain(root);
    const report = JSON.parse(result.stdout);
    expect(report.stages.declared.status).toBe('failed');
    expect(report.stages.implemented.status).toBe('failed');
  });

  test('rejects parser errors before analysis with fixed, private diagnostics', () => {
    const root = workspace();
    const result = invoke(root, ['--unknown-option', 'synthetic-secret-opaquevalue123']);
    expect(result.status).toBe(2);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('SOURCE_DIFF_ARGUMENT_INVALID');
    expect(result.stderr).not.toContain('opaquevalue123');
    expect(result.stderr).not.toContain(root);
  });

  test('emits four representations of the same Finding meaning with real exit verdicts', async () => {
    const root = workspace();
    const final = finalizeSourceAwareOutput(await analyzeSourceAwareWorkspace({
      workspaceRoot: root, openapiPath: 'openapi.yaml', policyPath: 'policy.yml', target: 'aws',
      source: { tsconfigPath: 'tsconfig.json' },
    }), { currentDate: date, failOn: 'warning' }).finalized!;
    expect(final.summary.unique).toBeGreaterThan(0);
    expect(final.threshold.reached).toBe(true);
    expect(final.exitCode).toBe(1);
    const outputs = Object.fromEntries((['text', 'json', 'sarif', 'summary'] as const).map((format) => [
      format, invoke(root, ['--source', 'tsconfig.json', '--format', format, '--fail-on', 'warning']),
    ])) as Record<'text' | 'json' | 'sarif' | 'summary', ReturnType<typeof invoke>>;
    for (const result of Object.values(outputs)) {
      expect(result.status).toBe(1);
      expect(result.stderr).toBe('');
      expect(result.stdout).not.toContain(root);
    }
    const json = JSON.parse(outputs.json.stdout);
    const sarif = JSON.parse(outputs.sarif.stdout);
    expect(validateSarif(sarif)).toBe(true);
    expect(json.summary).toEqual(final.summary);
    expect(json.analysis).toEqual(final.analysis);
    expect(json.threshold.reached).toBe(true);
    expect(outputs.json.stdout.endsWith('\n')).toBe(true);
    expect(outputs.sarif.stdout.endsWith('\n')).toBe(true);
    expect(outputs.text.stdout).toContain(`unique=${final.summary.unique}`);
    expect(outputs.summary.stdout).toContain(`| Unique | ${final.summary.unique} |`);
    expect(outputs.summary.stdout).toContain('**Exit verdict:** 1');
    const levels = { error: 'error', warning: 'warning', info: 'note' } as const;
    for (const finding of [...final.findings, ...final.suppressedFindings, ...final.exceptionDiagnostics]) {
      const result = sarif.runs[0].results.find((item: { partialFingerprints: Record<string, string> }) =>
        item.partialFingerprints['securityContractFinding/v1'] === finding.instanceId);
      expect(result).toMatchObject({ ruleId: finding.ruleId, level: levels[finding.severity] });
      expect(outputs.text.stdout).toContain(finding.instanceId);
      expect(outputs.summary.stdout).toContain(finding.instanceId);
    }
  });

  test('keeps independent Findings and exit 2 for failed input stages even with fail-on never', () => {
    const root = workspace();
    const originalOpenapi = fs.readFileSync(path.join(root, 'openapi.yaml'));
    fs.writeFileSync(path.join(root, 'openapi.yaml'), 'not: openapi\n');
    const before = hash(path.join(root, 'openapi.yaml'));
    const badOpenapi = invoke(root, ['--source', 'tsconfig.json', '--format', 'json', '--fail-on', 'never']);
    expect(badOpenapi.status).toBe(2);
    const openapiReport = JSON.parse(badOpenapi.stdout);
    expect(openapiReport.analysis).toMatchObject({ status: 'failed', outcome: 'input-error' });
    expect(openapiReport.comparisons.declaredAllowed.status).toBe('failed');
    expect(openapiReport.comparisons.implementedAllowed.status).toMatch(/complete|partial/);
    expect(openapiReport.summary.unique).toBeGreaterThan(0);
    expect(hash(path.join(root, 'openapi.yaml'))).toBe(before);
    expect(badOpenapi.stderr).toBe('');

    fs.writeFileSync(path.join(root, 'openapi.yaml'), originalOpenapi);
    const originalPolicy = fs.readFileSync(path.join(root, 'policy.yml'));
    fs.writeFileSync(path.join(root, 'policy.yml'), 'version: 1\n');
    const policyBefore = hash(path.join(root, 'policy.yml'));
    const badPolicy = invoke(root, ['--source', 'tsconfig.json', '--format', 'json', '--fail-on', 'never']);
    expect(badPolicy.status).toBe(2);
    const policyReport = JSON.parse(badPolicy.stdout);
    expect(policyReport.comparisons.implementedDeclared.status).toMatch(/complete|partial/);
    expect(policyReport.comparisons.implementedAllowed.status).toBe('failed');
    expect(hash(path.join(root, 'policy.yml'))).toBe(policyBefore);

    fs.writeFileSync(path.join(root, 'policy.yml'), originalPolicy);
    const badSource = invoke(root, ['--source', '../outside.ts', '--format', 'json', '--fail-on', 'never']);
    expect(badSource.status).toBe(2);
    expect(JSON.parse(badSource.stdout).comparisons.declaredAllowed.status).toMatch(/complete|partial/);
    expect(badSource.stdout).not.toContain(root);
    expect(badSource.stderr).toBe('');
  });

  test('uses the bounded exception loader and separates live, expired, and invalid files', async () => {
    const root = workspace();
    const final = finalizeSourceAwareOutput(await analyzeSourceAwareWorkspace({
      workspaceRoot: root, openapiPath: 'openapi.yaml', policyPath: 'policy.yml', target: 'aws',
      source: { tsconfigPath: 'tsconfig.json' },
    }), { currentDate: date, failOn: 'never' }).finalized!;
    const selected = final.findings.find((finding) => (WAIVABLE_FINDING_RULE_IDS as readonly string[]).includes(finding.ruleId));
    expect(selected).toBeDefined();
    if (!selected) return;
    const exception = { version: 1, exceptions: [{
      id: 'EXC-2026-ONE', rule_id: selected.ruleId,
      selector: { instance_id: selected.instanceId, environment: 'staging' },
      reason: 'Temporary exception for a reviewed route.', owner: 'security-team', expires_at: '2026-12-01',
    }] };
    const file = path.join(root, 'exceptions.json');
    fs.writeFileSync(file, JSON.stringify(exception));
    const before = hash(file);
    const extra = ['--source', 'tsconfig.json', '--exceptions', 'exceptions.json', '--format', 'json', '--fail-on', 'never'];
    const live = invoke(root, [...extra, '--environment', 'staging']);
    expect(live.status).toBe(0);
    const liveReport = JSON.parse(live.stdout);
    expect(liveReport.summary.suppressed).toBe(1);
    expect(liveReport.findings.suppressed.map((item: { instanceId: string }) => item.instanceId)).toContain(selected.instanceId);
    expect(hash(file)).toBe(before);
    const otherEnvironment = invoke(root, [...extra, '--environment', 'production']);
    expect(JSON.parse(otherEnvironment.stdout).summary.suppressed).toBe(0);

    exception.exceptions[0].expires_at = '2026-01-01';
    fs.writeFileSync(file, JSON.stringify(exception));
    const expiredHash = hash(file);
    const expired = invoke(root, [...extra, '--environment', 'staging']);
    expect(expired.status).toBe(0);
    const expiredReport = JSON.parse(expired.stdout);
    expect(expiredReport.summary.suppressed).toBe(0);
    expect(expiredReport.summary.governance).toBeGreaterThan(0);
    expect(hash(file)).toBe(expiredHash);

    fs.writeFileSync(file, 'version: 1\nexceptions: nope\n');
    const invalidHash = hash(file);
    const invalid = invoke(root, extra);
    expect(invalid.status).toBe(2);
    expect(invalid.stdout).toBe('');
    expect(invalid.stderr).toContain('SOURCE_DIFF_EXCEPTIONS_INVALID');
    expect(invalid.stderr).not.toContain(root);
    expect(hash(file)).toBe(invalidHash);
  });

  test('redacts secret-like description and input filenames in all four stdout formats', () => {
    const root = workspace();
    const refToken = 'token=opaquevalue123';
    const policyToken = 'ghp_abcdefghijklmnop';
    const refName = `${refToken}.yaml`;
    const policyName = `${policyToken}.yml`;
    fs.renameSync(path.join(root, 'refs/common.yaml'), path.join(root, 'refs', refName));
    fs.renameSync(path.join(root, 'policy.yml'), path.join(root, policyName));
    fs.writeFileSync(path.join(root, 'openapi.yaml'), fs.readFileSync(path.join(root, 'openapi.yaml'), 'utf8')
      .replace('common.yaml', refName).replace('description: OK', 'description: Authorization Bearer synthetic-secret-opaquevalue123'));
    for (const format of ['text', 'json', 'sarif', 'summary']) {
      const result = invoke(root, ['--source', 'tsconfig.json', '--policy', policyName, '--format', format, '--fail-on', 'never']);
      expect(result.status).toBe(0);
      expect(result.stdout + result.stderr).not.toContain(refToken);
      expect(result.stdout + result.stderr).not.toContain('token%3Dopaquevalue123');
      expect(result.stdout + result.stderr).not.toContain(policyToken);
      expect(result.stdout + result.stderr).not.toContain('opaquevalue123');
      expect(result.stdout + result.stderr).not.toContain(root);
      if (format === 'sarif') expect(validateSarif(JSON.parse(result.stdout))).toBe(true);
    }
  });

  test('fixed finalizer, internal, reporter, and stdout failure paths fail without a fallback report', () => {
    const root = workspace();
    const cases = [
      { name: 'finalizer', code: 'SOURCE_FINDING_INPUT_INVALID', hook: `
        const Module = require('node:module'); const original = Module._load;
        Module._load = function(request, parent, isMain) {
          const loaded = original.apply(this, arguments);
          return request.endsWith('/contract/source-aware-output')
            ? { ...loaded, finalizeSourceAwareOutput: () => ({ finalizationError: {
              code: 'SOURCE_FINDING_INPUT_INVALID', exitCode: 3 } }) } : loaded;
        };
      ` },
      { name: 'internal', code: 'SOURCE_DIFF_INTERNAL', hook: `
        const Module = require('node:module'); const original = Module._load;
        Module._load = function(request, parent, isMain) {
          const loaded = original.apply(this, arguments);
          return request.endsWith('/contract/source-aware-workspace')
            ? { ...loaded, analyzeSourceAwareWorkspace: async () => { throw new Error('opaquevalue123'); } } : loaded;
        };
      ` },
      { name: 'reporter', code: 'SOURCE_DIFF_REPORTER_FAILED', format: 'sarif', hook: `
        const Module = require('node:module'); const original = Module._load;
        Module._load = function(request, parent, isMain) {
          const loaded = original.apply(this, arguments);
          return request.endsWith('/reporters/sarif')
            ? { ...loaded, renderSourceAwareSarif: () => { throw new Error('opaquevalue123'); } } : loaded;
        };
      ` },
      { name: 'stdout', code: 'SOURCE_DIFF_OUTPUT_FAILED', hook: `
        process.stdout.write = function(chunk, callback) {
          queueMicrotask(() => callback(new Error('opaquevalue123')));
          return false;
        };
      ` },
    ];
    for (const scenario of cases) {
      const result = withFault(root, scenario.hook, scenario.format);
      expect(result.status, scenario.name).toBe(3);
      expect(result.stdout, scenario.name).toBe('');
      expect(result.stderr, scenario.name).toContain(scenario.code);
      expect(result.stderr, scenario.name).not.toContain('opaquevalue123');
      expect(result.stderr, scenario.name).not.toContain(root);
    }
  });

  test('finishes a large JSON report when a pipe consumer reads slowly', async () => {
    const root = workspace();
    const paths = Array.from({ length: 100 }, (_, index) => `  /items/${index}:\n    get:\n      responses:\n        '200': {description: OK}\n`).join('');
    fs.writeFileSync(path.join(root, 'openapi.yaml'), `openapi: 3.0.3\ninfo: {title: Synthetic, version: 1.0.0}\npaths:\n${paths}`);
    const child = spawn(process.execPath, [cli, 'contract', 'source-diff', '--workspace-root', root,
      '--openapi', 'openapi.yaml', '--policy', 'policy.yml', '--target', 'aws', '--current-date', date,
      '--format', 'sarif', '--fail-on', 'never'], {
      cwd: root, env: { ...process.env, NODE_PATH: '' }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk: string) => { stderr += chunk; });
    const completed = new Promise<number | null>((resolve, reject) => {
      const timer = setTimeout(() => { child.kill(); reject(new Error('slow pipe timed out')); }, 30_000);
      child.once('error', (error) => { clearTimeout(timer); reject(error); });
      child.once('close', (status) => { clearTimeout(timer); resolve(status); });
    });
    await new Promise((resolve) => setTimeout(resolve, 250));
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => { stdout += chunk; });
    const code = await completed;
    expect(code, stderr).toBe(0);
    expect(stderr).toBe('');
    expect(Buffer.byteLength(stdout)).toBeGreaterThan(65_536);
    expect(stdout.endsWith('\n')).toBe(true);
    const sarif = JSON.parse(stdout);
    expect(validateSarif(sarif)).toBe(true);
    expect(sarif.runs[0].results.length).toBeGreaterThan(100);
  });

  test.each([
    ['missing value', ['--source']],
    ['excess argument', ['unexpected-position']],
    ['unsupported output option', ['--out', 'report.json']],
    ['bad target', ['--target', 'synthetic-secret-opaquevalue123']],
    ['bad format', ['--format', 'synthetic-secret-opaquevalue123']],
    ['bad date', ['--current-date', '2026-02-30']],
    ['bad threshold', ['--fail-on', 'synthetic-secret-opaquevalue123']],
  ])('rejects %s before analysis without echoing values', (_name, extra) => {
    const root = workspace();
    const result = invoke(root, extra);
    expect(result.status).toBe(2);
    expect(result.stdout).toBe('');
    expect(result.stderr).toMatch(/SOURCE_DIFF_(ARGUMENT|TARGET|FORMAT|DATE|FAIL_ON)_INVALID/);
    expect(result.stderr).not.toContain('opaquevalue123');
    expect(result.stderr).not.toContain(root);
  });

  test('help and version have no workspace side effects', () => {
    const root = workspace();
    const before = fs.readdirSync(root).sort();
    const help = spawnSync(process.execPath, [cli, 'contract', 'source-diff', '--help'], {
      cwd: root, encoding: 'utf8', env: { ...process.env, NODE_PATH: '' },
    });
    const version = spawnSync(process.execPath, [cli, '--version'], {
      cwd: root, encoding: 'utf8', env: { ...process.env, NODE_PATH: '' },
    });
    expect(help.status).toBe(0);
    expect(help.stdout).toContain('--workspace-root');
    expect(version.status).toBe(0);
    expect(version.stdout).toMatch(/^1\.4\.0\n$/);
    expect(fs.readdirSync(root).sort()).toEqual(before);
  });
});
