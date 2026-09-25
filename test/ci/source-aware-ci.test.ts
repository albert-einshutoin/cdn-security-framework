import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import { buildSync } from 'esbuild';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const repo = path.resolve(__dirname, '../..');
const fixture = path.join(repo, 'examples/nestjs-contract');
const hash = (file: string) => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
let temp: string;
let candidate: string;
let driver: string;

function command(bin: string, args: string[], cwd: string, env = process.env) {
  const result = spawnSync(bin, args, { cwd, env, encoding: 'utf8', timeout: 90_000, maxBuffer: 1024 * 1024 });
  assert.equal(result.error, undefined, 'child process failed or timed out');
  assert.equal(result.signal, null, 'child process exited by signal');
  return result;
}

function env(extra: Record<string, string> = {}) {
  return { ...process.env, CSF_SOURCE: 'a'.repeat(40), GITHUB_RUN_ID: '1',
    GITHUB_RUN_ATTEMPT: '1', CSF_TGZ_SHA256: hash(path.join(candidate, 'candidate.tgz')),
    CSF_PRODUCER_STATE: 'success', CSF_ACCEPTANCE_STATE: 'success',
    CSF_ANALYZE_OUTCOME: 'success', CSF_PUBLISH_OUTCOME: 'success',
    CSF_ARTIFACT_OUTCOME: 'success', ...extra };
}

function workspace(name: string, overrides: Record<string, unknown> = {}) {
  const root = path.join(temp, name);
  fs.mkdirSync(root);
  fs.cpSync(fixture, root, { recursive: true });
  if (name === 'encoded') {
    fs.renameSync(path.join(root, 'policy/security.yml'),
      path.join(root, 'policy/token=opaquevalue123.yml'));
    fs.appendFileSync(path.join(root, 'openapi.yaml'),
      '  /token-refresh:\n    get:\n      responses: { "200": { description: ok } }\n');
  }
  fs.writeFileSync(path.join(root, 'exceptions.json'), JSON.stringify({ version: 1, exceptions: [] }));
  const output = path.join(root, 'reports');
  fs.mkdirSync(output);
  const config = path.join(temp, `${name}.json`);
  fs.writeFileSync(config, JSON.stringify({ workspaceRoot: root, openapi: 'openapi.yaml',
    policy: 'policy/security.yml', target: 'aws', source: 'tsconfig.json',
    currentDate: '2026-09-25', failOn: 'never', format: 'summary', ...overrides }));
  return { root, output, config };
}

function inputDigests(root: string): Record<string, string> {
  const values: Record<string, string> = {};
  const visit = (directory: string) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.name === 'reports') continue;
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(file);
      else if (entry.isFile()) values[path.relative(root, file)] = hash(file);
      else throw new Error('unexpected fixture file type');
    }
  };
  visit(root);
  return values;
}

function runCase(name: string, overrides: Record<string, unknown> = {}) {
  const target = workspace(name, overrides);
  const before = inputDigests(target.root);
  const analysis = command(process.execPath, [driver, 'run', target.config, candidate, target.output], repo, env());
  expect(analysis.status, analysis.stderr).toBe(0);
  const after = inputDigests(target.root);
  expect(after).toEqual(before);
  const record = JSON.parse(fs.readFileSync(path.join(target.output, 'ci-record.json'), 'utf8'));
  return { ...target, record };
}

function deliver(output: string, name: string, extra: Record<string, string> = {}) {
  const stage = path.join(temp, `${name}-stage`);
  fs.mkdirSync(stage);
  const step = path.join(temp, `${name}-step.md`);
  const outputs = path.join(temp, `${name}-outputs.txt`);
  const record = path.join(output, 'ci-record.json');
  const publish = command(process.execPath, [driver, 'publish', record, candidate, stage], repo,
    env({ GITHUB_STEP_SUMMARY: step, GITHUB_OUTPUT: outputs, ...extra }));
  const gate = command(process.execPath, [driver, 'gate', record, candidate,
    path.join(stage, 'delivery.json')], repo, env(extra));
  return { stage, step, outputs, publish, gate };
}

beforeAll(() => {
  temp = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-source-aware-ci-'));
  candidate = path.join(temp, 'candidate');
  fs.mkdirSync(candidate);
  const packed = command('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', candidate], repo);
  assert.equal(packed.status, 0, packed.stderr);
  const filename = JSON.parse(packed.stdout)[0].filename;
  fs.renameSync(path.join(candidate, filename), path.join(candidate, 'candidate.tgz'));
  const consumer = path.join(candidate, 'consumer');
  fs.mkdirSync(consumer);
  fs.writeFileSync(path.join(consumer, 'package.json'), JSON.stringify({ name: 'ci-test-consumer',
    version: '1.0.0', private: true, dependencies: {
      'cdn-security-framework': 'file:../candidate.tgz',
    } }));
  const install = command('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund'], consumer);
  assert.equal(install.status, 0, install.stderr);
  const validation = path.join(candidate, 'validation');
  fs.mkdirSync(validation);
  fs.copyFileSync(path.join(repo, 'test/fixtures/sarif/sarif-schema-2.1.0.json'),
    path.join(validation, 'sarif-schema-2.1.0.json'));
  buildSync({ entryPoints: [path.join(repo, 'scripts/official-sarif-test-validator.js')],
    outfile: path.join(validation, 'official-sarif-test-validator.cjs'), bundle: true,
    platform: 'node', format: 'cjs', target: 'node20', logLevel: 'silent' });
  fs.writeFileSync(path.join(candidate, 'metadata.json'), JSON.stringify({ schemaVersion: 1,
    source: 'a'.repeat(40), harness: 'a'.repeat(40), tree: 'b'.repeat(40), run: '1', attempt: '1',
    sha256: hash(path.join(candidate, 'candidate.tgz')),
    size: fs.statSync(path.join(candidate, 'candidate.tgz')).size,
    lockSha256: hash(path.join(consumer, 'package-lock.json')),
    schemaSha256: hash(path.join(validation, 'sarif-schema-2.1.0.json')),
    validatorSha256: hash(path.join(validation, 'official-sarif-test-validator.cjs')) }));
  driver = path.join(consumer, 'node_modules/cdn-security-framework/scripts/source-aware-ci.js');
  assert.ok(fs.statSync(driver).isFile());
}, 120_000);

afterAll(() => { if (temp) fs.rmSync(temp, { recursive: true, force: true }); });

describe('installed dev-only Source-aware CI connection', () => {
  it('W01/W09 uses one installed candidate, saves verified reports, and passes the real gate', () => {
    const { output, record } = runCase('pass', {
      sourceAuthConfig: 'security-analyzer.yml', exceptions: 'exceptions.json',
    });
    expect(record.analysis.exitCode).toBe(0);
    expect(record.reports.summary.status).toBe('saved');
    expect(record.reports.sarif.status).toBe('saved');
    const delivery = deliver(output, 'pass');
    expect(delivery.publish.status).toBe(0);
    expect(delivery.gate.status).toBe(0);
    expect(fs.readFileSync(delivery.step, 'utf8')).toContain('| implemented |');
    expect(fs.readdirSync(delivery.stage).sort()).toEqual(
      ['ci-record.json', 'delivery.json', 'source-aware.sarif', 'summary.md']);
    expect(JSON.parse(fs.readFileSync(path.join(output, 'source-aware.sarif'), 'utf8')).version).toBe('2.1.0');
  });

  it('W02 keeps reports but fails the real gate on a Finding threshold', () => {
    const { output, record } = runCase('threshold', { failOn: 'warning' });
    expect(record.analysis.exitCode).toBe(1);
    const delivery = deliver(output, 'threshold');
    expect(delivery.publish.status).toBe(0);
    expect(delivery.gate.status).toBe(1);
    expect(fs.readFileSync(delivery.step, 'utf8')).toContain('**Exit verdict:** 1');
  });

  it('W03/W04 distinguishes omitted Source and safely saved input-error partial results', () => {
    const omitted = runCase('omitted', { source: undefined });
    expect(fs.readFileSync(path.join(omitted.output, 'summary.md'), 'utf8')).toContain('| implemented | omitted |');
    const partial = runCase('partial', { openapi: 'missing-openapi.yaml' });
    expect(partial.record.analysis.exitCode).toBe(2);
    expect(partial.record.reports.summary.status).toBe('saved');
    const delivery = deliver(partial.output, 'partial');
    expect(delivery.publish.status).toBe(0);
    expect(delivery.gate.status).toBe(2);
  });

  it('W06/W07 rejects tampered bytes and failed Summary transfer at the real gate', () => {
    const tampered = runCase('tampered');
    fs.appendFileSync(path.join(tampered.output, 'summary.md'), 'changed\n');
    const bad = deliver(tampered.output, 'tampered');
    expect(bad.gate.status).toBe(3);
    const transfer = runCase('transfer');
    const missing = deliver(transfer.output, 'transfer', {
      GITHUB_STEP_SUMMARY: path.join(temp, 'missing-parent/summary.md'),
    });
    expect(missing.gate.status).toBe(3);
    expect(JSON.parse(fs.readFileSync(path.join(missing.stage, 'delivery.json'), 'utf8')).summaryTransfer)
      .toBe('failed');
    const states = runCase('states');
    for (const [name, extra] of [
      ['skipped', { CSF_ACCEPTANCE_STATE: 'skipped' }],
      ['cancelled', { CSF_PRODUCER_STATE: 'cancelled' }],
      ['artifact', { CSF_ARTIFACT_OUTCOME: 'failure' }],
      ['signal', { CSF_ANALYZE_OUTCOME: 'failure' }],
      ['publish', { CSF_PUBLISH_OUTCOME: 'failure' }],
      ['candidate', { CSF_TGZ_SHA256: '0'.repeat(64) }],
    ] as const) {
      const stage = deliver(states.output, name, extra);
      expect(stage.gate.status).toBe(3);
    }
  });

  it('W05 never substitutes stale or failed product reports', () => {
    const stale = workspace('stale');
    fs.writeFileSync(path.join(stale.output, 'summary.md'), '# old report\n');
    const analysis = command(process.execPath, [driver, 'run', stale.config, candidate, stale.output], repo, env());
    expect(analysis.status).toBe(3);
    expect(fs.readFileSync(path.join(stale.output, 'summary.md'), 'utf8')).toBe('# old report\n');
    const delivery = deliver(stale.output, 'stale');
    expect(delivery.gate.status).toBe(3);
    expect(fs.readFileSync(delivery.step, 'utf8')).toContain('CI_REPORT_UNAVAILABLE');
    expect(fs.readdirSync(delivery.stage)).not.toContain('summary.md');
  });

  it('W08 refuses unsafe replacement Summary content before transfer', () => {
    const unsafe = runCase('unsafe');
    const file = path.join(unsafe.output, 'summary.md');
    fs.appendFileSync(file, '\n<script>alert(1)</script>\n::error::raw\n/token%3Dhidden-secret\n');
    const recordFile = path.join(unsafe.output, 'ci-record.json');
    const record = JSON.parse(fs.readFileSync(recordFile, 'utf8'));
    record.reports.summary.sha256 = hash(file);
    record.reports.summary.bytes = fs.statSync(file).size;
    fs.writeFileSync(recordFile, JSON.stringify(record));
    const delivery = deliver(unsafe.output, 'unsafe');
    expect(delivery.gate.status).toBe(3);
    expect(fs.readFileSync(delivery.step, 'utf8')).toContain('CI_REPORT_UNAVAILABLE');
  });

  it('W08 redacts secret-like route and encoded input filenames before transfer', () => {
    const valid = runCase('encoded', { policy: 'policy/token=opaquevalue123.yml' });
    const summary = fs.readFileSync(path.join(valid.output, 'summary.md'), 'utf8');
    const sarif = fs.readFileSync(path.join(valid.output, 'source-aware.sarif'), 'utf8');
    expect(summary).toContain('REDACTED');
    expect(summary).not.toContain('/token-refresh');
    expect(summary + sarif).not.toContain('token=opaquevalue123');
    expect(summary + sarif).not.toContain('token%3Dopaquevalue123');
    const delivery = deliver(valid.output, 'encoded');
    expect(delivery.gate.status).toBe(0);
  });
});
