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

function changeJson(file: string, change: (value: any) => void) {
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  change(value);
  fs.writeFileSync(file, `${JSON.stringify(value)}\n`);
}

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
    CSF_STAGE_OUTCOME: 'success', CSF_ARTIFACT_OUTCOME: 'success', ...extra };
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

function deliver(output: string, name: string, extra: Record<string, string> = {},
  changeStage?: (stage: string) => void) {
  const stage = path.join(temp, `${name}-stage`);
  fs.mkdirSync(stage);
  const step = path.join(temp, `${name}-step.md`);
  const outputs = path.join(temp, `${name}-outputs.txt`);
  const record = path.join(output, 'ci-record.json');
  const publish = command(process.execPath, [driver, 'publish', record, candidate, stage], repo,
    env({ GITHUB_STEP_SUMMARY: step, GITHUB_OUTPUT: outputs, ...extra }));
  changeStage?.(stage);
  const verify = command(process.execPath, [driver, 'verify-stage', record, candidate,
    path.join(stage, 'delivery.json')], repo, env(extra));
  const gate = command(process.execPath, [driver, 'gate', record, candidate,
    path.join(stage, 'delivery.json')], repo, env(extra));
  return { stage, step, outputs, publish, verify, gate };
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
  it('records explicit routing separately and rejects a no-Source JSON prefix before reports', () => {
    const { output, record } = runCase('prefix', { sourceGlobalPrefix: 'api' });
    expect(record.routingAssumption).toMatchObject({ globalPrefix: '/api', origin: 'explicit-option' });
    expect(record.routingAssumption.digest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(record.routingAssumption.comparisonContractDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    const summary = fs.readFileSync(path.join(output, 'summary.md'), 'utf8');
    expect(summary).toContain('explicit global prefix /api');
    const sarif = JSON.parse(fs.readFileSync(path.join(output, 'source-aware.sarif'), 'utf8'));
    expect(sarif.runs[0].tool.driver.properties.sourceAware.metadata.routingAssumption.globalPrefix)
      .toBe('/api');
    expect(deliver(output, 'prefix').gate.status).toBe(0);

    const invalid = workspace('prefix-no-source', { source: undefined, sourceGlobalPrefix: '/api' });
    const rejected = command(process.execPath, [driver, 'run', invalid.config, candidate, invalid.output], repo, env());
    expect(rejected.status).toBe(3);
    expect(rejected.stdout).toBe('');
    expect(rejected.stderr).toContain('CI_SOURCE_AWARE_PROCESS_FAILED');
    expect(fs.readdirSync(invalid.output)).toEqual([]);

    const sensitive = runCase('prefix-sensitive', { sourceGlobalPrefix: 'token-opaquevalue123' });
    expect(sensitive.record.routingAssumption.globalPrefix).toBe('/[REDACTED_FILENAME]');
    for (const name of ['ci-record.json', 'summary.md', 'source-aware.sarif']) {
      expect(fs.readFileSync(path.join(sensitive.output, name), 'utf8')).not.toContain('opaquevalue123');
    }
    expect(deliver(sensitive.output, 'prefix-sensitive').gate.status).toBe(0);
  });

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

  it('W06 rejects tampered report bytes at the real gate', () => {
    const tampered = runCase('tampered');
    fs.appendFileSync(path.join(tampered.output, 'summary.md'), 'changed\n');
    const bad = deliver(tampered.output, 'tampered');
    expect(bad.gate.status).toBe(3);
  });

  it('W06 rejects a missing generated report at the real gate', () => {
    const missing = runCase('missing-report');
    fs.unlinkSync(path.join(missing.output, 'source-aware.sarif'));
    const delivery = deliver(missing.output, 'missing-report');
    expect(delivery.gate.status).toBe(3);
    expect(fs.readFileSync(delivery.step, 'utf8')).toContain('CI_REPORT_UNAVAILABLE');
  });

  it('W06 rejects a missing generation record at the real gate', () => {
    const missing = runCase('missing-record');
    fs.unlinkSync(path.join(missing.output, 'ci-record.json'));
    const delivery = deliver(missing.output, 'missing-record');
    expect(delivery.gate.status).toBe(3);
    expect(fs.readFileSync(delivery.step, 'utf8')).toContain('CI_REPORT_UNAVAILABLE');
  });

  it('W07 rejects failed Summary transfer at the real gate', () => {
    const transfer = runCase('transfer');
    const missing = deliver(transfer.output, 'transfer', {
      GITHUB_STEP_SUMMARY: path.join(temp, 'missing-parent/summary.md'),
    });
    expect(missing.gate.status).toBe(3);
    expect(JSON.parse(fs.readFileSync(path.join(missing.stage, 'delivery.json'), 'utf8')).summaryTransfer)
      .toBe('failed');
  });

  it('W06 rejects skipped acceptance and cancelled producer at the real gate', () => {
    const states = runCase('upstream-states');
    for (const [name, extra] of [
      ['skipped', { CSF_ACCEPTANCE_STATE: 'skipped' }],
      ['cancelled', { CSF_PRODUCER_STATE: 'cancelled' }],
    ] as const) {
      const stage = deliver(states.output, name, extra);
      expect(stage.gate.status).toBe(3);
    }
  });

  it('W07 rejects failed analysis, publish, and artifact outcomes at the real gate', () => {
    const states = runCase('delivery-states');
    for (const [name, extra] of [
      ['artifact', { CSF_ARTIFACT_OUTCOME: 'failure' }],
      ['signal', { CSF_ANALYZE_OUTCOME: 'failure' }],
      ['publish', { CSF_PUBLISH_OUTCOME: 'failure' }],
    ] as const) {
      const stage = deliver(states.output, name, extra);
      expect(stage.gate.status).toBe(3);
    }
  });

  it('W06 rejects candidate mismatch at the real gate', () => {
    const states = runCase('candidate-state');
    const stage = deliver(states.output, 'candidate', { CSF_TGZ_SHA256: '0'.repeat(64) });
    expect(stage.gate.status).toBe(3);
  });

  it('W06 rejects a changed staged Summary while original reports remain valid', () => {
    const current = runCase('stage-summary');
    const delivery = deliver(current.output, 'stage-summary', {}, stage => {
      fs.appendFileSync(path.join(stage, 'summary.md'), 'changed after publish\n');
    });
    expect(delivery.publish.status).toBe(0);
    expect(delivery.verify.status).toBe(3);
    expect(delivery.gate.status).toBe(3);
    expect(hash(path.join(current.output, 'summary.md'))).toBe(current.record.reports.summary.sha256);
  });

  it('W06 rejects a missing staged SARIF while original reports remain valid', () => {
    const current = runCase('stage-sarif');
    const delivery = deliver(current.output, 'stage-sarif', {}, stage => {
      fs.unlinkSync(path.join(stage, 'source-aware.sarif'));
    });
    expect(delivery.publish.status).toBe(0);
    expect(delivery.verify.status).toBe(3);
    expect(delivery.gate.status).toBe(3);
    expect(JSON.parse(fs.readFileSync(path.join(delivery.stage, 'delivery.json'), 'utf8')).code).toBe('CI_OK');
    expect(hash(path.join(current.output, 'source-aware.sarif'))).toBe(current.record.reports.sarif.sha256);
  });

  it('W06 rejects a staged CI record from another run', () => {
    const current = runCase('stage-record');
    const delivery = deliver(current.output, 'stage-record', {}, stage => {
      const file = path.join(stage, 'ci-record.json');
      const otherRun = JSON.parse(fs.readFileSync(file, 'utf8'));
      otherRun.candidate.run = '2';
      fs.writeFileSync(file, `${JSON.stringify(otherRun)}\n`);
    });
    expect(delivery.publish.status).toBe(0);
    expect(delivery.verify.status).toBe(3);
    expect(delivery.gate.status).toBe(3);
    expect(current.record.candidate.run).toBe('1');
  });

  it('W06 rejects a staged symlink before upload and at the gate', () => {
    const current = runCase('stage-link');
    const delivery = deliver(current.output, 'stage-link', {}, stage => {
      fs.unlinkSync(path.join(stage, 'summary.md'));
      fs.symlinkSync(path.join(current.output, 'summary.md'), path.join(stage, 'summary.md'));
    });
    expect(delivery.publish.status).toBe(0);
    expect(delivery.verify.status).toBe(3);
    expect(delivery.gate.status).toBe(3);
  });

  it('W06 rejects a delivery candidate from another run', () => {
    const current = runCase('delivery-run');
    const delivery = deliver(current.output, 'delivery-run', {}, stage => {
      changeJson(path.join(stage, 'delivery.json'), value => { value.candidate.run = '2'; });
    });
    expect(delivery.publish.status).toBe(0);
    expect(delivery.verify.status).toBe(3);
    expect(delivery.gate.status).toBe(3);
  });

  it('W06 rejects an altered delivery upload list', () => {
    const current = runCase('delivery-list');
    const delivery = deliver(current.output, 'delivery-list', {}, stage => {
      changeJson(path.join(stage, 'delivery.json'), value => { value.files = ['summary.md']; });
    });
    expect(delivery.publish.status).toBe(0);
    expect(delivery.verify.status).toBe(3);
    expect(delivery.gate.status).toBe(3);
  });

  it('W08 refuses an unknown secret-bearing delivery field before upload', () => {
    const current = runCase('delivery-unknown');
    const delivery = deliver(current.output, 'delivery-unknown', {}, stage => {
      changeJson(path.join(stage, 'delivery.json'), value => { value.rawConfig = 'token=hidden-secret'; });
    });
    expect(delivery.publish.status).toBe(0);
    expect(delivery.verify.status).toBe(3);
    expect(delivery.gate.status).toBe(3);
  });

  it('W08 refuses an unknown secret-bearing CI record field before staging', () => {
    const current = runCase('record-unknown');
    changeJson(path.join(current.output, 'ci-record.json'), value => {
      value.rawSource = 'token=hidden-secret';
    });
    const delivery = deliver(current.output, 'record-unknown');
    expect(delivery.gate.status).toBe(3);
    expect(fs.readdirSync(delivery.stage)).toEqual(['delivery.json']);
    expect(fs.readFileSync(path.join(delivery.stage, 'delivery.json'), 'utf8')).not.toContain('hidden-secret');
    expect(fs.readFileSync(delivery.step, 'utf8')).toContain('CI_REPORT_UNAVAILABLE');
  });

  it('W08 refuses an invalid analysis status', () => {
    const current = runCase('record-status');
    changeJson(path.join(current.output, 'ci-record.json'), value => {
      value.analysis.status = 'unknown';
    });
    const delivery = deliver(current.output, 'record-status');
    expect(delivery.gate.status).toBe(3);
    expect(fs.readdirSync(delivery.stage)).toEqual(['delivery.json']);
  });

  it('W08 refuses oversized analysis codes', () => {
    const current = runCase('record-codes');
    changeJson(path.join(current.output, 'ci-record.json'), value => {
      value.analysis.codes = Array(65).fill('OPENAPI_CAPABILITY_PARTIAL');
    });
    const delivery = deliver(current.output, 'record-codes');
    expect(delivery.gate.status).toBe(3);
    expect(fs.readdirSync(delivery.stage)).toEqual(['delivery.json']);
  });

  it('W08 refuses an invalid analysis code type', () => {
    const current = runCase('record-code-type');
    changeJson(path.join(current.output, 'ci-record.json'), value => {
      value.analysis.codes = ['OPENAPI_CAPABILITY_PARTIAL', 42];
    });
    const delivery = deliver(current.output, 'record-code-type');
    expect(delivery.gate.status).toBe(3);
    expect(fs.readdirSync(delivery.stage)).toEqual(['delivery.json']);
  });

  it('W08 refuses an unknown analysis code', () => {
    const current = runCase('record-unknown-code');
    changeJson(path.join(current.output, 'ci-record.json'), value => {
      value.analysis.codes = ['UNRECOGNIZED_CODE'];
    });
    const delivery = deliver(current.output, 'record-unknown-code');
    expect(delivery.gate.status).toBe(3);
    expect(fs.readdirSync(delivery.stage)).toEqual(['delivery.json']);
  });

  it('W08 refuses a mismatched saved report name', () => {
    const current = runCase('record-report-name');
    changeJson(path.join(current.output, 'ci-record.json'), value => {
      value.reports.sarif.name = 'summary.md';
    });
    const delivery = deliver(current.output, 'record-report-name');
    expect(delivery.gate.status).toBe(3);
    expect(fs.readdirSync(delivery.stage)).toEqual(['delivery.json']);
  });

  it('W08 refuses a nonnumeric saved report size', () => {
    const current = runCase('record-report-size');
    changeJson(path.join(current.output, 'ci-record.json'), value => {
      value.reports.sarif.bytes = '54031';
    });
    const delivery = deliver(current.output, 'record-report-size');
    expect(delivery.gate.status).toBe(3);
    expect(fs.readdirSync(delivery.stage)).toEqual(['delivery.json']);
  });

  it('W08 refuses an invalid saved report hash', () => {
    const current = runCase('record-report-hash');
    changeJson(path.join(current.output, 'ci-record.json'), value => {
      value.reports.sarif.sha256 = '0'.repeat(63);
    });
    const delivery = deliver(current.output, 'record-report-hash');
    expect(delivery.gate.status).toBe(3);
    expect(fs.readdirSync(delivery.stage)).toEqual(['delivery.json']);
  });

  it('W08 refuses an unknown secret-bearing candidate metadata field', () => {
    const metadata = path.join(candidate, 'metadata.json');
    const original = fs.readFileSync(metadata);
    const target = workspace('metadata-unknown');
    try {
      changeJson(metadata, value => { value.rawConfig = 'password=hidden-secret'; });
      const analysis = command(process.execPath,
        [driver, 'run', target.config, candidate, target.output], repo, env());
      expect(analysis.status).toBe(3);
      expect(analysis.stderr).not.toContain('hidden-secret');
      expect(fs.readdirSync(target.output)).toEqual([]);
    } finally {
      fs.writeFileSync(metadata, original);
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
