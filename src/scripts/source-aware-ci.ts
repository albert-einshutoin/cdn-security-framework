#!/usr/bin/env node
// Dev-only internal driver. It is run from an installed candidate, never exported as a public API.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { prepareSourceDiff, type SourceDiffOptions } from '../bin/commands/source-diff';
import { renderSourceAwareSarif } from '../reporters/sarif';
import { renderSourceAwareSummary } from '../reporters/source-aware-summary';
import { hasUnsafeSensitiveText } from '../contract/sensitive-text';
import { isSourceAwareDiagnosticCode } from '../contract/source-aware-finalizer';

type Candidate = { source: string; harness: string; tree: string; run: string; attempt: string;
  sha256: string; size: number; lockSha256: string; schemaSha256: string; validatorSha256: string };
type Saved = { status: 'saved'; name: 'summary.md' | 'source-aware.sarif'; sha256: string; bytes: number };
type Failed = { status: 'failed' | 'not-generated'; code: string };
type RecordV1 = { schemaVersion: 1; candidate: Candidate; targetEvidenceSha256: string;
  analysis: { exitCode: 0 | 1 | 2 | 3; status: 'complete' | 'partial' | 'failed'; codes: string[] };
  reports: { summary: Saved | Failed; sarif: Saved | Failed } };
type StagedFile = { name: Saved['name'] | 'ci-record.json'; sha256: string; bytes: number };
type Delivery = { schemaVersion: 1; candidate: Candidate; summaryTransfer: 'success' | 'failed';
  artifactListVerified: boolean; files: StagedFile['name'][]; staged: StagedFile[]; code: string };

const digest = (bytes: Buffer | string) => createHash('sha256').update(bytes).digest('hex');
const fileDigest = (file: string) => digest(fs.readFileSync(file));
const safeCode = (value: string) => /^[A-Z][A-Z0-9_]{1,79}$/.test(value) ? value : 'CI_UNKNOWN_ERROR';
const reportNames = ['summary.md', 'source-aware.sarif', 'ci-record.json'] as const;
const hex40 = /^[a-f0-9]{40}$/;
const hex64 = /^[a-f0-9]{64}$/;
const runId = /^[1-9][0-9]{0,19}$/;

function exactKeys(value: any, keys: readonly string[]): void {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
}

function boundedBytes(value: any, max = 1_048_576): void {
  assert.ok(Number.isSafeInteger(value) && value > 0 && value <= max);
}

function candidateFields(value: any, metadata = false): Candidate {
  exactKeys(value, ['source', 'harness', 'tree', 'run', 'attempt', 'sha256', 'size',
    'lockSha256', 'schemaSha256', 'validatorSha256', ...(metadata ? ['schemaVersion'] : [])]);
  if (metadata) assert.equal(value.schemaVersion, 1);
  assert.match(value.source, hex40);
  assert.equal(value.harness, value.source);
  assert.match(value.tree, hex40);
  assert.match(value.run, runId);
  assert.match(value.attempt, runId);
  for (const key of ['sha256', 'lockSha256', 'schemaSha256', 'validatorSha256']) {
    assert.match(value[key], hex64);
  }
  boundedBytes(value.size);
  const { schemaVersion: _schemaVersion, ...identity } = value;
  return identity as Candidate;
}

function recordFields(value: any): RecordV1 {
  exactKeys(value, ['schemaVersion', 'candidate', 'targetEvidenceSha256', 'analysis', 'reports']);
  assert.equal(value.schemaVersion, 1);
  candidateFields(value.candidate);
  assert.match(value.targetEvidenceSha256, hex64);
  exactKeys(value.analysis, ['exitCode', 'status', 'codes']);
  assert.ok([0, 1, 2, 3].includes(value.analysis.exitCode));
  assert.ok(['complete', 'partial', 'failed'].includes(value.analysis.status));
  assert.equal(value.analysis.status === 'failed', value.analysis.exitCode >= 2);
  assert.ok(Array.isArray(value.analysis.codes) && value.analysis.codes.length <= 64);
  for (const code of value.analysis.codes) assert.ok(isSourceAwareDiagnosticCode(code) || code === 'CI_UNKNOWN_ERROR');
  exactKeys(value.reports, ['summary', 'sarif']);
  for (const [key, name] of [['summary', 'summary.md'], ['sarif', 'source-aware.sarif']] as const) {
    const report = value.reports[key];
    assert.ok(report && typeof report === 'object' && !Array.isArray(report));
    if (report.status === 'saved') {
      exactKeys(report, ['status', 'name', 'sha256', 'bytes']);
      assert.equal(report.name, name);
      assert.match(report.sha256, hex64);
      boundedBytes(report.bytes);
    } else {
      exactKeys(report, ['status', 'code']);
      assert.ok(report.status === 'failed' || report.status === 'not-generated');
      assert.ok(report.status === 'not-generated' ? report.code === 'CI_NOT_RENDERED'
        : ['CI_REPORT_RENDER_FAILED', 'CI_REPORT_SAVE_FAILED'].includes(report.code));
    }
  }
  return value as RecordV1;
}

function deliveryFields(value: any): Delivery {
  exactKeys(value, ['schemaVersion', 'candidate', 'summaryTransfer', 'artifactListVerified',
    'files', 'staged', 'code']);
  assert.equal(value.schemaVersion, 1);
  candidateFields(value.candidate);
  assert.ok(['success', 'failed'].includes(value.summaryTransfer));
  assert.equal(typeof value.artifactListVerified, 'boolean');
  assert.ok(['CI_OK', 'CI_PARTIAL_REPORT', 'CI_SUMMARY_UNAVAILABLE',
    'CI_ARTIFACT_VERIFY_FAILED', 'CI_SUMMARY_TRANSFER_FAILED', 'CI_RECORD_MISSING'].includes(value.code));
  assert.ok(Array.isArray(value.files) && value.files.length <= reportNames.length);
  assert.ok(Array.isArray(value.staged) && value.staged.length === value.files.length);
  const expected = reportNames.filter(name => value.files.includes(name));
  assert.deepEqual(value.files, expected);
  value.staged.forEach((file: any, index: number) => {
    exactKeys(file, ['name', 'sha256', 'bytes']);
    assert.equal(file.name, value.files[index]);
    assert.match(file.sha256, hex64);
    boundedBytes(file.bytes);
  });
  assert.equal(value.artifactListVerified, value.code === 'CI_OK');
  return value as Delivery;
}

function readJsonBytes(file: string, max = 65_536): { value: any; bytes: Buffer } {
  const stat = fs.lstatSync(file);
  assert.ok(stat.isFile() && stat.nlink === 1 && stat.size > 0 && stat.size <= max);
  const bytes = fs.readFileSync(file);
  assert.equal(bytes.length, stat.size);
  return { value: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)), bytes };
}

function readJson(file: string, max = 65_536): any {
  return readJsonBytes(file, max).value;
}

function candidate(directory: string): Candidate {
  const root = fs.realpathSync(directory);
  const metadata = readJson(path.join(root, 'metadata.json'), 8192);
  const identity = candidateFields(metadata, true);
  assert.equal(metadata.source, process.env.CSF_SOURCE);
  assert.equal(metadata.run, process.env.GITHUB_RUN_ID);
  assert.equal(metadata.attempt, process.env.GITHUB_RUN_ATTEMPT);
  assert.equal(metadata.sha256, process.env.CSF_TGZ_SHA256);
  const tgz = path.join(root, 'candidate.tgz');
  assert.equal(fs.lstatSync(tgz).size, metadata.size);
  assert.equal(fileDigest(tgz), metadata.sha256);
  assert.equal(fileDigest(path.join(root, 'consumer/package-lock.json')), metadata.lockSha256);
  assert.equal(fileDigest(path.join(root, 'validation/sarif-schema-2.1.0.json')), metadata.schemaSha256);
  assert.equal(fileDigest(path.join(root, 'validation/official-sarif-test-validator.cjs')), metadata.validatorSha256);
  const installed = fs.realpathSync(path.join(root, 'consumer/node_modules/cdn-security-framework'));
  assert.equal(fs.realpathSync(path.resolve(__dirname, '..')), installed,
    'CI driver must resolve from the installed candidate');
  assert.equal(readJson(path.join(installed, 'package.json')).name, 'cdn-security-framework');
  return identity;
}

function checkOutputDirectory(workspace: string, output: string): void {
  const root = fs.realpathSync(workspace);
  const dir = fs.realpathSync(output);
  assert.ok(dir.startsWith(`${root}${path.sep}`) && fs.lstatSync(output).isDirectory());
  assert.deepEqual(fs.readdirSync(output), [], 'CI output directory must be new and empty');
}

async function run(configFile: string, candidateDir: string, output: string): Promise<void> {
  const identity = candidate(candidateDir);
  const config = readJson(configFile) as SourceDiffOptions;
  assert.ok(config && typeof config.workspaceRoot === 'string' && typeof config.openapi === 'string'
    && typeof config.policy === 'string' && typeof config.currentDate === 'string');
  checkOutputDirectory(config.workspaceRoot, output);
  const options: SourceDiffOptions = { ...config, out: path.relative(fs.realpathSync(config.workspaceRoot),
    path.join(fs.realpathSync(output), 'summary.md')) };
  const prepared = await prepareSourceDiff(options);
  if (!prepared.ok || !prepared.outputGuard || !prepared.bundle.finalized) {
    throw new Error(`CI_ANALYSIS_${safeCode(prepared.ok ? 'CI_INCOMPLETE' : prepared.code)}`);
  }
  const { bundle, workspace, outputGuard: guard } = prepared;
  const final = bundle.finalized!;
  const record: RecordV1 = {
    schemaVersion: 1, candidate: identity,
    targetEvidenceSha256: digest(JSON.stringify(bundle.metadata)),
    analysis: { exitCode: final.exitCode, status: final.analysis.status,
      codes: final.analysis.codes.map(safeCode) },
    reports: { summary: { status: 'not-generated', code: 'CI_NOT_RENDERED' },
      sarif: { status: 'not-generated', code: 'CI_NOT_RENDERED' } },
  };
  let summary: string | undefined;
  let sarif: string | undefined;
  try {
    summary = renderSourceAwareSummary(bundle);
    sarif = `${JSON.stringify(renderSourceAwareSarif(bundle), null, 2)}\n`;
  } catch {
    record.reports.summary = { status: 'failed', code: 'CI_REPORT_RENDER_FAILED' };
    record.reports.sarif = { status: 'failed', code: 'CI_REPORT_RENDER_FAILED' };
  }
  if (summary !== undefined && sarif !== undefined) {
    const summaryName = path.relative(fs.realpathSync(config.workspaceRoot), path.join(fs.realpathSync(output), 'summary.md'));
    const sarifName = path.relative(fs.realpathSync(config.workspaceRoot), path.join(fs.realpathSync(output), 'source-aware.sarif'));
    try {
      guard.write(guard.prepare(summaryName, workspace, final), summary);
      record.reports.summary = { status: 'saved', name: 'summary.md', sha256: digest(summary), bytes: Buffer.byteLength(summary) };
    } catch { record.reports.summary = { status: 'failed', code: 'CI_REPORT_SAVE_FAILED' }; }
    try {
      guard.write(guard.prepare(sarifName, workspace, final), sarif);
      record.reports.sarif = { status: 'saved', name: 'source-aware.sarif', sha256: digest(sarif), bytes: Buffer.byteLength(sarif) };
    } catch { record.reports.sarif = { status: 'failed', code: 'CI_REPORT_SAVE_FAILED' }; }
  }
  const recordName = path.relative(fs.realpathSync(config.workspaceRoot), path.join(fs.realpathSync(output), 'ci-record.json'));
  guard.write(guard.prepare(recordName, workspace, final), `${JSON.stringify(record, null, 2)}\n`);
  process.stdout.write(`CI_ANALYSIS_RECORDED exit=${final.exitCode}\n`);
}

function verifiedReport(output: string, report: Saved | Failed, name: Saved['name']): Buffer | undefined {
  if (report.status !== 'saved') return undefined;
  assert.equal(report.name, name);
  assert.match(report.sha256, hex64);
  boundedBytes(report.bytes);
  const file = path.join(output, name);
  const stat = fs.lstatSync(file);
  assert.ok(stat.isFile() && stat.nlink === 1 && stat.size === report.bytes);
  const bytes = fs.readFileSync(file);
  assert.equal(bytes.length, report.bytes);
  assert.equal(digest(bytes), report.sha256);
  return bytes;
}

function validateSummary(bytes: Buffer): void {
  assert.ok(bytes.length <= 32_768 && bytes.length > 0);
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  assert.ok(text.startsWith('# Source-aware Contract Diff (internal pre-Entry)\n') && text.endsWith('\n'));
  assert.ok(!/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(text.replace(/\n/g, '')));
  assert.ok(!/<[A-Za-z!/]|(?:^|\n)::[^\n]*|(?:^|\n)\s*\[\s*.*\]\([^)]*\)/m.test(text));
  assert.ok(!hasUnsafeSensitiveText(text));
}

function validateSarif(bytes: Buffer, candidateDir: string): void {
  assert.ok(bytes.length > 0 && bytes.length <= 1_048_576);
  const validator = require(path.join(fs.realpathSync(candidateDir), 'validation/official-sarif-test-validator.cjs')) as
    { createOfficialSarifValidator: (schemaPath: string) => (value: unknown) => boolean };
  const validate = validator.createOfficialSarifValidator(path.join(candidateDir, 'validation/sarif-schema-2.1.0.json'));
  const report = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  assert.ok(validate(report), 'official SARIF schema failed');
}

function writeNew(file: string, value: string | Buffer): void {
  fs.writeFileSync(file, value, { flag: 'wx', mode: 0o600 });
}

function publish(recordFile: string, candidateDir: string, stage: string): void {
  const identity = candidate(candidateDir);
  assert.ok(fs.lstatSync(stage).isDirectory() && fs.readdirSync(stage).length === 0);
  let summaryTransfer: Delivery['summaryTransfer'] = 'failed';
  let code = 'CI_RECORD_MISSING';
  const files: Delivery['files'] = [];
  const staged: StagedFile[] = [];
  const output = path.dirname(recordFile);
  const stageFile = (name: StagedFile['name'], bytes: Buffer) => {
    writeNew(path.join(stage, name), bytes);
    files.push(name);
    staged.push({ name, sha256: digest(bytes), bytes: bytes.length });
  };
  try {
    const stored = readJsonBytes(recordFile);
    const record = recordFields(stored.value);
    assert.deepEqual(record.candidate, identity);
    const summary = verifiedReport(output, record.reports.summary, 'summary.md');
    const sarif = verifiedReport(output, record.reports.sarif, 'source-aware.sarif');
    if (summary) validateSummary(summary);
    if (sarif) validateSarif(sarif, candidateDir);
    if (summary) stageFile('summary.md', summary);
    if (sarif) stageFile('source-aware.sarif', sarif);
    stageFile('ci-record.json', stored.bytes);
    if (summary) {
      fs.appendFileSync(assertSummaryPath(), summary);
      summaryTransfer = 'success';
      code = sarif ? 'CI_OK' : 'CI_PARTIAL_REPORT';
    } else code = 'CI_SUMMARY_UNAVAILABLE';
  } catch {
    code = 'CI_ARTIFACT_VERIFY_FAILED';
  }
  if (summaryTransfer === 'failed') {
    try { fs.appendFileSync(assertSummaryPath(), '# Source-aware Contract Diff\n\nCI_REPORT_UNAVAILABLE: report generation or verification failed.\n'); }
    catch { code = 'CI_SUMMARY_TRANSFER_FAILED'; }
  }
  const delivery: Delivery = { schemaVersion: 1, candidate: identity, summaryTransfer,
    artifactListVerified: code === 'CI_OK', files, staged, code };
  writeNew(path.join(stage, 'delivery.json'), `${JSON.stringify(delivery, null, 2)}\n`);
  if (process.env.GITHUB_OUTPUT) {
    const upload = [...files, 'delivery.json'];
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `has-files=${upload.length > 0}\nartifact-paths<<CSF_FILES\n${upload.map(name => path.join(stage, name)).join('\n')}\nCSF_FILES\n`);
  }
}

function assertSummaryPath(): string {
  const file = process.env.GITHUB_STEP_SUMMARY;
  assert.ok(file && path.isAbsolute(file), 'missing runner Summary destination');
  return file;
}

function verifyStage(recordFile: string, candidateDir: string, deliveryFile: string):
  { delivery: Delivery; record?: RecordV1 } {
  const identity = candidate(candidateDir);
  const stage = path.dirname(deliveryFile);
  assert.ok(fs.lstatSync(stage).isDirectory());
  const delivery = deliveryFields(readJson(deliveryFile, 8192));
  assert.deepEqual(delivery.candidate, identity);
  assert.deepEqual(fs.readdirSync(stage).sort(), [...delivery.files, 'delivery.json'].sort());
  const bytes = new Map<StagedFile['name'], Buffer>();
  for (const file of delivery.staged) {
    const target = path.join(stage, file.name);
    const stat = fs.lstatSync(target);
    assert.ok(stat.isFile() && stat.nlink === 1 && stat.size === file.bytes);
    const value = fs.readFileSync(target);
    assert.equal(value.length, file.bytes);
    assert.equal(digest(value), file.sha256);
    if (file.name === 'summary.md') validateSummary(value);
    if (file.name === 'source-aware.sarif') validateSarif(value, candidateDir);
    bytes.set(file.name, value);
  }
  const recorded = bytes.get('ci-record.json');
  if (!recorded) {
    assert.equal(bytes.size, 0);
    assert.notEqual(delivery.code, 'CI_OK');
    return { delivery };
  }
  const record = recordFields(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(recorded)));
  assert.deepEqual(record.candidate, identity);
  const original = readJsonBytes(recordFile);
  recordFields(original.value);
  assert.deepEqual(recorded, original.bytes);
  for (const [name, report] of [['summary.md', record.reports.summary],
    ['source-aware.sarif', record.reports.sarif]] as const) {
    const stagedBytes = bytes.get(name);
    if (!stagedBytes) continue;
    assert.equal(report.status, 'saved');
    if (report.status === 'saved') {
      assert.equal(digest(stagedBytes), report.sha256);
      assert.equal(stagedBytes.length, report.bytes);
    }
  }
  if (delivery.code === 'CI_OK') {
    assert.equal(delivery.summaryTransfer, 'success');
    assert.deepEqual(delivery.files, [...reportNames]);
    assert.equal(record.reports.summary.status, 'saved');
    assert.equal(record.reports.sarif.status, 'saved');
  }
  return { delivery, record };
}

function gate(recordFile: string, candidateDir: string, deliveryFile: string): void {
  const identity = candidate(candidateDir);
  assert.equal(process.env.CSF_PRODUCER_STATE, 'success');
  assert.equal(process.env.CSF_ACCEPTANCE_STATE, 'success');
  assert.equal(process.env.CSF_ANALYZE_OUTCOME, 'success');
  assert.equal(process.env.CSF_PUBLISH_OUTCOME, 'success');
  assert.equal(process.env.CSF_STAGE_OUTCOME, 'success');
  assert.equal(process.env.CSF_ARTIFACT_OUTCOME, 'success');
  const { delivery, record } = verifyStage(recordFile, candidateDir, deliveryFile);
  assert.ok(record);
  assert.deepEqual(record.candidate, identity);
  assert.equal(delivery.summaryTransfer, 'success');
  assert.equal(delivery.artifactListVerified, true);
  assert.equal(delivery.code, 'CI_OK');
  assert.deepEqual(delivery.files, [...reportNames]);
  const summary = verifiedReport(path.dirname(recordFile), record.reports.summary, 'summary.md');
  const sarif = verifiedReport(path.dirname(recordFile), record.reports.sarif, 'source-aware.sarif');
  assert.ok(summary && sarif);
  validateSummary(summary);
  validateSarif(sarif, candidateDir);
  assert.ok([0, 1, 2, 3].includes(record.analysis.exitCode));
  if (record.analysis.exitCode !== 0) {
    console.error(`CI_SOURCE_AWARE_ANALYSIS_EXIT_${record.analysis.exitCode}`);
    process.exitCode = record.analysis.exitCode;
    return;
  }
  process.stdout.write('CI_SOURCE_AWARE_GATE_PASS\n');
}

if (require.main === module) {
  const [command, first, second, third] = process.argv.slice(2);
  (async () => {
    try {
      assert.ok(first && second && third);
      if (command === 'run') await run(first, second, third);
      else if (command === 'publish') publish(first, second, third);
      else if (command === 'verify-stage') verifyStage(first, second, third);
      else if (command === 'gate') gate(first, second, third);
      else throw new Error('unknown command');
    } catch {
      console.error(`CI_SOURCE_AWARE_${command === 'gate' ? 'GATE' : 'PROCESS'}_FAILED`);
      process.exitCode = 3;
    }
  })();
}
