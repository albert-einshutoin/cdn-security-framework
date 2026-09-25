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

type Candidate = { source: string; harness: string; tree: string; run: string; attempt: string;
  sha256: string; size: number; lockSha256: string; schemaSha256: string; validatorSha256: string };
type Saved = { status: 'saved'; name: 'summary.md' | 'source-aware.sarif'; sha256: string; bytes: number };
type Failed = { status: 'failed' | 'not-generated'; code: string };
type RecordV1 = { schemaVersion: 1; candidate: Candidate; targetEvidenceSha256: string;
  analysis: { exitCode: 0 | 1 | 2 | 3; status: string; codes: string[] };
  reports: { summary: Saved | Failed; sarif: Saved | Failed } };
type Delivery = { schemaVersion: 1; summaryTransfer: 'success' | 'failed';
  artifactListVerified: boolean; files: string[]; code: string };

const digest = (bytes: Buffer | string) => createHash('sha256').update(bytes).digest('hex');
const fileDigest = (file: string) => digest(fs.readFileSync(file));
const safeCode = (value: string) => /^[A-Z][A-Z0-9_]{1,79}$/.test(value) ? value : 'CI_UNKNOWN_ERROR';

function readJson(file: string, max = 65_536): any {
  const stat = fs.lstatSync(file);
  assert.ok(stat.isFile() && stat.nlink === 1 && stat.size > 0 && stat.size <= max);
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function candidate(directory: string): Candidate {
  const root = fs.realpathSync(directory);
  const metadata = readJson(path.join(root, 'metadata.json'), 8192) as Candidate & { schemaVersion: number };
  assert.equal(metadata.schemaVersion, 1);
  assert.match(metadata.source, /^[a-f0-9]{40}$/);
  assert.equal(metadata.harness, metadata.source);
  assert.match(metadata.tree, /^[a-f0-9]{40}$/);
  assert.match(metadata.sha256, /^[a-f0-9]{64}$/);
  assert.match(metadata.lockSha256, /^[a-f0-9]{64}$/);
  assert.match(metadata.schemaSha256, /^[a-f0-9]{64}$/);
  assert.match(metadata.validatorSha256, /^[a-f0-9]{64}$/);
  assert.ok(Number.isSafeInteger(metadata.size) && metadata.size > 0 && metadata.size <= 1_048_576);
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
  const { schemaVersion: _schemaVersion, ...identity } = metadata;
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

function verifiedReport(output: string, report: Saved | Failed, name: Saved['name']): string | undefined {
  if (report.status !== 'saved') return undefined;
  assert.equal(report.name, name);
  assert.match(report.sha256, /^[a-f0-9]{64}$/);
  assert.ok(Number.isSafeInteger(report.bytes) && report.bytes > 0 && report.bytes <= 1_048_576);
  const file = path.join(output, name);
  const stat = fs.lstatSync(file);
  assert.ok(stat.isFile() && stat.nlink === 1 && stat.size === report.bytes);
  assert.equal(fileDigest(file), report.sha256);
  return file;
}

function validateSummary(file: string): void {
  const bytes = fs.readFileSync(file);
  assert.ok(bytes.length <= 32_768 && bytes.length > 0);
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  assert.ok(text.startsWith('# Source-aware Contract Diff (internal pre-Entry)\n') && text.endsWith('\n'));
  assert.ok(!/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(text.replace(/\n/g, '')));
  assert.ok(!/<[A-Za-z!/]|(?:^|\n)::[^\n]*|(?:^|\n)\s*\[\s*.*\]\([^)]*\)/m.test(text));
  assert.ok(!hasUnsafeSensitiveText(text));
}

function validateSarif(file: string, candidateDir: string): void {
  const validator = require(path.join(fs.realpathSync(candidateDir), 'validation/official-sarif-test-validator.cjs')) as
    { createOfficialSarifValidator: (schemaPath: string) => (value: unknown) => boolean };
  const validate = validator.createOfficialSarifValidator(path.join(candidateDir, 'validation/sarif-schema-2.1.0.json'));
  assert.ok(validate(readJson(file, 1_048_576)), 'official SARIF schema failed');
}

function writeNew(file: string, value: string): void {
  fs.writeFileSync(file, value, { flag: 'wx', mode: 0o600 });
}

function publish(recordFile: string, candidateDir: string, stage: string): void {
  const identity = candidate(candidateDir);
  assert.ok(fs.lstatSync(stage).isDirectory() && fs.readdirSync(stage).length === 0);
  let summaryTransfer: Delivery['summaryTransfer'] = 'failed';
  let code = 'CI_RECORD_MISSING';
  const files: string[] = [];
  const output = path.dirname(recordFile);
  try {
    const record = readJson(recordFile) as RecordV1;
    assert.equal(record.schemaVersion, 1);
    assert.deepEqual(record.candidate, identity);
    assert.match(record.targetEvidenceSha256, /^[a-f0-9]{64}$/);
    assert.ok([0, 1, 2, 3].includes(record.analysis.exitCode));
    const summary = verifiedReport(output, record.reports.summary, 'summary.md');
    const sarif = verifiedReport(output, record.reports.sarif, 'source-aware.sarif');
    if (summary) validateSummary(summary);
    if (sarif) validateSarif(sarif, candidateDir);
    for (const file of [summary, sarif, recordFile]) {
      if (!file) continue;
      const target = path.join(stage, path.basename(file));
      fs.copyFileSync(file, target, fs.constants.COPYFILE_EXCL);
      assert.equal(fileDigest(target), fileDigest(file));
      files.push(path.basename(file));
    }
    if (summary) {
      fs.appendFileSync(assertSummaryPath(), fs.readFileSync(summary));
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
  const delivery: Delivery = { schemaVersion: 1, summaryTransfer,
    artifactListVerified: code === 'CI_OK', files, code };
  writeNew(path.join(stage, 'delivery.json'), `${JSON.stringify(delivery, null, 2)}\n`);
  files.push('delivery.json');
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `has-files=${files.length > 0}\nartifact-paths<<CSF_FILES\n${files.map(name => path.join(stage, name)).join('\n')}\nCSF_FILES\n`);
  }
}

function assertSummaryPath(): string {
  const file = process.env.GITHUB_STEP_SUMMARY;
  assert.ok(file && path.isAbsolute(file), 'missing runner Summary destination');
  return file;
}

function gate(recordFile: string, candidateDir: string, deliveryFile: string): void {
  const identity = candidate(candidateDir);
  assert.equal(process.env.CSF_PRODUCER_STATE, 'success');
  assert.equal(process.env.CSF_ACCEPTANCE_STATE, 'success');
  assert.equal(process.env.CSF_ANALYZE_OUTCOME, 'success');
  assert.equal(process.env.CSF_PUBLISH_OUTCOME, 'success');
  assert.equal(process.env.CSF_ARTIFACT_OUTCOME, 'success');
  const record = readJson(recordFile) as RecordV1;
  const delivery = readJson(deliveryFile, 8192) as Delivery;
  assert.deepEqual(record.candidate, identity);
  assert.equal(delivery.schemaVersion, 1);
  assert.equal(delivery.summaryTransfer, 'success');
  assert.equal(delivery.artifactListVerified, true);
  assert.equal(delivery.code, 'CI_OK');
  assert.deepEqual(delivery.files, ['summary.md', 'source-aware.sarif', 'ci-record.json']);
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
      else if (command === 'gate') gate(first, second, third);
      else throw new Error('unknown command');
    } catch {
      console.error(`CI_SOURCE_AWARE_${command === 'gate' ? 'GATE' : 'PROCESS'}_FAILED`);
      process.exitCode = 3;
    }
  })();
}
