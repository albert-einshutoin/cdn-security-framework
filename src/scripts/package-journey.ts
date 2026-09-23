#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import cp from 'node:child_process';
import { createRequire } from 'node:module';
import { expectedIdentity, verifyTarball } from './single-pack';

const packageName = 'cdn-security-framework';
const requiredChecks = [
  'docs-commands', 'rich-inspection', 'review-candidate', 'candidate-build',
  'finding-parity', 'summary-limit', 'exceptions', 'exit-codes',
  'input-boundaries', 'privacy', 'determinism', 'cleanup',
] as const;
export { requiredChecks };
export const requiredStepIds = [
  'candidate-lint', 'candidate-build', 'rich-inspect-text', 'rich-inspect-json',
  'rich-diff-json', 'rich-diff-sarif', 'rich-diff-summary',
  'parity-text', 'parity-json', 'parity-sarif', 'parity-github-summary',
  'exception-valid', 'exception-text', 'exception-sarif', 'exception-github-summary',
  'exception-input-error', 'exception-expired', 'exception-expired-summary', 'exception-invalid',
  'diff-exit-0', 'diff-exit-2', 'diff-exit-3',
  'boundary-invalid-version', 'boundary-invalid-policy', 'boundary-remote-ref',
  'boundary-local-escape', 'boundary-oversized', 'boundary-ref-count',
  'boundary-output-collision', 'boundary-output-symlink', 'boundary-output-hardlink',
  'boundary-output-existing', 'boundary-input-symlink',
  'privacy-text', 'privacy-json', 'privacy-sarif', 'privacy-github-summary',
  'privacy-file-text', 'privacy-file-json', 'privacy-file-sarif', 'privacy-file-github-summary',
  'privacy-key-text', 'privacy-key-json', 'privacy-key-sarif', 'privacy-key-github-summary',
  'privacy-key-file-text', 'privacy-key-file-json', 'privacy-key-file-sarif', 'privacy-key-file-github-summary',
] as const;
export const requiredInputKeys = ['docs-openapi', 'docs-policy', 'rich-openapi', 'rich-policy',
  'parity-openapi', 'parity-policy', 'exception-valid', 'exception-expired', 'exception-invalid',
  'clean-openapi', 'clean-policy', 'fault-preload', 'input-symlink-target',
  'privacy-openapi', 'privacy-policy', 'privacy-key-openapi', 'privacy-key-policy'] as const;
export const requiredOutputKeys = ['candidate', 'candidate-meta', 'rich-inspection', 'rich-json',
  'rich-sarif', 'rich-summary', 'parity-text', 'parity-json', 'parity-sarif',
  'parity-github-summary', 'exception-valid', 'exception-text', 'exception-sarif',
  'exception-github-summary', 'exception-expired', 'exception-expired-summary',
  'privacy-text', 'privacy-json', 'privacy-sarif', 'privacy-github-summary',
  'privacy-key-text', 'privacy-key-json', 'privacy-key-sarif', 'privacy-key-github-summary'] as const;
type Step = { id: string; exit: number; expectedExit: number; durationMs: number; stdoutBytes: number; stderrBytes: number };
type Output = { sha256: string; bytes: number };
export type JourneyResult = { status: 'pass'; checks: string[]; steps: Step[]; outputs: Record<string, Output>; inputs: Record<string, string>; toolchain: Record<string, string>; onlinePreparationMs: number; offlineAcceptanceMs: number; findings: Array<{ ruleId: string; severity: string; route: string; evidence: string[]; suppressed: boolean }> };
const sha = (file: string) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const fail = (code: string): never => { throw new Error(`AC_${code}`); };
const need = (ok: unknown, code: string): void => { if (!ok) fail(code); };
const synthetic = ['SYNTHETIC_SECRET_890_VALUE', 'Bearer SYNTHETIC_SECRET_890_VALUE', 'query=SYNTHETIC_SECRET_890_VALUE'];
const steps: Step[] = [];
const outputs: Record<string, Output> = {};
const inputs: Record<string, string> = {};
let cli = '';
let installed = '';
let consumer = '';
let pkgExamples = '';

export function assertSafeOutput(value: string, root: string, label: string): void {
  for (const secret of synthetic) need(!value.includes(secret), `${label}_PRIVACY_VALUE`);
  const canonical = fs.existsSync(root) ? fs.realpathSync(root) : root;
  need(!value.includes(root) && !value.includes(canonical)
    && !(consumer && value.includes(consumer)) && !(installed && value.includes(installed))
    && !/(?:^|[\s"'=])\/(?:tmp|private\/tmp|home|Users|var\/folders)\//mu.test(value), `${label}_PRIVACY_PATH`);
}
function command(id: string, executable: string, args: string[], cwd: string, expectedExit: number, env: NodeJS.ProcessEnv = {}): { stdout: string; stderr: string } {
  const start = process.hrtime.bigint();
  const result = cp.spawnSync(executable, args, { cwd, encoding: 'utf8', timeout: 20_000, maxBuffer: 4 * 1024 * 1024,
    env: { ...process.env, LC_ALL: 'C', TZ: 'UTC', NO_COLOR: '1', NODE_PATH: '', NODE_OPTIONS: '', ...env } });
  const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
  need(!result.error && result.status !== null, `${id}_SPAWN`);
  const stdout = result.stdout || ''; const stderr = result.stderr || '';
  assertSafeOutput(stdout + stderr, cwd, id);
  need(result.status === expectedExit, `${id}_EXIT`);
  steps.push({ id, exit: result.status!, expectedExit, durationMs, stdoutBytes: Buffer.byteLength(stdout), stderrBytes: Buffer.byteLength(stderr) });
  return { stdout, stderr };
}
function cliCommand(id: string, cwd: string, args: string[], exit: number, env?: NodeJS.ProcessEnv): { stdout: string; stderr: string } {
  return command(id, process.execPath, [cli, ...args], cwd, exit, env);
}
function keepInput(file: string, label: string): string { const digest = sha(file); inputs[label] = digest; return digest; }
function unchanged(file: string, before: string, code: string): void { need(sha(file) === before, code); }
function keepOutput(file: string, label: string, root: string): string {
  need(fs.statSync(file).isFile(), `${label}_MISSING`);
  const content = fs.readFileSync(file, 'utf8'); assertSafeOutput(content, root, label);
  outputs[label] = { sha256: sha(file), bytes: Buffer.byteLength(content) };
  return content;
}
function isolated(label: string, fn: (root: string) => void): void {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `csf-890-${label}-`));
  try { fn(root); } finally { fs.rmSync(root, { recursive: true, force: true }); }
  need(!fs.existsSync(root), `${label}_CLEANUP`);
}
function section(file: string, number: number): string[] {
  const text = fs.readFileSync(file, 'utf8');
  const start = text.indexOf(`## ${number}. `); need(start >= 0, 'DOC_SECTION');
  const end = text.indexOf(`\n## ${number + 1}. `, start + 1);
  const portion = text.slice(start, end < 0 ? undefined : end);
  const block = portion.match(/```bash\n([\s\S]*?)\n```/); need(block, 'DOC_COMMAND_BLOCK');
  return block![1].replace(/\\\n\s*/g, ' ').split('\n').map(line => line.trim()).filter(line => line && !line.startsWith('#'));
}
function docs(root: string): void {
  const en = path.join(installed, 'docs/quickstart.md');
  const ja = path.join(installed, 'docs/quickstart.ja.md');
  for (const n of [1, 2, 5]) need(JSON.stringify(section(en, n)) === JSON.stringify(section(ja, n)), `DOC_JA_${n}`);
  const readmes = ['README.md', 'README.ja.md'].map(name => fs.readFileSync(path.join(installed, name), 'utf8'));
  for (const readme of readmes) {
    need(readme.includes('export CANDIDATE_TARBALL=/path/to/verified-candidate.tgz'), 'README_TARBALL');
    need(readme.includes('npm install --save-dev "$CANDIDATE_TARBALL"'), 'README_INSTALL');
    const block = readme.match(/### Init[^\n]*\n\n```bash\n([\s\S]*?)\n```/);
    need(block, 'README_COMMAND_BLOCK');
    const commands = block![1].split('\n').map(line => line.trim()).filter(Boolean);
    const quickstart = section(en, 2);
    need(JSON.stringify(commands) === JSON.stringify(quickstart), 'README_QUICKSTART_DRIFT');
  }
  // The CI consumer uses the producer's fixed lock and offline npm ci. This is the one documented install substitution.
  need(section(en, 1).includes('npm install --save-dev "$CANDIDATE_TARBALL"'), 'DOC_INSTALL_SUBSTITUTION');
  fs.symlinkSync(path.join(consumer, 'node_modules'), path.join(root, 'node_modules'), 'dir');
  for (const n of [2, 5]) {
    for (const line of section(en, n)) {
      if (line.startsWith('export ')) continue;
      const parts = line.split(/\s+/);
      const executable = parts.shift()!;
      need(['cp', 'node', './node_modules/.bin/cdn-security'].includes(executable), 'DOC_UNEXPECTED_COMMAND');
      command(`docs-${n}-${steps.length}`, executable, parts, root, 0, { EDGE_ADMIN_TOKEN: 'docs-fixture-token-not-for-deploy' });
    }
  }
  const openapi = path.join(root, 'openapi.yaml'); const policy = path.join(root, 'policy/security.yml');
  keepInput(openapi, 'docs-openapi'); keepInput(policy, 'docs-policy');
  const candidate = path.join(root, 'policy/openapi.candidate.yml');
  keepOutput(candidate, 'candidate', root); keepOutput(path.join(root, 'policy/openapi.candidate.meta.json'), 'candidate-meta', root);
  command('candidate-lint', process.execPath, [path.join(installed, 'scripts/policy-lint.js'), 'policy/openapi.candidate.yml'], root, 0);
  cliCommand('candidate-build', root, ['build', '--policy', 'policy/openapi.candidate.yml', '--target', 'aws', '--out-dir', 'dist/candidate'], 0,
    { EDGE_ADMIN_TOKEN: 'docs-fixture-token-not-for-deploy', ORIGIN_SECRET: 'docs-fixture-origin-not-for-deploy' });
  need(fs.existsSync(path.join(root, 'dist/candidate/edge')) && fs.existsSync(path.join(root, 'dist/candidate/infra')), 'CANDIDATE_ARTIFACTS');
  unchanged(openapi, inputs['docs-openapi'], 'DOC_OPENAPI_MUTATED'); unchanged(policy, inputs['docs-policy'], 'DOC_POLICY_MUTATED');
}
function diffArgs(openapi: string, policy: string, format: string, extra: string[] = []): string[] {
  return ['contract', 'diff', '--openapi', openapi, '--policy', policy, '--target', 'aws', '--workspace-root', '.', '--format', format, ...extra];
}
function parity(root: string): { report: any; raw: Record<string, string>; openapi: string; policy: string } {
  const source = fs.readFileSync(path.join(pkgExamples, 'github-actions/fixtures/openapi.yaml'), 'utf8');
  need(source.includes('    get:'), 'PARITY_SOURCE');
  const openapi = path.join(root, 'parity.yaml'); const policy = path.join(root, 'policy.yml');
  fs.writeFileSync(openapi, source.replace('    get:', '    post:'));
  fs.copyFileSync(path.join(pkgExamples, 'github-actions/fixtures/policy.yml'), policy);
  keepInput(openapi, 'parity-openapi'); keepInput(policy, 'parity-policy');
  const raw: Record<string, string> = {};
  for (const format of ['text', 'json', 'sarif', 'github-summary']) {
    const out = `report.${format === 'github-summary' ? 'md' : format}`;
    cliCommand(`parity-${format}`, root, [...diffArgs('parity.yaml', 'policy.yml', format, ['--fail-on', 'error']), '--out', out], 1);
    raw[format] = keepOutput(path.join(root, out), `parity-${format}`, root);
  }
  const report = JSON.parse(raw.json); const sarif = JSON.parse(raw.sarif);
  const installedRequire = createRequire(path.join(installed, 'package.json'));
  const Ajv = installedRequire('ajv'); const ajv = new Ajv({ strict: false });
  ajv.addSchema(JSON.parse(fs.readFileSync(path.join(installed, 'schemas/finding-v1.schema.json'), 'utf8')));
  const validReport = ajv.compile(JSON.parse(fs.readFileSync(path.join(installed, 'schemas/contract-diff-report-v1.schema.json'), 'utf8')));
  need(validReport(report) && sarif.version === '2.1.0' && sarif.runs?.length === 1, 'PARITY_SCHEMAS');
  const api = installedRequire(`${packageName}/contract`);
  const apiReport = api.diffSecurityContracts({ openapiPath: openapi, policyPath: policy, target: 'aws', workspaceRoot: root });
  need(apiReport.summary.total === report.summary.total && apiReport.summary.error === report.summary.error
    && apiReport.findings.length === report.findings.length
    && apiReport.findings.every((f: any, i: number) => f.ruleId === report.findings[i].ruleId
      && f.severity === report.findings[i].severity && f.instanceId === report.findings[i].instanceId), 'PUBLIC_API_PARITY');
  const expected = [
    { ruleId: 'SC-EXPOSURE-001', severity: 'error', route: '/health' },
    { ruleId: 'SC-EXPOSURE-002', severity: 'error', route: 'POST /health' },
  ];
  need(report.summary.total === 2 && report.summary.error === 2 && report.summary.suppressed === 0, 'PARITY_COUNTS');
  need(report.findings.length === 2 && sarif.runs[0].results.length === 2, 'PARITY_LENGTH');
  for (let i = 0; i < expected.length; i++) {
    const e = expected[i], f = report.findings[i], s = sarif.runs[0].results[i];
    const route = [f.route?.method, f.route?.path].filter(Boolean).join(' ');
    need(f.ruleId === e.ruleId && f.severity === e.severity && route === e.route && /^[a-f0-9]{64}$/.test(f.instanceId), `PARITY_JSON_${i}`);
    const evidence = f.evidence.map((v: any) => `${v.uri}#${v.pointer}`);
    need(evidence.includes('parity.yaml#/paths/~1health/post') && evidence.includes('policy.yml#/request/allow_methods'), `PARITY_EVIDENCE_${i}`);
    const locations = [...(s.locations || []), ...(s.relatedLocations || [])];
    need(s.ruleId === e.ruleId && s.level === e.severity
      && s.partialFingerprints['securityContractFinding/v1'] === f.instanceId
      && !s.suppressions?.length, `PARITY_SARIF_${i}`);
    need(locations.some((v: any) => v.physicalLocation.artifactLocation.uri === 'parity.yaml'
      && v.logicalLocations?.some((p: any) => p.name === '/paths/~1health/post')), `PARITY_SARIF_OPENAPI_${i}`);
    need(locations.some((v: any) => v.physicalLocation.artifactLocation.uri === 'policy.yml'
      && v.logicalLocations?.some((p: any) => p.name === '/request/allow_methods')), `PARITY_SARIF_POLICY_${i}`);
    const sarifEvidence = locations.map((v: any) => `${v.physicalLocation.artifactLocation.uri}#${v.logicalLocations?.[0]?.name ?? ''}`);
    need(JSON.stringify([...sarifEvidence].sort()) === JSON.stringify([...evidence].sort()), `PARITY_SARIF_EVIDENCE_SET_${i}`);
    const textLines = raw.text.split('\n');
    const first = textLines.findIndex(line => line.startsWith(`ERROR ${e.ruleId} `));
    need(first >= 0, `PARITY_TEXT_${i}`);
    const next = textLines.findIndex((line, index) => index > first && /^(?:ERROR|WARNING|INFO) SC-[A-Z]/u.test(line));
    const block = textLines.slice(first, next < 0 ? undefined : next).join('\n');
    need(block.split('\n')[0].includes(` ${e.route} `)
      && evidence.every((ref: string) => block.includes(`evidence=${ref}`)), `PARITY_TEXT_EVIDENCE_${i}`);
    const summaryRow = `| error | ${e.ruleId} | \`${e.route}\` |`;
    need(raw['github-summary'].split('\n').filter(line => line.startsWith(summaryRow)).length === 1,
      `PARITY_SUMMARY_${i}`);
  }
  need(raw.text.split('\n').filter(line => /^(?:ERROR|WARNING|INFO) SC-[A-Z]/u.test(line)).length === 2
    && raw['github-summary'].split('\n').filter(line => /^\| error \| SC-/u.test(line)).length === 2,
  'PARITY_VISIBLE_COUNTS');
  need(raw['github-summary'].includes('| 2 | 0 | 0 | 0 | 0 |') && !raw['github-summary'].includes('additional findings'), 'SUMMARY_COMPLETE');
  need(raw['github-summary'].includes('Full details: `contract-diff.json` and `cdn-security.sarif` artifacts.'), 'SUMMARY_EVIDENCE_LINK');
  unchanged(openapi, inputs['parity-openapi'], 'PARITY_OPENAPI_MUTATED'); unchanged(policy, inputs['parity-policy'], 'PARITY_POLICY_MUTATED');
  return { report, raw, openapi, policy };
}
function exceptions(root: string, report: any, openapi: string, policy: string): void {
  const finding = report.findings.find((item: any) => item.ruleId === 'SC-EXPOSURE-002'); need(finding, 'EXCEPTION_TARGET');
  const file = path.join(root, 'exceptions.yml');
  const value = `version: 1\nexceptions:\n  - id: EXC-2026-291\n    rule_id: SC-EXPOSURE-002\n    selector: { instance_id: ${finding.instanceId}, target: aws, environment: production }\n    reason: Approved synthetic compatibility window.\n    owner: security-team\n    expires_at: 2026-12-01\n`;
  fs.writeFileSync(file, value); keepInput(file, 'exception-valid');
  const args = [...diffArgs(path.basename(openapi), path.basename(policy), 'json', ['--exceptions', 'exceptions.yml', '--environment', 'production', '--current-date', '2026-09-23', '--include-suppressed']), '--out', 'exception.json'];
  cliCommand('exception-valid', root, args, 1);
  const valid = JSON.parse(keepOutput(path.join(root, 'exception.json'), 'exception-valid', root));
  need(valid.summary.suppressed === 1 && valid.findings.length === 1 && valid.findings[0].ruleId === 'SC-EXPOSURE-001', 'EXCEPTION_SCOPE');
  need(valid.suppressedFindings.length === 1 && valid.suppressedFindings[0].ruleId === 'SC-EXPOSURE-002', 'EXCEPTION_SUPPRESSION');
  for (const format of ['text', 'sarif', 'github-summary']) {
    const out = `exception.${format === 'github-summary' ? 'md' : format}`;
    cliCommand(`exception-${format}`, root, [...diffArgs('parity.yaml', 'policy.yml', format,
      ['--exceptions', 'exceptions.yml', '--environment', 'production', '--current-date', '2026-09-23', '--include-suppressed']), '--out', out], 1);
    const value = keepOutput(path.join(root, out), `exception-${format}`, root);
    if (format === 'text') need(value.includes('suppressed=1') && value.includes('Suppressed findings:')
      && value.includes('SC-EXPOSURE-001') && value.includes('SC-EXPOSURE-002'), 'EXCEPTION_TEXT');
    if (format === 'github-summary') need(value.includes('| 1 | 0 | 0 | 1 | 0 |')
      && value.includes('| error | SC-EXPOSURE-001 |') && !value.includes('| error | SC-EXPOSURE-002 |'), 'EXCEPTION_SUMMARY');
    if (format === 'sarif') {
      const results = JSON.parse(value).runs[0].results;
      need(results.length === 2 && results.some((x: any) => x.ruleId === 'SC-EXPOSURE-002'
        && x.suppressions?.some((s: any) => s.kind === 'external' && s.status === 'accepted')), 'EXCEPTION_SARIF');
    }
  }
  const invalidInput = path.join(root, 'invalid-openapi.yaml');
  fs.writeFileSync(invalidInput, 'openapi: 2.0.0\ninfo: {title: Invalid, version: 1}\npaths: {}\n');
  const invalidInputHash = keepInput(invalidInput, 'exception-invalid-openapi');
  cliCommand('exception-input-error', root, diffArgs('invalid-openapi.yaml', 'policy.yml', 'json',
    ['--exceptions', 'exceptions.yml', '--environment', 'production', '--current-date', '2026-09-23']), 2);
  unchanged(invalidInput, invalidInputHash, 'EXCEPTION_INPUT_MUTATED');
  unchanged(file, inputs['exception-valid'], 'EXCEPTION_MUTATED');
  fs.writeFileSync(file, value.replace('2026-12-01', '2026-01-01')); keepInput(file, 'exception-expired');
  cliCommand('exception-expired', root, [...diffArgs('parity.yaml', 'policy.yml', 'json', ['--exceptions', 'exceptions.yml', '--environment', 'production', '--current-date', '2026-09-23']), '--out', 'expired.json'], 1);
  const expired = JSON.parse(keepOutput(path.join(root, 'expired.json'), 'exception-expired', root));
  need(expired.summary.suppressed === 0 && expired.exceptionDiagnostics.some((x: any) => x.ruleId === 'SC-GOV-001'), 'EXCEPTION_EXPIRY');
  cliCommand('exception-expired-summary', root, [...diffArgs('parity.yaml', 'policy.yml', 'github-summary',
    ['--exceptions', 'exceptions.yml', '--environment', 'production', '--current-date', '2026-09-23']), '--out', 'expired.md'], 1);
  need(keepOutput(path.join(root, 'expired.md'), 'exception-expired-summary', root).includes('| 3 | 0 | 0 | 0 | 1 |'), 'EXPIRED_SUMMARY');
  unchanged(file, inputs['exception-expired'], 'EXPIRED_MUTATED');
  fs.writeFileSync(file, 'version: 1\nexceptions: nope\n'); keepInput(file, 'exception-invalid');
  cliCommand('exception-invalid', root, diffArgs('parity.yaml', 'policy.yml', 'json', ['--exceptions', 'exceptions.yml']), 2);
  unchanged(file, inputs['exception-invalid'], 'INVALID_EXCEPTION_MUTATED');
}
function cleanAndExits(root: string): void {
  const openapi = path.join(root, 'clean.yaml'), policy = path.join(root, 'policy.yml');
  fs.copyFileSync(path.join(pkgExamples, 'github-actions/fixtures/openapi.yaml'), openapi);
  fs.copyFileSync(path.join(pkgExamples, 'github-actions/fixtures/policy.yml'), policy);
  const before = keepInput(openapi, 'clean-openapi'); keepInput(policy, 'clean-policy');
  cliCommand('diff-exit-0', root, diffArgs('clean.yaml', 'policy.yml', 'json'), 0);
  cliCommand('diff-exit-2', root, diffArgs('clean.yaml', 'policy.yml', 'json', ['--target', 'invalid']), 2);
  const preload = path.join(root, 'fault.cjs');
  fs.writeFileSync(preload, `const Module=require('node:module');const load=Module._load;Module._load=function(request,parent,isMain){const value=load.call(this,request,parent,isMain);if(request.includes('contract/contract-diff'))return {...value,diffSecurityContractsForCli(){throw new Error('synthetic internal');}};return value;};\n`);
  keepInput(preload, 'fault-preload');
  const fault = cliCommand('diff-exit-3', root, diffArgs('clean.yaml', 'policy.yml', 'text'), 3, { NODE_OPTIONS: `--require=${preload}` });
  need(fault.stderr.includes('CONTRACT_DIFF_INTERNAL') && !fault.stderr.includes('synthetic internal'), 'INTERNAL_DIAGNOSTIC');
  unchanged(openapi, before, 'CLEAN_OPENAPI_MUTATED'); unchanged(policy, inputs['clean-policy'], 'CLEAN_POLICY_MUTATED');
  unchanged(preload, inputs['fault-preload'], 'FAULT_PRELOAD_MUTATED');
}
function rich(root: string): void {
  const openapi = path.join(root, 'openapi.yaml');
  fs.copyFileSync(path.join(pkgExamples, 'openapi/openapi.yaml'), openapi);
  const before = keepInput(openapi, 'rich-openapi');
  cliCommand('rich-inspect-text', root, ['openapi', 'inspect', '--input', 'openapi.yaml', '--workspace-root', '.'], 0);
  cliCommand('rich-inspect-json', root, ['openapi', 'inspect', '--input', 'openapi.yaml', '--workspace-root', '.', '--json', '--out', 'inspection.json'], 0);
  const inspection = JSON.parse(keepOutput(path.join(root, 'inspection.json'), 'rich-inspection', root));
  need(inspection.summary.operationCount === 5, 'RICH_OPERATION_COUNT');
  const operations = inspection.contract.operations;
  const byRoute = (key: string) => operations.find((item: any) => item.routeKey === key);
  need(inspection.summary.exposures.public === 1 && inspection.summary.exposures.authenticated === 4
    && byRoute('GET /health')?.exposure === 'public'
    && byRoute('GET /users/{userId}')?.auth?.alternatives?.[0]?.schemes?.[0]?.kind === 'bearer'
    && byRoute('GET /users/{userId}')?.request?.queryParameters?.find((p: any) => p.name === 'limit')?.constraints?.maximum === 100
    && byRoute('GET /admin/reports')?.request?.requiredHeaders?.includes('x-tenant-id')
    && byRoute('POST /documents')?.request?.body?.constraints?.requiredProperties?.includes('title')
    && byRoute('POST /uploads')?.request?.contentTypes?.includes('multipart/form-data')
    && inspection.summary.resolvedDocumentCount === 1 && inspection.summary.referenceCount === 6,
  'RICH_SEMANTICS');
  const text = fs.readFileSync(openapi, 'utf8');
  for (const marker of ['/health:', 'bearerAuth:', 'X-Tenant-ID', 'maximum: 100', 'application/json', 'multipart/form-data', "$ref: '#/components/parameters/UserId'"]) need(text.includes(marker), 'RICH_FIXTURE');
  unchanged(openapi, before, 'RICH_INPUT_MUTATED');
  const policy = path.join(root, 'policy.yml');
  fs.writeFileSync(policy, 'version: 2\ndefaults: { mode: enforce }\nrequest:\n  allow_methods: [GET]\n  limits: { max_uri_length: 2048 }\n  block: { header_missing: [] }\nroutes: []\nresponse_headers: {}\n');
  keepInput(policy, 'rich-policy');
  cliCommand('rich-diff-json', root, [...diffArgs('openapi.yaml', 'policy.yml', 'json', ['--fail-on', 'never']), '--out', 'rich.json'], 0);
  cliCommand('rich-diff-sarif', root, [...diffArgs('openapi.yaml', 'policy.yml', 'sarif', ['--fail-on', 'never']), '--out', 'rich.sarif'], 0);
  cliCommand('rich-diff-summary', root, [...diffArgs('openapi.yaml', 'policy.yml', 'github-summary', ['--fail-on', 'error']), '--out', 'rich.md'], 1);
  const json = JSON.parse(keepOutput(path.join(root, 'rich.json'), 'rich-json', root));
  const sarif = JSON.parse(keepOutput(path.join(root, 'rich.sarif'), 'rich-sarif', root));
  const summary = keepOutput(path.join(root, 'rich.md'), 'rich-summary', root);
  need(json.summary.total === 12 && json.summary.error === 4 && json.summary.warning === 6 && json.summary.info === 2, 'RICH_COUNTS');
  const actual = json.findings.map((f: any) => [f.ruleId, f.severity,
    [f.route?.method, f.route?.path].filter(Boolean).join(' '),
    f.evidence.find((v: any) => v.source === 'openapi' && v.pointer.startsWith('/paths/'))?.pointer,
    f.evidence.find((v: any) => v.source === 'policy')?.pointer]);
  const expected = [
    ['SC-EXPOSURE-001', 'error', '/documents', '/paths/~1documents/post', '/request/allow_methods'],
    ['SC-EXPOSURE-001', 'error', '/uploads', '/paths/~1uploads/post', '/request/allow_methods'],
    ['SC-EXPOSURE-002', 'error', 'POST /documents', '/paths/~1documents/post', '/request/allow_methods'],
    ['SC-EXPOSURE-002', 'error', 'POST /uploads', '/paths/~1uploads/post', '/request/allow_methods'],
    ['SC-AUTHN-001', 'warning', 'GET /admin/reports', '/paths/~1admin~1reports/get', '/request'],
    ['SC-AUTHN-001', 'warning', 'GET /users/{userId}', '/paths/~1users~1{userId}/get', '/request'],
    ['SC-LIMIT-002', 'warning', 'GET /admin/reports', '/paths/~1admin~1reports/get', '/request/limits/max_uri_length'],
    ['SC-LIMIT-002', 'warning', 'GET /health', '/paths/~1health/get/security', '/request/limits/max_uri_length'],
    ['SC-LIMIT-002', 'warning', 'GET /users/{userId}', '/paths/~1users~1{userId}/get', '/request'],
    ['SC-LIMIT-002', 'warning', 'GET /users/{userId}', '/paths/~1users~1{userId}/get', '/request/limits/max_uri_length'],
    ['SC-REQUEST-001', 'info', 'GET /admin/reports', '/paths/~1admin~1reports/get', '/request/block/header_missing'],
    ['SC-REQUEST-001', 'info', 'GET /users/{userId}', '/paths/~1users~1{userId}/get', '/request/block/header_missing'],
  ];
  need(JSON.stringify(actual) === JSON.stringify(expected), 'RICH_FINDINGS');
  need(sarif.runs[0].results.length === 12 && summary.includes('2 additional findings are available'), 'SUMMARY_TRUNCATION');
  need(JSON.stringify(json.omittedComparisons) === JSON.stringify([
    'policy.auth.route_gates:partial', 'policy.request.content_type:unsupported',
    'policy.request.graphql_guard:warning-only', 'policy.request.header_limits:partial',
    'policy.response.csp_nonce:unsupported', 'policy.response.response_dlp:warning-only',
    'policy.routes.request.allow_methods:unsupported',
  ]), 'RICH_UNKNOWN');
  unchanged(openapi, before, 'RICH_OPENAPI_MUTATED'); unchanged(policy, inputs['rich-policy'], 'RICH_POLICY_MUTATED');
}
function boundary(name: string, expectedCode: string, edit: (root: string) => { openapi?: string; policy?: string; extra?: string[]; out?: string }, commandName = 'contract'): void {
  isolated(name, root => {
    const source = path.join(root, 'openapi.yaml'), policy = path.join(root, 'policy.yml');
    fs.copyFileSync(path.join(pkgExamples, 'github-actions/fixtures/openapi.yaml'), source);
    fs.copyFileSync(path.join(pkgExamples, 'github-actions/fixtures/policy.yml'), policy);
    const changed = edit(root); const target = changed.openapi || source; const pol = changed.policy || policy;
    const files = [source, policy, ...(changed.extra || []).map(f => path.join(root, f))].filter(fs.existsSync);
    const before = files.map(sha); const entries = fs.readdirSync(root).sort().join('|');
    files.forEach((file, i) => { inputs[`${name}/${path.basename(file)}`] = before[i]; });
    const args = commandName === 'openapi' ? ['openapi', 'inspect', '--input', path.relative(root, target), '--workspace-root', '.', ...(changed.out ? ['--json', '--out', changed.out] : [])]
      : diffArgs(path.relative(root, target), path.relative(root, pol), 'json', changed.out ? ['--out', changed.out, '--force'] : []);
    const result = cliCommand(`boundary-${name}`, root, args, commandName === 'openapi' ? 1 : 2);
    need(result.stderr.includes(expectedCode), `BOUNDARY_${name}_DIAGNOSTIC`);
    files.forEach((file, i) => unchanged(file, before[i], `BOUNDARY_${name}_MUTATION`));
    need(fs.readdirSync(root).sort().join('|') === entries, `BOUNDARY_${name}_TEMP`);
  });
}
function boundaries(): void {
  boundary('invalid-version', 'OPENAPI_UNSUPPORTED_VERSION', root => { fs.writeFileSync(path.join(root, 'openapi.yaml'), 'openapi: 2.0.0\ninfo: {title: Invalid, version: 1}\npaths: {}\n'); return {}; }, 'openapi');
  boundary('invalid-policy', 'CONTRACT_DIFF_POLICY_INVALID', root => { fs.writeFileSync(path.join(root, 'policy.yml'), 'version: 99\n'); return {}; });
  boundary('remote-ref', 'OPENAPI_REMOTE_REF_DISABLED', root => { fs.appendFileSync(path.join(root, 'openapi.yaml'), "components:\n  schemas:\n    Remote:\n      $ref: 'https://invalid.example/schema'\n"); return {}; }, 'openapi');
  boundary('local-escape', 'OPENAPI_REF_OUTSIDE_ROOT', root => { fs.appendFileSync(path.join(root, 'openapi.yaml'), "components:\n  schemas:\n    Escaped:\n      $ref: '../outside.yml'\n"); return {}; }, 'openapi');
  boundary('oversized', 'OPENAPI_DOCUMENT_TOO_LARGE', root => { fs.appendFileSync(path.join(root, 'openapi.yaml'), 'x-large: ' + 'a'.repeat(2 * 1024 * 1024) + '\n'); return {}; }, 'openapi');
  boundary('ref-count', 'OPENAPI_DOCUMENT_COUNT_LIMIT', root => {
    const refs: string[] = [], files: string[] = [];
    for (let i = 0; i < 33; i++) { const name = `ref-${i}.yaml`; files.push(name); fs.writeFileSync(path.join(root, name), 'node: { type: string }\n'); refs.push(`    R${i}: { $ref: '${name}#/node' }`); }
    fs.appendFileSync(path.join(root, 'openapi.yaml'), `components:\n  schemas:\n${refs.join('\n')}\n`);
    return { extra: files };
  }, 'openapi');
  boundary('output-collision', 'CONTRACT_DIFF_OUTPUT_PROTECTED', root => ({ out: 'openapi.yaml' }));
  boundary('output-symlink', 'CONTRACT_DIFF_OUTPUT_PROTECTED', root => { fs.symlinkSync('openapi.yaml', path.join(root, 'report.json')); return { out: 'report.json', extra: ['report.json'] }; });
  boundary('output-hardlink', 'CONTRACT_DIFF_OUTPUT_PROTECTED', root => { fs.linkSync(path.join(root, 'openapi.yaml'), path.join(root, 'report.json')); return { out: 'report.json', extra: ['report.json'] }; });
  boundary('output-existing', 'OPENAPI_OUTPUT_EXISTS', root => { fs.writeFileSync(path.join(root, 'report.json'), 'protected\n'); return { out: 'report.json', extra: ['report.json'] }; }, 'openapi');
  isolated('input-symlink', root => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-890-outside-'));
    try {
      const target = path.join(outside, 'openapi.yaml');
      fs.copyFileSync(path.join(pkgExamples, 'github-actions/fixtures/openapi.yaml'), target);
      const before = keepInput(target, 'input-symlink-target');
      fs.symlinkSync(target, path.join(root, 'alias.yaml'));
      const result = cliCommand('boundary-input-symlink', root, ['openapi', 'inspect', '--input', 'alias.yaml', '--workspace-root', '.'], 1);
      need(result.stderr.includes('OPENAPI_REF_OUTSIDE_ROOT'), 'INPUT_SYMLINK_DIAGNOSTIC');
      unchanged(target, before, 'INPUT_SYMLINK_MUTATED');
      need(fs.readdirSync(root).join('|') === 'alias.yaml', 'INPUT_SYMLINK_TEMP');
    } finally { fs.rmSync(outside, { recursive: true, force: true }); }
  });
}
function privacy(): void {
  for (const [label, prefix] of [['privacy', 'authorization'], ['privacy-key', 'x-api-key']]) isolated(label, root => {
    const spec = fs.readFileSync(path.join(pkgExamples, 'github-actions/fixtures/openapi.yaml'), 'utf8');
    const file = path.join(root, `${prefix}-SYNTHETIC_SECRET_890_VALUE.yaml`);
    fs.writeFileSync(file, spec.replace('    get:', '    post:').replace('description: OK', 'description: SYNTHETIC_SECRET_890_VALUE')
      + 'x-example: { Authorization: "Bearer SYNTHETIC_SECRET_890_VALUE", query: "query=SYNTHETIC_SECRET_890_VALUE", body: "SYNTHETIC_SECRET_890_VALUE" }\n');
    fs.copyFileSync(path.join(pkgExamples, 'github-actions/fixtures/policy.yml'), path.join(root, 'policy.yml'));
    const before = [keepInput(file, `${label}-openapi`), keepInput(path.join(root, 'policy.yml'), `${label}-policy`)];
    for (const format of ['text', 'json', 'sarif', 'github-summary']) {
      const result = cliCommand(`${label}-${format}`, root, diffArgs(path.basename(file), 'policy.yml', format, ['--fail-on', 'never']), 0);
      assertSafeOutput(result.stdout + result.stderr, root, `${label}-${format}`);
      const out = `${label}.${format === 'github-summary' ? 'md' : format}`;
      cliCommand(`${label}-file-${format}`, root, [...diffArgs(path.basename(file), 'policy.yml', format, ['--fail-on', 'never']), '--out', out], 0);
      keepOutput(path.join(root, out), `${label}-${format}`, root);
    }
    need(sha(file) === before[0] && sha(path.join(root, 'policy.yml')) === before[1], 'PRIVACY_MUTATION');
  });
}
export function runAcceptance(artifact: string, fixtureRoot: string): JourneyResult {
  const start = process.hrtime.bigint();
  const m = verifyTarball(artifact, expectedIdentity());
  consumer = path.join(artifact, 'consumer'); installed = fs.realpathSync(path.join(consumer, 'node_modules', packageName));
  const prefix = fs.realpathSync(consumer) + path.sep;
  need(installed.startsWith(prefix), 'PACKAGE_RESOLUTION');
  cli = fs.realpathSync(path.join(consumer, 'node_modules/.bin/cdn-security'));
  need(cli === path.join(installed, 'bin/cli.js'), 'BINARY_RESOLUTION');
  pkgExamples = fs.realpathSync(fixtureRoot);
  need(pkgExamples.startsWith(installed + path.sep) && pkgExamples === path.join(installed, 'examples'), 'FIXTURE_RESOLUTION');
  const pkg = JSON.parse(fs.readFileSync(path.join(installed, 'package.json'), 'utf8'));
  need(pkg.name === packageName && m.sha256 === sha(path.join(artifact, 'candidate.tgz')), 'CANDIDATE_IDENTITY');
  isolated('docs', docs);
  isolated('rich', rich);
  let parityFindings: JourneyResult['findings'] = [];
  isolated('parity', root => {
    const base = parity(root);
    parityFindings = base.report.findings.map((f: any) => ({ ruleId: f.ruleId, severity: f.severity,
      route: [f.route?.method, f.route?.path].filter(Boolean).join(' '),
      evidence: f.evidence.map((v: any) => `${v.uri}#${v.pointer}`), suppressed: false }));
    exceptions(root, base.report, base.openapi, base.policy);
  });
  isolated('exits', cleanAndExits);
  boundaries(); privacy();
  let deterministic = '';
  for (let n = 0; n < 2; n++) isolated(`determinism-${n}`, root => {
    const result = parity(root);
    const value = result.raw.json + result.raw.sarif;
    if (n === 0) deterministic = value; else need(value === deterministic, 'DETERMINISM');
  });
  need(steps.some(step => step.expectedExit === 0) && steps.some(step => step.expectedExit === 1)
    && steps.some(step => step.expectedExit === 2) && steps.some(step => step.expectedExit === 3), 'EXIT_COVERAGE');
  const onlinePreparationMs = Number(process.env.CSF_ONLINE_PREP_MS);
  need(Number.isFinite(onlinePreparationMs) && onlinePreparationMs >= 0, 'ONLINE_PREPARATION_MISSING');
  const offlineAcceptanceMs = Number(process.hrtime.bigint() - start) / 1e6;
  const installedRequire = createRequire(path.join(installed, 'package.json'));
  return { status: 'pass', checks: [...requiredChecks], steps, outputs, inputs,
    toolchain: { node: process.versions.node, npm: cp.execFileSync('npm', ['--version'], { encoding: 'utf8' }).trim(),
      typescript: installedRequire('typescript/package.json').version,
      ajv: installedRequire('ajv/package.json').version,
      purpose: 'Node/npm run installed package; TypeScript/Ajv are installed product dependencies used for type/schema validation; online preparation uses the producer lock' },
    onlinePreparationMs, offlineAcceptanceMs,
    findings: parityFindings,
  };
}
if (require.main === module) {
  try {
    const [artifact, fixture] = process.argv.slice(2);
    need(Boolean(artifact && fixture), 'ARGUMENTS');
    console.log(JSON.stringify(runAcceptance(path.resolve(artifact), path.resolve(fixture))));
  } catch {
    console.error('CSF_ONBOARDING_ACCEPTANCE_FAILED: a required journey check failed.');
    process.exitCode = 1;
  }
}
