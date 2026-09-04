#!/usr/bin/env node
'use strict';

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import childProcess from 'node:child_process';

import {
  createFinding,
  sortFindings,
  type FindingInputV1,
  type SecurityFindingV1,
} from '../contract';
import { hasUnsafeSensitiveText, SENSITIVE_KEY_PATTERN } from '../contract/sensitive-text';

type FileDigest = { path: string; sha256: string; size: number };
type GoldenInventory = { scenarios: string[]; files: FileDigest[] };
type AuditWorkspace = { root: string; openApiPath: string; policyPath: string };

const repoRoot = path.join(__dirname, '..');
const policyPath = path.join(repoRoot, 'policy', 'base.yml');
const openApiPath = path.join(repoRoot, 'examples', 'openapi', 'openapi.yaml');
const sourceExamplePath = path.join(repoRoot, 'examples', 'nestjs-contract', 'run-analysis.cjs');
const goldenRoot = path.join(repoRoot, 'tests', 'golden');
const reportRoot = path.join(repoRoot, 'reports');
const fixtureSecrets = {
  EDGE_ADMIN_TOKEN: 'determinism-token-not-for-deploy',
  ORIGIN_SECRET: 'determinism-origin-not-for-deploy',
  JWT_SECRET: 'determinism-jwt-not-for-deploy',
};

function parseArgs(argv: string[]): { output: string } {
  let output = 'reports/determinism-audit.json';
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--output') { output = argv[index + 1]; index += 1; continue; }
    if (argv[index] === '--help' || argv[index] === '-h') {
      console.log('Usage: node scripts/determinism-audit.js [--output <path>]');
      process.exit(0);
    }
    throw new Error(`Unknown flag: ${argv[index]}`);
  }
  return { output };
}

function fixtureEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { NODE_ENV: 'test', TZ: 'UTC', LANG: 'C', LC_ALL: 'C', NO_COLOR: '1' };
  for (const name of ['PATH', 'Path', 'SystemRoot', 'ComSpec', 'PATHEXT', 'TMPDIR', 'TMP', 'TEMP']) {
    if (process.env[name] !== undefined) env[name] = process.env[name];
  }
  return { ...env, ...fixtureSecrets };
}

function runNode(args: string[], env = fixtureEnv()): string {
  const result = childProcess.spawnSync(process.execPath, args, {
    cwd: repoRoot,
    env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 20 * 1024 * 1024,
  });
  if (result.error) throw new Error('audit subprocess could not start');
  if (result.status !== 0) {
    const errorCode = result.stderr.match(/\[ERROR\]\s+([A-Z][A-Z0-9_]+)/u)?.[1];
    throw new Error(`audit subprocess${errorCode ? ` (${errorCode})` : ''} failed with status ${result.status ?? 'unknown'}`);
  }
  return result.stdout;
}

function runCli(args: string[], env = fixtureEnv()): void {
  runNode([path.join(repoRoot, 'bin', 'cli.js'), ...args], env);
}

function sha256File(filePath: string): string {
  return `sha256:${crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex')}`;
}

function listFiles(root: string, current = root): string[] {
  return fs.readdirSync(current, { withFileTypes: true }).flatMap((entry) => {
    const filePath = path.join(current, entry.name);
    if (entry.isDirectory()) return listFiles(root, filePath);
    if (!entry.isFile()) throw new Error(`unsupported fixture entry: ${path.relative(root, filePath)}`);
    return [filePath];
  }).sort();
}

function digestTree(root: string): FileDigest[] {
  return listFiles(root).map((filePath) => ({
    path: path.relative(root, filePath).split(path.sep).join('/'),
    sha256: sha256File(filePath),
    size: fs.statSync(filePath).size,
  }));
}

function createAuditWorkspace(root: string, lineEnding: '\n' | '\r\n'): AuditWorkspace {
  fs.mkdirSync(root, { recursive: true });
  const writeFixture = (source: string, name: string): string => {
    const destination = path.join(root, name);
    const content = fs.readFileSync(source, 'utf8').replace(/\r\n|\r|\n/gu, lineEnding);
    fs.writeFileSync(destination, content);
    return destination;
  };
  return {
    root,
    openApiPath: writeFixture(openApiPath, 'openapi.yaml'),
    policyPath: writeFixture(policyPath, 'policy.yml'),
  };
}

const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/u;
const CODE_SECRET_LITERAL_PATTERN = /\b(?:authorization|cookie|set[-_]?cookie|api[-_]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|token|password|secret)\b["']?\s*[:=]\s*["'](?!\[REDACTED\])[^"'\r\n]+["']/iu;
const ABSOLUTE_PATH_PATTERN = /(?:^|[\s"'`(=])(?:[A-Za-z]:[\\/]|\\\\[^\\\s]+\\[^\\\s]+|\/(?:Users|home|Volumes|private|tmp|var\/folders|workspace|workspaces|mnt)\/)/u;
const RUNTIME_METADATA_KEY_PATTERN = /^(?:timestamp|generatedAt|createdAt|updatedAt|hostname)$/iu;
const allowedFixtureValues = [
  ...Object.values(fixtureSecrets),
  'ci-build-token-not-for-deploy',
  'ci-origin-secret-not-for-deploy',
];

function scrubFixtureValues(value: string): string {
  return allowedFixtureValues.reduce((result, fixture) => result.replaceAll(fixture, '[REDACTED]'), value);
}

function hasAbsolutePath(value: string, root: string): boolean {
  return value.includes(root) || ABSOLUTE_PATH_PATTERN.test(value);
}

function assertNoAbsoluteOrSecretText(
  values: string[],
  root: string,
  code = false,
  context = 'audit output',
): void {
  for (const value of values) {
    const scrubbed = scrubFixtureValues(value);
    if (hasAbsolutePath(scrubbed, root)) throw new Error(`${context} contains an absolute path`);
    if (JWT_PATTERN.test(scrubbed)
      || (code ? CODE_SECRET_LITERAL_PATTERN.test(scrubbed) : hasUnsafeSensitiveText(scrubbed))) {
      throw new Error(`${context} contains a secret-like value`);
    }
  }
}

function assertJsonValueSafe(value: unknown, root: string, context: string, key = ''): void {
  if (typeof value === 'string') {
    const scrubbed = scrubFixtureValues(value);
    if (hasAbsolutePath(scrubbed, root)) throw new Error(`${context} contains an absolute path`);
    if (JWT_PATTERN.test(scrubbed) || hasUnsafeSensitiveText(scrubbed)
      || (SENSITIVE_KEY_PATTERN.test(key) && scrubbed !== '[REDACTED]')) {
      throw new Error(`${context} contains a secret-like value`);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const child of value) assertJsonValueSafe(child, root, context);
    return;
  }
  if (value && typeof value === 'object') {
    for (const [childKey, child] of Object.entries(value)) {
      if (RUNTIME_METADATA_KEY_PATTERN.test(childKey)) {
        throw new Error(`${context} contains runtime metadata`);
      }
      assertJsonValueSafe(child, root, context, childKey);
    }
  }
}

function assertFilesSafe(files: string[], root: string): void {
  for (const file of files) {
    const content = fs.readFileSync(file, 'utf8');
    const context = `audit artifact ${path.relative(repoRoot, file)}`;
    if (path.extname(file) === '.json') {
      assertJsonValueSafe(JSON.parse(content), root, context);
      continue;
    }
    assertNoAbsoluteOrSecretText(
      [content],
      root,
      /\.[cm]?[jt]s$/u.test(file),
      context,
    );
  }
}

function assertTreeSafe(root: string): void {
  assertFilesSafe(listFiles(root), repoRoot);
}

function auditPrivacyGuard(): boolean {
  for (const unsafe of [
    '{"secret":"value"}',
    'secret: value',
    '/home/runner/work/repository',
    '/Volumes/build/repository',
    'C:\\Users\\runner\\repository',
  ]) {
    let rejected = false;
    try { assertNoAbsoluteOrSecretText([unsafe], repoRoot); } catch { rejected = true; }
    if (!rejected) throw new Error('audit privacy guard accepted an unsafe fixture');
  }
  assertNoAbsoluteOrSecretText(['{"secret":"[REDACTED]"}', '/health', 'https://example.com/docs'], repoRoot);
  return true;
}

function within(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

function writeAuditReport(output: string, content: string): void {
  const lexicalRoot = path.resolve(reportRoot);
  const lexicalOutput = path.resolve(repoRoot, output);
  if (!within(lexicalRoot, lexicalOutput) || path.dirname(lexicalOutput) !== lexicalRoot) {
    throw new Error('audit report output must be a file directly inside reports');
  }
  fs.mkdirSync(lexicalRoot, { recursive: true });
  const rootEntry = fs.lstatSync(lexicalRoot);
  const realRepoRoot = fs.realpathSync(repoRoot);
  const realRoot = fs.realpathSync(lexicalRoot);
  if (rootEntry.isSymbolicLink() || !rootEntry.isDirectory()
    || realRoot !== path.join(realRepoRoot, 'reports')) {
    throw new Error('audit report output escaped reports');
  }
  const noFollow = fs.constants.O_NOFOLLOW;
  if (noFollow === undefined) throw new Error('audit report output cannot be opened safely');
  const outputPath = path.join(realRoot, path.basename(lexicalOutput));
  let descriptor: number | undefined;
  try {
    descriptor = fs.openSync(
      outputPath,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | noFollow,
      0o666,
    );
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || opened.nlink > 1) throw new Error('unsafe report output');
    fs.ftruncateSync(descriptor, 0);
    fs.writeFileSync(descriptor, content, 'utf8');
  } catch {
    throw new Error('audit report output could not be written safely');
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function runPair(label: string, first: string, second: string, run: (outputPath: string, index: number) => void): boolean {
  run(first, 0);
  run(second, 1);
  const firstBytes = fs.readFileSync(first);
  const secondBytes = fs.readFileSync(second);
  if (!firstBytes.equals(secondBytes)) throw new Error(`${label} output is not byte-identical`);
  return true;
}

function withoutByteIdentity(value: unknown, parentKey = ''): unknown {
  if (Array.isArray(value)) {
    const items = value.map((child) => withoutByteIdentity(child));
    if (parentKey === 'findings' || parentKey === 'suppressedFindings' || parentKey === 'exceptionDiagnostics') {
      items.sort((left, right) => {
        const a = JSON.stringify(left);
        const b = JSON.stringify(right);
        return a < b ? -1 : a > b ? 1 : 0;
      });
    }
    return items;
  }
  if (!value || typeof value !== 'object') return value;
  const record = value as Record<string, unknown>;
  return Object.fromEntries(Object.entries(value).flatMap(([key, child]) => (
    key === 'sourceDigest' || key === 'instanceId' || key === 'totalByteSize'
      || (key === 'digest' && record.source === 'openapi')
      ? [] : [[key, withoutByteIdentity(child, key)]]
  )));
}

function assertSemanticJsonEqual(label: string, first: string, second: string): void {
  const left = withoutByteIdentity(JSON.parse(fs.readFileSync(first, 'utf8')));
  const right = withoutByteIdentity(JSON.parse(fs.readFileSync(second, 'utf8')));
  if (JSON.stringify(left) !== JSON.stringify(right)) throw new Error(`${label} semantic output drifted`);
}

function runBuild(inputPolicyPath: string, outputRoot: string, env: NodeJS.ProcessEnv): FileDigest[] {
  runNode([path.join(repoRoot, 'scripts', 'compile.js'), '--policy', inputPolicyPath, '--out-dir', outputRoot], env);
  runNode([path.join(repoRoot, 'scripts', 'compile-cloudflare.js'), '--policy', inputPolicyPath, '--out-dir', outputRoot], env);
  runNode([path.join(repoRoot, 'scripts', 'compile-infra.js'), '--policy', inputPolicyPath, '--out-dir', outputRoot], env);
  runNode([path.join(repoRoot, 'scripts', 'compile-cloudflare-waf.js'), '--policy', inputPolicyPath, '--out-dir', outputRoot], env);
  return digestTree(outputRoot);
}

function auditGoldenInventory(): GoldenInventory {
  const files = digestTree(goldenRoot);
  const scenarios = fs.readdirSync(goldenRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  if (scenarios.length !== 3 || !scenarios.includes('base') || !scenarios.includes('profiles') || !scenarios.includes('archetypes')) {
    throw new Error(`unexpected golden scenario roots: ${scenarios.join(', ')}`);
  }
  if (files.length === 0 || files.some((file) => path.isAbsolute(file.path))) throw new Error('golden inventory is empty or absolute');
  for (const file of files) {
    const filePath = path.join(goldenRoot, file.path);
    const content = fs.readFileSync(filePath, 'utf8');
    if (path.extname(filePath) === '.json') {
      assertJsonValueSafe(JSON.parse(content), repoRoot, `golden fixture ${file.path}`);
      continue;
    }
    assertNoAbsoluteOrSecretText(
      [content],
      repoRoot,
      /\.[cm]?[jt]s$/u.test(filePath),
      `golden fixture ${file.path}`,
    );
  }
  return { scenarios, files };
}

function auditFindingIdentity(): boolean {
  const evidence = [
    { source: 'openapi', uri: 'examples/openapi/openapi.yaml', digest: 'sha256:openapi', analyzer: 'openapi@1', capability: 'routes', complete: true },
    { source: 'policy', uri: 'policy/base.yml', digest: 'sha256:policy', analyzer: 'policy@1', capability: 'routes', complete: true },
  ] as const;
  const base: FindingInputV1 = {
    ruleId: 'SC-INVENTORY-001', severity: 'error', confidence: 'deterministic', category: 'inventory',
    title: 'Route mismatch', message: 'first message', route: { method: 'GET', path: '/users/{id}' }, evidence: [...evidence],
  };
  const reordered = createFinding({
    ...base,
    message: 'second message',
    route: { path: '/users/{id}', method: 'get' },
    evidence: [...evidence].reverse(),
  });
  const first = createFinding(base);
  if (first.instanceId !== reordered.instanceId) throw new Error('finding instance ID depends on message or evidence order');
  for (let iteration = 0; iteration < 100; iteration += 1) {
    const repeated = createFinding({
      ...base,
      message: `message ${iteration}`,
      evidence: iteration % 2 === 0 ? [...evidence] : [...evidence].reverse(),
    });
    if (first.instanceId !== repeated.instanceId) throw new Error('finding instance ID drifted across repeated inputs');
  }
  const windowsEvidence = evidence.map((item) => ({ ...item, uri: item.uri.replaceAll('/', '\\') }));
  if (first.instanceId !== createFinding({ ...base, evidence: windowsEvidence }).instanceId) {
    throw new Error('finding instance ID depends on path separator');
  }
  const changedRoute = createFinding({ ...base, route: { method: 'GET', path: '/admins/{id}' } });
  if (first.instanceId === changedRoute.instanceId) throw new Error('finding instance ID ignores route identity');
  const changedEvidence = createFinding({ ...base, evidence: [{ ...evidence[0], digest: 'sha256:other' }, evidence[1]] });
  if (first.instanceId === changedEvidence.instanceId) throw new Error('finding instance ID ignores evidence identity');
  const sorted = sortFindings([changedEvidence, first, changedRoute]);
  if (JSON.stringify(sorted.map(({ instanceId }) => instanceId)) !== JSON.stringify(sortFindings([changedRoute, changedEvidence, first]).map(({ instanceId }) => instanceId))) {
    throw new Error('finding ordering depends on input order');
  }
  return true;
}

type ReportEvidence = Pick<FindingInputV1['evidence'][number], 'uri' | 'pointer' | 'source' | 'digest' | 'analyzer' | 'capability' | 'complete'>;
type ReportFinding = SecurityFindingV1;
type SarifLocation = {
  physicalLocation: {
    artifactLocation: { uri: string };
    region?: { startLine: number; startColumn?: number };
    properties: Omit<ReportEvidence, 'uri' | 'pointer'>;
  };
  logicalLocations?: Array<{ fullyQualifiedName: string }>;
};
type SarifResult = {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  partialFingerprints?: { 'securityContractFinding/v1'?: string };
  locations?: SarifLocation[];
  relatedLocations?: SarifLocation[];
  suppressions?: Array<{ kind: 'external'; status: 'accepted' }>;
};

function evidenceFingerprint(evidence: ReportEvidence): string {
  return JSON.stringify([
    evidence.uri,
    evidence.pointer ?? '',
    evidence.source,
    evidence.digest,
    evidence.analyzer,
    evidence.capability,
    evidence.complete,
  ]);
}

function findingFingerprint(finding: ReportFinding, suppressed = false): string {
  return JSON.stringify({
    ruleId: finding.ruleId,
    instanceId: finding.instanceId,
    severity: finding.severity,
    suppressed,
    evidence: finding.evidence.map(evidenceFingerprint).sort(),
  });
}

function sarifLocationEvidence(location: SarifLocation): ReportEvidence {
  const region = location.physicalLocation.region;
  const pointer = location.logicalLocations?.[0]?.fullyQualifiedName
    ?? (region ? `line:${region.startLine}:column:${region.startColumn ?? 1}` : undefined);
  return {
    uri: location.physicalLocation.artifactLocation.uri,
    ...(pointer ? { pointer } : {}),
    ...location.physicalLocation.properties,
  };
}

function sarifFindingFingerprint(result: SarifResult): string {
  const instanceId = result.partialFingerprints?.['securityContractFinding/v1'];
  if (!instanceId) throw new Error(`SARIF result ${result.ruleId} is missing finding identity`);
  const severity = result.level === 'note' ? 'info' : result.level;
  const suppressed = result.suppressions !== undefined;
  if (suppressed && (result.suppressions?.length !== 1
    || result.suppressions[0]?.kind !== 'external' || result.suppressions[0]?.status !== 'accepted')) {
    throw new Error(`SARIF result ${result.ruleId} has invalid suppression metadata`);
  }
  const locations = [...(result.locations ?? []), ...(result.relatedLocations ?? [])];
  return JSON.stringify({
    ruleId: result.ruleId,
    instanceId,
    severity,
    suppressed,
    evidence: locations.map(sarifLocationEvidence).map(evidenceFingerprint).sort(),
  });
}

function summaryCell(value: string): string {
  const normalized = value.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}|`]/gu, ' ').replace(/\s+/gu, ' ').trim();
  return normalized.length > 120 ? `${normalized.slice(0, 117)}...` : normalized;
}

function summaryRoute(finding: SecurityFindingV1): string {
  const method = summaryCell(finding.route?.method ?? '');
  const routePath = summaryCell((finding.route?.path ?? '').split(/[?#]/u, 1)[0]);
  return method || routePath ? `\`${[method, routePath].filter(Boolean).join(' ')}\`` : '-';
}

function summaryRow(finding: SecurityFindingV1): string {
  return `| ${finding.severity} | ${summaryCell(finding.ruleId)} | ${summaryRoute(finding)} | ${summaryCell(finding.title)} |`;
}

function topSummaryRows(summary: string): string[] {
  const marker = '## Top findings';
  const start = summary.indexOf(marker);
  if (start < 0) throw new Error('GitHub summary is missing the Top findings section');
  const section = summary.slice(start + marker.length);
  const rows = [...section.matchAll(/^\| ([^|]*) \| ([^|]*) \| ([^|]*) \| ([^|]*) \|$/gmu)]
    .map(([row]) => row);
  return rows.slice(2);
}

function auditReportConsistency(
  workspaces: [AuditWorkspace, AuditWorkspace],
  lineEndingWorkspace: AuditWorkspace,
): boolean {
  const baselinePath = path.join(workspaces[0].root, 'contract-baseline.json');
  const runBaseline = (workspace: AuditWorkspace, outputPath: string): void => runCli([
    'contract', 'diff', '--openapi', workspace.openApiPath, '--policy', workspace.policyPath,
    '--target', 'aws', '--workspace-root', workspace.root, '--fail-on', 'never',
    '--format', 'json', '--out', outputPath,
  ]);
  runBaseline(workspaces[0], baselinePath);
  const lineEndingBaselinePath = path.join(lineEndingWorkspace.root, 'contract-baseline.json');
  runBaseline(lineEndingWorkspace, lineEndingBaselinePath);
  assertSemanticJsonEqual('contract line ending', baselinePath, lineEndingBaselinePath);
  const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8')) as { findings: ReportFinding[] };
  if (baseline.findings.length < 2) throw new Error('contract fixture needs two findings for exception audit');
  const exceptionSet = {
    version: 1,
    exceptions: [
      {
        id: 'EXC-2099-DETERMINISM_LIVE', rule_id: baseline.findings[0].ruleId,
        selector: { instance_id: baseline.findings[0].instanceId },
        reason: 'Approved release audit fixture', owner: 'release-audit', expires_at: '2099-12-31',
      },
      {
        id: 'EXC-2025-DETERMINISM_EXPIRED', rule_id: baseline.findings[1].ruleId,
        selector: { instance_id: baseline.findings[1].instanceId },
        reason: 'Expired release audit fixture', owner: 'release-audit', expires_at: '2025-12-31',
      },
    ],
  };
  const exceptionPaths = workspaces.map((workspace) => path.join(workspace.root, 'exceptions.json'));
  for (const exceptionPath of exceptionPaths) {
    fs.writeFileSync(exceptionPath, `${JSON.stringify(exceptionSet, null, 2)}\n`);
  }
  const contractArgs = (index: number): string[] => [
    'contract', 'diff', '--openapi', workspaces[index].openApiPath, '--policy', workspaces[index].policyPath,
    '--target', 'aws', '--workspace-root', workspaces[index].root, '--exceptions', exceptionPaths[index],
    '--current-date', '2026-01-01', '--include-suppressed', '--fail-on', 'never',
  ];
  const jsonPaths = workspaces.map((workspace) => path.join(workspace.root, 'contract-json.json'));
  const sarifPaths = workspaces.map((workspace) => path.join(workspace.root, 'contract-sarif.json'));
  const summaryPaths = workspaces.map((workspace) => path.join(workspace.root, 'contract-summary.md'));
  const repeatedJson = runPair('contract JSON', jsonPaths[0], jsonPaths[1], (outputPath, index) => (
    runCli([...contractArgs(index), '--format', 'json', '--out', outputPath])
  ));
  const repeatedSarif = runPair('contract SARIF', sarifPaths[0], sarifPaths[1], (outputPath, index) => (
    runCli([...contractArgs(index), '--format', 'sarif', '--out', outputPath])
  ));
  const repeatedSummary = runPair('contract summary', summaryPaths[0], summaryPaths[1], (outputPath, index) => (
    runCli([...contractArgs(index), '--format', 'github-summary', '--out', outputPath])
  ));
  const json = JSON.parse(fs.readFileSync(jsonPaths[0], 'utf8')) as {
    findings: ReportFinding[];
    suppressedFindings: ReportFinding[];
    exceptionDiagnostics: ReportFinding[];
    summary: { error: number; warning: number; info: number; suppressed: number };
  };
  if (json.suppressedFindings.length !== 1
    || json.exceptionDiagnostics.filter(({ ruleId }) => ruleId === 'SC-GOV-001').length !== 1) {
    throw new Error('contract fixture did not exercise live and expired exceptions');
  }
  const sarif = JSON.parse(fs.readFileSync(sarifPaths[0], 'utf8')) as { runs: Array<{ results: SarifResult[] }> };
  const jsonFindings = [
    ...json.findings.map((finding) => findingFingerprint(finding)),
    ...json.exceptionDiagnostics.map((finding) => findingFingerprint(finding)),
    ...json.suppressedFindings.map((finding) => findingFingerprint(finding, true)),
  ].sort();
  const sarifFindings = sarif.runs[0].results.map(sarifFindingFingerprint).sort();
  if (JSON.stringify(jsonFindings) !== JSON.stringify(sarifFindings)) {
    throw new Error('JSON/SARIF finding identity, evidence, or suppression drifted');
  }
  const summary = fs.readFileSync(summaryPaths[0], 'utf8');
  const summaryFindings = sortFindings([...json.findings, ...json.exceptionDiagnostics]);
  const expectedSummaryRows = summaryFindings.slice(0, 10).map(summaryRow);
  if (JSON.stringify(topSummaryRows(summary)) !== JSON.stringify(expectedSummaryRows)) {
    throw new Error('GitHub summary top findings identity, order, or severity drifted');
  }
  const expectedCountRow = `| ${json.summary.error} | ${json.summary.warning} | ${json.summary.info} | ${json.summary.suppressed} | 1 |`;
  if (!summary.includes(expectedCountRow)) throw new Error('GitHub summary suppression or expiry count drifted');
  assertFilesSafe([
    baselinePath, lineEndingBaselinePath, ...exceptionPaths, ...jsonPaths, ...sarifPaths, ...summaryPaths,
  ], repoRoot);
  return repeatedJson && repeatedSarif && repeatedSummary;
}

function main(): void {
  const { output } = parseArgs(process.argv.slice(2));
  for (const required of [policyPath, openApiPath, sourceExamplePath, goldenRoot]) {
    if (!fs.existsSync(required)) throw new Error(`audit input is missing: ${path.relative(repoRoot, required)}`);
  }
  const tempRoot = fs.mkdtempSync(path.join(repoRoot, '.determinism-audit-'));
  try {
    const env = fixtureEnv();
    const workspaces: [AuditWorkspace, AuditWorkspace] = [
      createAuditWorkspace(path.join(tempRoot, 'workspace-a'), '\n'),
      createAuditWorkspace(path.join(tempRoot, 'workspace-b'), '\n'),
    ];
    const lineEndingWorkspace = createAuditWorkspace(path.join(tempRoot, 'workspace-crlf'), '\r\n');
    const golden = auditGoldenInventory();
    const inspectPaths = workspaces.map((workspace) => path.join(workspace.root, 'openapi-inspect.json'));
    const openApiInspect = runPair('OpenAPI inspection', inspectPaths[0], inspectPaths[1], (outputPath, index) => runCli([
      'openapi', 'inspect', '--input', workspaces[index].openApiPath, '--workspace-root', workspaces[index].root,
      '--json', '--out', outputPath,
    ], env));
    const lineEndingInspectPath = path.join(lineEndingWorkspace.root, 'openapi-inspect.json');
    runCli([
      'openapi', 'inspect', '--input', lineEndingWorkspace.openApiPath, '--workspace-root', lineEndingWorkspace.root,
      '--json', '--out', lineEndingInspectPath,
    ], env);
    assertSemanticJsonEqual('OpenAPI line ending', inspectPaths[0], lineEndingInspectPath);
    const candidatePaths = workspaces.map((workspace) => path.join(workspace.root, 'openapi-candidate.yml'));
    const candidate = runPair('OpenAPI candidate', candidatePaths[0], candidatePaths[1], (outputPath, index) => runCli([
      'openapi', 'generate-policy', '--input', workspaces[index].openApiPath, '--workspace-root', workspaces[index].root,
      '--profile', 'balanced', '--out', outputPath,
    ], env));
    const lineEndingCandidatePath = path.join(lineEndingWorkspace.root, 'openapi-candidate.yml');
    runCli([
      'openapi', 'generate-policy', '--input', lineEndingWorkspace.openApiPath,
      '--workspace-root', lineEndingWorkspace.root, '--profile', 'balanced', '--out', lineEndingCandidatePath,
    ], env);
    if (!fs.readFileSync(candidatePaths[0]).equals(fs.readFileSync(lineEndingCandidatePath))) {
      throw new Error('OpenAPI candidate depends on input line ending');
    }
    const candidateMetaA = path.join(workspaces[0].root, 'openapi-candidate.meta.json');
    const candidateMetaB = path.join(workspaces[1].root, 'openapi-candidate.meta.json');
    if (!fs.readFileSync(candidateMetaA).equals(fs.readFileSync(candidateMetaB))) {
      throw new Error('openapi candidate metadata is not byte-identical');
    }
    const lineEndingCandidateMeta = path.join(lineEndingWorkspace.root, 'openapi-candidate.meta.json');
    assertSemanticJsonEqual('OpenAPI candidate metadata line ending', candidateMetaA, lineEndingCandidateMeta);
    assertFilesSafe([
      ...inspectPaths, lineEndingInspectPath, ...candidatePaths, lineEndingCandidatePath,
      candidateMetaA, candidateMetaB, lineEndingCandidateMeta,
    ], repoRoot);
    const sourceFirst = runNode([sourceExamplePath], env);
    const sourceSecond = runNode([sourceExamplePath], env);
    if (sourceFirst !== sourceSecond) throw new Error('source example output is not byte-identical');
    assertNoAbsoluteOrSecretText([sourceFirst], repoRoot);
    const buildRoots = workspaces.map((workspace) => path.join(workspace.root, 'build'));
    const buildA = runBuild(workspaces[0].policyPath, buildRoots[0], env);
    const buildB = runBuild(workspaces[1].policyPath, buildRoots[1], env);
    if (JSON.stringify(buildA) !== JSON.stringify(buildB)) throw new Error('generated artifact digest drifted between runs');
    const lineEndingBuildRoot = path.join(lineEndingWorkspace.root, 'build');
    const lineEndingBuild = runBuild(lineEndingWorkspace.policyPath, lineEndingBuildRoot, env);
    if (JSON.stringify(buildA) !== JSON.stringify(lineEndingBuild)) {
      throw new Error('generated artifact depends on input line ending');
    }
    assertTreeSafe(buildRoots[0]);
    assertTreeSafe(buildRoots[1]);
    assertTreeSafe(lineEndingBuildRoot);
    const reporters = auditReportConsistency(workspaces, lineEndingWorkspace);
    const report = {
      schemaVersion: 1,
      status: 'pass',
      golden: { scenarioRoots: golden.scenarios, fileCount: golden.files.length },
      repeatedRuns: {
        openApiInspect,
        openApiCandidate: candidate,
        sourceExample: true,
        generatedArtifacts: true,
        jsonSarifSummary: reporters,
        workspaceRootsAndLineEndings: true,
      },
      findingIdentity: auditFindingIdentity(),
      privacyGuard: auditPrivacyGuard(),
      artifactDigests: buildA.reduce<Record<string, string>>((result, file) => {
        result[file.path] = file.sha256;
        return result;
      }, {}),
    };
    const reportText = `${JSON.stringify(report, null, 2)}\n`;
    assertJsonValueSafe(report, repoRoot, 'audit report');
    writeAuditReport(output, reportText);
    console.log(`[determinism-audit] PASS: ${golden.files.length} golden files`);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  const safeMessage = hasAbsolutePath(message, repoRoot) || hasUnsafeSensitiveText(message)
    ? 'audit failed without a safe diagnostic'
    : message;
  console.error('[determinism-audit] FAIL:', safeMessage);
  process.exitCode = 1;
}
