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

type FileDigest = { path: string; sha256: string; size: number };
type GoldenInventory = { scenarios: string[]; files: FileDigest[] };

const repoRoot = path.join(__dirname, '..');
const policyPath = path.join(repoRoot, 'policy', 'base.yml');
const openApiPath = path.join(repoRoot, 'examples', 'openapi', 'openapi.yaml');
const sourceExamplePath = path.join(repoRoot, 'examples', 'nestjs-contract', 'run-analysis.cjs');
const goldenRoot = path.join(repoRoot, 'tests', 'golden');

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
  return {
    ...process.env,
    EDGE_ADMIN_TOKEN: process.env.EDGE_ADMIN_TOKEN || 'determinism-token-not-for-deploy',
    ORIGIN_SECRET: process.env.ORIGIN_SECRET || 'determinism-origin-not-for-deploy',
    JWT_SECRET: process.env.JWT_SECRET || 'determinism-jwt-not-for-deploy',
  };
}

function runNode(args: string[], env = fixtureEnv()): string {
  const result = childProcess.spawnSync(process.execPath, args, {
    cwd: repoRoot,
    env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 20 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`command failed (${args.map((arg) => path.basename(arg)).join(' ')}): ${result.stderr.trim() || `exit ${result.status}`}`);
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

function runTwice(label: string, run: (outputPath: string) => void, root: string, suffix = ''): boolean {
  const first = path.join(root, `${label}-a${suffix}`);
  const second = path.join(root, `${label}-b${suffix}`);
  run(first);
  run(second);
  const firstBytes = fs.readFileSync(first);
  const secondBytes = fs.readFileSync(second);
  if (!firstBytes.equals(secondBytes)) throw new Error(`${label} output is not byte-identical`);
  return true;
}

function runBuild(outputRoot: string, env: NodeJS.ProcessEnv): FileDigest[] {
  runNode([path.join(repoRoot, 'scripts', 'compile.js'), '--policy', policyPath, '--out-dir', outputRoot], env);
  runNode([path.join(repoRoot, 'scripts', 'compile-cloudflare.js'), '--policy', policyPath, '--out-dir', outputRoot], env);
  runNode([path.join(repoRoot, 'scripts', 'compile-infra.js'), '--policy', policyPath, '--out-dir', outputRoot], env);
  runNode([path.join(repoRoot, 'scripts', 'compile-cloudflare-waf.js'), '--policy', policyPath, '--out-dir', outputRoot], env);
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
  const sensitive = /(?:-----BEGIN|AKIA[0-9A-Z]{16}|Bearer\s+[A-Za-z0-9._~+/=-]{16,}|(?:password|api[_-]?key|authorization|cookie|secret)\s*[:=]\s*["'](?!ci-(?:build|origin)-)[^"']+)/iu;
  for (const file of files) {
    const content = fs.readFileSync(path.join(goldenRoot, file.path), 'utf8');
    if (content.includes(repoRoot) || content.includes('/Users/') || content.includes('/tmp/')) {
      throw new Error(`golden file contains an absolute path: ${file.path}`);
    }
    if (sensitive.test(content)) throw new Error(`golden file contains a secret-like literal: ${file.path}`);
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

function assertNoAbsoluteOrSecretText(values: string[], root: string): void {
  const sensitive = /(?:Bearer\s+[A-Za-z0-9._~+/=-]{16,}|AKIA[0-9A-Z]{16}|-----BEGIN|(?:password|api[_-]?key|authorization|cookie|secret)\s*[:=]\s*["'](?!\[REDACTED\]|ci-)[^"']+)/iu;
  for (const value of values) {
    if (value.includes(root) || value.includes('/Users/') || value.includes('/tmp/')) throw new Error('audit report contains an absolute path');
    if (sensitive.test(value)) throw new Error('audit report contains a secret-like value');
  }
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

function findingFingerprint(finding: ReportFinding): string {
  return JSON.stringify({
    ruleId: finding.ruleId,
    instanceId: finding.instanceId,
    severity: finding.severity,
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
  const locations = [...(result.locations ?? []), ...(result.relatedLocations ?? [])];
  return JSON.stringify({
    ruleId: result.ruleId,
    instanceId,
    severity,
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

function auditReportConsistency(root: string): boolean {
  fs.mkdirSync(root, { recursive: true });
  const jsonPath = path.join(root, 'contract-json.json');
  const sarifPath = path.join(root, 'contract-sarif.json');
  const summaryPath = path.join(root, 'contract-summary.md');
  const contractArgs = [
    'contract', 'diff', '--openapi', openApiPath, '--policy', policyPath,
    '--target', 'aws', '--workspace-root', repoRoot, '--fail-on', 'never',
  ];
  runCli([...contractArgs, '--format', 'json', '--out', jsonPath]);
  runCli([...contractArgs, '--format', 'sarif', '--out', sarifPath]);
  runCli([...contractArgs, '--format', 'github-summary', '--out', summaryPath]);
  const json = JSON.parse(fs.readFileSync(jsonPath, 'utf8')) as {
    findings: ReportFinding[];
    suppressedFindings: ReportFinding[];
    exceptionDiagnostics: ReportFinding[];
  };
  const sarif = JSON.parse(fs.readFileSync(sarifPath, 'utf8')) as { runs: Array<{ results: SarifResult[] }> };
  const jsonFindings = [
    ...json.findings,
    ...json.exceptionDiagnostics,
    ...json.suppressedFindings,
  ].map(findingFingerprint).sort();
  const sarifFindings = sarif.runs[0].results.map(sarifFindingFingerprint).sort();
  if (JSON.stringify(jsonFindings) !== JSON.stringify(sarifFindings)) throw new Error('JSON/SARIF finding identity or evidence drifted');
  const summary = fs.readFileSync(summaryPath, 'utf8');
  const summaryFindings = sortFindings([
    ...json.findings,
    ...json.exceptionDiagnostics,
  ]);
  const expectedSummaryRows = summaryFindings.slice(0, 10).map(summaryRow);
  if (JSON.stringify(topSummaryRows(summary)) !== JSON.stringify(expectedSummaryRows)) {
    throw new Error('GitHub summary top findings identity, order, or severity drifted');
  }
  const repeatedJson = runTwice('contract-json-repeat', (outputPath) => runCli([...contractArgs, '--format', 'json', '--out', outputPath]), root, '.json');
  const repeatedSarif = runTwice('contract-sarif-repeat', (outputPath) => runCli([...contractArgs, '--format', 'sarif', '--out', outputPath]), root, '.json');
  const repeatedSummary = runTwice('contract-summary-repeat', (outputPath) => runCli([...contractArgs, '--format', 'github-summary', '--out', outputPath]), root, '.md');
  assertNoAbsoluteOrSecretText([
    fs.readFileSync(jsonPath, 'utf8'), fs.readFileSync(sarifPath, 'utf8'), summary,
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
    const golden = auditGoldenInventory();
    const openApiInspect = runTwice('openapi-inspect', (outputPath) => runCli([
      'openapi', 'inspect', '--input', openApiPath, '--workspace-root', repoRoot,
      '--json', '--out', outputPath,
    ]), tempRoot);
    const candidate = runTwice('openapi-candidate', (outputPath) => runCli([
      'openapi', 'generate-policy', '--input', openApiPath, '--workspace-root', repoRoot,
      '--profile', 'balanced', '--out', outputPath,
    ]), tempRoot, '.yml');
    const candidateMetaA = path.join(tempRoot, 'openapi-candidate-a.meta.json');
    const candidateMetaB = path.join(tempRoot, 'openapi-candidate-b.meta.json');
    if (!fs.readFileSync(candidateMetaA).equals(fs.readFileSync(candidateMetaB))) {
      throw new Error('openapi candidate metadata is not byte-identical');
    }
    const sourceFirst = runNode([sourceExamplePath], env);
    const sourceSecond = runNode([sourceExamplePath], env);
    if (sourceFirst !== sourceSecond) throw new Error('source example output is not byte-identical');
    assertNoAbsoluteOrSecretText([sourceFirst], repoRoot);
    const buildA = runBuild(path.join(tempRoot, 'build-a'), env);
    const buildB = runBuild(path.join(tempRoot, 'build-b'), env);
    if (JSON.stringify(buildA) !== JSON.stringify(buildB)) throw new Error('generated artifact digest drifted between runs');
    const reporters = auditReportConsistency(path.join(tempRoot, 'reports'));
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
      },
      findingIdentity: auditFindingIdentity(),
      artifactDigests: buildA.reduce<Record<string, string>>((result, file) => {
        result[file.path] = file.sha256;
        return result;
      }, {}),
    };
    const outputPath = path.resolve(repoRoot, output);
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`);
    console.log(`[determinism-audit] PASS: ${golden.files.length} golden files`);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error: unknown) {
  console.error('[determinism-audit] FAIL:', error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
