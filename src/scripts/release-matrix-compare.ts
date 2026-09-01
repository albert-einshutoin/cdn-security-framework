#!/usr/bin/env node
'use strict';

import fs from 'node:fs';
import path from 'node:path';

type ArtifactTree = { aggregateSha256: string; files: Array<{ path: string; sha256: string; size: number }> };
type MatrixReport = {
  schemaVersion: number;
  nodeVersion: string;
  packageVersion: string;
  checks: Record<string, boolean>;
  apiExports: Record<string, string[]>;
  schemaDigests: Record<string, string>;
  artifacts: { aws: ArtifactTree; cloudflare: ArtifactTree };
};

type ComparisonReport = {
  schemaVersion: 1;
  status: 'pass';
  packageVersion: string;
  nodeVersions: string[];
  checks: { apiExports: true; schemas: true; artifacts: true; examples: true };
  artifactDigests: { aws: string; cloudflare: string };
};

function parseArgs(argv: string[]): { input: string; output: string } {
  let input = 'reports/release-matrix';
  let output = 'reports/release-matrix-summary.json';
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--input') { input = argv[index + 1]; index += 1; continue; }
    if (argv[index] === '--output') { output = argv[index + 1]; index += 1; continue; }
    if (argv[index] === '--help' || argv[index] === '-h') {
      console.log('Usage: node scripts/release-matrix-compare.js [--input <dir>] [--output <path>]');
      process.exit(0);
    }
    throw new Error(`Unknown flag: ${argv[index]}`);
  }
  return { input, output };
}

function readReports(input: string): MatrixReport[] {
  const inputPath = path.resolve(process.cwd(), input);
  if (!fs.existsSync(inputPath) || !fs.statSync(inputPath).isDirectory()) throw new Error(`matrix report directory is missing: ${input}`);
  const reports = fs.readdirSync(inputPath).filter((file) => file.endsWith('.json')).sort().map((file) => {
    return JSON.parse(fs.readFileSync(path.join(inputPath, file), 'utf8')) as MatrixReport;
  });
  if (reports.length !== 3) throw new Error(`expected 3 Node matrix reports, found ${reports.length}`);
  return reports;
}

function sameJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function main(): void {
  const { input, output } = parseArgs(process.argv.slice(2));
  const reports = readReports(input);
  const first = reports[0];
  if (reports.some((report) => report.schemaVersion !== 1)) throw new Error('matrix report schema version drifted');
  const nodeMajors = reports.map((report) => Number.parseInt(report.nodeVersion.split('.')[0], 10)).sort((a, b) => a - b);
  if (!sameJson(nodeMajors, [20, 22, 24])) throw new Error(`unexpected Node matrix: ${nodeMajors.join(', ')}`);
  if (reports.some((report) => report.packageVersion !== first.packageVersion)) throw new Error('package version differs across Node matrix');
  if (reports.some((report) => Object.values(report.checks).some((value) => value !== true))) throw new Error('a matrix example/check did not pass');
  if (reports.some((report) => !sameJson(report.apiExports, first.apiExports))) throw new Error('API exports differ across Node matrix');
  if (reports.some((report) => !sameJson(report.schemaDigests, first.schemaDigests))) throw new Error('schema digests differ across Node matrix');
  if (reports.some((report) => report.artifacts.aws.aggregateSha256 !== first.artifacts.aws.aggregateSha256
    || report.artifacts.cloudflare.aggregateSha256 !== first.artifacts.cloudflare.aggregateSha256)) {
    throw new Error('generated artifact digests differ across Node matrix');
  }
  const result: ComparisonReport = {
    schemaVersion: 1,
    status: 'pass',
    packageVersion: first.packageVersion,
    nodeVersions: reports.map((report) => report.nodeVersion),
    checks: { apiExports: true, schemas: true, artifacts: true, examples: true },
    artifactDigests: {
      aws: first.artifacts.aws.aggregateSha256,
      cloudflare: first.artifacts.cloudflare.aggregateSha256,
    },
  };
  const outputPath = path.resolve(process.cwd(), output);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`);
  console.log(`[release-matrix] PASS: ${result.nodeVersions.join(', ')}`);
}

try {
  main();
} catch (error: unknown) {
  console.error('[release-matrix] FAIL:', error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
