#!/usr/bin/env node
'use strict';

import fs from 'node:fs';
import path from 'node:path';

type ArtifactTree = { aggregateSha256: string; files: Array<{ path: string; sha256: string; size: number }> };
type MatrixReport = {
  schemaVersion: number;
  status: 'pass' | 'fail';
  failureCode?: 'validation_failed';
  failureStage?: string;
  nodeVersion: string;
  packageVersion: string;
  checks: Record<string, boolean>;
  skippedChecks: string[];
  apiExports: Record<string, string[]>;
  schemaDigests: Record<string, string>;
  artifacts: { aws: ArtifactTree; cloudflare: ArtifactTree };
};

type ComparisonReport = {
  schemaVersion: 1;
  status: 'pass' | 'fail';
  failureCode?: 'comparison_failed';
  failureStage?: string;
  packageVersion: string;
  nodeVersions: string[];
  checks: { apiExports: boolean; schemas: boolean; artifacts: boolean; examples: boolean };
  artifactDigests: { aws: string; cloudflare: string };
};

const requiredChecks = [
  'apiContract',
  'packageSmoke',
  'cliVersion',
  'cliHelp',
  'apiExports',
  'schemas',
  'openApiExample',
  'sourceExample',
  'awsBuild',
  'cloudflareBuild',
].sort();

class ComparisonFailure extends Error {
  constructor(readonly stage: string, message: string) {
    super(message);
  }
}

function parseArgs(argv: string[]): { input: string; output: string } {
  let input = 'reports/release-matrix';
  let output = 'reports/release-matrix-summary.json';
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--input') {
      const next = argv[index + 1];
      if (!next || next.startsWith('-')) throw new Error('--input requires a directory');
      input = next;
      index += 1;
      continue;
    }
    if (argv[index] === '--output') {
      const next = argv[index + 1];
      if (!next || next.startsWith('-')) throw new Error('--output requires a path');
      output = next;
      index += 1;
      continue;
    }
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
  if (!fs.existsSync(inputPath) || !fs.statSync(inputPath).isDirectory()) {
    throw new ComparisonFailure('reportCollection', `matrix report directory is missing: ${input}`);
  }
  const reports = fs.readdirSync(inputPath).filter((file) => file.endsWith('.json')).sort().map((file) => {
    try {
      return JSON.parse(fs.readFileSync(path.join(inputPath, file), 'utf8')) as MatrixReport;
    } catch {
      throw new ComparisonFailure('reportSchema', `matrix report is not valid JSON: ${file}`);
    }
  });
  if (reports.length !== 3) {
    throw new ComparisonFailure('reportCollection', `expected 3 Node matrix reports, found ${reports.length}`);
  }
  return reports;
}

function sameJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function writeFailureSummary(output: string, failureStage: string): void {
  const outputPath = path.resolve(process.cwd(), output);
  const result: ComparisonReport = {
    schemaVersion: 1,
    status: 'fail',
    failureCode: 'comparison_failed',
    failureStage,
    packageVersion: 'unknown',
    nodeVersions: [],
    checks: { apiExports: false, schemas: false, artifacts: false, examples: false },
    artifactDigests: { aws: '', cloudflare: '' },
  };
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`);
}

function main(input: string, output: string): void {
  const reports = readReports(input);
  const first = reports[0];
  if (reports.some((report) => report.schemaVersion !== 1)) {
    throw new ComparisonFailure('reportSchema', 'matrix report schema version drifted');
  }
  const failedReport = reports.find((report) => report.status !== 'pass');
  if (failedReport) {
    const stage = failedReport.failureStage ? `matrixValidation.${failedReport.failureStage}` : 'matrixValidation';
    throw new ComparisonFailure(stage, `matrix validation failed on Node ${failedReport.nodeVersion}`);
  }
  const nodeVersions = reports.map((report) => report.nodeVersion);
  const nodeMajors = nodeVersions.map((version) => Number.parseInt(version.split('.')[0], 10)).sort((a, b) => a - b);
  if (!nodeVersions.includes('20.17.0') || !sameJson(nodeMajors, [20, 22, 24])) {
    throw new ComparisonFailure('nodeVersions', `unexpected Node matrix: ${nodeVersions.join(', ')}`);
  }
  if (reports.some((report) => report.packageVersion !== first.packageVersion)) {
    throw new ComparisonFailure('packageVersion', 'package version differs across Node matrix');
  }
  if (reports.some((report) => !Array.isArray(report.skippedChecks)
    || report.skippedChecks.length > 0
    || !sameJson(Object.keys(report.checks).sort(), requiredChecks)
    || Object.values(report.checks).some((value) => value !== true))) {
    throw new ComparisonFailure('checks', 'a matrix example/check did not pass or was skipped');
  }
  if (reports.some((report) => !sameJson(report.apiExports, first.apiExports))) {
    throw new ComparisonFailure('apiExports', 'API exports differ across Node matrix');
  }
  if (reports.some((report) => !sameJson(report.schemaDigests, first.schemaDigests))) {
    throw new ComparisonFailure('schemas', 'schema digests differ across Node matrix');
  }
  if (reports.some((report) => report.artifacts.aws.aggregateSha256 !== first.artifacts.aws.aggregateSha256
    || report.artifacts.cloudflare.aggregateSha256 !== first.artifacts.cloudflare.aggregateSha256)) {
    throw new ComparisonFailure('artifacts', 'generated artifact digests differ across Node matrix');
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

let output = 'reports/release-matrix-summary.json';
try {
  const args = parseArgs(process.argv.slice(2));
  output = args.output;
  main(args.input, output);
} catch (error: unknown) {
  try {
    writeFailureSummary(output, error instanceof ComparisonFailure ? error.stage : 'arguments');
  } catch {
    // Preserve the original failure when the requested report path is unavailable.
  }
  console.error('[release-matrix] FAIL:', error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
