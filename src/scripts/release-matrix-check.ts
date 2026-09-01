#!/usr/bin/env node
'use strict';

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import childProcess from 'node:child_process';

type Manifest = {
  entrypoints: Record<string, { require?: string; exports: string[] }>;
  schemas: Array<{ path: string }>;
};

type ArtifactTree = {
  aggregateSha256: string;
  files: Array<{ path: string; sha256: string; size: number }>;
};

type MatrixReport = {
  schemaVersion: 1;
  nodeVersion: string;
  packageVersion: string;
  checks: {
    cliVersion: boolean;
    cliHelp: boolean;
    openApiExample: boolean;
    sourceExample: boolean;
    awsBuild: boolean;
    cloudflareBuild: boolean;
  };
  apiExports: Record<string, string[]>;
  schemaDigests: Record<string, string>;
  artifacts: { aws: ArtifactTree; cloudflare: ArtifactTree };
};

const repoRoot = path.join(__dirname, '..');
const cliPath = path.join(repoRoot, 'bin', 'cli.js');
const packageJsonPath = path.join(repoRoot, 'package.json');
const manifestPath = path.join(repoRoot, 'docs', 'api-manifest.json');

function parseArgs(argv: string[]): { output: string } {
  let output = 'reports/release-matrix.json';
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--output') {
      output = argv[index + 1];
      index += 1;
      continue;
    }
    if (argv[index] === '--help' || argv[index] === '-h') {
      console.log('Usage: node scripts/release-matrix-check.js [--output <path>]');
      process.exit(0);
    }
    throw new Error(`Unknown flag: ${argv[index]}`);
  }
  return { output };
}

function runCli(args: string[], env: NodeJS.ProcessEnv): { stdout: string; stderr: string } {
  const result = childProcess.spawnSync(process.execPath, [cliPath, ...args], {
    cwd: repoRoot,
    env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 20 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`CLI failed (${args.join(' ')}): ${result.stderr.trim() || `exit ${result.status}`}`);
  }
  return { stdout: result.stdout, stderr: result.stderr };
}

function sha256File(filePath: string): string {
  return `sha256:${crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex')}`;
}

function listFiles(root: string, current = root): string[] {
  return fs.readdirSync(current, { withFileTypes: true }).flatMap((entry) => {
    const filePath = path.join(current, entry.name);
    if (entry.isDirectory()) return listFiles(root, filePath);
    if (!entry.isFile()) throw new Error(`artifact tree contains unsupported entry: ${path.relative(root, filePath)}`);
    return [filePath];
  }).sort();
}

function hashTree(root: string): ArtifactTree {
  const files = listFiles(root).map((filePath) => ({
    path: path.relative(root, filePath).split(path.sep).join('/'),
    sha256: sha256File(filePath),
    size: fs.statSync(filePath).size,
  }));
  const aggregate = crypto.createHash('sha256');
  for (const file of files) aggregate.update(`${file.path}\0${file.sha256}\0${file.size}\n`);
  return { aggregateSha256: `sha256:${aggregate.digest('hex')}`, files };
}

function ensureExampleFiles(): void {
  for (const relative of [
    'examples/openapi/openapi.yaml',
    'examples/nestjs-contract/run-analysis.cjs',
    'examples/github-actions/contract-diff.yml',
  ]) {
    if (!fs.existsSync(path.join(repoRoot, relative))) throw new Error(`example is missing: ${relative}`);
  }
}

function main(): void {
  const { output } = parseArgs(process.argv.slice(2));
  const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8')) as { version: string };
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as Manifest;
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    EDGE_ADMIN_TOKEN: process.env.EDGE_ADMIN_TOKEN || 'release-matrix-token-not-for-deploy',
    ORIGIN_SECRET: process.env.ORIGIN_SECRET || 'release-matrix-origin-not-for-deploy',
    JWT_SECRET: process.env.JWT_SECRET || 'release-matrix-jwt-not-for-deploy',
  };

  const version = runCli(['--version'], env).stdout.trim();
  if (version !== pkg.version) throw new Error(`CLI version ${version} does not match package ${pkg.version}`);
  const help = runCli(['--help'], env).stdout;
  for (const command of ['build', 'openapi', 'contract', 'migrate']) {
    if (!help.includes(command)) throw new Error(`CLI help is missing ${command}`);
  }
  ensureExampleFiles();

  const apiExports: Record<string, string[]> = {};
  for (const [entrypoint, declaration] of Object.entries(manifest.entrypoints)) {
    if (!declaration.require) continue;
    const modulePath = path.join(repoRoot, declaration.require.replace(/^\.\//u, ''));
    apiExports[entrypoint] = Object.keys(require(modulePath)).sort();
    if (JSON.stringify(apiExports[entrypoint]) !== JSON.stringify([...declaration.exports].sort())) {
      throw new Error(`API export drift detected for ${entrypoint}`);
    }
  }

  const schemaDigests: Record<string, string> = {};
  for (const schema of manifest.schemas) schemaDigests[schema.path] = sha256File(path.join(repoRoot, schema.path));

  // OpenAPI output is required to stay under its workspace root; keep this
  // ephemeral build directory inside the repository and remove it below.
  const tempRoot = fs.mkdtempSync(path.join(repoRoot, '.release-matrix-'));
  try {
    const openApiReport = path.join(tempRoot, 'openapi-inspection.json');
    runCli([
      'openapi', 'inspect', '--input', path.join(repoRoot, 'examples/openapi/openapi.yaml'),
      '--workspace-root', repoRoot, '--json', '--out', openApiReport,
    ], env);
    const inspection = JSON.parse(fs.readFileSync(openApiReport, 'utf8')) as { schemaVersion: number; summary?: { operationCount?: number } };
    if (inspection.schemaVersion !== 1 || inspection.summary?.operationCount !== 5) {
      throw new Error('OpenAPI example report is not the expected v1 fixture');
    }

    const sourceExample = childProcess.spawnSync(process.execPath, [
      path.join(repoRoot, 'examples/nestjs-contract/run-analysis.cjs'),
    ], { cwd: repoRoot, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    if (sourceExample.error) throw sourceExample.error;
    if (sourceExample.status !== 0) throw new Error(`NestJS example failed: ${sourceExample.stderr.trim()}`);
    const sourceReport = JSON.parse(sourceExample.stdout) as { schemaVersion: number; operations?: unknown[] };
    if (sourceReport.schemaVersion !== 1 || sourceReport.operations?.length !== 6) {
      throw new Error('NestJS example report is not the expected v1 fixture');
    }

    const awsRoot = path.join(tempRoot, 'aws');
    const cloudflareRoot = path.join(tempRoot, 'cloudflare');
    runCli(['build', '--policy', path.join(repoRoot, 'policy/base.yml'), '--out-dir', awsRoot], env);
    runCli(['build', '--target', 'cloudflare', '--policy', path.join(repoRoot, 'policy/base.yml'), '--out-dir', cloudflareRoot], env);

    const report: MatrixReport = {
      schemaVersion: 1,
      nodeVersion: process.versions.node,
      packageVersion: pkg.version,
      checks: {
        cliVersion: true,
        cliHelp: true,
        openApiExample: true,
        sourceExample: true,
        awsBuild: true,
        cloudflareBuild: true,
      },
      apiExports,
      schemaDigests,
      artifacts: { aws: hashTree(awsRoot), cloudflare: hashTree(cloudflareRoot) },
    };
    const outputPath = path.resolve(repoRoot, output);
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`);
    console.log(`[release-matrix] OK: ${process.versions.node}`);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error: unknown) {
  console.error('[release-matrix] FAIL:', error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
