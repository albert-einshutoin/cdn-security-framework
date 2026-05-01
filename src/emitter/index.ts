const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const { lintPolicy } = require('../lib/lint');

import type { SpawnSyncReturns } from 'child_process';

const DEFAULT_PKG_ROOT = path.join(__dirname, '..');

const AWS_EDGE_FILES = ['viewer-request.js', 'viewer-response.js', 'origin-request.js'];
const CF_EDGE_FILES = [path.join('cloudflare', 'index.ts')];

export type CompileTarget = 'aws' | 'cloudflare';

export type CompileArtifactsOptions = {
  policyPath?: string;
  outDir?: string;
  target?: CompileTarget;
  failOnPermissive?: boolean;
  failOnWafApproximation?: boolean;
  outputMode?: string;
  ruleGroupOnly?: boolean;
  cwd?: string;
  pkgRoot?: string;
  env?: NodeJS.ProcessEnv;
};

export type CompileResultBase = {
  edgeFiles: string[];
  infraFiles: string[];
  policyPath: string | null;
  outDir: string | null;
  target: string;
};

export type CompileArtifactsResult = CompileResultBase & {
  ok: boolean;
  errors: string[];
  warnings: string[];
};

export function resolveAbsolute(inputPath: string, cwd: string): string {
  return path.isAbsolute(inputPath) ? inputPath : path.join(cwd, inputPath);
}

export function listInfraArtifacts(outDir: string, sinceMs = 0): string[] {
  const infraDir = path.join(outDir, 'infra');
  if (!fs.existsSync(infraDir)) return [];
  return fs
    .readdirSync(infraDir)
    .filter((name: string) => name.endsWith('.tf.json'))
    .map((name: string) => path.join(infraDir, name))
    .filter((filePath: string) => sinceMs <= 0 || fs.statSync(filePath).mtimeMs >= sinceMs);
}

function collectStderrWarnings(result: SpawnSyncReturns<string>, warnings: string[]): void {
  if (result.stderr) {
    warnings.push(...result.stderr.trim().split('\n').filter(Boolean));
  }
}

function collectFailedSpawn(
  label: string,
  result: SpawnSyncReturns<string>,
  errors: string[],
): void {
  errors.push(`${label} failed (status ${result.status})`);
  if (result.stderr) errors.push(result.stderr.trim());
}

export function compileArtifacts(opts: CompileArtifactsOptions = {}): CompileArtifactsResult {
  opts = opts || {};
  const cwd = opts.cwd || process.cwd();
  const pkgRoot = opts.pkgRoot || DEFAULT_PKG_ROOT;
  const env = opts.env || process.env;

  const errors: string[] = [];
  const warnings: string[] = [];
  const baseResult: CompileResultBase = {
    edgeFiles: [],
    infraFiles: [],
    policyPath: null,
    outDir: null,
    target: opts.target || 'aws',
  };

  if (!opts.policyPath) {
    return { ok: false, errors: ['policyPath is required'], warnings, ...baseResult };
  }
  if (!opts.outDir) {
    return { ok: false, errors: ['outDir is required'], warnings, ...baseResult };
  }
  const target = opts.target || 'aws';
  if (target !== 'aws' && target !== 'cloudflare') {
    return {
      ok: false,
      errors: [`Unknown target: ${target} (expected aws | cloudflare)`],
      warnings,
      ...baseResult,
      target,
    };
  }

  const policyPath = resolveAbsolute(opts.policyPath, cwd);
  const outDir = resolveAbsolute(opts.outDir, cwd);
  const compileStartedAt = Date.now() - 1000;
  baseResult.policyPath = policyPath;
  baseResult.outDir = outDir;
  baseResult.target = target;

  if (!fs.existsSync(policyPath)) {
    return {
      ok: false,
      errors: [`policy file not found: ${policyPath}`],
      warnings,
      ...baseResult,
    };
  }

  const lint = lintPolicy({ policyPath, pkgRoot, env });
  warnings.push(...lint.warnings);
  if (!lint.ok) {
    errors.push(...lint.errors);
    return { ok: false, errors, warnings, ...baseResult };
  }

  const permissiveFlag = opts.failOnPermissive ? ['--fail-on-permissive'] : [];

  if (target === 'aws') {
    const compilePath = path.join(pkgRoot, 'scripts', 'compile.js');
    const compileResult = spawnSync(
      process.execPath,
      [
        compilePath,
        '--policy', policyPath,
        '--out-dir', outDir,
        ...permissiveFlag,
      ],
      { cwd, encoding: 'utf8', env },
    );
    if (compileResult.status !== 0) {
      collectFailedSpawn('edge compile', compileResult, errors);
      return { ok: false, errors, warnings, ...baseResult };
    }
    collectStderrWarnings(compileResult, warnings);
    baseResult.edgeFiles = AWS_EDGE_FILES.map((f) => path.join(outDir, 'edge', f));

    const infraPath = path.join(pkgRoot, 'scripts', 'compile-infra.js');
    const infraResult = spawnSync(
      process.execPath,
      [
        infraPath,
        '--policy', policyPath,
        '--out-dir', outDir,
        '--output-mode', opts.outputMode || 'full',
        ...(opts.ruleGroupOnly ? ['--rule-group-only'] : []),
      ],
      { cwd, encoding: 'utf8', env },
    );
    if (infraResult.status !== 0) {
      collectFailedSpawn('infra compile', infraResult, errors);
      return { ok: false, errors, warnings, ...baseResult };
    }
    collectStderrWarnings(infraResult, warnings);
    baseResult.infraFiles = listInfraArtifacts(outDir, compileStartedAt);
  } else {
    const compileCfPath = path.join(pkgRoot, 'scripts', 'compile-cloudflare.js');
    const cfResult = spawnSync(
      process.execPath,
      [
        compileCfPath,
        '--policy', policyPath,
        '--out-dir', outDir,
        ...permissiveFlag,
      ],
      { cwd, encoding: 'utf8', env },
    );
    if (cfResult.status !== 0) {
      collectFailedSpawn('cloudflare edge compile', cfResult, errors);
      return { ok: false, errors, warnings, ...baseResult };
    }
    collectStderrWarnings(cfResult, warnings);
    baseResult.edgeFiles = CF_EDGE_FILES.map((f) => path.join(outDir, 'edge', f));

    const cfWafPath = path.join(pkgRoot, 'scripts', 'compile-cloudflare-waf.js');
    const cfWafResult = spawnSync(
      process.execPath,
      [
        cfWafPath,
        '--policy', policyPath,
        '--out-dir', outDir,
        ...(opts.failOnWafApproximation ? ['--fail-on-waf-approximation'] : []),
      ],
      { cwd, encoding: 'utf8', env },
    );
    if (cfWafResult.status !== 0) {
      collectFailedSpawn('cloudflare waf compile', cfWafResult, errors);
      return { ok: false, errors, warnings, ...baseResult };
    }
    collectStderrWarnings(cfWafResult, warnings);
    baseResult.infraFiles = listInfraArtifacts(outDir, compileStartedAt);
  }

  return { ok: true, errors, warnings, ...baseResult };
}
