import { assertSupportedNode } from '../lib/node-engine';
assertSupportedNode(require.main === module);

const fs = require('fs');
const path = require('path');

const { lintPolicy } = require('../lib/lint');

import type { CompilerOptions } from '../scripts/lib/compiler-entry';

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
  allowPlaceholderToken?: boolean;
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
  if (target === 'cloudflare') {
    try { require('../scripts/lib/cloudflare-rate-limit').buildCloudflareRateRules(lint.policy?.firewall?.waf || {}); }
    catch (error: unknown) { errors.push((error as Error).message); return { ok: false, errors, warnings, ...baseResult }; }
  }

  const compilerOptions: CompilerOptions = { ...opts, rootDir: pkgRoot, outDir, env };
  const run = (file: string, name: string, label: string): boolean => {
    const diagnostics: string[] = [];
    const logger = { log() {}, error: (...args: unknown[]) => diagnostics.push(args.join(' ')),
      warn: (...args: unknown[]) => diagnostics.push(args.join(' ')) };
    try {
      require(path.join(pkgRoot, 'scripts', file))[name](lint.policy, { ...compilerOptions, logger });
      warnings.push(...diagnostics);
      return true;
    } catch (error: unknown) {
      errors.push(`${label} failed: ${(error as Error).message}`, ...diagnostics);
      return false;
    }
  };
  if (target === 'aws') {
    if (!run('lib/compile-core', 'compileAws', 'edge compile')) return { ok: false, errors, warnings, ...baseResult };
    baseResult.edgeFiles = AWS_EDGE_FILES.map((f) => path.join(outDir, 'edge', f));
    if (!run('compile-infra', 'compileInfra', 'infra compile')) return { ok: false, errors, warnings, ...baseResult };
  } else {
    if (!run('compile-cloudflare', 'compileCloudflare', 'cloudflare edge compile')) return { ok: false, errors, warnings, ...baseResult };
    baseResult.edgeFiles = CF_EDGE_FILES.map((f) => path.join(outDir, 'edge', f));
    if (!run('compile-cloudflare-waf', 'compileCloudflareWaf', 'cloudflare waf compile')) return { ok: false, errors, warnings, ...baseResult };
  }
  baseResult.infraFiles = listInfraArtifacts(outDir, compileStartedAt);

  return { ok: true, errors, warnings, ...baseResult };
}
