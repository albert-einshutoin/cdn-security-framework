// @ts-nocheck
/**
 * Programmatic API: emitWaf
 *
 * Generate only the WAF/infra config — no edge code. Mirrors the CLI
 * `emit-waf` subcommand and keeps the same flag surface.
 *
 * Input:
 *   {
 *     policyPath:     string,
 *     outDir:         string,
 *     target:         'aws' | 'cloudflare',
 *     format?:        'terraform' | 'cloudformation' | 'cdk',
 *     outputMode?:    'full' | 'rule-group',
 *     ruleGroupOnly?: boolean,
 *     failOnWafApproximation?: boolean,  // cloudflare only
 *     cwd?:           string,
 *     pkgRoot?:       string,
 *     env?:           NodeJS.ProcessEnv,
 *   }
 *
 * Output: same shape as compile() but edgeFiles is always [].
 *
 * Error semantics for unimplemented formats: cloudformation and cdk return
 * { ok: false } with `errors` explaining the format is not implemented. The
 * CLI layer translates this to exit code 2 (see bin/cli.js).
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const { lintPolicy } = require('./lint');

const DEFAULT_PKG_ROOT = path.join(__dirname, '..');

function resolveAbsolute(inputPath, cwd) {
  return path.isAbsolute(inputPath) ? inputPath : path.join(cwd, inputPath);
}

function listInfraArtifacts(outDir) {
  const infraDir = path.join(outDir, 'infra');
  if (!fs.existsSync(infraDir)) return [];
  return fs
    .readdirSync(infraDir)
    .filter((name) => name.endsWith('.tf.json'))
    .map((name) => path.join(infraDir, name));
}

function emitWaf(opts) {
  opts = opts || {};
  const cwd = opts.cwd || process.cwd();
  const pkgRoot = opts.pkgRoot || DEFAULT_PKG_ROOT;
  const env = opts.env || process.env;
  const format = opts.format || 'terraform';
  const target = opts.target || 'aws';

  const errors = [];
  const warnings = [];
  const baseResult = {
    edgeFiles: [],
    infraFiles: [],
    policyPath: null,
    outDir: null,
    target,
    format,
    formatNotImplemented: false,
  };

  if (!opts.policyPath) {
    return { ok: false, errors: ['policyPath is required'], warnings, ...baseResult };
  }
  if (!opts.outDir) {
    return { ok: false, errors: ['outDir is required'], warnings, ...baseResult };
  }
  if (target !== 'aws' && target !== 'cloudflare') {
    return {
      ok: false,
      errors: [`Unknown target: ${target} (expected aws | cloudflare)`],
      warnings,
      ...baseResult,
    };
  }
  if (!['terraform', 'cloudformation', 'cdk'].includes(format)) {
    return {
      ok: false,
      errors: [`Unknown --format: ${format} (expected terraform | cloudformation | cdk)`],
      warnings,
      ...baseResult,
    };
  }
  if (format !== 'terraform') {
    return {
      ok: false,
      errors: [
        `--format ${format} is not yet implemented. Only terraform is generated today; cloudformation and cdk are reserved and intentionally fail loudly to prevent silent fallback.`,
      ],
      warnings,
      ...baseResult,
      formatNotImplemented: true,
    };
  }

  const policyPath = resolveAbsolute(opts.policyPath, cwd);
  const outDir = resolveAbsolute(opts.outDir, cwd);
  baseResult.policyPath = policyPath;
  baseResult.outDir = outDir;

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

  if (target === 'aws') {
    const infraPath = path.join(pkgRoot, 'scripts', 'compile-infra.js');
    const result = spawnSync(
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
    if (result.status !== 0) {
      errors.push(`infra compile failed (status ${result.status})`);
      if (result.stderr) errors.push(result.stderr.trim());
      return { ok: false, errors, warnings, ...baseResult };
    }
    if (result.stderr) {
      warnings.push(...result.stderr.trim().split('\n').filter(Boolean));
    }
    baseResult.infraFiles = listInfraArtifacts(outDir);
  } else {
    const cfWafPath = path.join(pkgRoot, 'scripts', 'compile-cloudflare-waf.js');
    const result = spawnSync(
      process.execPath,
      [
        cfWafPath,
        '--policy', policyPath,
        '--out-dir', outDir,
        ...(opts.failOnWafApproximation ? ['--fail-on-waf-approximation'] : []),
      ],
      { cwd, encoding: 'utf8', env },
    );
    if (result.status !== 0) {
      errors.push(`cloudflare waf compile failed (status ${result.status})`);
      if (result.stderr) errors.push(result.stderr.trim());
      return { ok: false, errors, warnings, ...baseResult };
    }
    if (result.stderr) {
      warnings.push(...result.stderr.trim().split('\n').filter(Boolean));
    }
    baseResult.infraFiles = listInfraArtifacts(outDir);
  }

  return { ok: true, errors, warnings, ...baseResult };
}

module.exports = { emitWaf };
