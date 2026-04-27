"use strict";
/**
 * Programmatic API: compile
 *
 * Build edge runtime + infra config from a policy file. Stable public
 * contract. Internally delegates to the existing compiler scripts via
 * spawnSync (see note in lib/index.js); that will be replaced by in-process
 * module boundaries in #69 without changing this surface.
 *
 * Input:
 *   {
 *     policyPath:       string,     // required, absolute or relative to cwd
 *     outDir:           string,     // required, absolute or relative to cwd
 *     target:           'aws' | 'cloudflare',
 *     failOnPermissive?: boolean,
 *     failOnWafApproximation?: boolean,           // Cloudflare only
 *     outputMode?:      'full' | 'rule-group',   // AWS only
 *     ruleGroupOnly?:   boolean,                  // AWS only
 *     cwd?:             string,     // defaults to process.cwd()
 *     pkgRoot?:         string,     // defaults to installed package root
 *     env?:             NodeJS.ProcessEnv,
 *   }
 *
 * Output:
 *   {
 *     ok:         boolean,
 *     errors:     string[],
 *     warnings:   string[],
 *     edgeFiles:  string[],    // absolute paths to emitted edge code
 *     infraFiles: string[],    // absolute paths to emitted infra config
 *     policyPath: string,      // resolved policy path
 *     outDir:     string,      // resolved output dir
 *     target:     string,
 *   }
 */
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { lintPolicy } = require('./lint');
const DEFAULT_PKG_ROOT = path.join(__dirname, '..');
const AWS_EDGE_FILES = ['viewer-request.js', 'viewer-response.js', 'origin-request.js'];
const CF_EDGE_FILES = [path.join('cloudflare', 'index.ts')];
function resolveAbsolute(inputPath, cwd) {
    return path.isAbsolute(inputPath) ? inputPath : path.join(cwd, inputPath);
}
function listInfraArtifacts(outDir) {
    const infraDir = path.join(outDir, 'infra');
    if (!fs.existsSync(infraDir))
        return [];
    return fs
        .readdirSync(infraDir)
        .filter((name) => name.endsWith('.tf.json'))
        .map((name) => path.join(infraDir, name));
}
function compile(opts = {}) {
    opts = opts || {};
    const cwd = opts.cwd || process.cwd();
    const pkgRoot = opts.pkgRoot || DEFAULT_PKG_ROOT;
    const env = opts.env || process.env;
    const errors = [];
    const warnings = [];
    const baseResult = {
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
    // Step 1: lint (in-process — fast, deterministic).
    const lint = lintPolicy({ policyPath, pkgRoot, env });
    warnings.push(...lint.warnings);
    if (!lint.ok) {
        errors.push(...lint.errors);
        return { ok: false, errors, warnings, ...baseResult };
    }
    const permissiveFlag = opts.failOnPermissive ? ['--fail-on-permissive'] : [];
    // Step 2: edge compile.
    if (target === 'aws') {
        const compilePath = path.join(pkgRoot, 'scripts', 'compile.js');
        const compileResult = spawnSync(process.execPath, [
            compilePath,
            '--policy', policyPath,
            '--out-dir', outDir,
            ...permissiveFlag,
        ], { cwd, encoding: 'utf8', env });
        if (compileResult.status !== 0) {
            errors.push(`edge compile failed (status ${compileResult.status})`);
            if (compileResult.stderr)
                errors.push(compileResult.stderr.trim());
            return { ok: false, errors, warnings, ...baseResult };
        }
        if (compileResult.stderr) {
            warnings.push(...compileResult.stderr.trim().split('\n').filter(Boolean));
        }
        baseResult.edgeFiles = AWS_EDGE_FILES.map((f) => path.join(outDir, 'edge', f));
        const infraPath = path.join(pkgRoot, 'scripts', 'compile-infra.js');
        const infraResult = spawnSync(process.execPath, [
            infraPath,
            '--policy', policyPath,
            '--out-dir', outDir,
            '--output-mode', opts.outputMode || 'full',
            ...(opts.ruleGroupOnly ? ['--rule-group-only'] : []),
        ], { cwd, encoding: 'utf8', env });
        if (infraResult.status !== 0) {
            errors.push(`infra compile failed (status ${infraResult.status})`);
            if (infraResult.stderr)
                errors.push(infraResult.stderr.trim());
            return { ok: false, errors, warnings, ...baseResult };
        }
        if (infraResult.stderr) {
            warnings.push(...infraResult.stderr.trim().split('\n').filter(Boolean));
        }
        baseResult.infraFiles = listInfraArtifacts(outDir);
    }
    else {
        const compileCfPath = path.join(pkgRoot, 'scripts', 'compile-cloudflare.js');
        const cfResult = spawnSync(process.execPath, [
            compileCfPath,
            '--policy', policyPath,
            '--out-dir', outDir,
            ...permissiveFlag,
        ], { cwd, encoding: 'utf8', env });
        if (cfResult.status !== 0) {
            errors.push(`cloudflare edge compile failed (status ${cfResult.status})`);
            if (cfResult.stderr)
                errors.push(cfResult.stderr.trim());
            return { ok: false, errors, warnings, ...baseResult };
        }
        if (cfResult.stderr) {
            warnings.push(...cfResult.stderr.trim().split('\n').filter(Boolean));
        }
        baseResult.edgeFiles = CF_EDGE_FILES.map((f) => path.join(outDir, 'edge', f));
        const cfWafPath = path.join(pkgRoot, 'scripts', 'compile-cloudflare-waf.js');
        const cfWafResult = spawnSync(process.execPath, [
            cfWafPath,
            '--policy', policyPath,
            '--out-dir', outDir,
            ...(opts.failOnWafApproximation ? ['--fail-on-waf-approximation'] : []),
        ], { cwd, encoding: 'utf8', env });
        if (cfWafResult.status !== 0) {
            errors.push(`cloudflare waf compile failed (status ${cfWafResult.status})`);
            if (cfWafResult.stderr)
                errors.push(cfWafResult.stderr.trim());
            return { ok: false, errors, warnings, ...baseResult };
        }
        if (cfWafResult.stderr) {
            warnings.push(...cfWafResult.stderr.trim().split('\n').filter(Boolean));
        }
        baseResult.infraFiles = listInfraArtifacts(outDir);
    }
    return { ok: true, errors, warnings, ...baseResult };
}
module.exports = { compile };
