"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.defaultPolicyPath = defaultPolicyPath;
exports.defaultOutDir = defaultOutDir;
exports.parseArgs = parseArgs;
exports.parseCompilerArgs = parseCompilerArgs;
exports.hasFlag = hasFlag;
exports.loadPolicy = loadPolicy;
exports.loadPolicyWithWarnings = loadPolicyWithWarnings;
exports.reportPolicyWarnings = reportPolicyWarnings;
exports.reportPolicyLoadError = reportPolicyLoadError;
const fs = require('fs');
const path = require('path');
const { parsePolicyFile } = require('../../parser');
/**
 * Resolve the default policy path under `rootDir`:
 *   `<rootDir>/policy/security.yml` if it exists, otherwise
 *   `<rootDir>/policy/base.yml`.
 *
 * Centralized so every entry point that resolves a default policy (the AWS
 * compiler, the Cloudflare compiler, the infra compiler, the Cloudflare WAF
 * compiler, and the CLI's inline fallback) makes the same choice. Issue #182.
 */
function defaultPolicyPath(rootDir) {
    const securityPath = path.join(rootDir, 'policy', 'security.yml');
    const basePath = path.join(rootDir, 'policy', 'base.yml');
    return fs.existsSync(securityPath) ? securityPath : basePath;
}
/**
 * Default output directory under `rootDir`: `<rootDir>/dist`.
 */
function defaultOutDir(rootDir) {
    return path.join(rootDir, 'dist');
}
/**
 * Parse a compiler-style argv.
 *
 * Behavior preserved exactly from the pre-#182 inline copies:
 *   - default policy is `defaultPolicyPath(rootDir)`
 *   - default outDir is `defaultOutDir(rootDir)`
 *   - `--policy <value>` and `<positional>` compete for `policyPath`; the
 *     LAST one seen wins (so argv order between them matters: a positional
 *     that appears after `--policy` overrides the flag, and vice versa)
 *   - `--policy` without any following token is ignored. When a following
 *     token exists, it is consumed as the value, matching the old loop
 *   - `--out-dir <value>` sets `outDir`; same end-of-argv ignored rule
 *   - `--output-mode <value>` (used by compile-infra / emit-waf to pick
 *     between `full` and `rule-group`) is consumed so its value does NOT
 *     leak into the positional handler. The actual mode string is then
 *     re-parsed by the script-specific loop; we only skip the value here
 *   - any other flag (including `--allow-placeholder-token`,
 *     `--fail-on-permissive`, `--strict-origin-auth`,
 *     `--fail-on-waf-approximation`, `--rule-group-only`, etc.) is ignored
 *     by the parser — flag detection is handled by the dedicated `has*`
 *     helpers in compile-core
 *   - boolean flags (any `--flag` with no following non-flag value) are
 *     treated as no-arg flags and skipped
 */
function parseArgs(argv, rootDir) {
    let policyPath = defaultPolicyPath(rootDir);
    let outDir = defaultOutDir(rootDir);
    for (let i = 0; i < argv.length; i++) {
        if (argv[i] === '--policy' && argv[i + 1]) {
            policyPath = argv[++i];
            continue;
        }
        if (argv[i] === '--out-dir' && argv[i + 1]) {
            outDir = argv[++i];
            continue;
        }
        if (argv[i] === '--output-mode' && argv[i + 1]) {
            // consume value so it does not leak into the positional handler.
            ++i;
            continue;
        }
        if (isFlag(argv[i])) {
            // Unknown / boolean flag — ignored by argv parser. Flag detection
            // (which flags are present) lives in the dedicated has* helpers in
            // compile-core (hasAllowPlaceholderFlag, hasFailOnPermissiveFlag,
            // hasStrictOriginAuthFlag, etc.). A boolean flag has no following
            // value; here we still skip it so it never reaches the positional
            // branch below.
            continue;
        }
        policyPath = argv[i];
    }
    return { policyPath, outDir };
}
function parseCompilerArgs(argv, rootDir) {
    const parsed = parseArgs(argv, rootDir);
    return {
        ...parsed,
        allowPlaceholderToken: hasFlag(argv, '--allow-placeholder-token'),
        failOnPermissive: hasFlag(argv, '--fail-on-permissive'),
        strictOriginAuth: hasFlag(argv, '--strict-origin-auth'),
        failOnWafApproximation: hasFlag(argv, '--fail-on-waf-approximation'),
    };
}
function hasFlag(argv, flagName) {
    return Array.isArray(argv) && argv.includes(flagName);
}
function isFlag(token) {
    return typeof token === 'string' && token.startsWith('--');
}
/**
 * Load a policy file and return the parsed policy. Wraps the lower-level
 * `loadPolicyWithWarnings` so callers that only care about the policy object
 * (and not the parser warnings) get a one-liner.
 */
function loadPolicy(policyPath) {
    return loadPolicyWithWarnings(policyPath).policy;
}
/**
 * Load a policy file and return both the parsed policy and any parser
 * warnings. Throws an Error with `code === 'ENOENT'` when the file is
 * missing (so callers can map that to a friendlier "policy file not found"
 * message) and a plain Error otherwise.
 */
function loadPolicyWithWarnings(policyPath) {
    const parsed = parsePolicyFile({ policyPath });
    if (!parsed.ok) {
        const message = parsed.errors.join('; ') || 'failed to parse policy';
        const err = new Error(message);
        if (message.startsWith('policy file not found:')) {
            err.code = 'ENOENT';
        }
        throw err;
    }
    return { policy: parsed.policy, warnings: parsed.warnings };
}
function reportPolicyWarnings(warnings, policyPath, logger = console) {
    if (warnings.length === 0)
        return;
    if (policyPath) {
        logger.warn('Policy parse warnings:', policyPath);
    }
    else {
        logger.warn('Policy parse warnings:');
    }
    for (const warning of warnings) {
        logger.warn('  - ' + warning);
    }
}
function reportPolicyLoadError(policyPath, error, logger = console) {
    if (isErrorWithCode(error, 'ENOENT')) {
        logger.error('Error: policy file not found:', policyPath);
        return;
    }
    logger.error('Error: failed to parse policy YAML:', errorMessage(error));
}
function isErrorWithCode(error, code) {
    return error instanceof Error && error.code === code;
}
function errorMessage(error) {
    return error instanceof Error ? error.message : String(error);
}
