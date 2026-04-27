"use strict";
/**
 * Programmatic API: lintPolicy
 *
 * In-process equivalent of `scripts/policy-lint.js`. Returns a structured
 * result instead of calling process.exit. Stable public surface — the
 * underlying ajv / validateAuthGates / parsePathPatterns plumbing may change,
 * but the return shape is stable.
 *
 * Input:
 *   { policyPath: string, pkgRoot?: string }
 *   pkgRoot defaults to the installed package root (where schema.json lives).
 *
 * Output:
 *   { ok, errors[], warnings[], policy }
 *   - `policy` is the parsed YAML object (null if parse failed).
 */
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const Ajv = require('ajv');
const { validateAuthGates, parsePathPatterns, } = require('../scripts/lib/compile-core');
const DEFAULT_PKG_ROOT = path.join(__dirname, '..');
function formatAjvErrors(errors) {
    return errors.map((err) => {
        const loc = err.instancePath || '(root)';
        const key = err.params && err.params.additionalProperty
            ? ` (property "${err.params.additionalProperty}")`
            : '';
        return `  - ${loc} ${err.message}${key}`;
    });
}
function lintPolicy(opts = {}) {
    opts = opts || {};
    const pkgRoot = opts.pkgRoot || DEFAULT_PKG_ROOT;
    const policyPath = opts.policyPath;
    const env = opts.env || process.env;
    const errors = [];
    const warnings = [];
    if (!policyPath) {
        return {
            ok: false,
            errors: ['policyPath is required'],
            warnings: [],
            policy: null,
        };
    }
    let policy = null;
    try {
        policy = yaml.load(fs.readFileSync(policyPath, 'utf8'));
    }
    catch (e) {
        if (e.code === 'ENOENT') {
            return {
                ok: false,
                errors: [`policy file not found: ${policyPath}`],
                warnings: [],
                policy: null,
            };
        }
        return {
            ok: false,
            errors: [`failed to parse policy YAML: ${e.message}`],
            warnings: [],
            policy: null,
        };
    }
    let schema;
    try {
        schema = JSON.parse(fs.readFileSync(path.join(pkgRoot, 'policy', 'schema.json'), 'utf8'));
    }
    catch (e) {
        return {
            ok: false,
            errors: [`failed to load schema: ${e.message}`],
            warnings: [],
            policy,
        };
    }
    const ajv = new Ajv({
        allErrors: true,
        strict: true,
        strictRequired: false,
        allowUnionTypes: true,
    });
    const validate = ajv.compile(schema);
    if (!validate(policy)) {
        errors.push('Schema validation failed:');
        errors.push(...formatAjvErrors(validate.errors || []));
    }
    try {
        const block = (policy && policy.request && policy.request.block) || {};
        if (block.path_patterns !== undefined) {
            parsePathPatterns(block.path_patterns);
        }
    }
    catch (e) {
        errors.push(`  - request.block.path_patterns: ${e.message}`);
    }
    try {
        validateAuthGates(policy, {
            exitOnError: false,
            allowPlaceholderToken: true,
        });
    }
    catch (e) {
        if (Array.isArray(e.validationErrors)) {
            errors.push('Auth gate validation failed:');
            e.validationErrors.forEach((msg) => errors.push('  - ' + msg));
        }
        else {
            errors.push('Auth gate validation error: ' + e.message);
        }
    }
    const waf = (policy && policy.firewall && policy.firewall.waf) || {};
    if (waf.fingerprint_action &&
        !['block', 'count'].includes(waf.fingerprint_action)) {
        errors.push('  - firewall.waf.fingerprint_action must be "block" or "count"');
    }
    const mode = (policy && policy.defaults && policy.defaults.mode) || null;
    const isEnforce = mode === 'enforce';
    const hasWaf = policy && policy.firewall && policy.firewall.waf;
    if (isEnforce && hasWaf) {
        const managed = Array.isArray(waf.managed_rules) ? waf.managed_rules : [];
        const hasCoreSignal = managed.some((r) => r === 'AWSManagedRulesBotControlRuleSet' ||
            r === 'AWSManagedRulesATPRuleSet' ||
            r === 'AWSManagedRulesIPReputationList' ||
            r === 'AWSManagedRulesAnonymousIpList');
        if (!hasCoreSignal) {
            warnings.push('firewall.waf.managed_rules does not include any of BotControl / ATP / IPReputation / AnonymousIp. Consider adding at least IPReputation + AnonymousIp for production enforce mode.');
        }
        const loggingEnabled = waf.logging && waf.logging.enabled === true;
        if (waf.scope === 'CLOUDFRONT' && !loggingEnabled) {
            warnings.push('firewall.waf.logging is not enabled while scope=CLOUDFRONT. PCI-DSS / SOC2 require WAF log retention — set logging.enabled: true and supply destination_arn_env.');
        }
    }
    const originAuth = policy && policy.origin && policy.origin.auth;
    if (originAuth && originAuth.type === 'custom_header' && originAuth.secret_env) {
        const envVal = env[originAuth.secret_env];
        if (envVal !== undefined && envVal.length === 0) {
            warnings.push('origin.auth.secret_env "' +
                originAuth.secret_env +
                '" is set but empty in the current shell. The edge will refuse to forward the origin-auth header, breaking origin trust. Unset the env or supply a value.');
        }
    }
    return {
        ok: errors.length === 0,
        errors,
        warnings,
        policy,
    };
}
module.exports = { lintPolicy };
