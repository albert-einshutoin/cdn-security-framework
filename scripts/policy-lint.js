#!/usr/bin/env node
"use strict";
// @ts-nocheck
// @ts-nocheck
// @ts-nocheck
/**
 * Policy lint: validates policy YAML against policy/schema.json using ajv,
 * then runs compile-core's auth-gate validator for cross-field checks that
 * JSON Schema cannot express.
 * Usage: node scripts/policy-lint.js [path/to/policy.yml]
 * Default: policy/base.yml
 */
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const Ajv = require('ajv');
const { validateAuthGates, parsePathPatterns } = require('./lib/compile-core');
const repoRoot = path.join(__dirname, '..');
const schemaPath = path.join(repoRoot, 'policy', 'schema.json');
const defaultPolicyPath = path.join(repoRoot, 'policy', 'base.yml');
function loadJson(filePath) {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}
function loadYaml(filePath) {
    return yaml.load(fs.readFileSync(filePath, 'utf8'));
}
function formatAjvErrors(errors) {
    return errors.map((err) => {
        const loc = err.instancePath || '(root)';
        const key = err.params && err.params.additionalProperty
            ? ` (property "${err.params.additionalProperty}")`
            : '';
        return `  - ${loc} ${err.message}${key}`;
    });
}
function main() {
    const policyPath = process.argv[2] || defaultPolicyPath;
    const errors = [];
    let policy;
    try {
        policy = loadYaml(policyPath);
    }
    catch (e) {
        if (e.code === 'ENOENT') {
            console.error('Error: policy file not found:', policyPath);
            process.exit(1);
        }
        console.error('Error: failed to parse policy YAML:', e.message);
        process.exit(1);
    }
    let schema;
    try {
        schema = loadJson(schemaPath);
    }
    catch (e) {
        console.error('Error: failed to load schema:', e.message);
        process.exit(1);
    }
    // strict: true flips on schema-authoring lint (typos in keywords / unknown
    // formats). strictRequired is off because our origin.auth `allOf/if/then`
    // conditionally requires properties that live in the parent scope — AJV's
    // strictRequired check would reject that pattern even though it is valid.
    const ajv = new Ajv({ allErrors: true, strict: true, strictRequired: false, allowUnionTypes: true });
    const validate = ajv.compile(schema);
    const valid = validate(policy);
    if (!valid) {
        errors.push('Schema validation failed:');
        errors.push(...formatAjvErrors(validate.errors || []));
    }
    // path_patterns semantic checks (regex compilation, ambiguous legacy entries)
    try {
        const block = (policy && policy.request && policy.request.block) || {};
        if (block.path_patterns !== undefined) {
            parsePathPatterns(block.path_patterns);
        }
    }
    catch (e) {
        errors.push(`  - request.block.path_patterns: ${e.message}`);
    }
    // Cross-field auth gate validation (jwt/signed_url required fields).
    // Allow missing token envs at lint time — they are enforced at build time.
    try {
        validateAuthGates(policy, { exitOnError: false, allowPlaceholderToken: true });
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
    // WAF fingerprint_action sanity (ajv already enforces enum, but keep friendly message).
    const waf = (policy && policy.firewall && policy.firewall.waf) || {};
    if (waf.fingerprint_action && !['block', 'count'].includes(waf.fingerprint_action)) {
        errors.push('  - firewall.waf.fingerprint_action must be "block" or "count"');
    }
    // Non-fatal warnings for production-grade WAF hygiene.
    const warnings = [];
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
    // origin.auth.custom_header env-var presence check (best-effort; env may be CI-only)
    const originAuth = policy && policy.origin && policy.origin.auth;
    if (originAuth && originAuth.type === 'custom_header' && originAuth.secret_env) {
        const envVal = process.env[originAuth.secret_env];
        if (envVal !== undefined && envVal.length === 0) {
            warnings.push('origin.auth.secret_env "' + originAuth.secret_env + '" is set but empty in the current shell. The edge will refuse to forward the origin-auth header, breaking origin trust. Unset the env or supply a value.');
        }
    }
    if (warnings.length > 0) {
        console.warn('Policy lint warnings:', policyPath);
        warnings.forEach((w) => console.warn('  - ' + w));
    }
    if (errors.length > 0) {
        console.error('Policy lint failed:', policyPath);
        errors.forEach((e) => console.error(e));
        process.exit(1);
    }
    console.log('Policy lint OK:', policyPath);
    process.exit(0);
}
main();
