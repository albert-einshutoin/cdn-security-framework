"use strict";
/**
 * Programmatic API: lintPolicy
 *
 * In-process policy validation. The public API keeps the same structured
 * result shape, while parsing and validation now live behind explicit compiler
 * phase modules.
 *
 * @typedef {import('../types/policy').CDNSecurityFrameworkPolicy} CDNSecurityFrameworkPolicy
 */
Object.defineProperty(exports, "__esModule", { value: true });
const path = require('path');
const { parsePolicyFile } = require('../parser');
const { validatePolicy } = require('../validator');
const DEFAULT_PKG_ROOT = path.join(__dirname, '..');
function lintPolicy(opts = {}) {
    opts = opts || {};
    const pkgRoot = opts.pkgRoot || DEFAULT_PKG_ROOT;
    const policyPath = opts.policyPath;
    const env = opts.env || process.env;
    if (!policyPath) {
        return {
            ok: false,
            errors: ['policyPath is required'],
            warnings: [],
            policy: null,
        };
    }
    const parsed = parsePolicyFile({ policyPath });
    if (!parsed.ok) {
        return {
            ok: false,
            errors: parsed.errors,
            warnings: parsed.warnings,
            policy: parsed.policy,
        };
    }
    const validated = validatePolicy({
        policy: parsed.policy,
        pkgRoot,
        env,
    });
    return {
        ok: validated.ok,
        errors: validated.errors,
        warnings: validated.warnings,
        policy: parsed.policy,
    };
}
module.exports = { lintPolicy };
