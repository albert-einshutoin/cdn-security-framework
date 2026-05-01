"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parsePolicyFile = parsePolicyFile;
const fs = require('fs');
const yaml = require('js-yaml');
function parsePolicyFile(opts = {}) {
    const policyPath = opts && opts.policyPath;
    if (!policyPath) {
        return { ok: false, errors: ['policyPath is required'], policy: null };
    }
    try {
        const policy = yaml.load(fs.readFileSync(policyPath, 'utf8'));
        return { ok: true, errors: [], policy };
    }
    catch (e) {
        if (e && typeof e === 'object' && 'code' in e && e.code === 'ENOENT') {
            return { ok: false, errors: [`policy file not found: ${policyPath}`], policy: null };
        }
        const message = e instanceof Error ? e.message : String(e);
        return {
            ok: false,
            errors: [`failed to parse policy YAML: ${message}`],
            policy: null,
        };
    }
}
