"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parsePolicyFile = parsePolicyFile;
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
function isPlainObject(value) {
    return (typeof value === 'object'
        && value !== null
        && !Array.isArray(value)
        && (value.constructor === Object || Object.getPrototypeOf(value) === null));
}
function collectDeepKeys(value, prefix = '') {
    if (!isPlainObject(value))
        return [];
    const entries = [];
    for (const [key, child] of Object.entries(value)) {
        const p = prefix ? `${prefix}.${key}` : key;
        entries.push(p);
        entries.push(...collectDeepKeys(child, p));
    }
    return entries;
}
function mergePolicyValues(base, override, warnings, pathHint = '') {
    if (Array.isArray(base) || Array.isArray(override)) {
        if (Array.isArray(base) && Array.isArray(override)) {
            return [...base, ...override];
        }
        if (override !== undefined) {
            if (base !== undefined) {
                warnings.push(`[policy] unreachable keys in ${pathHint || '<root>'}: replaced base subtree by non-array value.`);
            }
            return override;
        }
        return base;
    }
    if (isPlainObject(base) && isPlainObject(override)) {
        const merged = { ...base };
        for (const [key, value] of Object.entries(override)) {
            if (key === 'extends')
                continue;
            const childPath = pathHint ? `${pathHint}.${key}` : key;
            if (Object.prototype.hasOwnProperty.call(base, key)) {
                merged[key] = mergePolicyValues(base[key], value, warnings, childPath);
            }
            else {
                merged[key] = value;
            }
        }
        return merged;
    }
    if (override !== undefined) {
        if (base !== undefined) {
            const unreachableKeys = collectDeepKeys(base, pathHint);
            if (unreachableKeys.length > 0) {
                warnings.push(`[policy] unreachable keys at ${pathHint || '<root>'}: ${unreachableKeys.join(', ')}`);
            }
        }
        return override;
    }
    return base;
}
function loadPolicyFile(policyPath, stack, warnings) {
    const absPath = path.resolve(policyPath);
    if (stack.includes(absPath)) {
        const cycle = [...stack, absPath].join(' -> ');
        return { __error: `cyclic extends detected: ${cycle}` };
    }
    let raw;
    try {
        raw = yaml.load(fs.readFileSync(absPath, 'utf8'));
    }
    catch (e) {
        if (e && typeof e === 'object' && 'code' in e && e.code === 'ENOENT') {
            throw e;
        }
        throw new Error(`failed to parse YAML at ${absPath}: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (raw === null || raw === undefined || Array.isArray(raw) || typeof raw !== 'object') {
        throw new Error(`policy YAML at ${absPath} must be an object`);
    }
    const doc = raw;
    const extendsPath = doc.extends;
    if (extendsPath === undefined) {
        const filtered = { ...doc };
        delete filtered.extends;
        return filtered;
    }
    if (typeof extendsPath !== 'string' || extendsPath.trim() === '') {
        throw new Error(`invalid extends in ${absPath}: value must be a non-empty string`);
    }
    const nextPath = path.resolve(path.dirname(absPath), extendsPath.trim());
    let parent;
    try {
        parent = loadPolicyFile(nextPath, [...stack, absPath], warnings);
    }
    catch (e) {
        if (e && typeof e === 'object' && e.__error) {
            throw e;
        }
        throw e;
    }
    if (parent && typeof parent === 'object' && '__error' in parent) {
        throw new Error(String(parent.__error));
    }
    if (!isPlainObject(parent)) {
        throw new Error(`extends target must be an object: ${nextPath}`);
    }
    const child = { ...doc };
    delete child.extends;
    if (Object.keys(parent).length === 0) {
        return child;
    }
    return mergePolicyValues(parent, child, warnings, '');
}
function isFileMissingError(e) {
    return typeof e === 'object' && e !== null && 'code' in e && e.code === 'ENOENT';
}
function parsePolicyFile(opts = {}) {
    const policyPath = opts && opts.policyPath;
    if (!policyPath) {
        return { ok: false, errors: ['policyPath is required'], warnings: [], policy: null };
    }
    try {
        const warnings = [];
        const policy = loadPolicyFile(policyPath, [], warnings);
        if (isPlainObject(policy)) {
            return { ok: true, errors: [], warnings, policy: policy };
        }
        if (policy && typeof policy === 'object' && '__error' in policy) {
            const message = String(policy.__error);
            return { ok: false, errors: [message], warnings, policy: null };
        }
        return {
            ok: false,
            warnings,
            errors: ['loaded policy is not an object'],
            policy: null,
        };
    }
    catch (e) {
        if (isFileMissingError(e)) {
            return { ok: false, errors: [`policy file not found: ${policyPath}`], warnings: [], policy: null };
        }
        const message = e instanceof Error ? e.message : String(e);
        return {
            ok: false,
            errors: [`failed to parse policy YAML: ${message}`],
            warnings: [],
            policy: null,
        };
    }
}
