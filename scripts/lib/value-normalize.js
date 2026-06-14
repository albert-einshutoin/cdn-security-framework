"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.clampNumber = clampNumber;
exports.numberOr = numberOr;
exports.normalizeStringList = normalizeStringList;
function applyStringCase(value, casing) {
    if (casing === 'lower')
        return value.toLowerCase();
    if (casing === 'upper')
        return value.toUpperCase();
    return value;
}
function toFiniteNumber(raw) {
    const n = Number(raw);
    return Number.isFinite(n) ? n : null;
}
function clampNumber(raw, min, max, fallback) {
    const n = toFiniteNumber(raw);
    return n === null ? fallback : Math.max(min, Math.min(max, n));
}
function numberOr(raw, fallback) {
    return Number(raw) || fallback;
}
function normalizeStringList(raw, casing = 'preserve', options = {}) {
    if (!Array.isArray(raw))
        return [];
    const trimOutput = options.trim !== false;
    return raw
        .filter((s) => typeof s === 'string' && !!s.trim())
        .map((s) => (trimOutput ? s.trim() : s))
        .map((s) => applyStringCase(s, casing))
        .filter(Boolean);
}
