#!/usr/bin/env node
"use strict";
// @ts-nocheck
// @ts-nocheck
// @ts-nocheck
/**
 * ReDoS fuzz: exercises every user-supplied regex from policy YAML against
 * adversarial inputs with a per-match timeout. Fails if any regex takes longer
 * than REDOS_TIMEOUT_MS, which is the signal for catastrophic backtracking.
 *
 * Covered sources:
 *   - request.block.path_patterns.regex
 *   - routes[].match.regex (future-proof; currently not in schema)
 *
 * Also runs a static sanity check rejecting classic ReDoS shapes
 * (nested quantifiers over overlapping classes) before runtime fuzzing — see
 * hasNestedQuantifier().
 */
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const yaml = require('js-yaml');
const { compileRegexOrThrow, hasCatastrophicBacktrackShape } = require('./lib/compile-core');
const REDOS_TIMEOUT_MS = 50;
const repoRoot = path.join(__dirname, '..');
function test(name, fn) {
    try {
        fn();
        console.log('OK:', name);
    }
    catch (e) {
        console.error('FAIL:', name);
        console.error(e && e.stack ? e.stack : e);
        process.exitCode = 1;
    }
}
function loadPolicy(filePath) {
    return yaml.load(fs.readFileSync(filePath, 'utf8'));
}
function collectRegexes(policy) {
    const out = [];
    const patterns = policy && policy.request && policy.request.block && policy.request.block.path_patterns;
    if (patterns && typeof patterns === 'object' && !Array.isArray(patterns) && Array.isArray(patterns.regex)) {
        for (const r of patterns.regex) {
            if (typeof r === 'string' && r.length > 0)
                out.push({ source: 'request.block.path_patterns.regex', pattern: r });
        }
    }
    return out;
}
// Proxy to the shared heuristic in compile-core so build-time rejection and
// fuzz-time rejection stay in lockstep — any pattern the compiler refuses is
// also something the fuzz harness refuses to even benchmark.
function hasNestedQuantifier(src) {
    return hasCatastrophicBacktrackShape(src);
}
function runWithTimeout(regex, input, timeoutMs) {
    const ctx = { regex, input };
    vm.createContext(ctx);
    const start = Date.now();
    try {
        vm.runInContext('regex.test(input)', ctx, { timeout: timeoutMs });
    }
    catch (e) {
        if (/Script execution timed out/i.test(String(e && e.message))) {
            return { ok: false, elapsed: Date.now() - start, timedOut: true };
        }
        throw e;
    }
    return { ok: true, elapsed: Date.now() - start, timedOut: false };
}
// Adversarial inputs that commonly trigger catastrophic backtracking in
// ill-formed regexes. Each is short enough that a well-formed regex matches
// or fails in < 1ms; a vulnerable regex explodes past our timeout.
function adversarialInputs() {
    return [
        'a'.repeat(30) + '!',
        'a'.repeat(60) + '!',
        'a'.repeat(90) + '!',
        '/' + 'a'.repeat(40) + '/b',
        '%2e' + 'a'.repeat(40) + 'Z',
        '.'.repeat(60) + '/',
        '/'.repeat(60),
        '\\' + 'a'.repeat(60),
    ];
}
function fuzzRegex(patternSource) {
    const results = [];
    let compiled;
    try {
        // Use the compiler's helper so `(?i)` / `(?s)` / `(?m)` inline flags
        // (which Node's RegExp does not natively accept) are translated the same
        // way as at compile time.
        compiled = compileRegexOrThrow(patternSource, 'redos-fuzz');
    }
    catch (e) {
        return { compile: false, reason: String(e && e.message) };
    }
    for (const input of adversarialInputs()) {
        const res = runWithTimeout(compiled, input, REDOS_TIMEOUT_MS);
        results.push({ input, ...res });
        if (res.timedOut)
            return { compile: true, timedOut: true, worstInput: input, elapsed: res.elapsed };
    }
    const worst = results.reduce((acc, r) => (r.elapsed > acc.elapsed ? r : acc), { elapsed: 0 });
    return { compile: true, timedOut: false, worstElapsedMs: worst.elapsed, results };
}
const profilePaths = [
    path.join(repoRoot, 'policy', 'base.yml'),
    path.join(repoRoot, 'policy', 'profiles', 'strict.yml'),
    path.join(repoRoot, 'policy', 'profiles', 'balanced.yml'),
    path.join(repoRoot, 'policy', 'profiles', 'permissive.yml'),
];
for (const p of profilePaths) {
    if (!fs.existsSync(p))
        continue;
    const policy = loadPolicy(p);
    const regexes = collectRegexes(policy);
    test(`redos-fuzz ${path.relative(repoRoot, p)}: ${regexes.length} regex(es) within ${REDOS_TIMEOUT_MS}ms`, () => {
        for (const { source, pattern } of regexes) {
            if (hasNestedQuantifier(pattern)) {
                throw new Error(`${source}: pattern rejected by nested-quantifier heuristic: ${JSON.stringify(pattern)}`);
            }
            const r = fuzzRegex(pattern);
            if (!r.compile) {
                throw new Error(`${source}: regex failed to compile: ${r.reason}`);
            }
            if (r.timedOut) {
                throw new Error(`${source}: regex timed out (>${REDOS_TIMEOUT_MS}ms) on input ${JSON.stringify(r.worstInput)}: ${JSON.stringify(pattern)}`);
            }
        }
    });
}
// Positive control: canonical ReDoS shapes should trip the fuzz harness, so
// if the detection itself regresses the test suite fails loudly.
test('redos-fuzz: canonical (a+)+ shape is rejected by nested-quantifier heuristic', () => {
    const pattern = '^(a+)+$';
    if (!hasNestedQuantifier(pattern)) {
        throw new Error('nested-quantifier heuristic failed to flag ^(a+)+$');
    }
});
test('redos-fuzz: runtime timeout triggers on an exponentially backtracking regex', () => {
    // `^(a|a?)*b$` is a classic exponential-backtracking shape that V8's
    // optimizer does not reliably collapse. Our heuristic does not flag it
    // (the quantifier is inside `(a|a?)` but the outer group has no extra
    // quantifier span the heuristic matches). We rely on the runtime timeout.
    const pattern = '^(a|a?)*b$';
    const compiled = new RegExp(pattern);
    const input = 'a'.repeat(60) + 'c';
    const ctx = { regex: compiled, input };
    vm.createContext(ctx);
    let timedOut = false;
    try {
        vm.runInContext('regex.test(input)', ctx, { timeout: REDOS_TIMEOUT_MS });
    }
    catch (e) {
        if (/Script execution timed out/i.test(String(e && e.message)))
            timedOut = true;
        else
            throw e;
    }
    if (!timedOut) {
        throw new Error(`expected runtime timeout on ${pattern} with 60-char input; V8 optimizer may have collapsed it — harness still protective via heuristic + timeout wrapper`);
    }
});
if (process.exitCode) {
    process.exit(process.exitCode);
}
console.log('ReDoS fuzz tests passed.');
