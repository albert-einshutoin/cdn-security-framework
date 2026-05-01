"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
function runtimeCode(code) {
    return { __runtimeCode: code };
}
function isRuntimeLiteral(value) {
    return Boolean(value &&
        typeof value === 'object' &&
        typeof value.__runtimeCode === 'string');
}
function renderValue(value) {
    if (isRuntimeLiteral(value))
        return value.__runtimeCode;
    return JSON.stringify(value);
}
function renderConstObject(name, value) {
    const lines = [`const ${name} = {`];
    for (const [key, entryValue] of Object.entries(value)) {
        lines.push(`  ${key}: ${renderValue(entryValue)},`);
    }
    lines.push('};');
    return lines.join('\n');
}
function injectTemplateCode(template, marker, code) {
    const count = template.split(marker).length - 1;
    if (count !== 1) {
        throw new Error(`Template marker ${marker} must appear exactly once, found ${count}`);
    }
    return template.replace(marker, code);
}
function parseForConstInspection(code, loader) {
    const acorn = require('acorn');
    let jsCode = code;
    if (loader === 'ts') {
        const esbuild = require('esbuild');
        jsCode = esbuild.transformSync(code, {
            loader: 'ts',
            format: 'esm',
            target: 'es2022',
        }).code;
    }
    return acorn.parse(jsCode, {
        ecmaVersion: 'latest',
        sourceType: 'module',
    });
}
function assertInjectedConstDeclarations(code, constNames, options = {}) {
    const loader = options.loader || 'js';
    const ast = parseForConstInspection(code, loader);
    for (const constName of constNames) {
        let count = 0;
        for (const node of ast.body || []) {
            if (node.type !== 'VariableDeclaration' || node.kind !== 'const')
                continue;
            for (const declaration of node.declarations || []) {
                if (declaration.id &&
                    declaration.id.type === 'Identifier' &&
                    declaration.id.name === constName) {
                    count += 1;
                }
            }
        }
        if (count !== 1) {
            throw new Error(`Injected config const ${constName} must appear exactly once at top level, found ${count}`);
        }
    }
}
module.exports = {
    assertInjectedConstDeclarations,
    injectTemplateCode,
    renderConstObject,
    runtimeCode,
};
