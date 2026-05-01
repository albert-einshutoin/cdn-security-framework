"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.assertNoConfigBindingShadow = assertNoConfigBindingShadow;
exports.assertBundledConfigBindings = assertBundledConfigBindings;
exports.buildBundlerEmitterPrototype = buildBundlerEmitterPrototype;
const acorn = require('acorn');
const esbuild = require('esbuild');
function parseForPrototypeInspection(code, loader) {
    let jsCode = code;
    if (loader === 'ts') {
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
function visitNode(node, visit) {
    if (!node || typeof node !== 'object')
        return;
    const astNode = node;
    visit(astNode);
    for (const [key, value] of Object.entries(astNode)) {
        if (key === 'parent')
            continue;
        if (Array.isArray(value)) {
            for (const item of value)
                visitNode(item, visit);
        }
        else if (value && typeof value === 'object') {
            visitNode(value, visit);
        }
    }
}
function identifierName(node) {
    return node && node.type === 'Identifier' && typeof node.name === 'string'
        ? node.name
        : null;
}
function collectPatternBindingNames(node, names, matches) {
    if (!node)
        return;
    const name = identifierName(node);
    if (name) {
        if (names.has(name))
            matches.push(name);
        return;
    }
    if (node.type === 'ObjectPattern') {
        for (const property of node.properties || []) {
            if (property.type === 'RestElement') {
                collectPatternBindingNames(property.argument, names, matches);
            }
            else {
                collectPatternBindingNames(property.value, names, matches);
            }
        }
        return;
    }
    if (node.type === 'ArrayPattern') {
        for (const element of node.elements || []) {
            collectPatternBindingNames(element, names, matches);
        }
        return;
    }
    if (node.type === 'AssignmentPattern') {
        collectPatternBindingNames(node.left, names, matches);
        return;
    }
    if (node.type === 'RestElement') {
        collectPatternBindingNames(node.argument, names, matches);
    }
}
function collectBindingNames(node, names, moduleName) {
    const matches = [];
    visitNode(node, (entry) => {
        if (entry.type === 'ImportDeclaration') {
            if (entry.source && entry.source.value === moduleName)
                return;
            for (const specifier of entry.specifiers || []) {
                const local = identifierName(specifier.local || null);
                if (local && names.has(local))
                    matches.push(local);
            }
            return;
        }
        if (entry.type === 'VariableDeclarator') {
            collectPatternBindingNames(entry.id || null, names, matches);
            return;
        }
        if (entry.type === 'FunctionDeclaration' ||
            entry.type === 'FunctionExpression' ||
            entry.type === 'ArrowFunctionExpression') {
            const name = identifierName(entry.id || null);
            if (name && names.has(name))
                matches.push(name);
            for (const param of entry.params || []) {
                collectPatternBindingNames(param, names, matches);
            }
            return;
        }
        if (entry.type === 'ClassDeclaration' || entry.type === 'ClassExpression') {
            const name = identifierName(entry.id || null);
            if (name && names.has(name))
                matches.push(name);
        }
    });
    return matches;
}
function assertNoConfigBindingShadow(source, configNames, options = {}) {
    const loader = options.loader || 'js';
    const moduleName = options.configModuleName || 'cdn-security:config';
    const names = new Set(configNames);
    const ast = parseForPrototypeInspection(source, loader);
    const matches = collectBindingNames(ast, names, moduleName);
    if (matches.length > 0) {
        throw new Error(`Bundler emitter prototype source shadows config binding(s): ${Array.from(new Set(matches)).join(', ')}`);
    }
}
function assertBundledConfigBindings(code, configNames) {
    const ast = parseForPrototypeInspection(code, 'js');
    const body = Array.isArray(ast.body) ? ast.body : [];
    for (const configName of configNames) {
        let count = 0;
        for (const node of body) {
            if (node.type !== 'VariableDeclaration' ||
                !Array.isArray(node.declarations)) {
                continue;
            }
            for (const declaration of node.declarations) {
                if (identifierName(declaration.id || null) === configName) {
                    count += 1;
                }
            }
        }
        if (count !== 1) {
            throw new Error(`Bundled config binding ${configName} must appear exactly once at top level, found ${count}`);
        }
    }
}
function renderConfigModule(configExports) {
    return Object.entries(configExports)
        .map(([name, value]) => `export const ${name} = ${JSON.stringify(value)};`)
        .join('\n');
}
async function buildBundlerEmitterPrototype(options) {
    const loader = options.loader || 'js';
    const configModuleName = options.configModuleName || 'cdn-security:config';
    const configNames = Object.keys(options.configExports);
    assertNoConfigBindingShadow(options.source, configNames, { loader, configModuleName });
    const result = await esbuild.build({
        stdin: {
            contents: options.source,
            sourcefile: options.sourcefile || 'edge-entry.js',
            loader,
        },
        bundle: true,
        write: false,
        format: 'esm',
        platform: 'neutral',
        target: 'es2022',
        plugins: [{
                name: 'cdn-security-config-prototype',
                setup(build) {
                    build.onResolve({ filter: new RegExp(`^${configModuleName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`) }, (args) => ({
                        path: args.path,
                        namespace: 'cdn-security-config',
                    }));
                    build.onLoad({ filter: /.*/, namespace: 'cdn-security-config' }, () => ({
                        contents: renderConfigModule(options.configExports),
                        loader: 'js',
                    }));
                },
            }],
    });
    const code = result.outputFiles[0].text;
    assertBundledConfigBindings(code, configNames);
    return { code, configNames };
}
