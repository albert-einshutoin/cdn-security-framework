"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NESTJS_ROUTE_DECORATORS = void 0;
exports.nestJsRouteDecoratorCandidate = nestJsRouteDecoratorCandidate;
exports.nestJsRouteDecorator = nestJsRouteDecorator;
exports.isUnsupportedNestJsDecorator = isUnsupportedNestJsDecorator;
const node_module_1 = require("node:module");
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const typescript_1 = __importDefault(require("typescript"));
exports.NESTJS_ROUTE_DECORATORS = [
    'All', 'Controller', 'Delete', 'Get', 'Head', 'Options', 'Patch', 'Post', 'Put', 'RequestMapping', 'Search', 'Sse', 'Version',
];
const UNKNOWN_NESTJS_ROUTE = Symbol('unknown-nestjs-route');
function targetSymbol(node, checker) {
    const unwrap = (expression) => {
        let current = expression;
        while (typescript_1.default.isParenthesizedExpression(current) || typescript_1.default.isAsExpression(current)
            || typescript_1.default.isTypeAssertionExpression(current) || typescript_1.default.isSatisfiesExpression(current)
            || typescript_1.default.isNonNullExpression(current))
            current = current.expression;
        return current;
    };
    const seen = new Set();
    let current = unwrap(node);
    let selected;
    while (true) {
        const location = typescript_1.default.isPropertyAccessExpression(current) ? current.name : current;
        const symbol = selected ?? checker.getSymbolAtLocation(location);
        selected = undefined;
        if (!symbol)
            return undefined;
        const target = symbol.flags & typescript_1.default.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
        if (seen.has(target))
            return undefined;
        seen.add(target);
        const alias = target.declarations?.find((declaration) => (typescript_1.default.isVariableDeclaration(declaration)
            && typescript_1.default.isVariableDeclarationList(declaration.parent)
            && Boolean(declaration.parent.flags & typescript_1.default.NodeFlags.Const)
            && declaration.initializer !== undefined));
        if (alias?.initializer) {
            const initializer = unwrap(alias.initializer);
            if (!typescript_1.default.isIdentifier(initializer) && !typescript_1.default.isPropertyAccessExpression(initializer))
                return target;
            current = initializer;
            continue;
        }
        const binding = target.declarations?.find((declaration) => (typescript_1.default.isBindingElement(declaration) && !declaration.dotDotDotToken
            && typescript_1.default.isObjectBindingPattern(declaration.parent)
            && typescript_1.default.isVariableDeclaration(declaration.parent.parent)
            && typescript_1.default.isVariableDeclarationList(declaration.parent.parent.parent)
            && Boolean(declaration.parent.parent.parent.flags & typescript_1.default.NodeFlags.Const)
            && declaration.parent.parent.initializer !== undefined));
        const property = binding?.propertyName ?? binding?.name;
        if (!binding || !property)
            return target;
        const initializer = unwrap(binding.parent.parent.initializer);
        if (typescript_1.default.isComputedPropertyName(property)) {
            const namespaceType = checker.getTypeAtLocation(initializer);
            return exports.NESTJS_ROUTE_DECORATORS.some((name) => (originatesFromNestJsCommon(namespaceType.getProperty(name)))) ? UNKNOWN_NESTJS_ROUTE : target;
        }
        if (!typescript_1.default.isIdentifier(property) && !typescript_1.default.isStringLiteral(property))
            return target;
        selected = checker.getTypeAtLocation(initializer).getProperty(property.text);
        if (!selected)
            return target;
        current = initializer;
    }
}
function importDeclaration(declaration) {
    let current = declaration;
    while (current && !typescript_1.default.isImportDeclaration(current))
        current = current.parent;
    return current;
}
function directNestJsImport(node, checker) {
    if (typescript_1.default.isIdentifier(node)) {
        return Boolean(checker.getSymbolAtLocation(node)?.declarations?.some((declaration) => {
            const imported = importDeclaration(declaration);
            return typescript_1.default.isImportSpecifier(declaration) && Boolean(imported)
                && typescript_1.default.isStringLiteral(imported.moduleSpecifier)
                && imported.moduleSpecifier.text === '@nestjs/common';
        }));
    }
    if (!typescript_1.default.isPropertyAccessExpression(node) || !typescript_1.default.isIdentifier(node.expression))
        return false;
    return Boolean(checker.getSymbolAtLocation(node.expression)?.declarations?.some((declaration) => {
        const imported = importDeclaration(declaration);
        return typescript_1.default.isNamespaceImport(declaration) && Boolean(imported)
            && typescript_1.default.isStringLiteral(imported.moduleSpecifier)
            && imported.moduleSpecifier.text === '@nestjs/common';
    }));
}
function packageRoot(fileName) {
    let directory = node_path_1.default.dirname(node_path_1.default.resolve(fileName));
    while (true) {
        if (node_path_1.default.basename(directory) === 'common'
            && node_path_1.default.basename(node_path_1.default.dirname(directory)) === '@nestjs'
            && node_path_1.default.basename(node_path_1.default.dirname(node_path_1.default.dirname(directory))) === 'node_modules')
            return directory;
        const parent = node_path_1.default.dirname(directory);
        if (parent === directory)
            return undefined;
        directory = parent;
    }
}
function originatesFromNestJsCommon(symbol) {
    return Boolean(symbol?.declarations?.some((declaration) => {
        const targetRoot = packageRoot(declaration.getSourceFile().fileName);
        if (!targetRoot)
            return false;
        try {
            const resolvedRoot = packageRoot((0, node_module_1.createRequire)(declaration.getSourceFile().fileName).resolve('@nestjs/common'));
            return resolvedRoot !== undefined && node_fs_1.default.realpathSync(targetRoot) === node_fs_1.default.realpathSync(resolvedRoot);
        }
        catch {
            return false;
        }
    }));
}
function matchesConsumerNestJsCommon(node, symbol) {
    let resolvedRoot;
    try {
        resolvedRoot = packageRoot((0, node_module_1.createRequire)(node.getSourceFile().fileName).resolve('@nestjs/common'));
    }
    catch {
        return false;
    }
    if (!resolvedRoot)
        return false;
    return Boolean(symbol?.declarations?.some((declaration) => {
        const targetRoot = packageRoot(declaration.getSourceFile().fileName);
        return targetRoot !== undefined && node_fs_1.default.realpathSync(targetRoot) === node_fs_1.default.realpathSync(resolvedRoot);
    }));
}
function match(decorator, checker) {
    if (!typescript_1.default.isCallExpression(decorator.expression))
        return undefined;
    const symbol = targetSymbol(decorator.expression.expression, checker);
    if (symbol === UNKNOWN_NESTJS_ROUTE) {
        return { name: 'Unknown', call: decorator.expression, trusted: false, nestJsOrigin: true };
    }
    const name = symbol?.getName();
    if (!name || !exports.NESTJS_ROUTE_DECORATORS.includes(name))
        return undefined;
    const nestJsOrigin = originatesFromNestJsCommon(symbol);
    return {
        name,
        call: decorator.expression,
        trusted: directNestJsImport(decorator.expression.expression, checker)
            && matchesConsumerNestJsCommon(decorator.expression.expression, symbol),
        nestJsOrigin,
    };
}
function nestJsRouteDecoratorCandidate(decorator, checker) {
    const result = match(decorator, checker);
    return result?.nestJsOrigin
        ? { name: result.name, call: result.call, trusted: result.trusted }
        : undefined;
}
function nestJsRouteDecorator(decorator, checker) {
    const result = match(decorator, checker);
    return result?.trusted && result.name !== 'Unknown'
        ? { name: result.name, call: result.call }
        : undefined;
}
function isUnsupportedNestJsDecorator(decorator, checker) {
    const result = match(decorator, checker);
    return Boolean(result && (!result.trusted
        || result.name === 'RequestMapping' || result.name === 'Search' || result.name === 'Version'));
}
