"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NESTJS_ROUTE_DECORATORS = void 0;
exports.classifyNestJsRouteDecorator = classifyNestJsRouteDecorator;
exports.resolveDecoratorSymbol = resolveDecoratorSymbol;
exports.resolveBareDecoratorName = resolveBareDecoratorName;
exports.resolveDecoratorCallSymbol = resolveDecoratorCallSymbol;
exports.resolveStaticSymbolName = resolveStaticSymbolName;
exports.isStaticSymbolFrom = isStaticSymbolFrom;
exports.isStaticShorthandSymbolFrom = isStaticShorthandSymbolFrom;
exports.isNestJsUseGlobalGuardsCall = isNestJsUseGlobalGuardsCall;
const node_module_1 = require("node:module");
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const typescript_1 = __importDefault(require("typescript"));
exports.NESTJS_ROUTE_DECORATORS = [
    'All', 'Controller', 'Delete', 'Get', 'Head', 'Options', 'Patch', 'Post', 'Put', 'RequestMapping', 'Search', 'Sse', 'Version',
];
const UNKNOWN_NESTJS_ROUTE = Symbol('unknown-nestjs-route');
const MAX_COMPOSED_DECORATORS = 256;
const NESTJS_ORIGIN_CACHE = new WeakMap();
function unwrapExpression(expression) {
    let current = expression;
    while (typescript_1.default.isParenthesizedExpression(current) || typescript_1.default.isAsExpression(current)
        || typescript_1.default.isTypeAssertionExpression(current) || typescript_1.default.isSatisfiesExpression(current)
        || typescript_1.default.isNonNullExpression(current))
        current = current.expression;
    return current;
}
function targetSymbol(node, checker, check) {
    const seen = new Set();
    let current = unwrapExpression(node);
    let selected;
    while (true) {
        check();
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
            const initializer = unwrapExpression(alias.initializer);
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
        const initializer = unwrapExpression(binding.parent.parent.initializer);
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
function storedDecoratorCall(expression, checker, check) {
    const seen = new Set();
    let current = expression;
    while (true) {
        const symbol = targetSymbol(current, checker, check);
        if (!symbol || symbol === UNKNOWN_NESTJS_ROUTE || seen.has(symbol))
            return undefined;
        seen.add(symbol);
        const declaration = symbol.declarations?.find((candidate) => ((typescript_1.default.isVariableDeclaration(candidate) || typescript_1.default.isPropertyAssignment(candidate))
            ? candidate.initializer !== undefined
            : typescript_1.default.isShorthandPropertyAssignment(candidate)));
        let initializer = declaration && !typescript_1.default.isShorthandPropertyAssignment(declaration)
            ? declaration.initializer
            : undefined;
        if (declaration && typescript_1.default.isShorthandPropertyAssignment(declaration)) {
            const valueSymbol = checker.getShorthandAssignmentValueSymbol(declaration);
            initializer = valueSymbol?.declarations?.find((candidate) => (typescript_1.default.isVariableDeclaration(candidate) && candidate.initializer !== undefined))?.initializer;
        }
        const unwrapped = initializer && unwrapExpression(initializer);
        if (!unwrapped)
            return undefined;
        if (typescript_1.default.isCallExpression(unwrapped))
            return unwrapped;
        if (!typescript_1.default.isIdentifier(unwrapped) && !typescript_1.default.isPropertyAccessExpression(unwrapped))
            return undefined;
        current = unwrapped;
    }
}
function composesNestJsRoute(call, checker, check, budget) {
    return call.arguments.some((argument) => {
        check();
        budget.remaining -= 1;
        if (budget.remaining < 0)
            return true;
        if (typescript_1.default.isSpreadElement(argument))
            return true;
        if (!typescript_1.default.isCallExpression(argument))
            return true;
        const symbol = targetSymbol(argument.expression, checker, check);
        if (!symbol || symbol === UNKNOWN_NESTJS_ROUTE || !originatesFromNestJsCommon(symbol))
            return false;
        const name = symbol.getName();
        if (exports.NESTJS_ROUTE_DECORATORS.includes(name))
            return true;
        return name === 'applyDecorators' && composesNestJsRoute(argument, checker, check, budget);
    });
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
function packageRoot(fileName, moduleName) {
    const segments = moduleName.split('/');
    let directory = node_path_1.default.dirname(node_path_1.default.resolve(fileName));
    while (true) {
        let candidate = directory;
        let matches = true;
        for (let index = segments.length - 1; index >= 0; index -= 1) {
            if (node_path_1.default.basename(candidate) !== segments[index])
                matches = false;
            candidate = node_path_1.default.dirname(candidate);
        }
        if (matches && node_path_1.default.basename(candidate) === 'node_modules')
            return directory;
        const parent = node_path_1.default.dirname(directory);
        if (parent === directory)
            return undefined;
        directory = parent;
    }
}
function originatesFromNestJsCommon(symbol) {
    if (!symbol)
        return false;
    const cached = NESTJS_ORIGIN_CACHE.get(symbol);
    if (cached !== undefined)
        return cached;
    const result = Boolean(symbol.declarations?.some((declaration) => {
        const targetRoot = packageRoot(declaration.getSourceFile().fileName, '@nestjs/common');
        if (!targetRoot)
            return false;
        try {
            const resolvedRoot = packageRoot((0, node_module_1.createRequire)(declaration.getSourceFile().fileName).resolve('@nestjs/common'), '@nestjs/common');
            return resolvedRoot !== undefined && node_fs_1.default.realpathSync(targetRoot) === node_fs_1.default.realpathSync(resolvedRoot);
        }
        catch {
            return false;
        }
    }));
    NESTJS_ORIGIN_CACHE.set(symbol, result);
    return result;
}
function matchesConsumerModule(node, symbol, moduleName) {
    let resolvedRoot;
    try {
        resolvedRoot = packageRoot((0, node_module_1.createRequire)(node.getSourceFile().fileName).resolve(moduleName), moduleName);
    }
    catch {
        return false;
    }
    if (!resolvedRoot)
        return false;
    return Boolean(symbol?.declarations?.some((declaration) => {
        const targetRoot = packageRoot(declaration.getSourceFile().fileName, moduleName);
        return targetRoot !== undefined && node_fs_1.default.realpathSync(targetRoot) === node_fs_1.default.realpathSync(resolvedRoot);
    }));
}
function matchesConsumerNestJsCommon(node, symbol) {
    return matchesConsumerModule(node, symbol, '@nestjs/common');
}
function match(decorator, checker, check) {
    const storedCall = typescript_1.default.isCallExpression(decorator.expression)
        ? undefined
        : storedDecoratorCall(decorator.expression, checker, check);
    const call = typescript_1.default.isCallExpression(decorator.expression) ? decorator.expression : storedCall;
    if (!call)
        return undefined;
    const symbol = targetSymbol(call.expression, checker, check);
    if (symbol === UNKNOWN_NESTJS_ROUTE) {
        return { name: 'Unknown', call, trusted: false, nestJsOrigin: true };
    }
    const name = symbol?.getName();
    if (storedCall && originatesFromNestJsCommon(symbol) && (exports.NESTJS_ROUTE_DECORATORS.includes(name)
        || (name === 'applyDecorators' && composesNestJsRoute(call, checker, check, { remaining: MAX_COMPOSED_DECORATORS }))))
        return { name: 'Unknown', call, trusted: false, nestJsOrigin: true };
    if (name === 'applyDecorators' && originatesFromNestJsCommon(symbol)
        && composesNestJsRoute(call, checker, check, { remaining: MAX_COMPOSED_DECORATORS })) {
        return { name: 'Unknown', call, trusted: false, nestJsOrigin: true };
    }
    if (!name || !exports.NESTJS_ROUTE_DECORATORS.includes(name))
        return undefined;
    const nestJsOrigin = originatesFromNestJsCommon(symbol);
    return {
        name: name,
        call,
        trusted: directNestJsImport(call.expression, checker)
            && matchesConsumerNestJsCommon(call.expression, symbol),
        nestJsOrigin,
    };
}
function classifyNestJsRouteDecorator(decorator, checker, check) {
    const result = match(decorator, checker, check);
    return {
        ...(result?.nestJsOrigin ? {
            candidate: { name: result.name, call: result.call, trusted: result.trusted },
        } : {}),
        ...(result?.trusted && result.name !== 'Unknown' ? {
            route: { name: result.name, call: result.call },
        } : {}),
        unsupported: Boolean(result && (!result.trusted
            || result.name === 'RequestMapping' || result.name === 'Search' || result.name === 'Version')),
    };
}
function resolveDecoratorSymbol(decorator, checker, check) {
    const call = typescript_1.default.isCallExpression(decorator.expression) ? decorator.expression : undefined;
    if (!call)
        return undefined;
    return resolveDecoratorCallSymbol(call, checker, check);
}
function resolveBareDecoratorName(decorator, checker, check) {
    if (typescript_1.default.isCallExpression(decorator.expression))
        return undefined;
    const symbol = targetSymbol(decorator.expression, checker, check);
    return !symbol || symbol === UNKNOWN_NESTJS_ROUTE ? undefined : symbol.getName();
}
function resolveDecoratorCallSymbol(call, checker, check) {
    const symbol = targetSymbol(call.expression, checker, check);
    if (!symbol || symbol === UNKNOWN_NESTJS_ROUTE)
        return undefined;
    const nestJsCommon = originatesFromNestJsCommon(symbol);
    return {
        name: symbol.getName(),
        call,
        nestJsCommon,
        trustedNestJsCommon: nestJsCommon && directNestJsImport(call.expression, checker)
            && matchesConsumerNestJsCommon(call.expression, symbol),
    };
}
function resolveStaticSymbolName(expression, checker, check) {
    const symbol = targetSymbol(expression, checker, check);
    return !symbol || symbol === UNKNOWN_NESTJS_ROUTE
        || !symbol.declarations?.some(typescript_1.default.isClassLike) ? undefined : symbol.getName();
}
function isResolvedSymbolFrom(symbol, source, moduleName, importedName) {
    if (symbol.getName() !== importedName)
        return false;
    let resolvedRoot;
    try {
        resolvedRoot = packageRoot((0, node_module_1.createRequire)(source.getSourceFile().fileName).resolve(moduleName), moduleName);
    }
    catch {
        return false;
    }
    return Boolean(resolvedRoot && symbol.declarations?.some((declaration) => {
        const targetRoot = packageRoot(declaration.getSourceFile().fileName, moduleName);
        return targetRoot !== undefined && node_fs_1.default.realpathSync(targetRoot) === node_fs_1.default.realpathSync(resolvedRoot);
    }));
}
function isStaticSymbolFrom(expression, checker, check, moduleName, importedName) {
    const symbol = targetSymbol(expression, checker, check);
    return Boolean(symbol && symbol !== UNKNOWN_NESTJS_ROUTE
        && isResolvedSymbolFrom(symbol, expression, moduleName, importedName));
}
function isStaticShorthandSymbolFrom(shorthand, checker, check, moduleName, importedName) {
    const symbol = checker.getShorthandAssignmentValueSymbol(shorthand);
    if (!symbol)
        return false;
    const target = symbol.flags & typescript_1.default.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
    if (isResolvedSymbolFrom(target, shorthand, moduleName, importedName))
        return true;
    const declaration = symbol.declarations?.find((candidate) => (typescript_1.default.isVariableDeclaration(candidate) && candidate.initializer !== undefined
        && typescript_1.default.isVariableDeclarationList(candidate.parent)
        && Boolean(candidate.parent.flags & typescript_1.default.NodeFlags.Const)));
    return Boolean(declaration?.initializer && isStaticSymbolFrom(declaration.initializer, checker, check, moduleName, importedName));
}
function isNestJsUseGlobalGuardsCall(call, checker) {
    if (!typescript_1.default.isPropertyAccessExpression(call.expression)
        || call.expression.name.text !== 'useGlobalGuards') {
        return false;
    }
    const symbol = checker.getSymbolAtLocation(call.expression.name);
    return matchesConsumerModule(call.expression, symbol, '@nestjs/common')
        || matchesConsumerModule(call.expression, symbol, '@nestjs/core');
}
