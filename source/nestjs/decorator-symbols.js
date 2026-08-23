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
exports.resolveStaticDecoratorWrapperCall = resolveStaticDecoratorWrapperCall;
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
function staticPropertyKey(input, checker, check) {
    const seen = new Set();
    let current = input;
    while (true) {
        check();
        const expression = unwrapExpression(current);
        if (typescript_1.default.isStringLiteral(expression) || typescript_1.default.isNumericLiteral(expression)
            || typescript_1.default.isNoSubstitutionTemplateLiteral(expression))
            return expression.text;
        if (!typescript_1.default.isIdentifier(expression))
            return undefined;
        let symbol = checker.getSymbolAtLocation(expression);
        if (!symbol)
            return undefined;
        if (symbol.flags & typescript_1.default.SymbolFlags.Alias)
            symbol = checker.getAliasedSymbol(symbol);
        if (seen.has(symbol))
            return undefined;
        seen.add(symbol);
        const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
        const declaration = declarations.length === 1 ? declarations[0] : undefined;
        if (!declaration?.initializer || !typescript_1.default.isVariableDeclarationList(declaration.parent)
            || !(declaration.parent.flags & typescript_1.default.NodeFlags.Const))
            return undefined;
        current = declaration.initializer;
    }
}
function isNamespaceImportAccess(expression, checker) {
    const callee = unwrapExpression(expression);
    const receiver = typescript_1.default.isPropertyAccessExpression(callee) || typescript_1.default.isElementAccessExpression(callee)
        ? unwrapExpression(callee.expression)
        : undefined;
    return Boolean(receiver && typescript_1.default.isIdentifier(receiver)
        && checker.getSymbolAtLocation(receiver)?.declarations?.some(typescript_1.default.isNamespaceImport));
}
function targetSymbol(node, checker, check) {
    const seen = new Set();
    let current = unwrapExpression(node);
    let selected;
    while (true) {
        check();
        const location = typescript_1.default.isPropertyAccessExpression(current) ? current.name : current;
        const elementKey = typescript_1.default.isElementAccessExpression(current) && current.argumentExpression
            ? staticPropertyKey(current.argumentExpression, checker, check)
            : undefined;
        const symbol = selected ?? (elementKey === undefined
            ? checker.getSymbolAtLocation(location)
            : checker.getTypeAtLocation(current.expression).getProperty(elementKey));
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
            if (!typescript_1.default.isIdentifier(initializer) && !typescript_1.default.isPropertyAccessExpression(initializer)
                && !typescript_1.default.isElementAccessExpression(initializer))
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
    const expression = unwrapExpression(decorator.expression);
    const storedCall = typescript_1.default.isCallExpression(expression)
        ? undefined
        : storedDecoratorCall(expression, checker, check);
    const call = typescript_1.default.isCallExpression(expression) ? expression : storedCall;
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
    const expression = unwrapExpression(decorator.expression);
    const call = typescript_1.default.isCallExpression(expression) ? expression : undefined;
    if (!call)
        return undefined;
    return resolveDecoratorCallSymbol(call, checker, check);
}
function resolveBareDecoratorName(decorator, checker, check) {
    const expression = unwrapExpression(decorator.expression);
    if (typescript_1.default.isCallExpression(expression))
        return undefined;
    const symbol = targetSymbol(expression, checker, check);
    return !symbol || symbol === UNKNOWN_NESTJS_ROUTE ? undefined : symbol.getName();
}
function resolveDecoratorCallSymbol(call, checker, check) {
    const symbol = targetSymbol(call.expression, checker, check);
    if (!symbol || symbol === UNKNOWN_NESTJS_ROUTE) {
        return !symbol && typescript_1.default.isElementAccessExpression(unwrapExpression(call.expression))
            ? { name: '', call, nestJsCommon: false, trustedNestJsCommon: false }
            : undefined;
    }
    const nestJsCommon = originatesFromNestJsCommon(symbol);
    return {
        name: symbol.getName(),
        call,
        nestJsCommon,
        trustedNestJsCommon: nestJsCommon && directNestJsImport(call.expression, checker)
            && matchesConsumerNestJsCommon(call.expression, symbol),
    };
}
function resolveStaticDecoratorWrapperCall(call, checker, projectSources, check) {
    const symbol = targetSymbol(call.expression, checker, check);
    if (!symbol || symbol === UNKNOWN_NESTJS_ROUTE) {
        const callee = unwrapExpression(call.expression);
        const base = typescript_1.default.isElementAccessExpression(callee)
            ? targetSymbol(callee.expression, checker, check)
            : undefined;
        return base && base !== UNKNOWN_NESTJS_ROUTE && base.declarations?.some((candidate) => (projectSources.has(candidate.getSourceFile()))) ? { symbol: base, stable: false, dynamic: true } : undefined;
    }
    const declaration = symbol.declarations?.find((candidate) => projectSources.has(candidate.getSourceFile()) && ((typescript_1.default.isFunctionDeclaration(candidate) && candidate.body !== undefined)
        || (typescript_1.default.isVariableDeclaration(candidate) && candidate.initializer !== undefined
            && (typescript_1.default.isArrowFunction(candidate.initializer) || typescript_1.default.isFunctionExpression(candidate.initializer)))
        || (typescript_1.default.isPropertyAssignment(candidate)
            && (typescript_1.default.isArrowFunction(candidate.initializer) || typescript_1.default.isFunctionExpression(candidate.initializer)))));
    if (!declaration && symbol.declarations?.some((candidate) => (projectSources.has(candidate.getSourceFile()))))
        return { symbol, stable: false, dynamic: true };
    const implementation = declaration && (typescript_1.default.isVariableDeclaration(declaration)
        || typescript_1.default.isPropertyAssignment(declaration))
        ? declaration.initializer
        : declaration;
    if (!implementation || (!typescript_1.default.isFunctionDeclaration(implementation)
        && !typescript_1.default.isArrowFunction(implementation) && !typescript_1.default.isFunctionExpression(implementation)))
        return undefined;
    const unwrappedCallee = unwrapExpression(call.expression);
    const objectAccess = typescript_1.default.isPropertyAccessExpression(unwrappedCallee)
        || typescript_1.default.isElementAccessExpression(unwrappedCallee);
    const stable = Boolean((!objectAccess || isNamespaceImportAccess(unwrappedCallee, checker))
        && declaration && typescript_1.default.isVariableDeclaration(declaration)
        && typescript_1.default.isVariableDeclarationList(declaration.parent)
        && declaration.parent.flags & typescript_1.default.NodeFlags.Const);
    const { body } = implementation;
    if (!body)
        return undefined;
    const resolveReturnedCall = (input, resolving, depth) => {
        check();
        if (depth > 64)
            return { dynamic: true };
        const expression = unwrapExpression(input);
        if (typescript_1.default.isCallExpression(expression))
            return { call: expression, dynamic: false };
        if (typescript_1.default.isFunctionLike(expression) || typescript_1.default.isClassLike(expression))
            return undefined;
        if (typescript_1.default.isIdentifier(expression)) {
            const valueSymbol = targetSymbol(expression, checker, check);
            if (!valueSymbol || valueSymbol === UNKNOWN_NESTJS_ROUTE || resolving.has(valueSymbol)) {
                return { dynamic: true };
            }
            const declarations = valueSymbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
            const value = declarations.length === 1 ? declarations[0] : undefined;
            if (!value?.initializer || !projectSources.has(value.getSourceFile())
                || !typescript_1.default.isVariableDeclarationList(value.parent)
                || !(value.parent.flags & typescript_1.default.NodeFlags.Const))
                return { dynamic: true };
            resolving.add(valueSymbol);
            const resolved = resolveReturnedCall(value.initializer, resolving, depth + 1);
            resolving.delete(valueSymbol);
            return resolved;
        }
        const nodes = [expression];
        while (nodes.length > 0) {
            const node = nodes.pop();
            check();
            if (typescript_1.default.isCallExpression(node))
                return { dynamic: true };
            if (typescript_1.default.isFunctionLike(node) || typescript_1.default.isClassLike(node))
                continue;
            typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
        }
        return { dynamic: true };
    };
    if (!typescript_1.default.isBlock(body)) {
        const resolved = resolveReturnedCall(body, new Set(), 0);
        return resolved && { ...resolved, symbol, stable };
    }
    if (body.statements.length === 1 && typescript_1.default.isReturnStatement(body.statements[0])
        && body.statements[0].expression) {
        const expression = unwrapExpression(body.statements[0].expression);
        if (typescript_1.default.isCallExpression(expression)) {
            return { call: expression, symbol, stable, dynamic: false };
        }
    }
    return { symbol, stable, dynamic: true };
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
