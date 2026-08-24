"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NESTJS_ROUTE_DECORATORS = void 0;
exports.isDefinitelyNonProvidePropertyKey = isDefinitelyNonProvidePropertyKey;
exports.resolveStaticPropertyKey = resolveStaticPropertyKey;
exports.classifyNestJsRouteDecorator = classifyNestJsRouteDecorator;
exports.resolveDecoratorSymbol = resolveDecoratorSymbol;
exports.resolveBareDecoratorName = resolveBareDecoratorName;
exports.isBareDecoratorBindingStable = isBareDecoratorBindingStable;
exports.resolveDecoratorCallSymbol = resolveDecoratorCallSymbol;
exports.resolveStaticDecoratorWrapperCall = resolveStaticDecoratorWrapperCall;
exports.resolveStaticSymbolName = resolveStaticSymbolName;
exports.isStaticSymbolFrom = isStaticSymbolFrom;
exports.containsStaticSymbolFrom = containsStaticSymbolFrom;
exports.isStaticShorthandSymbolFrom = isStaticShorthandSymbolFrom;
exports.isNestJsUseGlobalGuardsCall = isNestJsUseGlobalGuardsCall;
const node_module_1 = require("node:module");
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const typescript_1 = __importDefault(require("typescript"));
const static_string_resolver_js_1 = require("./static-string-resolver.js");
exports.NESTJS_ROUTE_DECORATORS = [
    'All', 'Controller', 'Delete', 'Get', 'Head', 'Options', 'Patch', 'Post', 'Put', 'RequestMapping', 'Search', 'Sse', 'Version',
];
const UNKNOWN_NESTJS_ROUTE = Symbol('unknown-nestjs-route');
const MAX_COMPOSED_DECORATORS = 256;
const NESTJS_ORIGIN_CACHE = new WeakMap();
const MEMBER_ESCAPE_CACHE = new WeakMap();
const MEMBER_REFERENCE_CACHE = new WeakMap();
const CALLABLE_REFERENCE_CACHE = new WeakMap();
const BARE_RECEIVER_STABILITY_CACHE = new WeakMap();
const WRAPPER_MUTATION_CACHE = new WeakMap();
const WRAPPED_RECEIVER_CACHE = new WeakMap();
const CALLABLE_WRITE_INDEX_CACHE = new WeakMap();
function callableWriteIndex(projectSources, checker, check) {
    const cached = CALLABLE_WRITE_INDEX_CACHE.get(projectSources);
    if (cached)
        return cached;
    const index = new Map();
    const isNestedAssignmentTarget = (node) => {
        let child = node;
        while (child.parent && !typescript_1.default.isStatement(child.parent)) {
            const parent = child.parent;
            if (typescript_1.default.isBinaryExpression(parent) && parent.left === child
                && parent.operatorToken.kind >= typescript_1.default.SyntaxKind.FirstAssignment
                && parent.operatorToken.kind <= typescript_1.default.SyntaxKind.LastAssignment)
                return true;
            child = parent;
        }
        return false;
    };
    const recordSymbol = (target, record) => {
        let symbol = typescript_1.default.isShorthandPropertyAssignment(target.parent) && target.parent.name === target
            ? checker.getShorthandAssignmentValueSymbol(target.parent)
            : checker.getSymbolAtLocation(target);
        if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
            symbol = checker.getAliasedSymbol(symbol);
        if (!symbol)
            return;
        const records = index.get(symbol) ?? [];
        records.push(record);
        index.set(symbol, records);
    };
    const fallback = (target, record) => {
        const current = typescript_1.default.isExpression(target) ? unwrapExpression(target) : target;
        if (typescript_1.default.isIdentifier(current)) {
            recordSymbol(current, record);
        }
        else if (typescript_1.default.isBinaryExpression(current)
            && current.operatorToken.kind === typescript_1.default.SyntaxKind.EqualsToken) {
            fallback(current.left, record);
        }
        else if (typescript_1.default.isArrayLiteralExpression(current)) {
            for (const element of current.elements) {
                if (!typescript_1.default.isOmittedExpression(element))
                    fallback(typescript_1.default.isSpreadElement(element) ? element.expression : element, record);
            }
        }
        else if (typescript_1.default.isObjectLiteralExpression(current)) {
            for (const property of current.properties) {
                if (typescript_1.default.isShorthandPropertyAssignment(property))
                    fallback(property.name, record);
                else if (typescript_1.default.isPropertyAssignment(property))
                    fallback(property.initializer, record);
                else if (typescript_1.default.isSpreadAssignment(property))
                    fallback(property.expression, record);
            }
        }
    };
    const undefinedState = (input, seen = new Set(), depth = 0) => {
        if (depth >= 64)
            return undefined;
        const value = unwrapExpression(input);
        if (typescript_1.default.isVoidExpression(value))
            return true;
        if (value.kind === typescript_1.default.SyntaxKind.NullKeyword || typescript_1.default.isStringLiteralLike(value)
            || typescript_1.default.isNumericLiteral(value) || value.kind === typescript_1.default.SyntaxKind.TrueKeyword
            || value.kind === typescript_1.default.SyntaxKind.FalseKeyword || typescript_1.default.isObjectLiteralExpression(value)
            || typescript_1.default.isArrayLiteralExpression(value) || typescript_1.default.isFunctionExpression(value)
            || typescript_1.default.isArrowFunction(value) || typescript_1.default.isClassExpression(value))
            return false;
        if (!typescript_1.default.isIdentifier(value))
            return undefined;
        let symbol = checker.getSymbolAtLocation(value);
        if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
            symbol = checker.getAliasedSymbol(symbol);
        if (value.text === 'undefined' && (!symbol || !symbol.declarations?.length))
            return true;
        if (!symbol || seen.has(symbol))
            return undefined;
        const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
        const declaration = declarations.length === 1 ? declarations[0] : undefined;
        if (!declaration?.initializer || !typescript_1.default.isVariableDeclarationList(declaration.parent)
            || !(declaration.parent.flags & typescript_1.default.NodeFlags.Const))
            return undefined;
        return undefinedState(declaration.initializer, new Set(seen).add(symbol), depth + 1);
    };
    const add = (target, record) => {
        const current = unwrapExpression(target);
        if (typescript_1.default.isIdentifier(current)) {
            recordSymbol(current, record);
            return;
        }
        if (typescript_1.default.isBinaryExpression(current)
            && current.operatorToken.kind === typescript_1.default.SyntaxKind.EqualsToken) {
            const state = record.value ? undefinedState(record.value) : true;
            if (state !== true)
                add(current.left, record);
            if (state !== false) {
                add(current.left, { ...record, value: current.right, directTopLevel: false });
            }
            return;
        }
        const value = record.value && unwrapExpression(record.value);
        if (typescript_1.default.isArrayLiteralExpression(current) && value && typescript_1.default.isArrayLiteralExpression(value)
            && !current.elements.some(typescript_1.default.isSpreadElement) && !value.elements.some(typescript_1.default.isSpreadElement)) {
            for (let index = 0; index < current.elements.length; index += 1) {
                const element = current.elements[index];
                if (typescript_1.default.isOmittedExpression(element))
                    continue;
                const assigned = value.elements[index];
                add(element, {
                    ...record,
                    ...(assigned && !typescript_1.default.isOmittedExpression(assigned) ? { value: assigned } : { value: undefined }),
                    directTopLevel: false,
                });
            }
            return;
        }
        if (typescript_1.default.isObjectLiteralExpression(current) && value && typescript_1.default.isObjectLiteralExpression(value)
            && !current.properties.some(typescript_1.default.isSpreadAssignment)
            && !value.properties.some(typescript_1.default.isSpreadAssignment)) {
            for (const property of current.properties) {
                const key = typescript_1.default.isShorthandPropertyAssignment(property) ? property.name.text
                    : typescript_1.default.isPropertyAssignment(property) && (typescript_1.default.isIdentifier(property.name)
                        || typescript_1.default.isStringLiteral(property.name) || typescript_1.default.isNumericLiteral(property.name))
                        ? property.name.text : undefined;
                const nestedTarget = typescript_1.default.isShorthandPropertyAssignment(property) ? property.name
                    : typescript_1.default.isPropertyAssignment(property) ? property.initializer : undefined;
                if (!key || !nestedTarget) {
                    fallback(property, { ...record, directTopLevel: false, uncertainCanonical: true });
                    continue;
                }
                let candidates = [];
                for (const source of value.properties) {
                    if (typescript_1.default.isSpreadAssignment(source)) {
                        candidates.push({ value: source.expression, uncertainCanonical: true });
                        continue;
                    }
                    const sourceKey = typescript_1.default.isComputedPropertyName(source.name)
                        ? resolveStaticPropertyKey(source.name.expression, checker, check)
                        : (typescript_1.default.isIdentifier(source.name)
                            || typescript_1.default.isStringLiteral(source.name) || typescript_1.default.isNumericLiteral(source.name))
                            ? source.name.text : undefined;
                    const assigned = typescript_1.default.isShorthandPropertyAssignment(source) ? source.name
                        : typescript_1.default.isPropertyAssignment(source) ? source.initializer : undefined;
                    const uncertainCanonical = !assigned;
                    if (sourceKey === key)
                        candidates = [{ ...(assigned ? { value: assigned } : {}), uncertainCanonical }];
                    else if (sourceKey === undefined)
                        candidates.push({
                            ...(assigned ? { value: assigned } : {}), uncertainCanonical: true,
                        });
                }
                if (candidates.length === 0) {
                    add(nestedTarget, { ...record, value: undefined, directTopLevel: false });
                }
                else {
                    for (const candidate of candidates)
                        add(nestedTarget, {
                            ...record, ...candidate, directTopLevel: false,
                        });
                }
            }
            return;
        }
        fallback(current, { ...record, directTopLevel: false, uncertainCanonical: true });
    };
    for (const sourceFile of projectSources) {
        const nodes = [sourceFile];
        while (nodes.length > 0) {
            check();
            const node = nodes.pop();
            if (typescript_1.default.isBinaryExpression(node)
                && node.operatorToken.kind >= typescript_1.default.SyntaxKind.FirstAssignment
                && node.operatorToken.kind <= typescript_1.default.SyntaxKind.LastAssignment
                && !isNestedAssignmentTarget(node)) {
                const target = unwrapExpression(node.left);
                add(target, {
                    sourceFile,
                    start: node.getStart(),
                    directTopLevel: node.operatorToken.kind === typescript_1.default.SyntaxKind.EqualsToken
                        && typescript_1.default.isIdentifier(target) && typescript_1.default.isExpressionStatement(node.parent)
                        && typescript_1.default.isSourceFile(node.parent.parent),
                    ...(node.operatorToken.kind === typescript_1.default.SyntaxKind.EqualsToken ? { value: node.right } : {}),
                });
            }
            else if (typescript_1.default.isForOfStatement(node) || typescript_1.default.isForInStatement(node)) {
                if (!typescript_1.default.isVariableDeclarationList(node.initializer))
                    add(node.initializer, {
                        sourceFile, start: node.getStart(), directTopLevel: false,
                    });
            }
            else if ((typescript_1.default.isPrefixUnaryExpression(node) || typescript_1.default.isPostfixUnaryExpression(node))
                && (node.operator === typescript_1.default.SyntaxKind.PlusPlusToken
                    || node.operator === typescript_1.default.SyntaxKind.MinusMinusToken)) {
                add(node.operand, { sourceFile, start: node.getStart(), directTopLevel: false });
            }
            typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
        }
    }
    CALLABLE_WRITE_INDEX_CACHE.set(projectSources, index);
    return index;
}
function callableBindingMayBeWritten(symbol, declarations, checker, projectSources, check) {
    let projectCache = projectSources && CALLABLE_REFERENCE_CACHE.get(projectSources);
    if (projectSources && !projectCache) {
        projectCache = new WeakMap();
        CALLABLE_REFERENCE_CACHE.set(projectSources, projectCache);
    }
    const cached = projectCache?.get(symbol);
    if (cached !== undefined)
        return cached;
    let written = false;
    const references = projectSources ? [...projectSources] : [];
    while (references.length > 0 && !written) {
        const reference = references.pop();
        check();
        if (typescript_1.default.isIdentifier(reference)) {
            let referenceSymbol = checker.getSymbolAtLocation(reference);
            if (referenceSymbol?.flags && referenceSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                referenceSymbol = checker.getAliasedSymbol(referenceSymbol);
            }
            if (referenceSymbol === symbol) {
                const declarationName = declarations.some((declaration) => ('name' in declaration && declaration.name === reference));
                let usage = reference;
                while (typescript_1.default.isParenthesizedExpression(usage.parent)
                    || typescript_1.default.isAsExpression(usage.parent) || typescript_1.default.isTypeAssertionExpression(usage.parent)
                    || typescript_1.default.isSatisfiesExpression(usage.parent) || typescript_1.default.isNonNullExpression(usage.parent)) {
                    usage = usage.parent;
                }
                let target = usage;
                while (!declarationName && target.parent && !typescript_1.default.isStatement(target)) {
                    const parent = target.parent;
                    if (typescript_1.default.isBinaryExpression(parent) && parent.left === target
                        && parent.operatorToken.kind >= typescript_1.default.SyntaxKind.FirstAssignment
                        && parent.operatorToken.kind <= typescript_1.default.SyntaxKind.LastAssignment) {
                        written = true;
                        break;
                    }
                    if ((typescript_1.default.isPrefixUnaryExpression(parent) || typescript_1.default.isPostfixUnaryExpression(parent))
                        && parent.operand === target) {
                        written = true;
                        break;
                    }
                    if ((typescript_1.default.isForOfStatement(parent) || typescript_1.default.isForInStatement(parent))
                        && parent.initializer === target) {
                        written = true;
                        break;
                    }
                    target = parent;
                }
            }
        }
        typescript_1.default.forEachChild(reference, (child) => { references.push(child); });
    }
    projectCache?.set(symbol, written);
    return written;
}
function unwrapExpression(expression) {
    let current = expression;
    while (typescript_1.default.isParenthesizedExpression(current) || typescript_1.default.isAsExpression(current)
        || typescript_1.default.isTypeAssertionExpression(current) || typescript_1.default.isSatisfiesExpression(current)
        || typescript_1.default.isNonNullExpression(current))
        current = current.expression;
    return current;
}
function resolveConstInitializer(input, checker, check, projectSources) {
    const seen = new Set();
    let expression = unwrapExpression(input);
    while (typescript_1.default.isIdentifier(expression)) {
        check();
        let symbol = checker.getSymbolAtLocation(expression);
        if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
            symbol = checker.getAliasedSymbol(symbol);
        if (!symbol || seen.has(symbol))
            break;
        seen.add(symbol);
        const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
        const declaration = declarations.length === 1 ? declarations[0] : undefined;
        if (!declaration?.initializer || (projectSources
            && !projectSources.has(declaration.getSourceFile()))
            || !typescript_1.default.isVariableDeclarationList(declaration.parent)
            || !(declaration.parent.flags & typescript_1.default.NodeFlags.Const))
            break;
        expression = unwrapExpression(declaration.initializer);
    }
    return expression;
}
function isDefinitelyNonProvidePropertyKey(expression) {
    const key = unwrapExpression(expression);
    return typescript_1.default.isPrefixUnaryExpression(key)
        && (key.operator === typescript_1.default.SyntaxKind.PlusToken || key.operator === typescript_1.default.SyntaxKind.MinusToken);
}
function resolveStaticPropertyKey(input, checker, check) {
    const seen = new Set();
    let current = input;
    while (true) {
        check();
        const expression = unwrapExpression(current);
        if (typescript_1.default.isStringLiteral(expression)
            || typescript_1.default.isNoSubstitutionTemplateLiteral(expression))
            return expression.text;
        if (typescript_1.default.isNumericLiteral(expression))
            return String(Number(expression.text));
        if (typescript_1.default.isBigIntLiteral(expression))
            return String(BigInt(expression.text.slice(0, -1)));
        if (typescript_1.default.isPrefixUnaryExpression(expression)
            && (expression.operator === typescript_1.default.SyntaxKind.PlusToken
                || expression.operator === typescript_1.default.SyntaxKind.MinusToken)) {
            if (typescript_1.default.isNumericLiteral(expression.operand)) {
                const value = Number(expression.operand.text);
                return String(expression.operator === typescript_1.default.SyntaxKind.MinusToken ? -value : value);
            }
            if (typescript_1.default.isBigIntLiteral(expression.operand)
                && expression.operator === typescript_1.default.SyntaxKind.MinusToken) {
                return String(-BigInt(expression.operand.text.slice(0, -1)));
            }
            return undefined;
        }
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
            ? resolveStaticPropertyKey(current.argumentExpression, checker, check)
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
function resolveDecoratorSymbol(decorator, checker, check, projectSources) {
    const expression = resolveConstInitializer(decorator.expression, checker, check, projectSources);
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
function isBareDecoratorBindingStable(decorator, checker, projectSources, check) {
    const expression = unwrapExpression(decorator.expression);
    if (typescript_1.default.isCallExpression(expression))
        return false;
    if (typescript_1.default.isIdentifier(expression)) {
        let bindingExpression = expression;
        const seen = new Set();
        let binding;
        while (typescript_1.default.isIdentifier(bindingExpression)) {
            const symbol = checker.getSymbolAtLocation(bindingExpression);
            if (!symbol || seen.has(symbol))
                break;
            seen.add(symbol);
            binding = symbol.declarations
                ?.find((declaration) => typescript_1.default.isBindingElement(declaration));
            if (binding)
                break;
            const alias = symbol.declarations?.find((declaration) => (typescript_1.default.isVariableDeclaration(declaration) && declaration.initializer !== undefined
                && typescript_1.default.isVariableDeclarationList(declaration.parent)
                && Boolean(declaration.parent.flags & typescript_1.default.NodeFlags.Const)));
            if (!alias)
                break;
            bindingExpression = unwrapExpression(alias.initializer);
        }
        if (binding) {
            const declaration = typescript_1.default.isVariableDeclaration(binding.parent.parent)
                ? binding.parent.parent : undefined;
            const bindingSymbol = typescript_1.default.isIdentifier(binding.name)
                ? checker.getSymbolAtLocation(binding.name) : undefined;
            if (!declaration || !typescript_1.default.isVariableDeclarationList(declaration.parent)
                || !(declaration.parent.flags & typescript_1.default.NodeFlags.Const) || !bindingSymbol
                || callableBindingMayBeWritten(bindingSymbol, bindingSymbol.declarations ?? [], checker, projectSources, check))
                return false;
            const receiver = declaration?.initializer && unwrapExpression(declaration.initializer);
            if (!receiver)
                return false;
            const propertyName = binding.propertyName ?? binding.name;
            const key = typescript_1.default.isIdentifier(propertyName) || typescript_1.default.isStringLiteral(propertyName)
                ? propertyName.text : undefined;
            const stableObjectProperty = (object) => {
                if (!key || object.properties.some((property) => (!typescript_1.default.isShorthandPropertyAssignment(property))))
                    return false;
                const properties = object.properties.filter((property) => (typescript_1.default.isShorthandPropertyAssignment(property)
                    && property.name.text === key));
                if (properties.length !== 1)
                    return false;
                const value = checker.getShorthandAssignmentValueSymbol(properties[0]);
                const symbol = value
                    ? (value.flags & typescript_1.default.SymbolFlags.Alias ? checker.getAliasedSymbol(value) : value)
                    : undefined;
                return Boolean(symbol && symbol.getName() === key && !callableBindingMayBeWritten(symbol, symbol.declarations ?? [], checker, projectSources, check));
            };
            if (!typescript_1.default.isObjectLiteralExpression(receiver)) {
                if (!typescript_1.default.isIdentifier(receiver))
                    return false;
                const receiverSymbol = checker.getSymbolAtLocation(receiver);
                if (!receiverSymbol)
                    return false;
                const receiverDeclaration = receiverSymbol?.declarations?.find(typescript_1.default.isVariableDeclaration);
                if (!receiverSymbol.declarations?.some(typescript_1.default.isNamespaceImport)) {
                    if (!receiverDeclaration?.initializer
                        || !typescript_1.default.isObjectLiteralExpression(unwrapExpression(receiverDeclaration.initializer))
                        || !stableObjectProperty(unwrapExpression(receiverDeclaration.initializer))
                        || !typescript_1.default.isVariableDeclarationList(receiverDeclaration.parent)
                        || !(receiverDeclaration.parent.flags & typescript_1.default.NodeFlags.Const)
                        || callableBindingMayBeWritten(receiverSymbol, receiverSymbol.declarations ?? [], checker, projectSources, check))
                        return false;
                    let cache = BARE_RECEIVER_STABILITY_CACHE.get(projectSources);
                    if (!cache) {
                        cache = new WeakMap();
                        BARE_RECEIVER_STABILITY_CACHE.set(projectSources, cache);
                    }
                    let isolated = cache.get(receiverSymbol);
                    if (isolated === undefined) {
                        isolated = true;
                        const references = [...projectSources];
                        while (references.length > 0 && isolated) {
                            const reference = references.pop();
                            check();
                            if (typescript_1.default.isIdentifier(reference) && reference !== receiver
                                && reference !== receiverDeclaration.name) {
                                let referenceSymbol = checker.getSymbolAtLocation(reference);
                                if (referenceSymbol?.flags && referenceSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                                    referenceSymbol = checker.getAliasedSymbol(referenceSymbol);
                                }
                                if (referenceSymbol !== receiverSymbol) {
                                    typescript_1.default.forEachChild(reference, (child) => { references.push(child); });
                                    continue;
                                }
                                let usage = reference;
                                while (typescript_1.default.isParenthesizedExpression(usage.parent)
                                    || typescript_1.default.isAsExpression(usage.parent) || typescript_1.default.isTypeAssertionExpression(usage.parent)
                                    || typescript_1.default.isSatisfiesExpression(usage.parent) || typescript_1.default.isNonNullExpression(usage.parent)) {
                                    usage = usage.parent;
                                }
                                const member = (typescript_1.default.isPropertyAccessExpression(usage.parent)
                                    || typescript_1.default.isElementAccessExpression(usage.parent))
                                    && usage.parent.expression === usage ? usage.parent : undefined;
                                let memberUsage = member;
                                while (memberUsage && (typescript_1.default.isParenthesizedExpression(memberUsage.parent)
                                    || typescript_1.default.isAsExpression(memberUsage.parent)
                                    || typescript_1.default.isTypeAssertionExpression(memberUsage.parent)
                                    || typescript_1.default.isSatisfiesExpression(memberUsage.parent)
                                    || typescript_1.default.isNonNullExpression(memberUsage.parent)))
                                    memberUsage = memberUsage.parent;
                                let memberUnsafe = false;
                                let target = memberUsage;
                                while (target?.parent && !typescript_1.default.isStatement(target)) {
                                    const parent = target.parent;
                                    if ((typescript_1.default.isBinaryExpression(parent) && parent.left === target
                                        && parent.operatorToken.kind >= typescript_1.default.SyntaxKind.FirstAssignment
                                        && parent.operatorToken.kind <= typescript_1.default.SyntaxKind.LastAssignment)
                                        || ((typescript_1.default.isForOfStatement(parent) || typescript_1.default.isForInStatement(parent))
                                            && parent.initializer === target)
                                        || (typescript_1.default.isDeleteExpression(parent) && parent.expression === target)
                                        || ((typescript_1.default.isPrefixUnaryExpression(parent) || typescript_1.default.isPostfixUnaryExpression(parent))
                                            && parent.operand === target)
                                        || (typescript_1.default.isCallExpression(parent) && parent.expression === target)
                                        || (typescript_1.default.isTaggedTemplateExpression(parent) && parent.tag === target)) {
                                        memberUnsafe = true;
                                        break;
                                    }
                                    target = parent;
                                }
                                const destructuredAgain = typescript_1.default.isVariableDeclaration(usage.parent)
                                    && usage.parent.initializer === usage
                                    && typescript_1.default.isObjectBindingPattern(usage.parent.name);
                                if ((!member || memberUnsafe) && !destructuredAgain)
                                    isolated = false;
                            }
                            typescript_1.default.forEachChild(reference, (child) => { references.push(child); });
                        }
                        cache.set(receiverSymbol, isolated);
                    }
                    if (!isolated)
                        return false;
                }
            }
            else if (!stableObjectProperty(receiver)) {
                return false;
            }
        }
    }
    if ((typescript_1.default.isPropertyAccessExpression(expression) || typescript_1.default.isElementAccessExpression(expression))
        && !isNamespaceImportAccess(expression, checker))
        return false;
    const symbol = targetSymbol(expression, checker, check);
    if (!symbol || symbol === UNKNOWN_NESTJS_ROUTE)
        return false;
    return !callableBindingMayBeWritten(symbol, symbol.declarations ?? [], checker, projectSources, check);
}
function hasRuntimeBinding(identifier, checker) {
    return checker.getSymbolAtLocation(identifier)?.declarations?.some((declaration) => {
        if (declaration.getSourceFile().isDeclarationFile)
            return false;
        const variableStatement = typescript_1.default.isVariableDeclaration(declaration)
            && typescript_1.default.isVariableStatement(declaration.parent.parent) ? declaration.parent.parent : undefined;
        return !variableStatement?.modifiers?.some(({ kind }) => kind === typescript_1.default.SyntaxKind.DeclareKeyword);
    }) === true;
}
function isStandardReflectReceiver(input, checker, check) {
    const receiver = unwrapExpression(input);
    if (typescript_1.default.isIdentifier(receiver)) {
        return receiver.text === 'Reflect' && !hasRuntimeBinding(receiver, checker);
    }
    if (!typescript_1.default.isPropertyAccessExpression(receiver) && !typescript_1.default.isElementAccessExpression(receiver)) {
        return false;
    }
    const name = typescript_1.default.isPropertyAccessExpression(receiver) ? receiver.name.text
        : receiver.argumentExpression
            ? resolveStaticPropertyKey(receiver.argumentExpression, checker, check) : undefined;
    const globalReceiver = unwrapExpression(receiver.expression);
    return name === 'Reflect' && typescript_1.default.isIdentifier(globalReceiver)
        && globalReceiver.text === 'globalThis' && !hasRuntimeBinding(globalReceiver, checker);
}
function standardFunctionPrototypeMethod(input, checker, check) {
    const member = unwrapExpression(input);
    if (!typescript_1.default.isPropertyAccessExpression(member) && !typescript_1.default.isElementAccessExpression(member))
        return undefined;
    const method = typescript_1.default.isPropertyAccessExpression(member) ? member.name.text
        : member.argumentExpression
            ? resolveStaticPropertyKey(member.argumentExpression, checker, check) : undefined;
    if (method !== 'call' && method !== 'apply')
        return undefined;
    const prototype = unwrapExpression(member.expression);
    if (!typescript_1.default.isPropertyAccessExpression(prototype) && !typescript_1.default.isElementAccessExpression(prototype))
        return undefined;
    const prototypeName = typescript_1.default.isPropertyAccessExpression(prototype) ? prototype.name.text
        : prototype.argumentExpression
            ? resolveStaticPropertyKey(prototype.argumentExpression, checker, check) : undefined;
    const constructor = unwrapExpression(prototype.expression);
    if (prototypeName !== 'prototype')
        return undefined;
    if (typescript_1.default.isIdentifier(constructor)) {
        return constructor.text === 'Function' && !hasRuntimeBinding(constructor, checker) ? method : undefined;
    }
    if (!typescript_1.default.isPropertyAccessExpression(constructor) && !typescript_1.default.isElementAccessExpression(constructor))
        return undefined;
    const constructorName = typescript_1.default.isPropertyAccessExpression(constructor) ? constructor.name.text
        : constructor.argumentExpression
            ? resolveStaticPropertyKey(constructor.argumentExpression, checker, check) : undefined;
    const globalReceiver = unwrapExpression(constructor.expression);
    return constructorName === 'Function' && typescript_1.default.isIdentifier(globalReceiver)
        && globalReceiver.text === 'globalThis' && !hasRuntimeBinding(globalReceiver, checker)
        ? method : undefined;
}
function resolveDecoratorCallSymbol(call, checker, check) {
    let expression = call.expression;
    let indirectInvocation = false;
    const outer = unwrapExpression(expression);
    const outerInvocation = typescript_1.default.isPropertyAccessExpression(outer) ? outer.name.text
        : typescript_1.default.isElementAccessExpression(outer) && outer.argumentExpression
            ? resolveStaticPropertyKey(outer.argumentExpression, checker, check) : undefined;
    const outerReceiver = (typescript_1.default.isPropertyAccessExpression(outer)
        || typescript_1.default.isElementAccessExpression(outer)) ? unwrapExpression(outer.expression) : undefined;
    if ((outerInvocation === 'apply' || outerInvocation === 'construct') && outerReceiver
        && isStandardReflectReceiver(outerReceiver, checker, check) && call.arguments[0]) {
        indirectInvocation = true;
        expression = call.arguments[0];
    }
    while (true) {
        check();
        const callee = unwrapExpression(expression);
        const invocation = typescript_1.default.isPropertyAccessExpression(callee) ? callee.name.text
            : typescript_1.default.isElementAccessExpression(callee) && callee.argumentExpression
                ? resolveStaticPropertyKey(callee.argumentExpression, checker, check) : undefined;
        if ((invocation !== 'call' && invocation !== 'apply')
            || (!typescript_1.default.isPropertyAccessExpression(callee) && !typescript_1.default.isElementAccessExpression(callee)))
            break;
        indirectInvocation = true;
        expression = callee.expression;
    }
    const symbol = targetSymbol(expression, checker, check);
    if (!symbol || symbol === UNKNOWN_NESTJS_ROUTE) {
        return !symbol && typescript_1.default.isElementAccessExpression(unwrapExpression(expression))
            ? {
                name: '', call, nestJsCommon: false, trustedNestJsCommon: false, indirectInvocation,
            }
            : undefined;
    }
    const nestJsCommon = originatesFromNestJsCommon(symbol);
    if (indirectInvocation && (!nestJsCommon
        || (symbol.getName() !== 'UseGuards' && symbol.getName() !== 'applyDecorators')))
        return undefined;
    return {
        name: symbol.getName(),
        call,
        nestJsCommon,
        trustedNestJsCommon: !indirectInvocation && nestJsCommon
            && directNestJsImport(expression, checker)
            && matchesConsumerNestJsCommon(expression, symbol),
        indirectInvocation,
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
        && declaration && ((typescript_1.default.isVariableDeclaration(declaration)
        && typescript_1.default.isVariableDeclarationList(declaration.parent)
        && declaration.parent.flags & typescript_1.default.NodeFlags.Const)
        || (typescript_1.default.isFunctionDeclaration(declaration)
            && !callableBindingMayBeWritten(symbol, symbol.declarations ?? [], checker, projectSources, check))));
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
        if (typescript_1.default.isFunctionLike(expression)) {
            if (!expression.body)
                return { dynamic: true };
            const nodes = [expression.body];
            while (nodes.length > 0) {
                const node = nodes.pop();
                check();
                if (typescript_1.default.isCallExpression(node) || typescript_1.default.isNewExpression(node)
                    || typescript_1.default.isTaggedTemplateExpression(node))
                    return { dynamic: true };
                if (node !== expression.body && typescript_1.default.isFunctionLike(node))
                    continue;
                typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
            }
            return undefined;
        }
        if (typescript_1.default.isClassLike(expression))
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
function resolveStaticSymbolName(expression, checker, check, projectSources) {
    const reference = unwrapExpression(expression);
    if (projectSources && typescript_1.default.isIdentifier(reference)) {
        let binding = checker.getSymbolAtLocation(reference);
        if (binding?.flags && binding.flags & typescript_1.default.SymbolFlags.Alias)
            binding = checker.getAliasedSymbol(binding);
        if (binding && callableBindingMayBeWritten(binding, binding.declarations ?? [], checker, projectSources, check))
            return undefined;
    }
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
function containsStaticSymbolFrom(expression, checker, check, moduleName, importedName, projectSources) {
    const resolving = new Set();
    const resolvingNullish = new Set();
    const truthiness = (input, depth, bindings) => {
        check();
        if (depth > 64)
            return undefined;
        const node = unwrapExpression(input);
        if (node.kind === typescript_1.default.SyntaxKind.TrueKeyword)
            return true;
        if (node.kind === typescript_1.default.SyntaxKind.FalseKeyword || node.kind === typescript_1.default.SyntaxKind.NullKeyword)
            return false;
        if (typescript_1.default.isVoidExpression(node))
            return false;
        if (typescript_1.default.isStringLiteral(node) || typescript_1.default.isNoSubstitutionTemplateLiteral(node))
            return node.text.length > 0;
        if (typescript_1.default.isNumericLiteral(node))
            return Number(node.text) !== 0;
        if (typescript_1.default.isBigIntLiteral(node))
            return BigInt(node.text.slice(0, -1)) !== 0n;
        if (typescript_1.default.isPrefixUnaryExpression(node)) {
            if (typescript_1.default.isNumericLiteral(node.operand)
                && (node.operator === typescript_1.default.SyntaxKind.PlusToken || node.operator === typescript_1.default.SyntaxKind.MinusToken)) {
                return Number(node.operand.text) !== 0;
            }
            if (typescript_1.default.isBigIntLiteral(node.operand) && node.operator === typescript_1.default.SyntaxKind.MinusToken) {
                return BigInt(node.operand.text.slice(0, -1)) !== 0n;
            }
        }
        if (typescript_1.default.isObjectLiteralExpression(node) || typescript_1.default.isArrayLiteralExpression(node)
            || typescript_1.default.isFunctionExpression(node) || typescript_1.default.isArrowFunction(node)
            || typescript_1.default.isClassExpression(node) || typescript_1.default.isRegularExpressionLiteral(node)
            || typescript_1.default.isNewExpression(node))
            return true;
        if (typescript_1.default.isPrefixUnaryExpression(node) && node.operator === typescript_1.default.SyntaxKind.ExclamationToken) {
            const value = truthiness(node.operand, depth + 1, bindings);
            return value === undefined ? undefined : !value;
        }
        if (isStaticSymbolFrom(node, checker, check, moduleName, importedName))
            return true;
        if (!typescript_1.default.isIdentifier(node))
            return undefined;
        let symbol = checker.getSymbolAtLocation(node);
        if (!symbol)
            return undefined;
        if (symbol.flags & typescript_1.default.SymbolFlags.Alias)
            symbol = checker.getAliasedSymbol(symbol);
        const bound = bindings.get(symbol);
        if (bound) {
            const values = bound.map((candidate) => truthiness(candidate, depth + 1, bindings));
            return values.length > 0 && values.every((value) => value === values[0])
                ? values[0]
                : undefined;
        }
        if (resolving.has(symbol))
            return undefined;
        const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
        const declaration = declarations.length === 1 ? declarations[0] : undefined;
        if (!declaration?.initializer || !typescript_1.default.isVariableDeclarationList(declaration.parent)
            || !(declaration.parent.flags & typescript_1.default.NodeFlags.Const)) {
            return node.text === 'undefined' && !symbol.declarations?.length ? false : undefined;
        }
        resolving.add(symbol);
        const result = truthiness(declaration.initializer, depth + 1, bindings);
        resolving.delete(symbol);
        return result;
    };
    const nullishCache = new WeakMap();
    const nullishState = (input, includeNull, depth, bindings) => {
        let expressions = nullishCache.get(bindings);
        if (!expressions) {
            expressions = new WeakMap();
            nullishCache.set(bindings, expressions);
        }
        let modes = expressions.get(input);
        if (!modes) {
            modes = new Map();
            expressions.set(input, modes);
        }
        if (modes.has(includeNull))
            return modes.get(includeNull);
        const result = nullishStateUncached(input, includeNull, depth, bindings);
        modes.set(includeNull, result);
        return result;
    };
    const nullishStateUncached = (input, includeNull, depth, bindings) => {
        check();
        if (depth > 64)
            return undefined;
        const node = unwrapExpression(input);
        if (typescript_1.default.isIdentifier(node)) {
            let symbol = checker.getSymbolAtLocation(node);
            if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
                symbol = checker.getAliasedSymbol(symbol);
            if (symbol) {
                const bound = bindings.get(symbol);
                if (bound) {
                    const states = bound.map((candidate) => (nullishState(candidate, includeNull, depth + 1, bindings)));
                    return states.length > 0 && states.every((state) => state === states[0])
                        ? states[0]
                        : undefined;
                }
                if (resolvingNullish.has(symbol))
                    return undefined;
                const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
                const declaration = declarations.length === 1 ? declarations[0] : undefined;
                if (declaration?.initializer && typescript_1.default.isVariableDeclarationList(declaration.parent)
                    && declaration.parent.flags & typescript_1.default.NodeFlags.Const) {
                    resolvingNullish.add(symbol);
                    const result = nullishState(declaration.initializer, includeNull, depth + 1, bindings);
                    resolvingNullish.delete(symbol);
                    return result;
                }
            }
        }
        const type = checker.getTypeAtLocation(node);
        const mask = typescript_1.default.TypeFlags.VoidLike | (includeNull ? typescript_1.default.TypeFlags.Null : 0);
        if (type.flags & (typescript_1.default.TypeFlags.Any | typescript_1.default.TypeFlags.Unknown | typescript_1.default.TypeFlags.TypeParameter)) {
            return undefined;
        }
        if (type.isUnion()) {
            const hasNullish = type.types.some((part) => Boolean(part.flags & mask));
            return hasNullish
                ? type.types.every((part) => Boolean(part.flags & mask)) || undefined
                : false;
        }
        return Boolean(type.flags & mask);
    };
    const resolutionCache = new WeakMap();
    const maySetObjectPrototype = (expression) => {
        const type = checker.getTypeAtLocation(expression);
        const definitelyPrimitive = (candidate) => Boolean(candidate.flags & (typescript_1.default.TypeFlags.StringLike | typescript_1.default.TypeFlags.NumberLike | typescript_1.default.TypeFlags.BigIntLike
            | typescript_1.default.TypeFlags.BooleanLike | typescript_1.default.TypeFlags.ESSymbolLike | typescript_1.default.TypeFlags.EnumLike
            | typescript_1.default.TypeFlags.Void | typescript_1.default.TypeFlags.Null | typescript_1.default.TypeFlags.Undefined | typescript_1.default.TypeFlags.Never));
        return type.isUnion()
            ? !type.types.every(definitelyPrimitive)
            : !definitelyPrimitive(type);
    };
    const subtreeContainsTarget = (root) => {
        const nodes = [root];
        const seen = new Set();
        while (nodes.length > 0) {
            const node = nodes.pop();
            check();
            if (typescript_1.default.isFunctionLike(node) || typescript_1.default.isClassLike(node))
                continue;
            if ((typescript_1.default.isIdentifier(node) || typescript_1.default.isPropertyAccessExpression(node)
                || typescript_1.default.isElementAccessExpression(node))
                && isStaticSymbolFrom(node, checker, check, moduleName, importedName))
                return true;
            if (typescript_1.default.isIdentifier(node)) {
                let symbol = checker.getSymbolAtLocation(node);
                if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
                    symbol = checker.getAliasedSymbol(symbol);
                if (symbol && !seen.has(symbol)) {
                    seen.add(symbol);
                    const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
                    const declaration = declarations.length === 1 ? declarations[0] : undefined;
                    if (declaration?.initializer && typescript_1.default.isVariableDeclarationList(declaration.parent)
                        && declaration.parent.flags & typescript_1.default.NodeFlags.Const)
                        nodes.push(declaration.initializer);
                }
            }
            typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
        }
        return false;
    };
    const deepContainsTarget = (root) => {
        const nodes = [root];
        while (nodes.length > 0) {
            const node = nodes.pop();
            check();
            if ((typescript_1.default.isIdentifier(node) || typescript_1.default.isPropertyAccessExpression(node)
                || typescript_1.default.isElementAccessExpression(node))
                && isStaticSymbolFrom(node, checker, check, moduleName, importedName))
                return true;
            typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
        }
        return false;
    };
    const callableUsesThis = (root) => {
        const nodes = [root];
        while (nodes.length > 0) {
            const node = nodes.pop();
            check();
            if (node !== root && ((typescript_1.default.isFunctionLike(node) && !typescript_1.default.isArrowFunction(node))
                || typescript_1.default.isClassLike(node)))
                continue;
            if (node.kind === typescript_1.default.SyntaxKind.ThisKeyword)
                return true;
            typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
        }
        return false;
    };
    const parameterDefaultsMayTarget = (parameters, args, depth, bindings) => parameters.some((parameter, index) => {
        if (!parameter.initializer || !subtreeContainsTarget(parameter.initializer))
            return false;
        if (!args)
            return true;
        if (args.slice(0, index + 1).some((argument) => argument && typescript_1.default.isSpreadElement(argument))) {
            return true;
        }
        const argument = args[index];
        if (!argument || typescript_1.default.isSpreadElement(argument))
            return true;
        return nullishState(argument, false, depth + 1, bindings) !== false;
    });
    const resolve = (input, depth, bindings) => {
        let expressions = resolutionCache.get(bindings);
        if (!expressions) {
            expressions = new WeakMap();
            resolutionCache.set(bindings, expressions);
        }
        if (expressions.has(input))
            return expressions.get(input);
        const result = resolveUncached(input, depth, bindings);
        expressions.set(input, result);
        return result;
    };
    const expressionMayThrow = (expression) => {
        if (!expression)
            return false;
        const value = unwrapExpression(expression);
        return !(typescript_1.default.isStringLiteral(value) || typescript_1.default.isNoSubstitutionTemplateLiteral(value) || typescript_1.default.isNumericLiteral(value)
            || typescript_1.default.isBigIntLiteral(value) || typescript_1.default.isRegularExpressionLiteral(value)
            || value.kind === typescript_1.default.SyntaxKind.TrueKeyword || value.kind === typescript_1.default.SyntaxKind.FalseKeyword
            || value.kind === typescript_1.default.SyntaxKind.NullKeyword);
    };
    const staticSwitchKey = (input, switchDepth = 0, seen = new Set()) => {
        if (switchDepth > 64)
            return undefined;
        const value = unwrapExpression(input);
        if (typescript_1.default.isStringLiteral(value) || typescript_1.default.isNoSubstitutionTemplateLiteral(value))
            return `s:${value.text}`;
        if (typescript_1.default.isNumericLiteral(value))
            return `n:${Number(value.text)}`;
        if (typescript_1.default.isBigIntLiteral(value))
            return `b:${BigInt(value.text.slice(0, -1))}`;
        if (value.kind === typescript_1.default.SyntaxKind.TrueKeyword)
            return 'z:true';
        if (value.kind === typescript_1.default.SyntaxKind.FalseKeyword)
            return 'z:false';
        if (value.kind === typescript_1.default.SyntaxKind.NullKeyword)
            return 'z:null';
        if (typescript_1.default.isPrefixUnaryExpression(value)
            && (value.operator === typescript_1.default.SyntaxKind.PlusToken || value.operator === typescript_1.default.SyntaxKind.MinusToken)
            && typescript_1.default.isNumericLiteral(value.operand)) {
            const number = Number(value.operand.text);
            return `n:${value.operator === typescript_1.default.SyntaxKind.MinusToken ? -number : number}`;
        }
        if (!typescript_1.default.isIdentifier(value))
            return undefined;
        let symbol = checker.getSymbolAtLocation(value);
        if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
            symbol = checker.getAliasedSymbol(symbol);
        if (!symbol || seen.has(symbol))
            return undefined;
        const declaration = symbol.declarations?.find((candidate) => (typescript_1.default.isVariableDeclaration(candidate) && candidate.initializer !== undefined
            && typescript_1.default.isVariableDeclarationList(candidate.parent)
            && Boolean(candidate.parent.flags & typescript_1.default.NodeFlags.Const)));
        if (!declaration?.initializer)
            return undefined;
        seen.add(symbol);
        return staticSwitchKey(declaration.initializer, switchDepth + 1, seen);
    };
    const callableParametersMayBeWritten = (body, parameters) => {
        const parameterSymbols = new Set(parameters.flatMap((parameter) => {
            if (!typescript_1.default.isIdentifier(parameter.name))
                return [];
            const symbol = checker.getSymbolAtLocation(parameter.name);
            return symbol ? [symbol] : [];
        }));
        if (parameterSymbols.size === 0)
            return false;
        const bodyNodes = [];
        typescript_1.default.forEachChild(body, (child) => { bodyNodes.push(child); });
        while (bodyNodes.length > 0) {
            const child = bodyNodes.pop();
            check();
            if (typescript_1.default.isIdentifier(child) && parameterSymbols.has(checker.getSymbolAtLocation(child))) {
                let target = child;
                while (target.parent && !typescript_1.default.isStatement(target)) {
                    const parent = target.parent;
                    if (typescript_1.default.isBinaryExpression(parent) && parent.left === target
                        && parent.operatorToken.kind >= typescript_1.default.SyntaxKind.FirstAssignment
                        && parent.operatorToken.kind <= typescript_1.default.SyntaxKind.LastAssignment)
                        return true;
                    if ((typescript_1.default.isPrefixUnaryExpression(parent) || typescript_1.default.isPostfixUnaryExpression(parent))
                        && parent.operand === target)
                        return true;
                    if ((typescript_1.default.isForOfStatement(parent) || typescript_1.default.isForInStatement(parent))
                        && parent.initializer === target)
                        return true;
                    target = parent;
                }
            }
            typescript_1.default.forEachChild(child, (descendant) => { bodyNodes.push(descendant); });
        }
        return false;
    };
    const staticallyUnreachable = (candidate, branchDepth, branchBindings) => {
        let child = candidate;
        let parent = candidate.parent;
        while (parent) {
            if (typescript_1.default.isIfStatement(parent)) {
                const condition = truthiness(parent.expression, branchDepth + 1, branchBindings);
                if ((condition === false && child === parent.thenStatement)
                    || (condition === true && child === parent.elseStatement))
                    return true;
            }
            if (typescript_1.default.isConditionalExpression(parent)) {
                const condition = truthiness(parent.condition, branchDepth + 1, branchBindings);
                if ((condition === false && child === parent.whenTrue)
                    || (condition === true && child === parent.whenFalse))
                    return true;
            }
            if (typescript_1.default.isWhileStatement(parent) && child === parent.statement
                && truthiness(parent.expression, branchDepth + 1, branchBindings) === false)
                return true;
            if (typescript_1.default.isForStatement(parent) && child === parent.statement && parent.condition
                && truthiness(parent.condition, branchDepth + 1, branchBindings) === false)
                return true;
            child = parent;
            parent = parent.parent;
        }
        return false;
    };
    function statementFlow(statement, flowDepth, callDepth, localBindings) {
        check();
        if (flowDepth > 64)
            return { target: true, completes: true, mayThrow: true };
        if (typescript_1.default.isReturnStatement(statement)) {
            return {
                target: Boolean(statement.expression
                    && resolve(statement.expression, callDepth + 1, localBindings)),
                completes: false,
                mayThrow: expressionMayThrow(statement.expression),
            };
        }
        if (typescript_1.default.isThrowStatement(statement)) {
            return { target: false, completes: false, mayThrow: true };
        }
        if (typescript_1.default.isBreakStatement(statement) && !statement.label) {
            return { target: false, completes: false, mayThrow: false, breaks: true };
        }
        if (typescript_1.default.isContinueStatement(statement) && !statement.label) {
            return { target: false, completes: false, mayThrow: false, continues: true };
        }
        if (typescript_1.default.isBlock(statement)) {
            return sequenceFlow(statement.statements, flowDepth + 1, callDepth, localBindings);
        }
        if (typescript_1.default.isIfStatement(statement)) {
            const condition = truthiness(statement.expression, callDepth + 1, localBindings);
            if (condition === true) {
                const selected = statementFlow(statement.thenStatement, flowDepth + 1, callDepth, localBindings);
                return { ...selected, mayThrow: selected.mayThrow || expressionMayThrow(statement.expression) };
            }
            if (condition === false) {
                const selected = statement.elseStatement
                    ? statementFlow(statement.elseStatement, flowDepth + 1, callDepth, localBindings)
                    : { target: false, completes: true, mayThrow: false };
                return { ...selected, mayThrow: selected.mayThrow || expressionMayThrow(statement.expression) };
            }
            const whenTrue = statementFlow(statement.thenStatement, flowDepth + 1, callDepth, localBindings);
            const whenFalse = statement.elseStatement
                ? statementFlow(statement.elseStatement, flowDepth + 1, callDepth, localBindings)
                : { target: false, completes: true, mayThrow: false };
            return {
                target: whenTrue.target || whenFalse.target,
                completes: whenTrue.completes || whenFalse.completes,
                mayThrow: expressionMayThrow(statement.expression)
                    || whenTrue.mayThrow || whenFalse.mayThrow,
                breaks: Boolean(whenTrue.breaks || whenFalse.breaks),
                continues: Boolean(whenTrue.continues || whenFalse.continues),
            };
        }
        if (typescript_1.default.isWhileStatement(statement)) {
            const condition = truthiness(statement.expression, callDepth + 1, localBindings);
            if (condition === false) {
                return {
                    target: false,
                    completes: true,
                    mayThrow: expressionMayThrow(statement.expression),
                };
            }
        }
        if (typescript_1.default.isForStatement(statement) && statement.condition) {
            const condition = truthiness(statement.condition, callDepth + 1, localBindings);
            if (condition === false) {
                const initializer = statement.initializer;
                const initializerMayThrow = initializer && typescript_1.default.isVariableDeclarationList(initializer)
                    ? initializer.declarations.some((declaration) => (!typescript_1.default.isIdentifier(declaration.name) || expressionMayThrow(declaration.initializer)))
                    : expressionMayThrow(initializer);
                return {
                    target: false,
                    completes: true,
                    mayThrow: initializerMayThrow || expressionMayThrow(statement.condition),
                };
            }
        }
        if (typescript_1.default.isForOfStatement(statement)) {
            const iterable = unwrapExpression(statement.expression);
            const values = typescript_1.default.isArrayLiteralExpression(iterable)
                && iterable.elements.every((element) => (!typescript_1.default.isSpreadElement(element) && !typescript_1.default.isOmittedExpression(element))) ? iterable.elements : undefined;
            const declaration = typescript_1.default.isVariableDeclarationList(statement.initializer)
                && statement.initializer.declarations.length === 1
                ? statement.initializer.declarations[0] : undefined;
            const name = declaration && typescript_1.default.isIdentifier(declaration.name) ? declaration.name
                : typescript_1.default.isIdentifier(statement.initializer) ? statement.initializer : undefined;
            const symbol = name && checker.getSymbolAtLocation(name);
            if (values && symbol) {
                let target = false;
                let completes = false;
                let mayThrow = false;
                for (const value of values) {
                    const iterationBindings = new Map(localBindings);
                    iterationBindings.set(symbol, [value]);
                    const flow = statementFlow(statement.statement, flowDepth + 1, callDepth, iterationBindings);
                    target ||= flow.target;
                    completes ||= Boolean(flow.breaks);
                    mayThrow ||= flow.mayThrow;
                    if (!flow.completes && !flow.continues) {
                        return { target, completes, mayThrow };
                    }
                }
                return { target, completes: true, mayThrow: true };
            }
        }
        if (typescript_1.default.isSwitchStatement(statement)) {
            const selected = staticSwitchKey(statement.expression);
            if (selected !== undefined) {
                let start = statement.caseBlock.clauses.findIndex((clause) => (typescript_1.default.isCaseClause(clause) && staticSwitchKey(clause.expression) === selected));
                if (start < 0)
                    start = statement.caseBlock.clauses.findIndex(typescript_1.default.isDefaultClause);
                if (start < 0)
                    return { target: false, completes: true, mayThrow: true };
                let target = false;
                let breaks = false;
                let continues = false;
                let mayThrow = false;
                for (const clause of statement.caseBlock.clauses.slice(start)) {
                    for (const child of clause.statements) {
                        const flow = statementFlow(child, flowDepth + 1, callDepth, localBindings);
                        target ||= flow.target;
                        breaks ||= Boolean(flow.breaks);
                        continues ||= Boolean(flow.continues);
                        mayThrow ||= flow.mayThrow;
                        if (!flow.completes)
                            return {
                                target,
                                completes: breaks,
                                mayThrow,
                                continues,
                            };
                    }
                }
                return { target, completes: true, mayThrow: true, continues };
            }
        }
        if (typescript_1.default.isTryStatement(statement)) {
            const attempted = statementFlow(statement.tryBlock, flowDepth + 1, callDepth, localBindings);
            const caught = statement.catchClause && attempted.mayThrow
                ? statementFlow(statement.catchClause.block, flowDepth + 1, callDepth, localBindings)
                : { target: false, completes: false, mayThrow: false };
            const beforeFinally = {
                target: attempted.target || caught.target,
                completes: attempted.completes || caught.completes,
                mayThrow: statement.catchClause ? caught.mayThrow : attempted.mayThrow,
                breaks: Boolean(attempted.breaks || caught.breaks),
                continues: Boolean(attempted.continues || caught.continues),
            };
            if (!statement.finallyBlock)
                return beforeFinally;
            const finalized = statementFlow(statement.finallyBlock, flowDepth + 1, callDepth, localBindings);
            return finalized.completes
                ? {
                    target: beforeFinally.target || finalized.target,
                    completes: beforeFinally.completes,
                    mayThrow: beforeFinally.mayThrow || finalized.mayThrow,
                    breaks: Boolean(beforeFinally.breaks || finalized.breaks),
                    continues: Boolean(beforeFinally.continues || finalized.continues),
                }
                : finalized;
        }
        if (typescript_1.default.isFunctionLike(statement) || typescript_1.default.isClassLike(statement)) {
            return { target: false, completes: true, mayThrow: false };
        }
        let target = false;
        const nested = [];
        typescript_1.default.forEachChild(statement, (child) => { nested.push(child); });
        while (nested.length > 0) {
            const child = nested.pop();
            check();
            if (typescript_1.default.isFunctionLike(child) || typescript_1.default.isClassLike(child))
                continue;
            if (typescript_1.default.isReturnStatement(child)) {
                target ||= Boolean(child.expression
                    && resolve(child.expression, callDepth + 1, localBindings));
                continue;
            }
            typescript_1.default.forEachChild(child, (descendant) => { nested.push(descendant); });
        }
        return { target, completes: true, mayThrow: true };
    }
    function sequenceFlow(statements, flowDepth, callDepth, localBindings) {
        if (flowDepth > 64)
            return { target: true, completes: true, mayThrow: true };
        let target = false;
        let completes = true;
        let mayThrow = false;
        let breaks = false;
        let continues = false;
        for (const statement of statements) {
            if (!completes)
                break;
            const flow = statementFlow(statement, flowDepth + 1, callDepth, localBindings);
            target ||= flow.target;
            completes = flow.completes;
            mayThrow ||= flow.mayThrow;
            breaks ||= Boolean(flow.breaks);
            continues ||= Boolean(flow.continues);
        }
        return { target, completes, mayThrow, breaks, continues };
    }
    const resolveUncached = (input, depth, bindings) => {
        check();
        if (depth > 64)
            return true;
        const node = unwrapExpression(input);
        if (isStaticSymbolFrom(node, checker, check, moduleName, importedName))
            return true;
        if (typescript_1.default.isAwaitExpression(node)) {
            const awaited = unwrapExpression(node.expression);
            if (typescript_1.default.isCallExpression(awaited) && typescript_1.default.isIdentifier(unwrapExpression(awaited.expression))) {
                const callee = unwrapExpression(awaited.expression);
                let symbol = checker.getSymbolAtLocation(callee);
                if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
                    symbol = checker.getAliasedSymbol(symbol);
                const declarations = symbol?.declarations ?? [];
                const localDeclarations = projectSources
                    ? declarations.filter((candidate) => projectSources.has(candidate.getSourceFile())) : [];
                const functionDeclarations = localDeclarations.filter((candidate) => (typescript_1.default.isFunctionDeclaration(candidate) && candidate.body !== undefined));
                const functionDeclaration = functionDeclarations.length === 1 ? functionDeclarations[0] : undefined;
                const variableDeclarations = localDeclarations.filter(typescript_1.default.isVariableDeclaration);
                const variableDeclaration = variableDeclarations.length === 1 ? variableDeclarations[0] : undefined;
                const variableInitializer = variableDeclaration?.initializer
                    && typescript_1.default.isVariableDeclarationList(variableDeclaration.parent)
                    && variableDeclaration.parent.flags & typescript_1.default.NodeFlags.Const
                    ? unwrapExpression(variableDeclaration.initializer) : undefined;
                if (symbol && functionDeclaration
                    && callableBindingMayBeWritten(symbol, declarations, checker, projectSources, check))
                    return true;
                if (!functionDeclaration && variableDeclaration && !variableInitializer)
                    return true;
                const callable = functionDeclaration ?? variableInitializer;
                if (callable && (typescript_1.default.isFunctionDeclaration(callable)
                    || typescript_1.default.isFunctionExpression(callable) || typescript_1.default.isArrowFunction(callable))
                    && callable.body
                    && callable.modifiers?.some((modifier) => modifier.kind === typescript_1.default.SyntaxKind.AsyncKeyword)
                    && !((typescript_1.default.isFunctionDeclaration(callable) || typescript_1.default.isFunctionExpression(callable))
                        && callable.asteriskToken)) {
                    const callableBody = callable.body;
                    if (awaited.arguments.some(typescript_1.default.isSpreadElement)
                        || callable.parameters.some((parameter) => (!typescript_1.default.isIdentifier(parameter.name) || Boolean(parameter.dotDotDotToken))))
                        return deepContainsTarget(callableBody)
                            || callable.parameters.some((parameter) => Boolean(parameter.initializer && subtreeContainsTarget(parameter.initializer)))
                            || awaited.arguments.some((argument) => subtreeContainsTarget(typescript_1.default.isSpreadElement(argument) ? argument.expression : argument));
                    if (parameterDefaultsMayTarget(callable.parameters, awaited.arguments, depth, bindings))
                        return true;
                    if (callableParametersMayBeWritten(callableBody, callable.parameters))
                        return true;
                    const awaitedBindings = new Map(bindings);
                    for (let index = 0; index < callable.parameters.length; index += 1) {
                        const parameter = callable.parameters[index];
                        const parameterSymbol = checker.getSymbolAtLocation(parameter.name);
                        const argument = awaited.arguments[index];
                        if (!parameterSymbol)
                            continue;
                        if (!argument) {
                            if (parameter.initializer)
                                awaitedBindings.set(parameterSymbol, [parameter.initializer]);
                            continue;
                        }
                        if (!parameter.initializer) {
                            awaitedBindings.set(parameterSymbol, [argument]);
                            continue;
                        }
                        const state = nullishState(argument, false, depth + 1, bindings);
                        awaitedBindings.set(parameterSymbol, state === true
                            ? [parameter.initializer]
                            : state === false ? [argument] : [argument, parameter.initializer]);
                    }
                    return typescript_1.default.isBlock(callableBody)
                        ? sequenceFlow(callableBody.statements, 0, depth, awaitedBindings).target
                        : resolve(callableBody, depth + 1, awaitedBindings);
                }
            }
            return resolve(node.expression, depth + 1, bindings) || deepContainsTarget(node.expression);
        }
        if (typescript_1.default.isTaggedTemplateExpression(node)) {
            if (typescript_1.default.isTemplateExpression(node.template)
                && node.template.templateSpans.some((span) => resolve(span.expression, depth + 1, bindings)))
                return true;
            const tag = unwrapExpression(node.tag);
            if (!typescript_1.default.isIdentifier(tag)) {
                if (typescript_1.default.isPropertyAccessExpression(tag) || typescript_1.default.isElementAccessExpression(tag)) {
                    const receiver = unwrapExpression(tag.expression);
                    if (typescript_1.default.isIdentifier(receiver)) {
                        let receiverSymbol = checker.getSymbolAtLocation(receiver);
                        if (receiverSymbol?.flags && receiverSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                            receiverSymbol = checker.getAliasedSymbol(receiverSymbol);
                        }
                        if (receiverSymbol?.declarations?.some((candidate) => (projectSources?.has(candidate.getSourceFile()))))
                            return true;
                    }
                }
                return deepContainsTarget(tag);
            }
            let symbol = checker.getSymbolAtLocation(tag);
            if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
                symbol = checker.getAliasedSymbol(symbol);
            const declaration = symbol?.declarations?.find((candidate) => (typescript_1.default.isFunctionDeclaration(candidate) && candidate.body !== undefined)
                || (typescript_1.default.isVariableDeclaration(candidate) && candidate.initializer !== undefined));
            const callable = declaration && typescript_1.default.isFunctionDeclaration(declaration) ? declaration
                : declaration && typescript_1.default.isVariableDeclaration(declaration)
                    ? unwrapExpression(declaration.initializer) : undefined;
            if (!callable || (!typescript_1.default.isFunctionDeclaration(callable)
                && !typescript_1.default.isFunctionExpression(callable) && !typescript_1.default.isArrowFunction(callable)))
                return false;
            if (callable.modifiers?.some((modifier) => modifier.kind === typescript_1.default.SyntaxKind.AsyncKeyword)
                || ((typescript_1.default.isFunctionDeclaration(callable) || typescript_1.default.isFunctionExpression(callable))
                    && callable.asteriskToken))
                return false;
            const tagArguments = [node.template];
            if (typescript_1.default.isTemplateExpression(node.template)) {
                tagArguments.push(...node.template.templateSpans.map((span) => span.expression));
            }
            if (parameterDefaultsMayTarget(callable.parameters, tagArguments, depth, bindings))
                return true;
            const tagBindings = new Map(bindings);
            for (let index = 0; index < callable.parameters.length; index += 1) {
                const parameter = callable.parameters[index];
                if (!typescript_1.default.isIdentifier(parameter.name) || parameter.dotDotDotToken) {
                    return Boolean(callable.body && deepContainsTarget(callable.body));
                }
                const symbol = checker.getSymbolAtLocation(parameter.name);
                if (!symbol)
                    continue;
                const argument = tagArguments[index];
                if (argument)
                    tagBindings.set(symbol, [argument]);
                else if (parameter.initializer)
                    tagBindings.set(symbol, [parameter.initializer]);
            }
            if (!callable.body)
                return false;
            if (callableParametersMayBeWritten(callable.body, callable.parameters))
                return true;
            if (!typescript_1.default.isBlock(callable.body))
                return resolve(callable.body, depth + 1, tagBindings);
            return sequenceFlow(callable.body.statements, 0, depth, tagBindings).target;
        }
        if (typescript_1.default.isConditionalExpression(node)) {
            const condition = truthiness(node.condition, depth + 1, bindings);
            return condition === true
                ? resolve(node.whenTrue, depth + 1, bindings)
                : condition === false
                    ? resolve(node.whenFalse, depth + 1, bindings)
                    : resolve(node.whenTrue, depth + 1, bindings)
                        || resolve(node.whenFalse, depth + 1, bindings);
        }
        if (typescript_1.default.isPropertyAccessExpression(node) || typescript_1.default.isElementAccessExpression(node)) {
            const staticKey = typescript_1.default.isPropertyAccessExpression(node)
                ? node.name.text
                : node.argumentExpression
                    ? resolveStaticPropertyKey(node.argumentExpression, checker, check)
                    : undefined;
            const memberSymbol = (member) => {
                const key = typescript_1.default.isPropertyAccessExpression(member)
                    ? member.name.text
                    : member.argumentExpression
                        ? resolveStaticPropertyKey(member.argumentExpression, checker, check)
                        : undefined;
                return key === undefined
                    ? undefined
                    : checker.getTypeAtLocation(member.expression).getProperty(key);
            };
            const receiver = unwrapExpression(node.expression);
            if (staticKey === undefined) {
                const dynamicArrayTarget = (array, arrayDepth) => {
                    if (arrayDepth > 64)
                        return true;
                    for (const element of array.elements) {
                        check();
                        if (typescript_1.default.isOmittedExpression(element))
                            continue;
                        if (!typescript_1.default.isSpreadElement(element)) {
                            if (resolve(element, depth + 1, bindings))
                                return true;
                            continue;
                        }
                        const spread = unwrapExpression(element.expression);
                        if (!typescript_1.default.isArrayLiteralExpression(spread) || dynamicArrayTarget(spread, arrayDepth + 1)) {
                            return true;
                        }
                    }
                    return false;
                };
                const dynamicObjectTarget = (object) => {
                    const values = new Map();
                    for (const property of object.properties) {
                        check();
                        if (typescript_1.default.isGetAccessorDeclaration(property) || typescript_1.default.isSpreadAssignment(property))
                            return true;
                        const name = property.name;
                        const key = typescript_1.default.isComputedPropertyName(name)
                            ? resolveStaticPropertyKey(name.expression, checker, check)
                            : typescript_1.default.isIdentifier(name) || typescript_1.default.isStringLiteral(name) || typescript_1.default.isNumericLiteral(name)
                                ? name.text : undefined;
                        if (key === undefined)
                            return true;
                        if (key === '__proto__' && typescript_1.default.isPropertyAssignment(property)
                            && !typescript_1.default.isComputedPropertyName(name)) {
                            if (maySetObjectPrototype(property.initializer))
                                return true;
                            continue;
                        }
                        values.set(key, typescript_1.default.isPropertyAssignment(property) ? property.initializer
                            : typescript_1.default.isShorthandPropertyAssignment(property) ? property.name : undefined);
                    }
                    return [...values.values()].some((value) => Boolean(value && resolve(value, depth + 1, bindings)));
                };
                if (typescript_1.default.isIdentifier(receiver)) {
                    let receiverSymbol = checker.getSymbolAtLocation(receiver);
                    if (receiverSymbol?.flags && receiverSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                        receiverSymbol = checker.getAliasedSymbol(receiverSymbol);
                    }
                    const declarations = receiverSymbol?.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
                    const declaration = declarations.length === 1 ? declarations[0] : undefined;
                    const initializer = declaration?.initializer && typescript_1.default.isVariableDeclarationList(declaration.parent)
                        && declaration.parent.flags & typescript_1.default.NodeFlags.Const
                        ? unwrapExpression(declaration.initializer) : undefined;
                    if (!receiverSymbol || !initializer || !typescript_1.default.isObjectLiteralExpression(initializer))
                        return true;
                    let unsafeReference = false;
                    const references = projectSources ? [...projectSources] : [];
                    while (references.length > 0 && !unsafeReference) {
                        check();
                        const reference = references.pop();
                        if (typescript_1.default.isIdentifier(reference)) {
                            let referenceSymbol = checker.getSymbolAtLocation(reference);
                            if (referenceSymbol?.flags && referenceSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                                referenceSymbol = checker.getAliasedSymbol(referenceSymbol);
                            }
                            if (referenceSymbol === receiverSymbol && reference !== declaration?.name
                                && reference !== receiver) {
                                const member = (typescript_1.default.isPropertyAccessExpression(reference.parent)
                                    || typescript_1.default.isElementAccessExpression(reference.parent))
                                    && reference.parent.expression === reference ? reference.parent : undefined;
                                if (!member || (typescript_1.default.isBinaryExpression(member.parent) && member.parent.left === member)) {
                                    unsafeReference = true;
                                }
                            }
                        }
                        typescript_1.default.forEachChild(reference, (child) => { references.push(child); });
                    }
                    if (unsafeReference)
                        return true;
                    return dynamicObjectTarget(initializer);
                }
                if (typescript_1.default.isArrayLiteralExpression(receiver))
                    return dynamicArrayTarget(receiver, 0);
                if (typescript_1.default.isObjectLiteralExpression(receiver))
                    return dynamicObjectTarget(receiver);
                return true;
            }
            if (typescript_1.default.isArrayLiteralExpression(receiver) && staticKey !== undefined
                && /^(0|[1-9]\d*)$/.test(staticKey)) {
                const index = Number(staticKey);
                const flatten = (array, flattenDepth) => {
                    if (flattenDepth > 64)
                        return undefined;
                    const values = [];
                    for (const element of array.elements) {
                        check();
                        if (typescript_1.default.isOmittedExpression(element)) {
                            values.push(undefined);
                            continue;
                        }
                        if (!typescript_1.default.isSpreadElement(element)) {
                            values.push(element);
                            continue;
                        }
                        const spread = unwrapExpression(element.expression);
                        if (!typescript_1.default.isArrayLiteralExpression(spread))
                            return undefined;
                        const spreadValues = flatten(spread, flattenDepth + 1);
                        if (!spreadValues)
                            return undefined;
                        values.push(...spreadValues);
                    }
                    return values;
                };
                const values = flatten(receiver, 0);
                if (!values)
                    return true;
                const value = values[index];
                return Boolean(value && resolve(value, depth + 1, bindings));
            }
            if (typescript_1.default.isIdentifier(receiver) && staticKey !== undefined && /^(0|[1-9]\d*)$/.test(staticKey)) {
                let receiverArraySymbol = checker.getSymbolAtLocation(receiver);
                if (receiverArraySymbol?.flags && receiverArraySymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                    receiverArraySymbol = checker.getAliasedSymbol(receiverArraySymbol);
                }
                const declarations = receiverArraySymbol?.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
                const declaration = declarations.length === 1 ? declarations[0] : undefined;
                if (declaration?.initializer && typescript_1.default.isVariableDeclarationList(declaration.parent)
                    && declaration.parent.flags & typescript_1.default.NodeFlags.Const
                    && typescript_1.default.isArrayLiteralExpression(unwrapExpression(declaration.initializer))) {
                    let escaped = false;
                    const references = projectSources ? [...projectSources] : [];
                    while (references.length > 0 && !escaped) {
                        check();
                        const reference = references.pop();
                        if (typescript_1.default.isIdentifier(reference)) {
                            let referenceSymbol = checker.getSymbolAtLocation(reference);
                            if (referenceSymbol?.flags && referenceSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                                referenceSymbol = checker.getAliasedSymbol(referenceSymbol);
                            }
                            if (referenceSymbol === receiverArraySymbol && reference !== declaration.name
                                && reference !== receiver) {
                                const member = (typescript_1.default.isPropertyAccessExpression(reference.parent)
                                    || typescript_1.default.isElementAccessExpression(reference.parent))
                                    && reference.parent.expression === reference ? reference.parent : undefined;
                                const memberKey = member && (typescript_1.default.isPropertyAccessExpression(member)
                                    ? member.name.text : member.argumentExpression
                                    ? resolveStaticPropertyKey(member.argumentExpression, checker, check) : undefined);
                                let written = false;
                                let invocationUsage = member;
                                while (invocationUsage && (typescript_1.default.isParenthesizedExpression(invocationUsage.parent)
                                    || typescript_1.default.isAsExpression(invocationUsage.parent)
                                    || typescript_1.default.isTypeAssertionExpression(invocationUsage.parent)
                                    || typescript_1.default.isSatisfiesExpression(invocationUsage.parent)
                                    || typescript_1.default.isNonNullExpression(invocationUsage.parent))
                                    && invocationUsage.parent.expression === invocationUsage) {
                                    invocationUsage = invocationUsage.parent;
                                }
                                const invoked = Boolean(invocationUsage
                                    && ((typescript_1.default.isCallExpression(invocationUsage.parent)
                                        && invocationUsage.parent.expression === invocationUsage)
                                        || (typescript_1.default.isTaggedTemplateExpression(invocationUsage.parent)
                                            && invocationUsage.parent.tag === invocationUsage)));
                                let target = member;
                                while (target?.parent && !typescript_1.default.isStatement(target)) {
                                    const parent = target.parent;
                                    if (typescript_1.default.isBinaryExpression(parent) && parent.left === target
                                        && parent.operatorToken.kind >= typescript_1.default.SyntaxKind.FirstAssignment
                                        && parent.operatorToken.kind <= typescript_1.default.SyntaxKind.LastAssignment) {
                                        written = true;
                                        break;
                                    }
                                    if ((typescript_1.default.isForOfStatement(parent) || typescript_1.default.isForInStatement(parent))
                                        && parent.initializer === target) {
                                        written = true;
                                        break;
                                    }
                                    target = parent;
                                }
                                if (!member || memberKey === undefined || !/^(0|[1-9]\d*)$/.test(memberKey)
                                    || written || invoked) {
                                    escaped = true;
                                }
                            }
                        }
                        typescript_1.default.forEachChild(reference, (child) => { references.push(child); });
                    }
                    if (escaped)
                        return true;
                    const array = unwrapExpression(declaration.initializer);
                    const flattenArray = (input, flattenDepth) => {
                        if (flattenDepth > 64)
                            return undefined;
                        const result = [];
                        for (const candidate of input.elements) {
                            check();
                            if (typescript_1.default.isOmittedExpression(candidate)) {
                                result.push(undefined);
                            }
                            else if (!typescript_1.default.isSpreadElement(candidate)) {
                                result.push(candidate);
                            }
                            else {
                                const spread = unwrapExpression(candidate.expression);
                                if (!typescript_1.default.isArrayLiteralExpression(spread))
                                    return undefined;
                                const values = flattenArray(spread, flattenDepth + 1);
                                if (!values)
                                    return undefined;
                                result.push(...values);
                            }
                        }
                        return result;
                    };
                    if (!typescript_1.default.isArrayLiteralExpression(array))
                        return true;
                    const values = flattenArray(array, 0);
                    if (!values)
                        return true;
                    const value = values[Number(staticKey)];
                    return Boolean(value && resolve(value, depth + 1, bindings));
                }
            }
            const symbol = memberSymbol(node);
            let receiverSymbol = typescript_1.default.isIdentifier(receiver)
                ? checker.getSymbolAtLocation(receiver)
                : typescript_1.default.isPropertyAccessExpression(receiver) || typescript_1.default.isElementAccessExpression(receiver)
                    ? memberSymbol(receiver)
                    : undefined;
            if (!receiverSymbol && (typescript_1.default.isFunctionExpression(receiver) || typescript_1.default.isArrowFunction(receiver))) {
                return false;
            }
            if (!receiverSymbol && !typescript_1.default.isIdentifier(receiver) && !typescript_1.default.isObjectLiteralExpression(receiver)) {
                return true;
            }
            if (receiverSymbol?.flags && receiverSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                receiverSymbol = checker.getAliasedSymbol(receiverSymbol);
            }
            const receiverDeclaration = receiverSymbol?.declarations?.filter(typescript_1.default.isVariableDeclaration);
            const receiverVariable = receiverDeclaration?.length === 1 ? receiverDeclaration[0] : undefined;
            const receiverObject = typescript_1.default.isObjectLiteralExpression(receiver) ? receiver
                : receiverVariable?.initializer
                    && typescript_1.default.isVariableDeclarationList(receiverVariable.parent)
                    && receiverVariable.parent.flags & typescript_1.default.NodeFlags.Const
                    && typescript_1.default.isObjectLiteralExpression(unwrapExpression(receiverVariable.initializer))
                    ? unwrapExpression(receiverVariable.initializer) : undefined;
            const objectProperty = (key) => {
                if (key === undefined || !receiverObject)
                    return undefined;
                let result;
                for (const candidate of receiverObject.properties) {
                    if (typescript_1.default.isSpreadAssignment(candidate)) {
                        result = null;
                        continue;
                    }
                    const name = candidate.name;
                    const propertyKey = typescript_1.default.isComputedPropertyName(name)
                        ? resolveStaticPropertyKey(name.expression, checker, check)
                        : typescript_1.default.isIdentifier(name) || typescript_1.default.isStringLiteral(name) || typescript_1.default.isNumericLiteral(name)
                            ? name.text : undefined;
                    if (propertyKey === '__proto__' && typescript_1.default.isPropertyAssignment(candidate)
                        && !typescript_1.default.isComputedPropertyName(name)) {
                        if (maySetObjectPrototype(candidate.initializer))
                            result = null;
                        continue;
                    }
                    if (propertyKey === undefined) {
                        if (typescript_1.default.isComputedPropertyName(name))
                            result = null;
                        continue;
                    }
                    if (propertyKey !== key)
                        continue;
                    result = typescript_1.default.isPropertyAssignment(candidate) || typescript_1.default.isShorthandPropertyAssignment(candidate)
                        ? candidate : null;
                }
                return result;
            };
            const runtimeProperty = objectProperty(staticKey);
            if (runtimeProperty === null)
                return true;
            if (!symbol) {
                if (runtimeProperty && typescript_1.default.isPropertyAssignment(runtimeProperty)) {
                    return resolve(runtimeProperty.initializer, depth + 1, bindings);
                }
                if (runtimeProperty && typescript_1.default.isShorthandPropertyAssignment(runtimeProperty)) {
                    return resolve(runtimeProperty.name, depth + 1, bindings);
                }
                if (receiverVariable?.initializer
                    && !typescript_1.default.isObjectLiteralExpression(unwrapExpression(receiverVariable.initializer))
                    && !typescript_1.default.isArrayLiteralExpression(unwrapExpression(receiverVariable.initializer)))
                    return true;
                return false;
            }
            if (resolving.has(symbol))
                return true;
            let wrappedReceivers = projectSources && WRAPPED_RECEIVER_CACHE.get(projectSources);
            if (receiverSymbol && projectSources && !wrappedReceivers) {
                const receivers = new Set();
                const candidates = [...projectSources];
                while (candidates.length > 0) {
                    check();
                    const candidate = candidates.pop();
                    if (typescript_1.default.isObjectLiteralExpression(candidate)) {
                        const properties = new Map();
                        for (const property of candidate.properties) {
                            if (typescript_1.default.isSpreadAssignment(property))
                                continue;
                            const name = property.name;
                            const key = typescript_1.default.isComputedPropertyName(name)
                                ? resolveStaticPropertyKey(name.expression, checker, check)
                                : typescript_1.default.isIdentifier(name) || typescript_1.default.isStringLiteral(name) || typescript_1.default.isNumericLiteral(name)
                                    ? name.text : undefined;
                            if (key !== undefined)
                                properties.set(key, property);
                        }
                        for (const property of properties.values()) {
                            const value = typescript_1.default.isShorthandPropertyAssignment(property) ? property.name
                                : typescript_1.default.isPropertyAssignment(property) ? unwrapExpression(property.initializer) : undefined;
                            if (!value || !typescript_1.default.isIdentifier(value))
                                continue;
                            let valueSymbol = typescript_1.default.isShorthandPropertyAssignment(property)
                                ? checker.getShorthandAssignmentValueSymbol(property)
                                : checker.getSymbolAtLocation(value);
                            if (valueSymbol?.flags && valueSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                                valueSymbol = checker.getAliasedSymbol(valueSymbol);
                            }
                            if (valueSymbol)
                                receivers.add(valueSymbol);
                        }
                    }
                    typescript_1.default.forEachChild(candidate, (child) => { candidates.push(child); });
                }
                wrappedReceivers = receivers;
                WRAPPED_RECEIVER_CACHE.set(projectSources, receivers);
            }
            if (receiverSymbol && projectSources && wrappedReceivers?.has(receiverSymbol)) {
                let wrapperMutationCache = WRAPPER_MUTATION_CACHE.get(projectSources);
                if (!wrapperMutationCache) {
                    wrapperMutationCache = new WeakMap();
                    WRAPPER_MUTATION_CACHE.set(projectSources, wrapperMutationCache);
                }
                const cachedWrapperMutation = wrapperMutationCache.get(receiverSymbol);
                if (cachedWrapperMutation)
                    return true;
                if (cachedWrapperMutation === undefined) {
                    const wrapperAliases = new Set();
                    const valueAliasesReceiver = (value) => {
                        const expression = unwrapExpression(value);
                        if (!typescript_1.default.isIdentifier(expression))
                            return false;
                        let valueSymbol = checker.getSymbolAtLocation(expression);
                        if (valueSymbol?.flags && valueSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                            valueSymbol = checker.getAliasedSymbol(valueSymbol);
                        }
                        return valueSymbol === receiverSymbol;
                    };
                    const objectPropertyAliasesReceiver = (object, key) => {
                        let selected;
                        for (const property of object.properties) {
                            check();
                            if (typescript_1.default.isSpreadAssignment(property)) {
                                selected = null;
                                continue;
                            }
                            const name = property.name;
                            const propertyKey = typescript_1.default.isComputedPropertyName(name)
                                ? resolveStaticPropertyKey(name.expression, checker, check)
                                : typescript_1.default.isIdentifier(name) || typescript_1.default.isStringLiteral(name) || typescript_1.default.isNumericLiteral(name)
                                    ? name.text : undefined;
                            if (propertyKey === undefined) {
                                if (typescript_1.default.isComputedPropertyName(name))
                                    selected = null;
                                continue;
                            }
                            if (propertyKey === key)
                                selected = property;
                        }
                        if (selected === null)
                            return undefined;
                        if (!selected)
                            return false;
                        const value = typescript_1.default.isShorthandPropertyAssignment(selected) ? selected.name
                            : typescript_1.default.isPropertyAssignment(selected) ? selected.initializer : undefined;
                        return Boolean(value && valueAliasesReceiver(value));
                    };
                    const objectForSymbol = (candidate) => {
                        const declarations = candidate.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
                        const declaration = declarations.length === 1 ? declarations[0] : undefined;
                        const initializer = declaration?.initializer && typescript_1.default.isVariableDeclarationList(declaration.parent)
                            && declaration.parent.flags & typescript_1.default.NodeFlags.Const
                            ? unwrapExpression(declaration.initializer) : undefined;
                        return initializer && typescript_1.default.isObjectLiteralExpression(initializer) ? initializer : undefined;
                    };
                    const memberAliasesReceiver = (input) => {
                        let member = unwrapExpression(input);
                        while (typescript_1.default.isPropertyAccessExpression(member) || typescript_1.default.isElementAccessExpression(member)) {
                            check();
                            const base = unwrapExpression(member.expression);
                            if (typescript_1.default.isIdentifier(base)) {
                                let baseSymbol = checker.getSymbolAtLocation(base);
                                if (baseSymbol?.flags && baseSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                                    baseSymbol = checker.getAliasedSymbol(baseSymbol);
                                }
                                if (baseSymbol && wrapperAliases.has(baseSymbol)) {
                                    const key = typescript_1.default.isPropertyAccessExpression(member) ? member.name.text
                                        : member.argumentExpression
                                            ? resolveStaticPropertyKey(member.argumentExpression, checker, check) : undefined;
                                    if (key === undefined)
                                        return true;
                                    const object = objectForSymbol(baseSymbol);
                                    if (!object)
                                        return true;
                                    return objectPropertyAliasesReceiver(object, key) !== false;
                                }
                            }
                            const propertySymbol = memberSymbol(member);
                            const matches = propertySymbol?.declarations?.some((property) => {
                                const value = typescript_1.default.isShorthandPropertyAssignment(property) ? property.name
                                    : typescript_1.default.isPropertyAssignment(property) ? unwrapExpression(property.initializer) : undefined;
                                if (!value || !typescript_1.default.isIdentifier(value))
                                    return false;
                                let valueSymbol = typescript_1.default.isShorthandPropertyAssignment(property)
                                    ? checker.getShorthandAssignmentValueSymbol(property)
                                    : checker.getSymbolAtLocation(value);
                                if (valueSymbol?.flags && valueSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                                    valueSymbol = checker.getAliasedSymbol(valueSymbol);
                                }
                                return valueSymbol === receiverSymbol;
                            });
                            if (matches)
                                return true;
                            member = unwrapExpression(member.expression);
                        }
                        return false;
                    };
                    const objectWrapsReceiver = (input) => {
                        const object = unwrapExpression(input);
                        if (!typescript_1.default.isObjectLiteralExpression(object))
                            return false;
                        return object.properties.some((property) => {
                            const value = typescript_1.default.isShorthandPropertyAssignment(property) ? property.name
                                : typescript_1.default.isPropertyAssignment(property) ? unwrapExpression(property.initializer) : undefined;
                            if (!value || !typescript_1.default.isIdentifier(value))
                                return false;
                            let valueSymbol = typescript_1.default.isShorthandPropertyAssignment(property)
                                ? checker.getShorthandAssignmentValueSymbol(property)
                                : checker.getSymbolAtLocation(value);
                            if (valueSymbol?.flags && valueSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                                valueSymbol = checker.getAliasedSymbol(valueSymbol);
                            }
                            return valueSymbol === receiverSymbol;
                        });
                    };
                    const aliasDeclarations = [];
                    const aliasNodes = [...projectSources];
                    while (aliasNodes.length > 0) {
                        check();
                        const candidate = aliasNodes.pop();
                        if (typescript_1.default.isVariableDeclaration(candidate) && candidate.initializer) {
                            aliasDeclarations.push(candidate);
                        }
                        typescript_1.default.forEachChild(candidate, (child) => { aliasNodes.push(child); });
                    }
                    let aliasesChanged = true;
                    while (aliasesChanged) {
                        aliasesChanged = false;
                        for (const declaration of aliasDeclarations) {
                            check();
                            const initializer = unwrapExpression(declaration.initializer);
                            let initializerSymbol = typescript_1.default.isIdentifier(initializer)
                                ? checker.getSymbolAtLocation(initializer) : undefined;
                            if (initializerSymbol?.flags && initializerSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                                initializerSymbol = checker.getAliasedSymbol(initializerSymbol);
                            }
                            const aliasesWrapper = memberAliasesReceiver(initializer) || objectWrapsReceiver(initializer)
                                || Boolean(initializerSymbol && wrapperAliases.has(initializerSymbol));
                            if (typescript_1.default.isIdentifier(declaration.name)) {
                                const alias = checker.getSymbolAtLocation(declaration.name);
                                if (!alias || wrapperAliases.has(alias) || !aliasesWrapper)
                                    continue;
                                wrapperAliases.add(alias);
                                aliasesChanged = true;
                                continue;
                            }
                            if (!typescript_1.default.isObjectBindingPattern(declaration.name))
                                continue;
                            const initializerType = checker.getTypeAtLocation(initializer);
                            for (const element of declaration.name.elements) {
                                if (element.dotDotDotToken || !typescript_1.default.isIdentifier(element.name))
                                    continue;
                                const keyNode = element.propertyName ?? element.name;
                                const key = typescript_1.default.isIdentifier(keyNode) || typescript_1.default.isStringLiteral(keyNode)
                                    || typescript_1.default.isNumericLiteral(keyNode) ? keyNode.text : undefined;
                                if (key === undefined)
                                    continue;
                                const initializerObject = initializerSymbol && wrapperAliases.has(initializerSymbol)
                                    ? objectForSymbol(initializerSymbol) : undefined;
                                const objectEdge = initializerObject
                                    ? objectPropertyAliasesReceiver(initializerObject, key) : false;
                                const property = initializerType.getProperty(key);
                                const propertyAliasesReceiver = initializerObject ? objectEdge !== false
                                    : property?.declarations?.some((candidate) => {
                                        const value = typescript_1.default.isShorthandPropertyAssignment(candidate) ? candidate.name
                                            : typescript_1.default.isPropertyAssignment(candidate)
                                                ? unwrapExpression(candidate.initializer) : undefined;
                                        if (!value || !typescript_1.default.isIdentifier(value))
                                            return false;
                                        let valueSymbol = typescript_1.default.isShorthandPropertyAssignment(candidate)
                                            ? checker.getShorthandAssignmentValueSymbol(candidate)
                                            : checker.getSymbolAtLocation(value);
                                        if (valueSymbol?.flags && valueSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                                            valueSymbol = checker.getAliasedSymbol(valueSymbol);
                                        }
                                        return valueSymbol === receiverSymbol;
                                    });
                                if (!propertyAliasesReceiver)
                                    continue;
                                const alias = checker.getSymbolAtLocation(element.name);
                                if (alias && !wrapperAliases.has(alias)) {
                                    wrapperAliases.add(alias);
                                    aliasesChanged = true;
                                }
                            }
                        }
                    }
                    let wrapperMutated = false;
                    const wrapperNodes = [...projectSources];
                    while (wrapperNodes.length > 0 && !wrapperMutated) {
                        check();
                        const candidate = wrapperNodes.pop();
                        if (typescript_1.default.isIdentifier(candidate)) {
                            let candidateSymbol = checker.getSymbolAtLocation(candidate);
                            if (candidateSymbol?.flags && candidateSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                                candidateSymbol = checker.getAliasedSymbol(candidateSymbol);
                            }
                            if (candidateSymbol && wrapperAliases.has(candidateSymbol)) {
                                const declarationName = typescript_1.default.isVariableDeclaration(candidate.parent)
                                    && candidate.parent.name === candidate;
                                const member = (typescript_1.default.isPropertyAccessExpression(candidate.parent)
                                    || typescript_1.default.isElementAccessExpression(candidate.parent))
                                    && candidate.parent.expression === candidate ? candidate.parent : undefined;
                                const staticDestructure = typescript_1.default.isVariableDeclaration(candidate.parent)
                                    && candidate.parent.initializer === candidate
                                    && typescript_1.default.isObjectBindingPattern(candidate.parent.name)
                                    && candidate.parent.name.elements.every((element) => {
                                        if (element.dotDotDotToken)
                                            return false;
                                        const property = element.propertyName ?? element.name;
                                        return typescript_1.default.isIdentifier(property) || typescript_1.default.isStringLiteral(property)
                                            || typescript_1.default.isNumericLiteral(property);
                                    });
                                if (!declarationName && !member && !staticDestructure)
                                    wrapperMutated = true;
                            }
                        }
                        if (typescript_1.default.isBinaryExpression(candidate)
                            && candidate.operatorToken.kind >= typescript_1.default.SyntaxKind.FirstAssignment
                            && candidate.operatorToken.kind <= typescript_1.default.SyntaxKind.LastAssignment
                            && deepContainsTarget(candidate.right)) {
                            let root = unwrapExpression(candidate.left);
                            while (typescript_1.default.isPropertyAccessExpression(root) || typescript_1.default.isElementAccessExpression(root)) {
                                root = unwrapExpression(root.expression);
                            }
                            let rootSymbol = typescript_1.default.isIdentifier(root) ? checker.getSymbolAtLocation(root) : undefined;
                            if (rootSymbol?.flags && rootSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                                rootSymbol = checker.getAliasedSymbol(rootSymbol);
                            }
                            if (rootSymbol && wrapperAliases.has(rootSymbol))
                                wrapperMutated = true;
                            let member = unwrapExpression(candidate.left);
                            while (!wrapperMutated
                                && (typescript_1.default.isPropertyAccessExpression(member) || typescript_1.default.isElementAccessExpression(member))) {
                                check();
                                const propertySymbol = memberSymbol(member);
                                const aliasesReceiver = propertySymbol?.declarations?.some((property) => {
                                    if (!typescript_1.default.isShorthandPropertyAssignment(property))
                                        return false;
                                    let valueSymbol = checker.getShorthandAssignmentValueSymbol(property);
                                    if (valueSymbol?.flags && valueSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                                        valueSymbol = checker.getAliasedSymbol(valueSymbol);
                                    }
                                    return valueSymbol === receiverSymbol;
                                });
                                if (aliasesReceiver)
                                    wrapperMutated = true;
                                member = unwrapExpression(member.expression);
                            }
                        }
                        typescript_1.default.forEachChild(candidate, (child) => { wrapperNodes.push(child); });
                    }
                    wrapperMutationCache.set(receiverSymbol, wrapperMutated);
                    if (wrapperMutated)
                        return true;
                }
            }
            const resolvesReceiver = (candidate) => {
                const expression = unwrapExpression(candidate);
                if (!receiverSymbol || !typescript_1.default.isIdentifier(expression))
                    return false;
                let candidateSymbol = checker.getSymbolAtLocation(expression);
                if (candidateSymbol?.flags && candidateSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                    candidateSymbol = checker.getAliasedSymbol(candidateSymbol);
                }
                return candidateSymbol === receiverSymbol;
            };
            const cacheKey = receiverSymbol ?? symbol;
            let escapeCache = projectSources && MEMBER_ESCAPE_CACHE.get(projectSources);
            if (projectSources && !escapeCache) {
                escapeCache = new WeakMap();
                MEMBER_ESCAPE_CACHE.set(projectSources, escapeCache);
            }
            let escapeAnalysis = escapeCache?.get(cacheKey);
            if (!escapeAnalysis) {
                let escaped = false;
                const assignedProperties = new Set();
                const deletedProperties = new Map();
                let referenceIndex = projectSources && MEMBER_REFERENCE_CACHE.get(projectSources);
                if (projectSources && !referenceIndex) {
                    const mutableIndex = new Map();
                    const addReference = (candidateSymbol, reference) => {
                        if (!candidateSymbol)
                            return;
                        const target = candidateSymbol.flags & typescript_1.default.SymbolFlags.Alias
                            ? checker.getAliasedSymbol(candidateSymbol) : candidateSymbol;
                        const existing = mutableIndex.get(target);
                        if (existing)
                            existing.push(reference);
                        else
                            mutableIndex.set(target, [reference]);
                    };
                    const projectNodes = [...projectSources];
                    while (projectNodes.length > 0) {
                        const candidate = projectNodes.pop();
                        check();
                        if (typescript_1.default.isIdentifier(candidate)) {
                            addReference(checker.getSymbolAtLocation(candidate), candidate);
                            if (typescript_1.default.isShorthandPropertyAssignment(candidate.parent)
                                && candidate.parent.name === candidate) {
                                addReference(checker.getShorthandAssignmentValueSymbol(candidate.parent), candidate);
                            }
                        }
                        if (typescript_1.default.isPropertyAccessExpression(candidate) || typescript_1.default.isElementAccessExpression(candidate)) {
                            addReference(memberSymbol(candidate), candidate);
                        }
                        typescript_1.default.forEachChild(candidate, (child) => { projectNodes.push(child); });
                    }
                    referenceIndex = mutableIndex;
                    MEMBER_REFERENCE_CACHE.set(projectSources, referenceIndex);
                }
                const references = receiverSymbol && referenceIndex
                    ? [...(referenceIndex.get(receiverSymbol) ?? [])]
                    : receiverSymbol
                        ? [node.getSourceFile(),
                            ...(symbol.declarations?.map((declaration) => declaration.getSourceFile()) ?? [])]
                        : [];
                const indexed = Boolean(receiverSymbol && referenceIndex);
                while (references.length > 0 && !escaped) {
                    const candidate = references.pop();
                    check();
                    const directReceiver = receiverSymbol && (typescript_1.default.isPropertyAccessExpression(candidate)
                        || typescript_1.default.isElementAccessExpression(candidate)) && memberSymbol(candidate) === receiverSymbol
                        ? candidate : undefined;
                    if (directReceiver || (typescript_1.default.isIdentifier(candidate) && resolvesReceiver(candidate))) {
                        const namedMember = !directReceiver && typescript_1.default.isIdentifier(candidate)
                            && typescript_1.default.isPropertyAccessExpression(candidate.parent)
                            && candidate.parent.name === candidate && memberSymbol(candidate.parent) === receiverSymbol
                            ? candidate.parent : undefined;
                        const reference = directReceiver ?? namedMember ?? candidate;
                        const declarationName = ((typescript_1.default.isVariableDeclaration(reference.parent)
                            || typescript_1.default.isParameter(reference.parent) || typescript_1.default.isBindingElement(reference.parent)
                            || typescript_1.default.isPropertyAssignment(reference.parent))
                            && reference.parent.name === reference);
                        const importName = (typescript_1.default.isImportSpecifier(reference.parent)
                            || typescript_1.default.isImportClause(reference.parent) || typescript_1.default.isNamespaceImport(reference.parent))
                            && reference.parent.name === reference;
                        const wrapperCandidate = typescript_1.default.isShorthandPropertyAssignment(reference.parent)
                            || (typescript_1.default.isPropertyAssignment(reference.parent)
                                && reference.parent.initializer === reference);
                        let wrapped = wrapperCandidate;
                        if (wrapped && typescript_1.default.isObjectLiteralExpression(reference.parent.parent)) {
                            const property = reference.parent;
                            const name = property.name;
                            const key = typescript_1.default.isComputedPropertyName(name)
                                ? resolveStaticPropertyKey(name.expression, checker, check)
                                : typescript_1.default.isIdentifier(name) || typescript_1.default.isStringLiteral(name) || typescript_1.default.isNumericLiteral(name)
                                    ? name.text : undefined;
                            if (key !== undefined) {
                                let selected;
                                for (const candidateProperty of reference.parent.parent.properties) {
                                    if (typescript_1.default.isSpreadAssignment(candidateProperty))
                                        continue;
                                    const candidateName = candidateProperty.name;
                                    const candidateKey = typescript_1.default.isComputedPropertyName(candidateName)
                                        ? resolveStaticPropertyKey(candidateName.expression, checker, check)
                                        : typescript_1.default.isIdentifier(candidateName) || typescript_1.default.isStringLiteral(candidateName)
                                            || typescript_1.default.isNumericLiteral(candidateName) ? candidateName.text : undefined;
                                    if (candidateKey === key)
                                        selected = candidateProperty;
                                }
                                wrapped = selected === property;
                            }
                        }
                        if (wrapped) {
                            const wrapperObject = reference.parent.parent;
                            const wrapperDeclaration = typescript_1.default.isObjectLiteralExpression(wrapperObject)
                                && typescript_1.default.isVariableDeclaration(wrapperObject.parent)
                                && typescript_1.default.isIdentifier(wrapperObject.parent.name) ? wrapperObject.parent : undefined;
                            let wrapperSymbol = wrapperDeclaration
                                ? checker.getSymbolAtLocation(wrapperDeclaration.name) : undefined;
                            if (wrapperSymbol?.flags && wrapperSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                                wrapperSymbol = checker.getAliasedSymbol(wrapperSymbol);
                            }
                            const mutations = projectSources ? [...projectSources] : [];
                            while (mutations.length > 0 && !escaped) {
                                check();
                                const mutation = mutations.pop();
                                if (wrapperSymbol && typescript_1.default.isIdentifier(mutation)) {
                                    let mutationSymbol = checker.getSymbolAtLocation(mutation);
                                    if (mutationSymbol?.flags && mutationSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                                        mutationSymbol = checker.getAliasedSymbol(mutationSymbol);
                                    }
                                    if (mutationSymbol === wrapperSymbol && mutation !== wrapperDeclaration?.name) {
                                        const member = (typescript_1.default.isPropertyAccessExpression(mutation.parent)
                                            || typescript_1.default.isElementAccessExpression(mutation.parent))
                                            && mutation.parent.expression === mutation ? mutation.parent : undefined;
                                        const staticDestructure = typescript_1.default.isVariableDeclaration(mutation.parent)
                                            && mutation.parent.initializer === mutation
                                            && typescript_1.default.isObjectBindingPattern(mutation.parent.name)
                                            && mutation.parent.name.elements.every((element) => {
                                                if (element.dotDotDotToken)
                                                    return false;
                                                const property = element.propertyName ?? element.name;
                                                return typescript_1.default.isIdentifier(property) || typescript_1.default.isStringLiteral(property)
                                                    || typescript_1.default.isNumericLiteral(property);
                                            });
                                        if (!member && !staticDestructure)
                                            escaped = true;
                                    }
                                }
                                if (typescript_1.default.isBinaryExpression(mutation)
                                    && mutation.operatorToken.kind >= typescript_1.default.SyntaxKind.FirstAssignment
                                    && mutation.operatorToken.kind <= typescript_1.default.SyntaxKind.LastAssignment
                                    && deepContainsTarget(mutation.right)) {
                                    let root = unwrapExpression(mutation.left);
                                    while (typescript_1.default.isPropertyAccessExpression(root) || typescript_1.default.isElementAccessExpression(root)) {
                                        root = unwrapExpression(root.expression);
                                    }
                                    let rootSymbol = typescript_1.default.isIdentifier(root) ? checker.getSymbolAtLocation(root) : undefined;
                                    if (rootSymbol?.flags && rootSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                                        rootSymbol = checker.getAliasedSymbol(rootSymbol);
                                    }
                                    escaped = Boolean(wrapperSymbol && rootSymbol === wrapperSymbol);
                                }
                                typescript_1.default.forEachChild(mutation, (child) => { mutations.push(child); });
                            }
                            continue;
                        }
                        if (wrapperCandidate)
                            continue;
                        const member = (typescript_1.default.isPropertyAccessExpression(reference.parent)
                            || typescript_1.default.isElementAccessExpression(reference.parent))
                            && reference.parent.expression === reference ? reference.parent : undefined;
                        const memberProperty = member && memberSymbol(member);
                        const getter = memberProperty?.declarations?.some(typescript_1.default.isGetAccessorDeclaration);
                        const declaredDataProperty = memberProperty?.declarations?.some((declaration) => (typescript_1.default.isPropertyAssignment(declaration) || typescript_1.default.isShorthandPropertyAssignment(declaration)));
                        const runtimeDataProperty = member && objectProperty(typescript_1.default.isPropertyAccessExpression(member) ? member.name.text
                            : member.argumentExpression
                                ? resolveStaticPropertyKey(member.argumentExpression, checker, check) : undefined);
                        let usage = member ?? reference;
                        while (usage && (typescript_1.default.isParenthesizedExpression(usage.parent)
                            || typescript_1.default.isAsExpression(usage.parent) || typescript_1.default.isTypeAssertionExpression(usage.parent)
                            || typescript_1.default.isSatisfiesExpression(usage.parent) || typescript_1.default.isNonNullExpression(usage.parent))
                            && usage.parent.expression === usage)
                            usage = usage.parent;
                        const invoked = usage && ((typescript_1.default.isCallExpression(usage.parent)
                            && usage.parent.expression === usage)
                            || (typescript_1.default.isTaggedTemplateExpression(usage.parent) && usage.parent.tag === usage));
                        const deletion = usage && typescript_1.default.isDeleteExpression(usage.parent)
                            && usage.parent.expression === usage ? usage.parent : undefined;
                        if (deletion && memberProperty) {
                            const deletions = deletedProperties.get(memberProperty);
                            if (deletions)
                                deletions.push(deletion);
                            else
                                deletedProperties.set(memberProperty, [deletion]);
                        }
                        let assigned = false;
                        let assignmentTarget = usage;
                        while (assignmentTarget?.parent && !typescript_1.default.isStatement(assignmentTarget)) {
                            const parent = assignmentTarget.parent;
                            if (typescript_1.default.isBinaryExpression(parent) && parent.left === assignmentTarget
                                && parent.operatorToken.kind >= typescript_1.default.SyntaxKind.FirstAssignment
                                && parent.operatorToken.kind <= typescript_1.default.SyntaxKind.LastAssignment) {
                                assigned = true;
                                break;
                            }
                            if ((typescript_1.default.isForOfStatement(parent) || typescript_1.default.isForInStatement(parent))
                                && parent.initializer === assignmentTarget) {
                                assigned = true;
                                break;
                            }
                            assignmentTarget = parent;
                        }
                        if (assigned && memberProperty)
                            assignedProperties.add(memberProperty);
                        const memberRead = Boolean(member && memberProperty && !getter && !invoked
                            && (declaredDataProperty || runtimeDataProperty)
                            && (!assigned || memberProperty !== undefined));
                        const usageParent = usage.parent;
                        const strictComparison = typescript_1.default.isBinaryExpression(usageParent)
                            && (usageParent.operatorToken.kind === typescript_1.default.SyntaxKind.EqualsEqualsEqualsToken
                                || usageParent.operatorToken.kind === typescript_1.default.SyntaxKind.ExclamationEqualsEqualsToken);
                        const logicalRead = typescript_1.default.isBinaryExpression(usageParent)
                            && (usageParent.operatorToken.kind === typescript_1.default.SyntaxKind.AmpersandAmpersandToken
                                || usageParent.operatorToken.kind === typescript_1.default.SyntaxKind.BarBarToken
                                || usageParent.operatorToken.kind === typescript_1.default.SyntaxKind.QuestionQuestionToken);
                        const readOnlyReference = !member && !assigned && !invoked && (strictComparison || logicalRead
                            || (typescript_1.default.isIfStatement(usageParent) && usageParent.expression === usage)
                            || (typescript_1.default.isConditionalExpression(usageParent) && usageParent.condition === usage)
                            || (typescript_1.default.isPrefixUnaryExpression(usageParent)
                                && usageParent.operator === typescript_1.default.SyntaxKind.ExclamationToken)
                            || (typescript_1.default.isTypeOfExpression(usageParent) || typescript_1.default.isVoidExpression(usageParent))
                            || typescript_1.default.isExpressionStatement(usageParent));
                        escaped = !declarationName && !importName && !memberRead && !readOnlyReference;
                    }
                    if (!indexed)
                        typescript_1.default.forEachChild(candidate, (child) => { references.push(child); });
                }
                escapeAnalysis = { escaped, assigned: assignedProperties, deleted: deletedProperties };
                escapeCache?.set(cacheKey, escapeAnalysis);
            }
            if (escapeAnalysis.escaped)
                return true;
            if (escapeAnalysis.assigned.has(symbol)) {
                let topLevelStatement = node;
                let delayed = false;
                while (!typescript_1.default.isSourceFile(topLevelStatement.parent)) {
                    topLevelStatement = topLevelStatement.parent;
                    delayed ||= typescript_1.default.isFunctionLike(topLevelStatement) || typescript_1.default.isClassLike(topLevelStatement);
                }
                if (delayed)
                    return true;
                let sawDirectAssignment = false;
                let uncertainAssignment = false;
                let latestAssignment;
                let latestStart = -1;
                for (const sourceFile of projectSources ?? [node.getSourceFile()]) {
                    const assignments = [sourceFile];
                    while (assignments.length > 0) {
                        const candidate = assignments.pop();
                        check();
                        if (typescript_1.default.isBinaryExpression(candidate)
                            && (typescript_1.default.isPropertyAccessExpression(unwrapExpression(candidate.left))
                                || typescript_1.default.isElementAccessExpression(unwrapExpression(candidate.left)))) {
                            const left = unwrapExpression(candidate.left);
                            if (memberSymbol(left) === symbol) {
                                sawDirectAssignment = true;
                                if (staticallyUnreachable(candidate, depth, bindings)) {
                                    typescript_1.default.forEachChild(candidate, (child) => { assignments.push(child); });
                                    continue;
                                }
                                const direct = candidate.operatorToken.kind === typescript_1.default.SyntaxKind.EqualsToken
                                    && typescript_1.default.isExpressionStatement(candidate.parent)
                                    && typescript_1.default.isSourceFile(candidate.parent.parent)
                                    && candidate.getSourceFile() === node.getSourceFile();
                                if (!direct)
                                    uncertainAssignment = true;
                                else if (candidate.getStart() < topLevelStatement.getStart()
                                    && candidate.getStart() > latestStart) {
                                    latestAssignment = candidate.right;
                                    latestStart = candidate.getStart();
                                }
                            }
                        }
                        typescript_1.default.forEachChild(candidate, (child) => { assignments.push(child); });
                    }
                }
                if (!sawDirectAssignment || uncertainAssignment)
                    return true;
                if (latestAssignment)
                    return resolve(latestAssignment, depth + 1, bindings);
            }
            const deletions = escapeAnalysis.deleted.get(symbol);
            if (deletions?.length) {
                const sourceFile = node.getSourceFile();
                let topLevelStatement = node;
                let delayed = false;
                while (!typescript_1.default.isSourceFile(topLevelStatement.parent)) {
                    topLevelStatement = topLevelStatement.parent;
                    delayed ||= typescript_1.default.isFunctionLike(topLevelStatement) || typescript_1.default.isClassLike(topLevelStatement);
                }
                const staticallyDeleted = deletions.every((deletion) => (node === unwrapExpression(expression) && !delayed
                    && deletion.getSourceFile() === sourceFile
                    && deletion.end <= topLevelStatement.getStart()
                    && typescript_1.default.isExpressionStatement(deletion.parent) && typescript_1.default.isSourceFile(deletion.parent.parent)));
                return !staticallyDeleted;
            }
            if (symbol.declarations?.some(typescript_1.default.isGetAccessorDeclaration))
                return true;
            resolving.add(symbol);
            const property = symbol.declarations?.find((candidate) => ((typescript_1.default.isPropertyAssignment(candidate) || typescript_1.default.isPropertyDeclaration(candidate))
                && candidate.initializer !== undefined));
            const shorthand = symbol.declarations?.find(typescript_1.default.isShorthandPropertyAssignment);
            const resolvedProperty = runtimeProperty !== undefined
                ? runtimeProperty && typescript_1.default.isPropertyAssignment(runtimeProperty) ? runtimeProperty : undefined
                : property;
            const resolvedShorthand = runtimeProperty !== undefined
                ? runtimeProperty && typescript_1.default.isShorthandPropertyAssignment(runtimeProperty) ? runtimeProperty : undefined
                : shorthand;
            let result = Boolean(resolvedProperty?.initializer
                && resolve(resolvedProperty.initializer, depth + 1, bindings));
            if (!result && resolvedShorthand) {
                const valueSymbol = checker.getShorthandAssignmentValueSymbol(resolvedShorthand);
                const declaration = valueSymbol?.declarations?.find((candidate) => typescript_1.default.isVariableDeclaration(candidate)
                    && candidate.initializer !== undefined
                    && typescript_1.default.isVariableDeclarationList(candidate.parent)
                    && Boolean(candidate.parent.flags & typescript_1.default.NodeFlags.Const));
                result = Boolean(declaration?.initializer
                    && resolve(declaration.initializer, depth + 1, bindings));
            }
            resolving.delete(symbol);
            return result;
        }
        if (typescript_1.default.isBinaryExpression(node)) {
            if (node.operatorToken.kind === typescript_1.default.SyntaxKind.EqualsToken) {
                return resolve(node.right, depth + 1, bindings);
            }
            if (node.operatorToken.kind === typescript_1.default.SyntaxKind.CommaToken) {
                return resolve(node.right, depth + 1, bindings);
            }
            const logicalAnd = node.operatorToken.kind === typescript_1.default.SyntaxKind.AmpersandAmpersandToken
                || node.operatorToken.kind === typescript_1.default.SyntaxKind.AmpersandAmpersandEqualsToken;
            const logicalOr = node.operatorToken.kind === typescript_1.default.SyntaxKind.BarBarToken
                || node.operatorToken.kind === typescript_1.default.SyntaxKind.BarBarEqualsToken;
            if (logicalAnd || logicalOr) {
                const left = truthiness(node.left, depth + 1, bindings);
                if (logicalAnd) {
                    if (left === false)
                        return resolve(node.left, depth + 1, bindings);
                    if (left === true)
                        return resolve(node.right, depth + 1, bindings);
                    return resolve(node.right, depth + 1, bindings);
                }
                if (left === true)
                    return resolve(node.left, depth + 1, bindings);
                if (left === false)
                    return resolve(node.right, depth + 1, bindings);
                return resolve(node.left, depth + 1, bindings)
                    || resolve(node.right, depth + 1, bindings);
            }
            if (node.operatorToken.kind === typescript_1.default.SyntaxKind.QuestionQuestionToken
                || node.operatorToken.kind === typescript_1.default.SyntaxKind.QuestionQuestionEqualsToken) {
                const left = nullishState(node.left, true, depth + 1, bindings);
                return left === true
                    ? resolve(node.right, depth + 1, bindings)
                    : left === false
                        ? resolve(node.left, depth + 1, bindings)
                        : resolve(node.left, depth + 1, bindings)
                            || resolve(node.right, depth + 1, bindings);
            }
        }
        if (typescript_1.default.isCallExpression(node)) {
            let callee = unwrapExpression(node.expression);
            while (typescript_1.default.isBinaryExpression(callee)
                && callee.operatorToken.kind === typescript_1.default.SyntaxKind.CommaToken)
                callee = unwrapExpression(callee.right);
            if (typescript_1.default.isConditionalExpression(callee)) {
                const condition = truthiness(callee.condition, depth + 1, bindings);
                if (condition === true)
                    callee = unwrapExpression(callee.whenTrue);
                else if (condition === false)
                    callee = unwrapExpression(callee.whenFalse);
                else {
                    const callableAnalysis = (candidate) => {
                        const target = unwrapExpression(candidate);
                        const direct = typescript_1.default.isFunctionExpression(target) || typescript_1.default.isArrowFunction(target)
                            ? target : undefined;
                        if (direct) {
                            const sync = !direct.modifiers?.some((modifier) => modifier.kind === typescript_1.default.SyntaxKind.AsyncKeyword)
                                && !(typescript_1.default.isFunctionExpression(direct) && direct.asteriskToken);
                            return { sync, target: sync && (parameterDefaultsMayTarget(direct.parameters, node.arguments, depth, bindings) || deepContainsTarget(direct.body)) };
                        }
                        if (!typescript_1.default.isIdentifier(target)) {
                            if (typescript_1.default.isPropertyAccessExpression(target) || typescript_1.default.isElementAccessExpression(target)) {
                                let receiver = unwrapExpression(target.expression);
                                while (typescript_1.default.isPropertyAccessExpression(receiver) || typescript_1.default.isElementAccessExpression(receiver)) {
                                    receiver = unwrapExpression(receiver.expression);
                                }
                                if (typescript_1.default.isIdentifier(receiver)) {
                                    let receiverSymbol = checker.getSymbolAtLocation(receiver);
                                    if (receiverSymbol?.flags && receiverSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                                        receiverSymbol = checker.getAliasedSymbol(receiverSymbol);
                                    }
                                    if (receiverSymbol?.declarations?.some((item) => (projectSources?.has(item.getSourceFile()))))
                                        return { sync: true, target: true };
                                }
                            }
                            return { sync: true, target: deepContainsTarget(target) };
                        }
                        let symbol = checker.getSymbolAtLocation(target);
                        if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
                            symbol = checker.getAliasedSymbol(symbol);
                        const declaration = symbol?.declarations?.find((item) => (typescript_1.default.isFunctionDeclaration(item) && item.body !== undefined)
                            || (typescript_1.default.isVariableDeclaration(item) && item.initializer !== undefined));
                        const implementation = declaration && typescript_1.default.isFunctionDeclaration(declaration) ? declaration
                            : declaration && typescript_1.default.isVariableDeclaration(declaration)
                                ? unwrapExpression(declaration.initializer) : undefined;
                        if (!implementation || (!typescript_1.default.isFunctionDeclaration(implementation)
                            && !typescript_1.default.isFunctionExpression(implementation)
                            && !typescript_1.default.isArrowFunction(implementation)))
                            return { sync: true, target: false };
                        if (implementation.modifiers?.some((modifier) => modifier.kind === typescript_1.default.SyntaxKind.AsyncKeyword)
                            || ((typescript_1.default.isFunctionDeclaration(implementation) || typescript_1.default.isFunctionExpression(implementation))
                                && implementation.asteriskToken))
                            return { sync: false, target: false };
                        return { sync: true, target: parameterDefaultsMayTarget(implementation.parameters, node.arguments, depth, bindings) || Boolean(implementation.body && deepContainsTarget(implementation.body)) };
                    };
                    const alternatives = [callableAnalysis(callee.whenTrue), callableAnalysis(callee.whenFalse)];
                    if (!alternatives.some(({ sync }) => sync))
                        return false;
                    if (node.arguments.some((argument) => subtreeContainsTarget(typescript_1.default.isSpreadElement(argument) ? argument.expression : argument)))
                        return true;
                    return alternatives.some(({ sync, target }) => sync && target);
                }
            }
            if (typescript_1.default.isIdentifier(callee)) {
                let calleeSymbol = checker.getSymbolAtLocation(callee);
                if (calleeSymbol?.flags && calleeSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                    calleeSymbol = checker.getAliasedSymbol(calleeSymbol);
                }
                const declarations = calleeSymbol?.declarations ?? [];
                const localDeclarations = projectSources
                    ? declarations.filter((declaration) => projectSources.has(declaration.getSourceFile())) : [];
                const functionDeclarations = localDeclarations.filter((declaration) => (typescript_1.default.isFunctionDeclaration(declaration) && declaration.body !== undefined));
                const functionDeclaration = functionDeclarations.length === 1
                    ? functionDeclarations[0] : undefined;
                const variableDeclarations = calleeSymbol?.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
                const variableDeclaration = variableDeclarations.length === 1 ? variableDeclarations[0] : undefined;
                const variableInitializer = variableDeclaration?.initializer
                    && typescript_1.default.isVariableDeclarationList(variableDeclaration.parent)
                    && variableDeclaration.parent.flags & typescript_1.default.NodeFlags.Const
                    ? unwrapExpression(variableDeclaration.initializer) : undefined;
                if (functionDeclaration) {
                    if (calleeSymbol && callableBindingMayBeWritten(calleeSymbol, declarations, checker, projectSources, check))
                        return true;
                    callee = functionDeclaration;
                }
                else if (variableInitializer && (typescript_1.default.isArrowFunction(variableInitializer)
                    || typescript_1.default.isFunctionExpression(variableInitializer)))
                    callee = variableInitializer;
                else if (localDeclarations.length > 0)
                    return true;
                else
                    return node.arguments.some((argument) => resolve(typescript_1.default.isSpreadElement(argument) ? argument.expression : argument, depth + 1, bindings));
            }
            if (!typescript_1.default.isArrowFunction(callee) && !typescript_1.default.isFunctionExpression(callee)
                && !typescript_1.default.isFunctionDeclaration(callee)) {
                if (typescript_1.default.isCallExpression(callee)) {
                    return resolve(callee, depth + 1, bindings) || deepContainsTarget(callee);
                }
                if (node.arguments.some((argument) => subtreeContainsTarget(typescript_1.default.isSpreadElement(argument) ? argument.expression : argument)))
                    return true;
                if (typescript_1.default.isPropertyAccessExpression(callee) || typescript_1.default.isElementAccessExpression(callee)) {
                    const receiver = unwrapExpression(callee.expression);
                    const key = typescript_1.default.isPropertyAccessExpression(callee) ? callee.name.text
                        : callee.argumentExpression
                            ? resolveStaticPropertyKey(callee.argumentExpression, checker, check) : undefined;
                    if (key === 'valueOf' && node.arguments.length === 0
                        && isStaticSymbolFrom(receiver, checker, check, moduleName, importedName))
                        return true;
                    if (!typescript_1.default.isIdentifier(receiver) && !typescript_1.default.isFunctionExpression(receiver)
                        && !typescript_1.default.isArrowFunction(receiver)
                        && subtreeContainsTarget(receiver))
                        return true;
                    if (typescript_1.default.isFunctionExpression(receiver) || typescript_1.default.isArrowFunction(receiver)) {
                        if (key === undefined)
                            return true;
                        if (key !== 'call' && key !== 'apply')
                            return false;
                        if (receiver.modifiers?.some((modifier) => modifier.kind === typescript_1.default.SyntaxKind.AsyncKeyword)
                            || (typescript_1.default.isFunctionExpression(receiver) && receiver.asteriskToken))
                            return false;
                        const invocationArgs = key === 'call'
                            ? node.arguments.slice(1)
                            : (() => {
                                const list = node.arguments[1] && unwrapExpression(node.arguments[1]);
                                return list && typescript_1.default.isArrayLiteralExpression(list)
                                    ? list.elements.some(typescript_1.default.isSpreadElement) ? undefined
                                        : [...list.elements].map((element) => (typescript_1.default.isOmittedExpression(element) ? undefined : element))
                                    : list === undefined ? [] : undefined;
                            })();
                        if (invocationArgs === undefined)
                            return true;
                        if (parameterDefaultsMayTarget(receiver.parameters, invocationArgs, depth, bindings))
                            return true;
                        if (typescript_1.default.isFunctionExpression(receiver) && callableUsesThis(receiver))
                            return true;
                        return typescript_1.default.isBlock(receiver.body)
                            ? receiver.body.statements.some(subtreeContainsTarget)
                            : subtreeContainsTarget(receiver.body);
                    }
                    if (typescript_1.default.isIdentifier(receiver) && key !== undefined) {
                        let localSymbol = checker.getSymbolAtLocation(receiver);
                        if (localSymbol?.flags && localSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                            localSymbol = checker.getAliasedSymbol(localSymbol);
                        }
                        const declarations = localSymbol?.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
                        const declaration = declarations.length === 1 ? declarations[0] : undefined;
                        const initializer = declaration?.initializer
                            && typescript_1.default.isVariableDeclarationList(declaration.parent)
                            && declaration.parent.flags & typescript_1.default.NodeFlags.Const
                            ? unwrapExpression(declaration.initializer) : undefined;
                        if (initializer && typescript_1.default.isObjectLiteralExpression(initializer)) {
                            const references = projectSources ? [...projectSources] : [];
                            while (references.length > 0) {
                                check();
                                const reference = references.pop();
                                if (typescript_1.default.isIdentifier(reference)) {
                                    let referenceSymbol = checker.getSymbolAtLocation(reference);
                                    if (referenceSymbol?.flags && referenceSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                                        referenceSymbol = checker.getAliasedSymbol(referenceSymbol);
                                    }
                                    if (referenceSymbol === localSymbol && reference !== declaration?.name
                                        && reference !== receiver) {
                                        const member = (typescript_1.default.isPropertyAccessExpression(reference.parent)
                                            || typescript_1.default.isElementAccessExpression(reference.parent))
                                            && reference.parent.expression === reference ? reference.parent : undefined;
                                        if (!member)
                                            return true;
                                        const memberKey = typescript_1.default.isPropertyAccessExpression(member) ? member.name.text
                                            : member.argumentExpression
                                                ? resolveStaticPropertyKey(member.argumentExpression, checker, check) : undefined;
                                        let usage = member;
                                        while ((typescript_1.default.isParenthesizedExpression(usage.parent)
                                            || typescript_1.default.isAsExpression(usage.parent) || typescript_1.default.isTypeAssertionExpression(usage.parent)
                                            || typescript_1.default.isSatisfiesExpression(usage.parent) || typescript_1.default.isNonNullExpression(usage.parent))
                                            && usage.parent.expression === usage)
                                            usage = usage.parent;
                                        const invoked = (typescript_1.default.isCallExpression(usage.parent)
                                            && usage.parent.expression === usage)
                                            || (typescript_1.default.isTaggedTemplateExpression(usage.parent) && usage.parent.tag === usage);
                                        const getter = memberKey !== undefined
                                            && checker.getTypeAtLocation(member.expression).getProperty(memberKey)
                                                ?.declarations?.some(typescript_1.default.isGetAccessorDeclaration);
                                        let written = false;
                                        let target = usage;
                                        while (target.parent && !typescript_1.default.isStatement(target)) {
                                            const parent = target.parent;
                                            if (typescript_1.default.isBinaryExpression(parent) && parent.left === target
                                                && parent.operatorToken.kind >= typescript_1.default.SyntaxKind.FirstAssignment
                                                && parent.operatorToken.kind <= typescript_1.default.SyntaxKind.LastAssignment) {
                                                written = true;
                                                break;
                                            }
                                            if ((typescript_1.default.isForOfStatement(parent) || typescript_1.default.isForInStatement(parent))
                                                && parent.initializer === target) {
                                                written = true;
                                                break;
                                            }
                                            target = parent;
                                        }
                                        if (memberKey === undefined || typescript_1.default.isDeleteExpression(usage.parent)
                                            || invoked || getter || written)
                                            return true;
                                    }
                                }
                                typescript_1.default.forEachChild(reference, (child) => { references.push(child); });
                            }
                            let selected;
                            for (const property of initializer.properties) {
                                if (typescript_1.default.isSpreadAssignment(property)) {
                                    selected = null;
                                    continue;
                                }
                                const name = property.name;
                                const propertyKey = typescript_1.default.isComputedPropertyName(name)
                                    ? resolveStaticPropertyKey(name.expression, checker, check)
                                    : typescript_1.default.isIdentifier(name) || typescript_1.default.isStringLiteral(name) || typescript_1.default.isNumericLiteral(name)
                                        ? name.text : undefined;
                                if (propertyKey === undefined) {
                                    if (typescript_1.default.isComputedPropertyName(name))
                                        selected = null;
                                    continue;
                                }
                                if (propertyKey === key)
                                    selected = property;
                            }
                            if (selected === null)
                                return true;
                            if (!selected)
                                return false;
                            const callable = typescript_1.default.isMethodDeclaration(selected) ? selected
                                : typescript_1.default.isPropertyAssignment(selected)
                                    && (typescript_1.default.isFunctionExpression(selected.initializer)
                                        || typescript_1.default.isArrowFunction(selected.initializer)) ? selected.initializer : undefined;
                            if (!callable)
                                return Boolean(selected);
                            if (callable.modifiers?.some((modifier) => modifier.kind === typescript_1.default.SyntaxKind.AsyncKeyword)
                                || ((typescript_1.default.isMethodDeclaration(callable) || typescript_1.default.isFunctionExpression(callable))
                                    && callable.asteriskToken))
                                return false;
                            if (!callable.body)
                                return false;
                            callee = callable;
                        }
                    }
                    let rootReceiver = receiver;
                    while (typescript_1.default.isPropertyAccessExpression(rootReceiver) || typescript_1.default.isElementAccessExpression(rootReceiver)) {
                        rootReceiver = unwrapExpression(rootReceiver.expression);
                    }
                    if (!typescript_1.default.isArrowFunction(callee) && !typescript_1.default.isFunctionExpression(callee)
                        && !typescript_1.default.isFunctionDeclaration(callee) && !typescript_1.default.isMethodDeclaration(callee)
                        && typescript_1.default.isIdentifier(rootReceiver)) {
                        let receiverSymbol = checker.getSymbolAtLocation(rootReceiver);
                        if (receiverSymbol?.flags && receiverSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                            receiverSymbol = checker.getAliasedSymbol(receiverSymbol);
                        }
                        if (receiverSymbol?.declarations?.some((declaration) => (projectSources?.has(declaration.getSourceFile()))))
                            return true;
                    }
                    if (typescript_1.default.isObjectLiteralExpression(receiver)) {
                        if (key === undefined)
                            return true;
                        let selected;
                        for (const property of receiver.properties) {
                            if (typescript_1.default.isSpreadAssignment(property)) {
                                selected = null;
                                continue;
                            }
                            const name = property.name;
                            const propertyKey = typescript_1.default.isComputedPropertyName(name)
                                ? resolveStaticPropertyKey(name.expression, checker, check)
                                : typescript_1.default.isIdentifier(name) || typescript_1.default.isStringLiteral(name) || typescript_1.default.isNumericLiteral(name)
                                    ? name.text : undefined;
                            if (propertyKey === undefined) {
                                if (typescript_1.default.isComputedPropertyName(name))
                                    selected = null;
                                continue;
                            }
                            if (propertyKey === key)
                                selected = property;
                        }
                        if (selected === null)
                            return true;
                        if (!selected)
                            return false;
                        const callable = typescript_1.default.isMethodDeclaration(selected) ? selected
                            : typescript_1.default.isPropertyAssignment(selected)
                                && (typescript_1.default.isFunctionExpression(selected.initializer)
                                    || typescript_1.default.isArrowFunction(selected.initializer))
                                ? selected.initializer : undefined;
                        if (!callable)
                            return Boolean(selected);
                        if (callable.modifiers?.some((modifier) => modifier.kind === typescript_1.default.SyntaxKind.AsyncKeyword)
                            || ((typescript_1.default.isMethodDeclaration(callable) || typescript_1.default.isFunctionExpression(callable))
                                && callable.asteriskToken))
                            return false;
                        if (!callable.body)
                            return false;
                        if (parameterDefaultsMayTarget(callable.parameters, node.arguments, depth, bindings))
                            return true;
                        if (!typescript_1.default.isArrowFunction(callable) && callableUsesThis(callable))
                            return true;
                        callee = callable;
                    }
                }
                if (!typescript_1.default.isArrowFunction(callee) && !typescript_1.default.isFunctionExpression(callee)
                    && !typescript_1.default.isFunctionDeclaration(callee) && !typescript_1.default.isMethodDeclaration(callee))
                    return false;
            }
            const calleeBody = callee.body;
            if (!calleeBody)
                return false;
            if (callee.modifiers?.some((modifier) => modifier.kind === typescript_1.default.SyntaxKind.AsyncKeyword)
                || ((typescript_1.default.isFunctionExpression(callee) || typescript_1.default.isFunctionDeclaration(callee))
                    && callee.asteriskToken))
                return false;
            if (!typescript_1.default.isArrowFunction(callee)) {
                const bodyNodes = [];
                typescript_1.default.forEachChild(calleeBody, (child) => { bodyNodes.push(child); });
                while (bodyNodes.length > 0) {
                    const child = bodyNodes.pop();
                    check();
                    if ((typescript_1.default.isFunctionLike(child) && !typescript_1.default.isArrowFunction(child)) || typescript_1.default.isClassLike(child))
                        continue;
                    if (typescript_1.default.isIdentifier(child) && child.text === 'arguments') {
                        const parent = child.parent;
                        const declarationName = 'name' in parent && parent.name === child
                            && !typescript_1.default.isShorthandPropertyAssignment(parent);
                        const bindingKey = typescript_1.default.isBindingElement(parent) && parent.propertyName === child;
                        const accessName = typescript_1.default.isPropertyAccessExpression(parent) && parent.name === child;
                        const label = (typescript_1.default.isLabeledStatement(parent) || typescript_1.default.isBreakStatement(parent)
                            || typescript_1.default.isContinueStatement(parent)) && parent.label === child;
                        const qualifiedName = typescript_1.default.isQualifiedName(parent);
                        let typeOnly = false;
                        let ancestor = parent;
                        while (ancestor && !typescript_1.default.isStatement(ancestor) && !typescript_1.default.isExpression(ancestor)) {
                            if (typescript_1.default.isTypeNode(ancestor)) {
                                typeOnly = true;
                                break;
                            }
                            ancestor = ancestor.parent;
                        }
                        if (!declarationName && !bindingKey && !accessName && !label
                            && !qualifiedName && !typeOnly)
                            return true;
                    }
                    typescript_1.default.forEachChild(child, (descendant) => { bodyNodes.push(descendant); });
                }
            }
            if (callableParametersMayBeWritten(calleeBody, callee.parameters))
                return true;
            const localBindings = new Map(bindings);
            const callArguments = [];
            for (const argument of node.arguments) {
                if (!typescript_1.default.isSpreadElement(argument)) {
                    callArguments.push(argument);
                    continue;
                }
                const spread = unwrapExpression(argument.expression);
                if (typescript_1.default.isArrayLiteralExpression(spread)
                    && spread.elements.every((element) => (!typescript_1.default.isSpreadElement(element) && !typescript_1.default.isOmittedExpression(element)))) {
                    callArguments.push(...spread.elements);
                    continue;
                }
                return subtreeContainsTarget(calleeBody)
                    || node.arguments.some((candidate) => subtreeContainsTarget(typescript_1.default.isSpreadElement(candidate) ? candidate.expression : candidate))
                    || callee.parameters.slice(callArguments.length).some((parameter) => (Boolean(parameter.initializer && subtreeContainsTarget(parameter.initializer))));
            }
            for (let index = 0; index < callee.parameters.length; index += 1) {
                const parameter = callee.parameters[index];
                if (!typescript_1.default.isIdentifier(parameter.name) || parameter.dotDotDotToken) {
                    return subtreeContainsTarget(calleeBody)
                        || node.arguments.some((candidate) => subtreeContainsTarget(typescript_1.default.isSpreadElement(candidate) ? candidate.expression : candidate))
                        || callee.parameters.some((candidate) => Boolean(candidate.initializer && subtreeContainsTarget(candidate.initializer)));
                }
                const symbol = checker.getSymbolAtLocation(parameter.name);
                const argument = callArguments[index];
                if (!symbol)
                    continue;
                if (!argument) {
                    if (parameter.initializer)
                        localBindings.set(symbol, [parameter.initializer]);
                    continue;
                }
                if (!parameter.initializer) {
                    localBindings.set(symbol, [argument]);
                    continue;
                }
                const state = nullishState(argument, false, depth + 1, bindings);
                localBindings.set(symbol, state === true
                    ? [parameter.initializer]
                    : state === false
                        ? [argument]
                        : [argument, parameter.initializer]);
            }
            if (!typescript_1.default.isBlock(calleeBody))
                return resolve(calleeBody, depth + 1, localBindings);
            return sequenceFlow(calleeBody.statements, 0, depth, localBindings).target;
        }
        if (!typescript_1.default.isIdentifier(node))
            return false;
        let symbol = checker.getSymbolAtLocation(node);
        if (!symbol)
            return false;
        if (symbol.flags & typescript_1.default.SymbolFlags.Alias)
            symbol = checker.getAliasedSymbol(symbol);
        const bound = bindings.get(symbol);
        if (bound)
            return bound.some((candidate) => resolve(candidate, depth + 1, bindings));
        if (resolving.has(symbol))
            return true;
        const binding = symbol.declarations?.find((candidate) => (typescript_1.default.isBindingElement(candidate) && !candidate.dotDotDotToken
            && typescript_1.default.isVariableDeclaration(candidate.parent.parent)
            && typescript_1.default.isVariableDeclarationList(candidate.parent.parent.parent)
            && Boolean(candidate.parent.parent.parent.flags & typescript_1.default.NodeFlags.Const)
            && candidate.parent.parent.initializer !== undefined));
        const nestedBinding = symbol.declarations?.find((candidate) => (typescript_1.default.isBindingElement(candidate) && !typescript_1.default.isVariableDeclaration(candidate.parent.parent)));
        if (nestedBinding) {
            let owner = nestedBinding.parent;
            while (!typescript_1.default.isVariableDeclaration(owner) && !typescript_1.default.isSourceFile(owner))
                owner = owner.parent;
            return typescript_1.default.isVariableDeclaration(owner) && Boolean(owner.initializer
                && deepContainsTarget(owner.initializer));
        }
        if (binding) {
            const initializer = unwrapExpression(binding.parent.parent.initializer);
            const resolveBindingValue = (candidate) => {
                if (!binding.initializer)
                    return Boolean(candidate
                        && resolve(candidate, depth + 1, bindings));
                if (!candidate)
                    return resolve(binding.initializer, depth + 1, bindings);
                const state = nullishState(candidate, false, depth + 1, bindings);
                return state === true
                    ? resolve(binding.initializer, depth + 1, bindings)
                    : state === false
                        ? resolve(candidate, depth + 1, bindings)
                        : resolve(candidate, depth + 1, bindings)
                            || resolve(binding.initializer, depth + 1, bindings);
            };
            if (typescript_1.default.isArrayBindingPattern(binding.parent) && typescript_1.default.isArrayLiteralExpression(initializer)) {
                const index = binding.parent.elements.indexOf(binding);
                if (initializer.elements.slice(0, index + 1).some(typescript_1.default.isSpreadElement)) {
                    return subtreeContainsTarget(initializer)
                        || Boolean(binding.initializer
                            && resolve(binding.initializer, depth + 1, bindings));
                }
                const element = initializer.elements[index];
                return resolveBindingValue(element && !typescript_1.default.isOmittedExpression(element)
                    && !typescript_1.default.isSpreadElement(element) ? element : undefined);
            }
            if (typescript_1.default.isObjectBindingPattern(binding.parent)) {
                const property = binding.propertyName ?? binding.name;
                const key = typescript_1.default.isComputedPropertyName(property)
                    ? resolveStaticPropertyKey(property.expression, checker, check)
                    : typescript_1.default.isIdentifier(property) || typescript_1.default.isStringLiteral(property) || typescript_1.default.isNumericLiteral(property)
                        ? property.text
                        : undefined;
                if (key !== undefined && typescript_1.default.isObjectLiteralExpression(initializer)
                    && typescript_1.default.isVariableDeclaration(binding.parent.parent)) {
                    let selected;
                    for (const candidate of initializer.properties) {
                        check();
                        if (typescript_1.default.isSpreadAssignment(candidate)) {
                            selected = null;
                            continue;
                        }
                        const name = candidate.name;
                        const candidateKey = typescript_1.default.isComputedPropertyName(name)
                            ? resolveStaticPropertyKey(name.expression, checker, check)
                            : typescript_1.default.isIdentifier(name) || typescript_1.default.isStringLiteral(name) || typescript_1.default.isNumericLiteral(name)
                                ? name.text : undefined;
                        if (candidateKey === undefined) {
                            if (typescript_1.default.isComputedPropertyName(name))
                                selected = null;
                            continue;
                        }
                        if (candidateKey === key)
                            selected = candidate;
                    }
                    if (selected === null)
                        return true;
                    if (selected && typescript_1.default.isShorthandPropertyAssignment(selected)) {
                        const valueSymbol = checker.getShorthandAssignmentValueSymbol(selected);
                        const valueDeclaration = valueSymbol?.declarations?.find((candidate) => typescript_1.default.isVariableDeclaration(candidate)
                            && candidate.initializer !== undefined
                            && typescript_1.default.isVariableDeclarationList(candidate.parent)
                            && Boolean(candidate.parent.flags & typescript_1.default.NodeFlags.Const));
                        return resolveBindingValue(valueDeclaration?.initializer ?? selected.name);
                    }
                    return resolveBindingValue(selected && typescript_1.default.isPropertyAssignment(selected)
                        ? selected.initializer : undefined);
                }
                const propertySymbol = key === undefined
                    ? undefined
                    : checker.getTypeAtLocation(initializer).getProperty(key);
                const propertyDeclaration = propertySymbol?.declarations?.find((candidate) => typescript_1.default.isPropertyAssignment(candidate));
                const shorthand = propertySymbol?.declarations?.find(typescript_1.default.isShorthandPropertyAssignment);
                const valueSymbol = shorthand && checker.getShorthandAssignmentValueSymbol(shorthand);
                const valueDeclaration = valueSymbol?.declarations?.find((candidate) => typescript_1.default.isVariableDeclaration(candidate)
                    && candidate.initializer !== undefined
                    && typescript_1.default.isVariableDeclarationList(candidate.parent)
                    && Boolean(candidate.parent.flags & typescript_1.default.NodeFlags.Const));
                return resolveBindingValue(propertyDeclaration?.initializer ?? valueDeclaration?.initializer);
            }
        }
        const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
        const declaration = declarations.length === 1 ? declarations[0] : undefined;
        if (!declaration)
            return false;
        if (!typescript_1.default.isVariableDeclarationList(declaration.parent))
            return true;
        if (!(declaration.parent.flags & typescript_1.default.NodeFlags.Const)) {
            let latest = declaration.initializer;
            let latestStart = declaration.getStart();
            let uncertainTarget = false;
            resolving.add(symbol);
            const targetsSymbol = (root) => {
                const target = typescript_1.default.isExpression(root) ? unwrapExpression(root) : root;
                if (typescript_1.default.isIdentifier(target)) {
                    let targetSymbol = checker.getSymbolAtLocation(target);
                    if (targetSymbol?.flags && targetSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                        targetSymbol = checker.getAliasedSymbol(targetSymbol);
                    }
                    return targetSymbol === symbol;
                }
                if (typescript_1.default.isPropertyAccessExpression(target) || typescript_1.default.isElementAccessExpression(target))
                    return false;
                if (typescript_1.default.isSpreadElement(target) || typescript_1.default.isSpreadAssignment(target)) {
                    return targetsSymbol(target.expression);
                }
                if (typescript_1.default.isBindingElement(target))
                    return targetsSymbol(target.name);
                if (typescript_1.default.isVariableDeclaration(target))
                    return targetsSymbol(target.name);
                if (typescript_1.default.isVariableDeclarationList(target))
                    return target.declarations.some(targetsSymbol);
                if (typescript_1.default.isArrayLiteralExpression(target) || typescript_1.default.isArrayBindingPattern(target)) {
                    return target.elements.some((element) => !typescript_1.default.isOmittedExpression(element)
                        && targetsSymbol(element));
                }
                if (typescript_1.default.isObjectBindingPattern(target))
                    return target.elements.some(targetsSymbol);
                if (typescript_1.default.isObjectLiteralExpression(target)) {
                    return target.properties.some((property) => typescript_1.default.isShorthandPropertyAssignment(property)
                        ? targetsSymbol(property.name)
                        : typescript_1.default.isPropertyAssignment(property) ? targetsSymbol(property.initializer)
                            : typescript_1.default.isSpreadAssignment(property) ? targetsSymbol(property.expression) : false);
                }
                return false;
            };
            let delayed = false;
            let ancestor = node;
            while (!typescript_1.default.isSourceFile(ancestor.parent)) {
                ancestor = ancestor.parent;
                delayed ||= typescript_1.default.isFunctionLike(ancestor) || typescript_1.default.isClassLike(ancestor);
            }
            if (delayed) {
                resolving.delete(symbol);
                return true;
            }
            for (const sourceFile of projectSources ?? [node.getSourceFile()]) {
                const nodes = [sourceFile];
                while (nodes.length > 0) {
                    const candidate = nodes.pop();
                    check();
                    if (typescript_1.default.isBinaryExpression(candidate)
                        && candidate.operatorToken.kind >= typescript_1.default.SyntaxKind.FirstAssignment
                        && candidate.operatorToken.kind <= typescript_1.default.SyntaxKind.LastAssignment
                        && targetsSymbol(candidate.left) && !staticallyUnreachable(candidate, depth, bindings)) {
                        const direct = candidate.operatorToken.kind === typescript_1.default.SyntaxKind.EqualsToken
                            && typescript_1.default.isIdentifier(unwrapExpression(candidate.left))
                            && typescript_1.default.isExpressionStatement(candidate.parent)
                            && typescript_1.default.isSourceFile(candidate.parent.parent)
                            && candidate.getSourceFile() === node.getSourceFile();
                        if (direct && candidate.getStart() < node.getStart()
                            && candidate.getStart() > latestStart) {
                            latest = candidate.right;
                            latestStart = candidate.getStart();
                        }
                        else if (!direct)
                            uncertainTarget = true;
                    }
                    if ((typescript_1.default.isForOfStatement(candidate) || typescript_1.default.isForInStatement(candidate))
                        && targetsSymbol(candidate.initializer)
                        && !staticallyUnreachable(candidate, depth, bindings)) {
                        uncertainTarget = true;
                    }
                    typescript_1.default.forEachChild(candidate, (child) => { nodes.push(child); });
                }
            }
            const result = uncertainTarget || Boolean(latest && resolve(latest, depth + 1, bindings));
            resolving.delete(symbol);
            return result;
        }
        if (!declaration.initializer)
            return false;
        resolving.add(symbol);
        const result = resolve(declaration.initializer, depth + 1, bindings);
        resolving.delete(symbol);
        return result;
    };
    return resolve(expression, 0, new Map());
}
function isStaticShorthandSymbolFrom(shorthand, checker, check, moduleName, importedName, projectSources) {
    const symbol = checker.getShorthandAssignmentValueSymbol(shorthand);
    if (!symbol)
        return false;
    const target = symbol.flags & typescript_1.default.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
    if (isResolvedSymbolFrom(target, shorthand, moduleName, importedName))
        return true;
    const binding = target.declarations?.find((candidate) => (typescript_1.default.isBindingElement(candidate)));
    if (binding && !typescript_1.default.isIdentifier(binding.name))
        return true;
    const expression = binding && typescript_1.default.isIdentifier(binding.name) ? binding.name : shorthand.name;
    return containsStaticSymbolFrom(expression, checker, check, moduleName, importedName, projectSources);
}
function isNestJsUseGlobalGuardsCall(call, checker, check, projectSources) {
    const writeIndex = projectSources
        ? callableWriteIndex(projectSources, checker, check) : new Map();
    const staticPropertyName = (input) => {
        const direct = resolveStaticPropertyKey(input, checker, check);
        if (direct !== undefined || !projectSources)
            return direct;
        const values = (0, static_string_resolver_js_1.resolveStaticStrings)(input, checker, projectSources, { check, maxSteps: 4096 });
        return values?.length === 1 ? values[0] : undefined;
    };
    const resolveUnmodifiedAlias = (input) => {
        const seen = new Set();
        let value = unwrapExpression(input);
        while (typescript_1.default.isIdentifier(value)) {
            check();
            let symbol = checker.getSymbolAtLocation(value);
            if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
                symbol = checker.getAliasedSymbol(symbol);
            if (!symbol || seen.has(symbol) || seen.size >= 64)
                break;
            seen.add(symbol);
            const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
            const declaration = declarations.length === 1 ? declarations[0] : undefined;
            if (!declaration?.initializer || (projectSources
                && !projectSources.has(declaration.getSourceFile()))
                || !typescript_1.default.isVariableDeclarationList(declaration.parent)
                || (!(declaration.parent.flags & typescript_1.default.NodeFlags.Const)
                    && (writeIndex.get(symbol)?.length ?? 0) > 0))
                break;
            value = unwrapExpression(declaration.initializer);
        }
        return value;
    };
    const canonicalGuardMember = (input) => {
        const value = resolveUnmodifiedAlias(input);
        const property = typescript_1.default.isPropertyAccessExpression(value) ? value.name.text
            : typescript_1.default.isElementAccessExpression(value) && value.argumentExpression
                ? staticPropertyName(value.argumentExpression) : undefined;
        if (property !== 'useGlobalGuards'
            || (!typescript_1.default.isPropertyAccessExpression(value) && !typescript_1.default.isElementAccessExpression(value)))
            return false;
        const symbol = checker.getNonNullableType(checker.getTypeAtLocation(value.expression)).getProperty(property);
        return matchesConsumerModule(value, symbol, '@nestjs/common')
            || matchesConsumerModule(value, symbol, '@nestjs/core');
    };
    const canonicalExpressionMemo = new WeakMap();
    const canonicalSymbolMemo = new Map();
    const canonicalAliasEvidence = (input, depth = 0) => {
        check();
        if (depth >= 64)
            return true;
        const value = unwrapExpression(input);
        const cachedExpression = canonicalExpressionMemo.get(value);
        if (cachedExpression !== undefined)
            return cachedExpression === 'visiting' ? false : cachedExpression;
        canonicalExpressionMemo.set(value, 'visiting');
        let result = canonicalGuardMember(value);
        if (!result && typescript_1.default.isArrayLiteralExpression(value))
            result = value.elements.some((element) => (!typescript_1.default.isOmittedExpression(element) && canonicalAliasEvidence(typescript_1.default.isSpreadElement(element) ? element.expression : element, depth + 1)));
        if (!result && typescript_1.default.isObjectLiteralExpression(value))
            result = value.properties.some((property) => {
                const candidate = typescript_1.default.isPropertyAssignment(property) ? property.initializer
                    : typescript_1.default.isShorthandPropertyAssignment(property) ? property.name
                        : typescript_1.default.isSpreadAssignment(property) ? property.expression : undefined;
                return Boolean(candidate && canonicalAliasEvidence(candidate, depth + 1));
            });
        if (typescript_1.default.isConditionalExpression(value)) {
            result ||= canonicalAliasEvidence(value.whenTrue, depth + 1)
                || canonicalAliasEvidence(value.whenFalse, depth + 1);
        }
        if (typescript_1.default.isBinaryExpression(value)) {
            result ||= canonicalAliasEvidence(value.left, depth + 1)
                || canonicalAliasEvidence(value.right, depth + 1);
        }
        if (!result && typescript_1.default.isIdentifier(value)) {
            let symbol = checker.getSymbolAtLocation(value);
            if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
                symbol = checker.getAliasedSymbol(symbol);
            if (symbol) {
                const cachedSymbol = canonicalSymbolMemo.get(symbol);
                if (cachedSymbol !== undefined)
                    result = cachedSymbol === 'visiting' ? false : cachedSymbol;
                else {
                    canonicalSymbolMemo.set(symbol, 'visiting');
                    const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
                    const declaration = declarations.length === 1 ? declarations[0] : undefined;
                    result = Boolean(declaration?.initializer && (!projectSources
                        || projectSources.has(declaration.getSourceFile()))
                        && canonicalAliasEvidence(declaration.initializer, depth + 1))
                        || (writeIndex.get(symbol) ?? []).some((record) => Boolean(record.uncertainCanonical
                            || (record.value && canonicalAliasEvidence(record.value, depth + 1))));
                    canonicalSymbolMemo.set(symbol, result);
                }
            }
        }
        canonicalExpressionMemo.set(value, result);
        return result;
    };
    const callStatement = typescript_1.default.isExpressionStatement(call.parent)
        && typescript_1.default.isSourceFile(call.parent.parent) ? call.parent : undefined;
    const mutableAssignmentsAtCall = (symbol) => {
        let latest;
        let latestStart = -1;
        let ambiguous = !callStatement;
        let canonicalCandidate = false;
        for (const record of writeIndex.get(symbol) ?? []) {
            canonicalCandidate ||= Boolean(record.uncertainCanonical
                || (record.value && canonicalAliasEvidence(record.value)));
            const direct = record.directTopLevel && callStatement
                && record.sourceFile === call.getSourceFile();
            if (direct && record.start < call.getStart()) {
                if (record.start > latestStart && record.value) {
                    latest = record.value;
                    latestStart = record.start;
                }
            }
            else if (!(direct && record.start > call.getStart())) {
                ambiguous = true;
            }
        }
        return { ...(latest ? { latest } : {}), ambiguous, canonicalCandidate };
    };
    let uncertainCanonicalAlias = false;
    const resolveStableInitializer = (input) => {
        const seen = new Set();
        let value = unwrapExpression(input);
        while (typescript_1.default.isIdentifier(value)) {
            check();
            let symbol = checker.getSymbolAtLocation(value);
            if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
                symbol = checker.getAliasedSymbol(symbol);
            if (!symbol || seen.has(symbol))
                break;
            seen.add(symbol);
            const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
            const declaration = declarations.length === 1 ? declarations[0] : undefined;
            if (!declaration?.initializer || (projectSources
                && !projectSources.has(declaration.getSourceFile()))
                || !typescript_1.default.isVariableDeclarationList(declaration.parent))
                break;
            if (declaration.parent.flags & typescript_1.default.NodeFlags.Const) {
                value = unwrapExpression(declaration.initializer);
                continue;
            }
            if (!projectSources)
                break;
            const assignments = mutableAssignmentsAtCall(symbol);
            if (assignments.ambiguous) {
                uncertainCanonicalAlias ||= canonicalAliasEvidence(declaration.initializer)
                    || assignments.canonicalCandidate;
                break;
            }
            value = unwrapExpression(assignments.latest ?? declaration.initializer);
        }
        return value;
    };
    const flattenArguments = (args) => {
        const pending = [...args];
        const flattened = [];
        let steps = 0;
        while (pending.length > 0) {
            check();
            if (steps++ >= 64)
                return undefined;
            const argument = pending.shift();
            if (!typescript_1.default.isSpreadElement(argument)) {
                flattened.push(argument);
                continue;
            }
            const spread = unwrapExpression(argument.expression);
            if (!typescript_1.default.isArrayLiteralExpression(spread))
                return undefined;
            if (spread.elements.some(typescript_1.default.isOmittedExpression))
                return undefined;
            pending.unshift(...spread.elements.filter((element) => (!typescript_1.default.isOmittedExpression(element))));
        }
        return flattened;
    };
    const isDefinitelyNullish = (input) => {
        const value = unwrapExpression(input);
        if (value.kind === typescript_1.default.SyntaxKind.NullKeyword || typescript_1.default.isVoidExpression(value))
            return true;
        return typescript_1.default.isIdentifier(value) && value.text === 'undefined'
            && !checker.getSymbolAtLocation(value)?.declarations?.length;
    };
    let effectiveArguments = flattenArguments(call.arguments);
    let expression = resolveStableInitializer(call.expression);
    const reflectCall = unwrapExpression(call.expression);
    const reflectMethod = typescript_1.default.isPropertyAccessExpression(reflectCall) ? reflectCall.name.text
        : typescript_1.default.isElementAccessExpression(reflectCall) && reflectCall.argumentExpression
            ? staticPropertyName(reflectCall.argumentExpression) : undefined;
    const reflectReceiver = (typescript_1.default.isPropertyAccessExpression(reflectCall)
        || typescript_1.default.isElementAccessExpression(reflectCall))
        ? unwrapExpression(reflectCall.expression) : undefined;
    const standardReflectApply = reflectMethod === 'apply' && reflectReceiver
        && isStandardReflectReceiver(reflectReceiver, checker, check);
    if (standardReflectApply && call.arguments[0]) {
        expression = resolveStableInitializer(call.arguments[0]);
        const guards = call.arguments[2] ? unwrapExpression(call.arguments[2]) : undefined;
        effectiveArguments = guards && typescript_1.default.isArrayLiteralExpression(guards)
            ? guards.elements.some(typescript_1.default.isOmittedExpression) ? undefined
                : flattenArguments(guards.elements.filter((element) => (!typescript_1.default.isOmittedExpression(element)))) : guards ? undefined : [];
    }
    const outerCallable = unwrapExpression(expression);
    const outerInvocation = typescript_1.default.isPropertyAccessExpression(outerCallable) ? outerCallable.name.text
        : typescript_1.default.isElementAccessExpression(outerCallable) && outerCallable.argumentExpression
            ? staticPropertyName(outerCallable.argumentExpression) : undefined;
    const prototypeMethod = (outerInvocation === 'call' || outerInvocation === 'apply')
        && (typescript_1.default.isPropertyAccessExpression(outerCallable) || typescript_1.default.isElementAccessExpression(outerCallable))
        ? standardFunctionPrototypeMethod(outerCallable.expression, checker, check) : undefined;
    if (prototypeMethod && effectiveArguments?.[0]) {
        let forwarded = effectiveArguments;
        if (outerInvocation === 'apply') {
            const argumentList = effectiveArguments[1] ? unwrapExpression(effectiveArguments[1]) : undefined;
            const argumentsArray = !argumentList || isDefinitelyNullish(argumentList) ? []
                : typescript_1.default.isArrayLiteralExpression(argumentList)
                    && !argumentList.elements.some(typescript_1.default.isOmittedExpression)
                    ? flattenArguments(argumentList.elements.filter((element) => (!typescript_1.default.isOmittedExpression(element)))) : undefined;
            forwarded = argumentsArray ? [effectiveArguments[0], ...argumentsArray] : undefined;
        }
        expression = resolveStableInitializer(effectiveArguments[0]);
        if (forwarded) {
            if (prototypeMethod === 'call')
                effectiveArguments = forwarded.slice(2);
            else {
                const guards = forwarded[2] ? unwrapExpression(forwarded[2]) : undefined;
                effectiveArguments = !guards || isDefinitelyNullish(guards) ? []
                    : typescript_1.default.isArrayLiteralExpression(guards)
                        && !guards.elements.some(typescript_1.default.isOmittedExpression)
                        ? flattenArguments(guards.elements.filter((element) => (!typescript_1.default.isOmittedExpression(element)))) : guards ? undefined : [];
            }
        }
        else
            effectiveArguments = undefined;
    }
    let depthLimitReached = false;
    for (let depth = 0; depth <= 64; depth += 1) {
        check();
        if (depth === 64) {
            depthLimitReached = true;
            break;
        }
        if (typescript_1.default.isBinaryExpression(expression)
            && expression.operatorToken.kind === typescript_1.default.SyntaxKind.CommaToken) {
            expression = resolveStableInitializer(expression.right);
            continue;
        }
        if (typescript_1.default.isCallExpression(expression)) {
            const bind = unwrapExpression(expression.expression);
            const bindName = typescript_1.default.isPropertyAccessExpression(bind) ? bind.name.text
                : typescript_1.default.isElementAccessExpression(bind) && bind.argumentExpression
                    ? staticPropertyName(bind.argumentExpression) : undefined;
            if (bindName === 'bind'
                && (typescript_1.default.isPropertyAccessExpression(bind) || typescript_1.default.isElementAccessExpression(bind))) {
                const bound = flattenArguments(expression.arguments.slice(1));
                effectiveArguments = bound && effectiveArguments
                    ? [...bound, ...effectiveArguments] : undefined;
                expression = resolveStableInitializer(bind.expression);
                continue;
            }
        }
        const invocation = typescript_1.default.isPropertyAccessExpression(expression) ? expression.name.text
            : typescript_1.default.isElementAccessExpression(expression) && expression.argumentExpression
                ? staticPropertyName(expression.argumentExpression) : undefined;
        if ((invocation === 'call' || invocation === 'apply')
            && (typescript_1.default.isPropertyAccessExpression(expression) || typescript_1.default.isElementAccessExpression(expression))) {
            if (invocation === 'call') {
                effectiveArguments = effectiveArguments?.slice(1);
            }
            else if (effectiveArguments) {
                const argument = effectiveArguments[1];
                if (!argument || isDefinitelyNullish(argument))
                    effectiveArguments = [];
                else {
                    const guards = unwrapExpression(argument);
                    effectiveArguments = typescript_1.default.isArrayLiteralExpression(guards)
                        ? guards.elements.some(typescript_1.default.isOmittedExpression) ? undefined
                            : flattenArguments(guards.elements.filter((element) => (!typescript_1.default.isOmittedExpression(element)))) : undefined;
                }
            }
            expression = resolveStableInitializer(expression.expression);
            continue;
        }
        break;
    }
    if (depthLimitReached) {
        const nodes = [expression];
        let steps = 0;
        while (nodes.length > 0 && steps++ < 4096) {
            check();
            const node = nodes.pop();
            if (typescript_1.default.isBinaryExpression(node)
                && node.operatorToken.kind === typescript_1.default.SyntaxKind.CommaToken) {
                nodes.push(node.right);
                continue;
            }
            if (typescript_1.default.isCallExpression(node)) {
                nodes.push(node.expression);
                continue;
            }
            if (typescript_1.default.isPropertyAccessExpression(node) || typescript_1.default.isElementAccessExpression(node)) {
                const key = typescript_1.default.isPropertyAccessExpression(node) ? node.name.text
                    : node.argumentExpression
                        ? staticPropertyName(node.argumentExpression) : undefined;
                if (key === 'useGlobalGuards') {
                    const symbol = checker.getNonNullableType(checker.getTypeAtLocation(node.expression)).getProperty(key);
                    if (matchesConsumerModule(node, symbol, '@nestjs/common')
                        || matchesConsumerModule(node, symbol, '@nestjs/core'))
                        return true;
                }
                nodes.push(node.expression);
                continue;
            }
            else if (typescript_1.default.isIdentifier(node)) {
                const resolved = resolveStableInitializer(node);
                if (resolved !== node)
                    nodes.push(resolved);
                const binding = checker.getSymbolAtLocation(node)?.declarations?.find(typescript_1.default.isBindingElement);
                const pattern = binding?.parent;
                const declaration = pattern && typescript_1.default.isObjectBindingPattern(pattern)
                    && typescript_1.default.isVariableDeclaration(pattern.parent) ? pattern.parent : undefined;
                const key = binding?.propertyName && (typescript_1.default.isIdentifier(binding.propertyName)
                    || typescript_1.default.isStringLiteral(binding.propertyName))
                    ? binding.propertyName.text
                    : binding && typescript_1.default.isIdentifier(binding.name) ? binding.name.text : undefined;
                if (key === 'useGlobalGuards' && declaration?.initializer) {
                    const bindingSymbol = checker.getSymbolAtLocation(node);
                    if (!bindingSymbol || !projectSources || callableBindingMayBeWritten(bindingSymbol, bindingSymbol.declarations ?? [], checker, projectSources, check))
                        continue;
                    const symbol = checker.getNonNullableType(checker.getTypeAtLocation(declaration.initializer)).getProperty(key);
                    if (matchesConsumerModule(node, symbol, '@nestjs/common')
                        || matchesConsumerModule(node, symbol, '@nestjs/core'))
                        return true;
                }
                continue;
            }
            typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
        }
        return nodes.length > 0;
    }
    let property = typescript_1.default.isPropertyAccessExpression(expression)
        ? expression.name.text
        : typescript_1.default.isElementAccessExpression(expression) && expression.argumentExpression
            ? staticPropertyName(expression.argumentExpression)
            : undefined;
    let receiver = (typescript_1.default.isPropertyAccessExpression(expression)
        || typescript_1.default.isElementAccessExpression(expression))
        ? expression.expression : undefined;
    const hasGuardArgument = !effectiveArguments || effectiveArguments.length > 0;
    if (uncertainCanonicalAlias && hasGuardArgument)
        return true;
    if (!receiver && typescript_1.default.isIdentifier(expression)) {
        const binding = checker.getSymbolAtLocation(expression)?.declarations?.find(typescript_1.default.isBindingElement);
        const pattern = binding?.parent;
        const declaration = pattern && typescript_1.default.isObjectBindingPattern(pattern)
            && typescript_1.default.isVariableDeclaration(pattern.parent) ? pattern.parent : undefined;
        if (binding && declaration?.initializer && typescript_1.default.isVariableDeclarationList(declaration.parent)) {
            const bindingSymbol = checker.getSymbolAtLocation(expression);
            property = binding.propertyName && (typescript_1.default.isIdentifier(binding.propertyName)
                || typescript_1.default.isStringLiteral(binding.propertyName))
                ? binding.propertyName.text : typescript_1.default.isIdentifier(binding.name) ? binding.name.text : undefined;
            receiver = declaration.initializer;
            if (!bindingSymbol || !projectSources)
                return false;
            if (callableBindingMayBeWritten(bindingSymbol, bindingSymbol.declarations ?? [], checker, projectSources, check)) {
                const assignments = mutableAssignmentsAtCall(bindingSymbol);
                if (assignments.ambiguous) {
                    const symbol = property ? checker.getNonNullableType(checker.getTypeAtLocation(receiver)).getProperty(property) : undefined;
                    return hasGuardArgument && Boolean(property === 'useGlobalGuards'
                        && (matchesConsumerModule(expression, symbol, '@nestjs/common')
                            || matchesConsumerModule(expression, symbol, '@nestjs/core')
                            || assignments.canonicalCandidate));
                }
                if (assignments.latest)
                    return hasGuardArgument && canonicalGuardMember(assignments.latest);
            }
        }
    }
    if (!hasGuardArgument || property !== 'useGlobalGuards' || !receiver)
        return false;
    const receiverType = checker.getNonNullableType(checker.getTypeAtLocation(receiver));
    const symbol = receiverType.getProperty(property);
    return matchesConsumerModule(expression, symbol, '@nestjs/common')
        || matchesConsumerModule(expression, symbol, '@nestjs/core')
        || Boolean(receiverType.flags & typescript_1.default.TypeFlags.Any);
}
