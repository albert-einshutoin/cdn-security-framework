"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NESTJS_ROUTE_DECORATORS = void 0;
exports.nestJsRouteDecorator = nestJsRouteDecorator;
exports.isUnsupportedNestJsDecorator = isUnsupportedNestJsDecorator;
const node_module_1 = require("node:module");
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const typescript_1 = __importDefault(require("typescript"));
exports.NESTJS_ROUTE_DECORATORS = [
    'All', 'Controller', 'Delete', 'Get', 'Head', 'Options', 'Patch', 'Post', 'Put', 'RequestMapping', 'Search', 'Sse', 'Version',
];
function targetSymbol(node, checker) {
    const location = typescript_1.default.isPropertyAccessExpression(node) ? node.name : node;
    const symbol = checker.getSymbolAtLocation(location);
    if (!symbol)
        return undefined;
    return symbol.flags & typescript_1.default.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
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
function originatesFromNestJsCommon(node, symbol, checker) {
    const importSymbol = checker.getSymbolAtLocation(typescript_1.default.isPropertyAccessExpression(node) ? node.expression : node);
    const sourceFile = importSymbol?.declarations?.[0]?.getSourceFile();
    if (!sourceFile)
        return false;
    const packageRoot = (fileName) => {
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
    };
    let resolvedRoot;
    try {
        resolvedRoot = packageRoot((0, node_module_1.createRequire)(sourceFile.fileName).resolve('@nestjs/common'));
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
    const name = symbol?.getName();
    if (!name || !exports.NESTJS_ROUTE_DECORATORS.includes(name))
        return undefined;
    return {
        name,
        call: decorator.expression,
        trusted: directNestJsImport(decorator.expression.expression, checker)
            && originatesFromNestJsCommon(decorator.expression.expression, symbol, checker),
    };
}
function nestJsRouteDecorator(decorator, checker) {
    const result = match(decorator, checker);
    return result?.trusted ? { name: result.name, call: result.call } : undefined;
}
function isUnsupportedNestJsDecorator(decorator, checker) {
    const result = match(decorator, checker);
    return Boolean(result && (!result.trusted
        || result.name === 'RequestMapping' || result.name === 'Search' || result.name === 'Version'));
}
