"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveStaticStrings = resolveStaticStrings;
const typescript_1 = __importDefault(require("typescript"));
const MAX_STATIC_VALUES = 128;
function unwrap(expression) {
    let current = expression;
    while (typescript_1.default.isParenthesizedExpression(current)
        || typescript_1.default.isAsExpression(current)
        || typescript_1.default.isTypeAssertionExpression(current)
        || typescript_1.default.isSatisfiesExpression(current))
        current = current.expression;
    return current;
}
function isConstDeclaration(declaration) {
    return Boolean(declaration.parent.flags & typescript_1.default.NodeFlags.Const);
}
function isConstAssertion(expression) {
    let current = expression;
    while (typescript_1.default.isParenthesizedExpression(current) || typescript_1.default.isSatisfiesExpression(current))
        current = current.expression;
    return (typescript_1.default.isAsExpression(current) || typescript_1.default.isTypeAssertionExpression(current))
        && current.type.getText(current.getSourceFile()) === 'const';
}
function isReadonlyTuple(declaration) {
    return Boolean(declaration.type && typescript_1.default.isTypeOperatorNode(declaration.type)
        && declaration.type.operator === typescript_1.default.SyntaxKind.ReadonlyKeyword
        && typescript_1.default.isTupleTypeNode(declaration.type.type));
}
function resolveStaticStrings(expression, checker, projectSources, options = {}) {
    if (!expression)
        return [''];
    const maxSteps = options.maxSteps ?? 100_000;
    const maxStringLength = options.maxStringLength ?? 16_384;
    const resolving = new Set();
    const memo = new Map();
    let steps = 0;
    const resolve = (input, depth) => {
        options.check?.();
        steps += 1;
        if (steps > maxSteps || depth > 64)
            return undefined;
        const node = unwrap(input);
        if (typescript_1.default.isStringLiteral(node) || typescript_1.default.isNoSubstitutionTemplateLiteral(node)) {
            return node.text.length <= maxStringLength ? { values: [node.text], array: false } : undefined;
        }
        if (typescript_1.default.isArrayLiteralExpression(node)) {
            const values = [];
            for (const element of node.elements) {
                if (typescript_1.default.isSpreadElement(element))
                    return undefined;
                const resolved = resolve(element, depth + 1);
                if (!resolved || resolved.array)
                    return undefined;
                values.push(...resolved.values);
                if (values.length > MAX_STATIC_VALUES)
                    return undefined;
            }
            return { values, array: true };
        }
        if (typescript_1.default.isBinaryExpression(node) && node.operatorToken.kind === typescript_1.default.SyntaxKind.PlusToken) {
            const left = resolve(node.left, depth + 1);
            const right = resolve(node.right, depth + 1);
            if (left?.array || right?.array || left?.values.length !== 1 || right?.values.length !== 1
                || left.values[0].length + right.values[0].length > maxStringLength)
                return undefined;
            return { values: [`${left.values[0]}${right.values[0]}`], array: false };
        }
        if (!typescript_1.default.isIdentifier(node))
            return undefined;
        let symbol = checker.getSymbolAtLocation(node);
        if (!symbol)
            return undefined;
        if (symbol.flags & typescript_1.default.SymbolFlags.Alias)
            symbol = checker.getAliasedSymbol(symbol);
        if (memo.has(symbol))
            return memo.get(symbol) ?? undefined;
        if (resolving.has(symbol))
            return undefined;
        const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
        if (declarations.length !== 1 || !isConstDeclaration(declarations[0])
            || !declarations[0].initializer || !projectSources.has(declarations[0].getSourceFile()))
            return undefined;
        resolving.add(symbol);
        const result = resolve(declarations[0].initializer, depth + 1);
        resolving.delete(symbol);
        const immutable = !result?.array || isConstAssertion(declarations[0].initializer)
            || isReadonlyTuple(declarations[0])
            || typescript_1.default.isIdentifier(unwrap(declarations[0].initializer));
        const safeResult = result && immutable ? result : undefined;
        memo.set(symbol, safeResult ?? null);
        return safeResult;
    };
    const resolved = resolve(expression, 0);
    return resolved ? [...new Set(resolved.values)] : undefined;
}
