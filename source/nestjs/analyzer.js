"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.nestJsSourceAnalyzer = exports.validateNestJsAuthConfig = void 0;
exports.createNestJsSourceAnalyzer = createNestJsSourceAnalyzer;
const node_crypto_1 = require("node:crypto");
const node_path_1 = __importDefault(require("node:path"));
const typescript_1 = __importDefault(require("typescript"));
const canonical_route_1 = require("../../contract/canonical-route");
const security_ir_1 = require("../../contract/security-ir");
const source_analysis_1 = require("../../source-analysis");
const project_loader_1 = require("../typescript/project-loader");
const decorator_symbols_1 = require("./decorator-symbols");
const auth_config_1 = require("./auth-config");
const static_string_resolver_1 = require("./static-string-resolver");
var auth_config_2 = require("./auth-config");
Object.defineProperty(exports, "validateNestJsAuthConfig", { enumerable: true, get: function () { return auth_config_2.validateNestJsAuthConfig; } });
const ANALYZER_ID = 'nestjs-typescript';
const ANALYZER_VERSION = '1.2.0';
const ANALYZER_IDENTITY = `${ANALYZER_ID}@${ANALYZER_VERSION}`;
const MAX_PROVIDER_SPREAD_ELEMENTS = 4_096;
const READ_ONLY_ARRAY_METHODS = new Set([
    'at', 'concat', 'entries', 'flat', 'includes', 'indexOf', 'join', 'keys',
    'lastIndexOf', 'slice', 'toLocaleString',
    'toReversed', 'toSorted', 'toSpliced', 'toString', 'values', 'with',
]);
const CALLBACK_ARRAY_METHODS = new Set([
    'every', 'filter', 'find', 'findIndex', 'findLast', 'findLastIndex', 'flatMap', 'forEach',
    'map', 'reduce', 'reduceRight', 'some',
]);
const MUTABLE_STORED_GUARD_CACHE = new WeakMap();
const METHOD_DECORATORS = Object.freeze({
    All: canonical_route_1.HTTP_METHODS,
    Delete: ['DELETE'],
    Get: ['GET'],
    Head: ['HEAD'],
    Options: ['OPTIONS'],
    Patch: ['PATCH'],
    Post: ['POST'],
    Put: ['PUT'],
    Sse: ['GET'],
});
function routeMethods(name) {
    if (name === 'Unknown' || name === 'RequestMapping')
        return canonical_route_1.HTTP_METHODS;
    return METHOD_DECORATORS[name];
}
const EMPTY_REQUEST = Object.freeze({
    contentTypes: [], requiredHeaders: [], queryParameters: [], pathParameters: [],
    headerParameters: [], cookieParameters: [],
});
function decorators(node) {
    return typescript_1.default.canHaveDecorators(node) ? typescript_1.default.getDecorators(node) ?? [] : [];
}
function sourceLocation(node, workspaceRoot) {
    const sourceFile = node.getSourceFile();
    const position = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
    return {
        sourceUri: node_path_1.default.relative(workspaceRoot, sourceFile.fileName).replaceAll('\\', '/'),
        line: position.line + 1,
        column: position.character + 1,
    };
}
function digest(sourceFile) {
    return `sha256:${(0, node_crypto_1.createHash)('sha256').update(sourceFile.text).digest('hex')}`;
}
function staticTruth(input) {
    let expression = input;
    while (typescript_1.default.isParenthesizedExpression(expression) || typescript_1.default.isAsExpression(expression)
        || typescript_1.default.isTypeAssertionExpression(expression) || typescript_1.default.isSatisfiesExpression(expression)
        || typescript_1.default.isNonNullExpression(expression))
        expression = expression.expression;
    if (expression.kind === typescript_1.default.SyntaxKind.TrueKeyword)
        return true;
    if (expression.kind === typescript_1.default.SyntaxKind.FalseKeyword || expression.kind === typescript_1.default.SyntaxKind.NullKeyword
        || typescript_1.default.isVoidExpression(expression))
        return false;
    if (typescript_1.default.isStringLiteral(expression) || typescript_1.default.isNoSubstitutionTemplateLiteral(expression)) {
        return expression.text.length > 0;
    }
    if (typescript_1.default.isNumericLiteral(expression))
        return Number(expression.text) !== 0;
    return undefined;
}
function staticNullish(input) {
    let expression = input;
    while (typescript_1.default.isParenthesizedExpression(expression) || typescript_1.default.isAsExpression(expression)
        || typescript_1.default.isTypeAssertionExpression(expression) || typescript_1.default.isSatisfiesExpression(expression)
        || typescript_1.default.isNonNullExpression(expression))
        expression = expression.expression;
    if (expression.kind === typescript_1.default.SyntaxKind.NullKeyword || typescript_1.default.isVoidExpression(expression))
        return true;
    if (expression.kind === typescript_1.default.SyntaxKind.TrueKeyword || expression.kind === typescript_1.default.SyntaxKind.FalseKeyword
        || typescript_1.default.isLiteralExpression(expression) || typescript_1.default.isObjectLiteralExpression(expression)
        || typescript_1.default.isArrayLiteralExpression(expression) || typescript_1.default.isFunctionExpression(expression)
        || typescript_1.default.isArrowFunction(expression) || typescript_1.default.isClassExpression(expression)
        || typescript_1.default.isNewExpression(expression))
        return false;
    return undefined;
}
function staticallyUnreachable(node) {
    let current = node;
    while (!typescript_1.default.isSourceFile(current)) {
        const parent = current.parent;
        if (typescript_1.default.isIfStatement(parent)) {
            const truth = staticTruth(parent.expression);
            if ((current === parent.thenStatement && truth === false)
                || (current === parent.elseStatement && truth === true))
                return true;
        }
        else if ((typescript_1.default.isWhileStatement(parent) || typescript_1.default.isForStatement(parent))
            && current === parent.statement) {
            const condition = typescript_1.default.isWhileStatement(parent) ? parent.expression : parent.condition;
            if (condition && staticTruth(condition) === false)
                return true;
        }
        else if (typescript_1.default.isConditionalExpression(parent)) {
            const truth = staticTruth(parent.condition);
            if ((current === parent.whenTrue && truth === false)
                || (current === parent.whenFalse && truth === true))
                return true;
        }
        else if (typescript_1.default.isBinaryExpression(parent) && current === parent.right) {
            const truth = staticTruth(parent.left);
            if ((parent.operatorToken.kind === typescript_1.default.SyntaxKind.AmpersandAmpersandToken && truth === false)
                || (parent.operatorToken.kind === typescript_1.default.SyntaxKind.BarBarToken && truth === true)
                || (parent.operatorToken.kind === typescript_1.default.SyntaxKind.QuestionQuestionToken
                    && staticNullish(parent.left) === false))
                return true;
        }
        else if ((typescript_1.default.isBlock(parent) || typescript_1.default.isCaseClause(parent) || typescript_1.default.isDefaultClause(parent))
            && typescript_1.default.isStatement(current)) {
            const index = parent.statements.indexOf(current);
            if (!typescript_1.default.isFunctionDeclaration(current) && parent.statements.slice(0, index).some((statement) => (typescript_1.default.isReturnStatement(statement) || typescript_1.default.isThrowStatement(statement)
                || typescript_1.default.isBreakStatement(statement) || typescript_1.default.isContinueStatement(statement))))
                return true;
        }
        current = parent;
    }
    return false;
}
function isProvidersName(node) {
    return (typescript_1.default.isIdentifier(node) || typescript_1.default.isStringLiteral(node)) && node.text === 'providers';
}
function resolvedSymbolAt(node, checker) {
    let symbol = typescript_1.default.isShorthandPropertyAssignment(node.parent)
        ? checker.getShorthandAssignmentValueSymbol(node.parent)
        : checker.getSymbolAtLocation(node);
    if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
        symbol = checker.getAliasedSymbol(symbol);
    return symbol;
}
function resolveConstObject(input, checker, projectSources, check, seen = new Set(), depth = 0) {
    check();
    if (depth > 64)
        return undefined;
    let expression = input;
    while (typescript_1.default.isParenthesizedExpression(expression) || typescript_1.default.isAsExpression(expression)
        || typescript_1.default.isTypeAssertionExpression(expression) || typescript_1.default.isSatisfiesExpression(expression)
        || typescript_1.default.isNonNullExpression(expression))
        expression = expression.expression;
    if (typescript_1.default.isObjectLiteralExpression(expression))
        return expression;
    if (!typescript_1.default.isIdentifier(expression))
        return undefined;
    const symbol = resolvedSymbolAt(expression, checker);
    if (!symbol || seen.has(symbol))
        return undefined;
    const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
    const declaration = declarations.length === 1 ? declarations[0] : undefined;
    if (!declaration?.initializer || !projectSources.has(declaration.getSourceFile())
        || !typescript_1.default.isVariableDeclarationList(declaration.parent)
        || !(declaration.parent.flags & typescript_1.default.NodeFlags.Const))
        return undefined;
    seen.add(symbol);
    return resolveConstObject(declaration.initializer, checker, projectSources, check, seen, depth + 1);
}
function effectiveObjectProperty(object, propertyName, checker, projectSources, check, seen = new Set()) {
    check();
    if (seen.has(object))
        return { present: true, candidates: [object], accessor: false };
    seen.add(object);
    const returnedExpressions = (body) => {
        const result = [];
        const collectReturns = (statement) => {
            check();
            if (typescript_1.default.isReturnStatement(statement)) {
                if (statement.expression)
                    result.push(statement.expression);
                return true;
            }
            if (typescript_1.default.isBlock(statement)) {
                for (const child of statement.statements) {
                    if (collectReturns(child))
                        return true;
                }
            }
            else if (typescript_1.default.isIfStatement(statement)) {
                const condition = statement.expression.kind === typescript_1.default.SyntaxKind.TrueKeyword
                    ? true : statement.expression.kind === typescript_1.default.SyntaxKind.FalseKeyword ? false : undefined;
                const thenReturns = condition !== false && collectReturns(statement.thenStatement);
                const elseReturns = condition !== true && Boolean(statement.elseStatement
                    && collectReturns(statement.elseStatement));
                return condition === true ? thenReturns : condition === false ? elseReturns
                    : thenReturns && elseReturns;
            }
            else if (typescript_1.default.isTryStatement(statement)) {
                const start = result.length;
                const tryReturns = collectReturns(statement.tryBlock);
                const catchReturns = Boolean(statement.catchClause
                    && collectReturns(statement.catchClause.block));
                if (!statement.finallyBlock)
                    return tryReturns && (!statement.catchClause || catchReturns);
                const finallyStart = result.length;
                const finallyReturns = collectReturns(statement.finallyBlock);
                if (finallyReturns)
                    result.splice(start, finallyStart - start);
                return finallyReturns || (tryReturns && (!statement.catchClause || catchReturns));
            }
            else if (typescript_1.default.isSwitchStatement(statement)) {
                let allReturn = statement.caseBlock.clauses.length > 0;
                for (const clause of statement.caseBlock.clauses) {
                    let clauseReturns = false;
                    for (const child of clause.statements) {
                        if (collectReturns(child)) {
                            clauseReturns = true;
                            break;
                        }
                    }
                    allReturn &&= clauseReturns;
                }
                return allReturn && statement.caseBlock.clauses.some(typescript_1.default.isDefaultClause);
            }
            else if (typescript_1.default.isWhileStatement(statement)) {
                if (statement.expression.kind !== typescript_1.default.SyntaxKind.FalseKeyword) {
                    collectReturns(statement.statement);
                }
            }
            else if (typescript_1.default.isDoStatement(statement)) {
                collectReturns(statement.statement);
            }
            else if (typescript_1.default.isForStatement(statement)) {
                if (statement.condition?.kind !== typescript_1.default.SyntaxKind.FalseKeyword) {
                    collectReturns(statement.statement);
                }
            }
            else if (typescript_1.default.isForInStatement(statement) || typescript_1.default.isForOfStatement(statement)) {
                collectReturns(statement.statement);
            }
            return false;
        };
        collectReturns(body);
        return result;
    };
    let result = {
        present: false, candidates: [], accessor: false,
    };
    for (const property of object.properties) {
        if (typescript_1.default.isPropertyAssignment(property)) {
            const name = typescript_1.default.isComputedPropertyName(property.name)
                ? (0, decorator_symbols_1.resolveStaticPropertyKey)(property.name.expression, checker, check)
                : (typescript_1.default.isIdentifier(property.name) || typescript_1.default.isStringLiteral(property.name))
                    ? property.name.text : undefined;
            if (name === propertyName) {
                result = { present: true, candidates: [property.initializer], accessor: false };
            }
            else if (typescript_1.default.isComputedPropertyName(property.name) && name === undefined
                && !(0, decorator_symbols_1.isDefinitelyNonProvidePropertyKey)(property.name.expression)) {
                result = {
                    present: true, candidates: [...result.candidates, property.initializer], accessor: false,
                };
            }
        }
        else if (typescript_1.default.isShorthandPropertyAssignment(property) && property.name.text === propertyName) {
            result = { present: true, candidates: [property.name], accessor: false };
        }
        else if (typescript_1.default.isGetAccessorDeclaration(property)) {
            const name = typescript_1.default.isComputedPropertyName(property.name)
                ? (0, decorator_symbols_1.resolveStaticPropertyKey)(property.name.expression, checker, check)
                : (typescript_1.default.isIdentifier(property.name) || typescript_1.default.isStringLiteral(property.name))
                    ? property.name.text : undefined;
            if (name === propertyName) {
                result = {
                    present: true, candidates: property.body ? returnedExpressions(property.body) : [], accessor: true,
                };
            }
            else if (typescript_1.default.isComputedPropertyName(property.name) && name === undefined
                && !(0, decorator_symbols_1.isDefinitelyNonProvidePropertyKey)(property.name.expression)) {
                result = {
                    present: true,
                    candidates: [...result.candidates, ...(property.body ? returnedExpressions(property.body) : [])],
                    accessor: true,
                };
            }
        }
        else if (typescript_1.default.isSetAccessorDeclaration(property) || typescript_1.default.isMethodDeclaration(property)) {
            const name = typescript_1.default.isComputedPropertyName(property.name)
                ? (0, decorator_symbols_1.resolveStaticPropertyKey)(property.name.expression, checker, check)
                : (typescript_1.default.isIdentifier(property.name) || typescript_1.default.isStringLiteral(property.name))
                    ? property.name.text : undefined;
            if (name === propertyName) {
                if (typescript_1.default.isMethodDeclaration(property)) {
                    result = { present: true, candidates: [], accessor: false };
                }
                else if (!result.accessor)
                    result = { present: true, candidates: [], accessor: true };
            }
        }
        else if (typescript_1.default.isSpreadAssignment(property)) {
            const spread = resolveConstObject(property.expression, checker, projectSources, check);
            if (spread) {
                const nested = effectiveObjectProperty(spread, propertyName, checker, projectSources, check, new Set(seen));
                if (nested.present)
                    result = nested;
            }
            else {
                result = {
                    present: true, candidates: [...result.candidates, property.expression], accessor: false,
                };
            }
        }
    }
    return result;
}
function assignmentTargetContainsSymbol(input, symbol, checker, check) {
    const nodes = [input];
    while (nodes.length > 0) {
        check();
        const node = nodes.pop();
        if (typescript_1.default.isIdentifier(node)) {
            let target = checker.getSymbolAtLocation(node);
            if (target?.flags && target.flags & typescript_1.default.SymbolFlags.Alias)
                target = checker.getAliasedSymbol(target);
            if (target === symbol)
                return true;
            continue;
        }
        if (typescript_1.default.isPropertyAccessExpression(node)) {
            nodes.push(node.expression, node.name);
            continue;
        }
        if (typescript_1.default.isElementAccessExpression(node)) {
            const key = node.argumentExpression
                ? (0, decorator_symbols_1.resolveStaticPropertyKey)(node.argumentExpression, checker, check) : undefined;
            const target = key === undefined ? undefined
                : checker.getNonNullableType(checker.getTypeAtLocation(node.expression)).getProperty(key);
            if (target === symbol)
                return true;
            nodes.push(node.expression);
            continue;
        }
        if (typescript_1.default.isParenthesizedExpression(node) || typescript_1.default.isAsExpression(node)
            || typescript_1.default.isTypeAssertionExpression(node) || typescript_1.default.isSatisfiesExpression(node)
            || typescript_1.default.isNonNullExpression(node))
            nodes.push(node.expression);
        else if (typescript_1.default.isArrayLiteralExpression(node)) {
            for (const element of node.elements) {
                if (!typescript_1.default.isOmittedExpression(element)) {
                    nodes.push(typescript_1.default.isSpreadElement(element) ? element.expression : element);
                }
            }
        }
        else if (typescript_1.default.isBinaryExpression(node)
            && node.operatorToken.kind === typescript_1.default.SyntaxKind.EqualsToken)
            nodes.push(node.left);
        else if (typescript_1.default.isObjectLiteralExpression(node)) {
            for (const property of node.properties) {
                if (typescript_1.default.isPropertyAssignment(property))
                    nodes.push(property.initializer);
                else if (typescript_1.default.isShorthandPropertyAssignment(property))
                    nodes.push(property.name);
                else if (typescript_1.default.isSpreadAssignment(property))
                    nodes.push(property.expression);
            }
        }
        else if (typescript_1.default.isArrayBindingPattern(node) || typescript_1.default.isObjectBindingPattern(node)) {
            nodes.push(...node.elements);
        }
        else if (typescript_1.default.isBindingElement(node))
            nodes.push(node.name);
        else if (typescript_1.default.isVariableDeclarationList(node)) {
            nodes.push(...node.declarations.map(({ name }) => name));
        }
        else if (typescript_1.default.isVariableDeclaration(node))
            nodes.push(node.name);
    }
    return false;
}
function staticUndefinedState(input, checker, projectSources, check, seen = new Set(), depth = 0) {
    check();
    if (depth > 64)
        return undefined;
    let expression = input;
    while (typescript_1.default.isParenthesizedExpression(expression) || typescript_1.default.isAsExpression(expression)
        || typescript_1.default.isTypeAssertionExpression(expression) || typescript_1.default.isSatisfiesExpression(expression)
        || typescript_1.default.isNonNullExpression(expression))
        expression = expression.expression;
    if (typescript_1.default.isVoidExpression(expression))
        return true;
    if (expression.kind === typescript_1.default.SyntaxKind.NullKeyword || expression.kind === typescript_1.default.SyntaxKind.TrueKeyword
        || expression.kind === typescript_1.default.SyntaxKind.FalseKeyword || typescript_1.default.isLiteralExpression(expression)
        || typescript_1.default.isObjectLiteralExpression(expression) || typescript_1.default.isArrayLiteralExpression(expression)
        || typescript_1.default.isFunctionExpression(expression) || typescript_1.default.isArrowFunction(expression)
        || typescript_1.default.isClassExpression(expression) || typescript_1.default.isNewExpression(expression))
        return false;
    if (!typescript_1.default.isIdentifier(expression))
        return undefined;
    let symbol = checker.getSymbolAtLocation(expression);
    if (expression.text === 'undefined' && !symbol?.declarations?.length)
        return true;
    if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
        symbol = checker.getAliasedSymbol(symbol);
    if (!symbol || seen.has(symbol))
        return undefined;
    if (symbol.declarations?.some((declaration) => ((typescript_1.default.isClassLike(declaration) || typescript_1.default.isFunctionDeclaration(declaration))
        && projectSources.has(declaration.getSourceFile()))))
        return false;
    const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
    const declaration = declarations.length === 1 ? declarations[0] : undefined;
    if (!declaration?.initializer || !projectSources.has(declaration.getSourceFile())
        || !typescript_1.default.isVariableDeclarationList(declaration.parent)
        || !(declaration.parent.flags & typescript_1.default.NodeFlags.Const))
        return undefined;
    seen.add(symbol);
    return staticUndefinedState(declaration.initializer, checker, projectSources, check, seen, depth + 1);
}
function isNestedDestructuringDefault(node) {
    if (node.operatorToken.kind !== typescript_1.default.SyntaxKind.EqualsToken)
        return false;
    let current = node;
    while (current.parent) {
        const parent = current.parent;
        if (typescript_1.default.isParenthesizedExpression(parent) || typescript_1.default.isAsExpression(parent)
            || typescript_1.default.isTypeAssertionExpression(parent) || typescript_1.default.isSatisfiesExpression(parent)
            || typescript_1.default.isNonNullExpression(parent) || typescript_1.default.isArrayLiteralExpression(parent)) {
            current = parent;
            continue;
        }
        if (typescript_1.default.isPropertyAssignment(parent) && parent.initializer === current
            && typescript_1.default.isObjectLiteralExpression(parent.parent)) {
            current = parent.parent;
            continue;
        }
        return (typescript_1.default.isBinaryExpression(parent) && parent.left === current)
            || ((typescript_1.default.isForOfStatement(parent) || typescript_1.default.isForInStatement(parent))
                && parent.initializer === current);
    }
    return false;
}
function assignmentValuesForSymbol(input, value, symbol, checker, projectSources, check, depth = 0) {
    check();
    if (depth > 64)
        return undefined;
    let target = input;
    while (typescript_1.default.isParenthesizedExpression(target) || typescript_1.default.isAsExpression(target)
        || typescript_1.default.isTypeAssertionExpression(target) || typescript_1.default.isSatisfiesExpression(target)
        || typescript_1.default.isNonNullExpression(target))
        target = target.expression;
    if (typescript_1.default.isIdentifier(target)) {
        let targetSymbol = checker.getSymbolAtLocation(target);
        if (targetSymbol?.flags && targetSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
            targetSymbol = checker.getAliasedSymbol(targetSymbol);
        }
        return targetSymbol === symbol ? [value] : [];
    }
    if (typescript_1.default.isPropertyAccessExpression(target) || typescript_1.default.isElementAccessExpression(target)) {
        let targetSymbol = typescript_1.default.isPropertyAccessExpression(target)
            ? checker.getSymbolAtLocation(target.name)
            : target.argumentExpression
                ? checker.getNonNullableType(checker.getTypeAtLocation(target.expression)).getProperty((0, decorator_symbols_1.resolveStaticPropertyKey)(target.argumentExpression, checker, check) ?? '') : undefined;
        if (targetSymbol?.flags && targetSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
            targetSymbol = checker.getAliasedSymbol(targetSymbol);
        }
        return targetSymbol === symbol ? [value] : [];
    }
    if (typescript_1.default.isBinaryExpression(target)
        && target.operatorToken.kind === typescript_1.default.SyntaxKind.EqualsToken) {
        const undefinedState = staticUndefinedState(value, checker, projectSources, check);
        const assignedValue = undefinedState === true ? target.right : value;
        const values = assignmentValuesForSymbol(target.left, assignedValue, symbol, checker, projectSources, check, depth + 1);
        return values && undefinedState === undefined ? [...values, target.right] : values;
    }
    if (typescript_1.default.isArrayLiteralExpression(target)) {
        if (!typescript_1.default.isArrayLiteralExpression(value))
            return undefined;
        const values = [];
        for (let index = 0; index < target.elements.length; index += 1) {
            const element = target.elements[index];
            if (typescript_1.default.isOmittedExpression(element)
                || !assignmentTargetContainsSymbol(element, symbol, checker, check))
                continue;
            const candidate = value.elements[index];
            if (!candidate || typescript_1.default.isOmittedExpression(candidate)) {
                if (!typescript_1.default.isBinaryExpression(element)
                    || element.operatorToken.kind !== typescript_1.default.SyntaxKind.EqualsToken)
                    return undefined;
                const nested = assignmentValuesForSymbol(element.left, element.right, symbol, checker, projectSources, check, depth + 1);
                if (!nested)
                    return undefined;
                values.push(...nested);
                continue;
            }
            if (typescript_1.default.isSpreadElement(element) || typescript_1.default.isSpreadElement(candidate))
                return undefined;
            const nested = assignmentValuesForSymbol(element, candidate, symbol, checker, projectSources, check, depth + 1);
            if (!nested)
                return undefined;
            values.push(...nested);
        }
        return values;
    }
    if (typescript_1.default.isObjectLiteralExpression(target)) {
        if (!typescript_1.default.isObjectLiteralExpression(value))
            return undefined;
        const values = [];
        for (const property of target.properties) {
            if (!typescript_1.default.isPropertyAssignment(property) && !typescript_1.default.isShorthandPropertyAssignment(property)) {
                if (assignmentTargetContainsSymbol(property, symbol, checker, check))
                    return undefined;
                continue;
            }
            const nestedTarget = typescript_1.default.isPropertyAssignment(property) ? property.initializer : property.name;
            if (!assignmentTargetContainsSymbol(nestedTarget, symbol, checker, check))
                continue;
            const { name } = property;
            const propertyName = typescript_1.default.isComputedPropertyName(name)
                ? (0, decorator_symbols_1.resolveStaticPropertyKey)(name.expression, checker, check)
                : (typescript_1.default.isIdentifier(name) || typescript_1.default.isStringLiteral(name) || typescript_1.default.isNumericLiteral(name))
                    ? name.text : undefined;
            if (propertyName === undefined)
                return undefined;
            const effective = effectiveObjectProperty(value, propertyName, checker, projectSources, check);
            if (!effective.present) {
                if (!typescript_1.default.isBinaryExpression(nestedTarget)
                    || nestedTarget.operatorToken.kind !== typescript_1.default.SyntaxKind.EqualsToken)
                    return undefined;
                const nested = assignmentValuesForSymbol(nestedTarget.left, nestedTarget.right, symbol, checker, projectSources, check, depth + 1);
                if (!nested)
                    return undefined;
                values.push(...nested);
                continue;
            }
            if (effective.accessor)
                return undefined;
            for (const candidate of effective.candidates) {
                const nested = assignmentValuesForSymbol(nestedTarget, candidate, symbol, checker, projectSources, check, depth + 1);
                if (!nested)
                    return undefined;
                values.push(...nested);
            }
        }
        return values;
    }
    return assignmentTargetContainsSymbol(target, symbol, checker, check) ? undefined : [];
}
function registeredProviderObjects(checker, projectSources, check) {
    const providers = new Set();
    const candidates = [];
    const staticState = (input, seen = new Set(), depth = 0) => {
        check();
        if (depth > 64)
            return {};
        let expression = input;
        while (typescript_1.default.isParenthesizedExpression(expression) || typescript_1.default.isAsExpression(expression)
            || typescript_1.default.isTypeAssertionExpression(expression) || typescript_1.default.isSatisfiesExpression(expression)
            || typescript_1.default.isNonNullExpression(expression))
            expression = expression.expression;
        if (typescript_1.default.isBinaryExpression(expression) && (expression.operatorToken.kind === typescript_1.default.SyntaxKind.AmpersandAmpersandToken
            || expression.operatorToken.kind === typescript_1.default.SyntaxKind.BarBarToken
            || expression.operatorToken.kind === typescript_1.default.SyntaxKind.QuestionQuestionToken)) {
            const left = staticState(expression.left, new Set(seen), depth + 1);
            if (expression.operatorToken.kind === typescript_1.default.SyntaxKind.AmpersandAmpersandToken) {
                if (left.truthy === false)
                    return left;
                if (left.truthy === true)
                    return staticState(expression.right, seen, depth + 1);
            }
            else if (expression.operatorToken.kind === typescript_1.default.SyntaxKind.BarBarToken) {
                if (left.truthy === true)
                    return left;
                if (left.truthy === false)
                    return staticState(expression.right, seen, depth + 1);
            }
            else {
                if (left.nullish === false)
                    return left;
                if (left.nullish === true)
                    return staticState(expression.right, seen, depth + 1);
            }
            const right = staticState(expression.right, seen, depth + 1);
            return {
                ...(left.truthy === right.truthy ? { truthy: left.truthy } : {}),
                ...(left.nullish === right.nullish ? { nullish: left.nullish } : {}),
            };
        }
        if (expression.kind === typescript_1.default.SyntaxKind.NullKeyword || typescript_1.default.isVoidExpression(expression)) {
            return { truthy: false, nullish: true };
        }
        if (expression.kind === typescript_1.default.SyntaxKind.TrueKeyword)
            return { truthy: true, nullish: false };
        if (expression.kind === typescript_1.default.SyntaxKind.FalseKeyword)
            return { truthy: false, nullish: false };
        if (typescript_1.default.isStringLiteral(expression) || typescript_1.default.isNoSubstitutionTemplateLiteral(expression)) {
            return { truthy: expression.text.length > 0, nullish: false };
        }
        if (typescript_1.default.isNumericLiteral(expression)) {
            return { truthy: Number(expression.text) !== 0, nullish: false };
        }
        if (typescript_1.default.isBigIntLiteral(expression)) {
            return { truthy: BigInt(expression.text.slice(0, -1)) !== 0n, nullish: false };
        }
        if (typescript_1.default.isObjectLiteralExpression(expression) || typescript_1.default.isArrayLiteralExpression(expression)
            || typescript_1.default.isFunctionExpression(expression) || typescript_1.default.isArrowFunction(expression)
            || typescript_1.default.isClassExpression(expression) || typescript_1.default.isRegularExpressionLiteral(expression)
            || typescript_1.default.isNewExpression(expression))
            return { truthy: true, nullish: false };
        if (!typescript_1.default.isIdentifier(expression))
            return {};
        let symbol = checker.getSymbolAtLocation(expression);
        if (expression.text === 'undefined' && !symbol?.declarations?.length) {
            return { truthy: false, nullish: true };
        }
        if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
            symbol = checker.getAliasedSymbol(symbol);
        if (!symbol || seen.has(symbol))
            return {};
        if (symbol.declarations?.some((declaration) => ((typescript_1.default.isClassLike(declaration) || typescript_1.default.isFunctionDeclaration(declaration))
            && projectSources.has(declaration.getSourceFile()))))
            return { truthy: true, nullish: false };
        const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
        const declaration = declarations.length === 1 ? declarations[0] : undefined;
        if (!declaration?.initializer || !projectSources.has(declaration.getSourceFile())
            || !typescript_1.default.isVariableDeclarationList(declaration.parent)
            || !(declaration.parent.flags & typescript_1.default.NodeFlags.Const))
            return {};
        seen.add(symbol);
        return staticState(declaration.initializer, seen, depth + 1);
    };
    const collect = (input, seen, depth) => {
        check();
        if (depth > 64)
            return false;
        let expression = input;
        while (typescript_1.default.isParenthesizedExpression(expression) || typescript_1.default.isAsExpression(expression)
            || typescript_1.default.isTypeAssertionExpression(expression) || typescript_1.default.isSatisfiesExpression(expression)
            || typescript_1.default.isNonNullExpression(expression))
            expression = expression.expression;
        if (typescript_1.default.isObjectLiteralExpression(expression)) {
            providers.add(expression);
            return true;
        }
        if (typescript_1.default.isArrayLiteralExpression(expression)) {
            let complete = true;
            for (const element of expression.elements) {
                complete = collect(typescript_1.default.isSpreadElement(element) ? element.expression : element, new Set(seen), depth + 1) && complete;
            }
            return complete;
        }
        if (typescript_1.default.isBinaryExpression(expression) && (expression.operatorToken.kind === typescript_1.default.SyntaxKind.AmpersandAmpersandToken
            || expression.operatorToken.kind === typescript_1.default.SyntaxKind.BarBarToken
            || expression.operatorToken.kind === typescript_1.default.SyntaxKind.QuestionQuestionToken)) {
            const state = staticState(expression.left);
            if (expression.operatorToken.kind === typescript_1.default.SyntaxKind.AmpersandAmpersandToken) {
                if (state.truthy === true)
                    return collect(expression.right, seen, depth + 1);
                if (state.truthy === false)
                    return collect(expression.left, seen, depth + 1);
            }
            else if (expression.operatorToken.kind === typescript_1.default.SyntaxKind.BarBarToken) {
                if (state.truthy === true)
                    return collect(expression.left, seen, depth + 1);
                if (state.truthy === false)
                    return collect(expression.right, seen, depth + 1);
            }
            else {
                if (state.nullish === true)
                    return collect(expression.right, seen, depth + 1);
                if (state.nullish === false)
                    return collect(expression.left, seen, depth + 1);
            }
            const left = collect(expression.left, new Set(seen), depth + 1);
            const right = collect(expression.right, new Set(seen), depth + 1);
            return left && right;
        }
        if (typescript_1.default.isCallExpression(expression) && expression.arguments.length === 0) {
            let callee = expression.expression;
            while (typescript_1.default.isParenthesizedExpression(callee))
                callee = callee.expression;
            if ((typescript_1.default.isArrowFunction(callee) || typescript_1.default.isFunctionExpression(callee))
                && callee.parameters.length === 0
                && !callee.modifiers?.some(({ kind }) => kind === typescript_1.default.SyntaxKind.AsyncKeyword)
                && (!typescript_1.default.isFunctionExpression(callee) || callee.asteriskToken === undefined)) {
                const returned = typescript_1.default.isBlock(callee.body)
                    && callee.body.statements.length === 1
                    && typescript_1.default.isReturnStatement(callee.body.statements[0])
                    ? callee.body.statements[0].expression
                    : typescript_1.default.isBlock(callee.body) ? undefined : callee.body;
                return returned ? collect(returned, seen, depth + 1) : false;
            }
            if (!typescript_1.default.isIdentifier(callee))
                return false;
            let symbol = checker.getSymbolAtLocation(callee);
            if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
                symbol = checker.getAliasedSymbol(symbol);
            const declarations = symbol?.declarations?.filter((candidate) => (typescript_1.default.isFunctionDeclaration(candidate) && candidate.body !== undefined
                && projectSources.has(candidate.getSourceFile()))) ?? [];
            const declaration = declarations.length === 1 ? declarations[0] : undefined;
            const returned = declaration?.body?.statements.length === 1
                && typescript_1.default.isReturnStatement(declaration.body.statements[0])
                ? declaration.body.statements[0].expression : undefined;
            if (symbol && returned && !seen.has(symbol)) {
                seen.add(symbol);
                return collect(returned, seen, depth + 1);
            }
            return false;
        }
        if (!typescript_1.default.isIdentifier(expression))
            return false;
        let symbol = typescript_1.default.isShorthandPropertyAssignment(expression.parent)
            ? checker.getShorthandAssignmentValueSymbol(expression.parent)
            : checker.getSymbolAtLocation(expression);
        if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
            symbol = checker.getAliasedSymbol(symbol);
        if (!symbol || seen.has(symbol))
            return false;
        const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
        const declaration = declarations.length === 1 ? declarations[0] : undefined;
        if (!declaration?.initializer || !projectSources.has(declaration.getSourceFile())
            || !typescript_1.default.isVariableDeclarationList(declaration.parent)
            || !(declaration.parent.flags & typescript_1.default.NodeFlags.Const))
            return false;
        seen.add(symbol);
        collect(declaration.initializer, seen, depth + 1);
        return false;
    };
    const reassignedSymbols = new Set();
    const escapedSymbols = new Set();
    const mutatedContainers = new Set();
    const propertyAssignedContainers = new Map();
    const mutatedContainerExpressions = new Set();
    const assignedValues = new Map();
    const unresolvedAssignments = new Set();
    const aliases = new Map();
    const memberMutationCache = new Map();
    const pendingEscapes = [];
    const unresolvedImportDefaultAliases = new Set();
    const unresolvedSpreadParameters = new Set();
    const incompleteDynamicAliases = new Set();
    const dynamicAliasExpressions = new Map();
    let escapeIndexIncomplete = false;
    let escapeIndexLimitExceeded = false;
    const incompleteLocalCallImportSymbols = new Set();
    let escapeSteps = 0;
    const isExternalModuleReference = (input, seen = new Set(), depth = 0) => {
        check();
        if (depth > 64)
            return true;
        let expression = input;
        while (typescript_1.default.isParenthesizedExpression(expression) || typescript_1.default.isAsExpression(expression)
            || typescript_1.default.isTypeAssertionExpression(expression) || typescript_1.default.isSatisfiesExpression(expression)
            || typescript_1.default.isNonNullExpression(expression))
            expression = expression.expression;
        if (typescript_1.default.isArrayLiteralExpression(expression)) {
            return expression.elements.some((element) => isExternalModuleReference(typescript_1.default.isSpreadElement(element) ? element.expression : element, new Set(seen), depth + 1));
        }
        if (typescript_1.default.isConditionalExpression(expression)) {
            const state = staticState(expression.condition);
            if (state.truthy === true) {
                return isExternalModuleReference(expression.whenTrue, seen, depth + 1);
            }
            if (state.truthy === false) {
                return isExternalModuleReference(expression.whenFalse, seen, depth + 1);
            }
            return isExternalModuleReference(expression.whenTrue, new Set(seen), depth + 1)
                || isExternalModuleReference(expression.whenFalse, new Set(seen), depth + 1);
        }
        if (typescript_1.default.isBinaryExpression(expression) && (expression.operatorToken.kind === typescript_1.default.SyntaxKind.AmpersandAmpersandToken
            || expression.operatorToken.kind === typescript_1.default.SyntaxKind.BarBarToken
            || expression.operatorToken.kind === typescript_1.default.SyntaxKind.QuestionQuestionToken)) {
            const state = staticState(expression.left);
            if (expression.operatorToken.kind === typescript_1.default.SyntaxKind.AmpersandAmpersandToken) {
                if (state.truthy === false)
                    return false;
                if (state.truthy === true) {
                    return isExternalModuleReference(expression.right, seen, depth + 1);
                }
            }
            else if (expression.operatorToken.kind === typescript_1.default.SyntaxKind.BarBarToken) {
                if (state.truthy === true)
                    return false;
                if (state.truthy === false) {
                    return isExternalModuleReference(expression.right, seen, depth + 1);
                }
            }
            else {
                if (state.nullish === false)
                    return false;
                if (state.nullish === true) {
                    return isExternalModuleReference(expression.right, seen, depth + 1);
                }
            }
            return isExternalModuleReference(expression.left, new Set(seen), depth + 1)
                || isExternalModuleReference(expression.right, new Set(seen), depth + 1);
        }
        if (typescript_1.default.isCallExpression(expression)) {
            let callee = expression.expression;
            while (typescript_1.default.isParenthesizedExpression(callee))
                callee = callee.expression;
            let callable;
            if ((typescript_1.default.isArrowFunction(callee) || typescript_1.default.isFunctionExpression(callee))
                && callee.parameters.length === 0)
                callable = callee;
            if (typescript_1.default.isIdentifier(callee)) {
                const original = checker.getSymbolAtLocation(callee);
                const importSpecifier = original?.declarations?.find(typescript_1.default.isImportSpecifier);
                const importDeclaration = importSpecifier?.parent.parent.parent;
                const isForwardRef = callee.text === 'forwardRef' && importDeclaration
                    && typescript_1.default.isImportDeclaration(importDeclaration)
                    && typescript_1.default.isStringLiteral(importDeclaration.moduleSpecifier)
                    && importDeclaration.moduleSpecifier.text === '@nestjs/common';
                const argument = isForwardRef && expression.arguments.length === 1
                    ? expression.arguments[0] : undefined;
                if (argument && (typescript_1.default.isArrowFunction(argument) || typescript_1.default.isFunctionExpression(argument))
                    && argument.parameters.length === 0)
                    callable = argument;
                if (!callable && expression.arguments.length === 0) {
                    let symbol = original;
                    if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
                        symbol = checker.getAliasedSymbol(symbol);
                    if (symbol && reassignedSymbols.has(symbol))
                        return true;
                    const declarations = symbol?.declarations?.filter((candidate) => (typescript_1.default.isFunctionDeclaration(candidate) && candidate.body !== undefined
                        && candidate.parameters.length === 0 && projectSources.has(candidate.getSourceFile()))) ?? [];
                    if (declarations.length === 1)
                        callable = declarations[0];
                }
            }
            const body = callable?.body;
            const returned = body && !typescript_1.default.isBlock(body) ? body
                : body && body.statements.length === 1 && typescript_1.default.isReturnStatement(body.statements[0])
                    ? body.statements[0].expression : undefined;
            return returned ? isExternalModuleReference(returned, seen, depth + 1) : true;
        }
        if (typescript_1.default.isPropertyAccessExpression(expression) || typescript_1.default.isElementAccessExpression(expression)) {
            let symbol = checker.getSymbolAtLocation(typescript_1.default.isPropertyAccessExpression(expression) ? expression.name : expression);
            if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
                symbol = checker.getAliasedSymbol(symbol);
            if (symbol?.declarations?.some((declaration) => (declaration.getSourceFile().fileName.replaceAll('\\', '/').includes('/node_modules/'))))
                return true;
            if (symbol?.declarations?.some((declaration) => (typescript_1.default.isClassLike(declaration) && projectSources.has(declaration.getSourceFile()))))
                return false;
            return true;
        }
        if (typescript_1.default.isClassExpression(expression))
            return false;
        if (expression.kind === typescript_1.default.SyntaxKind.TrueKeyword
            || expression.kind === typescript_1.default.SyntaxKind.FalseKeyword
            || expression.kind === typescript_1.default.SyntaxKind.NullKeyword
            || typescript_1.default.isVoidExpression(expression) || typescript_1.default.isStringLiteral(expression)
            || typescript_1.default.isNoSubstitutionTemplateLiteral(expression) || typescript_1.default.isNumericLiteral(expression)
            || typescript_1.default.isBigIntLiteral(expression))
            return false;
        if (!typescript_1.default.isIdentifier(expression))
            return true;
        let symbol = checker.getSymbolAtLocation(expression);
        if (!symbol || seen.has(symbol))
            return true;
        seen.add(symbol);
        if (symbol.flags & typescript_1.default.SymbolFlags.Alias)
            symbol = checker.getAliasedSymbol(symbol);
        if (symbol.declarations?.some((declaration) => (declaration.getSourceFile().fileName.replaceAll('\\', '/').includes('/node_modules/'))))
            return true;
        if (symbol.declarations?.some((declaration) => (typescript_1.default.isClassLike(declaration) && projectSources.has(declaration.getSourceFile()))))
            return false;
        const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
        const declaration = declarations.length === 1 ? declarations[0] : undefined;
        if (declaration?.initializer && projectSources.has(declaration.getSourceFile())
            && typescript_1.default.isVariableDeclarationList(declaration.parent)
            && declaration.parent.flags & typescript_1.default.NodeFlags.Const) {
            return isExternalModuleReference(declaration.initializer, seen, depth + 1);
        }
        return true;
    };
    const symbolAt = (node) => {
        let symbol = checker.getSymbolAtLocation(node);
        if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
            symbol = checker.getAliasedSymbol(symbol);
        return symbol;
    };
    const rootSymbolAt = (input) => {
        let expression = input;
        while (true) {
            while (typescript_1.default.isParenthesizedExpression(expression) || typescript_1.default.isAsExpression(expression)
                || typescript_1.default.isTypeAssertionExpression(expression) || typescript_1.default.isSatisfiesExpression(expression)
                || typescript_1.default.isNonNullExpression(expression))
                expression = expression.expression;
            if (typescript_1.default.isPropertyAccessExpression(expression) || typescript_1.default.isElementAccessExpression(expression)) {
                expression = expression.expression;
                continue;
            }
            return typescript_1.default.isIdentifier(expression) ? resolvedSymbolAt(expression, checker) : undefined;
        }
    };
    const linkAliases = (left, right) => {
        if (!left || !right || left === right)
            return;
        (aliases.get(left) ?? aliases.set(left, new Set()).get(left)).add(right);
        (aliases.get(right) ?? aliases.set(right, new Set()).get(right)).add(left);
    };
    const dynamicObjectIndexes = new WeakMap();
    const indexingDynamicObjects = new Set();
    let dynamicObjectIndexSteps = 0;
    const indexDynamicObject = (object) => {
        const cached = dynamicObjectIndexes.get(object);
        if (cached)
            return cached;
        if (indexingDynamicObjects.has(object))
            return { entries: new Map(), complete: false };
        indexingDynamicObjects.add(object);
        const result = { entries: new Map(), complete: true };
        for (const property of object.properties) {
            check();
            if (dynamicObjectIndexSteps++ >= MAX_PROVIDER_SPREAD_ELEMENTS) {
                result.complete = false;
                break;
            }
            if (typescript_1.default.isSpreadAssignment(property)) {
                const spread = resolveConstObject(property.expression, checker, projectSources, check);
                if (!spread)
                    result.complete = false;
                else {
                    const nested = indexDynamicObject(spread);
                    result.complete &&= nested.complete;
                    for (const [name, entry] of nested.entries)
                        result.entries.set(name, entry);
                }
                continue;
            }
            const name = typescript_1.default.isComputedPropertyName(property.name)
                ? (0, decorator_symbols_1.resolveStaticPropertyKey)(property.name.expression, checker, check)
                : typescript_1.default.isIdentifier(property.name) || typescript_1.default.isStringLiteral(property.name)
                    || typescript_1.default.isNumericLiteral(property.name) ? property.name.text : undefined;
            if (name === undefined) {
                result.complete = false;
            }
            else if (typescript_1.default.isPropertyAssignment(property)) {
                result.entries.set(name, { candidates: [property.initializer], accessor: false });
            }
            else if (typescript_1.default.isShorthandPropertyAssignment(property)) {
                result.entries.set(name, { candidates: [property.name], accessor: false });
            }
            else if (typescript_1.default.isGetAccessorDeclaration(property) || typescript_1.default.isSetAccessorDeclaration(property)) {
                result.entries.set(name, { candidates: [], accessor: true });
            }
            else {
                result.entries.set(name, { candidates: [], accessor: false });
            }
        }
        indexingDynamicObjects.delete(object);
        dynamicObjectIndexes.set(object, result);
        return result;
    };
    const linkDynamicElementCandidates = (alias, receiver) => {
        if (!alias)
            return;
        const object = resolveConstObject(receiver, checker, projectSources, check);
        if (!object) {
            incompleteDynamicAliases.add(alias);
            return;
        }
        const indexed = indexDynamicObject(object);
        if (!indexed.complete)
            incompleteDynamicAliases.add(alias);
        const expressions = dynamicAliasExpressions.get(alias) ?? new Set();
        dynamicAliasExpressions.set(alias, expressions);
        for (const effective of indexed.entries.values()) {
            if (effective.accessor || effective.candidates.length === 0) {
                incompleteDynamicAliases.add(alias);
            }
            for (const candidate of effective.candidates) {
                let value = candidate;
                while (typescript_1.default.isParenthesizedExpression(value) || typescript_1.default.isAsExpression(value)
                    || typescript_1.default.isTypeAssertionExpression(value) || typescript_1.default.isSatisfiesExpression(value)
                    || typescript_1.default.isNonNullExpression(value))
                    value = value.expression;
                expressions.add(value);
                const member = typescript_1.default.isIdentifier(value) ? symbolAt(value)
                    : typescript_1.default.isPropertyAccessExpression(value) || typescript_1.default.isElementAccessExpression(value)
                        ? symbolAt(typescript_1.default.isPropertyAccessExpression(value) ? value.name : value) : undefined;
                const root = typescript_1.default.isPropertyAccessExpression(value) || typescript_1.default.isElementAccessExpression(value)
                    ? rootSymbolAt(value.expression) : undefined;
                linkAliases(alias, member);
                linkAliases(alias, root);
            }
        }
    };
    const aliasSetHas = (values, symbol) => {
        const seen = new Set();
        const pending = [symbol];
        while (pending.length > 0) {
            check();
            const candidate = pending.pop();
            if (values.has(candidate))
                return true;
            if (seen.has(candidate))
                continue;
            if (seen.size >= MAX_PROVIDER_SPREAD_ELEMENTS)
                return true;
            seen.add(candidate);
            pending.push(...(aliases.get(candidate) ?? []));
        }
        return false;
    };
    const recordAssignedContainer = (input) => {
        const receiver = rootSymbolAt(input.expression);
        if (!receiver)
            return;
        let access = input;
        let key = '*';
        while (typescript_1.default.isPropertyAccessExpression(access) || typescript_1.default.isElementAccessExpression(access)) {
            key = typescript_1.default.isPropertyAccessExpression(access) ? access.name.text
                : access.argumentExpression
                    ? (0, decorator_symbols_1.resolveStaticPropertyKey)(access.argumentExpression, checker, check) ?? '*' : '*';
            access = access.expression;
            while (typescript_1.default.isParenthesizedExpression(access) || typescript_1.default.isAsExpression(access)
                || typescript_1.default.isTypeAssertionExpression(access) || typescript_1.default.isSatisfiesExpression(access)
                || typescript_1.default.isNonNullExpression(access))
                access = access.expression;
        }
        const keys = propertyAssignedContainers.get(receiver) ?? new Set();
        keys.add(key);
        propertyAssignedContainers.set(receiver, keys);
    };
    const markAssignmentTarget = (input) => {
        let target = input;
        while (typescript_1.default.isParenthesizedExpression(target) || typescript_1.default.isAsExpression(target)
            || typescript_1.default.isTypeAssertionExpression(target) || typescript_1.default.isSatisfiesExpression(target)
            || typescript_1.default.isNonNullExpression(target))
            target = target.expression;
        if (typescript_1.default.isIdentifier(target)) {
            const symbol = symbolAt(target);
            if (symbol)
                reassignedSymbols.add(symbol);
        }
        else if (typescript_1.default.isPropertyAccessExpression(target)) {
            const symbol = symbolAt(target.name);
            if (symbol)
                reassignedSymbols.add(symbol);
            recordAssignedContainer(target);
        }
        else if (typescript_1.default.isElementAccessExpression(target)) {
            const key = target.argumentExpression
                ? (0, decorator_symbols_1.resolveStaticPropertyKey)(target.argumentExpression, checker, check) : undefined;
            const symbol = key === undefined ? undefined
                : checker.getNonNullableType(checker.getTypeAtLocation(target.expression)).getProperty(key);
            if (symbol)
                reassignedSymbols.add(symbol);
            const receiver = rootSymbolAt(target.expression);
            recordAssignedContainer(target);
            if (!symbol && receiver)
                escapedSymbols.add(receiver);
            else if (!symbol && typescript_1.default.isIdentifier(target.expression)) {
                const expressionSymbol = symbolAt(target.expression);
                if (expressionSymbol)
                    escapedSymbols.add(expressionSymbol);
            }
        }
        else if (typescript_1.default.isArrayLiteralExpression(target)) {
            for (const element of target.elements) {
                if (!typescript_1.default.isOmittedExpression(element)) {
                    markAssignmentTarget(typescript_1.default.isSpreadElement(element) ? element.expression : element);
                }
            }
        }
        else if (typescript_1.default.isObjectLiteralExpression(target)) {
            for (const property of target.properties) {
                if (typescript_1.default.isPropertyAssignment(property))
                    markAssignmentTarget(property.initializer);
                else if (typescript_1.default.isShorthandPropertyAssignment(property))
                    markAssignmentTarget(property.name);
                else if (typescript_1.default.isSpreadAssignment(property))
                    markAssignmentTarget(property.expression);
            }
        }
        else if (typescript_1.default.isVariableDeclarationList(target)) {
            for (const declaration of target.declarations)
                markAssignmentTarget(declaration.name);
        }
        else if (typescript_1.default.isVariableDeclaration(target) || typescript_1.default.isBindingElement(target)) {
            markAssignmentTarget(target.name);
        }
        else if (typescript_1.default.isArrayBindingPattern(target) || typescript_1.default.isObjectBindingPattern(target)) {
            for (const element of target.elements)
                markAssignmentTarget(element);
        }
    };
    const directAssignmentSymbol = (input) => {
        let target = input;
        while (typescript_1.default.isParenthesizedExpression(target) || typescript_1.default.isAsExpression(target)
            || typescript_1.default.isTypeAssertionExpression(target) || typescript_1.default.isSatisfiesExpression(target)
            || typescript_1.default.isNonNullExpression(target))
            target = target.expression;
        if (typescript_1.default.isIdentifier(target))
            return symbolAt(target);
        if (typescript_1.default.isPropertyAccessExpression(target))
            return symbolAt(target.name);
        if (!typescript_1.default.isElementAccessExpression(target))
            return undefined;
        const key = target.argumentExpression
            ? (0, decorator_symbols_1.resolveStaticPropertyKey)(target.argumentExpression, checker, check) : undefined;
        return key === undefined ? undefined
            : checker.getNonNullableType(checker.getTypeAtLocation(target.expression)).getProperty(key);
    };
    const markEscapedValue = (input, depth = 0) => {
        check();
        if (escapeSteps++ >= MAX_PROVIDER_SPREAD_ELEMENTS) {
            escapeIndexIncomplete = true;
            escapeIndexLimitExceeded = true;
            return;
        }
        if (depth > 64) {
            escapeIndexIncomplete = true;
            escapeIndexLimitExceeded = true;
            return;
        }
        let value = input;
        while (typescript_1.default.isParenthesizedExpression(value) || typescript_1.default.isAsExpression(value)
            || typescript_1.default.isTypeAssertionExpression(value) || typescript_1.default.isSatisfiesExpression(value)
            || typescript_1.default.isNonNullExpression(value))
            value = value.expression;
        if (typescript_1.default.isIdentifier(value)) {
            const symbol = resolvedSymbolAt(value, checker);
            const declarations = symbol?.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
            const declaration = declarations.length === 1 ? declarations[0] : undefined;
            let initializer = declaration?.initializer;
            while (initializer && (typescript_1.default.isParenthesizedExpression(initializer) || typescript_1.default.isAsExpression(initializer)
                || typescript_1.default.isTypeAssertionExpression(initializer) || typescript_1.default.isSatisfiesExpression(initializer)
                || typescript_1.default.isNonNullExpression(initializer)))
                initializer = initializer.expression;
            if (symbol && (resolveConstObject(value, checker, projectSources, check)
                || (initializer && (typescript_1.default.isObjectLiteralExpression(initializer)
                    || typescript_1.default.isArrayLiteralExpression(initializer)))))
                escapedSymbols.add(symbol);
        }
        else if (typescript_1.default.isArrayLiteralExpression(value)) {
            for (const element of value.elements) {
                if (!typescript_1.default.isOmittedExpression(element)) {
                    markEscapedValue(typescript_1.default.isSpreadElement(element) ? element.expression : element, depth + 1);
                }
            }
        }
        else if (typescript_1.default.isObjectLiteralExpression(value)) {
            for (const property of value.properties) {
                if (typescript_1.default.isPropertyAssignment(property))
                    markEscapedValue(property.initializer, depth + 1);
                else if (typescript_1.default.isShorthandPropertyAssignment(property))
                    markEscapedValue(property.name, depth + 1);
                else if (typescript_1.default.isSpreadAssignment(property))
                    markEscapedValue(property.expression, depth + 1);
            }
        }
        else if (typescript_1.default.isConditionalExpression(value)) {
            markEscapedValue(value.whenTrue, depth + 1);
            markEscapedValue(value.whenFalse, depth + 1);
        }
        else if (typescript_1.default.isPropertyAccessExpression(value) || typescript_1.default.isElementAccessExpression(value)) {
            const propertyName = typescript_1.default.isPropertyAccessExpression(value) ? value.name.text
                : value.argumentExpression
                    ? (0, decorator_symbols_1.resolveStaticPropertyKey)(value.argumentExpression, checker, check) : undefined;
            const object = resolveConstObject(value.expression, checker, projectSources, check);
            if (propertyName !== undefined && object) {
                const effective = effectiveObjectProperty(object, propertyName, checker, projectSources, check);
                for (const candidate of effective.candidates)
                    markEscapedValue(candidate, depth + 1);
                const member = symbolAt(typescript_1.default.isPropertyAccessExpression(value) ? value.name : value);
                for (const candidate of member ? assignedValues.get(member) ?? [] : []) {
                    markEscapedValue(candidate, depth + 1);
                }
                if (member && unresolvedAssignments.has(member))
                    escapeIndexIncomplete = true;
                let receiver = value.expression;
                while (typescript_1.default.isParenthesizedExpression(receiver) || typescript_1.default.isAsExpression(receiver)
                    || typescript_1.default.isTypeAssertionExpression(receiver) || typescript_1.default.isSatisfiesExpression(receiver)
                    || typescript_1.default.isNonNullExpression(receiver))
                    receiver = receiver.expression;
                const receiverSymbol = rootSymbolAt(receiver);
                if (receiverSymbol && (aliasSetHas(escapedSymbols, receiverSymbol)
                    || aliasSetHas(mutatedContainers, receiverSymbol)))
                    escapeIndexIncomplete = true;
            }
            else if (typescript_1.default.isElementAccessExpression(value) && propertyName !== undefined) {
                let receiver = value.expression;
                while (typescript_1.default.isParenthesizedExpression(receiver) || typescript_1.default.isAsExpression(receiver)
                    || typescript_1.default.isTypeAssertionExpression(receiver) || typescript_1.default.isSatisfiesExpression(receiver)
                    || typescript_1.default.isNonNullExpression(receiver))
                    receiver = receiver.expression;
                if (typescript_1.default.isIdentifier(receiver)) {
                    const symbol = resolvedSymbolAt(receiver, checker);
                    const declarations = symbol?.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
                    const declaration = declarations.length === 1 ? declarations[0] : undefined;
                    if (declaration?.initializer && typescript_1.default.isVariableDeclarationList(declaration.parent)
                        && declaration.parent.flags & typescript_1.default.NodeFlags.Const)
                        receiver = declaration.initializer;
                    while (typescript_1.default.isParenthesizedExpression(receiver) || typescript_1.default.isAsExpression(receiver)
                        || typescript_1.default.isTypeAssertionExpression(receiver) || typescript_1.default.isSatisfiesExpression(receiver)
                        || typescript_1.default.isNonNullExpression(receiver))
                        receiver = receiver.expression;
                }
                const member = symbolAt(value);
                for (const candidate of member ? assignedValues.get(member) ?? [] : []) {
                    markEscapedValue(candidate, depth + 1);
                }
                if (member && unresolvedAssignments.has(member))
                    escapeIndexIncomplete = true;
                let sourceReceiver = value.expression;
                while (typescript_1.default.isParenthesizedExpression(sourceReceiver) || typescript_1.default.isAsExpression(sourceReceiver)
                    || typescript_1.default.isTypeAssertionExpression(sourceReceiver) || typescript_1.default.isSatisfiesExpression(sourceReceiver)
                    || typescript_1.default.isNonNullExpression(sourceReceiver))
                    sourceReceiver = sourceReceiver.expression;
                const sourceSymbol = rootSymbolAt(sourceReceiver);
                if (sourceSymbol && (aliasSetHas(escapedSymbols, sourceSymbol)
                    || aliasSetHas(mutatedContainers, sourceSymbol)))
                    escapeIndexIncomplete = true;
                const index = Number(propertyName);
                const canonicalIndex = Number.isInteger(index) && index >= 0 && index < 0xffff_ffff
                    && String(index) === propertyName;
                let remainingElements = MAX_PROVIDER_SPREAD_ELEMENTS;
                const flatten = (input, flattenDepth = 0) => {
                    check();
                    if (flattenDepth > 64)
                        return undefined;
                    let array = input;
                    while (typescript_1.default.isParenthesizedExpression(array) || typescript_1.default.isAsExpression(array)
                        || typescript_1.default.isTypeAssertionExpression(array) || typescript_1.default.isSatisfiesExpression(array)
                        || typescript_1.default.isNonNullExpression(array))
                        array = array.expression;
                    if (typescript_1.default.isIdentifier(array)) {
                        const symbol = resolvedSymbolAt(array, checker);
                        const declarations = symbol?.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
                        const declaration = declarations.length === 1 ? declarations[0] : undefined;
                        if (!declaration?.initializer || !typescript_1.default.isVariableDeclarationList(declaration.parent)
                            || !(declaration.parent.flags & typescript_1.default.NodeFlags.Const))
                            return undefined;
                        return flatten(declaration.initializer, flattenDepth + 1);
                    }
                    if (!typescript_1.default.isArrayLiteralExpression(array))
                        return undefined;
                    const flattened = [];
                    for (const element of array.elements) {
                        if (remainingElements-- <= 0)
                            return undefined;
                        if (typescript_1.default.isOmittedExpression(element))
                            flattened.push(undefined);
                        else if (typescript_1.default.isSpreadElement(element)) {
                            const spread = flatten(element.expression, flattenDepth + 1);
                            if (!spread || spread.length > remainingElements)
                                return undefined;
                            remainingElements -= spread.length;
                            flattened.push(...spread);
                        }
                        else
                            flattened.push(element);
                    }
                    return flattened;
                };
                const flattened = flatten(receiver);
                if (flattened && canonicalIndex) {
                    if (index < flattened.length) {
                        const element = flattened[index];
                        if (element)
                            markEscapedValue(element, depth + 1);
                    }
                }
                else
                    escapeIndexIncomplete = true;
            }
            else
                escapeIndexIncomplete = true;
        }
        else if (typescript_1.default.isBinaryExpression(value)) {
            const state = staticState(value.left);
            if (value.operatorToken.kind === typescript_1.default.SyntaxKind.AmpersandAmpersandToken) {
                if (state.truthy !== false)
                    markEscapedValue(value.right, depth + 1);
                if (state.truthy !== true)
                    markEscapedValue(value.left, depth + 1);
            }
            else if (value.operatorToken.kind === typescript_1.default.SyntaxKind.BarBarToken) {
                if (state.truthy !== true)
                    markEscapedValue(value.right, depth + 1);
                if (state.truthy !== false)
                    markEscapedValue(value.left, depth + 1);
            }
            else if (value.operatorToken.kind === typescript_1.default.SyntaxKind.QuestionQuestionToken) {
                if (state.nullish !== false)
                    markEscapedValue(value.right, depth + 1);
                if (state.nullish !== true)
                    markEscapedValue(value.left, depth + 1);
            }
            else if (value.operatorToken.kind === typescript_1.default.SyntaxKind.CommaToken) {
                markEscapedValue(value.right, depth + 1);
            }
        }
        else if (typescript_1.default.isCallExpression(value)) {
            let callee = value.expression;
            while (typescript_1.default.isParenthesizedExpression(callee) || typescript_1.default.isAsExpression(callee)
                || typescript_1.default.isTypeAssertionExpression(callee) || typescript_1.default.isSatisfiesExpression(callee)
                || typescript_1.default.isNonNullExpression(callee))
                callee = callee.expression;
            let callable;
            let localCallReference = false;
            if (typescript_1.default.isArrowFunction(callee) || typescript_1.default.isFunctionExpression(callee))
                callable = callee;
            else if (typescript_1.default.isIdentifier(callee)) {
                const symbol = resolvedSymbolAt(callee, checker);
                localCallReference = symbol?.declarations?.some((declaration) => (projectSources.has(declaration.getSourceFile()))) ?? false;
                const declarations = symbol?.declarations?.filter((declaration) => typescript_1.default.isFunctionDeclaration(declaration) && declaration.body !== undefined
                    && projectSources.has(declaration.getSourceFile())) ?? [];
                if (declarations.length === 1 && symbol && !reassignedSymbols.has(symbol))
                    callable = declarations[0];
            }
            else if (typescript_1.default.isPropertyAccessExpression(callee) || typescript_1.default.isElementAccessExpression(callee)) {
                const symbol = symbolAt(typescript_1.default.isPropertyAccessExpression(callee) ? callee.name : callee);
                const receiver = rootSymbolAt(callee.expression);
                const declarations = symbol?.declarations?.filter((declaration) => (projectSources.has(declaration.getSourceFile()) && (typescript_1.default.isMethodDeclaration(declaration)
                    || typescript_1.default.isPropertyAssignment(declaration)))) ?? [];
                localCallReference = declarations.length > 0;
                const unstable = (symbol && (reassignedSymbols.has(symbol)
                    || unresolvedAssignments.has(symbol) || assignedValues.has(symbol)))
                    || (receiver && (aliasSetHas(escapedSymbols, receiver)
                        || aliasSetHas(unstableContainers, receiver)));
                if (declarations.length === 1 && !unstable) {
                    const declaration = declarations[0];
                    const candidate = typescript_1.default.isMethodDeclaration(declaration) ? declaration
                        : typescript_1.default.isPropertyAssignment(declaration) ? declaration.initializer : undefined;
                    if (candidate && (typescript_1.default.isArrowFunction(candidate) || typescript_1.default.isFunctionExpression(candidate))) {
                        callable = candidate;
                    }
                    else if (candidate && typescript_1.default.isMethodDeclaration(candidate) && candidate.body)
                        callable = candidate;
                }
            }
            if (!callable?.body) {
                if (localCallReference)
                    escapeIndexIncomplete = true;
            }
            else if (callable.modifiers?.some(({ kind }) => kind === typescript_1.default.SyntaxKind.AsyncKeyword)
                || ('asteriskToken' in callable && callable.asteriskToken)) {
                // Async and generator calls expose a Promise/iterator, not the returned object itself.
            }
            else if (callable.parameters.length > 0 || value.arguments.length > 0) {
                escapeIndexIncomplete = true;
            }
            else if (!typescript_1.default.isBlock(callable.body))
                markEscapedValue(callable.body, depth + 1);
            else {
                let foundReturn = false;
                const nodes = [...callable.body.statements];
                while (nodes.length > 0) {
                    check();
                    const node = nodes.pop();
                    if (typescript_1.default.isReturnStatement(node) && node.expression) {
                        foundReturn = true;
                        markEscapedValue(node.expression, depth + 1);
                    }
                    else if (!typescript_1.default.isFunctionLike(node))
                        typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
                }
                if (!foundReturn)
                    escapeIndexIncomplete = true;
            }
        }
    };
    const markMutatedReceiver = (input, depth = 0) => {
        check();
        if (depth > 64)
            return;
        let receiver = input;
        while (typescript_1.default.isParenthesizedExpression(receiver) || typescript_1.default.isAsExpression(receiver)
            || typescript_1.default.isTypeAssertionExpression(receiver) || typescript_1.default.isSatisfiesExpression(receiver)
            || typescript_1.default.isNonNullExpression(receiver))
            receiver = receiver.expression;
        if (typescript_1.default.isArrayLiteralExpression(receiver) || typescript_1.default.isObjectLiteralExpression(receiver)) {
            mutatedContainerExpressions.add(receiver);
            return;
        }
        if (typescript_1.default.isIdentifier(receiver)) {
            const symbol = resolvedSymbolAt(receiver, checker);
            if (symbol)
                mutatedContainers.add(symbol);
            return;
        }
        if (!typescript_1.default.isPropertyAccessExpression(receiver) && !typescript_1.default.isElementAccessExpression(receiver))
            return;
        const propertyName = typescript_1.default.isPropertyAccessExpression(receiver) ? receiver.name.text
            : receiver.argumentExpression
                ? (0, decorator_symbols_1.resolveStaticPropertyKey)(receiver.argumentExpression, checker, check) : undefined;
        const object = resolveConstObject(receiver.expression, checker, projectSources, check);
        if (propertyName === undefined || !object)
            return;
        const effective = effectiveObjectProperty(object, propertyName, checker, projectSources, check);
        for (const candidate of effective.candidates)
            markMutatedReceiver(candidate, depth + 1);
    };
    const indexNodes = [...projectSources];
    while (indexNodes.length > 0) {
        check();
        const node = indexNodes.pop();
        if (typescript_1.default.isBinaryExpression(node) && !isNestedDestructuringDefault(node)
            && node.operatorToken.kind >= typescript_1.default.SyntaxKind.FirstAssignment
            && node.operatorToken.kind <= typescript_1.default.SyntaxKind.LastAssignment) {
            markAssignmentTarget(node.left);
            const symbol = directAssignmentSymbol(node.left);
            if (symbol) {
                if (node.operatorToken.kind === typescript_1.default.SyntaxKind.EqualsToken) {
                    (assignedValues.get(symbol) ?? assignedValues.set(symbol, []).get(symbol)).push(node.right);
                }
                else
                    unresolvedAssignments.add(symbol);
            }
            if (node.operatorToken.kind === typescript_1.default.SyntaxKind.EqualsToken) {
                let target = node.left;
                while (typescript_1.default.isParenthesizedExpression(target) || typescript_1.default.isAsExpression(target)
                    || typescript_1.default.isTypeAssertionExpression(target) || typescript_1.default.isSatisfiesExpression(target)
                    || typescript_1.default.isNonNullExpression(target))
                    target = target.expression;
                if (typescript_1.default.isIdentifier(target)) {
                    const alias = symbolAt(target);
                    let value = node.right;
                    while (typescript_1.default.isParenthesizedExpression(value) || typescript_1.default.isAsExpression(value)
                        || typescript_1.default.isTypeAssertionExpression(value) || typescript_1.default.isSatisfiesExpression(value)
                        || typescript_1.default.isNonNullExpression(value))
                        value = value.expression;
                    if (typescript_1.default.isIdentifier(value))
                        linkAliases(alias, symbolAt(value));
                    else if (typescript_1.default.isPropertyAccessExpression(value) || typescript_1.default.isElementAccessExpression(value)) {
                        linkAliases(alias, symbolAt(typescript_1.default.isPropertyAccessExpression(value) ? value.name : value));
                        const key = typescript_1.default.isPropertyAccessExpression(value) ? value.name.text
                            : value.argumentExpression
                                ? (0, decorator_symbols_1.resolveStaticPropertyKey)(value.argumentExpression, checker, check) : undefined;
                        if (key === 'imports' || (key === undefined && typescript_1.default.isElementAccessExpression(value))) {
                            linkAliases(alias, rootSymbolAt(value.expression));
                        }
                        if (key === undefined && typescript_1.default.isElementAccessExpression(value)) {
                            linkDynamicElementCandidates(alias, value.expression);
                        }
                    }
                }
            }
        }
        else if (typescript_1.default.isForOfStatement(node) || typescript_1.default.isForInStatement(node)) {
            markAssignmentTarget(node.initializer);
            if (typescript_1.default.isExpression(node.initializer)) {
                const symbol = directAssignmentSymbol(node.initializer);
                if (symbol)
                    unresolvedAssignments.add(symbol);
            }
        }
        else if (typescript_1.default.isVariableDeclaration(node) && typescript_1.default.isIdentifier(node.name) && node.initializer) {
            const alias = symbolAt(node.name);
            let value = node.initializer;
            while (typescript_1.default.isParenthesizedExpression(value) || typescript_1.default.isAsExpression(value)
                || typescript_1.default.isTypeAssertionExpression(value) || typescript_1.default.isSatisfiesExpression(value)
                || typescript_1.default.isNonNullExpression(value))
                value = value.expression;
            if (typescript_1.default.isIdentifier(value))
                linkAliases(alias, symbolAt(value));
            else if (typescript_1.default.isPropertyAccessExpression(value) || typescript_1.default.isElementAccessExpression(value)) {
                linkAliases(alias, symbolAt(typescript_1.default.isPropertyAccessExpression(value) ? value.name : value));
                const key = typescript_1.default.isPropertyAccessExpression(value) ? value.name.text
                    : value.argumentExpression
                        ? (0, decorator_symbols_1.resolveStaticPropertyKey)(value.argumentExpression, checker, check) : undefined;
                if (key === 'imports' || (key === undefined && typescript_1.default.isElementAccessExpression(value))) {
                    linkAliases(alias, rootSymbolAt(value.expression));
                }
                if (key === undefined && typescript_1.default.isElementAccessExpression(value)) {
                    linkDynamicElementCandidates(alias, value.expression);
                }
            }
        }
        else if (typescript_1.default.isVariableDeclaration(node) && typescript_1.default.isObjectBindingPattern(node.name)
            && node.initializer) {
            for (const element of node.name.elements) {
                if (!typescript_1.default.isIdentifier(element.name))
                    continue;
                const key = element.propertyName
                    ? typescript_1.default.isIdentifier(element.propertyName) || typescript_1.default.isStringLiteral(element.propertyName)
                        ? element.propertyName.text
                        : typescript_1.default.isComputedPropertyName(element.propertyName)
                            ? (0, decorator_symbols_1.resolveStaticPropertyKey)(element.propertyName.expression, checker, check) : undefined
                    : element.name.text;
                const alias = symbolAt(element.name);
                if (key === undefined) {
                    linkAliases(alias, rootSymbolAt(node.initializer));
                    continue;
                }
                if (key !== 'imports')
                    continue;
                let propertyMayBeSelected = true;
                let defaultMayBeSelected = Boolean(element.initializer);
                if (element.initializer) {
                    const object = resolveConstObject(node.initializer, checker, projectSources, check);
                    if (object) {
                        const property = effectiveObjectProperty(object, 'imports', checker, projectSources, check);
                        propertyMayBeSelected = property.present && (property.accessor
                            || property.candidates.length === 0 || property.candidates.some((candidate) => (staticUndefinedState(candidate, checker, projectSources, check) !== true)));
                        defaultMayBeSelected = !property.present || property.accessor
                            || property.candidates.length === 0 || property.candidates.some((candidate) => (staticUndefinedState(candidate, checker, projectSources, check) !== false));
                    }
                }
                if (propertyMayBeSelected) {
                    linkAliases(alias, checker.getNonNullableType(checker.getTypeAtLocation(node.initializer)).getProperty('imports'));
                    linkAliases(alias, rootSymbolAt(node.initializer));
                }
                if (defaultMayBeSelected && element.initializer) {
                    const fallbacks = [element.initializer];
                    const seenFallbacks = new Set();
                    let fallbackSteps = 0;
                    while (fallbacks.length > 0) {
                        if (fallbackSteps++ >= 64) {
                            if (alias)
                                unresolvedImportDefaultAliases.add(alias);
                            break;
                        }
                        let fallback = fallbacks.pop();
                        while (typescript_1.default.isParenthesizedExpression(fallback) || typescript_1.default.isAsExpression(fallback)
                            || typescript_1.default.isTypeAssertionExpression(fallback) || typescript_1.default.isSatisfiesExpression(fallback)
                            || typescript_1.default.isNonNullExpression(fallback))
                            fallback = fallback.expression;
                        if (typescript_1.default.isIdentifier(fallback)) {
                            const symbol = symbolAt(fallback);
                            linkAliases(alias, symbol);
                            if (!symbol || seenFallbacks.has(symbol))
                                continue;
                            seenFallbacks.add(symbol);
                            const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
                            const declaration = declarations.length === 1 ? declarations[0] : undefined;
                            if (declaration?.initializer && projectSources.has(declaration.getSourceFile())
                                && typescript_1.default.isVariableDeclarationList(declaration.parent)
                                && declaration.parent.flags & typescript_1.default.NodeFlags.Const) {
                                fallbacks.push(declaration.initializer);
                            }
                            continue;
                        }
                        if (typescript_1.default.isPropertyAccessExpression(fallback) || typescript_1.default.isElementAccessExpression(fallback)) {
                            const fallbackKey = typescript_1.default.isPropertyAccessExpression(fallback) ? fallback.name.text
                                : fallback.argumentExpression
                                    ? (0, decorator_symbols_1.resolveStaticPropertyKey)(fallback.argumentExpression, checker, check) : undefined;
                            if (fallbackKey === 'imports') {
                                linkAliases(alias, symbolAt(typescript_1.default.isPropertyAccessExpression(fallback) ? fallback.name : fallback));
                                linkAliases(alias, rootSymbolAt(fallback.expression));
                                const object = resolveConstObject(fallback.expression, checker, projectSources, check);
                                if (object) {
                                    const property = effectiveObjectProperty(object, 'imports', checker, projectSources, check);
                                    fallbacks.push(...property.candidates);
                                    if ((!property.present || property.accessor
                                        || property.candidates.length === 0) && alias) {
                                        unresolvedImportDefaultAliases.add(alias);
                                    }
                                }
                                else if (alias) {
                                    unresolvedImportDefaultAliases.add(alias);
                                }
                            }
                            else if (fallbackKey === undefined && alias)
                                unresolvedImportDefaultAliases.add(alias);
                            continue;
                        }
                        if (typescript_1.default.isConditionalExpression(fallback)) {
                            const state = staticState(fallback.condition);
                            if (state.truthy !== false)
                                fallbacks.push(fallback.whenTrue);
                            if (state.truthy !== true)
                                fallbacks.push(fallback.whenFalse);
                            continue;
                        }
                        if (typescript_1.default.isBinaryExpression(fallback)) {
                            const operator = fallback.operatorToken.kind;
                            if (operator === typescript_1.default.SyntaxKind.CommaToken) {
                                fallbacks.push(fallback.right);
                                continue;
                            }
                            const state = staticState(fallback.left);
                            if (operator === typescript_1.default.SyntaxKind.AmpersandAmpersandToken) {
                                if (state.truthy !== true)
                                    fallbacks.push(fallback.left);
                                if (state.truthy !== false)
                                    fallbacks.push(fallback.right);
                                continue;
                            }
                            if (operator === typescript_1.default.SyntaxKind.BarBarToken) {
                                if (state.truthy !== false)
                                    fallbacks.push(fallback.left);
                                if (state.truthy !== true)
                                    fallbacks.push(fallback.right);
                                continue;
                            }
                            if (operator === typescript_1.default.SyntaxKind.QuestionQuestionToken) {
                                if (state.nullish !== true)
                                    fallbacks.push(fallback.left);
                                if (state.nullish !== false)
                                    fallbacks.push(fallback.right);
                                continue;
                            }
                        }
                        if (!typescript_1.default.isArrayLiteralExpression(fallback) && alias) {
                            unresolvedImportDefaultAliases.add(alias);
                        }
                    }
                }
            }
        }
        else if (typescript_1.default.isCallExpression(node)) {
            let localCallee = node.expression;
            while (typescript_1.default.isParenthesizedExpression(localCallee) || typescript_1.default.isAsExpression(localCallee)
                || typescript_1.default.isTypeAssertionExpression(localCallee) || typescript_1.default.isSatisfiesExpression(localCallee)
                || typescript_1.default.isNonNullExpression(localCallee))
                localCallee = localCallee.expression;
            if (typescript_1.default.isIdentifier(localCallee)) {
                const symbol = symbolAt(localCallee);
                const callables = [];
                const callableSymbols = new Set();
                let callableResolutionComplete = true;
                const collectCallables = (candidate, depth = 0) => {
                    if (!candidate || depth >= 64) {
                        callableResolutionComplete = false;
                        return;
                    }
                    if (callableSymbols.has(candidate))
                        return;
                    callableSymbols.add(candidate);
                    if (reassignedSymbols.has(candidate) || unresolvedAssignments.has(candidate)
                        || assignedValues.has(candidate))
                        callableResolutionComplete = false;
                    for (const declaration of candidate.declarations ?? []) {
                        if (!projectSources.has(declaration.getSourceFile()))
                            continue;
                        if (typescript_1.default.isFunctionDeclaration(declaration) && declaration.body)
                            callables.push(declaration);
                        if (!typescript_1.default.isVariableDeclaration(declaration) || !declaration.initializer)
                            continue;
                        if (!typescript_1.default.isVariableDeclarationList(declaration.parent)
                            || !(declaration.parent.flags & typescript_1.default.NodeFlags.Const))
                            callableResolutionComplete = false;
                        let initializer = declaration.initializer;
                        while (typescript_1.default.isParenthesizedExpression(initializer) || typescript_1.default.isAsExpression(initializer)
                            || typescript_1.default.isTypeAssertionExpression(initializer) || typescript_1.default.isSatisfiesExpression(initializer)
                            || typescript_1.default.isNonNullExpression(initializer))
                            initializer = initializer.expression;
                        if (typescript_1.default.isArrowFunction(initializer)
                            || typescript_1.default.isFunctionExpression(initializer))
                            callables.push(initializer);
                        else if (typescript_1.default.isIdentifier(initializer)
                            && typescript_1.default.isVariableDeclarationList(declaration.parent)
                            && declaration.parent.flags & typescript_1.default.NodeFlags.Const) {
                            collectCallables(symbolAt(initializer), depth + 1);
                        }
                        else
                            callableResolutionComplete = false;
                    }
                };
                collectCallables(symbol);
                if (!callableResolutionComplete) {
                    for (const argument of node.arguments) {
                        const nodes = [argument];
                        const seenSymbols = new Set();
                        while (nodes.length > 0) {
                            const candidate = nodes.pop();
                            const importsAccess = (typescript_1.default.isPropertyAccessExpression(candidate)
                                && candidate.name.text === 'imports') || (typescript_1.default.isElementAccessExpression(candidate)
                                && candidate.argumentExpression
                                && (0, decorator_symbols_1.resolveStaticPropertyKey)(candidate.argumentExpression, checker, check) === 'imports');
                            if (importsAccess && (typescript_1.default.isPropertyAccessExpression(candidate)
                                || typescript_1.default.isElementAccessExpression(candidate))) {
                                const member = symbolAt(typescript_1.default.isPropertyAccessExpression(candidate)
                                    ? candidate.name : candidate);
                                const root = rootSymbolAt(candidate.expression);
                                if (member)
                                    incompleteLocalCallImportSymbols.add(member);
                                if (root)
                                    incompleteLocalCallImportSymbols.add(root);
                                continue;
                            }
                            if (typescript_1.default.isIdentifier(candidate)) {
                                const candidateSymbol = symbolAt(candidate);
                                if (candidateSymbol && !seenSymbols.has(candidateSymbol)) {
                                    seenSymbols.add(candidateSymbol);
                                    for (const declaration of candidateSymbol.declarations ?? []) {
                                        if (typescript_1.default.isVariableDeclaration(declaration) && declaration.initializer
                                            && projectSources.has(declaration.getSourceFile()))
                                            nodes.push(declaration.initializer);
                                    }
                                }
                            }
                            typescript_1.default.forEachChild(candidate, (child) => { nodes.push(child); });
                        }
                    }
                }
                if (callables.length === 1) {
                    const actualArguments = [];
                    let argumentsComplete = true;
                    const flattenSpread = (input, depth = 0) => {
                        if (depth >= 64)
                            return false;
                        let expression = input;
                        while (typescript_1.default.isParenthesizedExpression(expression) || typescript_1.default.isAsExpression(expression)
                            || typescript_1.default.isTypeAssertionExpression(expression) || typescript_1.default.isSatisfiesExpression(expression)
                            || typescript_1.default.isNonNullExpression(expression))
                            expression = expression.expression;
                        if (typescript_1.default.isIdentifier(expression)) {
                            const symbol = symbolAt(expression);
                            const declarations = symbol?.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
                            const declaration = declarations.length === 1 ? declarations[0] : undefined;
                            if (!declaration?.initializer || !projectSources.has(declaration.getSourceFile())
                                || !typescript_1.default.isVariableDeclarationList(declaration.parent)
                                || !(declaration.parent.flags & typescript_1.default.NodeFlags.Const))
                                return false;
                            return flattenSpread(declaration.initializer, depth + 1);
                        }
                        if (!typescript_1.default.isArrayLiteralExpression(expression))
                            return false;
                        for (const element of expression.elements) {
                            if (typescript_1.default.isOmittedExpression(element))
                                actualArguments.push(element);
                            else if (typescript_1.default.isSpreadElement(element)) {
                                if (!flattenSpread(element.expression, depth + 1))
                                    return false;
                            }
                            else
                                actualArguments.push(element);
                        }
                        return true;
                    };
                    for (const argument of node.arguments) {
                        if (typescript_1.default.isSpreadElement(argument)) {
                            if (!flattenSpread(argument.expression))
                                argumentsComplete = false;
                        }
                        else
                            actualArguments.push(argument);
                    }
                    for (const [index, parameter] of callables[0].parameters.entries()) {
                        if (!typescript_1.default.isIdentifier(parameter.name))
                            continue;
                        const parameterSymbol = symbolAt(parameter.name);
                        if (!argumentsComplete && parameterSymbol)
                            unresolvedSpreadParameters.add(parameterSymbol);
                        const actual = actualArguments[index];
                        const undefinedState = actual
                            ? staticUndefinedState(actual, checker, projectSources, check) : true;
                        const values = [
                            ...(actual && undefinedState !== true ? [actual] : []),
                            ...(parameter.initializer && undefinedState !== false ? [parameter.initializer] : []),
                        ];
                        for (let value of values) {
                            while (typescript_1.default.isParenthesizedExpression(value) || typescript_1.default.isAsExpression(value)
                                || typescript_1.default.isTypeAssertionExpression(value) || typescript_1.default.isSatisfiesExpression(value)
                                || typescript_1.default.isNonNullExpression(value))
                                value = value.expression;
                            if (typescript_1.default.isIdentifier(value))
                                linkAliases(parameterSymbol, symbolAt(value));
                            else if (typescript_1.default.isPropertyAccessExpression(value) || typescript_1.default.isElementAccessExpression(value)) {
                                linkAliases(parameterSymbol, symbolAt(typescript_1.default.isPropertyAccessExpression(value) ? value.name : value));
                                const key = typescript_1.default.isPropertyAccessExpression(value) ? value.name.text
                                    : value.argumentExpression
                                        ? (0, decorator_symbols_1.resolveStaticPropertyKey)(value.argumentExpression, checker, check) : undefined;
                                if (key === 'imports')
                                    linkAliases(parameterSymbol, rootSymbolAt(value.expression));
                            }
                        }
                    }
                }
            }
            const decorator = typescript_1.default.isDecorator(node.parent)
                ? (0, decorator_symbols_1.resolveDecoratorSymbol)(node.parent, checker, check) : undefined;
            if (decorator?.name !== 'Module' || !decorator.nestJsCommon) {
                for (const argument of node.arguments) {
                    const value = typescript_1.default.isSpreadElement(argument) ? argument.expression : argument;
                    pendingEscapes.push(value);
                }
            }
            const access = typescript_1.default.isPropertyAccessExpression(node.expression)
                || typescript_1.default.isElementAccessExpression(node.expression) ? node.expression : undefined;
            const method = access && (typescript_1.default.isPropertyAccessExpression(access) ? access.name.text
                : access.argumentExpression
                    ? (0, decorator_symbols_1.resolveStaticPropertyKey)(access.argumentExpression, checker, check) : undefined);
            const memberSymbol = access && symbolAt(typescript_1.default.isPropertyAccessExpression(access)
                ? access.name : access);
            let localCallMayMutateReceiver = memberSymbol
                ? memberMutationCache.get(memberSymbol) : undefined;
            if (localCallMayMutateReceiver === undefined) {
                const localCallables = memberSymbol?.declarations?.filter((declaration) => (projectSources.has(declaration.getSourceFile()) && (typescript_1.default.isMethodDeclaration(declaration)
                    || typescript_1.default.isPropertyAssignment(declaration)))) ?? [];
                localCallMayMutateReceiver = localCallables.length === 0 || localCallables.some((declaration) => {
                    const callable = typescript_1.default.isMethodDeclaration(declaration) ? declaration
                        : typescript_1.default.isPropertyAssignment(declaration) ? declaration.initializer : undefined;
                    if (!callable || (!typescript_1.default.isMethodDeclaration(callable) && !typescript_1.default.isArrowFunction(callable)
                        && !typescript_1.default.isFunctionExpression(callable)) || !callable.body)
                        return true;
                    let usesThis = false;
                    const nodes = [callable.body];
                    while (nodes.length > 0 && !usesThis) {
                        const current = nodes.pop();
                        if (current.kind === typescript_1.default.SyntaxKind.ThisKeyword)
                            usesThis = true;
                        else if (current !== callable && typescript_1.default.isFunctionLike(current)
                            && !typescript_1.default.isArrowFunction(current))
                            continue;
                        else
                            typescript_1.default.forEachChild(current, (child) => { nodes.push(child); });
                    }
                    return usesThis;
                });
                if (memberSymbol)
                    memberMutationCache.set(memberSymbol, localCallMayMutateReceiver);
            }
            let callbackReadOnly = false;
            if (access && method && CALLBACK_ARRAY_METHODS.has(method)) {
                const callback = node.arguments[0];
                const callable = callback && (typescript_1.default.isArrowFunction(callback) || typescript_1.default.isFunctionExpression(callback))
                    ? callback : undefined;
                const receiver = rootSymbolAt(access.expression);
                const arrayParameterIndex = method === 'reduce' || method === 'reduceRight' ? 4 : 3;
                if (callable && callable.parameters.length < arrayParameterIndex
                    && !callable.parameters.some(({ dotDotDotToken }) => dotDotDotToken)) {
                    let referencesReceiver = false;
                    let referencesArguments = false;
                    let mutatesElement = false;
                    const elementParameter = callable.parameters[method === 'reduce' || method === 'reduceRight' ? 1 : 0];
                    const elementSymbol = elementParameter && typescript_1.default.isIdentifier(elementParameter.name)
                        ? symbolAt(elementParameter.name) : undefined;
                    const elementSymbols = new Set(elementSymbol ? [elementSymbol] : []);
                    let elementSteps = 0;
                    const elementCache = new WeakMap();
                    const isElementSymbol = (symbol) => (!!symbol && aliasSetHas(elementSymbols, symbol));
                    const containsElement = (input) => {
                        if (!elementSymbol)
                            return false;
                        const cached = elementCache.get(input);
                        if (cached !== undefined)
                            return cached;
                        const pending = [input];
                        while (pending.length > 0) {
                            check();
                            if (elementSteps++ >= MAX_PROVIDER_SPREAD_ELEMENTS)
                                return true;
                            const candidate = pending.pop();
                            if (typescript_1.default.isIdentifier(candidate)) {
                                const symbol = symbolAt(candidate);
                                if (isElementSymbol(symbol)) {
                                    elementCache.set(input, true);
                                    return true;
                                }
                            }
                            if (candidate !== input && ((typescript_1.default.isFunctionLike(candidate)
                                && !typescript_1.default.isArrowFunction(candidate)) || typescript_1.default.isClassLike(candidate)))
                                continue;
                            typescript_1.default.forEachChild(candidate, (child) => { pending.push(child); });
                        }
                        elementCache.set(input, false);
                        return false;
                    };
                    const targetMutatesElement = (input) => {
                        let target = input;
                        while (typescript_1.default.isParenthesizedExpression(target) || typescript_1.default.isAsExpression(target)
                            || typescript_1.default.isTypeAssertionExpression(target) || typescript_1.default.isSatisfiesExpression(target)
                            || typescript_1.default.isNonNullExpression(target))
                            target = target.expression;
                        if (typescript_1.default.isPropertyAccessExpression(target) || typescript_1.default.isElementAccessExpression(target)) {
                            return isElementSymbol(rootSymbolAt(target.expression));
                        }
                        if (typescript_1.default.isArrayLiteralExpression(target)) {
                            return target.elements.some((element) => !typescript_1.default.isOmittedExpression(element)
                                && targetMutatesElement(typescript_1.default.isSpreadElement(element) ? element.expression : element));
                        }
                        if (typescript_1.default.isObjectLiteralExpression(target)) {
                            return target.properties.some((property) => (typescript_1.default.isPropertyAssignment(property) ? targetMutatesElement(property.initializer)
                                : typescript_1.default.isShorthandPropertyAssignment(property) ? false
                                    : typescript_1.default.isSpreadAssignment(property) && targetMutatesElement(property.expression)));
                        }
                        if (typescript_1.default.isBinaryExpression(target)
                            && target.operatorToken.kind === typescript_1.default.SyntaxKind.EqualsToken) {
                            return targetMutatesElement(target.left);
                        }
                        return false;
                    };
                    const nodes = [callable.body];
                    while (nodes.length > 0 && !referencesReceiver && !referencesArguments && !mutatesElement) {
                        const current = nodes.pop();
                        if (typescript_1.default.isBinaryExpression(current) && elementSymbol
                            && current.operatorToken.kind >= typescript_1.default.SyntaxKind.FirstAssignment
                            && current.operatorToken.kind <= typescript_1.default.SyntaxKind.LastAssignment
                            && targetMutatesElement(current.left)) {
                            mutatesElement = true;
                        }
                        else if (((typescript_1.default.isPrefixUnaryExpression(current)
                            && (current.operator === typescript_1.default.SyntaxKind.PlusPlusToken
                                || current.operator === typescript_1.default.SyntaxKind.MinusMinusToken))
                            || typescript_1.default.isPostfixUnaryExpression(current))
                            && targetMutatesElement(current.operand)) {
                            mutatesElement = true;
                        }
                        else if (typescript_1.default.isDeleteExpression(current)
                            && targetMutatesElement(current.expression)) {
                            mutatesElement = true;
                        }
                        else if (typescript_1.default.isCallExpression(current) && elementSymbol) {
                            const access = typescript_1.default.isPropertyAccessExpression(current.expression)
                                || typescript_1.default.isElementAccessExpression(current.expression) ? current.expression : undefined;
                            const calledMethod = access && (typescript_1.default.isPropertyAccessExpression(access) ? access.name.text
                                : access.argumentExpression
                                    ? (0, decorator_symbols_1.resolveStaticPropertyKey)(access.argumentExpression, checker, check) : undefined);
                            if (access && isElementSymbol(rootSymbolAt(access.expression))
                                && (calledMethod === undefined || !READ_ONLY_ARRAY_METHODS.has(calledMethod))) {
                                mutatesElement = true;
                            }
                            else if (current.arguments.some((argument) => containsElement(typescript_1.default.isSpreadElement(argument) ? argument.expression : argument)))
                                mutatesElement = true;
                        }
                        else if (typescript_1.default.isTaggedTemplateExpression(current) && elementSymbol
                            && typescript_1.default.isTemplateExpression(current.template)
                            && current.template.templateSpans.some(({ expression }) => containsElement(expression))) {
                            mutatesElement = true;
                        }
                        else if (typescript_1.default.isIdentifier(current) && receiver
                            && resolvedSymbolAt(current, checker) === receiver)
                            referencesReceiver = true;
                        else if (typescript_1.default.isFunctionExpression(callable) && typescript_1.default.isIdentifier(current)
                            && current.text === 'arguments') {
                            const parent = current.parent;
                            const declarationName = 'name' in parent && parent.name === current
                                && !typescript_1.default.isShorthandPropertyAssignment(parent);
                            const bindingKey = typescript_1.default.isBindingElement(parent) && parent.propertyName === current;
                            const accessName = typescript_1.default.isPropertyAccessExpression(parent) && parent.name === current;
                            const label = (typescript_1.default.isLabeledStatement(parent) || typescript_1.default.isBreakStatement(parent)
                                || typescript_1.default.isContinueStatement(parent)) && parent.label === current;
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
                            const argumentSymbol = checker.getSymbolAtLocation(current);
                            const shadowed = argumentSymbol?.declarations?.some((declaration) => (declaration.getSourceFile() === callable.getSourceFile()
                                && declaration.pos >= callable.pos && declaration.end <= callable.end)) ?? false;
                            referencesArguments = !declarationName && !bindingKey && !accessName && !label
                                && !qualifiedName && !typeOnly && !shadowed;
                        }
                        else if (current !== callable && typescript_1.default.isFunctionLike(current)
                            && !typescript_1.default.isArrowFunction(current))
                            continue;
                        else
                            typescript_1.default.forEachChild(current, (child) => { nodes.push(child); });
                    }
                    callbackReadOnly = !referencesReceiver && !referencesArguments && !mutatesElement;
                }
            }
            if (access && (method === undefined || (!READ_ONLY_ARRAY_METHODS.has(method)
                && !callbackReadOnly))
                && localCallMayMutateReceiver) {
                markMutatedReceiver(access.expression);
            }
        }
        typescript_1.default.forEachChild(node, (child) => { indexNodes.push(child); });
    }
    let previousEscapedCount = -1;
    let escapeRounds = 0;
    while (escapedSymbols.size !== previousEscapedCount) {
        check();
        if (escapeRounds++ >= MAX_PROVIDER_SPREAD_ELEMENTS
            || escapeSteps >= MAX_PROVIDER_SPREAD_ELEMENTS) {
            escapeIndexIncomplete = true;
            escapeIndexLimitExceeded = true;
            break;
        }
        previousEscapedCount = escapedSymbols.size;
        for (const value of pendingEscapes) {
            markEscapedValue(value);
            if (escapeSteps >= MAX_PROVIDER_SPREAD_ELEMENTS) {
                escapeIndexIncomplete = true;
                escapeIndexLimitExceeded = true;
                break;
            }
        }
    }
    const unstableSymbols = new Set([...reassignedSymbols, ...escapedSymbols]);
    const pendingUnstable = [...unstableSymbols];
    while (pendingUnstable.length > 0) {
        const symbol = pendingUnstable.pop();
        for (const alias of aliases.get(symbol) ?? []) {
            if (!unstableSymbols.has(alias)) {
                unstableSymbols.add(alias);
                pendingUnstable.push(alias);
            }
        }
    }
    const unstableContainers = new Set(mutatedContainers);
    const pendingContainers = [...unstableContainers];
    while (pendingContainers.length > 0) {
        const symbol = pendingContainers.pop();
        for (const alias of aliases.get(symbol) ?? []) {
            if (!unstableContainers.has(alias)) {
                unstableContainers.add(alias);
                pendingContainers.push(alias);
            }
        }
    }
    const containersWithAssignedImports = new Set([...propertyAssignedContainers]
        .filter(([, keys]) => keys.has('imports') || keys.has('*'))
        .map(([symbol]) => symbol));
    const unresolvedImportDefaultMutation = [...unresolvedImportDefaultAliases].some((symbol) => (aliasSetHas(unstableContainers, symbol) || aliasSetHas(escapedSymbols, symbol)));
    const unresolvedParameterSpreadMutation = [...unresolvedSpreadParameters].some((symbol) => (aliasSetHas(unstableContainers, symbol) || aliasSetHas(escapedSymbols, symbol)));
    const unresolvedDynamicAliasMutation = [...incompleteDynamicAliases].some((symbol) => (aliasSetHas(unstableContainers, symbol) || aliasSetHas(escapedSymbols, symbol)));
    const mutatedDynamicExpressions = new Set();
    for (const [symbol, expressions] of dynamicAliasExpressions) {
        if (aliasSetHas(unstableContainers, symbol) || aliasSetHas(escapedSymbols, symbol)) {
            for (const expression of expressions)
                mutatedDynamicExpressions.add(expression);
        }
    }
    const isExternalProviderReference = (input, seen = new Set(), depth = 0, tokenPosition = false) => {
        check();
        if (depth > 64)
            return true;
        let expression = input;
        while (typescript_1.default.isParenthesizedExpression(expression) || typescript_1.default.isAsExpression(expression)
            || typescript_1.default.isTypeAssertionExpression(expression) || typescript_1.default.isSatisfiesExpression(expression)
            || typescript_1.default.isNonNullExpression(expression))
            expression = expression.expression;
        if (typescript_1.default.isArrayLiteralExpression(expression)) {
            return expression.elements.some((element) => !typescript_1.default.isOmittedExpression(element)
                && isExternalProviderReference(typescript_1.default.isSpreadElement(element) ? element.expression : element, new Set(seen), depth + 1, tokenPosition));
        }
        if (typescript_1.default.isObjectLiteralExpression(expression)) {
            const provide = effectiveObjectProperty(expression, 'provide', checker, projectSources, check);
            return provide.candidates.some((candidate) => isExternalProviderReference(candidate, new Set(seen), depth + 1, true));
        }
        if (typescript_1.default.isConditionalExpression(expression)) {
            const condition = staticState(expression.condition);
            return (condition.truthy !== false
                && isExternalProviderReference(expression.whenTrue, new Set(seen), depth + 1, tokenPosition))
                || (condition.truthy !== true
                    && isExternalProviderReference(expression.whenFalse, new Set(seen), depth + 1, tokenPosition));
        }
        if (typescript_1.default.isBinaryExpression(expression)) {
            const left = staticState(expression.left);
            if (expression.operatorToken.kind === typescript_1.default.SyntaxKind.AmpersandAmpersandToken) {
                if (left.truthy === false)
                    return false;
                if (left.truthy === true) {
                    return isExternalProviderReference(expression.right, seen, depth + 1, tokenPosition);
                }
            }
            else if (expression.operatorToken.kind === typescript_1.default.SyntaxKind.BarBarToken) {
                if (left.truthy === true)
                    return false;
                if (left.truthy === false) {
                    return isExternalProviderReference(expression.right, seen, depth + 1, tokenPosition);
                }
            }
            else if (expression.operatorToken.kind === typescript_1.default.SyntaxKind.QuestionQuestionToken) {
                if (left.nullish === false)
                    return false;
                if (left.nullish === true) {
                    return isExternalProviderReference(expression.right, seen, depth + 1, tokenPosition);
                }
            }
            return isExternalProviderReference(expression.left, new Set(seen), depth + 1, tokenPosition)
                || isExternalProviderReference(expression.right, new Set(seen), depth + 1, tokenPosition);
        }
        if (typescript_1.default.isCallExpression(expression)) {
            if (expression.arguments.some((argument) => isExternalProviderReference(typescript_1.default.isSpreadElement(argument) ? argument.expression : argument, new Set(seen), depth + 1, tokenPosition)))
                return true;
            let callee = expression.expression;
            while (typescript_1.default.isParenthesizedExpression(callee))
                callee = callee.expression;
            if ((typescript_1.default.isPropertyAccessExpression(callee) || typescript_1.default.isElementAccessExpression(callee))) {
                const invocation = typescript_1.default.isPropertyAccessExpression(callee) ? callee.name.text
                    : callee.argumentExpression
                        ? (0, decorator_symbols_1.resolveStaticPropertyKey)(callee.argumentExpression, checker, check) : undefined;
                if (invocation === 'call' || invocation === 'apply' || invocation === 'bind') {
                    callee = callee.expression;
                }
            }
            const calleeAliases = new Set();
            while (typescript_1.default.isIdentifier(callee)) {
                let alias = checker.getSymbolAtLocation(callee);
                if (alias?.flags && alias.flags & typescript_1.default.SymbolFlags.Alias)
                    alias = checker.getAliasedSymbol(alias);
                if (!alias || calleeAliases.has(alias))
                    break;
                calleeAliases.add(alias);
                const declarations = alias.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
                const declaration = declarations.length === 1 ? declarations[0] : undefined;
                if (!declaration?.initializer || !projectSources.has(declaration.getSourceFile())
                    || !typescript_1.default.isVariableDeclarationList(declaration.parent)
                    || !(declaration.parent.flags & typescript_1.default.NodeFlags.Const))
                    break;
                callee = declaration.initializer;
                while (typescript_1.default.isParenthesizedExpression(callee) || typescript_1.default.isAsExpression(callee)
                    || typescript_1.default.isTypeAssertionExpression(callee) || typescript_1.default.isSatisfiesExpression(callee)
                    || typescript_1.default.isNonNullExpression(callee))
                    callee = callee.expression;
            }
            if (typescript_1.default.isArrowFunction(callee) || typescript_1.default.isFunctionExpression(callee)) {
                if (!tokenPosition && callee.parameters.length > 0)
                    return true;
                if (!typescript_1.default.isBlock(callee.body)) {
                    return isExternalProviderReference(callee.body, new Set(seen), depth + 1, tokenPosition);
                }
                const nodes = [...callee.body.statements];
                while (nodes.length > 0) {
                    check();
                    const node = nodes.pop();
                    if (typescript_1.default.isReturnStatement(node) && node.expression
                        && isExternalProviderReference(node.expression, new Set(seen), depth + 1, tokenPosition))
                        return true;
                    if (!typescript_1.default.isFunctionLike(node))
                        typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
                }
                return false;
            }
            if (isExternalProviderReference(callee, seen, depth + 1, tokenPosition))
                return true;
            let symbol = checker.getSymbolAtLocation(callee);
            if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
                symbol = checker.getAliasedSymbol(symbol);
            if (symbol?.declarations?.some((declaration) => (declaration.getSourceFile().fileName.replaceAll('\\', '/').includes('/node_modules/'))))
                return true;
            const functionReturnsExternal = (callable) => {
                if (!callable.body)
                    return false;
                if (!typescript_1.default.isBlock(callable.body)) {
                    return isExternalProviderReference(callable.body, new Set(seen), depth + 1, tokenPosition);
                }
                const nodes = [...callable.body.statements];
                while (nodes.length > 0) {
                    check();
                    const node = nodes.pop();
                    if (typescript_1.default.isReturnStatement(node) && node.expression
                        && isExternalProviderReference(node.expression, new Set(seen), depth + 1, tokenPosition))
                        return true;
                    if (!typescript_1.default.isFunctionLike(node))
                        typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
                }
                return false;
            };
            if (symbol && unstableSymbols.has(symbol))
                return true;
            let resolvedLocalCallable = false;
            const localDeclarations = (symbol?.declarations ?? []).filter((declaration) => (projectSources.has(declaration.getSourceFile())));
            const functionDeclarations = localDeclarations.filter(typescript_1.default.isFunctionDeclaration);
            if (functionDeclarations.length > 0) {
                const implementations = functionDeclarations.filter((declaration) => declaration.body);
                if (implementations.length !== 1)
                    return true;
                if (!tokenPosition && implementations[0].parameters.length > 0)
                    return true;
                resolvedLocalCallable = true;
                if (functionReturnsExternal(implementations[0]))
                    return true;
            }
            const methodDeclarations = localDeclarations.filter(typescript_1.default.isMethodDeclaration);
            if (methodDeclarations.length > 0) {
                if (!tokenPosition || methodDeclarations.length !== 1 || !methodDeclarations[0].body)
                    return true;
                resolvedLocalCallable = true;
                if (functionReturnsExternal(methodDeclarations[0]))
                    return true;
            }
            for (const declaration of localDeclarations) {
                if (typescript_1.default.isFunctionDeclaration(declaration) || typescript_1.default.isMethodDeclaration(declaration))
                    continue;
                if (typescript_1.default.isVariableDeclaration(declaration) || typescript_1.default.isPropertyAssignment(declaration)) {
                    if (!declaration.initializer)
                        return true;
                    let initializer = declaration.initializer;
                    while (typescript_1.default.isParenthesizedExpression(initializer) || typescript_1.default.isAsExpression(initializer)
                        || typescript_1.default.isTypeAssertionExpression(initializer) || typescript_1.default.isSatisfiesExpression(initializer)
                        || typescript_1.default.isNonNullExpression(initializer))
                        initializer = initializer.expression;
                    if (!typescript_1.default.isArrowFunction(initializer) && !typescript_1.default.isFunctionExpression(initializer))
                        return true;
                    if (!tokenPosition && initializer.parameters.length > 0)
                        return true;
                    resolvedLocalCallable = true;
                    if (functionReturnsExternal(initializer))
                        return true;
                }
                else
                    return true;
            }
            return tokenPosition ? false : !resolvedLocalCallable;
        }
        if (typescript_1.default.isPropertyAccessExpression(expression) || typescript_1.default.isElementAccessExpression(expression)) {
            const propertyName = typescript_1.default.isPropertyAccessExpression(expression) ? expression.name.text
                : expression.argumentExpression
                    ? (0, decorator_symbols_1.resolveStaticPropertyKey)(expression.argumentExpression, checker, check) : undefined;
            const receiver = resolveConstObject(expression.expression, checker, projectSources, check);
            const memberSymbol = symbolAt(typescript_1.default.isPropertyAccessExpression(expression)
                ? expression.name : expression);
            let receiverExpression = expression.expression;
            while (typescript_1.default.isParenthesizedExpression(receiverExpression) || typescript_1.default.isAsExpression(receiverExpression)
                || typescript_1.default.isTypeAssertionExpression(receiverExpression) || typescript_1.default.isSatisfiesExpression(receiverExpression)
                || typescript_1.default.isNonNullExpression(receiverExpression))
                receiverExpression = receiverExpression.expression;
            const receiverSymbol = rootSymbolAt(receiverExpression);
            if (tokenPosition && (escapeIndexIncomplete
                || (memberSymbol && unresolvedAssignments.has(memberSymbol))
                || (receiverSymbol && (unstableSymbols.has(receiverSymbol)
                    || unstableContainers.has(receiverSymbol)))))
                return true;
            if (tokenPosition && memberSymbol && (assignedValues.get(memberSymbol) ?? []).some((value) => (isExternalProviderReference(value, new Set(seen), depth + 1, true))))
                return true;
            if (propertyName !== undefined && receiver) {
                const effective = effectiveObjectProperty(receiver, propertyName, checker, projectSources, check);
                if (effective.present) {
                    return effective.candidates.some((candidate) => (isExternalProviderReference(candidate, new Set(seen), depth + 1, tokenPosition)));
                }
            }
            let symbol = checker.getSymbolAtLocation(typescript_1.default.isPropertyAccessExpression(expression)
                ? expression.name : expression);
            if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
                symbol = checker.getAliasedSymbol(symbol);
            if (symbol?.declarations?.some((declaration) => (typescript_1.default.isClassLike(declaration) || typescript_1.default.isFunctionDeclaration(declaration))))
                return false;
            if (symbol?.declarations?.some((declaration) => (declaration.getSourceFile().fileName.replaceAll('\\', '/').includes('/node_modules/'))))
                return true;
            const property = symbol?.declarations?.find((declaration) => typescript_1.default.isPropertyAssignment(declaration) || typescript_1.default.isShorthandPropertyAssignment(declaration));
            if (property && projectSources.has(property.getSourceFile())) {
                let initializer = typescript_1.default.isPropertyAssignment(property)
                    ? property.initializer : undefined;
                if (typescript_1.default.isShorthandPropertyAssignment(property)) {
                    let value = checker.getShorthandAssignmentValueSymbol(property);
                    if (value?.flags && value.flags & typescript_1.default.SymbolFlags.Alias)
                        value = checker.getAliasedSymbol(value);
                    const declaration = value?.declarations?.find((entry) => (typescript_1.default.isVariableDeclaration(entry) && entry.initializer !== undefined));
                    initializer = declaration?.initializer;
                }
                if (!initializer)
                    return false;
                return isExternalProviderReference(initializer, seen, depth + 1, tokenPosition);
            }
            return !symbol && isExternalProviderReference(expression.expression, seen, depth + 1, tokenPosition);
        }
        if (!typescript_1.default.isIdentifier(expression))
            return false;
        const symbol = resolvedSymbolAt(expression, checker);
        if (symbol?.getName() === 'APP_GUARD' && symbol.declarations?.some((declaration) => (declaration.getSourceFile().fileName.replaceAll('\\', '/').includes('/node_modules/@nestjs/core/'))))
            return false;
        if (symbol?.declarations?.some(typescript_1.default.isClassLike))
            return false;
        if (symbol?.declarations?.some(typescript_1.default.isFunctionDeclaration)) {
            const local = symbol.declarations.some((declaration) => (projectSources.has(declaration.getSourceFile())));
            if (!local)
                return false;
            return reassignedSymbols.has(symbol) || unresolvedAssignments.has(symbol)
                || assignedValues.has(symbol) || aliasSetHas(escapedSymbols, symbol);
        }
        if (symbol?.declarations?.some((declaration) => (declaration.getSourceFile().fileName.replaceAll('\\', '/').includes('/node_modules/'))))
            return true;
        if (!symbol || seen.has(symbol))
            return false;
        seen.add(symbol);
        const bindings = symbol.declarations?.filter(typescript_1.default.isBindingElement) ?? [];
        if (bindings.length > 0) {
            if (bindings.length !== 1)
                return true;
            const steps = [];
            let binding = bindings[0];
            let variable;
            while (true) {
                if (binding.dotDotDotToken || binding.initializer)
                    return true;
                const pattern = binding.parent;
                if (typescript_1.default.isObjectBindingPattern(pattern)) {
                    const key = binding.propertyName && (typescript_1.default.isIdentifier(binding.propertyName)
                        || typescript_1.default.isStringLiteral(binding.propertyName) || typescript_1.default.isNumericLiteral(binding.propertyName))
                        ? binding.propertyName.text : typescript_1.default.isIdentifier(binding.name) ? binding.name.text : undefined;
                    if (key === undefined)
                        return true;
                    steps.push({ key });
                }
                else if (typescript_1.default.isArrayBindingPattern(pattern)) {
                    const index = pattern.elements.indexOf(binding);
                    if (index < 0)
                        return true;
                    steps.push({ index });
                }
                else
                    return true;
                if (typescript_1.default.isVariableDeclaration(pattern.parent)) {
                    variable = pattern.parent;
                    break;
                }
                if (typescript_1.default.isParameter(pattern.parent))
                    return false;
                if (!typescript_1.default.isBindingElement(pattern.parent))
                    return true;
                binding = pattern.parent;
            }
            if (!variable.initializer || !projectSources.has(variable.getSourceFile())
                || !typescript_1.default.isVariableDeclarationList(variable.parent)
                || !(variable.parent.flags & typescript_1.default.NodeFlags.Const))
                return true;
            if (unresolvedAssignments.has(symbol) || reassignedSymbols.has(symbol)
                || aliasSetHas(escapedSymbols, symbol) || aliasSetHas(unstableContainers, symbol))
                return true;
            let values = [variable.initializer];
            for (const step of steps.reverse()) {
                const next = [];
                for (const value of values) {
                    if ('key' in step) {
                        const object = resolveConstObject(value, checker, projectSources, check);
                        if (!object)
                            return true;
                        const effective = effectiveObjectProperty(object, step.key, checker, projectSources, check);
                        if (!effective.present || effective.accessor)
                            return true;
                        next.push(...effective.candidates);
                    }
                    else {
                        let array = value;
                        while (typescript_1.default.isParenthesizedExpression(array) || typescript_1.default.isAsExpression(array)
                            || typescript_1.default.isTypeAssertionExpression(array) || typescript_1.default.isSatisfiesExpression(array)
                            || typescript_1.default.isNonNullExpression(array))
                            array = array.expression;
                        if (!typescript_1.default.isArrayLiteralExpression(array) || array.elements.some(typescript_1.default.isSpreadElement))
                            return true;
                        const element = array.elements[step.index];
                        if (!element || typescript_1.default.isOmittedExpression(element) || typescript_1.default.isSpreadElement(element))
                            return true;
                        next.push(element);
                    }
                }
                values = next;
            }
            return [...values, ...(assignedValues.get(symbol) ?? [])].some((value) => isExternalProviderReference(value, new Set(seen), depth + 1, tokenPosition));
        }
        const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
        const declaration = declarations.length === 1 ? declarations[0] : undefined;
        if (!declaration) {
            return !tokenPosition && (symbol.declarations?.some((entry) => (typescript_1.default.isParameter(entry) && projectSources.has(entry.getSourceFile()))) ?? false);
        }
        if (!projectSources.has(declaration.getSourceFile()))
            return false;
        const candidates = [
            ...(declaration.initializer ? [declaration.initializer] : []),
            ...(assignedValues.get(symbol) ?? []),
        ];
        const unresolvedWrite = unresolvedAssignments.has(symbol)
            || unstableContainers.has(symbol) || escapedSymbols.has(symbol)
            || (reassignedSymbols.has(symbol) && !assignedValues.has(symbol));
        return unresolvedWrite || candidates.some((candidate) => (isExternalProviderReference(candidate, new Set(seen), depth + 1, tokenPosition)));
    };
    let unresolvedProvider;
    let externalModuleImport;
    const moduleEntries = [];
    const localClassesBySymbol = new Map();
    for (const sourceFile of projectSources) {
        const nodes = [sourceFile];
        while (nodes.length > 0) {
            const node = nodes.pop();
            check();
            if (typescript_1.default.isClassLike(node)) {
                const classSymbol = node.name ? checker.getSymbolAtLocation(node.name) : undefined;
                if (classSymbol)
                    localClassesBySymbol.set(classSymbol, node);
                for (const decorator of decorators(node)) {
                    const module = (0, decorator_symbols_1.resolveDecoratorSymbol)(decorator, checker, check);
                    if (module?.name !== 'Module' || !module.nestJsCommon)
                        continue;
                    const symbol = classSymbol;
                    const metadataArgument = module.call.arguments[0];
                    moduleEntries.push({
                        node,
                        symbol,
                        ...(metadataArgument ? {
                            metadataArgument,
                            metadata: resolveConstObject(metadataArgument, checker, projectSources, check),
                        } : {}),
                    });
                }
            }
            typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
        }
    }
    const modulesBySymbol = new Map();
    const duplicateModuleSymbols = new Set();
    for (const entry of moduleEntries) {
        if (entry.symbol) {
            if (modulesBySymbol.has(entry.symbol))
                duplicateModuleSymbols.add(entry.symbol);
            modulesBySymbol.set(entry.symbol, entry);
        }
    }
    const unwrapModuleExpression = (input) => {
        let expression = input;
        while (typescript_1.default.isParenthesizedExpression(expression) || typescript_1.default.isAsExpression(expression)
            || typescript_1.default.isTypeAssertionExpression(expression) || typescript_1.default.isSatisfiesExpression(expression)
            || typescript_1.default.isNonNullExpression(expression))
            expression = expression.expression;
        return expression;
    };
    const moduleSymbol = (input) => {
        let expression = unwrapModuleExpression(input);
        for (let depth = 0; depth < 64; depth += 1) {
            check();
            if (!(typescript_1.default.isCallExpression(expression) && expression.arguments.length === 1
                && (0, decorator_symbols_1.containsStaticSymbolFrom)(expression.expression, checker, check, '@nestjs/common', 'forwardRef', projectSources)))
                break;
            const callback = expression.arguments[0];
            if (!((typescript_1.default.isArrowFunction(callback) || typescript_1.default.isFunctionExpression(callback))
                && !typescript_1.default.isBlock(callback.body)))
                return undefined;
            expression = unwrapModuleExpression(callback.body);
        }
        if (typescript_1.default.isCallExpression(expression))
            return undefined;
        let symbol = checker.getSymbolAtLocation(typescript_1.default.isPropertyAccessExpression(expression)
            ? expression.name : expression);
        if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
            symbol = checker.getAliasedSymbol(symbol);
        return symbol && modulesBySymbol.has(symbol) ? symbol : undefined;
    };
    const roots = new Set();
    let moduleGraphComplete = !escapeIndexLimitExceeded && !unresolvedImportDefaultMutation
        && !unresolvedParameterSpreadMutation
        && !unresolvedDynamicAliasMutation
        && duplicateModuleSymbols.size === 0;
    const indirectBootstrapTarget = (input, includeContainers = true, asValue = false) => {
        const expressions = [input];
        const seen = new Set();
        const parameterBindings = new Map();
        const candidateContainsBootstrapAccess = (input) => {
            const nodes = [input];
            const candidateSymbols = new Set();
            let candidateSteps = 0;
            while (nodes.length > 0) {
                check();
                if (candidateSteps >= 256)
                    return true;
                candidateSteps += 1;
                const candidate = nodes.pop();
                if (candidate !== input && (typescript_1.default.isFunctionLike(candidate) || typescript_1.default.isClassLike(candidate)))
                    continue;
                if (candidate !== input && staticallyUnreachable(candidate))
                    continue;
                if (typescript_1.default.isCallExpression(candidate)) {
                    let callee = candidate.expression;
                    while (typescript_1.default.isParenthesizedExpression(callee) || typescript_1.default.isAsExpression(callee)
                        || typescript_1.default.isTypeAssertionExpression(callee) || typescript_1.default.isSatisfiesExpression(callee)
                        || typescript_1.default.isNonNullExpression(callee))
                        callee = callee.expression;
                    const pushCallable = (callable) => {
                        if (!callable.body || callable.modifiers?.some(({ kind }) => (kind === typescript_1.default.SyntaxKind.AsyncKeyword)) || ('asteriskToken' in callable && callable.asteriskToken))
                            return false;
                        for (const [index, parameter] of callable.parameters.entries()) {
                            if (!typescript_1.default.isIdentifier(parameter.name) || parameter.dotDotDotToken)
                                return true;
                            const argument = candidate.arguments[index];
                            const actual = argument && !typescript_1.default.isSpreadElement(argument) ? argument : undefined;
                            const isUndefined = actual ? staticUndefined(actual) : true;
                            if (parameter.initializer && isUndefined !== false)
                                nodes.push(parameter.initializer);
                        }
                        nodes.push(callable.body);
                        return false;
                    };
                    if (typescript_1.default.isArrowFunction(callee) || typescript_1.default.isFunctionExpression(callee)) {
                        if (pushCallable(callee))
                            return true;
                    }
                    else if (typescript_1.default.isIdentifier(callee)) {
                        let symbol = checker.getSymbolAtLocation(callee);
                        if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
                            symbol = checker.getAliasedSymbol(symbol);
                        for (const declaration of symbol?.declarations ?? []) {
                            if (!projectSources.has(declaration.getSourceFile()))
                                continue;
                            const callable = typescript_1.default.isFunctionDeclaration(declaration) ? declaration
                                : typescript_1.default.isVariableDeclaration(declaration) && declaration.initializer
                                    && (typescript_1.default.isArrowFunction(declaration.initializer)
                                        || typescript_1.default.isFunctionExpression(declaration.initializer))
                                    ? declaration.initializer : undefined;
                            if (callable && pushCallable(callable))
                                return true;
                        }
                    }
                    else if (typescript_1.default.isPropertyAccessExpression(callee) || typescript_1.default.isElementAccessExpression(callee)) {
                        const key = typescript_1.default.isPropertyAccessExpression(callee) ? callee.name.text
                            : callee.argumentExpression
                                ? (0, decorator_symbols_1.resolveStaticPropertyKey)(callee.argumentExpression, checker, check) : undefined;
                        const member = symbolAt(typescript_1.default.isPropertyAccessExpression(callee) ? callee.name : callee);
                        const receiver = rootSymbolAt(callee.expression);
                        const memberValues = member ? assignedValues.get(member) ?? [] : [];
                        if (member && aliasSetHas(unresolvedAssignments, member))
                            return true;
                        if (member && aliasSetHas(reassignedSymbols, member) && memberValues.length === 0)
                            return true;
                        nodes.push(...memberValues);
                        if (receiver && (aliasSetHas(unresolvedAssignments, receiver)
                            || aliasSetHas(escapedSymbols, receiver)
                            || aliasSetHas(unstableContainers, receiver)))
                            return true;
                        const receiverUnstable = Boolean(receiver && (aliasSetHas(reassignedSymbols, receiver)
                            || assignedValues.has(receiver)));
                        let resolvedCallable = false;
                        let unresolvedReceiverValue = false;
                        if (key !== undefined) {
                            const callableProperties = (object, visited = new Set()) => {
                                if (visited.has(object))
                                    return { present: true, callables: [], complete: false };
                                visited.add(object);
                                let result = { present: false, callables: [], complete: true };
                                for (const property of object.properties) {
                                    if (typescript_1.default.isSpreadAssignment(property)) {
                                        const spread = resolveConstObject(property.expression, checker, projectSources, check);
                                        if (!spread) {
                                            result.complete = false;
                                            continue;
                                        }
                                        const nested = callableProperties(spread, new Set(visited));
                                        if (nested.present)
                                            result = nested;
                                        else
                                            result.complete &&= nested.complete;
                                        continue;
                                    }
                                    const name = 'name' in property && property.name
                                        ? typescript_1.default.isComputedPropertyName(property.name)
                                            ? (0, decorator_symbols_1.resolveStaticPropertyKey)(property.name.expression, checker, check)
                                            : (typescript_1.default.isIdentifier(property.name) || typescript_1.default.isStringLiteral(property.name))
                                                ? property.name.text : undefined
                                        : undefined;
                                    if (name === undefined && 'name' in property
                                        && property.name && typescript_1.default.isComputedPropertyName(property.name)) {
                                        result.complete = false;
                                    }
                                    if (name !== key)
                                        continue;
                                    const callable = typescript_1.default.isMethodDeclaration(property) ? property
                                        : typescript_1.default.isPropertyAssignment(property)
                                            && (typescript_1.default.isArrowFunction(property.initializer)
                                                || typescript_1.default.isFunctionExpression(property.initializer))
                                            ? property.initializer : undefined;
                                    result = {
                                        present: true,
                                        callables: callable ? [callable] : [],
                                        complete: Boolean(callable),
                                    };
                                }
                                return result;
                            };
                            const receiverDeclarations = receiver?.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
                            const receiverValues = [
                                ...(receiver ? [] : [callee.expression]),
                                ...receiverDeclarations.flatMap(({ initializer }) => initializer ? [initializer] : []),
                                ...(receiver ? assignedValues.get(receiver) ?? [] : []),
                            ];
                            for (const value of receiverValues) {
                                const object = resolveConstObject(value, checker, projectSources, check);
                                if (!object) {
                                    unresolvedReceiverValue = true;
                                    continue;
                                }
                                const effective = callableProperties(object);
                                unresolvedReceiverValue ||= !effective.complete;
                                for (const callable of effective.callables) {
                                    resolvedCallable = true;
                                    if (pushCallable(callable))
                                        return true;
                                }
                            }
                        }
                        const declarations = member?.declarations?.filter((declaration) => (projectSources.has(declaration.getSourceFile()) && (typescript_1.default.isMethodDeclaration(declaration)
                            || typescript_1.default.isPropertyAssignment(declaration)))) ?? [];
                        const unstable = receiverUnstable;
                        if (unresolvedReceiverValue || (receiverUnstable && !resolvedCallable))
                            return true;
                        if (!resolvedCallable && declarations.length > 0
                            && (declarations.length !== 1 || unstable))
                            return true;
                        const declaration = resolvedCallable ? undefined : declarations[0];
                        const callable = declaration && typescript_1.default.isMethodDeclaration(declaration) ? declaration
                            : declaration && typescript_1.default.isPropertyAssignment(declaration)
                                && (typescript_1.default.isArrowFunction(declaration.initializer)
                                    || typescript_1.default.isFunctionExpression(declaration.initializer))
                                ? declaration.initializer : undefined;
                        if (callable && pushCallable(callable))
                            return true;
                    }
                }
                if (typescript_1.default.isIdentifier(candidate)) {
                    let symbol = checker.getSymbolAtLocation(candidate);
                    if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
                        symbol = checker.getAliasedSymbol(symbol);
                    if (symbol && !candidateSymbols.has(symbol)) {
                        candidateSymbols.add(symbol);
                        for (const declaration of symbol.declarations ?? []) {
                            if (typescript_1.default.isVariableDeclaration(declaration) && declaration.initializer
                                && projectSources.has(declaration.getSourceFile()))
                                nodes.push(declaration.initializer);
                        }
                    }
                }
                if (typescript_1.default.isPropertyAccessExpression(candidate) || typescript_1.default.isElementAccessExpression(candidate)) {
                    const candidateMethod = typescript_1.default.isPropertyAccessExpression(candidate)
                        ? candidate.name.text : candidate.argumentExpression
                        ? (0, decorator_symbols_1.resolveStaticPropertyKey)(candidate.argumentExpression, checker, check) : undefined;
                    if ((candidateMethod === 'create' || candidateMethod === 'createApplicationContext'
                        || candidateMethod === 'createMicroservice') && ((0, decorator_symbols_1.isStaticSymbolFrom)(candidate.expression, checker, check, '@nestjs/core', 'NestFactory')
                        || (0, decorator_symbols_1.containsStaticSymbolFrom)(candidate.expression, checker, check, '@nestjs/core', 'NestFactory', projectSources)))
                        return true;
                }
                typescript_1.default.forEachChild(candidate, (child) => { nodes.push(child); });
            }
            return false;
        };
        const staticUndefined = (input, symbols = new Set(), depth = 0) => {
            if (depth > 64)
                return undefined;
            let expression = input;
            while (typescript_1.default.isParenthesizedExpression(expression) || typescript_1.default.isAsExpression(expression)
                || typescript_1.default.isTypeAssertionExpression(expression) || typescript_1.default.isSatisfiesExpression(expression)
                || typescript_1.default.isNonNullExpression(expression))
                expression = expression.expression;
            if (typescript_1.default.isVoidExpression(expression))
                return true;
            if (expression.kind === typescript_1.default.SyntaxKind.NullKeyword || expression.kind === typescript_1.default.SyntaxKind.TrueKeyword
                || expression.kind === typescript_1.default.SyntaxKind.FalseKeyword || typescript_1.default.isLiteralExpression(expression)
                || typescript_1.default.isObjectLiteralExpression(expression) || typescript_1.default.isArrayLiteralExpression(expression)
                || typescript_1.default.isFunctionExpression(expression) || typescript_1.default.isArrowFunction(expression)
                || typescript_1.default.isClassExpression(expression) || typescript_1.default.isNewExpression(expression))
                return false;
            if (!typescript_1.default.isIdentifier(expression))
                return undefined;
            let symbol = checker.getSymbolAtLocation(expression);
            if (expression.text === 'undefined' && !symbol?.declarations?.length)
                return true;
            if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
                symbol = checker.getAliasedSymbol(symbol);
            if (!symbol || symbols.has(symbol))
                return undefined;
            const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
            const declaration = declarations.length === 1 ? declarations[0] : undefined;
            if (!declaration?.initializer || !projectSources.has(declaration.getSourceFile())
                || !typescript_1.default.isVariableDeclarationList(declaration.parent)
                || !(declaration.parent.flags & typescript_1.default.NodeFlags.Const))
                return undefined;
            symbols.add(symbol);
            return staticUndefined(declaration.initializer, symbols, depth + 1);
        };
        let steps = 0;
        while (expressions.length > 0) {
            check();
            if (steps >= 256)
                return true;
            steps += 1;
            let node = expressions.pop();
            while (typescript_1.default.isParenthesizedExpression(node) || typescript_1.default.isAsExpression(node)
                || typescript_1.default.isTypeAssertionExpression(node) || typescript_1.default.isSatisfiesExpression(node)
                || typescript_1.default.isNonNullExpression(node))
                node = node.expression;
            if ((typescript_1.default.isPropertyAccessExpression(node) || typescript_1.default.isElementAccessExpression(node))) {
                const object = resolveConstObject(node.expression, checker, projectSources, check);
                const receiverSymbol = rootSymbolAt(node.expression);
                const mutableReceiverDeclaration = receiverSymbol?.declarations?.find((declaration) => (typescript_1.default.isVariableDeclaration(declaration)
                    && projectSources.has(declaration.getSourceFile())
                    && typescript_1.default.isVariableDeclarationList(declaration.parent)
                    && !(declaration.parent.flags & typescript_1.default.NodeFlags.Const)));
                const mutableObjectReceiver = Boolean(mutableReceiverDeclaration && receiverSymbol && (unresolvedAssignments.has(receiverSymbol)
                    || [
                        ...(mutableReceiverDeclaration.initializer ? [mutableReceiverDeclaration.initializer] : []),
                        ...(assignedValues.get(receiverSymbol) ?? []),
                    ].some(candidateContainsBootstrapAccess)));
                if (mutableObjectReceiver)
                    return true;
                if (object && receiverSymbol && (aliasSetHas(unstableContainers, receiverSymbol)
                    || aliasSetHas(escapedSymbols, receiverSymbol)
                    || unresolvedAssignments.has(receiverSymbol)))
                    return true;
                const memberSymbol = symbolAt(typescript_1.default.isPropertyAccessExpression(node) ? node.name : node);
                if (object && memberSymbol && unresolvedAssignments.has(memberSymbol))
                    return true;
                if (memberSymbol) {
                    expressions.push(...(assignedValues.get(memberSymbol) ?? []));
                    for (const declaration of memberSymbol.declarations ?? []) {
                        if (typescript_1.default.isPropertyDeclaration(declaration) && declaration.initializer
                            && projectSources.has(declaration.getSourceFile())) {
                            expressions.push(declaration.initializer);
                        }
                    }
                }
                const method = typescript_1.default.isPropertyAccessExpression(node) ? node.name.text
                    : node.argumentExpression
                        ? (0, decorator_symbols_1.resolveStaticPropertyKey)(node.argumentExpression, checker, check) : undefined;
                const canonicalReceiver = (0, decorator_symbols_1.containsStaticSymbolFrom)(node.expression, checker, check, '@nestjs/core', 'NestFactory', projectSources);
                if (canonicalReceiver && (method === undefined || method === 'create'
                    || method === 'createApplicationContext' || method === 'createMicroservice'))
                    return true;
                if (method !== undefined) {
                    if (object) {
                        expressions.push(...effectiveObjectProperty(object, method, checker, projectSources, check).candidates);
                    }
                }
                else {
                    if (object && includeContainers)
                        expressions.push(object);
                }
                continue;
            }
            if (typescript_1.default.isIdentifier(node)) {
                let symbol = checker.getSymbolAtLocation(node);
                if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias) {
                    symbol = checker.getAliasedSymbol(symbol);
                }
                const bound = symbol ? parameterBindings.get(symbol) : undefined;
                if (bound) {
                    expressions.push(...bound);
                    continue;
                }
                if (!symbol || seen.has(symbol))
                    continue;
                seen.add(symbol);
                if (!asValue && symbol.declarations?.some((declaration) => (typescript_1.default.isFunctionDeclaration(declaration) && projectSources.has(declaration.getSourceFile()))))
                    continue;
                if (includeContainers && (aliasSetHas(unstableContainers, symbol)
                    || aliasSetHas(escapedSymbols, symbol)
                    || aliasSetHas(unresolvedAssignments, symbol)))
                    return true;
                for (const declaration of symbol.declarations ?? []) {
                    if (typescript_1.default.isVariableDeclaration(declaration) && declaration.initializer
                        && projectSources.has(declaration.getSourceFile()))
                        expressions.push(declaration.initializer);
                    if (asValue && typescript_1.default.isFunctionDeclaration(declaration) && declaration.body
                        && projectSources.has(declaration.getSourceFile()) && (candidateContainsBootstrapAccess(declaration.body)
                        || declaration.parameters.some(({ initializer }) => (!!initializer && candidateContainsBootstrapAccess(initializer)))))
                        return true;
                    if (typescript_1.default.isBindingElement(declaration)
                        && typescript_1.default.isObjectBindingPattern(declaration.parent)) {
                        const variable = declaration.parent.parent;
                        const key = declaration.propertyName
                            ? typescript_1.default.isIdentifier(declaration.propertyName) ? declaration.propertyName.text
                                : (0, decorator_symbols_1.resolveStaticPropertyKey)(typescript_1.default.isComputedPropertyName(declaration.propertyName)
                                    ? declaration.propertyName.expression : declaration.propertyName, checker, check)
                            : typescript_1.default.isIdentifier(declaration.name) ? declaration.name.text : undefined;
                        const canonicalReceiver = typescript_1.default.isVariableDeclaration(variable)
                            && variable.initializer && (0, decorator_symbols_1.containsStaticSymbolFrom)(variable.initializer, checker, check, '@nestjs/core', 'NestFactory', projectSources);
                        if (canonicalReceiver && (key === undefined || key === 'create'
                            || key === 'createApplicationContext' || key === 'createMicroservice'))
                            return true;
                    }
                }
                expressions.push(...(assignedValues.get(symbol) ?? []));
                continue;
            }
            if (typescript_1.default.isCallExpression(node)) {
                let callee = node.expression;
                while (typescript_1.default.isParenthesizedExpression(callee) || typescript_1.default.isAsExpression(callee)
                    || typescript_1.default.isTypeAssertionExpression(callee) || typescript_1.default.isSatisfiesExpression(callee)
                    || typescript_1.default.isNonNullExpression(callee))
                    callee = callee.expression;
                if (typescript_1.default.isIdentifier(callee)) {
                    let symbol = checker.getSymbolAtLocation(callee);
                    if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias) {
                        symbol = checker.getAliasedSymbol(symbol);
                    }
                    for (const declaration of symbol?.declarations ?? []) {
                        if (!projectSources.has(declaration.getSourceFile()))
                            continue;
                        const callable = typescript_1.default.isFunctionDeclaration(declaration) ? declaration
                            : typescript_1.default.isVariableDeclaration(declaration) && declaration.initializer
                                && (typescript_1.default.isArrowFunction(declaration.initializer)
                                    || typescript_1.default.isFunctionExpression(declaration.initializer))
                                ? declaration.initializer : undefined;
                        if (!callable?.body)
                            continue;
                        const bootstrapEvidence = candidateContainsBootstrapAccess(callable.body)
                            || callable.parameters.some(({ initializer }) => (!!initializer && candidateContainsBootstrapAccess(initializer))) || node.arguments.some((argument) => candidateContainsBootstrapAccess(argument));
                        if (callable.modifiers?.some(({ kind }) => kind === typescript_1.default.SyntaxKind.AsyncKeyword)
                            || ('asteriskToken' in callable && callable.asteriskToken)) {
                            if (bootstrapEvidence)
                                return true;
                            continue;
                        }
                        for (const [index, parameter] of callable.parameters.entries()) {
                            if (!typescript_1.default.isIdentifier(parameter.name) || parameter.dotDotDotToken)
                                return true;
                            const parameterSymbol = checker.getSymbolAtLocation(parameter.name);
                            if (!parameterSymbol)
                                return true;
                            if (aliasSetHas(reassignedSymbols, parameterSymbol)
                                || aliasSetHas(unresolvedAssignments, parameterSymbol)) {
                                if (bootstrapEvidence)
                                    return true;
                                continue;
                            }
                            const argument = node.arguments[index];
                            let actual = argument && !typescript_1.default.isSpreadElement(argument) ? argument : undefined;
                            const isUndefined = actual ? staticUndefined(actual) : true;
                            const valuesToBind = [
                                ...(actual && isUndefined !== true ? [actual] : []),
                                ...(parameter.initializer && isUndefined !== false ? [parameter.initializer] : []),
                            ];
                            for (const value of valuesToBind) {
                                const values = parameterBindings.get(parameterSymbol) ?? [];
                                values.push(value);
                                parameterBindings.set(parameterSymbol, values);
                            }
                        }
                        if (!typescript_1.default.isBlock(callable.body)) {
                            expressions.push(callable.body);
                            continue;
                        }
                        const returns = [...callable.body.statements];
                        while (returns.length > 0) {
                            check();
                            const current = returns.pop();
                            if (typescript_1.default.isReturnStatement(current) && current.expression
                                && !staticallyUnreachable(current)) {
                                expressions.push(current.expression);
                            }
                            else if (!typescript_1.default.isFunctionLike(current) && !typescript_1.default.isClassLike(current)) {
                                typescript_1.default.forEachChild(current, (child) => { returns.push(child); });
                            }
                        }
                    }
                }
                continue;
            }
            if (typescript_1.default.isAwaitExpression(node)) {
                expressions.push(node.expression);
                continue;
            }
            if (asValue && (typescript_1.default.isArrowFunction(node) || typescript_1.default.isFunctionExpression(node))) {
                if (candidateContainsBootstrapAccess(node.body)
                    || node.parameters.some(({ initializer }) => (!!initializer && candidateContainsBootstrapAccess(initializer))))
                    return true;
                continue;
            }
            if (typescript_1.default.isConditionalExpression(node)) {
                const state = staticState(node.condition);
                if (state.truthy !== false)
                    expressions.push(node.whenTrue);
                if (state.truthy !== true)
                    expressions.push(node.whenFalse);
            }
            else if (typescript_1.default.isBinaryExpression(node)
                && node.operatorToken.kind === typescript_1.default.SyntaxKind.CommaToken)
                expressions.push(node.right);
            else if (typescript_1.default.isBinaryExpression(node) && (node.operatorToken.kind === typescript_1.default.SyntaxKind.AmpersandAmpersandToken
                || node.operatorToken.kind === typescript_1.default.SyntaxKind.BarBarToken
                || node.operatorToken.kind === typescript_1.default.SyntaxKind.QuestionQuestionToken)) {
                const state = staticState(node.left);
                if (node.operatorToken.kind === typescript_1.default.SyntaxKind.AmpersandAmpersandToken) {
                    if (state.truthy !== true)
                        expressions.push(node.left);
                    if (state.truthy !== false)
                        expressions.push(node.right);
                }
                else if (node.operatorToken.kind === typescript_1.default.SyntaxKind.BarBarToken) {
                    if (state.truthy !== false)
                        expressions.push(node.left);
                    if (state.truthy !== true)
                        expressions.push(node.right);
                }
                else {
                    if (state.nullish !== true)
                        expressions.push(node.left);
                    if (state.nullish !== false)
                        expressions.push(node.right);
                }
            }
            else if (includeContainers && typescript_1.default.isObjectLiteralExpression(node)) {
                for (const property of node.properties) {
                    if (typescript_1.default.isPropertyAssignment(property))
                        expressions.push(property.initializer);
                    else if (typescript_1.default.isShorthandPropertyAssignment(property))
                        expressions.push(property.name);
                    else if (typescript_1.default.isSpreadAssignment(property)) {
                        if (resolveConstObject(property.expression, checker, projectSources, check)) {
                            expressions.push(property.expression);
                        }
                        else if (candidateContainsBootstrapAccess(property.expression))
                            return true;
                    }
                    else if (typescript_1.default.isMethodDeclaration(property) || typescript_1.default.isAccessor(property)) {
                        if (candidateContainsBootstrapAccess(property))
                            return true;
                        const returnedSymbols = new Set();
                        const returnedCallableContainsBootstrap = (input, depth = 0) => {
                            if (depth >= 64)
                                return true;
                            if (candidateContainsBootstrapAccess(input))
                                return true;
                            let expression = input;
                            while (typescript_1.default.isParenthesizedExpression(expression) || typescript_1.default.isAsExpression(expression)
                                || typescript_1.default.isTypeAssertionExpression(expression) || typescript_1.default.isSatisfiesExpression(expression)
                                || typescript_1.default.isNonNullExpression(expression))
                                expression = expression.expression;
                            if (typescript_1.default.isIdentifier(expression)) {
                                let symbol = checker.getSymbolAtLocation(expression);
                                if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias) {
                                    symbol = checker.getAliasedSymbol(symbol);
                                }
                                if (!symbol || returnedSymbols.has(symbol))
                                    return false;
                                returnedSymbols.add(symbol);
                                if (unresolvedAssignments.has(symbol))
                                    return true;
                                const writes = assignedValues.get(symbol) ?? [];
                                if (reassignedSymbols.has(symbol) && writes.length === 0)
                                    return true;
                                for (const value of writes) {
                                    if (returnedCallableContainsBootstrap(value, depth + 1))
                                        return true;
                                }
                                for (const declaration of symbol.declarations ?? []) {
                                    if (!projectSources.has(declaration.getSourceFile()))
                                        continue;
                                    if (typescript_1.default.isBindingElement(declaration) && typescript_1.default.isObjectBindingPattern(declaration.parent)) {
                                        const variable = declaration.parent.parent;
                                        const key = declaration.propertyName
                                            ? typescript_1.default.isIdentifier(declaration.propertyName) ? declaration.propertyName.text
                                                : typescript_1.default.isComputedPropertyName(declaration.propertyName)
                                                    ? (0, decorator_symbols_1.resolveStaticPropertyKey)(declaration.propertyName.expression, checker, check)
                                                    : undefined
                                            : typescript_1.default.isIdentifier(declaration.name) ? declaration.name.text : undefined;
                                        if (typescript_1.default.isVariableDeclaration(variable) && variable.initializer
                                            && (0, decorator_symbols_1.containsStaticSymbolFrom)(variable.initializer, checker, check, '@nestjs/core', 'NestFactory', projectSources) && (key === undefined || key === 'create'
                                            || key === 'createApplicationContext' || key === 'createMicroservice'))
                                            return true;
                                    }
                                    if (typescript_1.default.isVariableDeclaration(declaration) && declaration.initializer
                                        && returnedCallableContainsBootstrap(declaration.initializer, depth + 1))
                                        return true;
                                    if (typescript_1.default.isFunctionDeclaration(declaration) && declaration.body) {
                                        if (candidateContainsBootstrapAccess(declaration.body))
                                            return true;
                                        const declarationReturns = [...declaration.body.statements];
                                        while (declarationReturns.length > 0) {
                                            const nested = declarationReturns.pop();
                                            if (typescript_1.default.isReturnStatement(nested) && nested.expression
                                                && !staticallyUnreachable(nested)
                                                && returnedCallableContainsBootstrap(nested.expression, depth + 1))
                                                return true;
                                            if (!typescript_1.default.isFunctionLike(nested) && !typescript_1.default.isClassLike(nested)) {
                                                typescript_1.default.forEachChild(nested, (child) => { declarationReturns.push(child); });
                                            }
                                        }
                                    }
                                }
                                return false;
                            }
                            if (typescript_1.default.isPropertyAccessExpression(expression) || typescript_1.default.isElementAccessExpression(expression)) {
                                const member = symbolAt(typescript_1.default.isPropertyAccessExpression(expression)
                                    ? expression.name : expression);
                                if (member && unresolvedAssignments.has(member))
                                    return true;
                                for (const value of member ? assignedValues.get(member) ?? [] : []) {
                                    if (returnedCallableContainsBootstrap(value, depth + 1))
                                        return true;
                                }
                                for (const declaration of member?.declarations ?? []) {
                                    if (typescript_1.default.isPropertyDeclaration(declaration) && declaration.initializer
                                        && projectSources.has(declaration.getSourceFile())
                                        && returnedCallableContainsBootstrap(declaration.initializer, depth + 1))
                                        return true;
                                }
                                const key = typescript_1.default.isPropertyAccessExpression(expression) ? expression.name.text
                                    : expression.argumentExpression
                                        ? (0, decorator_symbols_1.resolveStaticPropertyKey)(expression.argumentExpression, checker, check) : undefined;
                                const receiver = rootSymbolAt(expression.expression);
                                if (key === undefined || (receiver && (unresolvedAssignments.has(receiver)
                                    || aliasSetHas(escapedSymbols, receiver)
                                    || aliasSetHas(unstableContainers, receiver))))
                                    return true;
                                const receiverDeclarations = receiver?.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
                                let immediateReceiver = expression.expression;
                                while (typescript_1.default.isParenthesizedExpression(immediateReceiver)
                                    || typescript_1.default.isAsExpression(immediateReceiver)
                                    || typescript_1.default.isTypeAssertionExpression(immediateReceiver)
                                    || typescript_1.default.isSatisfiesExpression(immediateReceiver)
                                    || typescript_1.default.isNonNullExpression(immediateReceiver))
                                    immediateReceiver = immediateReceiver.expression;
                                const nestedReceiver = typescript_1.default.isPropertyAccessExpression(immediateReceiver)
                                    || typescript_1.default.isElementAccessExpression(immediateReceiver);
                                const receiverValues = nestedReceiver ? [immediateReceiver] : [
                                    ...(receiver ? [] : [immediateReceiver]),
                                    ...receiverDeclarations.flatMap(({ initializer }) => initializer ? [initializer] : []),
                                    ...(receiver ? assignedValues.get(receiver) ?? [] : []),
                                ];
                                const resolveReceiverObjects = (input, objectDepth = 0) => {
                                    if (objectDepth >= 64)
                                        return [];
                                    let candidate = input;
                                    while (typescript_1.default.isParenthesizedExpression(candidate) || typescript_1.default.isAsExpression(candidate)
                                        || typescript_1.default.isTypeAssertionExpression(candidate) || typescript_1.default.isSatisfiesExpression(candidate)
                                        || typescript_1.default.isNonNullExpression(candidate))
                                        candidate = candidate.expression;
                                    const direct = resolveConstObject(candidate, checker, projectSources, check);
                                    if (direct)
                                        return [direct];
                                    if (!typescript_1.default.isPropertyAccessExpression(candidate)
                                        && !typescript_1.default.isElementAccessExpression(candidate))
                                        return [];
                                    const propertyKey = typescript_1.default.isPropertyAccessExpression(candidate) ? candidate.name.text
                                        : candidate.argumentExpression
                                            ? (0, decorator_symbols_1.resolveStaticPropertyKey)(candidate.argumentExpression, checker, check) : undefined;
                                    if (propertyKey === undefined)
                                        return [];
                                    const objects = [];
                                    for (const object of resolveReceiverObjects(candidate.expression, objectDepth + 1)) {
                                        const property = effectiveObjectProperty(object, propertyKey, checker, projectSources, check);
                                        for (const candidate of property.candidates) {
                                            objects.push(...resolveReceiverObjects(candidate, objectDepth + 1));
                                        }
                                    }
                                    return objects;
                                };
                                for (const value of receiverValues) {
                                    const objects = resolveReceiverObjects(value);
                                    if (objects.length === 0)
                                        return true;
                                    for (const object of objects) {
                                        const property = effectiveObjectProperty(object, key, checker, projectSources, check);
                                        if (!property.present || property.accessor || property.candidates.length === 0)
                                            return true;
                                        for (const candidate of property.candidates) {
                                            if (returnedCallableContainsBootstrap(candidate, depth + 1))
                                                return true;
                                        }
                                    }
                                }
                                return false;
                            }
                            if (!typescript_1.default.isArrowFunction(expression) && !typescript_1.default.isFunctionExpression(expression))
                                return false;
                            if (!typescript_1.default.isBlock(expression.body)) {
                                return returnedCallableContainsBootstrap(expression.body, depth + 1);
                            }
                            const nestedReturns = [...expression.body.statements];
                            while (nestedReturns.length > 0) {
                                const nested = nestedReturns.pop();
                                if (typescript_1.default.isReturnStatement(nested) && nested.expression
                                    && !staticallyUnreachable(nested)
                                    && returnedCallableContainsBootstrap(nested.expression, depth + 1))
                                    return true;
                                if (!typescript_1.default.isFunctionLike(nested) && !typescript_1.default.isClassLike(nested)) {
                                    typescript_1.default.forEachChild(nested, (child) => { nestedReturns.push(child); });
                                }
                            }
                            return false;
                        };
                        if (property.body) {
                            const returns = [...property.body.statements];
                            while (returns.length > 0) {
                                const returned = returns.pop();
                                if (typescript_1.default.isReturnStatement(returned) && returned.expression
                                    && !staticallyUnreachable(returned)
                                    && returnedCallableContainsBootstrap(returned.expression))
                                    return true;
                                if (!typescript_1.default.isFunctionLike(returned) && !typescript_1.default.isClassLike(returned)) {
                                    typescript_1.default.forEachChild(returned, (child) => { returns.push(child); });
                                }
                            }
                        }
                    }
                }
            }
            else if (includeContainers && typescript_1.default.isArrayLiteralExpression(node)) {
                for (const element of node.elements) {
                    if (!typescript_1.default.isOmittedExpression(element)) {
                        expressions.push(typescript_1.default.isSpreadElement(element) ? element.expression : element);
                    }
                }
            }
        }
        return false;
    };
    const invokedLocalFunctions = new Set();
    const functionsWithResolvedBootstrap = new Set();
    for (const sourceFile of projectSources) {
        const nodes = [sourceFile];
        while (nodes.length > 0) {
            const node = nodes.pop();
            check();
            if (typescript_1.default.isCallExpression(node) && !staticallyUnreachable(node)) {
                let callee = unwrapModuleExpression(node.expression);
                let functionAncestor;
                for (let parent = node.parent; !typescript_1.default.isSourceFile(parent); parent = parent.parent) {
                    if (typescript_1.default.isFunctionLike(parent)) {
                        functionAncestor = parent;
                        break;
                    }
                }
                if (!functionAncestor && node.arguments.length === 0 && typescript_1.default.isIdentifier(callee)) {
                    const symbol = symbolAt(callee);
                    const declarations = symbol?.declarations?.filter((declaration) => typescript_1.default.isFunctionDeclaration(declaration) && declaration.body !== undefined
                        && projectSources.has(declaration.getSourceFile())) ?? [];
                    if (symbol && declarations.length === 1 && !reassignedSymbols.has(symbol)
                        && !unresolvedAssignments.has(symbol))
                        invokedLocalFunctions.add(symbol);
                }
                const method = typescript_1.default.isPropertyAccessExpression(callee) ? callee.name.text
                    : typescript_1.default.isElementAccessExpression(callee) && callee.argumentExpression
                        ? (0, decorator_symbols_1.resolveStaticPropertyKey)(callee.argumentExpression, checker, check) : undefined;
                if (functionAncestor && node.arguments[0]
                    && (method === 'create' || method === 'createApplicationContext'
                        || method === 'createMicroservice')
                    && (typescript_1.default.isPropertyAccessExpression(callee) || typescript_1.default.isElementAccessExpression(callee))
                    && (0, decorator_symbols_1.containsStaticSymbolFrom)(callee.expression, checker, check, '@nestjs/core', 'NestFactory', projectSources) && moduleSymbol(node.arguments[0])
                    && typescript_1.default.isFunctionDeclaration(functionAncestor) && functionAncestor.name) {
                    const symbol = symbolAt(functionAncestor.name);
                    if (symbol)
                        functionsWithResolvedBootstrap.add(symbol);
                }
            }
            typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
        }
    }
    for (const sourceFile of projectSources) {
        const nodes = [sourceFile];
        while (nodes.length > 0) {
            const node = nodes.pop();
            check();
            if (typescript_1.default.isCallExpression(node) && node.arguments[0] && !staticallyUnreachable(node)) {
                const callee = node.expression;
                const method = typescript_1.default.isPropertyAccessExpression(callee) ? callee.name.text
                    : typescript_1.default.isElementAccessExpression(callee) && callee.argumentExpression
                        ? (0, decorator_symbols_1.resolveStaticPropertyKey)(callee.argumentExpression, checker, check) : undefined;
                if ((method === 'create' || method === 'createApplicationContext'
                    || method === 'createMicroservice')
                    && (typescript_1.default.isPropertyAccessExpression(callee) || typescript_1.default.isElementAccessExpression(callee))
                    && (0, decorator_symbols_1.containsStaticSymbolFrom)(callee.expression, checker, check, '@nestjs/core', 'NestFactory', projectSources)) {
                    const symbol = moduleSymbol(node.arguments[0]);
                    if (symbol)
                        roots.add(symbol);
                    else
                        moduleGraphComplete = false;
                    for (let parent = node.parent; !typescript_1.default.isSourceFile(parent); parent = parent.parent) {
                        if (typescript_1.default.isFunctionLike(parent)) {
                            const functionSymbol = typescript_1.default.isFunctionDeclaration(parent) && parent.name
                                ? symbolAt(parent.name) : undefined;
                            if (!functionSymbol || !invokedLocalFunctions.has(functionSymbol)
                                || !functionsWithResolvedBootstrap.has(functionSymbol)) {
                                moduleGraphComplete = false;
                            }
                            break;
                        }
                    }
                }
                else {
                    const localFunction = typescript_1.default.isIdentifier(unwrapModuleExpression(callee))
                        ? symbolAt(unwrapModuleExpression(callee)) : undefined;
                    if (localFunction && invokedLocalFunctions.has(localFunction)
                        && functionsWithResolvedBootstrap.has(localFunction)) {
                        typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
                        continue;
                    }
                    const target = (typescript_1.default.isPropertyAccessExpression(callee)
                        || typescript_1.default.isElementAccessExpression(callee)) ? callee.expression : undefined;
                    const unwrappedTarget = target ? unwrapModuleExpression(target) : undefined;
                    const dynamicTarget = Boolean(unwrappedTarget && typescript_1.default.isElementAccessExpression(unwrappedTarget)
                        && (!unwrappedTarget.argumentExpression
                            || (0, decorator_symbols_1.resolveStaticPropertyKey)(unwrappedTarget.argumentExpression, checker, check) === undefined));
                    if ((method === 'call' || method === 'apply' || method === 'bind')
                        && target && indirectBootstrapTarget(target, dynamicTarget))
                        moduleGraphComplete = false;
                    else {
                        const unwrappedCallee = unwrapModuleExpression(callee);
                        const dynamicCallee = typescript_1.default.isElementAccessExpression(unwrappedCallee)
                            && (!unwrappedCallee.argumentExpression || (0, decorator_symbols_1.resolveStaticPropertyKey)(unwrappedCallee.argumentExpression, checker, check) === undefined);
                        if (indirectBootstrapTarget(callee, dynamicCallee))
                            moduleGraphComplete = false;
                    }
                }
                for (const argument of node.arguments) {
                    const candidate = typescript_1.default.isSpreadElement(argument) ? argument.expression : argument;
                    if (indirectBootstrapTarget(candidate, false, true)
                        || indirectBootstrapTarget(candidate, true, true)) {
                        moduleGraphComplete = false;
                    }
                }
            }
            typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
        }
    }
    const activeModules = new Set(roots.size > 0 ? roots : modulesBySymbol.keys());
    if (roots.size > 0) {
        const pending = [...roots];
        const visitedBaseClasses = new Set();
        const activateInheritedModules = (node) => {
            const classes = [node];
            let steps = 0;
            while (classes.length > 0) {
                check();
                if (steps >= 256) {
                    moduleGraphComplete = false;
                    return;
                }
                steps += 1;
                for (const heritage of classes.pop().heritageClauses ?? []) {
                    if (heritage.token !== typescript_1.default.SyntaxKind.ExtendsKeyword)
                        continue;
                    for (const type of heritage.types) {
                        let symbol = checker.getSymbolAtLocation(type.expression);
                        if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias) {
                            symbol = checker.getAliasedSymbol(symbol);
                        }
                        const module = symbol ? modulesBySymbol.get(symbol) : undefined;
                        if (module?.symbol && !activeModules.has(module.symbol)) {
                            activeModules.add(module.symbol);
                            pending.push(module.symbol);
                            continue;
                        }
                        const localClass = symbol ? localClassesBySymbol.get(symbol) : undefined;
                        if (symbol && localClass) {
                            if (!visitedBaseClasses.has(symbol)) {
                                visitedBaseClasses.add(symbol);
                                classes.push(localClass);
                            }
                            continue;
                        }
                        moduleGraphComplete = false;
                        if (isExternalModuleReference(type.expression)) {
                            externalModuleImport ??= type.expression;
                        }
                    }
                }
            }
        };
        while (pending.length > 0) {
            check();
            const entry = modulesBySymbol.get(pending.pop());
            if (entry)
                activateInheritedModules(entry.node);
            const metadataSymbol = entry?.metadataArgument
                ? rootSymbolAt(entry.metadataArgument) : undefined;
            if (metadataSymbol && (aliasSetHas(unstableContainers, metadataSymbol)
                || aliasSetHas(escapedSymbols, metadataSymbol)
                || aliasSetHas(containersWithAssignedImports, metadataSymbol)
                || aliasSetHas(incompleteLocalCallImportSymbols, metadataSymbol)
                || aliasSetHas(unresolvedAssignments, metadataSymbol)))
                moduleGraphComplete = false;
            if (!entry?.metadata) {
                if (entry?.metadataArgument)
                    moduleGraphComplete = false;
                continue;
            }
            const imports = effectiveObjectProperty(entry.metadata, 'imports', checker, projectSources, check);
            const importsSymbol = checker.getTypeAtLocation(entry.metadata).getProperty('imports');
            if (importsSymbol && (reassignedSymbols.has(importsSymbol)
                || unresolvedAssignments.has(importsSymbol)
                || aliasSetHas(unstableContainers, importsSymbol)
                || aliasSetHas(escapedSymbols, importsSymbol)
                || aliasSetHas(incompleteLocalCallImportSymbols, importsSymbol)
                || assignedValues.has(importsSymbol)))
                moduleGraphComplete = false;
            if (imports.candidates.some((candidate) => {
                const symbol = rootSymbolAt(candidate);
                return Boolean(symbol && (aliasSetHas(unstableContainers, symbol)
                    || aliasSetHas(escapedSymbols, symbol)
                    || aliasSetHas(incompleteLocalCallImportSymbols, symbol)
                    || aliasSetHas(unresolvedAssignments, symbol)));
            }))
                moduleGraphComplete = false;
            if (imports.candidates.some((candidate) => (mutatedContainerExpressions.has(unwrapModuleExpression(candidate))
                || mutatedDynamicExpressions.has(unwrapModuleExpression(candidate)))))
                moduleGraphComplete = false;
            const expressions = [...imports.candidates];
            while (expressions.length > 0) {
                const expression = expressions.pop();
                const unwrapped = unwrapModuleExpression(expression);
                if (typescript_1.default.isArrayLiteralExpression(unwrapped)) {
                    for (const element of unwrapped.elements) {
                        if (!typescript_1.default.isOmittedExpression(element)) {
                            expressions.push(typescript_1.default.isSpreadElement(element) ? element.expression : element);
                        }
                    }
                    continue;
                }
                if (typescript_1.default.isConditionalExpression(unwrapped)) {
                    expressions.push(unwrapped.whenTrue, unwrapped.whenFalse);
                    continue;
                }
                const symbol = moduleSymbol(unwrapped);
                if (symbol && !activeModules.has(symbol)) {
                    activeModules.add(symbol);
                    pending.push(symbol);
                }
                else if (!symbol)
                    moduleGraphComplete = false;
            }
        }
    }
    if (!moduleGraphComplete) {
        for (const symbol of modulesBySymbol.keys())
            activeModules.add(symbol);
    }
    for (const entry of moduleEntries) {
        if (entry.symbol && !activeModules.has(entry.symbol))
            continue;
        const { metadataArgument, metadata } = entry;
        if (!metadata) {
            if (metadataArgument)
                candidates.push(metadataArgument);
            continue;
        }
        const effectiveProviders = effectiveObjectProperty(metadata, 'providers', checker, projectSources, check);
        for (const providerExpression of effectiveProviders.candidates) {
            if (!collect(providerExpression, new Set(), 0))
                candidates.push(providerExpression);
            if (!unresolvedProvider && isExternalProviderReference(providerExpression)) {
                unresolvedProvider = providerExpression;
            }
        }
        const effectiveImports = effectiveObjectProperty(metadata, 'imports', checker, projectSources, check);
        externalModuleImport ??= effectiveImports.candidates.find((candidate) => (isExternalModuleReference(candidate)));
    }
    return { providers, candidates, unresolvedProvider, externalModuleImport };
}
function isProviderRegistration(node, registeredProviders) {
    const entry = node.parent;
    return typescript_1.default.isObjectLiteralExpression(entry) && registeredProviders.has(entry);
}
function indexIdentifierReferences(checker, projectSources, check) {
    const references = new Map();
    for (const sourceFile of projectSources) {
        const nodes = [sourceFile];
        while (nodes.length > 0) {
            const node = nodes.pop();
            check();
            if (typescript_1.default.isIdentifier(node)) {
                const symbol = resolvedSymbolAt(node, checker);
                if (symbol) {
                    const entries = references.get(symbol) ?? [];
                    entries.push(node);
                    references.set(symbol, entries);
                }
            }
            typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
        }
    }
    return references;
}
function containsCanonicalProviderToken(input, checker, projectSources, check, maxSteps, referencesBySymbol) {
    const expressions = [input];
    const seenExpressions = new Set();
    const seenSymbols = new Set();
    let steps = 0;
    const symbolAt = (node) => resolvedSymbolAt(node, checker);
    const staticBoolean = (input) => {
        let expression = input;
        while (typescript_1.default.isParenthesizedExpression(expression) || typescript_1.default.isAsExpression(expression)
            || typescript_1.default.isTypeAssertionExpression(expression) || typescript_1.default.isSatisfiesExpression(expression)
            || typescript_1.default.isNonNullExpression(expression))
            expression = expression.expression;
        return expression.kind === typescript_1.default.SyntaxKind.TrueKeyword
            ? true : expression.kind === typescript_1.default.SyntaxKind.FalseKeyword ? false : undefined;
    };
    const collectReturns = (statement) => {
        check();
        if (typescript_1.default.isReturnStatement(statement)) {
            if (statement.expression)
                expressions.push(statement.expression);
            return true;
        }
        if (typescript_1.default.isBlock(statement)) {
            for (const child of statement.statements) {
                if (collectReturns(child))
                    return true;
            }
            return false;
        }
        if (typescript_1.default.isIfStatement(statement)) {
            const condition = staticBoolean(statement.expression);
            if (condition === true)
                return collectReturns(statement.thenStatement);
            if (condition === false)
                return Boolean(statement.elseStatement
                    && collectReturns(statement.elseStatement));
            const whenTrue = collectReturns(statement.thenStatement);
            const whenFalse = Boolean(statement.elseStatement
                && collectReturns(statement.elseStatement));
            return whenTrue && whenFalse;
        }
        return false;
    };
    const staticallyUnreachable = (node) => {
        let child = node;
        let parent = node.parent;
        while (parent) {
            if (typescript_1.default.isIfStatement(parent)) {
                const condition = staticBoolean(parent.expression);
                if (condition === false && child === parent.thenStatement)
                    return true;
                if (condition === true && child === parent.elseStatement)
                    return true;
            }
            if (typescript_1.default.isBlock(parent) && typescript_1.default.isStatement(child)) {
                const index = parent.statements.indexOf(child);
                if (index > 0 && parent.statements.slice(0, index).some(typescript_1.default.isReturnStatement))
                    return true;
            }
            child = parent;
            parent = parent.parent;
        }
        return false;
    };
    const queueSymbolEdges = (symbol) => {
        if (seenSymbols.has(symbol))
            return;
        seenSymbols.add(symbol);
        for (const declaration of symbol.declarations ?? []) {
            if (!projectSources.has(declaration.getSourceFile()))
                continue;
            if (typescript_1.default.isVariableDeclaration(declaration) && declaration.initializer) {
                if (typescript_1.default.isArrowFunction(declaration.initializer)
                    || typescript_1.default.isFunctionExpression(declaration.initializer)) {
                    if (typescript_1.default.isBlock(declaration.initializer.body))
                        collectReturns(declaration.initializer.body);
                    else
                        expressions.push(declaration.initializer.body);
                }
                else
                    expressions.push(declaration.initializer);
            }
            else if (typescript_1.default.isFunctionDeclaration(declaration) && declaration.body) {
                collectReturns(declaration.body);
            }
        }
        for (const node of referencesBySymbol.get(symbol) ?? []) {
            if (staticallyUnreachable(node))
                continue;
            const access = (typescript_1.default.isPropertyAccessExpression(node.parent)
                || typescript_1.default.isElementAccessExpression(node.parent)) && node.parent.expression === node
                ? node.parent : undefined;
            const call = access && typescript_1.default.isCallExpression(access.parent) && access.parent.expression === access
                ? access.parent : undefined;
            const accessName = access && (typescript_1.default.isPropertyAccessExpression(access)
                ? access.name.text : access.argumentExpression
                ? (0, decorator_symbols_1.resolveStaticPropertyKey)(access.argumentExpression, checker, check) : undefined);
            if (access && call && (accessName === undefined || !READ_ONLY_ARRAY_METHODS.has(accessName))) {
                for (const argument of call.arguments) {
                    expressions.push(typescript_1.default.isSpreadElement(argument) ? argument.expression : argument);
                }
            }
            let aliasInitializer = node;
            while ((typescript_1.default.isParenthesizedExpression(aliasInitializer.parent)
                || typescript_1.default.isAsExpression(aliasInitializer.parent)
                || typescript_1.default.isTypeAssertionExpression(aliasInitializer.parent)
                || typescript_1.default.isSatisfiesExpression(aliasInitializer.parent)
                || typescript_1.default.isNonNullExpression(aliasInitializer.parent))
                && aliasInitializer.parent.expression === aliasInitializer) {
                aliasInitializer = aliasInitializer.parent;
            }
            const aliasDeclaration = typescript_1.default.isVariableDeclaration(aliasInitializer.parent)
                && aliasInitializer.parent.initializer === aliasInitializer ? aliasInitializer.parent : undefined;
            if (aliasDeclaration && typescript_1.default.isIdentifier(aliasDeclaration.name)
                && typescript_1.default.isVariableDeclarationList(aliasDeclaration.parent)
                && aliasDeclaration.parent.flags & typescript_1.default.NodeFlags.Const)
                expressions.push(aliasDeclaration.name);
            let target = access ?? node;
            while (target.parent && !typescript_1.default.isStatement(target)) {
                const parent = target.parent;
                if (typescript_1.default.isBinaryExpression(parent) && parent.left === target
                    && parent.operatorToken.kind >= typescript_1.default.SyntaxKind.FirstAssignment
                    && parent.operatorToken.kind <= typescript_1.default.SyntaxKind.LastAssignment) {
                    expressions.push(parent.right);
                    break;
                }
                target = parent;
            }
        }
    };
    while (expressions.length > 0) {
        let expression = expressions.pop();
        check();
        steps += 1;
        if (steps > maxSteps)
            throw new source_analysis_1.SourceAnalyzerContractError('SOURCE_ANALYZER_AST_NODE_LIMIT');
        if (seenExpressions.has(expression))
            continue;
        seenExpressions.add(expression);
        while (typescript_1.default.isParenthesizedExpression(expression) || typescript_1.default.isAsExpression(expression)
            || typescript_1.default.isTypeAssertionExpression(expression) || typescript_1.default.isSatisfiesExpression(expression)
            || typescript_1.default.isNonNullExpression(expression))
            expression = expression.expression;
        if ((0, decorator_symbols_1.isStaticSymbolFrom)(expression, checker, check, '@nestjs/core', 'APP_GUARD'))
            return true;
        if (typescript_1.default.isIdentifier(expression)) {
            const symbol = symbolAt(expression);
            if (symbol)
                queueSymbolEdges(symbol);
        }
        else if (typescript_1.default.isCallExpression(expression) && typescript_1.default.isIdentifier(expression.expression)) {
            const symbol = symbolAt(expression.expression);
            if (symbol)
                queueSymbolEdges(symbol);
        }
        else if (typescript_1.default.isArrayLiteralExpression(expression)) {
            for (const element of expression.elements) {
                expressions.push(typescript_1.default.isSpreadElement(element) ? element.expression : element);
            }
        }
        else if (typescript_1.default.isObjectLiteralExpression(expression)) {
            const effectiveProperties = [
                ['providers', effectiveObjectProperty(expression, 'providers', checker, projectSources, check)],
                ['provide', effectiveObjectProperty(expression, 'provide', checker, projectSources, check)],
            ];
            for (const [name, property] of effectiveProperties) {
                for (const initializer of property.candidates) {
                    if ((0, decorator_symbols_1.containsStaticSymbolFrom)(initializer, checker, check, '@nestjs/core', 'APP_GUARD', projectSources))
                        return true;
                    if (name === 'providers')
                        expressions.push(initializer);
                }
            }
        }
        else if (typescript_1.default.isConditionalExpression(expression)) {
            let conditionExpression = expression.condition;
            while (typescript_1.default.isParenthesizedExpression(conditionExpression)
                || typescript_1.default.isAsExpression(conditionExpression) || typescript_1.default.isTypeAssertionExpression(conditionExpression)
                || typescript_1.default.isSatisfiesExpression(conditionExpression)
                || typescript_1.default.isNonNullExpression(conditionExpression))
                conditionExpression = conditionExpression.expression;
            const undefinedIdentifier = typescript_1.default.isIdentifier(conditionExpression)
                && conditionExpression.text === 'undefined'
                && !checker.getSymbolAtLocation(conditionExpression)?.declarations?.length;
            const condition = conditionExpression.kind === typescript_1.default.SyntaxKind.TrueKeyword
                ? true : conditionExpression.kind === typescript_1.default.SyntaxKind.FalseKeyword
                || conditionExpression.kind === typescript_1.default.SyntaxKind.NullKeyword
                || typescript_1.default.isVoidExpression(conditionExpression) || undefinedIdentifier ? false : undefined;
            if (condition !== false)
                expressions.push(expression.whenTrue);
            if (condition !== true)
                expressions.push(expression.whenFalse);
        }
    }
    return false;
}
function routePath(controllerPath, methodPath) {
    let canonical;
    try {
        canonical = (0, canonical_route_1.canonicalizePath)(`${controllerPath}/${methodPath}`);
    }
    catch {
        return undefined;
    }
    const advancedPattern = /\*|:[A-Za-z_$][\w$]*\([^)]/u.test(canonical);
    return {
        path: canonical.replace(/:([A-Za-z_$][\w$]*)(?![\w$(])/gu, '{$1}'),
        complete: !advancedPattern,
    };
}
function directBaseClass(node, checker, check, maxSteps) {
    let expression = node.heritageClauses
        ?.find(({ token }) => token === typescript_1.default.SyntaxKind.ExtendsKeyword)
        ?.types[0]?.expression;
    if (!expression)
        return undefined;
    const seen = new Set();
    let steps = 0;
    while (expression) {
        check();
        steps += 1;
        if (steps > maxSteps)
            throw new source_analysis_1.SourceAnalyzerContractError('SOURCE_ANALYZER_AST_NODE_LIMIT');
        while (typescript_1.default.isParenthesizedExpression(expression))
            expression = expression.expression;
        let symbol = checker.getSymbolAtLocation(expression);
        if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
            symbol = checker.getAliasedSymbol(symbol);
        const declaration = symbol?.declarations?.find(typescript_1.default.isClassLike)
            ?? (typescript_1.default.isClassExpression(expression)
                ? checker.getTypeAtLocation(expression).getSymbol()?.declarations?.find(typescript_1.default.isClassLike)
                : undefined);
        if (declaration)
            return declaration;
        if (!symbol || seen.has(symbol))
            return undefined;
        seen.add(symbol);
        const aliases = symbol.declarations?.filter((candidate) => (typescript_1.default.isVariableDeclaration(candidate) && candidate.initializer !== undefined
            && typescript_1.default.isVariableDeclarationList(candidate.parent)
            && Boolean(candidate.parent.flags & typescript_1.default.NodeFlags.Const))) ?? [];
        if (aliases.length !== 1)
            return undefined;
        expression = aliases[0].initializer;
    }
    return undefined;
}
function unresolvedBaseExpression(node, checker, projectSources, check, maxSteps) {
    const seen = new Set();
    let current = node;
    let steps = 0;
    while (current && projectSources.has(current.getSourceFile()) && !seen.has(current)) {
        check();
        steps += 1;
        if (steps > maxSteps)
            throw new source_analysis_1.SourceAnalyzerContractError('SOURCE_ANALYZER_AST_NODE_LIMIT');
        seen.add(current);
        const expression = current.heritageClauses
            ?.find(({ token }) => token === typescript_1.default.SyntaxKind.ExtendsKeyword)?.types[0]?.expression;
        if (!expression)
            return undefined;
        const base = directBaseClass(current, checker, check, maxSteps);
        if (!base || !projectSources.has(base.getSourceFile()))
            return expression;
        current = base;
    }
    return undefined;
}
function hasInheritedClassVersion(node, checker, projectSources, check, maxSteps) {
    const seen = new Set();
    let current = directBaseClass(node, checker, check, maxSteps);
    let steps = 0;
    while (current && projectSources.has(current.getSourceFile()) && !seen.has(current)) {
        check();
        steps += 1;
        if (steps > maxSteps)
            throw new source_analysis_1.SourceAnalyzerContractError('SOURCE_ANALYZER_AST_NODE_LIMIT');
        seen.add(current);
        if (decorators(current).some((decorator) => {
            const name = (0, decorator_symbols_1.classifyNestJsRouteDecorator)(decorator, checker, check).candidate?.name;
            return name === 'Version' || name === 'Unknown';
        }))
            return true;
        current = directBaseClass(current, checker, check, maxSteps);
    }
    return false;
}
function effectiveControllerInChain(node, checker, projectSources, check, maxSteps) {
    const seen = new Set();
    let current = node;
    let steps = 0;
    while (current && projectSources.has(current.getSourceFile()) && !seen.has(current)) {
        check();
        steps += 1;
        if (steps > maxSteps)
            throw new source_analysis_1.SourceAnalyzerContractError('SOURCE_ANALYZER_AST_NODE_LIMIT');
        seen.add(current);
        for (const decorator of decorators(current)) {
            const classification = (0, decorator_symbols_1.classifyNestJsRouteDecorator)(decorator, checker, check);
            if (classification.candidate?.name === 'Controller'
                || classification.candidate?.name === 'Unknown')
                return { decorator, classification };
        }
        current = directBaseClass(current, checker, check, maxSteps);
    }
    return undefined;
}
function emptyAuthMetadata() {
    return {
        guardsPresent: false,
        guards: [],
        publicPresent: false,
        explicitPublic: false,
        rolesPresent: false,
        roles: [],
        dynamic: false,
        guardDynamic: false,
        publicDynamic: false,
        rolesDynamic: false,
        guardEvidence: [],
        publicEvidence: [],
        authorizationEvidence: [],
    };
}
function isUnresolvedStoredGuardDecorator(decorator, checker, projectSources, check) {
    const seen = new Set();
    const unwrap = (input) => {
        let current = input;
        while (typescript_1.default.isParenthesizedExpression(current) || typescript_1.default.isAsExpression(current)
            || typescript_1.default.isTypeAssertionExpression(current) || typescript_1.default.isSatisfiesExpression(current)
            || typescript_1.default.isNonNullExpression(current))
            current = current.expression;
        return current;
    };
    const expressionUsesGuardDecorator = (input) => {
        const expressions = [input];
        const visited = new Set();
        const assignments = new Map();
        const assignmentValues = (symbol) => {
            const cached = assignments.get(symbol);
            if (cached !== undefined)
                return cached ?? undefined;
            const values = [];
            let unresolved = false;
            const nodes = [...projectSources];
            while (nodes.length > 0) {
                check();
                const node = nodes.pop();
                if (typescript_1.default.isBinaryExpression(node) && !isNestedDestructuringDefault(node)
                    && assignmentTargetContainsSymbol(node.left, symbol, checker, check)) {
                    if (node.operatorToken.kind === typescript_1.default.SyntaxKind.EqualsToken) {
                        const assigned = assignmentValuesForSymbol(node.left, node.right, symbol, checker, projectSources, check);
                        if (assigned)
                            values.push(...assigned);
                        else
                            unresolved = true;
                    }
                    else if (node.operatorToken.kind >= typescript_1.default.SyntaxKind.FirstAssignment
                        && node.operatorToken.kind <= typescript_1.default.SyntaxKind.LastAssignment)
                        unresolved = true;
                }
                else if ((typescript_1.default.isForOfStatement(node) || typescript_1.default.isForInStatement(node))
                    && assignmentTargetContainsSymbol(node.initializer, symbol, checker, check)) {
                    if (typescript_1.default.isVariableDeclarationList(node.initializer))
                        unresolved = true;
                    else {
                        const assigned = assignmentValuesForSymbol(node.initializer, node.expression, symbol, checker, projectSources, check);
                        if (assigned)
                            values.push(...assigned);
                        else
                            unresolved = true;
                    }
                }
                typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
            }
            assignments.set(symbol, unresolved ? null : values);
            return unresolved ? undefined : values;
        };
        let steps = 0;
        while (expressions.length > 0) {
            check();
            steps += 1;
            if (steps > 64)
                return true;
            const candidate = unwrap(expressions.pop());
            if (typescript_1.default.isCallExpression(candidate)) {
                const resolved = (0, decorator_symbols_1.resolveDecoratorCallSymbol)(candidate, checker, check);
                if (resolved?.nestJsCommon
                    && (resolved.name === 'UseGuards' || resolved.name === 'applyDecorators'))
                    return true;
                expressions.push(...candidate.arguments.map((argument) => (typescript_1.default.isSpreadElement(argument) ? argument.expression : argument)));
                let calleeExpression = unwrap(candidate.expression);
                const calleeAliases = new Set();
                while (typescript_1.default.isIdentifier(calleeExpression)) {
                    let alias = checker.getSymbolAtLocation(calleeExpression);
                    if (alias?.flags && alias.flags & typescript_1.default.SymbolFlags.Alias)
                        alias = checker.getAliasedSymbol(alias);
                    if (!alias || calleeAliases.has(alias))
                        break;
                    calleeAliases.add(alias);
                    const declarations = alias.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
                    const declaration = declarations.length === 1 ? declarations[0] : undefined;
                    if (!declaration?.initializer || !projectSources.has(declaration.getSourceFile())
                        || !typescript_1.default.isVariableDeclarationList(declaration.parent)
                        || !(declaration.parent.flags & typescript_1.default.NodeFlags.Const))
                        break;
                    calleeExpression = unwrap(declaration.initializer);
                }
                if (typescript_1.default.isArrowFunction(calleeExpression) || typescript_1.default.isFunctionExpression(calleeExpression)) {
                    if (!typescript_1.default.isBlock(calleeExpression.body))
                        expressions.push(calleeExpression.body);
                    else {
                        const nodes = [...calleeExpression.body.statements];
                        while (nodes.length > 0) {
                            check();
                            const node = nodes.pop();
                            if (typescript_1.default.isReturnStatement(node) && node.expression)
                                expressions.push(node.expression);
                            else if (!typescript_1.default.isFunctionLike(node)) {
                                typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
                            }
                        }
                    }
                    continue;
                }
                let calleeSymbol = checker.getSymbolAtLocation(calleeExpression);
                if (calleeSymbol?.flags && calleeSymbol.flags & typescript_1.default.SymbolFlags.Alias) {
                    calleeSymbol = checker.getAliasedSymbol(calleeSymbol);
                }
                if (calleeSymbol?.declarations?.some(typescript_1.default.isMethodDeclaration))
                    return true;
                if (calleeSymbol?.declarations?.some((declaration) => (projectSources.has(declaration.getSourceFile())))) {
                    const values = assignmentValues(calleeSymbol);
                    if (!values)
                        return true;
                    expressions.push(...values);
                }
                for (const declaration of calleeSymbol?.declarations ?? []) {
                    if (!projectSources.has(declaration.getSourceFile()))
                        continue;
                    const callable = typescript_1.default.isFunctionDeclaration(declaration) && declaration.body
                        ? declaration
                        : typescript_1.default.isVariableDeclaration(declaration) && declaration.initializer
                            && (typescript_1.default.isArrowFunction(unwrap(declaration.initializer))
                                || typescript_1.default.isFunctionExpression(unwrap(declaration.initializer)))
                            ? unwrap(declaration.initializer)
                            : undefined;
                    if (!callable)
                        continue;
                    const body = callable.body;
                    if (!body)
                        continue;
                    if (!typescript_1.default.isBlock(body))
                        expressions.push(body);
                    else {
                        const nodes = [...body.statements];
                        while (nodes.length > 0) {
                            check();
                            const node = nodes.pop();
                            if (typescript_1.default.isReturnStatement(node) && node.expression)
                                expressions.push(node.expression);
                            else if (node !== callable && !typescript_1.default.isFunctionLike(node)) {
                                typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
                            }
                        }
                    }
                }
                continue;
            }
            if (typescript_1.default.isArrowFunction(candidate) || typescript_1.default.isFunctionExpression(candidate)) {
                if (!typescript_1.default.isBlock(candidate.body))
                    expressions.push(candidate.body);
                else {
                    const nodes = [...candidate.body.statements];
                    while (nodes.length > 0) {
                        check();
                        const node = nodes.pop();
                        if (typescript_1.default.isReturnStatement(node) && node.expression)
                            expressions.push(node.expression);
                        else if (!typescript_1.default.isFunctionLike(node)) {
                            typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
                        }
                    }
                }
                continue;
            }
            if (typescript_1.default.isIdentifier(candidate)) {
                let symbol = checker.getSymbolAtLocation(candidate);
                if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
                    symbol = checker.getAliasedSymbol(symbol);
                if (!symbol || visited.has(symbol))
                    continue;
                visited.add(symbol);
                if (symbol.declarations?.some((entry) => (typescript_1.default.isParameter(entry) && projectSources.has(entry.getSourceFile()))))
                    return true;
                const declaration = symbol.declarations?.find((entry) => (typescript_1.default.isVariableDeclaration(entry) && entry.initializer !== undefined
                    && projectSources.has(entry.getSourceFile())));
                if (declaration?.initializer)
                    expressions.push(declaration.initializer);
                if (symbol.declarations?.some((entry) => projectSources.has(entry.getSourceFile()))) {
                    const values = assignmentValues(symbol);
                    if (!values)
                        return true;
                    expressions.push(...values);
                }
                continue;
            }
            if (typescript_1.default.isConditionalExpression(candidate)) {
                expressions.push(candidate.whenTrue, candidate.whenFalse);
            }
            else if (typescript_1.default.isBinaryExpression(candidate)) {
                expressions.push(candidate.left, candidate.right);
            }
            else if (typescript_1.default.isArrayLiteralExpression(candidate)) {
                for (const element of candidate.elements) {
                    if (!typescript_1.default.isOmittedExpression(element)) {
                        expressions.push(typescript_1.default.isSpreadElement(element) ? element.expression : element);
                    }
                }
            }
            else if (typescript_1.default.isObjectLiteralExpression(candidate)) {
                for (const property of candidate.properties) {
                    if (typescript_1.default.isPropertyAssignment(property))
                        expressions.push(property.initializer);
                    else if (typescript_1.default.isSpreadAssignment(property))
                        expressions.push(property.expression);
                    else if (typescript_1.default.isShorthandPropertyAssignment(property))
                        expressions.push(property.name);
                }
            }
        }
        return false;
    };
    const mutableBindingUsesGuardDecorator = (symbol, declaration) => {
        let projectCache = MUTABLE_STORED_GUARD_CACHE.get(projectSources);
        if (!projectCache) {
            projectCache = new WeakMap();
            MUTABLE_STORED_GUARD_CACHE.set(projectSources, projectCache);
        }
        const cached = projectCache.get(symbol);
        if (cached !== undefined)
            return cached;
        let found = Boolean(declaration.initializer
            && expressionUsesGuardDecorator(declaration.initializer));
        const nodes = found ? [] : [...projectSources];
        while (nodes.length > 0 && !found) {
            const node = nodes.pop();
            check();
            if (typescript_1.default.isBinaryExpression(node) && !isNestedDestructuringDefault(node)
                && assignmentTargetContainsSymbol(node.left, symbol, checker, check)) {
                if (node.operatorToken.kind >= typescript_1.default.SyntaxKind.FirstAssignment
                    && node.operatorToken.kind <= typescript_1.default.SyntaxKind.LastAssignment) {
                    if (node.operatorToken.kind !== typescript_1.default.SyntaxKind.EqualsToken)
                        found = true;
                    else {
                        const assigned = assignmentValuesForSymbol(node.left, node.right, symbol, checker, projectSources, check);
                        found = !assigned || assigned.some(expressionUsesGuardDecorator);
                    }
                }
            }
            else if ((typescript_1.default.isForOfStatement(node) || typescript_1.default.isForInStatement(node))
                && assignmentTargetContainsSymbol(node.initializer, symbol, checker, check)) {
                if (typescript_1.default.isVariableDeclarationList(node.initializer))
                    found = true;
                else {
                    const assigned = assignmentValuesForSymbol(node.initializer, node.expression, symbol, checker, projectSources, check);
                    found = !assigned || assigned.some(expressionUsesGuardDecorator);
                }
            }
            typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
        }
        projectCache.set(symbol, found);
        return found;
    };
    let expression = decorator.expression;
    expression = unwrap(expression);
    if (typescript_1.default.isPropertyAccessExpression(expression) || typescript_1.default.isElementAccessExpression(expression)) {
        const receiver = unwrap(expression.expression);
        const namespace = typescript_1.default.isIdentifier(receiver)
            ? checker.getSymbolAtLocation(receiver)?.declarations?.some(typescript_1.default.isNamespaceImport) : false;
        let member = checker.getSymbolAtLocation(typescript_1.default.isPropertyAccessExpression(expression) ? expression.name : expression);
        if (member?.flags && member.flags & typescript_1.default.SymbolFlags.Alias)
            member = checker.getAliasedSymbol(member);
        const declarations = member?.declarations?.filter((declaration) => (projectSources.has(declaration.getSourceFile()))) ?? [];
        if (namespace && declarations.length > 0) {
            for (const declaration of declarations) {
                if (typescript_1.default.isVariableDeclaration(declaration)) {
                    if (!typescript_1.default.isVariableDeclarationList(declaration.parent)
                        || !(declaration.parent.flags & typescript_1.default.NodeFlags.Const))
                        return true;
                    if (declaration.initializer && expressionUsesGuardDecorator(declaration.initializer))
                        return true;
                }
                else if (typescript_1.default.isFunctionDeclaration(declaration) && declaration.body) {
                    const writes = [...projectSources];
                    while (writes.length > 0) {
                        check();
                        const node = writes.pop();
                        if (typescript_1.default.isBinaryExpression(node) && !isNestedDestructuringDefault(node)
                            && node.operatorToken.kind >= typescript_1.default.SyntaxKind.FirstAssignment
                            && node.operatorToken.kind <= typescript_1.default.SyntaxKind.LastAssignment
                            && member && assignmentTargetContainsSymbol(node.left, member, checker, check))
                            return true;
                        if ((typescript_1.default.isForOfStatement(node) || typescript_1.default.isForInStatement(node)) && member
                            && assignmentTargetContainsSymbol(node.initializer, member, checker, check))
                            return true;
                        typescript_1.default.forEachChild(node, (child) => { writes.push(child); });
                    }
                    const returns = [];
                    const staticTruth = (input) => {
                        let value = input;
                        while (typescript_1.default.isParenthesizedExpression(value) || typescript_1.default.isAsExpression(value)
                            || typescript_1.default.isTypeAssertionExpression(value) || typescript_1.default.isSatisfiesExpression(value)
                            || typescript_1.default.isNonNullExpression(value))
                            value = value.expression;
                        if (value.kind === typescript_1.default.SyntaxKind.TrueKeyword)
                            return true;
                        if (value.kind === typescript_1.default.SyntaxKind.FalseKeyword || value.kind === typescript_1.default.SyntaxKind.NullKeyword
                            || typescript_1.default.isVoidExpression(value))
                            return false;
                        if (typescript_1.default.isNumericLiteral(value))
                            return Number(value.text) !== 0;
                        if (typescript_1.default.isStringLiteral(value) || typescript_1.default.isNoSubstitutionTemplateLiteral(value)) {
                            return value.text.length > 0;
                        }
                        if (typescript_1.default.isIdentifier(value) && value.text === 'undefined'
                            && !checker.getSymbolAtLocation(value)?.declarations?.length)
                            return false;
                        return undefined;
                    };
                    const NORMAL = 1;
                    const RETURN = 2;
                    const BREAK = 4;
                    const CONTINUE = 8;
                    let flowDepth = 0;
                    let flowOverflow = false;
                    const collect = (statement) => {
                        check();
                        if (flowDepth >= 32) {
                            flowOverflow = true;
                            return NORMAL;
                        }
                        flowDepth += 1;
                        try {
                            if (typescript_1.default.isReturnStatement(statement)) {
                                if (statement.expression)
                                    returns.push(statement.expression);
                                return RETURN;
                            }
                            if (typescript_1.default.isBreakStatement(statement))
                                return BREAK;
                            if (typescript_1.default.isContinueStatement(statement))
                                return CONTINUE;
                            if (typescript_1.default.isBlock(statement)) {
                                let flow = NORMAL;
                                for (const child of statement.statements) {
                                    if (!(flow & NORMAL))
                                        break;
                                    flow = (flow & ~NORMAL) | collect(child);
                                }
                                return flow;
                            }
                            else if (typescript_1.default.isIfStatement(statement)) {
                                const condition = staticTruth(statement.expression);
                                if (condition === false) {
                                    return statement.elseStatement ? collect(statement.elseStatement) : NORMAL;
                                }
                                if (condition === true)
                                    return collect(statement.thenStatement);
                                return collect(statement.thenStatement)
                                    | (statement.elseStatement ? collect(statement.elseStatement) : NORMAL);
                            }
                            else if (typescript_1.default.isTryStatement(statement)) {
                                const start = returns.length;
                                const tryFlow = collect(statement.tryBlock);
                                const bodyFlow = statement.catchClause
                                    ? tryFlow | collect(statement.catchClause.block) : tryFlow;
                                const beforeFinally = returns.length;
                                const finallyFlow = statement.finallyBlock ? collect(statement.finallyBlock) : NORMAL;
                                if (!(finallyFlow & NORMAL))
                                    returns.splice(start, beforeFinally - start);
                                return (finallyFlow & ~NORMAL)
                                    | ((finallyFlow & NORMAL) ? bodyFlow : 0);
                            }
                            else if (typescript_1.default.isSwitchStatement(statement)) {
                                let flow = NORMAL;
                                for (const clause of statement.caseBlock.clauses) {
                                    let clauseFlow = NORMAL;
                                    for (const child of clause.statements) {
                                        if (!(clauseFlow & NORMAL))
                                            break;
                                        clauseFlow = (clauseFlow & ~NORMAL) | collect(child);
                                    }
                                    flow |= clauseFlow;
                                }
                                return flow;
                            }
                            else if (typescript_1.default.isWhileStatement(statement)) {
                                if (staticTruth(statement.expression) === false)
                                    return NORMAL;
                                return NORMAL | (collect(statement.statement) & RETURN);
                            }
                            else if (typescript_1.default.isForStatement(statement)) {
                                if (statement.condition && staticTruth(statement.condition) === false)
                                    return NORMAL;
                                return NORMAL | (collect(statement.statement) & RETURN);
                            }
                            else if (typescript_1.default.isDoStatement(statement)) {
                                const bodyFlow = collect(statement.statement);
                                return (bodyFlow & RETURN) | (bodyFlow === RETURN ? 0 : NORMAL);
                            }
                            else if (typescript_1.default.isForInStatement(statement) || typescript_1.default.isForOfStatement(statement)) {
                                return NORMAL | (collect(statement.statement) & RETURN);
                            }
                            return NORMAL;
                        }
                        finally {
                            flowDepth -= 1;
                        }
                    };
                    collect(declaration.body);
                    if (flowOverflow || returns.some(expressionUsesGuardDecorator))
                        return true;
                }
                else
                    return true;
            }
            return false;
        }
        return true;
    }
    while (typescript_1.default.isIdentifier(expression)) {
        check();
        let symbol = checker.getSymbolAtLocation(expression);
        if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
            symbol = checker.getAliasedSymbol(symbol);
        if (!symbol || seen.has(symbol))
            return false;
        seen.add(symbol);
        const declarations = symbol.declarations?.filter(typescript_1.default.isVariableDeclaration) ?? [];
        const declaration = declarations.length === 1 ? declarations[0] : undefined;
        if (!declaration || !projectSources.has(declaration.getSourceFile()))
            return false;
        if (!typescript_1.default.isVariableDeclarationList(declaration.parent)
            || !(declaration.parent.flags & typescript_1.default.NodeFlags.Const)) {
            return mutableBindingUsesGuardDecorator(symbol, declaration);
        }
        if (!declaration.initializer)
            return false;
        expression = unwrap(declaration.initializer);
    }
    if (typescript_1.default.isPropertyAccessExpression(expression) || typescript_1.default.isElementAccessExpression(expression)) {
        return true;
    }
    if (!typescript_1.default.isCallExpression(expression))
        return false;
    const resolved = (0, decorator_symbols_1.resolveDecoratorCallSymbol)(expression, checker, check);
    return Boolean(resolved?.nestJsCommon
        && (resolved.name === 'UseGuards' || resolved.name === 'applyDecorators'));
}
function ownAuthMetadata(node, checker, projectSources, config, check, maxSteps, maxDepth) {
    const result = emptyAuthMetadata();
    const resolvingWrappers = new Set();
    const applyResolved = (resolved, evidence, depth) => {
        check();
        if (depth > maxDepth) {
            result.guardDynamic = true;
            return true;
        }
        if (resolved.name === 'applyDecorators' && resolved.trustedNestJsCommon) {
            for (const argument of resolved.call.arguments) {
                if (!typescript_1.default.isCallExpression(argument)) {
                    result.guardDynamic = true;
                    continue;
                }
                const nested = (0, decorator_symbols_1.resolveDecoratorCallSymbol)(argument, checker, check);
                if (nested) {
                    if (!applyResolved(nested, evidence, depth + 1))
                        result.guardDynamic = true;
                }
                else
                    result.guardDynamic = true;
            }
            return true;
        }
        if (resolved.name === 'UseGuards' && resolved.trustedNestJsCommon) {
            result.guardsPresent = true;
            result.guardEvidence.push(evidence);
            if (resolved.call.arguments.some(typescript_1.default.isSpreadElement)) {
                result.guardDynamic = true;
                return true;
            }
            for (const argument of resolved.call.arguments) {
                const symbol = (0, decorator_symbols_1.resolveStaticSymbolName)(argument, checker, check);
                if (symbol)
                    result.guards.push(symbol);
                else {
                    result.guardDynamic = true;
                }
            }
            return true;
        }
        if (resolved.nestJsCommon
            && (resolved.name === 'UseGuards' || resolved.name === 'applyDecorators')) {
            result.guardDynamic = true;
            return true;
        }
        const wrapperCall = (0, decorator_symbols_1.resolveStaticDecoratorWrapperCall)(resolved.call, checker, projectSources, check);
        if (config.public_decorators.includes(resolved.name)) {
            result.publicPresent = true;
            result.explicitPublic = false;
            result.publicDynamic = false;
            result.publicEvidence = [evidence];
            if (wrapperCall && (!wrapperCall.stable || wrapperCall.dynamic))
                result.publicDynamic = true;
            else if (resolved.call.arguments.length === 0)
                result.explicitPublic = true;
            else
                result.publicDynamic = true;
            return true;
        }
        if (config.roles_decorators.includes(resolved.name)) {
            result.rolesPresent = true;
            result.roles = [];
            result.rolesDynamic = Boolean(wrapperCall && (!wrapperCall.stable || wrapperCall.dynamic));
            result.authorizationEvidence = [evidence];
            for (const argument of resolved.call.arguments) {
                if (typescript_1.default.isSpreadElement(argument)) {
                    result.rolesDynamic = true;
                    continue;
                }
                const values = (0, static_string_resolver_1.resolveStaticStrings)(argument, checker, projectSources, { check, maxSteps });
                if (values)
                    result.roles.push(...values);
                else
                    result.rolesDynamic = true;
            }
            return true;
        }
        if (wrapperCall?.dynamic) {
            result.guardDynamic = true;
            return true;
        }
        const wrapper = wrapperCall?.call
            && (0, decorator_symbols_1.resolveDecoratorCallSymbol)(wrapperCall.call, checker, check);
        if (!wrapper)
            return false;
        if (!wrapperCall.stable || resolvingWrappers.has(wrapperCall.symbol)
            || depth >= maxDepth) {
            result.guardDynamic = true;
            return true;
        }
        resolvingWrappers.add(wrapperCall.symbol);
        try {
            if (!applyResolved(wrapper, evidence, depth + 1))
                result.guardDynamic = true;
            return true;
        }
        finally {
            resolvingWrappers.delete(wrapperCall.symbol);
        }
    };
    for (const decorator of [...decorators(node)].reverse()) {
        const bareName = (0, decorator_symbols_1.resolveBareDecoratorName)(decorator, checker, check);
        if (bareName && config.public_decorators.includes(bareName)) {
            const stable = (0, decorator_symbols_1.isBareDecoratorBindingStable)(decorator, checker, projectSources, check);
            result.publicPresent = true;
            result.explicitPublic = stable;
            result.publicDynamic = !stable;
            result.publicEvidence = [decorator];
            continue;
        }
        const resolved = (0, decorator_symbols_1.resolveDecoratorSymbol)(decorator, checker, check, projectSources);
        if (resolved) {
            applyResolved(resolved, decorator, 0);
        }
        else if (isUnresolvedStoredGuardDecorator(decorator, checker, projectSources, check)) {
            result.guardDynamic = true;
        }
    }
    result.dynamic = result.guardDynamic || result.publicDynamic || result.rolesDynamic;
    return result;
}
function effectiveClassAuthMetadata(node, checker, projectSources, config, check, maxSteps, maxDepth) {
    const result = emptyAuthMetadata();
    const seen = new Set();
    let current = node;
    let steps = 0;
    while (current && projectSources.has(current.getSourceFile()) && !seen.has(current)) {
        check();
        steps += 1;
        if (steps > maxSteps)
            throw new source_analysis_1.SourceAnalyzerContractError('SOURCE_ANALYZER_AST_NODE_LIMIT');
        seen.add(current);
        const own = ownAuthMetadata(current, checker, projectSources, config, check, maxSteps, maxDepth);
        result.guardDynamic ||= own.guardDynamic;
        result.dynamic ||= own.guardDynamic;
        if (own.guardsPresent) {
            result.guardsPresent = true;
            result.guards = [...own.guards, ...result.guards];
            result.guardEvidence = [...own.guardEvidence, ...result.guardEvidence];
        }
        if (!result.publicPresent && own.publicPresent) {
            result.publicPresent = true;
            result.explicitPublic = own.explicitPublic;
            result.publicDynamic = own.publicDynamic;
            result.dynamic ||= own.publicDynamic;
            result.publicEvidence.push(...own.publicEvidence);
        }
        if (!result.rolesPresent && own.rolesPresent) {
            result.rolesPresent = true;
            result.roles = own.roles;
            result.rolesDynamic = own.rolesDynamic;
            result.dynamic ||= own.rolesDynamic;
            result.authorizationEvidence.push(...own.authorizationEvidence);
        }
        const baseExpression = current.heritageClauses
            ?.find(({ token }) => token === typescript_1.default.SyntaxKind.ExtendsKeyword)?.types[0]?.expression;
        const base = directBaseClass(current, checker, check, maxSteps);
        if (baseExpression && !base) {
            result.guardDynamic = true;
            result.dynamic = true;
            break;
        }
        if (base && !projectSources.has(base.getSourceFile())) {
            result.guardDynamic = true;
            result.dynamic = true;
            break;
        }
        current = base;
    }
    return result;
}
function composeAuth(classMetadata, methodMetadata, config, globalGuardFound) {
    const guards = [...classMetadata.guards, ...methodMetadata.guards];
    const explicitPublic = methodMetadata.publicPresent
        ? methodMetadata.explicitPublic
        : classMetadata.explicitPublic;
    const roles = methodMetadata.rolesPresent ? methodMetadata.roles : classMetadata.roles;
    const effectivePublicDynamic = methodMetadata.publicPresent
        ? methodMetadata.publicDynamic
        : classMetadata.publicDynamic;
    const effectiveRolesDynamic = methodMetadata.rolesPresent
        ? methodMetadata.rolesDynamic
        : classMetadata.rolesDynamic;
    const authenticationDynamic = classMetadata.guardDynamic || methodMetadata.guardDynamic
        || effectivePublicDynamic;
    const authorizationDynamic = effectiveRolesDynamic;
    const dynamic = authenticationDynamic || authorizationDynamic;
    const analyzedGuards = guards.map((symbol) => {
        const mapping = config.guard_mappings[symbol];
        return {
            symbol,
            ...(mapping ? { authKind: (0, auth_config_1.authKindToIr)(mapping.auth_kind) } : {}),
        };
    });
    const unknownGuard = analyzedGuards.some(({ authKind }) => authKind === undefined);
    const capabilityReasons = [];
    if (globalGuardFound)
        capabilityReasons.push('Global NestJS guards are not analyzed.');
    if (authenticationDynamic)
        capabilityReasons.push('Dynamic authentication metadata was not inferred.');
    if (authorizationDynamic)
        capabilityReasons.push('Dynamic role metadata was not inferred.');
    if (unknownGuard)
        capabilityReasons.push('Unmapped NestJS guards remain unknown.');
    if (!explicitPublic && guards.length === 0) {
        capabilityReasons.push('Local guard absence does not prove a public route.');
    }
    if (classMetadata.rolesPresent || methodMetadata.rolesPresent) {
        capabilityReasons.push('Role metadata does not prove authorization enforcement.');
    }
    const enforcementConfidence = !globalGuardFound && !dynamic
        && (explicitPublic || (guards.length > 0 && !unknownGuard)) ? 'high' : 'unknown';
    const analysis = {
        guards: analyzedGuards,
        explicitPublic,
        roles,
        enforcementConfidence,
        capabilityReasons,
    };
    let auth;
    let exposure;
    if (explicitPublic && !authenticationDynamic && !globalGuardFound) {
        auth = { mode: 'none', alternatives: [], analysis };
        exposure = 'public';
    }
    else if (guards.length > 0 && !unknownGuard && !authenticationDynamic && !globalGuardFound) {
        auth = {
            mode: 'alternatives',
            alternatives: [{
                    anonymous: false,
                    schemes: analyzedGuards.map(({ symbol, authKind }) => ({
                        name: symbol,
                        kind: authKind,
                        scopes: [],
                        capability: 'supported',
                    })),
                }],
            analysis,
        };
        exposure = 'authenticated';
    }
    else {
        auth = { mode: 'unknown', alternatives: [], analysis };
        exposure = 'unknown';
    }
    return {
        auth,
        exposure,
        evidence: [
            ...[
                ...classMetadata.guardEvidence,
                ...classMetadata.publicEvidence,
                ...methodMetadata.guardEvidence,
                ...methodMetadata.publicEvidence,
            ].map((decorator) => ({ decorator, capability: 'authentication' })),
            ...[
                ...classMetadata.authorizationEvidence,
                ...methodMetadata.authorizationEvidence,
            ].map((decorator) => ({ decorator, capability: 'authorization' })),
        ],
    };
}
function comparableAuth(exposure, auth) {
    const sortedSet = (values) => [...new Set(values)].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
    return JSON.stringify([exposure, {
            ...auth,
            ...(auth.analysis ? {
                analysis: {
                    ...auth.analysis,
                    roles: sortedSet(auth.analysis.roles),
                    capabilityReasons: sortedSet(auth.analysis.capabilityReasons),
                },
            } : {}),
        }]);
}
function methodsIncludingBaseChain(node, checker, projectSources, useDefineForClassFields, check, maxSteps) {
    const symbolKey = Symbol('symbol-method-key');
    const unwrapPropertyExpression = (expression) => {
        let current = expression;
        while (typescript_1.default.isParenthesizedExpression(current) || typescript_1.default.isAsExpression(current)
            || typescript_1.default.isTypeAssertionExpression(current) || typescript_1.default.isSatisfiesExpression(current)
            || typescript_1.default.isNonNullExpression(current))
            current = current.expression;
        return current;
    };
    const staticName = (name) => (typescript_1.default.isIdentifier(name) || typescript_1.default.isStringLiteral(name) || typescript_1.default.isNumericLiteral(name)
        || typescript_1.default.isNoSubstitutionTemplateLiteral(name) ? name.text : undefined);
    const destructuredInitializer = (binding) => {
        const steps = [];
        let current = binding;
        let declaration;
        while (true) {
            if (current.dotDotDotToken || current.initializer)
                return undefined;
            const pattern = current.parent;
            if (typescript_1.default.isArrayBindingPattern(pattern)) {
                const index = pattern.elements.indexOf(current);
                if (index < 0)
                    return undefined;
                steps.push({ kind: 'array', index });
            }
            else if (typescript_1.default.isObjectBindingPattern(pattern)) {
                const key = current.propertyName && staticName(current.propertyName)
                    || (typescript_1.default.isIdentifier(current.name) ? current.name.text : undefined);
                if (key === undefined)
                    return undefined;
                steps.push({ kind: 'object', key });
            }
            else
                return undefined;
            if (typescript_1.default.isVariableDeclaration(pattern.parent)) {
                declaration = pattern.parent;
                break;
            }
            if (!typescript_1.default.isBindingElement(pattern.parent))
                return undefined;
            current = pattern.parent;
        }
        if (!declaration.initializer || !projectSources.has(declaration.getSourceFile())
            || !(declaration.parent.flags & typescript_1.default.NodeFlags.Const))
            return undefined;
        let value = declaration.initializer;
        for (const step of steps.reverse()) {
            const node = unwrapPropertyExpression(value);
            if (step.kind === 'array') {
                if (!typescript_1.default.isArrayLiteralExpression(node) || node.elements.some(typescript_1.default.isSpreadElement))
                    return undefined;
                const element = node.elements[step.index];
                if (!element || typescript_1.default.isOmittedExpression(element) || typescript_1.default.isSpreadElement(element))
                    return undefined;
                value = element;
                continue;
            }
            if (step.key === '__proto__' || !typescript_1.default.isObjectLiteralExpression(node)
                || node.properties.some((property) => (typescript_1.default.isSpreadAssignment(property) || !property.name || staticName(property.name) === undefined)))
                return undefined;
            const property = [...node.properties].reverse().find((candidate) => (candidate.name && staticName(candidate.name) === step.key));
            if (!property)
                return undefined;
            if (typescript_1.default.isPropertyAssignment(property))
                value = property.initializer;
            else if (typescript_1.default.isShorthandPropertyAssignment(property))
                value = property.name;
            else
                return undefined;
        }
        return value;
    };
    const numericPropertyValue = (expression, resolving = new Set(), depth = 0) => {
        check();
        if (depth > 64)
            return undefined;
        const node = unwrapPropertyExpression(expression);
        const value = typescript_1.default.isNumericLiteral(node)
            ? Number(node.text)
            : typescript_1.default.isBigIntLiteral(node)
                ? BigInt(node.text.slice(0, -1))
                : undefined;
        if (value !== undefined)
            return value;
        if (typescript_1.default.isPrefixUnaryExpression(node)
            && (node.operator === typescript_1.default.SyntaxKind.PlusToken || node.operator === typescript_1.default.SyntaxKind.MinusToken)) {
            const operand = numericPropertyValue(node.operand, resolving, depth + 1);
            if (operand === undefined || (node.operator === typescript_1.default.SyntaxKind.PlusToken && typeof operand === 'bigint')) {
                return undefined;
            }
            return node.operator === typescript_1.default.SyntaxKind.MinusToken ? -operand : Number(operand);
        }
        if (!typescript_1.default.isIdentifier(node))
            return undefined;
        let symbol = checker.getSymbolAtLocation(node);
        if (!symbol)
            return undefined;
        if (symbol.flags & typescript_1.default.SymbolFlags.Alias)
            symbol = checker.getAliasedSymbol(symbol);
        if (resolving.has(symbol))
            return undefined;
        const declarations = symbol.declarations ?? [];
        if (declarations.length !== 1)
            return undefined;
        const declaration = declarations[0];
        const initializer = typescript_1.default.isVariableDeclaration(declaration)
            ? declaration.initializer
            : typescript_1.default.isBindingElement(declaration) ? destructuredInitializer(declaration) : undefined;
        if (!initializer || !projectSources.has(declaration.getSourceFile())
            || (typescript_1.default.isVariableDeclaration(declaration)
                && !(declaration.parent.flags & typescript_1.default.NodeFlags.Const)))
            return undefined;
        resolving.add(symbol);
        const result = numericPropertyValue(initializer, resolving, depth + 1);
        resolving.delete(symbol);
        return result;
    };
    const propertyKey = ({ name }) => {
        if (!name)
            return undefined;
        if (typescript_1.default.isComputedPropertyName(name)) {
            const numeric = numericPropertyValue(name.expression);
            if (numeric !== undefined)
                return String(numeric);
            const values = (0, static_string_resolver_1.resolveStaticStrings)(name.expression, checker, projectSources, { check, maxSteps });
            if (values?.length === 1)
                return values[0];
            return checker.getTypeAtLocation(name.expression).flags & typescript_1.default.TypeFlags.ESSymbolLike
                ? symbolKey
                : undefined;
        }
        return typescript_1.default.isIdentifier(name) || typescript_1.default.isStringLiteral(name) || typescript_1.default.isNumericLiteral(name)
            || typescript_1.default.isNoSubstitutionTemplateLiteral(name) ? name.text : undefined;
    };
    const concrete = (method) => Boolean(method.body)
        && !method.modifiers?.some(({ kind }) => (kind === typescript_1.default.SyntaxKind.StaticKeyword || kind === typescript_1.default.SyntaxKind.AbstractKeyword));
    const runtimeMember = (member) => {
        const modifiers = typescript_1.default.canHaveModifiers(member) ? typescript_1.default.getModifiers(member) : undefined;
        return !modifiers?.some(({ kind }) => (kind === typescript_1.default.SyntaxKind.StaticKeyword || kind === typescript_1.default.SyntaxKind.AbstractKeyword
            || kind === typescript_1.default.SyntaxKind.DeclareKeyword)) && ((typescript_1.default.isPropertyDeclaration(member)
            && (useDefineForClassFields || member.initializer !== undefined)) || ((typescript_1.default.isMethodDeclaration(member) || typescript_1.default.isGetAccessorDeclaration(member) || typescript_1.default.isSetAccessorDeclaration(member))
            && Boolean(member.body)));
    };
    const methods = [];
    const shadowed = new Set();
    const seen = new Set();
    let current = node;
    let steps = 0;
    while (current && projectSources.has(current.getSourceFile()) && !seen.has(current)) {
        check();
        steps += 1;
        if (steps > maxSteps)
            throw new source_analysis_1.SourceAnalyzerContractError('SOURCE_ANALYZER_AST_NODE_LIMIT');
        seen.add(current);
        methods.push(...current.members.filter(typescript_1.default.isMethodDeclaration).filter(concrete)
            .filter((method) => {
            const key = propertyKey(method);
            return key !== symbolKey && (key === undefined || !shadowed.has(key));
        }));
        for (const member of current.members.filter(runtimeMember)) {
            const key = propertyKey(member);
            if (typeof key === 'string')
                shadowed.add(key);
        }
        current = directBaseClass(current, checker, check, maxSteps);
    }
    return methods;
}
function mapLoaderError(error) {
    const code = error.diagnostics[0]?.code;
    if (code === 'TS_PROJECT_CANCELLED')
        return 'SOURCE_ANALYZER_CANCELLED';
    if (code === 'TS_PROJECT_TIMEOUT')
        return 'SOURCE_ANALYZER_TIMEOUT';
    if (code === 'TS_PROJECT_PATH_OUTSIDE_ROOT')
        return 'SOURCE_ANALYZER_INPUT_OUTSIDE_ROOT';
    if (code === 'TS_PROJECT_FILE_LIMIT')
        return 'SOURCE_ANALYZER_FILE_LIMIT';
    if (code === 'TS_PROJECT_FILE_BYTES_LIMIT')
        return 'SOURCE_ANALYZER_FILE_BYTES_LIMIT';
    if (code === 'TS_PROJECT_TOTAL_BYTES_LIMIT')
        return 'SOURCE_ANALYZER_TOTAL_BYTES_LIMIT';
    if (code === 'TS_PROJECT_AST_NODE_LIMIT')
        return 'SOURCE_ANALYZER_AST_NODE_LIMIT';
    if (code === 'TS_PROJECT_DEPTH_LIMIT')
        return 'SOURCE_ANALYZER_DEPTH_LIMIT';
    if (code === 'TS_PROJECT_DIAGNOSTIC_LIMIT')
        return 'SOURCE_ANALYZER_DIAGNOSTIC_LIMIT';
    if (['TS_PROJECT_INVALID_CONFIG', 'TS_PROJECT_CONFIG_MISSING', 'TS_PROJECT_EXTENSION_UNSUPPORTED',
        'TS_PROJECT_EXTENDS_UNSUPPORTED'].includes(code ?? ''))
        return 'SOURCE_ANALYZER_INPUT_INVALID';
    return 'SOURCE_ANALYZER_INTERNAL';
}
async function loadProject(workspaceRoot, tsconfigPath, context) {
    try {
        const loaded = await (0, project_loader_1.loadTypeScriptProject)({
            workspaceRoot,
            tsconfigPath,
            limits: context.limits,
            cancellationSignal: context.cancellationSignal,
        });
        if (loaded.diagnostics.some(({ code }) => code === 'TS_PROJECT_TYPESCRIPT_DIAGNOSTIC')) {
            throw new source_analysis_1.SourceAnalyzerContractError('SOURCE_ANALYZER_INPUT_INVALID');
        }
        return loaded;
    }
    catch (error) {
        if (error instanceof source_analysis_1.SourceAnalyzerContractError)
            throw error;
        if (error instanceof project_loader_1.TypeScriptProjectLoadError)
            throw new source_analysis_1.SourceAnalyzerContractError(mapLoaderError(error));
        throw new source_analysis_1.SourceAnalyzerContractError('SOURCE_ANALYZER_INTERNAL');
    }
}
async function analyze(context, authConfig) {
    if (context.entrypoints.length !== 1) {
        throw new source_analysis_1.SourceAnalyzerContractError('SOURCE_ANALYZER_INPUT_INVALID');
    }
    const deadline = performance.now() + context.limits.timeoutMs;
    const check = () => {
        if (context.cancellationSignal?.aborted) {
            throw new source_analysis_1.SourceAnalyzerContractError('SOURCE_ANALYZER_CANCELLED');
        }
        if (performance.now() >= deadline)
            throw new source_analysis_1.SourceAnalyzerContractError('SOURCE_ANALYZER_TIMEOUT');
    };
    const loaded = await loadProject(context.workspaceRoot, context.entrypoints[0], context);
    const checker = loaded.program.getTypeChecker();
    const compilerOptions = loaded.program.getCompilerOptions();
    const useDefineForClassFields = compilerOptions.useDefineForClassFields
        ?? (compilerOptions.target ?? typescript_1.default.ScriptTarget.ES5) >= typescript_1.default.ScriptTarget.ES2022;
    const projectSources = new Set(loaded.sourceFiles.filter((sourceFile) => (!sourceFile.isDeclarationFile && !sourceFile.fileName.replaceAll('\\', '/').includes('/node_modules/'))));
    const localFunctions = new Map();
    for (const sourceFile of projectSources) {
        if (!typescript_1.default.isExternalModule(sourceFile))
            continue;
        const nodes = [sourceFile];
        while (nodes.length > 0) {
            const node = nodes.pop();
            check();
            if (typescript_1.default.isFunctionDeclaration(node) && node.body && node.name
                && !node.modifiers?.some(({ kind }) => (kind === typescript_1.default.SyntaxKind.ExportKeyword || kind === typescript_1.default.SyntaxKind.DefaultKeyword))) {
                const symbol = resolvedSymbolAt(node.name, checker);
                const bodies = symbol?.declarations?.filter((declaration) => (typescript_1.default.isFunctionDeclaration(declaration) && declaration.body)) ?? [];
                if (symbol && bodies.length === 1)
                    localFunctions.set(symbol, node);
            }
            typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
        }
    }
    const referencedLocalFunctions = new Set();
    if (localFunctions.size > 0) {
        for (const sourceFile of projectSources) {
            const nodes = [sourceFile];
            while (nodes.length > 0) {
                const node = nodes.pop();
                check();
                if (typescript_1.default.isIdentifier(node)) {
                    const symbol = resolvedSymbolAt(node, checker);
                    const declaration = symbol ? localFunctions.get(symbol) : undefined;
                    if (symbol && declaration) {
                        let insideDeclaration = false;
                        for (let parent = node; parent; parent = parent.parent) {
                            if (parent === declaration) {
                                insideDeclaration = true;
                                break;
                            }
                            if (typescript_1.default.isSourceFile(parent))
                                break;
                        }
                        if (!insideDeclaration)
                            referencedLocalFunctions.add(symbol);
                    }
                }
                typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
            }
        }
    }
    const provablyUninvokedLocalFunctions = new Set([...localFunctions.keys()].filter((symbol) => (!referencedLocalFunctions.has(symbol))));
    const isInsideProvablyUninvokedFunction = (node) => {
        for (let parent = node.parent; !typescript_1.default.isSourceFile(parent); parent = parent.parent) {
            if (typescript_1.default.isFunctionDeclaration(parent) && parent.name) {
                const symbol = resolvedSymbolAt(parent.name, checker);
                if (symbol && provablyUninvokedLocalFunctions.has(symbol))
                    return true;
            }
        }
        return false;
    };
    const providerRegistrations = registeredProviderObjects(checker, projectSources, check);
    const providerCandidates = [
        ...providerRegistrations.candidates, ...providerRegistrations.providers,
    ];
    const identifierReferences = providerCandidates.length > 0
        ? indexIdentifierReferences(checker, projectSources, check) : new Map();
    const potentialGlobalProvider = providerCandidates.find((candidate) => (containsCanonicalProviderToken(candidate, checker, projectSources, check, context.limits.maxAstNodes, identifierReferences)));
    const registeredProviders = providerRegistrations.providers;
    const operations = new Map();
    const diagnostics = [];
    const unresolvedOperations = [];
    let unresolvedMethodCount = 0;
    let inspectedNodes = 0;
    let globalGuardFound = false;
    const checkpoint = async () => {
        inspectedNodes += 1;
        if (inspectedNodes % 256 === 0)
            await new Promise((resolve) => setImmediate(resolve));
        check();
    };
    const consume = (count = 1) => {
        check();
        if (operations.size + unresolvedMethodCount + count > context.limits.maxOperations) {
            throw new source_analysis_1.SourceAnalyzerContractError('SOURCE_ANALYZER_OPERATION_LIMIT');
        }
    };
    const addDiagnostic = (code, node) => {
        if (diagnostics.length >= context.limits.maxDiagnostics) {
            throw new source_analysis_1.SourceAnalyzerContractError('SOURCE_ANALYZER_DIAGNOSTIC_LIMIT');
        }
        diagnostics.push({
            code,
            safeMessage: code === 'SOURCE_ANALYZER_DYNAMIC_ROUTE'
                ? 'A dynamic route expression could not be resolved statically.'
                : code === 'SOURCE_ANALYZER_DYNAMIC_AUTH_METADATA'
                    ? 'Dynamic authentication metadata could not be resolved statically.'
                    : code === 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED'
                        ? 'Global NestJS guards are not analyzed.'
                        : 'A source decorator is not supported by this analyzer.',
            ...sourceLocation(node, context.workspaceRoot),
        });
    };
    const unsupportedGlobalGuard = potentialGlobalProvider
        ?? providerRegistrations.externalModuleImport
        ?? providerRegistrations.unresolvedProvider;
    if (unsupportedGlobalGuard) {
        addDiagnostic('SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED', unsupportedGlobalGuard);
        globalGuardFound = true;
    }
    const addUnresolved = (methods, node, reason) => {
        consume(methods.length);
        unresolvedMethodCount += methods.length;
        unresolvedOperations.push({
            methods: [...methods], path: null, reason, ...sourceLocation(node, context.workspaceRoot),
        });
    };
    for (const sourceFile of projectSources) {
        const nodes = [sourceFile];
        while (nodes.length > 0) {
            const node = nodes.pop();
            await checkpoint();
            if (typescript_1.default.isCallExpression(node)
                && !staticallyUnreachable(node)
                && !isInsideProvablyUninvokedFunction(node)
                && (0, decorator_symbols_1.isNestJsUseGlobalGuardsCall)(node, checker, check, projectSources)) {
                if (!globalGuardFound)
                    addDiagnostic('SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED', node.expression);
                globalGuardFound = true;
            }
            const propertyNames = typescript_1.default.isPropertyAssignment(node) && typescript_1.default.isComputedPropertyName(node.name)
                ? (() => {
                    if ((0, decorator_symbols_1.isDefinitelyNonProvidePropertyKey)(node.name.expression))
                        return [''];
                    const key = (0, decorator_symbols_1.resolveStaticPropertyKey)(node.name.expression, checker, check);
                    return key === undefined
                        ? (0, static_string_resolver_1.resolveStaticStrings)(node.name.expression, checker, projectSources, {
                            check, maxSteps: context.limits.maxAstNodes,
                        })
                        : [key];
                })()
                : undefined;
            const providerKeyPossible = typescript_1.default.isPropertyAssignment(node) && ((typescript_1.default.isIdentifier(node.name) || typescript_1.default.isStringLiteral(node.name))
                ? node.name.text === 'provide'
                : typescript_1.default.isComputedPropertyName(node.name) && (propertyNames === undefined
                    || (propertyNames.length === 1 && propertyNames[0] === 'provide')));
            const globalGuardProvider = (typescript_1.default.isPropertyAssignment(node) && providerKeyPossible
                && isProviderRegistration(node, registeredProviders)
                && (0, decorator_symbols_1.containsStaticSymbolFrom)(node.initializer, checker, check, '@nestjs/core', 'APP_GUARD', projectSources)) || (typescript_1.default.isShorthandPropertyAssignment(node) && node.name.text === 'provide'
                && isProviderRegistration(node, registeredProviders)
                && (0, decorator_symbols_1.isStaticShorthandSymbolFrom)(node, checker, check, '@nestjs/core', 'APP_GUARD', projectSources));
            if (globalGuardProvider) {
                if (!globalGuardFound)
                    addDiagnostic('SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED', node);
                globalGuardFound = true;
            }
            typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
        }
    }
    for (const sourceFile of projectSources) {
        const nodes = [...sourceFile.statements].reverse();
        while (nodes.length > 0) {
            const statement = nodes.pop();
            await checkpoint();
            const children = [];
            typescript_1.default.forEachChild(statement, (child) => { children.push(child); });
            nodes.push(...children.reverse());
            if (!typescript_1.default.isClassLike(statement))
                continue;
            const classDecorators = decorators(statement);
            const classClassifications = classDecorators.map((decorator) => ((0, decorator_symbols_1.classifyNestJsRouteDecorator)(decorator, checker, check)));
            const classCandidates = classClassifications.map(({ candidate }) => candidate);
            const classVersioned = classCandidates.some((match) => (match?.name === 'Version' || match?.name === 'Unknown'))
                || hasInheritedClassVersion(statement, checker, projectSources, check, context.limits.maxAstNodes);
            for (const [index, decorator] of classDecorators.entries()) {
                if (classClassifications[index]?.unsupported) {
                    addDiagnostic('SOURCE_ANALYZER_UNSUPPORTED_DECORATOR', decorator);
                }
            }
            const effectiveController = effectiveControllerInChain(statement, checker, projectSources, check, context.limits.maxAstNodes);
            const unresolvedBase = unresolvedBaseExpression(statement, checker, projectSources, check, context.limits.maxAstNodes);
            if (!effectiveController) {
                if (unresolvedBase) {
                    let foundRoute = false;
                    for (const method of statement.members.filter(typescript_1.default.isMethodDeclaration)) {
                        for (const decorator of decorators(method)) {
                            const candidate = (0, decorator_symbols_1.classifyNestJsRouteDecorator)(decorator, checker, check).candidate;
                            const methods = candidate && routeMethods(candidate.name);
                            if (methods?.length) {
                                addUnresolved(methods, decorator, 'SOURCE_ANALYZER_DYNAMIC_ROUTE');
                                foundRoute = true;
                                break;
                            }
                        }
                    }
                    const ownAuth = ownAuthMetadata(statement, checker, projectSources, authConfig, check, context.limits.maxAstNodes, context.limits.maxAnalysisDepth);
                    const hasAuthEvidence = ownAuth.guardsPresent || ownAuth.publicPresent
                        || ownAuth.rolesPresent || ownAuth.dynamic;
                    if (foundRoute || hasAuthEvidence) {
                        addUnresolved(canonical_route_1.HTTP_METHODS, unresolvedBase, 'SOURCE_ANALYZER_DYNAMIC_ROUTE');
                        addDiagnostic('SOURCE_ANALYZER_DYNAMIC_ROUTE', unresolvedBase);
                        if (hasAuthEvidence)
                            addDiagnostic('SOURCE_ANALYZER_DYNAMIC_AUTH_METADATA', statement);
                    }
                }
                continue;
            }
            const trustedController = effectiveController.classification.route?.name === 'Controller';
            const classAuthMetadata = trustedController
                ? effectiveClassAuthMetadata(statement, checker, projectSources, authConfig, check, context.limits.maxAstNodes, context.limits.maxAnalysisDepth)
                : emptyAuthMetadata();
            if (trustedController && classAuthMetadata.dynamic) {
                addDiagnostic('SOURCE_ANALYZER_DYNAMIC_AUTH_METADATA', statement);
            }
            const controllers = trustedController
                ? [{ decorator: effectiveController.decorator, match: effectiveController.classification.route }]
                : [];
            if (unresolvedBase) {
                addUnresolved(canonical_route_1.HTTP_METHODS, unresolvedBase, 'SOURCE_ANALYZER_DYNAMIC_ROUTE');
                addDiagnostic('SOURCE_ANALYZER_DYNAMIC_ROUTE', unresolvedBase);
            }
            for (const method of methodsIncludingBaseChain(statement, checker, projectSources, useDefineForClassFields, check, context.limits.maxAstNodes)) {
                await checkpoint();
                const methodDecorators = decorators(method);
                const classifications = methodDecorators.map((decorator) => ((0, decorator_symbols_1.classifyNestJsRouteDecorator)(decorator, checker, check)));
                const candidates = classifications.map(({ candidate }) => candidate);
                const matches = classifications.map(({ route }) => route);
                const versioned = classVersioned || candidates.some((match) => (match?.name === 'Version' || match?.name === 'Unknown'));
                const effectiveRoute = candidates.findIndex((match) => Boolean(match && (routeMethods(match.name) || match.name === 'Search')));
                if (effectiveRoute === -1)
                    continue;
                for (const [index, methodDecorator] of methodDecorators.entries()) {
                    if (classifications[index]?.unsupported) {
                        addDiagnostic('SOURCE_ANALYZER_UNSUPPORTED_DECORATOR', methodDecorator);
                    }
                }
                const effectiveCandidate = candidates[effectiveRoute];
                const effectiveMethods = routeMethods(effectiveCandidate.name) ?? [];
                if (controllers.length === 0 || !effectiveCandidate.trusted) {
                    if (effectiveMethods.length > 0) {
                        addUnresolved(effectiveMethods, methodDecorators[effectiveRoute], 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR');
                    }
                    continue;
                }
                const methodAuthMetadata = ownAuthMetadata(method, checker, projectSources, authConfig, check, context.limits.maxAstNodes, context.limits.maxAnalysisDepth);
                if (methodAuthMetadata.dynamic) {
                    addDiagnostic('SOURCE_ANALYZER_DYNAMIC_AUTH_METADATA', method);
                }
                const operationAuth = composeAuth(classAuthMetadata, methodAuthMetadata, authConfig, globalGuardFound);
                for (const [index, methodDecorator] of methodDecorators.entries()) {
                    await checkpoint();
                    const match = matches[index];
                    const methods = match && METHOD_DECORATORS[match.name];
                    if (!match || !methods) {
                        if ((match?.name === 'RequestMapping' || match?.name === 'Search') && index !== effectiveRoute)
                            continue;
                        if (match?.name === 'RequestMapping') {
                            addUnresolved(canonical_route_1.HTTP_METHODS, methodDecorator, 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR');
                        }
                        continue;
                    }
                    if (index !== effectiveRoute)
                        continue;
                    if (versioned) {
                        addDiagnostic('SOURCE_ANALYZER_UNSUPPORTED_DECORATOR', methodDecorator);
                        addUnresolved(methods, methodDecorator, 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR');
                        continue;
                    }
                    const methodPaths = match.call.arguments.length <= 1
                        ? (0, static_string_resolver_1.resolveStaticStrings)(match.call.arguments[0], checker, projectSources, {
                            check, maxSteps: context.limits.maxAstNodes,
                        })
                        : undefined;
                    for (const controller of controllers) {
                        await checkpoint();
                        const controllerPaths = controller.match.call.arguments.length <= 1
                            ? (0, static_string_resolver_1.resolveStaticStrings)(controller.match.call.arguments[0], checker, projectSources, {
                                check, maxSteps: context.limits.maxAstNodes,
                            })
                            : undefined;
                        if (!controllerPaths || !methodPaths) {
                            addDiagnostic('SOURCE_ANALYZER_DYNAMIC_ROUTE', methodDecorator);
                            addUnresolved(methods, methodDecorator, 'SOURCE_ANALYZER_DYNAMIC_ROUTE');
                            continue;
                        }
                        for (const prefix of controllerPaths)
                            for (const suffix of methodPaths) {
                                await checkpoint();
                                const route = routePath(prefix, suffix);
                                if (!route) {
                                    addDiagnostic('SOURCE_ANALYZER_UNSUPPORTED_DECORATOR', methodDecorator);
                                    addUnresolved(methods, methodDecorator, 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR');
                                    continue;
                                }
                                if (!route.complete && /:[A-Za-z_$][\w$]*\([^)]/u.test(route.path)) {
                                    addDiagnostic('SOURCE_ANALYZER_UNSUPPORTED_DECORATOR', methodDecorator);
                                }
                                for (const httpMethod of methods) {
                                    await checkpoint();
                                    const key = (0, canonical_route_1.createRouteKey)(httpMethod, route.path);
                                    const controllerLocation = sourceLocation(controller.decorator, context.workspaceRoot);
                                    const methodLocation = sourceLocation(methodDecorator, context.workspaceRoot);
                                    const provenance = [
                                        {
                                            source: 'source-ast',
                                            uri: controllerLocation.sourceUri,
                                            pointer: `line:${controllerLocation.line}:column:${controllerLocation.column}`,
                                            digest: digest(controller.decorator.getSourceFile()),
                                            analyzer: ANALYZER_IDENTITY,
                                            capability: 'routerPrefixes',
                                            complete: route.complete,
                                        },
                                        {
                                            source: 'source-ast',
                                            uri: methodLocation.sourceUri,
                                            pointer: `line:${methodLocation.line}:column:${methodLocation.column}`,
                                            digest: digest(methodDecorator.getSourceFile()),
                                            analyzer: ANALYZER_IDENTITY,
                                            capability: 'httpMethods',
                                            complete: route.complete,
                                        },
                                        ...operationAuth.evidence.map(({ decorator: authDecorator, capability }) => {
                                            const location = sourceLocation(authDecorator, context.workspaceRoot);
                                            return {
                                                source: 'source-ast',
                                                uri: location.sourceUri,
                                                pointer: `line:${location.line}:column:${location.column}`,
                                                digest: digest(authDecorator.getSourceFile()),
                                                analyzer: ANALYZER_IDENTITY,
                                                capability,
                                                complete: operationAuth.auth.analysis?.enforcementConfidence === 'high',
                                            };
                                        }),
                                    ];
                                    const previous = operations.get(key);
                                    if (previous) {
                                        previous.provenance.push(...provenance);
                                        if (comparableAuth(previous.exposure, previous.auth)
                                            !== comparableAuth(operationAuth.exposure, operationAuth.auth)) {
                                            const left = previous.auth.analysis;
                                            const right = operationAuth.auth.analysis;
                                            previous.exposure = 'unknown';
                                            previous.auth = {
                                                mode: 'unknown',
                                                alternatives: [],
                                                analysis: {
                                                    guards: [...left.guards, ...right.guards],
                                                    explicitPublic: left.explicitPublic || right.explicitPublic,
                                                    roles: [...left.roles, ...right.roles],
                                                    enforcementConfidence: 'unknown',
                                                    capabilityReasons: [
                                                        ...left.capabilityReasons,
                                                        ...right.capabilityReasons,
                                                        'Conflicting NestJS auth metadata was found for the same route.',
                                                    ],
                                                },
                                            };
                                        }
                                        continue;
                                    }
                                    consume();
                                    operations.set(key, {
                                        method: httpMethod,
                                        path: route.path,
                                        exposure: operationAuth.exposure,
                                        auth: operationAuth.auth,
                                        request: { ...EMPTY_REQUEST },
                                        provenance,
                                    });
                                }
                            }
                    }
                }
            }
        }
    }
    const contract = (0, security_ir_1.createSecurityContract)({
        source: 'source-ast',
        capabilities: {
            routes: 'partial', parameters: 'unsupported', requestBodies: 'unsupported', authentication: 'partial',
        },
        operations: [...operations.values()],
    });
    const methodOrder = new Map(canonical_route_1.HTTP_METHODS.map((method, index) => [method, index]));
    const orderedUnresolved = unresolvedOperations.map((candidate) => ({
        ...candidate,
        methods: [...candidate.methods].sort((left, right) => methodOrder.get(left) - methodOrder.get(right)),
    })).sort((left, right) => {
        const leftKey = `${left.sourceUri}\0${left.line.toString().padStart(10, '0')}\0${left.column.toString().padStart(10, '0')}\0${left.reason}\0${left.methods.join(',')}`;
        const rightKey = `${right.sourceUri}\0${right.line.toString().padStart(10, '0')}\0${right.column.toString().padStart(10, '0')}\0${right.reason}\0${right.methods.join(',')}`;
        return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    });
    return {
        contract,
        diagnostics,
        unresolvedOperations: orderedUnresolved,
        metrics: {
            files: loaded.metrics.files,
            totalSourceBytes: loaded.metrics.totalSourceBytes,
            largestFileBytes: loaded.metrics.largestFileBytes,
            astNodes: loaded.metrics.astNodes,
            diagnostics: diagnostics.length,
            operations: contract.operations.length + unresolvedMethodCount,
            maxDepth: loaded.metrics.maxDepth,
        },
    };
}
const CAPABILITIES = Object.freeze({
    routePaths: Object.freeze({ status: 'partial', reason: 'Static NestJS route paths are supported.' }),
    httpMethods: Object.freeze({ status: 'supported', reason: 'NestJS HTTP method decorators are supported.' }),
    routerPrefixes: Object.freeze({ status: 'supported', reason: 'Static controller prefixes are supported.' }),
    globalPrefixes: Object.freeze({ status: 'unsupported', reason: 'Runtime global prefixes are not inspected.' }),
    authentication: Object.freeze({ status: 'partial', reason: 'Configured local Guard and Public metadata are inspected.' }),
    authorization: Object.freeze({ status: 'partial', reason: 'Configured static role labels are inspected.' }),
    requestContentTypes: Object.freeze({ status: 'unsupported', reason: 'Request content types are not inspected.' }),
    requestLimits: Object.freeze({ status: 'unsupported', reason: 'Request limits are not inspected.' }),
    sourceLocations: Object.freeze({ status: 'supported', reason: 'Decorator locations are reported.' }),
    inheritedMetadata: Object.freeze({ status: 'partial', reason: 'Project-local class inheritance is supported.' }),
    dynamicExpressions: Object.freeze({ status: 'partial', reason: 'Only statically provable metadata is resolved.' }),
});
function createNestJsSourceAnalyzer(config) {
    const authConfig = config === undefined ? auth_config_1.EMPTY_NESTJS_AUTH_CONFIG : (0, auth_config_1.validateNestJsAuthConfig)(config);
    return Object.freeze({
        id: ANALYZER_ID,
        version: ANALYZER_VERSION,
        languages: Object.freeze(['typescript']),
        frameworks: Object.freeze(['nestjs']),
        capabilities: CAPABILITIES,
        analyze: (context) => analyze(context, authConfig),
    });
}
exports.nestJsSourceAnalyzer = createNestJsSourceAnalyzer();
