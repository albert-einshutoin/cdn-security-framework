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
const ANALYZER_VERSION = '1.1.0';
const ANALYZER_IDENTITY = `${ANALYZER_ID}@${ANALYZER_VERSION}`;
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
        if (typescript_1.default.isCallExpression(expression))
            return true;
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
    let externalModuleImport;
    for (const sourceFile of projectSources) {
        const nodes = [sourceFile];
        while (nodes.length > 0) {
            const node = nodes.pop();
            check();
            if (typescript_1.default.isClassLike(node)) {
                for (const decorator of decorators(node)) {
                    const module = (0, decorator_symbols_1.resolveDecoratorSymbol)(decorator, checker, check);
                    const metadataArgument = module?.name === 'Module' && module.nestJsCommon
                        ? module.call.arguments[0] : undefined;
                    const metadata = metadataArgument
                        ? resolveConstObject(metadataArgument, checker, projectSources, check) : undefined;
                    if (!metadata) {
                        if (metadataArgument)
                            candidates.push(metadataArgument);
                        continue;
                    }
                    const effectiveProviders = effectiveObjectProperty(metadata, 'providers', checker, projectSources, check);
                    for (const providerExpression of effectiveProviders.candidates) {
                        if (!collect(providerExpression, new Set(), 0)) {
                            candidates.push(providerExpression);
                        }
                    }
                    const effectiveImports = effectiveObjectProperty(metadata, 'imports', checker, projectSources, check);
                    externalModuleImport ??= effectiveImports.candidates.find((candidate) => (isExternalModuleReference(candidate)));
                }
            }
            typescript_1.default.forEachChild(node, (child) => { nodes.push(child); });
        }
    }
    return { providers, candidates, externalModuleImport };
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
    const READ_ONLY_ARRAY_METHODS = new Set([
        'at', 'concat', 'entries', 'every', 'filter', 'find', 'findIndex', 'findLast',
        'findLastIndex', 'flat', 'flatMap', 'forEach', 'includes', 'indexOf', 'join', 'keys',
        'lastIndexOf', 'map', 'reduce', 'reduceRight', 'slice', 'some', 'toLocaleString',
        'toReversed', 'toSorted', 'toSpliced', 'toString', 'values', 'with',
    ]);
    const expressions = [input];
    const seenExpressions = new Set();
    const seenSymbols = new Set();
    let steps = 0;
    const symbolAt = (node) => resolvedSymbolAt(node, checker);
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
            const condition = statement.expression.kind === typescript_1.default.SyntaxKind.TrueKeyword
                ? true : statement.expression.kind === typescript_1.default.SyntaxKind.FalseKeyword ? false : undefined;
            if (condition !== false && collectReturns(statement.thenStatement))
                return condition === true;
            return condition !== true && Boolean(statement.elseStatement
                && collectReturns(statement.elseStatement));
        }
        return false;
    };
    const staticallyUnreachable = (node) => {
        let child = node;
        let parent = node.parent;
        while (parent) {
            if (typescript_1.default.isIfStatement(parent)) {
                if (parent.expression.kind === typescript_1.default.SyntaxKind.FalseKeyword && child === parent.thenStatement)
                    return true;
                if (parent.expression.kind === typescript_1.default.SyntaxKind.TrueKeyword && child === parent.elseStatement)
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
    const unsupportedGlobalGuard = potentialGlobalProvider ?? providerRegistrations.externalModuleImport;
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
