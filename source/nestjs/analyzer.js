"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.nestJsSourceAnalyzer = void 0;
const node_crypto_1 = require("node:crypto");
const node_path_1 = __importDefault(require("node:path"));
const typescript_1 = __importDefault(require("typescript"));
const canonical_route_1 = require("../../contract/canonical-route");
const security_ir_1 = require("../../contract/security-ir");
const source_analysis_1 = require("../../source-analysis");
const project_loader_1 = require("../typescript/project-loader");
const decorator_symbols_1 = require("./decorator-symbols");
const static_string_resolver_1 = require("./static-string-resolver");
const ANALYZER_ID = 'nestjs-typescript';
const ANALYZER_VERSION = '1.0.0';
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
function directBaseClass(node, checker) {
    const expression = node.heritageClauses?.find(({ token }) => token === typescript_1.default.SyntaxKind.ExtendsKeyword)
        ?.types[0]?.expression;
    if (!expression)
        return undefined;
    let symbol = checker.getSymbolAtLocation(expression);
    if (symbol?.flags && symbol.flags & typescript_1.default.SymbolFlags.Alias)
        symbol = checker.getAliasedSymbol(symbol);
    return symbol?.declarations?.find(typescript_1.default.isClassLike)
        ?? checker.getTypeAtLocation(expression).getSymbol()?.declarations?.find(typescript_1.default.isClassLike);
}
function hasInheritedClassVersion(node, checker, projectSources, check, maxSteps) {
    const seen = new Set();
    let current = directBaseClass(node, checker);
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
        current = directBaseClass(current, checker);
    }
    return false;
}
function methodsIncludingBaseChain(node, checker, projectSources, useDefineForClassFields, check, maxSteps) {
    const symbolKey = Symbol('symbol-method-key');
    const propertyKey = ({ name }) => {
        if (!name)
            return undefined;
        if (typescript_1.default.isComputedPropertyName(name)) {
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
        current = directBaseClass(current, checker);
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
async function analyze(context) {
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
    const operations = new Map();
    const diagnostics = [];
    const unresolvedOperations = [];
    let unresolvedMethodCount = 0;
    let inspectedNodes = 0;
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
                : 'A source decorator is not supported by this analyzer.',
            ...sourceLocation(node, context.workspaceRoot),
        });
    };
    const addUnresolved = (methods, node, reason) => {
        consume(methods.length);
        unresolvedMethodCount += methods.length;
        unresolvedOperations.push({
            methods: [...methods], path: null, reason, ...sourceLocation(node, context.workspaceRoot),
        });
    };
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
            const classMatches = classClassifications.map(({ route }) => route);
            const classVersioned = classCandidates.some((match) => (match?.name === 'Version' || match?.name === 'Unknown'))
                || hasInheritedClassVersion(statement, checker, projectSources, check, context.limits.maxAstNodes);
            for (const [index, decorator] of classDecorators.entries()) {
                if (classClassifications[index]?.unsupported) {
                    addDiagnostic('SOURCE_ANALYZER_UNSUPPORTED_DECORATOR', decorator);
                }
            }
            const effectiveController = classCandidates.findIndex((match) => (match?.name === 'Controller' || match?.name === 'Unknown'));
            if (effectiveController === -1)
                continue;
            const controllers = classDecorators.map((decorator, index) => ({
                decorator,
                match: classMatches[index],
                index,
            })).filter(({ match, index }) => match?.name === 'Controller' && index === effectiveController);
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
                                    ];
                                    const previous = operations.get(key);
                                    if (previous) {
                                        previous.provenance.push(...provenance);
                                        continue;
                                    }
                                    consume();
                                    operations.set(key, {
                                        method: httpMethod,
                                        path: route.path,
                                        exposure: 'unknown',
                                        auth: { mode: 'unknown', alternatives: [] },
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
            routes: 'partial', parameters: 'unsupported', requestBodies: 'unsupported', authentication: 'unsupported',
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
exports.nestJsSourceAnalyzer = Object.freeze({
    id: ANALYZER_ID,
    version: ANALYZER_VERSION,
    languages: Object.freeze(['typescript']),
    frameworks: Object.freeze(['nestjs']),
    capabilities: Object.freeze({
        routePaths: Object.freeze({ status: 'partial', reason: 'Static NestJS route paths are supported.' }),
        httpMethods: Object.freeze({ status: 'supported', reason: 'NestJS HTTP method decorators are supported.' }),
        routerPrefixes: Object.freeze({ status: 'supported', reason: 'Static controller prefixes are supported.' }),
        globalPrefixes: Object.freeze({ status: 'unsupported', reason: 'Runtime global prefixes are not inspected.' }),
        authentication: Object.freeze({ status: 'unsupported', reason: 'Authentication metadata is handled separately.' }),
        authorization: Object.freeze({ status: 'unsupported', reason: 'Authorization metadata is handled separately.' }),
        requestContentTypes: Object.freeze({ status: 'unsupported', reason: 'Request content types are not inspected.' }),
        requestLimits: Object.freeze({ status: 'unsupported', reason: 'Request limits are not inspected.' }),
        sourceLocations: Object.freeze({ status: 'supported', reason: 'Decorator locations are reported.' }),
        inheritedMetadata: Object.freeze({ status: 'partial', reason: 'Direct class inheritance is supported.' }),
        dynamicExpressions: Object.freeze({ status: 'partial', reason: 'Only literal and const string expressions are resolved.' }),
    }),
    analyze,
});
