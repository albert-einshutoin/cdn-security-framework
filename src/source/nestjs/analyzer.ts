import { createHash } from 'node:crypto';
import path from 'node:path';

import ts from 'typescript';

import {
  HTTP_METHODS,
  canonicalizePath,
  createRouteKey,
  type HttpMethod,
} from '../../contract/canonical-route';
import { createSecurityContract, type ApiOperationInputV1 } from '../../contract/security-ir';
import {
  SourceAnalyzerContractError,
  type AnalyzerDiagnostic,
  type SourceAnalyzerDiagnosticCode,
  type SourceAnalyzerPlugin,
  type UnresolvedSourceOperationCandidate,
} from '../../source-analysis';
import {
  TypeScriptProjectLoadError,
  loadTypeScriptProject,
  type LoadedTypeScriptProject,
} from '../typescript/project-loader';
import {
  classifyNestJsRouteDecorator,
  type NestJsRouteDecoratorCandidate,
  type NestJsRouteDecorator,
} from './decorator-symbols';
import { resolveStaticStrings } from './static-string-resolver';

const ANALYZER_ID = 'nestjs-typescript';
const ANALYZER_VERSION = '1.0.0';
const ANALYZER_IDENTITY = `${ANALYZER_ID}@${ANALYZER_VERSION}`;
const METHOD_DECORATORS: Readonly<Partial<Record<NestJsRouteDecorator, readonly HttpMethod[]>>> = Object.freeze({
  All: HTTP_METHODS,
  Delete: ['DELETE'],
  Get: ['GET'],
  Head: ['HEAD'],
  Options: ['OPTIONS'],
  Patch: ['PATCH'],
  Post: ['POST'],
  Put: ['PUT'],
  Sse: ['GET'],
});
function routeMethods(name: NestJsRouteDecoratorCandidate): readonly HttpMethod[] | undefined {
  if (name === 'Unknown' || name === 'RequestMapping') return HTTP_METHODS;
  return METHOD_DECORATORS[name];
}
const EMPTY_REQUEST = Object.freeze({
  contentTypes: [], requiredHeaders: [], queryParameters: [], pathParameters: [],
  headerParameters: [], cookieParameters: [],
});

function decorators(node: ts.Node): readonly ts.Decorator[] {
  return ts.canHaveDecorators(node) ? ts.getDecorators(node) ?? [] : [];
}

function sourceLocation(node: ts.Node, workspaceRoot: string): {
  sourceUri: string; line: number; column: number;
} {
  const sourceFile = node.getSourceFile();
  const position = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  return {
    sourceUri: path.relative(workspaceRoot, sourceFile.fileName).replaceAll('\\', '/'),
    line: position.line + 1,
    column: position.character + 1,
  };
}

function digest(sourceFile: ts.SourceFile): string {
  return `sha256:${createHash('sha256').update(sourceFile.text).digest('hex')}`;
}

function routePath(controllerPath: string, methodPath: string): { path: string; complete: boolean } | undefined {
  let canonical: string;
  try { canonical = canonicalizePath(`${controllerPath}/${methodPath}`); } catch { return undefined; }
  const advancedPattern = /\*|:[A-Za-z_$][\w$]*\([^)]/u.test(canonical);
  return {
    path: canonical.replace(/:([A-Za-z_$][\w$]*)(?![\w$(])/gu, '{$1}'),
    complete: !advancedPattern,
  };
}

function directBaseClass(node: ts.ClassLikeDeclaration, checker: ts.TypeChecker): ts.ClassLikeDeclaration | undefined {
  const expression = node.heritageClauses?.find(({ token }) => token === ts.SyntaxKind.ExtendsKeyword)
    ?.types[0]?.expression;
  if (!expression) return undefined;
  let symbol = checker.getSymbolAtLocation(expression);
  if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
  return symbol?.declarations?.find(ts.isClassLike)
    ?? checker.getTypeAtLocation(expression).getSymbol()?.declarations?.find(ts.isClassLike);
}

function hasInheritedClassVersion(
  node: ts.ClassLikeDeclaration,
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  check: () => void,
  maxSteps: number,
): boolean {
  const seen = new Set<ts.ClassLikeDeclaration>();
  let current = directBaseClass(node, checker);
  let steps = 0;
  while (current && projectSources.has(current.getSourceFile()) && !seen.has(current)) {
    check();
    steps += 1;
    if (steps > maxSteps) throw new SourceAnalyzerContractError('SOURCE_ANALYZER_AST_NODE_LIMIT');
    seen.add(current);
    if (decorators(current).some((decorator) => {
      const name = classifyNestJsRouteDecorator(decorator, checker, check).candidate?.name;
      return name === 'Version' || name === 'Unknown';
    })) return true;
    current = directBaseClass(current, checker);
  }
  return false;
}

function methodsIncludingBaseChain(
  node: ts.ClassLikeDeclaration,
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  useDefineForClassFields: boolean,
  check: () => void,
  maxSteps: number,
): ts.MethodDeclaration[] {
  const symbolKey = Symbol('symbol-method-key');
  const unwrapPropertyExpression = (expression: ts.Expression): ts.Expression => {
    let current = expression;
    while (ts.isParenthesizedExpression(current) || ts.isAsExpression(current)
      || ts.isTypeAssertionExpression(current) || ts.isSatisfiesExpression(current)
      || ts.isNonNullExpression(current)) current = current.expression;
    return current;
  };
  const staticName = (name: ts.PropertyName): string | undefined => (
    ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)
      || ts.isNoSubstitutionTemplateLiteral(name) ? name.text : undefined
  );
  const destructuredInitializer = (binding: ts.BindingElement): ts.Expression | undefined => {
    const steps: ({ kind: 'array'; index: number } | { kind: 'object'; key: string })[] = [];
    let current = binding;
    let declaration: ts.VariableDeclaration | undefined;
    while (true) {
      if (current.dotDotDotToken || current.initializer) return undefined;
      const pattern = current.parent;
      if (ts.isArrayBindingPattern(pattern)) {
        const index = pattern.elements.indexOf(current);
        if (index < 0) return undefined;
        steps.push({ kind: 'array', index });
      } else if (ts.isObjectBindingPattern(pattern)) {
        const key = current.propertyName && staticName(current.propertyName)
          || (ts.isIdentifier(current.name) ? current.name.text : undefined);
        if (key === undefined) return undefined;
        steps.push({ kind: 'object', key });
      } else return undefined;
      if (ts.isVariableDeclaration(pattern.parent)) {
        declaration = pattern.parent;
        break;
      }
      if (!ts.isBindingElement(pattern.parent)) return undefined;
      current = pattern.parent;
    }
    if (!declaration.initializer || !projectSources.has(declaration.getSourceFile())
      || !(declaration.parent.flags & ts.NodeFlags.Const)) return undefined;
    let value = declaration.initializer;
    for (const step of steps.reverse()) {
      const node = unwrapPropertyExpression(value);
      if (step.kind === 'array') {
        if (!ts.isArrayLiteralExpression(node) || node.elements.some(ts.isSpreadElement)) return undefined;
        const element = node.elements[step.index];
        if (!element || ts.isOmittedExpression(element) || ts.isSpreadElement(element)) return undefined;
        value = element;
        continue;
      }
      if (step.key === '__proto__' || !ts.isObjectLiteralExpression(node)
        || node.properties.some((property) => (
          ts.isSpreadAssignment(property) || !property.name || staticName(property.name) === undefined
        ))) return undefined;
      const property = [...node.properties].reverse().find((candidate) => (
        candidate.name && staticName(candidate.name) === step.key
      ));
      if (!property) return undefined;
      if (ts.isPropertyAssignment(property)) value = property.initializer;
      else if (ts.isShorthandPropertyAssignment(property)) value = property.name;
      else return undefined;
    }
    return value;
  };
  const numericPropertyValue = (
    expression: ts.Expression,
    resolving = new Set<ts.Symbol>(),
    depth = 0,
  ): number | bigint | undefined => {
    check();
    if (depth > 64) return undefined;
    const node = unwrapPropertyExpression(expression);
    const value = ts.isNumericLiteral(node)
      ? Number(node.text)
      : ts.isBigIntLiteral(node)
        ? BigInt(node.text.slice(0, -1))
        : undefined;
    if (value !== undefined) return value;
    if (ts.isPrefixUnaryExpression(node)
      && (node.operator === ts.SyntaxKind.PlusToken || node.operator === ts.SyntaxKind.MinusToken)) {
      const operand = numericPropertyValue(node.operand, resolving, depth + 1);
      if (operand === undefined || (node.operator === ts.SyntaxKind.PlusToken && typeof operand === 'bigint')) {
        return undefined;
      }
      return node.operator === ts.SyntaxKind.MinusToken ? -operand : Number(operand);
    }
    if (!ts.isIdentifier(node)) return undefined;
    let symbol = checker.getSymbolAtLocation(node);
    if (!symbol) return undefined;
    if (symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    if (resolving.has(symbol)) return undefined;
    const declarations = symbol.declarations ?? [];
    if (declarations.length !== 1) return undefined;
    const declaration = declarations[0];
    const initializer = ts.isVariableDeclaration(declaration)
      ? declaration.initializer
      : ts.isBindingElement(declaration) ? destructuredInitializer(declaration) : undefined;
    if (!initializer || !projectSources.has(declaration.getSourceFile())
      || (ts.isVariableDeclaration(declaration)
        && !(declaration.parent.flags & ts.NodeFlags.Const))) return undefined;
    resolving.add(symbol);
    const result = numericPropertyValue(initializer, resolving, depth + 1);
    resolving.delete(symbol);
    return result;
  };
  const propertyKey = ({ name }: ts.NamedDeclaration): string | typeof symbolKey | undefined => {
    if (!name) return undefined;
    if (ts.isComputedPropertyName(name)) {
      const numeric = numericPropertyValue(name.expression);
      if (numeric !== undefined) return String(numeric);
      const values = resolveStaticStrings(name.expression, checker, projectSources, { check, maxSteps });
      if (values?.length === 1) return values[0];
      return checker.getTypeAtLocation(name.expression).flags & ts.TypeFlags.ESSymbolLike
        ? symbolKey
        : undefined;
    }
    return ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)
      || ts.isNoSubstitutionTemplateLiteral(name) ? name.text : undefined;
  };
  const concrete = (method: ts.MethodDeclaration) => Boolean(method.body)
    && !method.modifiers?.some(({ kind }) => (
      kind === ts.SyntaxKind.StaticKeyword || kind === ts.SyntaxKind.AbstractKeyword
    ));
  const runtimeMember = (member: ts.ClassElement) => {
    const modifiers = ts.canHaveModifiers(member) ? ts.getModifiers(member) : undefined;
    return !modifiers?.some(({ kind }) => (
      kind === ts.SyntaxKind.StaticKeyword || kind === ts.SyntaxKind.AbstractKeyword
      || kind === ts.SyntaxKind.DeclareKeyword
    )) && ((ts.isPropertyDeclaration(member)
      && (useDefineForClassFields || member.initializer !== undefined)) || (
      (ts.isMethodDeclaration(member) || ts.isGetAccessorDeclaration(member) || ts.isSetAccessorDeclaration(member))
      && Boolean(member.body)
    ));
  };
  const methods: ts.MethodDeclaration[] = [];
  const shadowed = new Set<string>();
  const seen = new Set<ts.ClassLikeDeclaration>();
  let current: ts.ClassLikeDeclaration | undefined = node;
  let steps = 0;
  while (current && projectSources.has(current.getSourceFile()) && !seen.has(current)) {
    check();
    steps += 1;
    if (steps > maxSteps) throw new SourceAnalyzerContractError('SOURCE_ANALYZER_AST_NODE_LIMIT');
    seen.add(current);
    methods.push(...current.members.filter(ts.isMethodDeclaration).filter(concrete)
      .filter((method) => {
        const key = propertyKey(method);
        return key !== symbolKey && (key === undefined || !shadowed.has(key));
      }));
    for (const member of current.members.filter(runtimeMember)) {
      const key = propertyKey(member);
      if (typeof key === 'string') shadowed.add(key);
    }
    current = directBaseClass(current, checker);
  }
  return methods;
}

function mapLoaderError(error: TypeScriptProjectLoadError): SourceAnalyzerDiagnosticCode {
  const code = error.diagnostics[0]?.code;
  if (code === 'TS_PROJECT_CANCELLED') return 'SOURCE_ANALYZER_CANCELLED';
  if (code === 'TS_PROJECT_TIMEOUT') return 'SOURCE_ANALYZER_TIMEOUT';
  if (code === 'TS_PROJECT_PATH_OUTSIDE_ROOT') return 'SOURCE_ANALYZER_INPUT_OUTSIDE_ROOT';
  if (code === 'TS_PROJECT_FILE_LIMIT') return 'SOURCE_ANALYZER_FILE_LIMIT';
  if (code === 'TS_PROJECT_FILE_BYTES_LIMIT') return 'SOURCE_ANALYZER_FILE_BYTES_LIMIT';
  if (code === 'TS_PROJECT_TOTAL_BYTES_LIMIT') return 'SOURCE_ANALYZER_TOTAL_BYTES_LIMIT';
  if (code === 'TS_PROJECT_AST_NODE_LIMIT') return 'SOURCE_ANALYZER_AST_NODE_LIMIT';
  if (code === 'TS_PROJECT_DEPTH_LIMIT') return 'SOURCE_ANALYZER_DEPTH_LIMIT';
  if (code === 'TS_PROJECT_DIAGNOSTIC_LIMIT') return 'SOURCE_ANALYZER_DIAGNOSTIC_LIMIT';
  if (['TS_PROJECT_INVALID_CONFIG', 'TS_PROJECT_CONFIG_MISSING', 'TS_PROJECT_EXTENSION_UNSUPPORTED',
    'TS_PROJECT_EXTENDS_UNSUPPORTED'].includes(code ?? '')) return 'SOURCE_ANALYZER_INPUT_INVALID';
  return 'SOURCE_ANALYZER_INTERNAL';
}

async function loadProject(
  workspaceRoot: string,
  tsconfigPath: string,
  context: Parameters<SourceAnalyzerPlugin['analyze']>[0],
): Promise<LoadedTypeScriptProject> {
  try {
    const loaded = await loadTypeScriptProject({
      workspaceRoot,
      tsconfigPath,
      limits: context.limits,
      cancellationSignal: context.cancellationSignal,
    });
    if (loaded.diagnostics.some(({ code }) => code === 'TS_PROJECT_TYPESCRIPT_DIAGNOSTIC')) {
      throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INPUT_INVALID');
    }
    return loaded;
  } catch (error) {
    if (error instanceof SourceAnalyzerContractError) throw error;
    if (error instanceof TypeScriptProjectLoadError) throw new SourceAnalyzerContractError(mapLoaderError(error));
    throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INTERNAL');
  }
}

async function analyze(context: Parameters<SourceAnalyzerPlugin['analyze']>[0]) {
  if (context.entrypoints.length !== 1) {
    throw new SourceAnalyzerContractError('SOURCE_ANALYZER_INPUT_INVALID');
  }
  const deadline = performance.now() + context.limits.timeoutMs;
  const check = () => {
    if (context.cancellationSignal?.aborted) {
      throw new SourceAnalyzerContractError('SOURCE_ANALYZER_CANCELLED');
    }
    if (performance.now() >= deadline) throw new SourceAnalyzerContractError('SOURCE_ANALYZER_TIMEOUT');
  };
  const loaded = await loadProject(context.workspaceRoot, context.entrypoints[0], context);
  const checker = loaded.program.getTypeChecker();
  const compilerOptions = loaded.program.getCompilerOptions();
  const useDefineForClassFields = compilerOptions.useDefineForClassFields
    ?? (compilerOptions.target ?? ts.ScriptTarget.ES5) >= ts.ScriptTarget.ES2022;
  const projectSources = new Set(loaded.sourceFiles.filter((sourceFile) => (
    !sourceFile.isDeclarationFile && !sourceFile.fileName.replaceAll('\\', '/').includes('/node_modules/')
  )));
  const operations = new Map<string, ApiOperationInputV1>();
  const diagnostics: AnalyzerDiagnostic[] = [];
  const unresolvedOperations: UnresolvedSourceOperationCandidate[] = [];
  let unresolvedMethodCount = 0;
  let inspectedNodes = 0;

  const checkpoint = async () => {
    inspectedNodes += 1;
    if (inspectedNodes % 256 === 0) await new Promise<void>((resolve) => setImmediate(resolve));
    check();
  };

  const consume = (count = 1) => {
    check();
    if (operations.size + unresolvedMethodCount + count > context.limits.maxOperations) {
      throw new SourceAnalyzerContractError('SOURCE_ANALYZER_OPERATION_LIMIT');
    }
  };
  const addDiagnostic = (
    code: 'SOURCE_ANALYZER_DYNAMIC_ROUTE' | 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR',
    node: ts.Node,
  ) => {
    if (diagnostics.length >= context.limits.maxDiagnostics) {
      throw new SourceAnalyzerContractError('SOURCE_ANALYZER_DIAGNOSTIC_LIMIT');
    }
    diagnostics.push({
      code,
      safeMessage: code === 'SOURCE_ANALYZER_DYNAMIC_ROUTE'
        ? 'A dynamic route expression could not be resolved statically.'
        : 'A source decorator is not supported by this analyzer.',
      ...sourceLocation(node, context.workspaceRoot),
    });
  };
  const addUnresolved = (methods: readonly HttpMethod[], node: ts.Node, reason: UnresolvedSourceOperationCandidate['reason']) => {
    consume(methods.length);
    unresolvedMethodCount += methods.length;
    unresolvedOperations.push({
      methods: [...methods], path: null, reason, ...sourceLocation(node, context.workspaceRoot),
    });
  };

  for (const sourceFile of projectSources) {
    const nodes: ts.Node[] = [...sourceFile.statements].reverse();
    while (nodes.length > 0) {
      const statement = nodes.pop()!;
      await checkpoint();
      const children: ts.Node[] = [];
      ts.forEachChild(statement, (child) => { children.push(child); });
      nodes.push(...children.reverse());
      if (!ts.isClassLike(statement)) continue;
      const classDecorators = decorators(statement);
      const classClassifications = classDecorators.map((decorator) => (
        classifyNestJsRouteDecorator(decorator, checker, check)
      ));
      const classCandidates = classClassifications.map(({ candidate }) => candidate);
      const classMatches = classClassifications.map(({ route }) => route);
      const classVersioned = classCandidates.some((match) => (
        match?.name === 'Version' || match?.name === 'Unknown'
      ))
        || hasInheritedClassVersion(
          statement, checker, projectSources, check, context.limits.maxAstNodes,
        );
      for (const [index, decorator] of classDecorators.entries()) {
        if (classClassifications[index]?.unsupported) {
          addDiagnostic('SOURCE_ANALYZER_UNSUPPORTED_DECORATOR', decorator);
        }
      }
      const effectiveController = classCandidates.findIndex((match) => (
        match?.name === 'Controller' || match?.name === 'Unknown'
      ));
      if (effectiveController === -1) continue;
      const controllers = classDecorators.map((decorator, index) => ({
        decorator,
        match: classMatches[index],
        index,
      })).filter(({ match, index }) => match?.name === 'Controller' && index === effectiveController);
      for (const method of methodsIncludingBaseChain(
        statement, checker, projectSources, useDefineForClassFields, check, context.limits.maxAstNodes,
      )) {
        await checkpoint();
        const methodDecorators = decorators(method);
        const classifications = methodDecorators.map((decorator) => (
          classifyNestJsRouteDecorator(decorator, checker, check)
        ));
        const candidates = classifications.map(({ candidate }) => candidate);
        const matches = classifications.map(({ route }) => route);
        const versioned = classVersioned || candidates.some((match) => (
          match?.name === 'Version' || match?.name === 'Unknown'
        ));
        const effectiveRoute = candidates.findIndex((match) => Boolean(match && (
          routeMethods(match.name) || match.name === 'Search'
        )));
        if (effectiveRoute === -1) continue;
        for (const [index, methodDecorator] of methodDecorators.entries()) {
          if (classifications[index]?.unsupported) {
            addDiagnostic('SOURCE_ANALYZER_UNSUPPORTED_DECORATOR', methodDecorator);
          }
        }
        const effectiveCandidate = candidates[effectiveRoute]!;
        const effectiveMethods = routeMethods(effectiveCandidate.name) ?? [];
        if (controllers.length === 0 || !effectiveCandidate.trusted) {
          if (effectiveMethods.length > 0) {
            addUnresolved(effectiveMethods, methodDecorators[effectiveRoute]!, 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR');
          }
          continue;
        }
        for (const [index, methodDecorator] of methodDecorators.entries()) {
          await checkpoint();
          const match = matches[index];
          const methods = match && METHOD_DECORATORS[match.name];
          if (!match || !methods) {
            if ((match?.name === 'RequestMapping' || match?.name === 'Search') && index !== effectiveRoute) continue;
            if (match?.name === 'RequestMapping') {
              addUnresolved(HTTP_METHODS, methodDecorator, 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR');
            }
            continue;
          }
          if (index !== effectiveRoute) continue;
          if (versioned) {
            addDiagnostic('SOURCE_ANALYZER_UNSUPPORTED_DECORATOR', methodDecorator);
            addUnresolved(methods, methodDecorator, 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR');
            continue;
          }
          const methodPaths = match.call.arguments.length <= 1
            ? resolveStaticStrings(match.call.arguments[0], checker, projectSources, {
              check, maxSteps: context.limits.maxAstNodes,
            })
            : undefined;
          for (const controller of controllers) {
            await checkpoint();
            const controllerPaths = controller.match!.call.arguments.length <= 1
              ? resolveStaticStrings(controller.match!.call.arguments[0], checker, projectSources, {
                check, maxSteps: context.limits.maxAstNodes,
              })
              : undefined;
            if (!controllerPaths || !methodPaths) {
              addDiagnostic('SOURCE_ANALYZER_DYNAMIC_ROUTE', methodDecorator);
              addUnresolved(methods, methodDecorator, 'SOURCE_ANALYZER_DYNAMIC_ROUTE');
              continue;
            }
            for (const prefix of controllerPaths) for (const suffix of methodPaths) {
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
                const key = createRouteKey(httpMethod, route.path);
                const controllerLocation = sourceLocation(controller.decorator, context.workspaceRoot);
                const methodLocation = sourceLocation(methodDecorator, context.workspaceRoot);
                const provenance = [
                  {
                    source: 'source-ast' as const,
                    uri: controllerLocation.sourceUri,
                    pointer: `line:${controllerLocation.line}:column:${controllerLocation.column}`,
                    digest: digest(controller.decorator.getSourceFile()),
                    analyzer: ANALYZER_IDENTITY,
                    capability: 'routerPrefixes',
                    complete: route.complete,
                  },
                  {
                    source: 'source-ast' as const,
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

  const contract = createSecurityContract({
    source: 'source-ast',
    capabilities: {
      routes: 'partial', parameters: 'unsupported', requestBodies: 'unsupported', authentication: 'unsupported',
    },
    operations: [...operations.values()],
  });
  const methodOrder = new Map(HTTP_METHODS.map((method, index) => [method, index]));
  const orderedUnresolved = unresolvedOperations.map((candidate) => ({
    ...candidate,
    methods: [...candidate.methods].sort((left, right) => methodOrder.get(left)! - methodOrder.get(right)!),
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

export const nestJsSourceAnalyzer: SourceAnalyzerPlugin = Object.freeze({
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
