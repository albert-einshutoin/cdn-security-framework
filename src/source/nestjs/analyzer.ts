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
  isUnsupportedNestJsDecorator,
  nestJsRouteDecorator,
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

function directBaseClass(node: ts.ClassDeclaration, checker: ts.TypeChecker): ts.ClassDeclaration | undefined {
  const expression = node.heritageClauses?.find(({ token }) => token === ts.SyntaxKind.ExtendsKeyword)
    ?.types[0]?.expression;
  if (!expression) return undefined;
  let symbol = checker.getSymbolAtLocation(expression);
  if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
  return symbol?.declarations?.find(ts.isClassDeclaration);
}

function methodsIncludingDirectBase(
  node: ts.ClassDeclaration,
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  check: () => void,
  maxSteps: number,
): ts.MethodDeclaration[] {
  const propertyKey = ({ name }: ts.MethodDeclaration): string | undefined => {
    if (ts.isComputedPropertyName(name)) {
      const values = resolveStaticStrings(name.expression, checker, projectSources, { check, maxSteps });
      return values?.length === 1 ? values[0] : undefined;
    }
    return ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)
      || ts.isNoSubstitutionTemplateLiteral(name) ? name.text : undefined;
  };
  const allOwn = node.members.filter(ts.isMethodDeclaration);
  const concrete = (method: ts.MethodDeclaration) => Boolean(method.body)
    && !method.modifiers?.some(({ kind }) => (
      kind === ts.SyntaxKind.StaticKeyword || kind === ts.SyntaxKind.AbstractKeyword
    ));
  const own = allOwn.filter(concrete);
  const ownNames = new Set(own.map(propertyKey).filter((name): name is string => name !== undefined));
  const base = directBaseClass(node, checker);
  const inherited = base && projectSources.has(base.getSourceFile())
    ? base.members.filter(ts.isMethodDeclaration).filter(concrete)
      .filter((method) => !ownNames.has(propertyKey(method) ?? ''))
    : [];
  return [...own, ...inherited];
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
    for (const statement of sourceFile.statements) {
      await checkpoint();
      if (!ts.isClassDeclaration(statement)) continue;
      const classDecorators = decorators(statement);
      for (const decorator of classDecorators) {
        if (isUnsupportedNestJsDecorator(decorator, checker)) {
          addDiagnostic('SOURCE_ANALYZER_UNSUPPORTED_DECORATOR', decorator);
        }
      }
      const controllers = classDecorators.map((decorator) => ({
        decorator,
        match: nestJsRouteDecorator(decorator, checker),
      })).filter(({ match }) => match?.name === 'Controller').slice(0, 1);
      if (controllers.length === 0) continue;
      for (const method of methodsIncludingDirectBase(
        statement, checker, projectSources, check, context.limits.maxAstNodes,
      )) {
        await checkpoint();
        const methodDecorators = decorators(method);
        const matches = methodDecorators.map((decorator) => nestJsRouteDecorator(decorator, checker));
        const versioned = matches.some((match) => match?.name === 'Version');
        const effectiveRoute = matches.findIndex((match) => Boolean(match && METHOD_DECORATORS[match.name]));
        for (const [index, methodDecorator] of methodDecorators.entries()) {
          await checkpoint();
          const match = matches[index];
          const methods = match && METHOD_DECORATORS[match.name];
          if (!match || !methods) {
            if (isUnsupportedNestJsDecorator(methodDecorator, checker)) {
              addDiagnostic('SOURCE_ANALYZER_UNSUPPORTED_DECORATOR', methodDecorator);
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
