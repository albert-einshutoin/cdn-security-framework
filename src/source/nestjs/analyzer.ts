import { createHash } from 'node:crypto';
import path from 'node:path';

import ts from 'typescript';

import {
  HTTP_METHODS,
  canonicalizePath,
  createRouteKey,
  type HttpMethod,
} from '../../contract/canonical-route';
import {
  createSecurityContract,
  type ApiAuthAnalysisV1,
  type ApiAuthenticationContractV1,
  type ApiOperationInputV1,
} from '../../contract/security-ir';
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
  containsStaticSymbolFrom,
  isDefinitelyNonProvidePropertyKey,
  isNestJsUseGlobalGuardsCall,
  isStaticShorthandSymbolFrom,
  isStaticSymbolFrom,
  resolveBareDecoratorName,
  resolveDecoratorCallSymbol,
  resolveDecoratorSymbol,
  resolveStaticDecoratorWrapperCall,
  resolveStaticPropertyKey,
  resolveStaticSymbolName,
  type NestJsRouteDecoratorCandidate,
  type NestJsRouteDecorator,
} from './decorator-symbols';
import {
  EMPTY_NESTJS_AUTH_CONFIG,
  authKindToIr,
  validateNestJsAuthConfig,
  type NestJsAuthConfig,
} from './auth-config';
import { resolveStaticStrings } from './static-string-resolver';

export { validateNestJsAuthConfig } from './auth-config';

const ANALYZER_ID = 'nestjs-typescript';
const ANALYZER_VERSION = '1.1.0';
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

function isProvidersName(node: ts.BindingName | ts.PropertyName): boolean {
  return (ts.isIdentifier(node) || ts.isStringLiteral(node)) && node.text === 'providers';
}

function resolvedSymbolAt(node: ts.Identifier, checker: ts.TypeChecker): ts.Symbol | undefined {
  let symbol = ts.isShorthandPropertyAssignment(node.parent)
    ? checker.getShorthandAssignmentValueSymbol(node.parent)
    : checker.getSymbolAtLocation(node);
  if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
  return symbol;
}

function resolveConstObject(
  input: ts.Expression,
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  check: () => void,
  seen = new Set<ts.Symbol>(),
  depth = 0,
): ts.ObjectLiteralExpression | undefined {
  check();
  if (depth > 64) return undefined;
  let expression = input;
  while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
    || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)
    || ts.isNonNullExpression(expression)) expression = expression.expression;
  if (ts.isObjectLiteralExpression(expression)) return expression;
  if (!ts.isIdentifier(expression)) return undefined;
  const symbol = resolvedSymbolAt(expression, checker);
  if (!symbol || seen.has(symbol)) return undefined;
  const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
  const declaration = declarations.length === 1 ? declarations[0] : undefined;
  if (!declaration?.initializer || !projectSources.has(declaration.getSourceFile())
    || !ts.isVariableDeclarationList(declaration.parent)
    || !(declaration.parent.flags & ts.NodeFlags.Const)) return undefined;
  seen.add(symbol);
  return resolveConstObject(
    declaration.initializer, checker, projectSources, check, seen, depth + 1,
  );
}

function effectiveObjectProperty(
  object: ts.ObjectLiteralExpression,
  propertyName: string,
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  check: () => void,
  seen = new Set<ts.ObjectLiteralExpression>(),
): { present: boolean; candidates: ts.Expression[]; accessor: boolean } {
  check();
  if (seen.has(object)) return { present: true, candidates: [object], accessor: false };
  seen.add(object);
  const returnedExpressions = (body: ts.Block): ts.Expression[] => {
    const result: ts.Expression[] = [];
    const collectReturns = (statement: ts.Statement): boolean => {
      check();
      if (ts.isReturnStatement(statement)) {
        if (statement.expression) result.push(statement.expression);
        return true;
      }
      if (ts.isBlock(statement)) {
        for (const child of statement.statements) {
          if (collectReturns(child)) return true;
        }
      } else if (ts.isIfStatement(statement)) {
        const condition = statement.expression.kind === ts.SyntaxKind.TrueKeyword
          ? true : statement.expression.kind === ts.SyntaxKind.FalseKeyword ? false : undefined;
        const thenReturns = condition !== false && collectReturns(statement.thenStatement);
        const elseReturns = condition !== true && Boolean(statement.elseStatement
          && collectReturns(statement.elseStatement));
        return condition === true ? thenReturns : condition === false ? elseReturns
          : thenReturns && elseReturns;
      } else if (ts.isTryStatement(statement)) {
        const start = result.length;
        const tryReturns = collectReturns(statement.tryBlock);
        const catchReturns = Boolean(statement.catchClause
          && collectReturns(statement.catchClause.block));
        if (!statement.finallyBlock) return tryReturns && (!statement.catchClause || catchReturns);
        const finallyStart = result.length;
        const finallyReturns = collectReturns(statement.finallyBlock);
        if (finallyReturns) result.splice(start, finallyStart - start);
        return finallyReturns || (tryReturns && (!statement.catchClause || catchReturns));
      } else if (ts.isSwitchStatement(statement)) {
        let allReturn = statement.caseBlock.clauses.length > 0;
        for (const clause of statement.caseBlock.clauses) {
          let clauseReturns = false;
          for (const child of clause.statements) {
            if (collectReturns(child)) { clauseReturns = true; break; }
          }
          allReturn &&= clauseReturns;
        }
        return allReturn && statement.caseBlock.clauses.some(ts.isDefaultClause);
      } else if (ts.isWhileStatement(statement)) {
        if (statement.expression.kind !== ts.SyntaxKind.FalseKeyword) {
          collectReturns(statement.statement);
        }
      } else if (ts.isDoStatement(statement)) {
        collectReturns(statement.statement);
      } else if (ts.isForStatement(statement)) {
        if (statement.condition?.kind !== ts.SyntaxKind.FalseKeyword) {
          collectReturns(statement.statement);
        }
      } else if (ts.isForInStatement(statement) || ts.isForOfStatement(statement)) {
        collectReturns(statement.statement);
      }
      return false;
    };
    collectReturns(body);
    return result;
  };
  let result: { present: boolean; candidates: ts.Expression[]; accessor: boolean } = {
    present: false, candidates: [], accessor: false,
  };
  for (const property of object.properties) {
    if (ts.isPropertyAssignment(property)) {
      const name = ts.isComputedPropertyName(property.name)
        ? resolveStaticPropertyKey(property.name.expression, checker, check)
        : (ts.isIdentifier(property.name) || ts.isStringLiteral(property.name))
          ? property.name.text : undefined;
      if (name === propertyName) {
        result = { present: true, candidates: [property.initializer], accessor: false };
      }
      else if (ts.isComputedPropertyName(property.name) && name === undefined
        && !isDefinitelyNonProvidePropertyKey(property.name.expression)) {
        result = {
          present: true, candidates: [...result.candidates, property.initializer], accessor: false,
        };
      }
    } else if (ts.isShorthandPropertyAssignment(property) && property.name.text === propertyName) {
      result = { present: true, candidates: [property.name], accessor: false };
    } else if (ts.isGetAccessorDeclaration(property)) {
      const name = ts.isComputedPropertyName(property.name)
        ? resolveStaticPropertyKey(property.name.expression, checker, check)
        : (ts.isIdentifier(property.name) || ts.isStringLiteral(property.name))
          ? property.name.text : undefined;
      if (name === propertyName) {
        result = {
          present: true, candidates: property.body ? returnedExpressions(property.body) : [], accessor: true,
        };
      } else if (ts.isComputedPropertyName(property.name) && name === undefined
        && !isDefinitelyNonProvidePropertyKey(property.name.expression)) {
        result = {
          present: true,
          candidates: [...result.candidates, ...(property.body ? returnedExpressions(property.body) : [])],
          accessor: true,
        };
      }
    } else if (ts.isSetAccessorDeclaration(property) || ts.isMethodDeclaration(property)) {
      const name = ts.isComputedPropertyName(property.name)
        ? resolveStaticPropertyKey(property.name.expression, checker, check)
        : (ts.isIdentifier(property.name) || ts.isStringLiteral(property.name))
          ? property.name.text : undefined;
      if (name === propertyName) {
        if (ts.isMethodDeclaration(property)) {
          result = { present: true, candidates: [], accessor: false };
        } else if (!result.accessor) result = { present: true, candidates: [], accessor: true };
      }
    } else if (ts.isSpreadAssignment(property)) {
      const spread = resolveConstObject(property.expression, checker, projectSources, check);
      if (spread) {
        const nested = effectiveObjectProperty(
          spread, propertyName, checker, projectSources, check, new Set(seen),
        );
        if (nested.present) result = nested;
      } else {
        result = {
          present: true, candidates: [...result.candidates, property.expression], accessor: false,
        };
      }
    }
  }
  return result;
}

function registeredProviderObjects(
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  check: () => void,
): {
  providers: ReadonlySet<ts.ObjectLiteralExpression>;
  candidates: readonly ts.Expression[];
} {
  const providers = new Set<ts.ObjectLiteralExpression>();
  const candidates: ts.Expression[] = [];
  const collect = (input: ts.Expression, seen: Set<ts.Symbol>, depth: number): boolean => {
    check();
    if (depth > 64) return false;
    let expression = input;
    while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
      || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)
      || ts.isNonNullExpression(expression)) expression = expression.expression;
    if (ts.isObjectLiteralExpression(expression)) {
      providers.add(expression);
      return true;
    }
    if (ts.isArrayLiteralExpression(expression)) {
      let complete = true;
      for (const element of expression.elements) {
        complete = collect(
          ts.isSpreadElement(element) ? element.expression : element, new Set(seen), depth + 1,
        ) && complete;
      }
      return complete;
    }
    if (ts.isCallExpression(expression) && expression.arguments.length === 0
      && ts.isIdentifier(expression.expression)) {
      let symbol = checker.getSymbolAtLocation(expression.expression);
      if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
      const declarations = symbol?.declarations?.filter((candidate): candidate is ts.FunctionDeclaration => (
        ts.isFunctionDeclaration(candidate) && candidate.body !== undefined
        && projectSources.has(candidate.getSourceFile())
      )) ?? [];
      const declaration = declarations.length === 1 ? declarations[0] : undefined;
      const returned = declaration?.body?.statements.length === 1
        && ts.isReturnStatement(declaration.body.statements[0])
        ? declaration.body.statements[0].expression : undefined;
      if (symbol && returned && !seen.has(symbol)) {
        seen.add(symbol);
        return collect(returned, seen, depth + 1);
      }
      return false;
    }
    if (!ts.isIdentifier(expression)) return false;
    let symbol = ts.isShorthandPropertyAssignment(expression.parent)
      ? checker.getShorthandAssignmentValueSymbol(expression.parent)
      : checker.getSymbolAtLocation(expression);
    if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    if (!symbol || seen.has(symbol)) return false;
    const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
    const declaration = declarations.length === 1 ? declarations[0] : undefined;
    if (!declaration?.initializer || !projectSources.has(declaration.getSourceFile())
      || !ts.isVariableDeclarationList(declaration.parent)
      || !(declaration.parent.flags & ts.NodeFlags.Const)) return false;
    seen.add(symbol);
    collect(declaration.initializer, seen, depth + 1);
    return false;
  };
  for (const sourceFile of projectSources) {
    const nodes: ts.Node[] = [sourceFile];
    while (nodes.length > 0) {
      const node = nodes.pop()!;
      check();
      if (ts.isClassLike(node)) {
        for (const decorator of decorators(node)) {
          const module = resolveDecoratorSymbol(decorator, checker, check);
          const metadataArgument = module?.name === 'Module' && module.nestJsCommon
            ? module.call.arguments[0] : undefined;
          const metadata = metadataArgument
            ? resolveConstObject(metadataArgument, checker, projectSources, check) : undefined;
          if (!metadata) {
            if (metadataArgument) candidates.push(metadataArgument);
            continue;
          }
          const effectiveProviders = effectiveObjectProperty(
            metadata, 'providers', checker, projectSources, check,
          );
          for (const providerExpression of effectiveProviders.candidates) {
            if (!collect(providerExpression, new Set(), 0)) {
              candidates.push(providerExpression);
            }
          }
        }
      }
      ts.forEachChild(node, (child) => { nodes.push(child); });
    }
  }
  return { providers, candidates };
}

function isProviderRegistration(
  node: ts.ObjectLiteralElementLike,
  registeredProviders: ReadonlySet<ts.ObjectLiteralExpression>,
): boolean {
  const entry = node.parent;
  return ts.isObjectLiteralExpression(entry) && registeredProviders.has(entry);
}

function indexIdentifierReferences(
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  check: () => void,
): ReadonlyMap<ts.Symbol, readonly ts.Identifier[]> {
  const references = new Map<ts.Symbol, ts.Identifier[]>();
  for (const sourceFile of projectSources) {
    const nodes: ts.Node[] = [sourceFile];
    while (nodes.length > 0) {
      const node = nodes.pop()!;
      check();
      if (ts.isIdentifier(node)) {
        const symbol = resolvedSymbolAt(node, checker);
        if (symbol) {
          const entries = references.get(symbol) ?? [];
          entries.push(node);
          references.set(symbol, entries);
        }
      }
      ts.forEachChild(node, (child) => { nodes.push(child); });
    }
  }
  return references;
}

function containsCanonicalProviderToken(
  input: ts.Expression,
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  check: () => void,
  maxSteps: number,
  referencesBySymbol: ReadonlyMap<ts.Symbol, readonly ts.Identifier[]>,
): boolean {
  const READ_ONLY_ARRAY_METHODS = new Set([
    'at', 'concat', 'entries', 'every', 'filter', 'find', 'findIndex', 'findLast',
    'findLastIndex', 'flat', 'flatMap', 'forEach', 'includes', 'indexOf', 'join', 'keys',
    'lastIndexOf', 'map', 'reduce', 'reduceRight', 'slice', 'some', 'toLocaleString',
    'toReversed', 'toSorted', 'toSpliced', 'toString', 'values', 'with',
  ]);
  const expressions: ts.Expression[] = [input];
  const seenExpressions = new Set<ts.Expression>();
  const seenSymbols = new Set<ts.Symbol>();
  let steps = 0;
  const symbolAt = (node: ts.Identifier) => resolvedSymbolAt(node, checker);
  const collectReturns = (statement: ts.Statement): boolean => {
    check();
    if (ts.isReturnStatement(statement)) {
      if (statement.expression) expressions.push(statement.expression);
      return true;
    }
    if (ts.isBlock(statement)) {
      for (const child of statement.statements) {
        if (collectReturns(child)) return true;
      }
      return false;
    }
    if (ts.isIfStatement(statement)) {
      const condition = statement.expression.kind === ts.SyntaxKind.TrueKeyword
        ? true : statement.expression.kind === ts.SyntaxKind.FalseKeyword ? false : undefined;
      if (condition !== false && collectReturns(statement.thenStatement)) return condition === true;
      return condition !== true && Boolean(statement.elseStatement
        && collectReturns(statement.elseStatement));
    }
    return false;
  };
  const staticallyUnreachable = (node: ts.Node): boolean => {
    let child = node;
    let parent = node.parent;
    while (parent) {
      if (ts.isIfStatement(parent)) {
        if (parent.expression.kind === ts.SyntaxKind.FalseKeyword && child === parent.thenStatement) return true;
        if (parent.expression.kind === ts.SyntaxKind.TrueKeyword && child === parent.elseStatement) return true;
      }
      if (ts.isBlock(parent) && ts.isStatement(child)) {
        const index = parent.statements.indexOf(child);
        if (index > 0 && parent.statements.slice(0, index).some(ts.isReturnStatement)) return true;
      }
      child = parent;
      parent = parent.parent;
    }
    return false;
  };
  const queueSymbolEdges = (symbol: ts.Symbol): void => {
    if (seenSymbols.has(symbol)) return;
    seenSymbols.add(symbol);
    for (const declaration of symbol.declarations ?? []) {
      if (!projectSources.has(declaration.getSourceFile())) continue;
      if (ts.isVariableDeclaration(declaration) && declaration.initializer) {
        if (ts.isArrowFunction(declaration.initializer)
          || ts.isFunctionExpression(declaration.initializer)) {
          if (ts.isBlock(declaration.initializer.body)) collectReturns(declaration.initializer.body);
          else expressions.push(declaration.initializer.body);
        } else expressions.push(declaration.initializer);
      } else if (ts.isFunctionDeclaration(declaration) && declaration.body) {
        collectReturns(declaration.body);
      }
    }
    for (const node of referencesBySymbol.get(symbol) ?? []) {
      if (staticallyUnreachable(node)) continue;
      const access = (ts.isPropertyAccessExpression(node.parent)
        || ts.isElementAccessExpression(node.parent)) && node.parent.expression === node
        ? node.parent : undefined;
      const call = access && ts.isCallExpression(access.parent) && access.parent.expression === access
        ? access.parent : undefined;
      const accessName = access && (ts.isPropertyAccessExpression(access)
        ? access.name.text : access.argumentExpression
          ? resolveStaticPropertyKey(access.argumentExpression, checker, check) : undefined);
      if (access && call && (accessName === undefined || !READ_ONLY_ARRAY_METHODS.has(accessName))) {
        for (const argument of call.arguments) {
          expressions.push(ts.isSpreadElement(argument) ? argument.expression : argument);
        }
      }
      let aliasInitializer: ts.Expression = node;
      while ((ts.isParenthesizedExpression(aliasInitializer.parent)
        || ts.isAsExpression(aliasInitializer.parent)
        || ts.isTypeAssertionExpression(aliasInitializer.parent)
        || ts.isSatisfiesExpression(aliasInitializer.parent)
        || ts.isNonNullExpression(aliasInitializer.parent))
        && aliasInitializer.parent.expression === aliasInitializer) {
        aliasInitializer = aliasInitializer.parent;
      }
      const aliasDeclaration = ts.isVariableDeclaration(aliasInitializer.parent)
        && aliasInitializer.parent.initializer === aliasInitializer ? aliasInitializer.parent : undefined;
      if (aliasDeclaration && ts.isIdentifier(aliasDeclaration.name)
        && ts.isVariableDeclarationList(aliasDeclaration.parent)
        && aliasDeclaration.parent.flags & ts.NodeFlags.Const) expressions.push(aliasDeclaration.name);
      let target: ts.Node = access ?? node;
      while (target.parent && !ts.isStatement(target)) {
        const parent = target.parent;
        if (ts.isBinaryExpression(parent) && parent.left === target
          && parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
          && parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
          expressions.push(parent.right);
          break;
        }
        target = parent;
      }
    }
  };
  while (expressions.length > 0) {
    let expression = expressions.pop()!;
    check();
    steps += 1;
    if (steps > maxSteps) throw new SourceAnalyzerContractError('SOURCE_ANALYZER_AST_NODE_LIMIT');
    if (seenExpressions.has(expression)) continue;
    seenExpressions.add(expression);
    while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
      || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)
      || ts.isNonNullExpression(expression)) expression = expression.expression;
    if (isStaticSymbolFrom(expression, checker, check, '@nestjs/core', 'APP_GUARD')) return true;
    if (ts.isIdentifier(expression)) {
      const symbol = symbolAt(expression);
      if (symbol) queueSymbolEdges(symbol);
    } else if (ts.isCallExpression(expression) && ts.isIdentifier(expression.expression)) {
      const symbol = symbolAt(expression.expression);
      if (symbol) queueSymbolEdges(symbol);
    } else if (ts.isArrayLiteralExpression(expression)) {
      for (const element of expression.elements) {
        expressions.push(ts.isSpreadElement(element) ? element.expression : element);
      }
    } else if (ts.isObjectLiteralExpression(expression)) {
      const effectiveProperties: Array<[
        'providers' | 'provide', ReturnType<typeof effectiveObjectProperty>,
      ]> = [
        ['providers', effectiveObjectProperty(
          expression, 'providers', checker, projectSources, check,
        )],
        ['provide', effectiveObjectProperty(
          expression, 'provide', checker, projectSources, check,
        )],
      ];
      for (const [name, property] of effectiveProperties) {
        for (const initializer of property.candidates) {
          if (containsStaticSymbolFrom(
            initializer, checker, check, '@nestjs/core', 'APP_GUARD', projectSources,
          )) return true;
          if (name === 'providers') expressions.push(initializer);
        }
      }
    } else if (ts.isConditionalExpression(expression)) {
      let conditionExpression = expression.condition;
      while (ts.isParenthesizedExpression(conditionExpression)
        || ts.isAsExpression(conditionExpression) || ts.isTypeAssertionExpression(conditionExpression)
        || ts.isSatisfiesExpression(conditionExpression)
        || ts.isNonNullExpression(conditionExpression)) conditionExpression = conditionExpression.expression;
      const undefinedIdentifier = ts.isIdentifier(conditionExpression)
        && conditionExpression.text === 'undefined'
        && !checker.getSymbolAtLocation(conditionExpression)?.declarations?.length;
      const condition = conditionExpression.kind === ts.SyntaxKind.TrueKeyword
        ? true : conditionExpression.kind === ts.SyntaxKind.FalseKeyword
          || conditionExpression.kind === ts.SyntaxKind.NullKeyword
          || ts.isVoidExpression(conditionExpression) || undefinedIdentifier ? false : undefined;
      if (condition !== false) expressions.push(expression.whenTrue);
      if (condition !== true) expressions.push(expression.whenFalse);
    }
  }
  return false;
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

function directBaseClass(
  node: ts.ClassLikeDeclaration,
  checker: ts.TypeChecker,
  check: () => void,
  maxSteps: number,
): ts.ClassLikeDeclaration | undefined {
  let expression: ts.Expression | undefined = node.heritageClauses
    ?.find(({ token }) => token === ts.SyntaxKind.ExtendsKeyword)
    ?.types[0]?.expression;
  if (!expression) return undefined;
  const seen = new Set<ts.Symbol>();
  let steps = 0;
  while (expression) {
    check();
    steps += 1;
    if (steps > maxSteps) throw new SourceAnalyzerContractError('SOURCE_ANALYZER_AST_NODE_LIMIT');
    while (ts.isParenthesizedExpression(expression)) expression = expression.expression;
    let symbol = checker.getSymbolAtLocation(expression);
    if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    const declaration = symbol?.declarations?.find(ts.isClassLike)
      ?? (ts.isClassExpression(expression)
        ? checker.getTypeAtLocation(expression).getSymbol()?.declarations?.find(ts.isClassLike)
        : undefined);
    if (declaration) return declaration;
    if (!symbol || seen.has(symbol)) return undefined;
    seen.add(symbol);
    const aliases = symbol.declarations?.filter((candidate): candidate is ts.VariableDeclaration => (
      ts.isVariableDeclaration(candidate) && candidate.initializer !== undefined
      && ts.isVariableDeclarationList(candidate.parent)
      && Boolean(candidate.parent.flags & ts.NodeFlags.Const)
    )) ?? [];
    if (aliases.length !== 1) return undefined;
    expression = aliases[0].initializer;
  }
  return undefined;
}

function unresolvedBaseExpression(
  node: ts.ClassLikeDeclaration,
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  check: () => void,
  maxSteps: number,
): ts.Expression | undefined {
  const seen = new Set<ts.ClassLikeDeclaration>();
  let current: ts.ClassLikeDeclaration | undefined = node;
  let steps = 0;
  while (current && projectSources.has(current.getSourceFile()) && !seen.has(current)) {
    check();
    steps += 1;
    if (steps > maxSteps) throw new SourceAnalyzerContractError('SOURCE_ANALYZER_AST_NODE_LIMIT');
    seen.add(current);
    const expression = current.heritageClauses
      ?.find(({ token }) => token === ts.SyntaxKind.ExtendsKeyword)?.types[0]?.expression;
    if (!expression) return undefined;
    const base = directBaseClass(current, checker, check, maxSteps);
    if (!base || !projectSources.has(base.getSourceFile())) return expression;
    current = base;
  }
  return undefined;
}

function hasInheritedClassVersion(
  node: ts.ClassLikeDeclaration,
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  check: () => void,
  maxSteps: number,
): boolean {
  const seen = new Set<ts.ClassLikeDeclaration>();
  let current = directBaseClass(node, checker, check, maxSteps);
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
    current = directBaseClass(current, checker, check, maxSteps);
  }
  return false;
}

function effectiveControllerInChain(
  node: ts.ClassLikeDeclaration,
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  check: () => void,
  maxSteps: number,
): {
  decorator: ts.Decorator;
  classification: ReturnType<typeof classifyNestJsRouteDecorator>;
} | undefined {
  const seen = new Set<ts.ClassLikeDeclaration>();
  let current: ts.ClassLikeDeclaration | undefined = node;
  let steps = 0;
  while (current && projectSources.has(current.getSourceFile()) && !seen.has(current)) {
    check();
    steps += 1;
    if (steps > maxSteps) throw new SourceAnalyzerContractError('SOURCE_ANALYZER_AST_NODE_LIMIT');
    seen.add(current);
    for (const decorator of decorators(current)) {
      const classification = classifyNestJsRouteDecorator(decorator, checker, check);
      if (classification.candidate?.name === 'Controller'
        || classification.candidate?.name === 'Unknown') return { decorator, classification };
    }
    current = directBaseClass(current, checker, check, maxSteps);
  }
  return undefined;
}

interface AuthDecoratorMetadata {
  guardsPresent: boolean;
  guards: string[];
  publicPresent: boolean;
  explicitPublic: boolean;
  rolesPresent: boolean;
  roles: string[];
  dynamic: boolean;
  guardDynamic: boolean;
  publicDynamic: boolean;
  rolesDynamic: boolean;
  guardEvidence: ts.Decorator[];
  publicEvidence: ts.Decorator[];
  authorizationEvidence: ts.Decorator[];
}

function emptyAuthMetadata(): AuthDecoratorMetadata {
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

function ownAuthMetadata(
  node: ts.Node,
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  config: Readonly<NestJsAuthConfig>,
  check: () => void,
  maxSteps: number,
  maxDepth: number,
): AuthDecoratorMetadata {
  const result = emptyAuthMetadata();
  const resolvingWrappers = new Set<ts.Symbol>();
  const applyResolved = (
    resolved: NonNullable<ReturnType<typeof resolveDecoratorCallSymbol>>,
    evidence: ts.Decorator,
    depth: number,
  ): boolean => {
    check();
    if (depth > maxDepth) {
      result.guardDynamic = true;
      return true;
    }
    if (resolved.name === 'applyDecorators' && resolved.trustedNestJsCommon) {
      for (const argument of resolved.call.arguments) {
        if (!ts.isCallExpression(argument)) {
          result.guardDynamic = true;
          continue;
        }
        const nested = resolveDecoratorCallSymbol(argument, checker, check);
        if (nested) {
          if (!applyResolved(nested, evidence, depth + 1)) result.guardDynamic = true;
        }
        else result.guardDynamic = true;
      }
      return true;
    }
    if (resolved.name === 'UseGuards' && resolved.trustedNestJsCommon) {
      result.guardsPresent = true;
      result.guardEvidence.push(evidence);
      if (resolved.call.arguments.some(ts.isSpreadElement)) {
        result.guardDynamic = true;
        return true;
      }
      for (const argument of resolved.call.arguments) {
        const symbol = resolveStaticSymbolName(argument, checker, check);
        if (symbol) result.guards.push(symbol);
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
    const wrapperCall = resolveStaticDecoratorWrapperCall(
      resolved.call, checker, projectSources, check,
    );
    if (config.public_decorators.includes(resolved.name)) {
      result.publicPresent = true;
      result.explicitPublic = false;
      result.publicDynamic = false;
      result.publicEvidence = [evidence];
      if (wrapperCall && (!wrapperCall.stable || wrapperCall.dynamic)) result.publicDynamic = true;
      else if (resolved.call.arguments.length === 0) result.explicitPublic = true;
      else result.publicDynamic = true;
      return true;
    }
    if (config.roles_decorators.includes(resolved.name)) {
      result.rolesPresent = true;
      result.roles = [];
      result.rolesDynamic = Boolean(wrapperCall && (!wrapperCall.stable || wrapperCall.dynamic));
      result.authorizationEvidence = [evidence];
      for (const argument of resolved.call.arguments) {
        if (ts.isSpreadElement(argument)) {
          result.rolesDynamic = true;
          continue;
        }
        const values = resolveStaticStrings(argument, checker, projectSources, { check, maxSteps });
        if (values) result.roles.push(...values);
        else result.rolesDynamic = true;
      }
      return true;
    }
    if (wrapperCall?.dynamic) {
      result.guardDynamic = true;
      return true;
    }
    const wrapper = wrapperCall?.call
      && resolveDecoratorCallSymbol(wrapperCall.call, checker, check);
    if (!wrapper) return false;
    if (!wrapperCall.stable || resolvingWrappers.has(wrapperCall.symbol)
      || depth >= maxDepth) {
      result.guardDynamic = true;
      return true;
    }
    resolvingWrappers.add(wrapperCall.symbol);
    try {
      if (!applyResolved(wrapper, evidence, depth + 1)) result.guardDynamic = true;
      return true;
    } finally {
      resolvingWrappers.delete(wrapperCall.symbol);
    }
  };
  for (const decorator of [...decorators(node)].reverse()) {
    const bareName = resolveBareDecoratorName(decorator, checker, check);
    if (bareName && config.public_decorators.includes(bareName)) {
      result.publicPresent = true;
      result.explicitPublic = true;
      result.publicDynamic = false;
      result.publicEvidence = [decorator];
      continue;
    }
    const resolved = resolveDecoratorSymbol(decorator, checker, check, projectSources);
    if (resolved) {
      applyResolved(resolved, decorator, 0);
    }
  }
  result.dynamic = result.guardDynamic || result.publicDynamic || result.rolesDynamic;
  return result;
}

function effectiveClassAuthMetadata(
  node: ts.ClassLikeDeclaration,
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  config: Readonly<NestJsAuthConfig>,
  check: () => void,
  maxSteps: number,
  maxDepth: number,
): AuthDecoratorMetadata {
  const result = emptyAuthMetadata();
  const seen = new Set<ts.ClassLikeDeclaration>();
  let current: ts.ClassLikeDeclaration | undefined = node;
  let steps = 0;
  while (current && projectSources.has(current.getSourceFile()) && !seen.has(current)) {
    check();
    steps += 1;
    if (steps > maxSteps) throw new SourceAnalyzerContractError('SOURCE_ANALYZER_AST_NODE_LIMIT');
    seen.add(current);
    const own = ownAuthMetadata(
      current, checker, projectSources, config, check, maxSteps, maxDepth,
    );
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
      ?.find(({ token }) => token === ts.SyntaxKind.ExtendsKeyword)?.types[0]?.expression;
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

function composeAuth(
  classMetadata: AuthDecoratorMetadata,
  methodMetadata: AuthDecoratorMetadata,
  config: Readonly<NestJsAuthConfig>,
  globalGuardFound: boolean,
): {
  auth: ApiAuthenticationContractV1;
  exposure: ApiOperationInputV1['exposure'];
  evidence: Array<{ decorator: ts.Decorator; capability: 'authentication' | 'authorization' }>;
} {
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
  const analyzedGuards: ApiAuthAnalysisV1['guards'] = guards.map((symbol) => {
    const mapping = config.guard_mappings[symbol];
    return {
      symbol,
      ...(mapping ? { authKind: authKindToIr(mapping.auth_kind) } : {}),
    };
  });
  const unknownGuard = analyzedGuards.some(({ authKind }) => authKind === undefined);
  const capabilityReasons: string[] = [];
  if (globalGuardFound) capabilityReasons.push('Global NestJS guards are not analyzed.');
  if (authenticationDynamic) capabilityReasons.push('Dynamic authentication metadata was not inferred.');
  if (authorizationDynamic) capabilityReasons.push('Dynamic role metadata was not inferred.');
  if (unknownGuard) capabilityReasons.push('Unmapped NestJS guards remain unknown.');
  if (!explicitPublic && guards.length === 0) {
    capabilityReasons.push('Local guard absence does not prove a public route.');
  }
  if (classMetadata.rolesPresent || methodMetadata.rolesPresent) {
    capabilityReasons.push('Role metadata does not prove authorization enforcement.');
  }
  const enforcementConfidence = !globalGuardFound && !dynamic
    && (explicitPublic || (guards.length > 0 && !unknownGuard)) ? 'high' : 'unknown';
  const analysis: ApiAuthAnalysisV1 = {
    guards: analyzedGuards,
    explicitPublic,
    roles,
    enforcementConfidence,
    capabilityReasons,
  };
  let auth: ApiAuthenticationContractV1;
  let exposure: ApiOperationInputV1['exposure'];
  if (explicitPublic && !authenticationDynamic && !globalGuardFound) {
    auth = { mode: 'none', alternatives: [], analysis };
    exposure = 'public';
  } else if (guards.length > 0 && !unknownGuard && !authenticationDynamic && !globalGuardFound) {
    auth = {
      mode: 'alternatives',
      alternatives: [{
        anonymous: false,
        schemes: analyzedGuards.map(({ symbol, authKind }) => ({
          name: symbol,
          kind: authKind!,
          scopes: [],
          capability: 'supported',
        })),
      }],
      analysis,
    };
    exposure = 'authenticated';
  } else {
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
      ].map((decorator) => ({ decorator, capability: 'authentication' as const })),
      ...[
        ...classMetadata.authorizationEvidence,
        ...methodMetadata.authorizationEvidence,
      ].map((decorator) => ({ decorator, capability: 'authorization' as const })),
    ],
  };
}

function comparableAuth(
  exposure: ApiOperationInputV1['exposure'],
  auth: ApiAuthenticationContractV1,
): string {
  const sortedSet = (values: readonly string[]) => [...new Set(values)].sort((left, right) => (
    left < right ? -1 : left > right ? 1 : 0
  ));
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
    current = directBaseClass(current, checker, check, maxSteps);
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

async function analyze(
  context: Parameters<SourceAnalyzerPlugin['analyze']>[0],
  authConfig: Readonly<NestJsAuthConfig>,
) {
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
  const providerRegistrations = registeredProviderObjects(checker, projectSources, check);
  const providerCandidates = [
    ...providerRegistrations.candidates, ...providerRegistrations.providers,
  ];
  const identifierReferences = providerCandidates.length > 0
    ? indexIdentifierReferences(checker, projectSources, check) : new Map();
  const potentialGlobalProvider = providerCandidates.find((candidate) => (
    containsCanonicalProviderToken(
      candidate, checker, projectSources, check, context.limits.maxAstNodes, identifierReferences,
    )
  ));
  const registeredProviders = providerRegistrations.providers;
  const operations = new Map<string, ApiOperationInputV1>();
  const diagnostics: AnalyzerDiagnostic[] = [];
  const unresolvedOperations: UnresolvedSourceOperationCandidate[] = [];
  let unresolvedMethodCount = 0;
  let inspectedNodes = 0;
  let globalGuardFound = false;

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
    code: 'SOURCE_ANALYZER_DYNAMIC_ROUTE' | 'SOURCE_ANALYZER_DYNAMIC_AUTH_METADATA'
      | 'SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED' | 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR',
    node: ts.Node,
  ) => {
    if (diagnostics.length >= context.limits.maxDiagnostics) {
      throw new SourceAnalyzerContractError('SOURCE_ANALYZER_DIAGNOSTIC_LIMIT');
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
  if (potentialGlobalProvider) {
    addDiagnostic('SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED', potentialGlobalProvider);
    globalGuardFound = true;
  }
  const addUnresolved = (methods: readonly HttpMethod[], node: ts.Node, reason: UnresolvedSourceOperationCandidate['reason']) => {
    consume(methods.length);
    unresolvedMethodCount += methods.length;
    unresolvedOperations.push({
      methods: [...methods], path: null, reason, ...sourceLocation(node, context.workspaceRoot),
    });
  };

  for (const sourceFile of projectSources) {
    const nodes: ts.Node[] = [sourceFile];
    while (nodes.length > 0) {
      const node = nodes.pop()!;
      await checkpoint();
      if (ts.isCallExpression(node)
        && isNestJsUseGlobalGuardsCall(node, checker, check, projectSources)) {
        if (!globalGuardFound) addDiagnostic('SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED', node.expression);
        globalGuardFound = true;
      }
      const propertyNames = ts.isPropertyAssignment(node) && ts.isComputedPropertyName(node.name)
        ? (() => {
          if (isDefinitelyNonProvidePropertyKey(node.name.expression)) return [''];
          const key = resolveStaticPropertyKey(node.name.expression, checker, check);
          return key === undefined
            ? resolveStaticStrings(node.name.expression, checker, projectSources, {
              check, maxSteps: context.limits.maxAstNodes,
            })
            : [key];
        })()
        : undefined;
      const providerKeyPossible = ts.isPropertyAssignment(node) && (
        (ts.isIdentifier(node.name) || ts.isStringLiteral(node.name))
          ? node.name.text === 'provide'
          : ts.isComputedPropertyName(node.name) && (propertyNames === undefined
            || (propertyNames.length === 1 && propertyNames[0] === 'provide'))
      );
      const globalGuardProvider = (ts.isPropertyAssignment(node) && providerKeyPossible
        && isProviderRegistration(node, registeredProviders)
        && containsStaticSymbolFrom(
          node.initializer, checker, check, '@nestjs/core', 'APP_GUARD', projectSources,
        )) || (ts.isShorthandPropertyAssignment(node) && node.name.text === 'provide'
        && isProviderRegistration(node, registeredProviders)
        && isStaticShorthandSymbolFrom(
          node, checker, check, '@nestjs/core', 'APP_GUARD', projectSources,
        ));
      if (globalGuardProvider) {
        if (!globalGuardFound) addDiagnostic('SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED', node);
        globalGuardFound = true;
      }
      ts.forEachChild(node, (child) => { nodes.push(child); });
    }
  }

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
      const effectiveController = effectiveControllerInChain(
        statement, checker, projectSources, check, context.limits.maxAstNodes,
      );
      const unresolvedBase = unresolvedBaseExpression(
        statement, checker, projectSources, check, context.limits.maxAstNodes,
      );
      if (!effectiveController) {
        if (unresolvedBase) {
          let foundRoute = false;
          for (const method of statement.members.filter(ts.isMethodDeclaration)) {
            for (const decorator of decorators(method)) {
              const candidate = classifyNestJsRouteDecorator(decorator, checker, check).candidate;
              const methods = candidate && routeMethods(candidate.name);
              if (methods?.length) {
                addUnresolved(methods, decorator, 'SOURCE_ANALYZER_DYNAMIC_ROUTE');
                foundRoute = true;
                break;
              }
            }
          }
          const ownAuth = ownAuthMetadata(
            statement, checker, projectSources, authConfig, check,
            context.limits.maxAstNodes, context.limits.maxAnalysisDepth,
          );
          const hasAuthEvidence = ownAuth.guardsPresent || ownAuth.publicPresent
            || ownAuth.rolesPresent || ownAuth.dynamic;
          if (foundRoute || hasAuthEvidence) {
            addUnresolved(HTTP_METHODS, unresolvedBase, 'SOURCE_ANALYZER_DYNAMIC_ROUTE');
            addDiagnostic('SOURCE_ANALYZER_DYNAMIC_ROUTE', unresolvedBase);
            if (hasAuthEvidence) addDiagnostic('SOURCE_ANALYZER_DYNAMIC_AUTH_METADATA', statement);
          }
        }
        continue;
      }
      const trustedController = effectiveController.classification.route?.name === 'Controller';
      const classAuthMetadata = trustedController
        ? effectiveClassAuthMetadata(
          statement, checker, projectSources, authConfig, check,
          context.limits.maxAstNodes, context.limits.maxAnalysisDepth,
        )
        : emptyAuthMetadata();
      if (trustedController && classAuthMetadata.dynamic) {
        addDiagnostic('SOURCE_ANALYZER_DYNAMIC_AUTH_METADATA', statement);
      }
      const controllers = trustedController
        ? [{ decorator: effectiveController.decorator, match: effectiveController.classification.route }]
        : [];
      if (unresolvedBase) {
        addUnresolved(HTTP_METHODS, unresolvedBase, 'SOURCE_ANALYZER_DYNAMIC_ROUTE');
        addDiagnostic('SOURCE_ANALYZER_DYNAMIC_ROUTE', unresolvedBase);
      }
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
        const methodAuthMetadata = ownAuthMetadata(
          method, checker, projectSources, authConfig, check,
          context.limits.maxAstNodes, context.limits.maxAnalysisDepth,
        );
        if (methodAuthMetadata.dynamic) {
          addDiagnostic('SOURCE_ANALYZER_DYNAMIC_AUTH_METADATA', method);
        }
        const operationAuth = composeAuth(
          classAuthMetadata, methodAuthMetadata, authConfig, globalGuardFound,
        );
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
                  ...operationAuth.evidence.map(({ decorator: authDecorator, capability }) => {
                    const location = sourceLocation(authDecorator, context.workspaceRoot);
                    return {
                      source: 'source-ast' as const,
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
                    const left = previous.auth.analysis!;
                    const right = operationAuth.auth.analysis!;
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

  const contract = createSecurityContract({
    source: 'source-ast',
    capabilities: {
      routes: 'partial', parameters: 'unsupported', requestBodies: 'unsupported', authentication: 'partial',
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

const CAPABILITIES = Object.freeze({
  routePaths: Object.freeze({ status: 'partial' as const, reason: 'Static NestJS route paths are supported.' }),
  httpMethods: Object.freeze({ status: 'supported' as const, reason: 'NestJS HTTP method decorators are supported.' }),
  routerPrefixes: Object.freeze({ status: 'supported' as const, reason: 'Static controller prefixes are supported.' }),
  globalPrefixes: Object.freeze({ status: 'unsupported' as const, reason: 'Runtime global prefixes are not inspected.' }),
  authentication: Object.freeze({ status: 'partial' as const, reason: 'Configured local Guard and Public metadata are inspected.' }),
  authorization: Object.freeze({ status: 'partial' as const, reason: 'Configured static role labels are inspected.' }),
  requestContentTypes: Object.freeze({ status: 'unsupported' as const, reason: 'Request content types are not inspected.' }),
  requestLimits: Object.freeze({ status: 'unsupported' as const, reason: 'Request limits are not inspected.' }),
  sourceLocations: Object.freeze({ status: 'supported' as const, reason: 'Decorator locations are reported.' }),
  inheritedMetadata: Object.freeze({ status: 'partial' as const, reason: 'Project-local class inheritance is supported.' }),
  dynamicExpressions: Object.freeze({ status: 'partial' as const, reason: 'Only statically provable metadata is resolved.' }),
});

export function createNestJsSourceAnalyzer(config?: unknown): SourceAnalyzerPlugin {
  const authConfig = config === undefined ? EMPTY_NESTJS_AUTH_CONFIG : validateNestJsAuthConfig(config);
  return Object.freeze({
    id: ANALYZER_ID,
    version: ANALYZER_VERSION,
    languages: Object.freeze(['typescript']),
    frameworks: Object.freeze(['nestjs']),
    capabilities: CAPABILITIES,
    analyze: (context: Parameters<SourceAnalyzerPlugin['analyze']>[0]) => analyze(context, authConfig),
  });
}

export const nestJsSourceAnalyzer = createNestJsSourceAnalyzer();
