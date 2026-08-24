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
  isBareDecoratorBindingStable,
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
const MUTABLE_STORED_GUARD_CACHE = new WeakMap<
  ReadonlySet<ts.SourceFile>, WeakMap<ts.Symbol, boolean>
>();
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

function assignmentTargetContainsSymbol(
  input: ts.Node,
  symbol: ts.Symbol,
  checker: ts.TypeChecker,
  check: () => void,
): boolean {
  const nodes: ts.Node[] = [input];
  while (nodes.length > 0) {
    check();
    const node = nodes.pop()!;
    if (ts.isIdentifier(node)) {
      let target = checker.getSymbolAtLocation(node);
      if (target?.flags && target.flags & ts.SymbolFlags.Alias) target = checker.getAliasedSymbol(target);
      if (target === symbol) return true;
      continue;
    }
    if (ts.isPropertyAccessExpression(node)) {
      nodes.push(node.expression, node.name);
      continue;
    }
    if (ts.isElementAccessExpression(node)) {
      const key = node.argumentExpression
        ? resolveStaticPropertyKey(node.argumentExpression, checker, check) : undefined;
      const target = key === undefined ? undefined
        : checker.getNonNullableType(checker.getTypeAtLocation(node.expression)).getProperty(key);
      if (target === symbol) return true;
      nodes.push(node.expression);
      continue;
    }
    if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node)
      || ts.isTypeAssertionExpression(node) || ts.isSatisfiesExpression(node)
      || ts.isNonNullExpression(node)) nodes.push(node.expression);
    else if (ts.isArrayLiteralExpression(node)) {
      for (const element of node.elements) {
        if (!ts.isOmittedExpression(element)) {
          nodes.push(ts.isSpreadElement(element) ? element.expression : element);
        }
      }
    } else if (ts.isBinaryExpression(node)
      && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) nodes.push(node.left);
    else if (ts.isObjectLiteralExpression(node)) {
      for (const property of node.properties) {
        if (ts.isPropertyAssignment(property)) nodes.push(property.initializer);
        else if (ts.isShorthandPropertyAssignment(property)) nodes.push(property.name);
        else if (ts.isSpreadAssignment(property)) nodes.push(property.expression);
      }
    } else if (ts.isArrayBindingPattern(node) || ts.isObjectBindingPattern(node)) {
      nodes.push(...node.elements);
    } else if (ts.isBindingElement(node)) nodes.push(node.name);
    else if (ts.isVariableDeclarationList(node)) {
      nodes.push(...node.declarations.map(({ name }) => name));
    } else if (ts.isVariableDeclaration(node)) nodes.push(node.name);
  }
  return false;
}

function staticUndefinedState(
  input: ts.Expression,
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  check: () => void,
  seen = new Set<ts.Symbol>(),
  depth = 0,
): boolean | undefined {
  check();
  if (depth > 64) return undefined;
  let expression = input;
  while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
    || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)
    || ts.isNonNullExpression(expression)) expression = expression.expression;
  if (ts.isVoidExpression(expression)) return true;
  if (expression.kind === ts.SyntaxKind.NullKeyword || expression.kind === ts.SyntaxKind.TrueKeyword
    || expression.kind === ts.SyntaxKind.FalseKeyword || ts.isLiteralExpression(expression)
    || ts.isObjectLiteralExpression(expression) || ts.isArrayLiteralExpression(expression)
    || ts.isFunctionExpression(expression) || ts.isArrowFunction(expression)
    || ts.isClassExpression(expression) || ts.isNewExpression(expression)) return false;
  if (!ts.isIdentifier(expression)) return undefined;
  let symbol = checker.getSymbolAtLocation(expression);
  if (expression.text === 'undefined' && !symbol?.declarations?.length) return true;
  if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
  if (!symbol || seen.has(symbol)) return undefined;
  if (symbol.declarations?.some((declaration) => (
    (ts.isClassLike(declaration) || ts.isFunctionDeclaration(declaration))
    && projectSources.has(declaration.getSourceFile())
  ))) return false;
  const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
  const declaration = declarations.length === 1 ? declarations[0] : undefined;
  if (!declaration?.initializer || !projectSources.has(declaration.getSourceFile())
    || !ts.isVariableDeclarationList(declaration.parent)
    || !(declaration.parent.flags & ts.NodeFlags.Const)) return undefined;
  seen.add(symbol);
  return staticUndefinedState(
    declaration.initializer, checker, projectSources, check, seen, depth + 1,
  );
}

function isNestedDestructuringDefault(node: ts.BinaryExpression): boolean {
  if (node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return false;
  let current: ts.Node = node;
  while (current.parent) {
    const parent = current.parent;
    if (ts.isParenthesizedExpression(parent) || ts.isAsExpression(parent)
      || ts.isTypeAssertionExpression(parent) || ts.isSatisfiesExpression(parent)
      || ts.isNonNullExpression(parent) || ts.isArrayLiteralExpression(parent)) {
      current = parent;
      continue;
    }
    if (ts.isPropertyAssignment(parent) && parent.initializer === current
      && ts.isObjectLiteralExpression(parent.parent)) {
      current = parent.parent;
      continue;
    }
    return (ts.isBinaryExpression(parent) && parent.left === current)
      || ((ts.isForOfStatement(parent) || ts.isForInStatement(parent))
        && parent.initializer === current);
  }
  return false;
}

function assignmentValuesForSymbol(
  input: ts.Expression,
  value: ts.Expression,
  symbol: ts.Symbol,
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  check: () => void,
  depth = 0,
): readonly ts.Expression[] | undefined {
  check();
  if (depth > 64) return undefined;
  let target = input;
  while (ts.isParenthesizedExpression(target) || ts.isAsExpression(target)
    || ts.isTypeAssertionExpression(target) || ts.isSatisfiesExpression(target)
    || ts.isNonNullExpression(target)) target = target.expression;
  if (ts.isIdentifier(target)) {
    let targetSymbol = checker.getSymbolAtLocation(target);
    if (targetSymbol?.flags && targetSymbol.flags & ts.SymbolFlags.Alias) {
      targetSymbol = checker.getAliasedSymbol(targetSymbol);
    }
    return targetSymbol === symbol ? [value] : [];
  }
  if (ts.isPropertyAccessExpression(target) || ts.isElementAccessExpression(target)) {
    let targetSymbol = ts.isPropertyAccessExpression(target)
      ? checker.getSymbolAtLocation(target.name)
      : target.argumentExpression
        ? checker.getNonNullableType(checker.getTypeAtLocation(target.expression)).getProperty(
          resolveStaticPropertyKey(target.argumentExpression, checker, check) ?? '',
        ) : undefined;
    if (targetSymbol?.flags && targetSymbol.flags & ts.SymbolFlags.Alias) {
      targetSymbol = checker.getAliasedSymbol(targetSymbol);
    }
    return targetSymbol === symbol ? [value] : [];
  }
  if (ts.isBinaryExpression(target)
    && target.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
    const undefinedState = staticUndefinedState(value, checker, projectSources, check);
    const assignedValue = undefinedState === true ? target.right : value;
    const values = assignmentValuesForSymbol(
      target.left, assignedValue, symbol, checker, projectSources, check, depth + 1,
    );
    return values && undefinedState === undefined ? [...values, target.right] : values;
  }
  if (ts.isArrayLiteralExpression(target)) {
    if (!ts.isArrayLiteralExpression(value)) return undefined;
    const values: ts.Expression[] = [];
    for (let index = 0; index < target.elements.length; index += 1) {
      const element = target.elements[index];
      if (ts.isOmittedExpression(element)
        || !assignmentTargetContainsSymbol(element, symbol, checker, check)) continue;
      const candidate = value.elements[index];
      if (!candidate || ts.isOmittedExpression(candidate)) {
        if (!ts.isBinaryExpression(element)
          || element.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return undefined;
        const nested = assignmentValuesForSymbol(
          element.left, element.right, symbol, checker, projectSources, check, depth + 1,
        );
        if (!nested) return undefined;
        values.push(...nested);
        continue;
      }
      if (ts.isSpreadElement(element) || ts.isSpreadElement(candidate)) return undefined;
      const nested = assignmentValuesForSymbol(
        element, candidate, symbol, checker, projectSources, check, depth + 1,
      );
      if (!nested) return undefined;
      values.push(...nested);
    }
    return values;
  }
  if (ts.isObjectLiteralExpression(target)) {
    if (!ts.isObjectLiteralExpression(value)) return undefined;
    const values: ts.Expression[] = [];
    for (const property of target.properties) {
      if (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property)) {
        if (assignmentTargetContainsSymbol(property, symbol, checker, check)) return undefined;
        continue;
      }
      const nestedTarget = ts.isPropertyAssignment(property) ? property.initializer : property.name;
      if (!assignmentTargetContainsSymbol(nestedTarget, symbol, checker, check)) continue;
      const { name } = property;
      const propertyName = ts.isComputedPropertyName(name)
        ? resolveStaticPropertyKey(name.expression, checker, check)
        : (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name))
          ? name.text : undefined;
      if (propertyName === undefined) return undefined;
      const effective = effectiveObjectProperty(
        value, propertyName, checker, projectSources, check,
      );
      if (!effective.present) {
        if (!ts.isBinaryExpression(nestedTarget)
          || nestedTarget.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return undefined;
        const nested = assignmentValuesForSymbol(
          nestedTarget.left, nestedTarget.right, symbol, checker, projectSources, check, depth + 1,
        );
        if (!nested) return undefined;
        values.push(...nested);
        continue;
      }
      if (effective.accessor) return undefined;
      for (const candidate of effective.candidates) {
        const nested = assignmentValuesForSymbol(
          nestedTarget, candidate, symbol, checker, projectSources, check, depth + 1,
        );
        if (!nested) return undefined;
        values.push(...nested);
      }
    }
    return values;
  }
  return assignmentTargetContainsSymbol(target, symbol, checker, check) ? undefined : [];
}

function registeredProviderObjects(
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  check: () => void,
): {
  providers: ReadonlySet<ts.ObjectLiteralExpression>;
  candidates: readonly ts.Expression[];
  unresolvedProvider?: ts.Expression;
  externalModuleImport?: ts.Expression;
} {
  const providers = new Set<ts.ObjectLiteralExpression>();
  const candidates: ts.Expression[] = [];
  const staticState = (
    input: ts.Expression,
    seen = new Set<ts.Symbol>(),
    depth = 0,
  ): { truthy?: boolean; nullish?: boolean } => {
    check();
    if (depth > 64) return {};
    let expression = input;
    while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
      || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)
      || ts.isNonNullExpression(expression)) expression = expression.expression;
    if (ts.isBinaryExpression(expression) && (
      expression.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
      || expression.operatorToken.kind === ts.SyntaxKind.BarBarToken
      || expression.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken
    )) {
      const left = staticState(expression.left, new Set(seen), depth + 1);
      if (expression.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) {
        if (left.truthy === false) return left;
        if (left.truthy === true) return staticState(expression.right, seen, depth + 1);
      } else if (expression.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
        if (left.truthy === true) return left;
        if (left.truthy === false) return staticState(expression.right, seen, depth + 1);
      } else {
        if (left.nullish === false) return left;
        if (left.nullish === true) return staticState(expression.right, seen, depth + 1);
      }
      const right = staticState(expression.right, seen, depth + 1);
      return {
        ...(left.truthy === right.truthy ? { truthy: left.truthy } : {}),
        ...(left.nullish === right.nullish ? { nullish: left.nullish } : {}),
      };
    }
    if (expression.kind === ts.SyntaxKind.NullKeyword || ts.isVoidExpression(expression)) {
      return { truthy: false, nullish: true };
    }
    if (expression.kind === ts.SyntaxKind.TrueKeyword) return { truthy: true, nullish: false };
    if (expression.kind === ts.SyntaxKind.FalseKeyword) return { truthy: false, nullish: false };
    if (ts.isStringLiteral(expression) || ts.isNoSubstitutionTemplateLiteral(expression)) {
      return { truthy: expression.text.length > 0, nullish: false };
    }
    if (ts.isNumericLiteral(expression)) {
      return { truthy: Number(expression.text) !== 0, nullish: false };
    }
    if (ts.isBigIntLiteral(expression)) {
      return { truthy: BigInt(expression.text.slice(0, -1)) !== 0n, nullish: false };
    }
    if (ts.isObjectLiteralExpression(expression) || ts.isArrayLiteralExpression(expression)
      || ts.isFunctionExpression(expression) || ts.isArrowFunction(expression)
      || ts.isClassExpression(expression) || ts.isRegularExpressionLiteral(expression)
      || ts.isNewExpression(expression)) return { truthy: true, nullish: false };
    if (!ts.isIdentifier(expression)) return {};
    let symbol = checker.getSymbolAtLocation(expression);
    if (expression.text === 'undefined' && !symbol?.declarations?.length) {
      return { truthy: false, nullish: true };
    }
    if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    if (!symbol || seen.has(symbol)) return {};
    if (symbol.declarations?.some((declaration) => (
      (ts.isClassLike(declaration) || ts.isFunctionDeclaration(declaration))
      && projectSources.has(declaration.getSourceFile())
    ))) return { truthy: true, nullish: false };
    const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
    const declaration = declarations.length === 1 ? declarations[0] : undefined;
    if (!declaration?.initializer || !projectSources.has(declaration.getSourceFile())
      || !ts.isVariableDeclarationList(declaration.parent)
      || !(declaration.parent.flags & ts.NodeFlags.Const)) return {};
    seen.add(symbol);
    return staticState(declaration.initializer, seen, depth + 1);
  };
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
    if (ts.isBinaryExpression(expression) && (
      expression.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
      || expression.operatorToken.kind === ts.SyntaxKind.BarBarToken
      || expression.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken
    )) {
      const state = staticState(expression.left);
      if (expression.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) {
        if (state.truthy === true) return collect(expression.right, seen, depth + 1);
        if (state.truthy === false) return collect(expression.left, seen, depth + 1);
      } else if (expression.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
        if (state.truthy === true) return collect(expression.left, seen, depth + 1);
        if (state.truthy === false) return collect(expression.right, seen, depth + 1);
      } else {
        if (state.nullish === true) return collect(expression.right, seen, depth + 1);
        if (state.nullish === false) return collect(expression.left, seen, depth + 1);
      }
      const left = collect(expression.left, new Set(seen), depth + 1);
      const right = collect(expression.right, new Set(seen), depth + 1);
      return left && right;
    }
    if (ts.isCallExpression(expression) && expression.arguments.length === 0) {
      let callee: ts.Expression = expression.expression;
      while (ts.isParenthesizedExpression(callee)) callee = callee.expression;
      if ((ts.isArrowFunction(callee) || ts.isFunctionExpression(callee))
        && callee.parameters.length === 0
        && !callee.modifiers?.some(({ kind }) => kind === ts.SyntaxKind.AsyncKeyword)
        && (!ts.isFunctionExpression(callee) || callee.asteriskToken === undefined)) {
        const returned = ts.isBlock(callee.body)
          && callee.body.statements.length === 1
          && ts.isReturnStatement(callee.body.statements[0])
          ? callee.body.statements[0].expression
          : ts.isBlock(callee.body) ? undefined : callee.body;
        return returned ? collect(returned, seen, depth + 1) : false;
      }
      if (!ts.isIdentifier(callee)) return false;
      let symbol = checker.getSymbolAtLocation(callee);
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
  const reassignedSymbols = new Set<ts.Symbol>();
  const escapedSymbols = new Set<ts.Symbol>();
  const mutatedContainers = new Set<ts.Symbol>();
  const assignedValues = new Map<ts.Symbol, ts.Expression[]>();
  const unresolvedAssignments = new Set<ts.Symbol>();
  const aliases = new Map<ts.Symbol, Set<ts.Symbol>>();
  const memberMutationCache = new Map<ts.Symbol, boolean>();
  const pendingEscapes: ts.Expression[] = [];
  let escapeIndexIncomplete = false;
  let escapeSteps = 0;
  const isExternalModuleReference = (
    input: ts.Expression,
    seen = new Set<ts.Symbol>(),
    depth = 0,
  ): boolean => {
    check();
    if (depth > 64) return true;
    let expression = input;
    while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
      || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)
      || ts.isNonNullExpression(expression)) expression = expression.expression;
    if (ts.isArrayLiteralExpression(expression)) {
      return expression.elements.some((element) => isExternalModuleReference(
        ts.isSpreadElement(element) ? element.expression : element, new Set(seen), depth + 1,
      ));
    }
    if (ts.isConditionalExpression(expression)) {
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
    if (ts.isBinaryExpression(expression) && (
      expression.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
      || expression.operatorToken.kind === ts.SyntaxKind.BarBarToken
      || expression.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken
    )) {
      const state = staticState(expression.left);
      if (expression.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) {
        if (state.truthy === false) return false;
        if (state.truthy === true) {
          return isExternalModuleReference(expression.right, seen, depth + 1);
        }
      } else if (expression.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
        if (state.truthy === true) return false;
        if (state.truthy === false) {
          return isExternalModuleReference(expression.right, seen, depth + 1);
        }
      } else {
        if (state.nullish === false) return false;
        if (state.nullish === true) {
          return isExternalModuleReference(expression.right, seen, depth + 1);
        }
      }
      return isExternalModuleReference(expression.left, new Set(seen), depth + 1)
        || isExternalModuleReference(expression.right, new Set(seen), depth + 1);
    }
    if (ts.isCallExpression(expression)) {
      let callee: ts.Expression = expression.expression;
      while (ts.isParenthesizedExpression(callee)) callee = callee.expression;
      let callable: ts.ArrowFunction | ts.FunctionExpression | ts.FunctionDeclaration
        | ts.MethodDeclaration | undefined;
      if ((ts.isArrowFunction(callee) || ts.isFunctionExpression(callee))
        && callee.parameters.length === 0) callable = callee;
      if (ts.isIdentifier(callee)) {
        const original = checker.getSymbolAtLocation(callee);
        const importSpecifier = original?.declarations?.find(ts.isImportSpecifier);
        const importDeclaration = importSpecifier?.parent.parent.parent;
        const isForwardRef = callee.text === 'forwardRef' && importDeclaration
          && ts.isImportDeclaration(importDeclaration)
          && ts.isStringLiteral(importDeclaration.moduleSpecifier)
          && importDeclaration.moduleSpecifier.text === '@nestjs/common';
        const argument = isForwardRef && expression.arguments.length === 1
          ? expression.arguments[0] : undefined;
        if (argument && (ts.isArrowFunction(argument) || ts.isFunctionExpression(argument))
          && argument.parameters.length === 0) callable = argument;
        if (!callable && expression.arguments.length === 0) {
          let symbol = original;
          if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
          if (symbol && reassignedSymbols.has(symbol)) return true;
          const declarations = symbol?.declarations?.filter((candidate): candidate is ts.FunctionDeclaration => (
            ts.isFunctionDeclaration(candidate) && candidate.body !== undefined
            && candidate.parameters.length === 0 && projectSources.has(candidate.getSourceFile())
          )) ?? [];
          if (declarations.length === 1) callable = declarations[0];
        }
      }
      const body = callable?.body;
      const returned = body && !ts.isBlock(body) ? body
        : body && body.statements.length === 1 && ts.isReturnStatement(body.statements[0])
          ? body.statements[0].expression : undefined;
      return returned ? isExternalModuleReference(returned, seen, depth + 1) : true;
    }
    if (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression)) {
      let symbol = checker.getSymbolAtLocation(
        ts.isPropertyAccessExpression(expression) ? expression.name : expression,
      );
      if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
      if (symbol?.declarations?.some((declaration) => (
        declaration.getSourceFile().fileName.replaceAll('\\', '/').includes('/node_modules/')
      ))) return true;
      if (symbol?.declarations?.some((declaration) => (
        ts.isClassLike(declaration) && projectSources.has(declaration.getSourceFile())
      ))) return false;
      return true;
    }
    if (ts.isClassExpression(expression)) return false;
    if (expression.kind === ts.SyntaxKind.TrueKeyword
      || expression.kind === ts.SyntaxKind.FalseKeyword
      || expression.kind === ts.SyntaxKind.NullKeyword
      || ts.isVoidExpression(expression) || ts.isStringLiteral(expression)
      || ts.isNoSubstitutionTemplateLiteral(expression) || ts.isNumericLiteral(expression)
      || ts.isBigIntLiteral(expression)) return false;
    if (!ts.isIdentifier(expression)) return true;
    let symbol = checker.getSymbolAtLocation(expression);
    if (!symbol || seen.has(symbol)) return true;
    seen.add(symbol);
    if (symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    if (symbol.declarations?.some((declaration) => (
      declaration.getSourceFile().fileName.replaceAll('\\', '/').includes('/node_modules/')
    ))) return true;
    if (symbol.declarations?.some((declaration) => (
      ts.isClassLike(declaration) && projectSources.has(declaration.getSourceFile())
    ))) return false;
    const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
    const declaration = declarations.length === 1 ? declarations[0] : undefined;
    if (declaration?.initializer && projectSources.has(declaration.getSourceFile())
      && ts.isVariableDeclarationList(declaration.parent)
      && declaration.parent.flags & ts.NodeFlags.Const) {
      return isExternalModuleReference(declaration.initializer, seen, depth + 1);
    }
    return true;
  };
  const symbolAt = (node: ts.Node): ts.Symbol | undefined => {
    let symbol = checker.getSymbolAtLocation(node);
    if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    return symbol;
  };
  const rootSymbolAt = (input: ts.Expression): ts.Symbol | undefined => {
    let expression = input;
    while (true) {
      while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
        || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)
        || ts.isNonNullExpression(expression)) expression = expression.expression;
      if (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression)) {
        expression = expression.expression;
        continue;
      }
      return ts.isIdentifier(expression) ? resolvedSymbolAt(expression, checker) : undefined;
    }
  };
  const linkAliases = (left: ts.Symbol | undefined, right: ts.Symbol | undefined): void => {
    if (!left || !right || left === right) return;
    (aliases.get(left) ?? aliases.set(left, new Set()).get(left)!).add(right);
    (aliases.get(right) ?? aliases.set(right, new Set()).get(right)!).add(left);
  };
  const aliasSetHas = (
    values: ReadonlySet<ts.Symbol>, symbol: ts.Symbol,
  ): boolean => {
    const seen = new Set<ts.Symbol>();
    const pending = [symbol];
    while (pending.length > 0) {
      check();
      const candidate = pending.pop()!;
      if (values.has(candidate)) return true;
      if (seen.has(candidate)) continue;
      if (seen.size >= MAX_PROVIDER_SPREAD_ELEMENTS) return true;
      seen.add(candidate);
      pending.push(...(aliases.get(candidate) ?? []));
    }
    return false;
  };
  const markAssignmentTarget = (input: ts.Node): void => {
    let target = input;
    while (ts.isParenthesizedExpression(target) || ts.isAsExpression(target)
      || ts.isTypeAssertionExpression(target) || ts.isSatisfiesExpression(target)
      || ts.isNonNullExpression(target)) target = target.expression;
    if (ts.isIdentifier(target)) {
      const symbol = symbolAt(target);
      if (symbol) reassignedSymbols.add(symbol);
    } else if (ts.isPropertyAccessExpression(target)) {
      const symbol = symbolAt(target.name);
      if (symbol) reassignedSymbols.add(symbol);
    } else if (ts.isElementAccessExpression(target)) {
      const key = target.argumentExpression
        ? resolveStaticPropertyKey(target.argumentExpression, checker, check) : undefined;
      const symbol = key === undefined ? undefined
        : checker.getNonNullableType(checker.getTypeAtLocation(target.expression)).getProperty(key);
      if (symbol) reassignedSymbols.add(symbol);
      else if (ts.isIdentifier(target.expression)) {
        const receiver = symbolAt(target.expression);
        if (receiver) escapedSymbols.add(receiver);
      }
    } else if (ts.isArrayLiteralExpression(target)) {
      for (const element of target.elements) {
        if (!ts.isOmittedExpression(element)) {
          markAssignmentTarget(ts.isSpreadElement(element) ? element.expression : element);
        }
      }
    } else if (ts.isObjectLiteralExpression(target)) {
      for (const property of target.properties) {
        if (ts.isPropertyAssignment(property)) markAssignmentTarget(property.initializer);
        else if (ts.isShorthandPropertyAssignment(property)) markAssignmentTarget(property.name);
        else if (ts.isSpreadAssignment(property)) markAssignmentTarget(property.expression);
      }
    } else if (ts.isVariableDeclarationList(target)) {
      for (const declaration of target.declarations) markAssignmentTarget(declaration.name);
    } else if (ts.isVariableDeclaration(target) || ts.isBindingElement(target)) {
      markAssignmentTarget(target.name);
    } else if (ts.isArrayBindingPattern(target) || ts.isObjectBindingPattern(target)) {
      for (const element of target.elements) markAssignmentTarget(element);
    }
  };
  const directAssignmentSymbol = (input: ts.Expression): ts.Symbol | undefined => {
    let target = input;
    while (ts.isParenthesizedExpression(target) || ts.isAsExpression(target)
      || ts.isTypeAssertionExpression(target) || ts.isSatisfiesExpression(target)
      || ts.isNonNullExpression(target)) target = target.expression;
    if (ts.isIdentifier(target)) return symbolAt(target);
    if (ts.isPropertyAccessExpression(target)) return symbolAt(target.name);
    if (!ts.isElementAccessExpression(target)) return undefined;
    const key = target.argumentExpression
      ? resolveStaticPropertyKey(target.argumentExpression, checker, check) : undefined;
    return key === undefined ? undefined
      : checker.getNonNullableType(checker.getTypeAtLocation(target.expression)).getProperty(key);
  };
  const markEscapedValue = (input: ts.Expression, depth = 0): void => {
    check();
    if (escapeSteps++ >= MAX_PROVIDER_SPREAD_ELEMENTS) {
      escapeIndexIncomplete = true;
      return;
    }
    if (depth > 64) {
      escapeIndexIncomplete = true;
      return;
    }
    let value = input;
    while (ts.isParenthesizedExpression(value) || ts.isAsExpression(value)
      || ts.isTypeAssertionExpression(value) || ts.isSatisfiesExpression(value)
      || ts.isNonNullExpression(value)) value = value.expression;
    if (ts.isIdentifier(value)) {
      const symbol = resolvedSymbolAt(value, checker);
      const declarations = symbol?.declarations?.filter(ts.isVariableDeclaration) ?? [];
      const declaration = declarations.length === 1 ? declarations[0] : undefined;
      let initializer = declaration?.initializer;
      while (initializer && (ts.isParenthesizedExpression(initializer) || ts.isAsExpression(initializer)
        || ts.isTypeAssertionExpression(initializer) || ts.isSatisfiesExpression(initializer)
        || ts.isNonNullExpression(initializer))) initializer = initializer.expression;
      if (symbol && (resolveConstObject(value, checker, projectSources, check)
        || (initializer && (ts.isObjectLiteralExpression(initializer)
          || ts.isArrayLiteralExpression(initializer))))) escapedSymbols.add(symbol);
    } else if (ts.isArrayLiteralExpression(value)) {
      for (const element of value.elements) {
        if (!ts.isOmittedExpression(element)) {
          markEscapedValue(ts.isSpreadElement(element) ? element.expression : element, depth + 1);
        }
      }
    } else if (ts.isObjectLiteralExpression(value)) {
      for (const property of value.properties) {
        if (ts.isPropertyAssignment(property)) markEscapedValue(property.initializer, depth + 1);
        else if (ts.isShorthandPropertyAssignment(property)) markEscapedValue(property.name, depth + 1);
        else if (ts.isSpreadAssignment(property)) markEscapedValue(property.expression, depth + 1);
      }
    } else if (ts.isConditionalExpression(value)) {
      markEscapedValue(value.whenTrue, depth + 1);
      markEscapedValue(value.whenFalse, depth + 1);
    } else if (ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)) {
      const propertyName = ts.isPropertyAccessExpression(value) ? value.name.text
        : value.argumentExpression
          ? resolveStaticPropertyKey(value.argumentExpression, checker, check) : undefined;
      const object = resolveConstObject(value.expression, checker, projectSources, check);
      if (propertyName !== undefined && object) {
        const effective = effectiveObjectProperty(
          object, propertyName, checker, projectSources, check,
        );
        for (const candidate of effective.candidates) markEscapedValue(candidate, depth + 1);
        const member = symbolAt(ts.isPropertyAccessExpression(value) ? value.name : value);
        for (const candidate of member ? assignedValues.get(member) ?? [] : []) {
          markEscapedValue(candidate, depth + 1);
        }
        if (member && unresolvedAssignments.has(member)) escapeIndexIncomplete = true;
        let receiver: ts.Expression = value.expression;
        while (ts.isParenthesizedExpression(receiver) || ts.isAsExpression(receiver)
          || ts.isTypeAssertionExpression(receiver) || ts.isSatisfiesExpression(receiver)
          || ts.isNonNullExpression(receiver)) receiver = receiver.expression;
        const receiverSymbol = rootSymbolAt(receiver);
        if (receiverSymbol && (aliasSetHas(escapedSymbols, receiverSymbol)
          || aliasSetHas(mutatedContainers, receiverSymbol))) escapeIndexIncomplete = true;
      } else if (ts.isElementAccessExpression(value) && propertyName !== undefined) {
        let receiver: ts.Expression = value.expression;
        while (ts.isParenthesizedExpression(receiver) || ts.isAsExpression(receiver)
          || ts.isTypeAssertionExpression(receiver) || ts.isSatisfiesExpression(receiver)
          || ts.isNonNullExpression(receiver)) receiver = receiver.expression;
        if (ts.isIdentifier(receiver)) {
          const symbol = resolvedSymbolAt(receiver, checker);
          const declarations = symbol?.declarations?.filter(ts.isVariableDeclaration) ?? [];
          const declaration = declarations.length === 1 ? declarations[0] : undefined;
          if (declaration?.initializer && ts.isVariableDeclarationList(declaration.parent)
            && declaration.parent.flags & ts.NodeFlags.Const) receiver = declaration.initializer;
          while (ts.isParenthesizedExpression(receiver) || ts.isAsExpression(receiver)
            || ts.isTypeAssertionExpression(receiver) || ts.isSatisfiesExpression(receiver)
            || ts.isNonNullExpression(receiver)) receiver = receiver.expression;
        }
        const member = symbolAt(value);
        for (const candidate of member ? assignedValues.get(member) ?? [] : []) {
          markEscapedValue(candidate, depth + 1);
        }
        if (member && unresolvedAssignments.has(member)) escapeIndexIncomplete = true;
        let sourceReceiver: ts.Expression = value.expression;
        while (ts.isParenthesizedExpression(sourceReceiver) || ts.isAsExpression(sourceReceiver)
          || ts.isTypeAssertionExpression(sourceReceiver) || ts.isSatisfiesExpression(sourceReceiver)
          || ts.isNonNullExpression(sourceReceiver)) sourceReceiver = sourceReceiver.expression;
        const sourceSymbol = rootSymbolAt(sourceReceiver);
        if (sourceSymbol && (aliasSetHas(escapedSymbols, sourceSymbol)
          || aliasSetHas(mutatedContainers, sourceSymbol))) escapeIndexIncomplete = true;
        const index = Number(propertyName);
        const canonicalIndex = Number.isInteger(index) && index >= 0 && index < 0xffff_ffff
          && String(index) === propertyName;
        let remainingElements = MAX_PROVIDER_SPREAD_ELEMENTS;
        const flatten = (
          input: ts.Expression, flattenDepth = 0,
        ): readonly (ts.Expression | undefined)[] | undefined => {
          check();
          if (flattenDepth > 64) return undefined;
          let array = input;
          while (ts.isParenthesizedExpression(array) || ts.isAsExpression(array)
            || ts.isTypeAssertionExpression(array) || ts.isSatisfiesExpression(array)
            || ts.isNonNullExpression(array)) array = array.expression;
          if (ts.isIdentifier(array)) {
            const symbol = resolvedSymbolAt(array, checker);
            const declarations = symbol?.declarations?.filter(ts.isVariableDeclaration) ?? [];
            const declaration = declarations.length === 1 ? declarations[0] : undefined;
            if (!declaration?.initializer || !ts.isVariableDeclarationList(declaration.parent)
              || !(declaration.parent.flags & ts.NodeFlags.Const)) return undefined;
            return flatten(declaration.initializer, flattenDepth + 1);
          }
          if (!ts.isArrayLiteralExpression(array)) return undefined;
          const flattened: (ts.Expression | undefined)[] = [];
          for (const element of array.elements) {
            if (remainingElements-- <= 0) return undefined;
            if (ts.isOmittedExpression(element)) flattened.push(undefined);
            else if (ts.isSpreadElement(element)) {
              const spread = flatten(element.expression, flattenDepth + 1);
              if (!spread || spread.length > remainingElements) return undefined;
              remainingElements -= spread.length;
              flattened.push(...spread);
            } else flattened.push(element);
          }
          return flattened;
        };
        const flattened = flatten(receiver);
        if (flattened && canonicalIndex) {
          if (index < flattened.length) {
            const element = flattened[index];
            if (element) markEscapedValue(element, depth + 1);
          }
        } else escapeIndexIncomplete = true;
      } else escapeIndexIncomplete = true;
    } else if (ts.isBinaryExpression(value)) {
      const state = staticState(value.left);
      if (value.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) {
        if (state.truthy !== false) markEscapedValue(value.right, depth + 1);
        if (state.truthy !== true) markEscapedValue(value.left, depth + 1);
      } else if (value.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
        if (state.truthy !== true) markEscapedValue(value.right, depth + 1);
        if (state.truthy !== false) markEscapedValue(value.left, depth + 1);
      } else if (value.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken) {
        if (state.nullish !== false) markEscapedValue(value.right, depth + 1);
        if (state.nullish !== true) markEscapedValue(value.left, depth + 1);
      } else if (value.operatorToken.kind === ts.SyntaxKind.CommaToken) {
        markEscapedValue(value.right, depth + 1);
      }
    } else if (ts.isCallExpression(value)) {
      let callee: ts.Expression = value.expression;
      while (ts.isParenthesizedExpression(callee) || ts.isAsExpression(callee)
        || ts.isTypeAssertionExpression(callee) || ts.isSatisfiesExpression(callee)
        || ts.isNonNullExpression(callee)) callee = callee.expression;
      let callable: ts.ArrowFunction | ts.FunctionExpression | ts.FunctionDeclaration
        | ts.MethodDeclaration | undefined;
      let localCallReference = false;
      if (ts.isArrowFunction(callee) || ts.isFunctionExpression(callee)) callable = callee;
      else if (ts.isIdentifier(callee)) {
        const symbol = resolvedSymbolAt(callee, checker);
        localCallReference = symbol?.declarations?.some((declaration) => (
          projectSources.has(declaration.getSourceFile())
        )) ?? false;
        const declarations = symbol?.declarations?.filter((declaration): declaration is (
          ts.FunctionDeclaration
        ) => ts.isFunctionDeclaration(declaration) && declaration.body !== undefined
          && projectSources.has(declaration.getSourceFile())) ?? [];
        if (declarations.length === 1 && symbol && !reassignedSymbols.has(symbol)) callable = declarations[0];
      } else if (ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee)) {
        const symbol = symbolAt(ts.isPropertyAccessExpression(callee) ? callee.name : callee);
        const receiver = rootSymbolAt(callee.expression);
        const declarations = symbol?.declarations?.filter((declaration) => (
          projectSources.has(declaration.getSourceFile()) && (ts.isMethodDeclaration(declaration)
            || ts.isPropertyAssignment(declaration))
        )) ?? [];
        localCallReference = declarations.length > 0;
        const unstable = (symbol && (reassignedSymbols.has(symbol)
          || unresolvedAssignments.has(symbol) || assignedValues.has(symbol)))
          || (receiver && (aliasSetHas(escapedSymbols, receiver)
            || aliasSetHas(unstableContainers, receiver)));
        if (declarations.length === 1 && !unstable) {
          const declaration = declarations[0];
          const candidate = ts.isMethodDeclaration(declaration) ? declaration
            : ts.isPropertyAssignment(declaration) ? declaration.initializer : undefined;
          if (candidate && (ts.isArrowFunction(candidate) || ts.isFunctionExpression(candidate))) {
            callable = candidate;
          } else if (candidate && ts.isMethodDeclaration(candidate) && candidate.body) callable = candidate;
        }
      }
      if (!callable?.body) {
        if (localCallReference) escapeIndexIncomplete = true;
      }
      else if (callable.modifiers?.some(({ kind }) => kind === ts.SyntaxKind.AsyncKeyword)
        || ('asteriskToken' in callable && callable.asteriskToken)) {
        // Async and generator calls expose a Promise/iterator, not the returned object itself.
      } else if (callable.parameters.length > 0 || value.arguments.length > 0) {
        escapeIndexIncomplete = true;
      }
      else if (!ts.isBlock(callable.body)) markEscapedValue(callable.body, depth + 1);
      else {
        let foundReturn = false;
        const nodes: ts.Node[] = [...callable.body.statements];
        while (nodes.length > 0) {
          check();
          const node = nodes.pop()!;
          if (ts.isReturnStatement(node) && node.expression) {
            foundReturn = true;
            markEscapedValue(node.expression, depth + 1);
          } else if (!ts.isFunctionLike(node)) ts.forEachChild(node, (child) => { nodes.push(child); });
        }
        if (!foundReturn) escapeIndexIncomplete = true;
      }
    }
  };
  const markMutatedReceiver = (input: ts.Expression, depth = 0): void => {
    check();
    if (depth > 64) return;
    let receiver = input;
    while (ts.isParenthesizedExpression(receiver) || ts.isAsExpression(receiver)
      || ts.isTypeAssertionExpression(receiver) || ts.isSatisfiesExpression(receiver)
      || ts.isNonNullExpression(receiver)) receiver = receiver.expression;
    if (ts.isIdentifier(receiver)) {
      const symbol = resolvedSymbolAt(receiver, checker);
      if (symbol) mutatedContainers.add(symbol);
      return;
    }
    if (!ts.isPropertyAccessExpression(receiver) && !ts.isElementAccessExpression(receiver)) return;
    const propertyName = ts.isPropertyAccessExpression(receiver) ? receiver.name.text
      : receiver.argumentExpression
        ? resolveStaticPropertyKey(receiver.argumentExpression, checker, check) : undefined;
    const object = resolveConstObject(receiver.expression, checker, projectSources, check);
    if (propertyName === undefined || !object) return;
    const effective = effectiveObjectProperty(object, propertyName, checker, projectSources, check);
    for (const candidate of effective.candidates) markMutatedReceiver(candidate, depth + 1);
  };
  const indexNodes: ts.Node[] = [...projectSources];
  while (indexNodes.length > 0) {
    check();
    const node = indexNodes.pop()!;
    if (ts.isBinaryExpression(node) && !isNestedDestructuringDefault(node)
      && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
      && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
      markAssignmentTarget(node.left);
      const symbol = directAssignmentSymbol(node.left);
      if (symbol) {
        if (node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
          (assignedValues.get(symbol) ?? assignedValues.set(symbol, []).get(symbol)!).push(node.right);
        } else unresolvedAssignments.add(symbol);
      }
      if (node.operatorToken.kind === ts.SyntaxKind.EqualsToken
        && ts.isIdentifier(node.left) && ts.isIdentifier(node.right)) {
        linkAliases(symbolAt(node.left), symbolAt(node.right));
      }
    }
    else if (ts.isForOfStatement(node) || ts.isForInStatement(node)) {
      markAssignmentTarget(node.initializer);
      if (ts.isExpression(node.initializer)) {
        const symbol = directAssignmentSymbol(node.initializer);
        if (symbol) unresolvedAssignments.add(symbol);
      }
    } else if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)
      && node.initializer && ts.isIdentifier(node.initializer)) {
      linkAliases(symbolAt(node.name), symbolAt(node.initializer));
    } else if (ts.isCallExpression(node)) {
      const decorator = ts.isDecorator(node.parent)
        ? resolveDecoratorSymbol(node.parent, checker, check) : undefined;
      if (decorator?.name !== 'Module' || !decorator.nestJsCommon) {
        for (const argument of node.arguments) {
          const value = ts.isSpreadElement(argument) ? argument.expression : argument;
          pendingEscapes.push(value);
        }
      }
      const access = ts.isPropertyAccessExpression(node.expression)
        || ts.isElementAccessExpression(node.expression) ? node.expression : undefined;
      const method = access && (ts.isPropertyAccessExpression(access) ? access.name.text
        : access.argumentExpression
          ? resolveStaticPropertyKey(access.argumentExpression, checker, check) : undefined);
      const memberSymbol = access && symbolAt(ts.isPropertyAccessExpression(access)
        ? access.name : access);
      let localCallMayMutateReceiver = memberSymbol
        ? memberMutationCache.get(memberSymbol) : undefined;
      if (localCallMayMutateReceiver === undefined) {
        const localCallables = memberSymbol?.declarations?.filter((declaration) => (
          projectSources.has(declaration.getSourceFile()) && (ts.isMethodDeclaration(declaration)
            || ts.isPropertyAssignment(declaration))
        )) ?? [];
        localCallMayMutateReceiver = localCallables.length === 0 || localCallables.some((declaration) => {
          const callable = ts.isMethodDeclaration(declaration) ? declaration
            : ts.isPropertyAssignment(declaration) ? declaration.initializer : undefined;
          if (!callable || (!ts.isMethodDeclaration(callable) && !ts.isArrowFunction(callable)
            && !ts.isFunctionExpression(callable)) || !callable.body) return true;
          let usesThis = false;
          const nodes: ts.Node[] = [callable.body];
          while (nodes.length > 0 && !usesThis) {
            const current = nodes.pop()!;
            if (current.kind === ts.SyntaxKind.ThisKeyword) usesThis = true;
            else if (current !== callable && ts.isFunctionLike(current)
              && !ts.isArrowFunction(current)) continue;
            else ts.forEachChild(current, (child) => { nodes.push(child); });
          }
          return usesThis;
        });
        if (memberSymbol) memberMutationCache.set(memberSymbol, localCallMayMutateReceiver);
      }
      let callbackReadOnly = false;
      if (access && method && CALLBACK_ARRAY_METHODS.has(method)) {
        const callback = node.arguments[0];
        const callable = callback && (ts.isArrowFunction(callback) || ts.isFunctionExpression(callback))
          ? callback : undefined;
        const receiver = rootSymbolAt(access.expression);
        const arrayParameterIndex = method === 'reduce' || method === 'reduceRight' ? 4 : 3;
        if (callable && callable.parameters.length < arrayParameterIndex
          && !callable.parameters.some(({ dotDotDotToken }) => dotDotDotToken)) {
          let referencesReceiver = false;
          let referencesArguments = false;
          let mutatesElement = false;
          const elementParameter = callable.parameters[
            method === 'reduce' || method === 'reduceRight' ? 1 : 0
          ];
          const elementSymbol = elementParameter && ts.isIdentifier(elementParameter.name)
            ? symbolAt(elementParameter.name) : undefined;
          const elementSymbols = new Set(elementSymbol ? [elementSymbol] : []);
          let elementSteps = 0;
          const elementCache = new WeakMap<ts.Node, boolean>();
          const isElementSymbol = (symbol: ts.Symbol | undefined): boolean => (
            !!symbol && aliasSetHas(elementSymbols, symbol)
          );
          const containsElement = (input: ts.Node): boolean => {
            if (!elementSymbol) return false;
            const cached = elementCache.get(input);
            if (cached !== undefined) return cached;
            const pending: ts.Node[] = [input];
            while (pending.length > 0) {
              check();
              if (elementSteps++ >= MAX_PROVIDER_SPREAD_ELEMENTS) return true;
              const candidate = pending.pop()!;
              if (ts.isIdentifier(candidate)) {
                const symbol = symbolAt(candidate);
                if (isElementSymbol(symbol)) {
                  elementCache.set(input, true);
                  return true;
                }
              }
              if (candidate !== input && ((ts.isFunctionLike(candidate)
                && !ts.isArrowFunction(candidate)) || ts.isClassLike(candidate))) continue;
              ts.forEachChild(candidate, (child) => { pending.push(child); });
            }
            elementCache.set(input, false);
            return false;
          };
          const targetMutatesElement = (input: ts.Node): boolean => {
            let target = input;
            while (ts.isParenthesizedExpression(target) || ts.isAsExpression(target)
              || ts.isTypeAssertionExpression(target) || ts.isSatisfiesExpression(target)
              || ts.isNonNullExpression(target)) target = target.expression;
            if (ts.isPropertyAccessExpression(target) || ts.isElementAccessExpression(target)) {
              return isElementSymbol(rootSymbolAt(target.expression));
            }
            if (ts.isArrayLiteralExpression(target)) {
              return target.elements.some((element) => !ts.isOmittedExpression(element)
                && targetMutatesElement(ts.isSpreadElement(element) ? element.expression : element));
            }
            if (ts.isObjectLiteralExpression(target)) {
              return target.properties.some((property) => (
                ts.isPropertyAssignment(property) ? targetMutatesElement(property.initializer)
                  : ts.isShorthandPropertyAssignment(property) ? false
                    : ts.isSpreadAssignment(property) && targetMutatesElement(property.expression)
              ));
            }
            if (ts.isBinaryExpression(target)
              && target.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
              return targetMutatesElement(target.left);
            }
            return false;
          };
          const nodes: ts.Node[] = [callable.body];
          while (nodes.length > 0 && !referencesReceiver && !referencesArguments && !mutatesElement) {
            const current = nodes.pop()!;
            if (ts.isBinaryExpression(current) && elementSymbol
              && current.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
              && current.operatorToken.kind <= ts.SyntaxKind.LastAssignment
              && targetMutatesElement(current.left)) {
              mutatesElement = true;
            } else if (((ts.isPrefixUnaryExpression(current)
              && (current.operator === ts.SyntaxKind.PlusPlusToken
                || current.operator === ts.SyntaxKind.MinusMinusToken))
              || ts.isPostfixUnaryExpression(current))
              && targetMutatesElement(current.operand)) {
              mutatesElement = true;
            } else if (ts.isDeleteExpression(current)
              && targetMutatesElement(current.expression)) {
              mutatesElement = true;
            } else if (ts.isCallExpression(current) && elementSymbol) {
              const access = ts.isPropertyAccessExpression(current.expression)
                || ts.isElementAccessExpression(current.expression) ? current.expression : undefined;
              const calledMethod = access && (ts.isPropertyAccessExpression(access) ? access.name.text
                : access.argumentExpression
                  ? resolveStaticPropertyKey(access.argumentExpression, checker, check) : undefined);
              if (access && isElementSymbol(rootSymbolAt(access.expression))
                && (calledMethod === undefined || !READ_ONLY_ARRAY_METHODS.has(calledMethod))) {
                mutatesElement = true;
              } else if (current.arguments.some((argument) => containsElement(
                ts.isSpreadElement(argument) ? argument.expression : argument,
              ))) mutatesElement = true;
            } else if (ts.isTaggedTemplateExpression(current) && elementSymbol
              && ts.isTemplateExpression(current.template)
              && current.template.templateSpans.some(({ expression }) => containsElement(expression))) {
              mutatesElement = true;
            } else if (ts.isIdentifier(current) && receiver
              && resolvedSymbolAt(current, checker) === receiver) referencesReceiver = true;
            else if (ts.isFunctionExpression(callable) && ts.isIdentifier(current)
              && current.text === 'arguments') {
              const parent = current.parent;
              const declarationName = 'name' in parent && parent.name === current
                && !ts.isShorthandPropertyAssignment(parent);
              const bindingKey = ts.isBindingElement(parent) && parent.propertyName === current;
              const accessName = ts.isPropertyAccessExpression(parent) && parent.name === current;
              const label = (ts.isLabeledStatement(parent) || ts.isBreakStatement(parent)
                || ts.isContinueStatement(parent)) && parent.label === current;
              const qualifiedName = ts.isQualifiedName(parent);
              let typeOnly = false;
              let ancestor: ts.Node | undefined = parent;
              while (ancestor && !ts.isStatement(ancestor) && !ts.isExpression(ancestor)) {
                if (ts.isTypeNode(ancestor)) {
                  typeOnly = true;
                  break;
                }
                ancestor = ancestor.parent;
              }
              const argumentSymbol = checker.getSymbolAtLocation(current);
              const shadowed = argumentSymbol?.declarations?.some((declaration) => (
                declaration.getSourceFile() === callable.getSourceFile()
                && declaration.pos >= callable.pos && declaration.end <= callable.end
              )) ?? false;
              referencesArguments = !declarationName && !bindingKey && !accessName && !label
                && !qualifiedName && !typeOnly && !shadowed;
            }
            else if (current !== callable && ts.isFunctionLike(current)
              && !ts.isArrowFunction(current)) continue;
            else ts.forEachChild(current, (child) => { nodes.push(child); });
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
    ts.forEachChild(node, (child) => { indexNodes.push(child); });
  }
  let previousEscapedCount = -1;
  let escapeRounds = 0;
  while (escapedSymbols.size !== previousEscapedCount) {
    check();
    if (escapeRounds++ >= MAX_PROVIDER_SPREAD_ELEMENTS
      || escapeSteps >= MAX_PROVIDER_SPREAD_ELEMENTS) {
      escapeIndexIncomplete = true;
      break;
    }
    previousEscapedCount = escapedSymbols.size;
    for (const value of pendingEscapes) {
      markEscapedValue(value);
      if (escapeSteps >= MAX_PROVIDER_SPREAD_ELEMENTS) {
        escapeIndexIncomplete = true;
        break;
      }
    }
  }
  const unstableSymbols = new Set([...reassignedSymbols, ...escapedSymbols]);
  const pendingUnstable = [...unstableSymbols];
  while (pendingUnstable.length > 0) {
    const symbol = pendingUnstable.pop()!;
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
    const symbol = pendingContainers.pop()!;
    for (const alias of aliases.get(symbol) ?? []) {
      if (!unstableContainers.has(alias)) {
        unstableContainers.add(alias);
        pendingContainers.push(alias);
      }
    }
  }
  const isExternalProviderReference = (
    input: ts.Expression,
    seen = new Set<ts.Symbol>(),
    depth = 0,
    tokenPosition = false,
  ): boolean => {
    check();
    if (depth > 64) return true;
    let expression = input;
    while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
      || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)
      || ts.isNonNullExpression(expression)) expression = expression.expression;
    if (ts.isArrayLiteralExpression(expression)) {
      return expression.elements.some((element) => !ts.isOmittedExpression(element)
        && isExternalProviderReference(
          ts.isSpreadElement(element) ? element.expression : element,
          new Set(seen), depth + 1, tokenPosition,
        ));
    }
    if (ts.isObjectLiteralExpression(expression)) {
      const provide = effectiveObjectProperty(
        expression, 'provide', checker, projectSources, check,
      );
      return provide.candidates.some((candidate) => isExternalProviderReference(
        candidate, new Set(seen), depth + 1, true,
      ));
    }
    if (ts.isConditionalExpression(expression)) {
      const condition = staticState(expression.condition);
      return (condition.truthy !== false
          && isExternalProviderReference(expression.whenTrue, new Set(seen), depth + 1, tokenPosition))
        || (condition.truthy !== true
          && isExternalProviderReference(expression.whenFalse, new Set(seen), depth + 1, tokenPosition));
    }
    if (ts.isBinaryExpression(expression)) {
      const left = staticState(expression.left);
      if (expression.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) {
        if (left.truthy === false) return false;
        if (left.truthy === true) {
          return isExternalProviderReference(expression.right, seen, depth + 1, tokenPosition);
        }
      } else if (expression.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
        if (left.truthy === true) return false;
        if (left.truthy === false) {
          return isExternalProviderReference(expression.right, seen, depth + 1, tokenPosition);
        }
      } else if (expression.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken) {
        if (left.nullish === false) return false;
        if (left.nullish === true) {
          return isExternalProviderReference(expression.right, seen, depth + 1, tokenPosition);
        }
      }
      return isExternalProviderReference(expression.left, new Set(seen), depth + 1, tokenPosition)
        || isExternalProviderReference(expression.right, new Set(seen), depth + 1, tokenPosition);
    }
    if (ts.isCallExpression(expression)) {
      if (expression.arguments.some((argument) => isExternalProviderReference(
        ts.isSpreadElement(argument) ? argument.expression : argument,
        new Set(seen), depth + 1, tokenPosition,
      ))) return true;
      let callee: ts.Expression = expression.expression;
      while (ts.isParenthesizedExpression(callee)) callee = callee.expression;
      if ((ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee))) {
        const invocation = ts.isPropertyAccessExpression(callee) ? callee.name.text
          : callee.argumentExpression
            ? resolveStaticPropertyKey(callee.argumentExpression, checker, check) : undefined;
        if (invocation === 'call' || invocation === 'apply' || invocation === 'bind') {
          callee = callee.expression;
        }
      }
      const calleeAliases = new Set<ts.Symbol>();
      while (ts.isIdentifier(callee)) {
        let alias = checker.getSymbolAtLocation(callee);
        if (alias?.flags && alias.flags & ts.SymbolFlags.Alias) alias = checker.getAliasedSymbol(alias);
        if (!alias || calleeAliases.has(alias)) break;
        calleeAliases.add(alias);
        const declarations = alias.declarations?.filter(ts.isVariableDeclaration) ?? [];
        const declaration = declarations.length === 1 ? declarations[0] : undefined;
        if (!declaration?.initializer || !projectSources.has(declaration.getSourceFile())
          || !ts.isVariableDeclarationList(declaration.parent)
          || !(declaration.parent.flags & ts.NodeFlags.Const)) break;
        callee = declaration.initializer;
        while (ts.isParenthesizedExpression(callee) || ts.isAsExpression(callee)
          || ts.isTypeAssertionExpression(callee) || ts.isSatisfiesExpression(callee)
          || ts.isNonNullExpression(callee)) callee = callee.expression;
      }
      if (ts.isArrowFunction(callee) || ts.isFunctionExpression(callee)) {
        if (!tokenPosition && callee.parameters.length > 0) return true;
        if (!ts.isBlock(callee.body)) {
          return isExternalProviderReference(callee.body, new Set(seen), depth + 1, tokenPosition);
        }
        const nodes: ts.Node[] = [...callee.body.statements];
        while (nodes.length > 0) {
          check();
          const node = nodes.pop()!;
          if (ts.isReturnStatement(node) && node.expression
            && isExternalProviderReference(
              node.expression, new Set(seen), depth + 1, tokenPosition,
            )) return true;
          if (!ts.isFunctionLike(node)) ts.forEachChild(node, (child) => { nodes.push(child); });
        }
        return false;
      }
      if (isExternalProviderReference(callee, seen, depth + 1, tokenPosition)) return true;
      let symbol = checker.getSymbolAtLocation(callee);
      if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
      if (symbol?.declarations?.some((declaration) => (
        declaration.getSourceFile().fileName.replaceAll('\\', '/').includes('/node_modules/')
      ))) return true;
      const functionReturnsExternal = (
        callable: ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction
          | ts.MethodDeclaration,
      ): boolean => {
        if (!callable.body) return false;
        if (!ts.isBlock(callable.body)) {
          return isExternalProviderReference(callable.body, new Set(seen), depth + 1, tokenPosition);
        }
        const nodes: ts.Node[] = [...callable.body.statements];
        while (nodes.length > 0) {
          check();
          const node = nodes.pop()!;
          if (ts.isReturnStatement(node) && node.expression
            && isExternalProviderReference(
              node.expression, new Set(seen), depth + 1, tokenPosition,
            )) return true;
          if (!ts.isFunctionLike(node)) ts.forEachChild(node, (child) => { nodes.push(child); });
        }
        return false;
      };
      if (symbol && unstableSymbols.has(symbol)) return true;
      let resolvedLocalCallable = false;
      const localDeclarations = (symbol?.declarations ?? []).filter((declaration) => (
        projectSources.has(declaration.getSourceFile())
      ));
      const functionDeclarations = localDeclarations.filter(ts.isFunctionDeclaration);
      if (functionDeclarations.length > 0) {
        const implementations = functionDeclarations.filter((declaration) => declaration.body);
        if (implementations.length !== 1) return true;
        if (!tokenPosition && implementations[0].parameters.length > 0) return true;
        resolvedLocalCallable = true;
        if (functionReturnsExternal(implementations[0])) return true;
      }
      const methodDeclarations = localDeclarations.filter(ts.isMethodDeclaration);
      if (methodDeclarations.length > 0) {
        if (!tokenPosition || methodDeclarations.length !== 1 || !methodDeclarations[0].body) return true;
        resolvedLocalCallable = true;
        if (functionReturnsExternal(methodDeclarations[0])) return true;
      }
      for (const declaration of localDeclarations) {
        if (ts.isFunctionDeclaration(declaration) || ts.isMethodDeclaration(declaration)) continue;
        if (ts.isVariableDeclaration(declaration) || ts.isPropertyAssignment(declaration)) {
          if (!declaration.initializer) return true;
          let initializer = declaration.initializer;
          while (ts.isParenthesizedExpression(initializer) || ts.isAsExpression(initializer)
            || ts.isTypeAssertionExpression(initializer) || ts.isSatisfiesExpression(initializer)
            || ts.isNonNullExpression(initializer)) initializer = initializer.expression;
          if (!ts.isArrowFunction(initializer) && !ts.isFunctionExpression(initializer)) return true;
          if (!tokenPosition && initializer.parameters.length > 0) return true;
          resolvedLocalCallable = true;
          if (functionReturnsExternal(initializer)) return true;
        } else return true;
      }
      return tokenPosition ? false : !resolvedLocalCallable;
    }
    if (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression)) {
      const propertyName = ts.isPropertyAccessExpression(expression) ? expression.name.text
        : expression.argumentExpression
          ? resolveStaticPropertyKey(expression.argumentExpression, checker, check) : undefined;
      const receiver = resolveConstObject(expression.expression, checker, projectSources, check);
      const memberSymbol = symbolAt(ts.isPropertyAccessExpression(expression)
        ? expression.name : expression);
      let receiverExpression: ts.Expression = expression.expression;
      while (ts.isParenthesizedExpression(receiverExpression) || ts.isAsExpression(receiverExpression)
        || ts.isTypeAssertionExpression(receiverExpression) || ts.isSatisfiesExpression(receiverExpression)
        || ts.isNonNullExpression(receiverExpression)) receiverExpression = receiverExpression.expression;
      const receiverSymbol = rootSymbolAt(receiverExpression);
      if (tokenPosition && (escapeIndexIncomplete
        || (memberSymbol && unresolvedAssignments.has(memberSymbol))
        || (receiverSymbol && (unstableSymbols.has(receiverSymbol)
          || unstableContainers.has(receiverSymbol))))) return true;
      if (tokenPosition && memberSymbol && (assignedValues.get(memberSymbol) ?? []).some((value) => (
        isExternalProviderReference(value, new Set(seen), depth + 1, true)
      ))) return true;
      if (propertyName !== undefined && receiver) {
        const effective = effectiveObjectProperty(
          receiver, propertyName, checker, projectSources, check,
        );
        if (effective.present) {
          return effective.candidates.some((candidate) => (
            isExternalProviderReference(candidate, new Set(seen), depth + 1, tokenPosition)
          ));
        }
      }
      let symbol = checker.getSymbolAtLocation(ts.isPropertyAccessExpression(expression)
        ? expression.name : expression);
      if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
      if (symbol?.declarations?.some((declaration) => (
        ts.isClassLike(declaration) || ts.isFunctionDeclaration(declaration)
      ))) return false;
      if (symbol?.declarations?.some((declaration) => (
        declaration.getSourceFile().fileName.replaceAll('\\', '/').includes('/node_modules/')
      ))) return true;
      const property = symbol?.declarations?.find((declaration): declaration is (
        ts.PropertyAssignment | ts.ShorthandPropertyAssignment
      ) => ts.isPropertyAssignment(declaration) || ts.isShorthandPropertyAssignment(declaration));
      if (property && projectSources.has(property.getSourceFile())) {
        let initializer: ts.Expression | undefined = ts.isPropertyAssignment(property)
          ? property.initializer : undefined;
        if (ts.isShorthandPropertyAssignment(property)) {
          let value = checker.getShorthandAssignmentValueSymbol(property);
          if (value?.flags && value.flags & ts.SymbolFlags.Alias) value = checker.getAliasedSymbol(value);
          const declaration = value?.declarations?.find((entry): entry is ts.VariableDeclaration => (
            ts.isVariableDeclaration(entry) && entry.initializer !== undefined
          ));
          initializer = declaration?.initializer;
        }
        if (!initializer) return false;
        return isExternalProviderReference(initializer, seen, depth + 1, tokenPosition);
      }
      return !symbol && isExternalProviderReference(
        expression.expression, seen, depth + 1, tokenPosition,
      );
    }
    if (!ts.isIdentifier(expression)) return false;
    const symbol = resolvedSymbolAt(expression, checker);
    if (symbol?.getName() === 'APP_GUARD' && symbol.declarations?.some((declaration) => (
      declaration.getSourceFile().fileName.replaceAll('\\', '/').includes('/node_modules/@nestjs/core/')
    ))) return false;
    if (symbol?.declarations?.some(ts.isClassLike)) return false;
    if (symbol?.declarations?.some(ts.isFunctionDeclaration)) {
      const local = symbol.declarations.some((declaration) => (
        projectSources.has(declaration.getSourceFile())
      ));
      if (!local) return false;
      return reassignedSymbols.has(symbol) || unresolvedAssignments.has(symbol)
        || assignedValues.has(symbol) || aliasSetHas(escapedSymbols, symbol);
    }
    if (symbol?.declarations?.some((declaration) => (
      declaration.getSourceFile().fileName.replaceAll('\\', '/').includes('/node_modules/')
    ))) return true;
    if (!symbol || seen.has(symbol)) return false;
    seen.add(symbol);
    const bindings = symbol.declarations?.filter(ts.isBindingElement) ?? [];
    if (bindings.length > 0) {
      if (bindings.length !== 1) return true;
      const steps: ({ key: string } | { index: number })[] = [];
      let binding = bindings[0];
      let variable: ts.VariableDeclaration | undefined;
      while (true) {
        if (binding.dotDotDotToken || binding.initializer) return true;
        const pattern = binding.parent;
        if (ts.isObjectBindingPattern(pattern)) {
          const key = binding.propertyName && (ts.isIdentifier(binding.propertyName)
            || ts.isStringLiteral(binding.propertyName) || ts.isNumericLiteral(binding.propertyName))
            ? binding.propertyName.text : ts.isIdentifier(binding.name) ? binding.name.text : undefined;
          if (key === undefined) return true;
          steps.push({ key });
        } else if (ts.isArrayBindingPattern(pattern)) {
          const index = pattern.elements.indexOf(binding);
          if (index < 0) return true;
          steps.push({ index });
        } else return true;
        if (ts.isVariableDeclaration(pattern.parent)) {
          variable = pattern.parent;
          break;
        }
        if (ts.isParameter(pattern.parent)) return false;
        if (!ts.isBindingElement(pattern.parent)) return true;
        binding = pattern.parent;
      }
      if (!variable.initializer || !projectSources.has(variable.getSourceFile())
        || !ts.isVariableDeclarationList(variable.parent)
        || !(variable.parent.flags & ts.NodeFlags.Const)) return true;
      if (unresolvedAssignments.has(symbol) || reassignedSymbols.has(symbol)
        || aliasSetHas(escapedSymbols, symbol) || aliasSetHas(unstableContainers, symbol)) return true;
      let values: readonly ts.Expression[] = [variable.initializer];
      for (const step of steps.reverse()) {
        const next: ts.Expression[] = [];
        for (const value of values) {
          if ('key' in step) {
            const object = resolveConstObject(value, checker, projectSources, check);
            if (!object) return true;
            const effective = effectiveObjectProperty(
              object, step.key, checker, projectSources, check,
            );
            if (!effective.present || effective.accessor) return true;
            next.push(...effective.candidates);
          } else {
            let array = value;
            while (ts.isParenthesizedExpression(array) || ts.isAsExpression(array)
              || ts.isTypeAssertionExpression(array) || ts.isSatisfiesExpression(array)
              || ts.isNonNullExpression(array)) array = array.expression;
            if (!ts.isArrayLiteralExpression(array) || array.elements.some(ts.isSpreadElement)) return true;
            const element = array.elements[step.index];
            if (!element || ts.isOmittedExpression(element) || ts.isSpreadElement(element)) return true;
            next.push(element);
          }
        }
        values = next;
      }
      return [...values, ...(assignedValues.get(symbol) ?? [])].some((value) => isExternalProviderReference(
        value, new Set(seen), depth + 1, tokenPosition,
      ));
    }
    const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
    const declaration = declarations.length === 1 ? declarations[0] : undefined;
    if (!declaration) {
      return !tokenPosition && (symbol.declarations?.some((entry) => (
        ts.isParameter(entry) && projectSources.has(entry.getSourceFile())
      )) ?? false);
    }
    if (!projectSources.has(declaration.getSourceFile())) return false;
    const candidates: ts.Expression[] = [
      ...(declaration.initializer ? [declaration.initializer] : []),
      ...(assignedValues.get(symbol) ?? []),
    ];
    const unresolvedWrite = unresolvedAssignments.has(symbol)
      || unstableContainers.has(symbol) || escapedSymbols.has(symbol)
      || (reassignedSymbols.has(symbol) && !assignedValues.has(symbol));
    return unresolvedWrite || candidates.some((candidate) => (
      isExternalProviderReference(candidate, new Set(seen), depth + 1, tokenPosition)
    ));
  };
  let unresolvedProvider: ts.Expression | undefined;
  let externalModuleImport: ts.Expression | undefined;
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
            if (!collect(providerExpression, new Set(), 0)) candidates.push(providerExpression);
            if (!unresolvedProvider && isExternalProviderReference(providerExpression)) {
              unresolvedProvider = providerExpression;
            }
          }
          const effectiveImports = effectiveObjectProperty(
            metadata, 'imports', checker, projectSources, check,
          );
          externalModuleImport ??= effectiveImports.candidates.find((candidate) => (
            isExternalModuleReference(candidate)
          ));
        }
      }
      ts.forEachChild(node, (child) => { nodes.push(child); });
    }
  }
  return { providers, candidates, unresolvedProvider, externalModuleImport };
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
  const expressions: ts.Expression[] = [input];
  const seenExpressions = new Set<ts.Expression>();
  const seenSymbols = new Set<ts.Symbol>();
  let steps = 0;
  const symbolAt = (node: ts.Identifier) => resolvedSymbolAt(node, checker);
  const staticBoolean = (input: ts.Expression): boolean | undefined => {
    let expression = input;
    while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
      || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)
      || ts.isNonNullExpression(expression)) expression = expression.expression;
    return expression.kind === ts.SyntaxKind.TrueKeyword
      ? true : expression.kind === ts.SyntaxKind.FalseKeyword ? false : undefined;
  };
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
      const condition = staticBoolean(statement.expression);
      if (condition === true) return collectReturns(statement.thenStatement);
      if (condition === false) return Boolean(statement.elseStatement
        && collectReturns(statement.elseStatement));
      const whenTrue = collectReturns(statement.thenStatement);
      const whenFalse = Boolean(statement.elseStatement
        && collectReturns(statement.elseStatement));
      return whenTrue && whenFalse;
    }
    return false;
  };
  const staticallyUnreachable = (node: ts.Node): boolean => {
    let child = node;
    let parent = node.parent;
    while (parent) {
      if (ts.isIfStatement(parent)) {
        const condition = staticBoolean(parent.expression);
        if (condition === false && child === parent.thenStatement) return true;
        if (condition === true && child === parent.elseStatement) return true;
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

function isUnresolvedStoredGuardDecorator(
  decorator: ts.Decorator,
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  check: () => void,
): boolean {
  const seen = new Set<ts.Symbol>();
  const unwrap = (input: ts.Expression): ts.Expression => {
    let current = input;
    while (ts.isParenthesizedExpression(current) || ts.isAsExpression(current)
      || ts.isTypeAssertionExpression(current) || ts.isSatisfiesExpression(current)
      || ts.isNonNullExpression(current)) current = current.expression;
    return current;
  };
  const expressionUsesGuardDecorator = (
    input: ts.Expression,
  ): boolean => {
    const expressions: ts.Expression[] = [input];
    const visited = new Set<ts.Symbol>();
    const assignments = new Map<ts.Symbol, readonly ts.Expression[] | null>();
    const assignmentValues = (symbol: ts.Symbol): readonly ts.Expression[] | undefined => {
      const cached = assignments.get(symbol);
      if (cached !== undefined) return cached ?? undefined;
      const values: ts.Expression[] = [];
      let unresolved = false;
      const nodes: ts.Node[] = [...projectSources];
      while (nodes.length > 0) {
        check();
        const node = nodes.pop()!;
        if (ts.isBinaryExpression(node) && !isNestedDestructuringDefault(node)
          && assignmentTargetContainsSymbol(node.left, symbol, checker, check)) {
          if (node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
            const assigned = assignmentValuesForSymbol(
              node.left, node.right, symbol, checker, projectSources, check,
            );
            if (assigned) values.push(...assigned);
            else unresolved = true;
          }
          else if (node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
            && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment) unresolved = true;
        } else if ((ts.isForOfStatement(node) || ts.isForInStatement(node))
          && assignmentTargetContainsSymbol(node.initializer, symbol, checker, check)) {
          if (ts.isVariableDeclarationList(node.initializer)) unresolved = true;
          else {
            const assigned = assignmentValuesForSymbol(
              node.initializer, node.expression, symbol, checker, projectSources, check,
            );
            if (assigned) values.push(...assigned);
            else unresolved = true;
          }
        }
        ts.forEachChild(node, (child) => { nodes.push(child); });
      }
      assignments.set(symbol, unresolved ? null : values);
      return unresolved ? undefined : values;
    };
    let steps = 0;
    while (expressions.length > 0) {
      check();
      steps += 1;
      if (steps > 64) return true;
      const candidate = unwrap(expressions.pop()!);
      if (ts.isCallExpression(candidate)) {
        const resolved = resolveDecoratorCallSymbol(candidate, checker, check);
        if (resolved?.nestJsCommon
          && (resolved.name === 'UseGuards' || resolved.name === 'applyDecorators')) return true;
        expressions.push(...candidate.arguments.map((argument) => (
          ts.isSpreadElement(argument) ? argument.expression : argument
        )));
        let calleeExpression = unwrap(candidate.expression);
        const calleeAliases = new Set<ts.Symbol>();
        while (ts.isIdentifier(calleeExpression)) {
          let alias = checker.getSymbolAtLocation(calleeExpression);
          if (alias?.flags && alias.flags & ts.SymbolFlags.Alias) alias = checker.getAliasedSymbol(alias);
          if (!alias || calleeAliases.has(alias)) break;
          calleeAliases.add(alias);
          const declarations = alias.declarations?.filter(ts.isVariableDeclaration) ?? [];
          const declaration = declarations.length === 1 ? declarations[0] : undefined;
          if (!declaration?.initializer || !projectSources.has(declaration.getSourceFile())
            || !ts.isVariableDeclarationList(declaration.parent)
            || !(declaration.parent.flags & ts.NodeFlags.Const)) break;
          calleeExpression = unwrap(declaration.initializer);
        }
        if (ts.isArrowFunction(calleeExpression) || ts.isFunctionExpression(calleeExpression)) {
          if (!ts.isBlock(calleeExpression.body)) expressions.push(calleeExpression.body);
          else {
            const nodes: ts.Node[] = [...calleeExpression.body.statements];
            while (nodes.length > 0) {
              check();
              const node = nodes.pop()!;
              if (ts.isReturnStatement(node) && node.expression) expressions.push(node.expression);
              else if (!ts.isFunctionLike(node)) {
                ts.forEachChild(node, (child) => { nodes.push(child); });
              }
            }
          }
          continue;
        }
        let calleeSymbol = checker.getSymbolAtLocation(calleeExpression);
        if (calleeSymbol?.flags && calleeSymbol.flags & ts.SymbolFlags.Alias) {
          calleeSymbol = checker.getAliasedSymbol(calleeSymbol);
        }
        if (calleeSymbol?.declarations?.some(ts.isMethodDeclaration)) return true;
        if (calleeSymbol?.declarations?.some((declaration) => (
          projectSources.has(declaration.getSourceFile())
        ))) {
          const values = assignmentValues(calleeSymbol);
          if (!values) return true;
          expressions.push(...values);
        }
        for (const declaration of calleeSymbol?.declarations ?? []) {
          if (!projectSources.has(declaration.getSourceFile())) continue;
          const callable = ts.isFunctionDeclaration(declaration) && declaration.body
            ? declaration
            : ts.isVariableDeclaration(declaration) && declaration.initializer
              && (ts.isArrowFunction(unwrap(declaration.initializer))
                || ts.isFunctionExpression(unwrap(declaration.initializer)))
              ? unwrap(declaration.initializer) as ts.ArrowFunction | ts.FunctionExpression
              : undefined;
          if (!callable) continue;
          const body = callable.body;
          if (!body) continue;
          if (!ts.isBlock(body)) expressions.push(body);
          else {
            const nodes: ts.Node[] = [...body.statements];
            while (nodes.length > 0) {
              check();
              const node = nodes.pop()!;
              if (ts.isReturnStatement(node) && node.expression) expressions.push(node.expression);
              else if (node !== callable && !ts.isFunctionLike(node)) {
                ts.forEachChild(node, (child) => { nodes.push(child); });
              }
            }
          }
        }
        continue;
      }
      if (ts.isArrowFunction(candidate) || ts.isFunctionExpression(candidate)) {
        if (!ts.isBlock(candidate.body)) expressions.push(candidate.body);
        else {
          const nodes: ts.Node[] = [...candidate.body.statements];
          while (nodes.length > 0) {
            check();
            const node = nodes.pop()!;
            if (ts.isReturnStatement(node) && node.expression) expressions.push(node.expression);
            else if (!ts.isFunctionLike(node)) {
              ts.forEachChild(node, (child) => { nodes.push(child); });
            }
          }
        }
        continue;
      }
      if (ts.isIdentifier(candidate)) {
        let symbol = checker.getSymbolAtLocation(candidate);
        if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
        if (!symbol || visited.has(symbol)) continue;
        visited.add(symbol);
        if (symbol.declarations?.some((entry) => (
          ts.isParameter(entry) && projectSources.has(entry.getSourceFile())
        ))) return true;
        const declaration = symbol.declarations?.find((entry): entry is ts.VariableDeclaration => (
          ts.isVariableDeclaration(entry) && entry.initializer !== undefined
          && projectSources.has(entry.getSourceFile())
        ));
        if (declaration?.initializer) expressions.push(declaration.initializer);
        if (symbol.declarations?.some((entry) => projectSources.has(entry.getSourceFile()))) {
          const values = assignmentValues(symbol);
          if (!values) return true;
          expressions.push(...values);
        }
        continue;
      }
      if (ts.isConditionalExpression(candidate)) {
        expressions.push(candidate.whenTrue, candidate.whenFalse);
      } else if (ts.isBinaryExpression(candidate)) {
        expressions.push(candidate.left, candidate.right);
      } else if (ts.isArrayLiteralExpression(candidate)) {
        for (const element of candidate.elements) {
          if (!ts.isOmittedExpression(element)) {
            expressions.push(ts.isSpreadElement(element) ? element.expression : element);
          }
        }
      } else if (ts.isObjectLiteralExpression(candidate)) {
        for (const property of candidate.properties) {
          if (ts.isPropertyAssignment(property)) expressions.push(property.initializer);
          else if (ts.isSpreadAssignment(property)) expressions.push(property.expression);
          else if (ts.isShorthandPropertyAssignment(property)) expressions.push(property.name);
        }
      }
    }
    return false;
  };
  const mutableBindingUsesGuardDecorator = (
    symbol: ts.Symbol,
    declaration: ts.VariableDeclaration,
  ): boolean => {
    let projectCache = MUTABLE_STORED_GUARD_CACHE.get(projectSources);
    if (!projectCache) {
      projectCache = new WeakMap();
      MUTABLE_STORED_GUARD_CACHE.set(projectSources, projectCache);
    }
    const cached = projectCache.get(symbol);
    if (cached !== undefined) return cached;
    let found = Boolean(declaration.initializer
      && expressionUsesGuardDecorator(declaration.initializer));
    const nodes: ts.Node[] = found ? [] : [...projectSources];
    while (nodes.length > 0 && !found) {
      const node = nodes.pop()!;
      check();
      if (ts.isBinaryExpression(node) && !isNestedDestructuringDefault(node)
        && assignmentTargetContainsSymbol(node.left, symbol, checker, check)) {
        if (node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
          && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
          if (node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) found = true;
          else {
            const assigned = assignmentValuesForSymbol(
              node.left, node.right, symbol, checker, projectSources, check,
            );
            found = !assigned || assigned.some(expressionUsesGuardDecorator);
          }
        }
      } else if ((ts.isForOfStatement(node) || ts.isForInStatement(node))
        && assignmentTargetContainsSymbol(node.initializer, symbol, checker, check)) {
        if (ts.isVariableDeclarationList(node.initializer)) found = true;
        else {
          const assigned = assignmentValuesForSymbol(
            node.initializer, node.expression, symbol, checker, projectSources, check,
          );
          found = !assigned || assigned.some(expressionUsesGuardDecorator);
        }
      }
      ts.forEachChild(node, (child) => { nodes.push(child); });
    }
    projectCache.set(symbol, found);
    return found;
  };
  let expression: ts.Expression = decorator.expression;
  expression = unwrap(expression);
  if (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression)) {
    const receiver = unwrap(expression.expression);
    const namespace = ts.isIdentifier(receiver)
      ? checker.getSymbolAtLocation(receiver)?.declarations?.some(ts.isNamespaceImport) : false;
    let member = checker.getSymbolAtLocation(
      ts.isPropertyAccessExpression(expression) ? expression.name : expression,
    );
    if (member?.flags && member.flags & ts.SymbolFlags.Alias) member = checker.getAliasedSymbol(member);
    const declarations = member?.declarations?.filter((declaration) => (
      projectSources.has(declaration.getSourceFile())
    )) ?? [];
    if (namespace && declarations.length > 0) {
      for (const declaration of declarations) {
        if (ts.isVariableDeclaration(declaration)) {
          if (!ts.isVariableDeclarationList(declaration.parent)
            || !(declaration.parent.flags & ts.NodeFlags.Const)) return true;
          if (declaration.initializer && expressionUsesGuardDecorator(declaration.initializer)) return true;
        } else if (ts.isFunctionDeclaration(declaration) && declaration.body) {
          const writes: ts.Node[] = [...projectSources];
          while (writes.length > 0) {
            check();
            const node = writes.pop()!;
            if (ts.isBinaryExpression(node) && !isNestedDestructuringDefault(node)
              && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
              && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment
              && member && assignmentTargetContainsSymbol(node.left, member, checker, check)) return true;
            if ((ts.isForOfStatement(node) || ts.isForInStatement(node)) && member
              && assignmentTargetContainsSymbol(node.initializer, member, checker, check)) return true;
            ts.forEachChild(node, (child) => { writes.push(child); });
          }
          const returns: ts.Expression[] = [];
          const staticTruth = (input: ts.Expression): boolean | undefined => {
            let value = input;
            while (ts.isParenthesizedExpression(value) || ts.isAsExpression(value)
              || ts.isTypeAssertionExpression(value) || ts.isSatisfiesExpression(value)
              || ts.isNonNullExpression(value)) value = value.expression;
            if (value.kind === ts.SyntaxKind.TrueKeyword) return true;
            if (value.kind === ts.SyntaxKind.FalseKeyword || value.kind === ts.SyntaxKind.NullKeyword
              || ts.isVoidExpression(value)) return false;
            if (ts.isNumericLiteral(value)) return Number(value.text) !== 0;
            if (ts.isStringLiteral(value) || ts.isNoSubstitutionTemplateLiteral(value)) {
              return value.text.length > 0;
            }
            if (ts.isIdentifier(value) && value.text === 'undefined'
              && !checker.getSymbolAtLocation(value)?.declarations?.length) return false;
            return undefined;
          };
          const NORMAL = 1;
          const RETURN = 2;
          const BREAK = 4;
          const CONTINUE = 8;
          let flowDepth = 0;
          let flowOverflow = false;
          const collect = (statement: ts.Statement): number => {
            check();
            if (flowDepth >= 32) {
              flowOverflow = true;
              return NORMAL;
            }
            flowDepth += 1;
            try {
              if (ts.isReturnStatement(statement)) {
                if (statement.expression) returns.push(statement.expression);
                return RETURN;
              }
              if (ts.isBreakStatement(statement)) return BREAK;
              if (ts.isContinueStatement(statement)) return CONTINUE;
              if (ts.isBlock(statement)) {
                let flow = NORMAL;
                for (const child of statement.statements) {
                  if (!(flow & NORMAL)) break;
                  flow = (flow & ~NORMAL) | collect(child);
                }
                return flow;
              } else if (ts.isIfStatement(statement)) {
                const condition = staticTruth(statement.expression);
                if (condition === false) {
                  return statement.elseStatement ? collect(statement.elseStatement) : NORMAL;
                }
                if (condition === true) return collect(statement.thenStatement);
                return collect(statement.thenStatement)
                  | (statement.elseStatement ? collect(statement.elseStatement) : NORMAL);
              } else if (ts.isTryStatement(statement)) {
                const start = returns.length;
                const tryFlow = collect(statement.tryBlock);
                const bodyFlow = statement.catchClause
                  ? tryFlow | collect(statement.catchClause.block) : tryFlow;
                const beforeFinally = returns.length;
                const finallyFlow = statement.finallyBlock ? collect(statement.finallyBlock) : NORMAL;
                if (!(finallyFlow & NORMAL)) returns.splice(start, beforeFinally - start);
                return (finallyFlow & ~NORMAL)
                  | ((finallyFlow & NORMAL) ? bodyFlow : 0);
              } else if (ts.isSwitchStatement(statement)) {
                let flow = NORMAL;
                for (const clause of statement.caseBlock.clauses) {
                  let clauseFlow = NORMAL;
                  for (const child of clause.statements) {
                    if (!(clauseFlow & NORMAL)) break;
                    clauseFlow = (clauseFlow & ~NORMAL) | collect(child);
                  }
                  flow |= clauseFlow;
                }
                return flow;
              } else if (ts.isWhileStatement(statement)) {
                if (staticTruth(statement.expression) === false) return NORMAL;
                return NORMAL | (collect(statement.statement) & RETURN);
              } else if (ts.isForStatement(statement)) {
                if (statement.condition && staticTruth(statement.condition) === false) return NORMAL;
                return NORMAL | (collect(statement.statement) & RETURN);
              } else if (ts.isDoStatement(statement)) {
                const bodyFlow = collect(statement.statement);
                return (bodyFlow & RETURN) | (bodyFlow === RETURN ? 0 : NORMAL);
              } else if (ts.isForInStatement(statement) || ts.isForOfStatement(statement)) {
                return NORMAL | (collect(statement.statement) & RETURN);
              }
              return NORMAL;
            } finally {
              flowDepth -= 1;
            }
          };
          collect(declaration.body);
          if (flowOverflow || returns.some(expressionUsesGuardDecorator)) return true;
        } else return true;
      }
      return false;
    }
    return true;
  }
  while (ts.isIdentifier(expression)) {
    check();
    let symbol = checker.getSymbolAtLocation(expression);
    if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    if (!symbol || seen.has(symbol)) return false;
    seen.add(symbol);
    const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
    const declaration = declarations.length === 1 ? declarations[0] : undefined;
    if (!declaration || !projectSources.has(declaration.getSourceFile())) return false;
    if (!ts.isVariableDeclarationList(declaration.parent)
      || !(declaration.parent.flags & ts.NodeFlags.Const)) {
      return mutableBindingUsesGuardDecorator(symbol, declaration);
    }
    if (!declaration.initializer) return false;
    expression = unwrap(declaration.initializer);
  }
  if (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression)) {
    return true;
  }
  if (!ts.isCallExpression(expression)) return false;
  const resolved = resolveDecoratorCallSymbol(expression, checker, check);
  return Boolean(resolved?.nestJsCommon
    && (resolved.name === 'UseGuards' || resolved.name === 'applyDecorators'));
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
      const stable = isBareDecoratorBindingStable(decorator, checker, projectSources, check);
      result.publicPresent = true;
      result.explicitPublic = stable;
      result.publicDynamic = !stable;
      result.publicEvidence = [decorator];
      continue;
    }
    const resolved = resolveDecoratorSymbol(decorator, checker, check, projectSources);
    if (resolved) {
      applyResolved(resolved, decorator, 0);
    } else if (isUnresolvedStoredGuardDecorator(decorator, checker, projectSources, check)) {
      result.guardDynamic = true;
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
  const unsupportedGlobalGuard = potentialGlobalProvider
    ?? providerRegistrations.externalModuleImport
    ?? providerRegistrations.unresolvedProvider;
  if (unsupportedGlobalGuard) {
    addDiagnostic('SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED', unsupportedGlobalGuard);
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
