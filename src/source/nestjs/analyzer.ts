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

function staticTruth(input: ts.Expression): boolean | undefined {
  let expression = input;
  while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
    || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)
    || ts.isNonNullExpression(expression)) expression = expression.expression;
  if (expression.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (expression.kind === ts.SyntaxKind.FalseKeyword || expression.kind === ts.SyntaxKind.NullKeyword
    || ts.isVoidExpression(expression)) return false;
  if (ts.isStringLiteral(expression) || ts.isNoSubstitutionTemplateLiteral(expression)) {
    return expression.text.length > 0;
  }
  if (ts.isNumericLiteral(expression)) return Number(expression.text) !== 0;
  return undefined;
}

function staticNullish(input: ts.Expression): boolean | undefined {
  let expression = input;
  while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
    || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)
    || ts.isNonNullExpression(expression)) expression = expression.expression;
  if (expression.kind === ts.SyntaxKind.NullKeyword || ts.isVoidExpression(expression)) return true;
  if (expression.kind === ts.SyntaxKind.TrueKeyword || expression.kind === ts.SyntaxKind.FalseKeyword
    || ts.isLiteralExpression(expression) || ts.isObjectLiteralExpression(expression)
    || ts.isArrayLiteralExpression(expression) || ts.isFunctionExpression(expression)
    || ts.isArrowFunction(expression) || ts.isClassExpression(expression)
    || ts.isNewExpression(expression)) return false;
  return undefined;
}

function staticSwitchValue(input: ts.Expression): string | undefined {
  let expression = input;
  while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
    || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)
    || ts.isNonNullExpression(expression)) expression = expression.expression;
  if (ts.isStringLiteral(expression) || ts.isNoSubstitutionTemplateLiteral(expression)) {
    return `string:${expression.text}`;
  }
  if (ts.isNumericLiteral(expression)) return `number:${Number(expression.text)}`;
  if (expression.kind === ts.SyntaxKind.TrueKeyword) return 'boolean:true';
  if (expression.kind === ts.SyntaxKind.FalseKeyword) return 'boolean:false';
  if (expression.kind === ts.SyntaxKind.NullKeyword) return 'null';
  return undefined;
}

function staticallyUnreachable(node: ts.Node): boolean {
  let current = node;
  while (!ts.isSourceFile(current)) {
    const parent = current.parent;
    if (ts.isIfStatement(parent)) {
      const truth = staticTruth(parent.expression);
      if ((current === parent.thenStatement && truth === false)
        || (current === parent.elseStatement && truth === true)) return true;
    } else if ((ts.isWhileStatement(parent) || ts.isForStatement(parent))
      && current === parent.statement) {
      const condition = ts.isWhileStatement(parent) ? parent.expression : parent.condition;
      if (condition && staticTruth(condition) === false) return true;
    } else if (ts.isConditionalExpression(parent)) {
      const truth = staticTruth(parent.condition);
      if ((current === parent.whenTrue && truth === false)
        || (current === parent.whenFalse && truth === true)) return true;
    } else if (ts.isBinaryExpression(parent) && current === parent.right) {
      const truth = staticTruth(parent.left);
      if ((parent.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken && truth === false)
        || (parent.operatorToken.kind === ts.SyntaxKind.BarBarToken && truth === true)
        || (parent.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken
          && staticNullish(parent.left) === false)) return true;
    } else if (ts.isCaseBlock(parent)
      && (ts.isCaseClause(current) || ts.isDefaultClause(current))) {
      const selected = staticSwitchValue(parent.parent.expression);
      if (selected !== undefined && parent.clauses.every((clause) => (
        ts.isDefaultClause(clause) || staticSwitchValue(clause.expression) !== undefined
      ))) {
        const matchingIndex = parent.clauses.findIndex((clause) => (
          ts.isCaseClause(clause) && staticSwitchValue(clause.expression) === selected
        ));
        const selectedIndex = matchingIndex >= 0 ? matchingIndex
          : parent.clauses.findIndex(ts.isDefaultClause);
        const currentIndex = parent.clauses.indexOf(current);
        if (selectedIndex < 0 || currentIndex < selectedIndex) return true;
      }
    } else if ((ts.isBlock(parent) || ts.isCaseClause(parent) || ts.isDefaultClause(parent))
      && ts.isStatement(current)) {
      const index = parent.statements.indexOf(current);
      if (!ts.isFunctionDeclaration(current) && parent.statements.slice(0, index).some((statement) => (
        ts.isReturnStatement(statement) || ts.isThrowStatement(statement)
        || ts.isBreakStatement(statement) || ts.isContinueStatement(statement)
      ))) return true;
    }
    current = parent;
  }
  return false;
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

function nodeMayThrow(
  input: ts.Node,
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  check: () => void,
): boolean {
  const unwrapTransparent = (input: ts.Expression): ts.Expression => {
    let expression = input;
    while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
      || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)
      || ts.isNonNullExpression(expression)) expression = expression.expression;
    return expression;
  };
  const primitiveKind = (input: ts.Expression): 'number' | 'bigint' | 'other' | undefined => {
    const expression = unwrapTransparent(input);
    if (ts.isNumericLiteral(expression)) return 'number';
    if (ts.isBigIntLiteral(expression)) return 'bigint';
    if (ts.isStringLiteral(expression) || ts.isNoSubstitutionTemplateLiteral(expression)
      || expression.kind === ts.SyntaxKind.TrueKeyword
      || expression.kind === ts.SyntaxKind.FalseKeyword
      || expression.kind === ts.SyntaxKind.NullKeyword) return 'other';
    return undefined;
  };
  const staticTruth = (input: ts.Expression): boolean | undefined => {
    const expression = unwrapTransparent(input);
    if (expression.kind === ts.SyntaxKind.TrueKeyword) return true;
    if (expression.kind === ts.SyntaxKind.FalseKeyword
      || expression.kind === ts.SyntaxKind.NullKeyword) return false;
    if (ts.isStringLiteral(expression) || ts.isNoSubstitutionTemplateLiteral(expression)) {
      return expression.text.length > 0;
    }
    if (ts.isNumericLiteral(expression)) return Number(expression.text) !== 0;
    if (ts.isBigIntLiteral(expression)) return BigInt(expression.text.slice(0, -1)) !== 0n;
    if (ts.isObjectLiteralExpression(expression) || ts.isArrayLiteralExpression(expression)
      || ts.isFunctionExpression(expression) || ts.isArrowFunction(expression)
      || ts.isClassExpression(expression) || ts.isRegularExpressionLiteral(expression)
      || ts.isNewExpression(expression)) return true;
    return undefined;
  };
  const staticNullish = (input: ts.Expression): boolean | undefined => {
    const expression = unwrapTransparent(input);
    if (expression.kind === ts.SyntaxKind.NullKeyword || ts.isVoidExpression(expression)) return true;
    if (ts.isIdentifier(expression) && expression.text === 'undefined'
      && !checker.getSymbolAtLocation(expression)?.declarations?.length) return true;
    return primitiveKind(expression) || ts.isObjectLiteralExpression(expression)
      || ts.isArrayLiteralExpression(expression) || ts.isFunctionExpression(expression)
      || ts.isArrowFunction(expression) || ts.isClassExpression(expression)
      || ts.isRegularExpressionLiteral(expression) || ts.isNewExpression(expression)
      ? false : undefined;
  };
  const operatorMayThrow = (node: ts.Node): boolean => {
    if (ts.isSpreadElement(node) || ts.isDeleteExpression(node)
      || ts.isPostfixUnaryExpression(node)) return true;
    if (ts.isPrefixUnaryExpression(node)) {
      if (node.operator === ts.SyntaxKind.ExclamationToken) return false;
      const kind = primitiveKind(node.operand);
      return kind === undefined || (kind === 'bigint' && node.operator === ts.SyntaxKind.PlusToken);
    }
    if (!ts.isBinaryExpression(node)) return false;
    const operator = node.operatorToken.kind;
    if (operator >= ts.SyntaxKind.FirstAssignment && operator <= ts.SyntaxKind.LastAssignment) {
      return true;
    }
    if (operator === ts.SyntaxKind.AmpersandAmpersandToken
      || operator === ts.SyntaxKind.BarBarToken || operator === ts.SyntaxKind.QuestionQuestionToken
      || operator === ts.SyntaxKind.CommaToken || operator === ts.SyntaxKind.EqualsEqualsEqualsToken
      || operator === ts.SyntaxKind.ExclamationEqualsEqualsToken) return false;
    if (operator === ts.SyntaxKind.InKeyword || operator === ts.SyntaxKind.InstanceOfKeyword) {
      return true;
    }
    const left = primitiveKind(node.left);
    const right = primitiveKind(node.right);
    if (!left || !right) return true;
    if (left !== 'bigint' && right !== 'bigint') return false;
    if (left !== right || operator === ts.SyntaxKind.GreaterThanGreaterThanGreaterThanToken) return true;
    const rightExpression = unwrapTransparent(node.right);
    return (operator === ts.SyntaxKind.SlashToken || operator === ts.SyntaxKind.PercentToken)
      && ts.isBigIntLiteral(rightExpression)
      && BigInt(rightExpression.text.slice(0, -1)) === 0n;
  };
  const containingFunction = (node: ts.Node): ts.SignatureDeclaration | undefined => {
    for (let parent = node.parent; parent && !ts.isSourceFile(parent); parent = parent.parent) {
      if (ts.isFunctionLike(parent)) return parent;
    }
    return undefined;
  };
  const identifierMayThrow = (node: ts.Identifier): boolean => {
    if ((ts.isVariableDeclaration(node.parent) || ts.isParameter(node.parent))
      && node.parent.name === node) return false;
    if ((ts.isPropertyAssignment(node.parent) || ts.isMethodDeclaration(node.parent)
      || ts.isPropertyDeclaration(node.parent) || ts.isGetAccessorDeclaration(node.parent)
      || ts.isSetAccessorDeclaration(node.parent)) && node.parent.name === node
      && !ts.isComputedPropertyName(node.parent.name)) return false;
    const symbol = resolvedSymbolAt(node, checker);
    if (!symbol?.declarations?.length) return true;
    if (symbol.declarations.every((declaration) => !projectSources.has(declaration.getSourceFile()))) {
      return false;
    }
    const readFunction = containingFunction(node);
    return symbol.declarations.some((declaration) => {
      if (ts.isParameter(declaration) || ts.isFunctionDeclaration(declaration)
        || ts.isImportSpecifier(declaration) || ts.isImportClause(declaration)
        || ts.isNamespaceImport(declaration)) return false;
      if (ts.isVariableDeclaration(declaration)) {
        const lexical = Boolean((declaration.parent.flags & ts.NodeFlags.Let)
          || (declaration.parent.flags & ts.NodeFlags.Const));
        if (!lexical) return false;
        const variableStatement = ts.isVariableStatement(declaration.parent.parent)
          ? declaration.parent.parent : undefined;
        const ambient = declaration.getSourceFile().isDeclarationFile
          || Boolean(variableStatement?.modifiers?.some(({ kind }) => (
            kind === ts.SyntaxKind.DeclareKeyword
          )));
        if (!declaration.initializer && (ambient
          || Boolean(declaration.parent.flags & ts.NodeFlags.Const))) return true;
        if (readFunction && containingFunction(declaration) !== readFunction) return true;
      }
      return declaration.getSourceFile() !== node.getSourceFile()
        || declaration.end > node.getStart();
    });
  };
  const nodes: ts.Node[] = [input];
  while (nodes.length > 0) {
    const node = nodes.pop()!;
    check();
    if (ts.isFunctionLike(node)) continue;
    if (ts.isTypeOfExpression(node)) {
      const operand = unwrapTransparent(node.expression);
      if (ts.isIdentifier(operand) && !checker.getSymbolAtLocation(operand)?.declarations?.length) {
        continue;
      }
    }
    if (ts.isConditionalExpression(node)) {
      const condition = staticTruth(node.condition);
      nodes.push(node.condition);
      if (condition !== false) nodes.push(node.whenTrue);
      if (condition !== true) nodes.push(node.whenFalse);
      continue;
    }
    if (ts.isBinaryExpression(node) && (
      node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
      || node.operatorToken.kind === ts.SyntaxKind.BarBarToken
      || node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken
    )) {
      const truth = staticTruth(node.left);
      const nullish = staticNullish(node.left);
      nodes.push(node.left);
      if ((node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken && truth !== false)
        || (node.operatorToken.kind === ts.SyntaxKind.BarBarToken && truth !== true)
        || (node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken && nullish !== false)) {
        nodes.push(node.right);
      }
      continue;
    }
    if (ts.isIdentifier(node) && identifierMayThrow(node)) return true;
    if (ts.isTypeNode(node)) continue;
    if (node !== input && ts.isClassLike(node)) continue;
    if (operatorMayThrow(node)) return true;
    if (ts.isThrowStatement(node) || ts.isCallExpression(node) || ts.isNewExpression(node)
      || ts.isAwaitExpression(node) || ts.isYieldExpression(node)
      || ts.isTaggedTemplateExpression(node) || ts.isPropertyAccessExpression(node)
      || ts.isElementAccessExpression(node)) return true;
    ts.forEachChild(node, (child) => { nodes.push(child); });
  }
  return false;
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
    const NORMAL = 1;
    const RETURN = 2;
    const BREAK = 4;
    const CONTINUE = 8;
    type ReturnFlow = { mask: number; mayThrow: boolean };
    const unwrap = (input: ts.Expression): ts.Expression => {
      let expression = input;
      while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
        || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)
        || ts.isNonNullExpression(expression)) expression = expression.expression;
      return expression;
    };
    const staticBoolean = (input: ts.Expression): boolean | undefined => {
      const expression = unwrap(input);
      return expression.kind === ts.SyntaxKind.TrueKeyword
        ? true : expression.kind === ts.SyntaxKind.FalseKeyword ? false : undefined;
    };
    const staticCaseValue = (input: ts.Expression): string | number | bigint | boolean | null | undefined => {
      const expression = unwrap(input);
      if (ts.isStringLiteral(expression) || ts.isNoSubstitutionTemplateLiteral(expression)) {
        return expression.text;
      }
      if (ts.isNumericLiteral(expression)) return Number(expression.text);
      if (ts.isBigIntLiteral(expression)) return BigInt(expression.text.slice(0, -1));
      if (expression.kind === ts.SyntaxKind.TrueKeyword) return true;
      if (expression.kind === ts.SyntaxKind.FalseKeyword) return false;
      if (expression.kind === ts.SyntaxKind.NullKeyword) return null;
      return undefined;
    };
    const collectReturns = (statement: ts.Statement): ReturnFlow => {
      check();
      if (ts.isReturnStatement(statement)) {
        if (statement.expression) result.push(statement.expression);
        return {
          mask: RETURN,
          mayThrow: Boolean(statement.expression && nodeMayThrow(
            statement.expression, checker, projectSources, check,
          )),
        };
      }
      if (ts.isThrowStatement(statement)) return { mask: 0, mayThrow: true };
      if (ts.isBreakStatement(statement)) return { mask: BREAK, mayThrow: false };
      if (ts.isContinueStatement(statement)) return { mask: CONTINUE, mayThrow: false };
      if (ts.isBlock(statement)) {
        const flow: ReturnFlow = { mask: NORMAL, mayThrow: false };
        for (const child of statement.statements) {
          if (!(flow.mask & NORMAL)) break;
          const childFlow = collectReturns(child);
          flow.mayThrow ||= childFlow.mayThrow;
          flow.mask = (flow.mask & ~NORMAL) | childFlow.mask;
        }
        return flow;
      } else if (ts.isIfStatement(statement)) {
        const condition = staticBoolean(statement.expression);
        const conditionMayThrow = nodeMayThrow(statement.expression, checker, projectSources, check);
        if (condition === true) {
          const flow = collectReturns(statement.thenStatement);
          return { ...flow, mayThrow: conditionMayThrow || flow.mayThrow };
        }
        if (condition === false) {
          const flow = statement.elseStatement
            ? collectReturns(statement.elseStatement)
            : { mask: NORMAL, mayThrow: false };
          return { ...flow, mayThrow: conditionMayThrow || flow.mayThrow };
        }
        const whenTrue = collectReturns(statement.thenStatement);
        const whenFalse = statement.elseStatement
          ? collectReturns(statement.elseStatement)
          : { mask: NORMAL, mayThrow: false };
        return {
          mask: whenTrue.mask | whenFalse.mask,
          mayThrow: conditionMayThrow || whenTrue.mayThrow || whenFalse.mayThrow,
        };
      } else if (ts.isTryStatement(statement)) {
        const start = result.length;
        const tryFlow = collectReturns(statement.tryBlock);
        const catchFlow = statement.catchClause && tryFlow.mayThrow
          ? collectReturns(statement.catchClause.block) : undefined;
        let flow: ReturnFlow = {
          mask: tryFlow.mask | (catchFlow?.mask ?? 0),
          mayThrow: catchFlow ? catchFlow.mayThrow : tryFlow.mayThrow,
        };
        if (!statement.finallyBlock) return flow;
        const finallyStart = result.length;
        const finallyFlow = collectReturns(statement.finallyBlock);
        if (!(finallyFlow.mask & NORMAL)) result.splice(start, finallyStart - start);
        flow = !(finallyFlow.mask & NORMAL) ? finallyFlow : {
          mask: (finallyFlow.mask & ~NORMAL) | flow.mask,
          mayThrow: flow.mayThrow || finallyFlow.mayThrow,
        };
        return flow;
      } else if (ts.isSwitchStatement(statement)) {
        let mayThrow = nodeMayThrow(statement.expression, checker, projectSources, check);
        const discriminant = staticCaseValue(statement.expression);
        let dynamic = discriminant === undefined;
        let start = -1;
        let fallback = -1;
        for (const [index, clause] of statement.caseBlock.clauses.entries()) {
          if (ts.isDefaultClause(clause)) {
            fallback = index;
            continue;
          }
          mayThrow ||= nodeMayThrow(clause.expression, checker, projectSources, check);
          const value = staticCaseValue(clause.expression);
          if (value === undefined) dynamic = true;
          if (!dynamic && Object.is(discriminant, value)) { start = index; break; }
        }
        const indexes = dynamic
          ? statement.caseBlock.clauses.map((_, index) => index)
          : start >= 0 ? statement.caseBlock.clauses.map((_, index) => index).slice(start)
            : fallback >= 0 ? statement.caseBlock.clauses.map((_, index) => index).slice(fallback) : [];
        let mask = NORMAL;
        for (const index of indexes) {
          if (!dynamic && !(mask & NORMAL)) break;
          const clause = statement.caseBlock.clauses[index];
          let clauseMask = NORMAL;
          for (const child of clause.statements) {
            if (!(clauseMask & NORMAL)) break;
            const childFlow = collectReturns(child);
            mayThrow ||= childFlow.mayThrow;
            clauseMask = (clauseMask & ~NORMAL) | childFlow.mask;
          }
          mask = dynamic ? mask | clauseMask : (mask & ~NORMAL) | clauseMask;
          if (clauseMask & BREAK) {
            mask = (mask & ~BREAK) | NORMAL;
            if (!dynamic) break;
          }
        }
        return { mask, mayThrow };
      } else if (ts.isWhileStatement(statement)) {
        const condition = staticBoolean(statement.expression);
        const conditionMayThrow = nodeMayThrow(
          statement.expression, checker, projectSources, check,
        );
        if (condition === false) {
          return { mask: NORMAL, mayThrow: conditionMayThrow };
        }
        const flow = collectReturns(statement.statement);
        return {
          mask: (flow.mask & RETURN)
            | ((condition !== true || (flow.mask & BREAK)) ? NORMAL : 0),
          mayThrow: conditionMayThrow || flow.mayThrow,
        };
      } else if (ts.isDoStatement(statement)) {
        const flow = collectReturns(statement.statement);
        const reachesCondition = Boolean(flow.mask & (NORMAL | CONTINUE));
        const condition = staticBoolean(statement.expression);
        return {
          mask: (flow.mask & RETURN) | ((flow.mask & BREAK) ? NORMAL : 0)
            | (reachesCondition && condition !== true ? NORMAL : 0),
          mayThrow: flow.mayThrow || (reachesCondition && nodeMayThrow(
            statement.expression, checker, projectSources, check,
          )),
        };
      } else if (ts.isForStatement(statement)) {
        const initializerMayThrow = Boolean(statement.initializer && nodeMayThrow(
          statement.initializer, checker, projectSources, check,
        ));
        const condition = statement.condition ? staticBoolean(statement.condition) : true;
        const conditionMayThrow = Boolean(statement.condition && nodeMayThrow(
          statement.condition, checker, projectSources, check,
        ));
        if (condition === false) {
          return {
            mask: NORMAL,
            mayThrow: initializerMayThrow || conditionMayThrow,
          };
        }
        const flow = collectReturns(statement.statement);
        const reachesIncrement = Boolean(flow.mask & (NORMAL | CONTINUE));
        const incrementMayThrow = reachesIncrement && Boolean(statement.incrementor
          && nodeMayThrow(statement.incrementor, checker, projectSources, check));
        return {
          mask: (flow.mask & RETURN)
            | ((condition !== true || (flow.mask & BREAK)) ? NORMAL : 0),
          mayThrow: initializerMayThrow || conditionMayThrow || flow.mayThrow || incrementMayThrow,
        };
      } else if (ts.isForInStatement(statement) || ts.isForOfStatement(statement)) {
        const flow = collectReturns(statement.statement);
        return {
          mask: (flow.mask & RETURN) | NORMAL,
          mayThrow: nodeMayThrow(statement.initializer, checker, projectSources, check)
            || nodeMayThrow(statement.expression, checker, projectSources, check)
            || flow.mayThrow,
        };
      }
      return {
        mask: NORMAL,
        mayThrow: nodeMayThrow(statement, checker, projectSources, check),
      };
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
  const propertyAssignedContainers = new Map<ts.Symbol, Set<string>>();
  const mutatedContainerExpressions = new Set<ts.Expression>();
  const assignedValues = new Map<ts.Symbol, ts.Expression[]>();
  const unresolvedAssignments = new Set<ts.Symbol>();
  const aliases = new Map<ts.Symbol, Set<ts.Symbol>>();
  const memberMutationCache = new Map<ts.Symbol, boolean>();
  const pendingEscapes: ts.Expression[] = [];
  const unresolvedImportDefaultAliases = new Set<ts.Symbol>();
  const unresolvedSpreadParameters = new Set<ts.Symbol>();
  const incompleteDynamicAliases = new Set<ts.Symbol>();
  const dynamicAliasExpressions = new Map<ts.Symbol, Set<ts.Expression>>();
  let escapeIndexIncomplete = false;
  let escapeIndexLimitExceeded = false;
  const incompleteLocalCallImportSymbols = new Set<ts.Symbol>();
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
  type DynamicObjectEntry = { candidates: ts.Expression[]; accessor: boolean };
  type DynamicObjectIndex = { entries: Map<string, DynamicObjectEntry>; complete: boolean };
  const dynamicObjectIndexes = new WeakMap<ts.ObjectLiteralExpression, DynamicObjectIndex>();
  const indexingDynamicObjects = new Set<ts.ObjectLiteralExpression>();
  let dynamicObjectIndexSteps = 0;
  const indexDynamicObject = (object: ts.ObjectLiteralExpression): DynamicObjectIndex => {
    const cached = dynamicObjectIndexes.get(object);
    if (cached) return cached;
    if (indexingDynamicObjects.has(object)) return { entries: new Map(), complete: false };
    indexingDynamicObjects.add(object);
    const result: DynamicObjectIndex = { entries: new Map(), complete: true };
    for (const property of object.properties) {
      check();
      if (dynamicObjectIndexSteps++ >= MAX_PROVIDER_SPREAD_ELEMENTS) {
        result.complete = false;
        break;
      }
      if (ts.isSpreadAssignment(property)) {
        const spread = resolveConstObject(property.expression, checker, projectSources, check);
        if (!spread) result.complete = false;
        else {
          const nested = indexDynamicObject(spread);
          result.complete &&= nested.complete;
          for (const [name, entry] of nested.entries) result.entries.set(name, entry);
        }
        continue;
      }
      const name = ts.isComputedPropertyName(property.name)
        ? resolveStaticPropertyKey(property.name.expression, checker, check)
        : ts.isIdentifier(property.name) || ts.isStringLiteral(property.name)
          || ts.isNumericLiteral(property.name) ? property.name.text : undefined;
      if (name === undefined) {
        result.complete = false;
      } else if (ts.isPropertyAssignment(property)) {
        result.entries.set(name, { candidates: [property.initializer], accessor: false });
      } else if (ts.isShorthandPropertyAssignment(property)) {
        result.entries.set(name, { candidates: [property.name], accessor: false });
      } else if (ts.isGetAccessorDeclaration(property) || ts.isSetAccessorDeclaration(property)) {
        result.entries.set(name, { candidates: [], accessor: true });
      } else {
        result.entries.set(name, { candidates: [], accessor: false });
      }
    }
    indexingDynamicObjects.delete(object);
    dynamicObjectIndexes.set(object, result);
    return result;
  };
  const linkDynamicElementCandidates = (
    alias: ts.Symbol | undefined, receiver: ts.Expression,
  ): void => {
    if (!alias) return;
    const object = resolveConstObject(receiver, checker, projectSources, check);
    if (!object) {
      incompleteDynamicAliases.add(alias);
      return;
    }
    const indexed = indexDynamicObject(object);
    if (!indexed.complete) incompleteDynamicAliases.add(alias);
    const expressions = dynamicAliasExpressions.get(alias) ?? new Set<ts.Expression>();
    dynamicAliasExpressions.set(alias, expressions);
    for (const effective of indexed.entries.values()) {
      if (effective.accessor || effective.candidates.length === 0) {
        incompleteDynamicAliases.add(alias);
      }
      for (const candidate of effective.candidates) {
        let value = candidate;
        while (ts.isParenthesizedExpression(value) || ts.isAsExpression(value)
          || ts.isTypeAssertionExpression(value) || ts.isSatisfiesExpression(value)
          || ts.isNonNullExpression(value)) value = value.expression;
        expressions.add(value);
        const member = ts.isIdentifier(value) ? symbolAt(value)
          : ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)
            ? symbolAt(ts.isPropertyAccessExpression(value) ? value.name : value) : undefined;
        const root = ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)
          ? rootSymbolAt(value.expression) : undefined;
        linkAliases(alias, member);
        linkAliases(alias, root);
      }
    }
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
  const recordAssignedContainer = (input: ts.PropertyAccessExpression | ts.ElementAccessExpression): void => {
    const receiver = rootSymbolAt(input.expression);
    if (!receiver) return;
    let access: ts.Expression = input;
    let key = '*';
    while (ts.isPropertyAccessExpression(access) || ts.isElementAccessExpression(access)) {
      key = ts.isPropertyAccessExpression(access) ? access.name.text
        : access.argumentExpression
          ? resolveStaticPropertyKey(access.argumentExpression, checker, check) ?? '*' : '*';
      access = access.expression;
      while (ts.isParenthesizedExpression(access) || ts.isAsExpression(access)
        || ts.isTypeAssertionExpression(access) || ts.isSatisfiesExpression(access)
        || ts.isNonNullExpression(access)) access = access.expression;
    }
    const keys = propertyAssignedContainers.get(receiver) ?? new Set<string>();
    keys.add(key);
    propertyAssignedContainers.set(receiver, keys);
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
      recordAssignedContainer(target);
    } else if (ts.isElementAccessExpression(target)) {
      const key = target.argumentExpression
        ? resolveStaticPropertyKey(target.argumentExpression, checker, check) : undefined;
      const symbol = key === undefined ? undefined
        : checker.getNonNullableType(checker.getTypeAtLocation(target.expression)).getProperty(key);
      if (symbol) reassignedSymbols.add(symbol);
      const receiver = rootSymbolAt(target.expression);
      recordAssignedContainer(target);
      if (!symbol && receiver) escapedSymbols.add(receiver);
      else if (!symbol && ts.isIdentifier(target.expression)) {
        const expressionSymbol = symbolAt(target.expression);
        if (expressionSymbol) escapedSymbols.add(expressionSymbol);
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
      escapeIndexLimitExceeded = true;
      return;
    }
    if (depth > 64) {
      escapeIndexIncomplete = true;
      escapeIndexLimitExceeded = true;
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
    if (ts.isArrayLiteralExpression(receiver) || ts.isObjectLiteralExpression(receiver)) {
      mutatedContainerExpressions.add(receiver);
      return;
    }
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
      if (node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        let target: ts.Expression = node.left;
        while (ts.isParenthesizedExpression(target) || ts.isAsExpression(target)
          || ts.isTypeAssertionExpression(target) || ts.isSatisfiesExpression(target)
          || ts.isNonNullExpression(target)) target = target.expression;
        if (ts.isIdentifier(target)) {
          const alias = symbolAt(target);
          let value = node.right;
          while (ts.isParenthesizedExpression(value) || ts.isAsExpression(value)
            || ts.isTypeAssertionExpression(value) || ts.isSatisfiesExpression(value)
            || ts.isNonNullExpression(value)) value = value.expression;
          if (ts.isIdentifier(value)) linkAliases(alias, symbolAt(value));
          else if (ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)) {
            linkAliases(alias, symbolAt(
              ts.isPropertyAccessExpression(value) ? value.name : value,
            ));
            const key = ts.isPropertyAccessExpression(value) ? value.name.text
              : value.argumentExpression
                ? resolveStaticPropertyKey(value.argumentExpression, checker, check) : undefined;
            if (key === 'imports' || (key === undefined && ts.isElementAccessExpression(value))) {
              linkAliases(alias, rootSymbolAt(value.expression));
            }
            if (key === undefined && ts.isElementAccessExpression(value)) {
              linkDynamicElementCandidates(alias, value.expression);
            }
          }
        }
      }
    }
    else if (ts.isForOfStatement(node) || ts.isForInStatement(node)) {
      markAssignmentTarget(node.initializer);
      if (ts.isExpression(node.initializer)) {
        const symbol = directAssignmentSymbol(node.initializer);
        if (symbol) unresolvedAssignments.add(symbol);
      }
    } else if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const alias = symbolAt(node.name);
      let value = node.initializer;
      while (ts.isParenthesizedExpression(value) || ts.isAsExpression(value)
        || ts.isTypeAssertionExpression(value) || ts.isSatisfiesExpression(value)
        || ts.isNonNullExpression(value)) value = value.expression;
      if (ts.isIdentifier(value)) linkAliases(alias, symbolAt(value));
      else if (ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)) {
        linkAliases(alias, symbolAt(
          ts.isPropertyAccessExpression(value) ? value.name : value,
        ));
        const key = ts.isPropertyAccessExpression(value) ? value.name.text
          : value.argumentExpression
            ? resolveStaticPropertyKey(value.argumentExpression, checker, check) : undefined;
        if (key === 'imports' || (key === undefined && ts.isElementAccessExpression(value))) {
          linkAliases(alias, rootSymbolAt(value.expression));
        }
        if (key === undefined && ts.isElementAccessExpression(value)) {
          linkDynamicElementCandidates(alias, value.expression);
        }
      }
    } else if (ts.isVariableDeclaration(node) && ts.isObjectBindingPattern(node.name)
      && node.initializer) {
      for (const element of node.name.elements) {
        if (!ts.isIdentifier(element.name)) continue;
        const key = element.propertyName
          ? ts.isIdentifier(element.propertyName) || ts.isStringLiteral(element.propertyName)
            ? element.propertyName.text
            : ts.isComputedPropertyName(element.propertyName)
              ? resolveStaticPropertyKey(element.propertyName.expression, checker, check) : undefined
          : element.name.text;
        const alias = symbolAt(element.name);
        if (key === undefined) {
          linkAliases(alias, rootSymbolAt(node.initializer));
          continue;
        }
        if (key !== 'imports') continue;
        let propertyMayBeSelected = true;
        let defaultMayBeSelected = Boolean(element.initializer);
        if (element.initializer) {
          const object = resolveConstObject(node.initializer, checker, projectSources, check);
          if (object) {
            const property = effectiveObjectProperty(
              object, 'imports', checker, projectSources, check,
            );
            propertyMayBeSelected = property.present && (property.accessor
              || property.candidates.length === 0 || property.candidates.some((candidate) => (
                staticUndefinedState(candidate, checker, projectSources, check) !== true
              )));
            defaultMayBeSelected = !property.present || property.accessor
              || property.candidates.length === 0 || property.candidates.some((candidate) => (
                staticUndefinedState(candidate, checker, projectSources, check) !== false
              ));
          }
        }
        if (propertyMayBeSelected) {
          linkAliases(alias, checker.getNonNullableType(
            checker.getTypeAtLocation(node.initializer),
          ).getProperty('imports'));
          linkAliases(alias, rootSymbolAt(node.initializer));
        }
        if (defaultMayBeSelected && element.initializer) {
          const fallbacks = [element.initializer];
          const seenFallbacks = new Set<ts.Symbol>();
          let fallbackSteps = 0;
          while (fallbacks.length > 0) {
            if (fallbackSteps++ >= 64) {
              if (alias) unresolvedImportDefaultAliases.add(alias);
              break;
            }
            let fallback = fallbacks.pop()!;
            while (ts.isParenthesizedExpression(fallback) || ts.isAsExpression(fallback)
              || ts.isTypeAssertionExpression(fallback) || ts.isSatisfiesExpression(fallback)
              || ts.isNonNullExpression(fallback)) fallback = fallback.expression;
            if (ts.isIdentifier(fallback)) {
              const symbol = symbolAt(fallback);
              linkAliases(alias, symbol);
              if (!symbol || seenFallbacks.has(symbol)) continue;
              seenFallbacks.add(symbol);
              const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
              const declaration = declarations.length === 1 ? declarations[0] : undefined;
              if (declaration?.initializer && projectSources.has(declaration.getSourceFile())
                && ts.isVariableDeclarationList(declaration.parent)
                && declaration.parent.flags & ts.NodeFlags.Const) {
                fallbacks.push(declaration.initializer);
              }
              continue;
            }
            if (ts.isPropertyAccessExpression(fallback) || ts.isElementAccessExpression(fallback)) {
              const fallbackKey = ts.isPropertyAccessExpression(fallback) ? fallback.name.text
                : fallback.argumentExpression
                  ? resolveStaticPropertyKey(fallback.argumentExpression, checker, check) : undefined;
              if (fallbackKey === 'imports') {
                linkAliases(alias, symbolAt(
                  ts.isPropertyAccessExpression(fallback) ? fallback.name : fallback,
                ));
                linkAliases(alias, rootSymbolAt(fallback.expression));
                const object = resolveConstObject(
                  fallback.expression, checker, projectSources, check,
                );
                if (object) {
                  const property = effectiveObjectProperty(
                    object, 'imports', checker, projectSources, check,
                  );
                  fallbacks.push(...property.candidates);
                  if ((!property.present || property.accessor
                    || property.candidates.length === 0) && alias) {
                    unresolvedImportDefaultAliases.add(alias);
                  }
                } else if (alias) {
                  unresolvedImportDefaultAliases.add(alias);
                }
              } else if (fallbackKey === undefined && alias) unresolvedImportDefaultAliases.add(alias);
              continue;
            }
            if (ts.isConditionalExpression(fallback)) {
              const state = staticState(fallback.condition);
              if (state.truthy !== false) fallbacks.push(fallback.whenTrue);
              if (state.truthy !== true) fallbacks.push(fallback.whenFalse);
              continue;
            }
            if (ts.isBinaryExpression(fallback)) {
              const operator = fallback.operatorToken.kind;
              if (operator === ts.SyntaxKind.CommaToken) {
                fallbacks.push(fallback.right);
                continue;
              }
              const state = staticState(fallback.left);
              if (operator === ts.SyntaxKind.AmpersandAmpersandToken) {
                if (state.truthy !== true) fallbacks.push(fallback.left);
                if (state.truthy !== false) fallbacks.push(fallback.right);
                continue;
              }
              if (operator === ts.SyntaxKind.BarBarToken) {
                if (state.truthy !== false) fallbacks.push(fallback.left);
                if (state.truthy !== true) fallbacks.push(fallback.right);
                continue;
              }
              if (operator === ts.SyntaxKind.QuestionQuestionToken) {
                if (state.nullish !== true) fallbacks.push(fallback.left);
                if (state.nullish !== false) fallbacks.push(fallback.right);
                continue;
              }
            }
            if (!ts.isArrayLiteralExpression(fallback) && alias) {
              unresolvedImportDefaultAliases.add(alias);
            }
          }
        }
      }
    } else if (ts.isCallExpression(node)) {
      let localCallee: ts.Expression = node.expression;
      while (ts.isParenthesizedExpression(localCallee) || ts.isAsExpression(localCallee)
        || ts.isTypeAssertionExpression(localCallee) || ts.isSatisfiesExpression(localCallee)
        || ts.isNonNullExpression(localCallee)) localCallee = localCallee.expression;
      if (ts.isIdentifier(localCallee)) {
        const symbol = symbolAt(localCallee);
        const callables: ts.FunctionLikeDeclaration[] = [];
        const callableSymbols = new Set<ts.Symbol>();
        let callableResolutionComplete = true;
        const collectCallables = (candidate: ts.Symbol | undefined, depth = 0): void => {
          if (!candidate || depth >= 64) {
            callableResolutionComplete = false;
            return;
          }
          if (callableSymbols.has(candidate)) return;
          callableSymbols.add(candidate);
          if (reassignedSymbols.has(candidate) || unresolvedAssignments.has(candidate)
            || assignedValues.has(candidate)) callableResolutionComplete = false;
          for (const declaration of candidate.declarations ?? []) {
            if (!projectSources.has(declaration.getSourceFile())) continue;
            if (ts.isFunctionDeclaration(declaration) && declaration.body) callables.push(declaration);
            if (!ts.isVariableDeclaration(declaration) || !declaration.initializer) continue;
            if (!ts.isVariableDeclarationList(declaration.parent)
              || !(declaration.parent.flags & ts.NodeFlags.Const)) callableResolutionComplete = false;
            let initializer = declaration.initializer;
            while (ts.isParenthesizedExpression(initializer) || ts.isAsExpression(initializer)
              || ts.isTypeAssertionExpression(initializer) || ts.isSatisfiesExpression(initializer)
              || ts.isNonNullExpression(initializer)) initializer = initializer.expression;
            if (ts.isArrowFunction(initializer)
              || ts.isFunctionExpression(initializer)) callables.push(initializer);
            else if (ts.isIdentifier(initializer)
              && ts.isVariableDeclarationList(declaration.parent)
              && declaration.parent.flags & ts.NodeFlags.Const) {
              collectCallables(symbolAt(initializer), depth + 1);
            } else callableResolutionComplete = false;
          }
        };
        collectCallables(symbol);
        if (!callableResolutionComplete) {
          for (const argument of node.arguments) {
            const nodes: ts.Node[] = [argument];
            const seenSymbols = new Set<ts.Symbol>();
            while (nodes.length > 0) {
              const candidate = nodes.pop()!;
              const importsAccess = (ts.isPropertyAccessExpression(candidate)
                && candidate.name.text === 'imports') || (ts.isElementAccessExpression(candidate)
                && candidate.argumentExpression
                && resolveStaticPropertyKey(candidate.argumentExpression, checker, check) === 'imports');
              if (importsAccess && (ts.isPropertyAccessExpression(candidate)
                || ts.isElementAccessExpression(candidate))) {
                const member = symbolAt(ts.isPropertyAccessExpression(candidate)
                  ? candidate.name : candidate);
                const root = rootSymbolAt(candidate.expression);
                if (member) incompleteLocalCallImportSymbols.add(member);
                if (root) incompleteLocalCallImportSymbols.add(root);
                continue;
              }
              if (ts.isIdentifier(candidate)) {
                const candidateSymbol = symbolAt(candidate);
                if (candidateSymbol && !seenSymbols.has(candidateSymbol)) {
                  seenSymbols.add(candidateSymbol);
                  for (const declaration of candidateSymbol.declarations ?? []) {
                    if (ts.isVariableDeclaration(declaration) && declaration.initializer
                      && projectSources.has(declaration.getSourceFile())) nodes.push(declaration.initializer);
                  }
                }
              }
              ts.forEachChild(candidate, (child) => { nodes.push(child); });
            }
          }
        }
        if (callables.length === 1) {
          const actualArguments: ts.Expression[] = [];
          let argumentsComplete = true;
          const flattenSpread = (input: ts.Expression, depth = 0): boolean => {
            if (depth >= 64) return false;
            let expression = input;
            while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
              || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)
              || ts.isNonNullExpression(expression)) expression = expression.expression;
            if (ts.isIdentifier(expression)) {
              const symbol = symbolAt(expression);
              const declarations = symbol?.declarations?.filter(ts.isVariableDeclaration) ?? [];
              const declaration = declarations.length === 1 ? declarations[0] : undefined;
              if (!declaration?.initializer || !projectSources.has(declaration.getSourceFile())
                || !ts.isVariableDeclarationList(declaration.parent)
                || !(declaration.parent.flags & ts.NodeFlags.Const)) return false;
              return flattenSpread(declaration.initializer, depth + 1);
            }
            if (!ts.isArrayLiteralExpression(expression)) return false;
            for (const element of expression.elements) {
              if (ts.isOmittedExpression(element)) actualArguments.push(element);
              else if (ts.isSpreadElement(element)) {
                if (!flattenSpread(element.expression, depth + 1)) return false;
              } else actualArguments.push(element);
            }
            return true;
          };
          for (const argument of node.arguments) {
            if (ts.isSpreadElement(argument)) {
              if (!flattenSpread(argument.expression)) argumentsComplete = false;
            } else actualArguments.push(argument);
          }
          for (const [index, parameter] of callables[0].parameters.entries()) {
            if (!ts.isIdentifier(parameter.name)) continue;
            const parameterSymbol = symbolAt(parameter.name);
            if (!argumentsComplete && parameterSymbol) unresolvedSpreadParameters.add(parameterSymbol);
            const actual = actualArguments[index];
            const undefinedState = actual
              ? staticUndefinedState(actual, checker, projectSources, check) : true;
            const values = [
              ...(actual && undefinedState !== true ? [actual] : []),
              ...(parameter.initializer && undefinedState !== false ? [parameter.initializer] : []),
            ];
            for (let value of values) {
              while (ts.isParenthesizedExpression(value) || ts.isAsExpression(value)
                || ts.isTypeAssertionExpression(value) || ts.isSatisfiesExpression(value)
                || ts.isNonNullExpression(value)) value = value.expression;
              if (ts.isIdentifier(value)) linkAliases(parameterSymbol, symbolAt(value));
              else if (ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)) {
                linkAliases(parameterSymbol, symbolAt(
                  ts.isPropertyAccessExpression(value) ? value.name : value,
                ));
                const key = ts.isPropertyAccessExpression(value) ? value.name.text
                  : value.argumentExpression
                    ? resolveStaticPropertyKey(value.argumentExpression, checker, check) : undefined;
                if (key === 'imports') linkAliases(parameterSymbol, rootSymbolAt(value.expression));
              }
            }
          }
        }
      }
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
  const containersWithAssignedImports = new Set([...propertyAssignedContainers]
    .filter(([, keys]) => keys.has('imports') || keys.has('*'))
    .map(([symbol]) => symbol));
  const unresolvedImportDefaultMutation = [...unresolvedImportDefaultAliases].some((symbol) => (
    aliasSetHas(unstableContainers, symbol) || aliasSetHas(escapedSymbols, symbol)
  ));
  const unresolvedParameterSpreadMutation = [...unresolvedSpreadParameters].some((symbol) => (
    aliasSetHas(unstableContainers, symbol) || aliasSetHas(escapedSymbols, symbol)
  ));
  const unresolvedDynamicAliasMutation = [...incompleteDynamicAliases].some((symbol) => (
    aliasSetHas(unstableContainers, symbol) || aliasSetHas(escapedSymbols, symbol)
  ));
  const mutatedDynamicExpressions = new Set<ts.Expression>();
  for (const [symbol, expressions] of dynamicAliasExpressions) {
    if (aliasSetHas(unstableContainers, symbol) || aliasSetHas(escapedSymbols, symbol)) {
      for (const expression of expressions) mutatedDynamicExpressions.add(expression);
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
  const moduleEntries: {
    node: ts.ClassLikeDeclaration;
    symbol?: ts.Symbol;
    metadataArgument?: ts.Expression;
    metadata?: ts.ObjectLiteralExpression;
  }[] = [];
  const localClassesBySymbol = new Map<ts.Symbol, ts.ClassLikeDeclaration>();
  for (const sourceFile of projectSources) {
    const nodes: ts.Node[] = [sourceFile];
    while (nodes.length > 0) {
      const node = nodes.pop()!;
      check();
      if (ts.isClassLike(node)) {
        const classSymbol = node.name ? checker.getSymbolAtLocation(node.name) : undefined;
        if (classSymbol) localClassesBySymbol.set(classSymbol, node);
        for (const decorator of decorators(node)) {
          const module = resolveDecoratorSymbol(decorator, checker, check);
          if (module?.name !== 'Module' || !module.nestJsCommon) continue;
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
      ts.forEachChild(node, (child) => { nodes.push(child); });
    }
  }
  const modulesBySymbol = new Map<ts.Symbol, (typeof moduleEntries)[number]>();
  const duplicateModuleSymbols = new Set<ts.Symbol>();
  for (const entry of moduleEntries) {
    if (entry.symbol) {
      if (modulesBySymbol.has(entry.symbol)) duplicateModuleSymbols.add(entry.symbol);
      modulesBySymbol.set(entry.symbol, entry);
    }
  }
  const unwrapModuleExpression = (input: ts.Expression): ts.Expression => {
    let expression = input;
    while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
      || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)
      || ts.isNonNullExpression(expression)) expression = expression.expression;
    return expression;
  };
  const moduleSymbol = (input: ts.Expression): ts.Symbol | undefined => {
    let expression = unwrapModuleExpression(input);
    for (let depth = 0; depth < 64; depth += 1) {
      check();
      if (!(ts.isCallExpression(expression) && expression.arguments.length === 1
        && containsStaticSymbolFrom(
          expression.expression, checker, check, '@nestjs/common', 'forwardRef', projectSources,
        ))) break;
      const callback = expression.arguments[0];
      if (!((ts.isArrowFunction(callback) || ts.isFunctionExpression(callback))
        && !ts.isBlock(callback.body))) return undefined;
      expression = unwrapModuleExpression(callback.body);
    }
    if (ts.isCallExpression(expression)) return undefined;
    let symbol = checker.getSymbolAtLocation(ts.isPropertyAccessExpression(expression)
      ? expression.name : expression);
    if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    return symbol && modulesBySymbol.has(symbol) ? symbol : undefined;
  };
  const roots = new Set<ts.Symbol>();
  let moduleGraphComplete = !escapeIndexLimitExceeded && !unresolvedImportDefaultMutation
    && !unresolvedParameterSpreadMutation
    && !unresolvedDynamicAliasMutation
    && duplicateModuleSymbols.size === 0;
  const indirectBootstrapTarget = (
    input: ts.Expression, includeContainers = true, asValue = false,
  ): boolean => {
    const expressions: ts.Expression[] = [input];
    const seen = new Set<ts.Symbol>();
    const parameterBindings = new Map<ts.Symbol, ts.Expression[]>();
    const candidateContainsBootstrapAccess = (input: ts.Node): boolean => {
      const nodes: ts.Node[] = [input];
      const candidateSymbols = new Set<ts.Symbol>();
      let candidateSteps = 0;
      while (nodes.length > 0) {
        check();
        if (candidateSteps >= 256) return true;
        candidateSteps += 1;
        const candidate = nodes.pop()!;
        if (candidate !== input && (ts.isFunctionLike(candidate) || ts.isClassLike(candidate))) continue;
        if (candidate !== input && staticallyUnreachable(candidate)) continue;
        if (ts.isCallExpression(candidate)) {
          let callee: ts.Expression = candidate.expression;
          while (ts.isParenthesizedExpression(callee) || ts.isAsExpression(callee)
            || ts.isTypeAssertionExpression(callee) || ts.isSatisfiesExpression(callee)
            || ts.isNonNullExpression(callee)) callee = callee.expression;
          const pushCallable = (callable: ts.FunctionLikeDeclaration): boolean => {
            if (!callable.body || callable.modifiers?.some(({ kind }) => (
              kind === ts.SyntaxKind.AsyncKeyword
            )) || ('asteriskToken' in callable && callable.asteriskToken)) return false;
            for (const [index, parameter] of callable.parameters.entries()) {
              if (!ts.isIdentifier(parameter.name) || parameter.dotDotDotToken) return true;
              const argument = candidate.arguments[index];
              const actual = argument && !ts.isSpreadElement(argument) ? argument : undefined;
              const isUndefined = actual ? staticUndefined(actual) : true;
              if (parameter.initializer && isUndefined !== false) nodes.push(parameter.initializer);
            }
            nodes.push(callable.body);
            return false;
          };
          if (ts.isArrowFunction(callee) || ts.isFunctionExpression(callee)) {
            if (pushCallable(callee)) return true;
          } else if (ts.isIdentifier(callee)) {
            let symbol = checker.getSymbolAtLocation(callee);
            if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
            for (const declaration of symbol?.declarations ?? []) {
              if (!projectSources.has(declaration.getSourceFile())) continue;
              const callable = ts.isFunctionDeclaration(declaration) ? declaration
                : ts.isVariableDeclaration(declaration) && declaration.initializer
                  && (ts.isArrowFunction(declaration.initializer)
                    || ts.isFunctionExpression(declaration.initializer))
                  ? declaration.initializer : undefined;
              if (callable && pushCallable(callable)) return true;
            }
          } else if (ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee)) {
            const key = ts.isPropertyAccessExpression(callee) ? callee.name.text
              : callee.argumentExpression
                ? resolveStaticPropertyKey(callee.argumentExpression, checker, check) : undefined;
            const member = symbolAt(ts.isPropertyAccessExpression(callee) ? callee.name : callee);
            const receiver = rootSymbolAt(callee.expression);
            const memberValues = member ? assignedValues.get(member) ?? [] : [];
            if (member && aliasSetHas(unresolvedAssignments, member)) return true;
            if (member && aliasSetHas(reassignedSymbols, member) && memberValues.length === 0) return true;
            nodes.push(...memberValues);
            if (receiver && (aliasSetHas(unresolvedAssignments, receiver)
              || aliasSetHas(escapedSymbols, receiver)
              || aliasSetHas(unstableContainers, receiver))) return true;
            const receiverUnstable = Boolean(receiver && (aliasSetHas(reassignedSymbols, receiver)
              || assignedValues.has(receiver)));
            let resolvedCallable = false;
            let unresolvedReceiverValue = false;
            if (key !== undefined) {
              const callableProperties = (
                object: ts.ObjectLiteralExpression,
                visited = new Set<ts.ObjectLiteralExpression>(),
              ): { present: boolean; callables: ts.FunctionLikeDeclaration[]; complete: boolean } => {
                if (visited.has(object)) return { present: true, callables: [], complete: false };
                visited.add(object);
                let result = { present: false, callables: [] as ts.FunctionLikeDeclaration[], complete: true };
                for (const property of object.properties) {
                  if (ts.isSpreadAssignment(property)) {
                    const spread = resolveConstObject(property.expression, checker, projectSources, check);
                    if (!spread) {
                      result.complete = false;
                      continue;
                    }
                    const nested = callableProperties(spread, new Set(visited));
                    if (nested.present) result = nested;
                    else result.complete &&= nested.complete;
                    continue;
                  }
                  const name = 'name' in property && property.name
                    ? ts.isComputedPropertyName(property.name)
                      ? resolveStaticPropertyKey(property.name.expression, checker, check)
                      : (ts.isIdentifier(property.name) || ts.isStringLiteral(property.name))
                        ? property.name.text : undefined
                    : undefined;
                  if (name === undefined && 'name' in property
                    && property.name && ts.isComputedPropertyName(property.name)) {
                    result.complete = false;
                  }
                  if (name !== key) continue;
                  const callable = ts.isMethodDeclaration(property) ? property
                    : ts.isPropertyAssignment(property)
                      && (ts.isArrowFunction(property.initializer)
                        || ts.isFunctionExpression(property.initializer))
                      ? property.initializer : undefined;
                  result = {
                    present: true,
                    callables: callable ? [callable] : [],
                    complete: Boolean(callable),
                  };
                }
                return result;
              };
              const receiverDeclarations = receiver?.declarations?.filter(ts.isVariableDeclaration) ?? [];
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
                  if (pushCallable(callable)) return true;
                }
              }
            }
            const declarations = member?.declarations?.filter((declaration) => (
              projectSources.has(declaration.getSourceFile()) && (ts.isMethodDeclaration(declaration)
                || ts.isPropertyAssignment(declaration))
            )) ?? [];
            const unstable = receiverUnstable;
            if (unresolvedReceiverValue || (receiverUnstable && !resolvedCallable)) return true;
            if (!resolvedCallable && declarations.length > 0
              && (declarations.length !== 1 || unstable)) return true;
            const declaration = resolvedCallable ? undefined : declarations[0];
            const callable = declaration && ts.isMethodDeclaration(declaration) ? declaration
              : declaration && ts.isPropertyAssignment(declaration)
                && (ts.isArrowFunction(declaration.initializer)
                  || ts.isFunctionExpression(declaration.initializer))
                ? declaration.initializer : undefined;
            if (callable && pushCallable(callable)) return true;
          }
        }
        if (ts.isIdentifier(candidate)) {
          let symbol = checker.getSymbolAtLocation(candidate);
          if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
          if (symbol && !candidateSymbols.has(symbol)) {
            candidateSymbols.add(symbol);
            for (const declaration of symbol.declarations ?? []) {
              if (ts.isVariableDeclaration(declaration) && declaration.initializer
                && projectSources.has(declaration.getSourceFile())) nodes.push(declaration.initializer);
            }
          }
        }
        if (ts.isPropertyAccessExpression(candidate) || ts.isElementAccessExpression(candidate)) {
          const candidateMethod = ts.isPropertyAccessExpression(candidate)
            ? candidate.name.text : candidate.argumentExpression
              ? resolveStaticPropertyKey(candidate.argumentExpression, checker, check) : undefined;
          if ((candidateMethod === 'create' || candidateMethod === 'createApplicationContext'
            || candidateMethod === 'createMicroservice') && (
            isStaticSymbolFrom(candidate.expression, checker, check, '@nestjs/core', 'NestFactory')
            || containsStaticSymbolFrom(
              candidate.expression, checker, check, '@nestjs/core', 'NestFactory', projectSources,
            )
          )) return true;
        }
        ts.forEachChild(candidate, (child) => { nodes.push(child); });
      }
      return false;
    };
    const staticUndefined = (
      input: ts.Expression, symbols = new Set<ts.Symbol>(), depth = 0,
    ): boolean | undefined => {
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
      if (!symbol || symbols.has(symbol)) return undefined;
      const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
      const declaration = declarations.length === 1 ? declarations[0] : undefined;
      if (!declaration?.initializer || !projectSources.has(declaration.getSourceFile())
        || !ts.isVariableDeclarationList(declaration.parent)
        || !(declaration.parent.flags & ts.NodeFlags.Const)) return undefined;
      symbols.add(symbol);
      return staticUndefined(declaration.initializer, symbols, depth + 1);
    };
    let steps = 0;
    while (expressions.length > 0) {
      check();
      if (steps >= 256) return true;
      steps += 1;
      let node = expressions.pop()!;
      while (ts.isParenthesizedExpression(node) || ts.isAsExpression(node)
        || ts.isTypeAssertionExpression(node) || ts.isSatisfiesExpression(node)
        || ts.isNonNullExpression(node)) node = node.expression;
      if ((ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node))) {
        const object = resolveConstObject(node.expression, checker, projectSources, check);
        const receiverSymbol = rootSymbolAt(node.expression);
        const mutableReceiverDeclaration = receiverSymbol?.declarations?.find((declaration) => (
          ts.isVariableDeclaration(declaration)
            && projectSources.has(declaration.getSourceFile())
            && ts.isVariableDeclarationList(declaration.parent)
            && !(declaration.parent.flags & ts.NodeFlags.Const)
        )) as ts.VariableDeclaration | undefined;
        const mutableObjectReceiver = Boolean(mutableReceiverDeclaration && receiverSymbol && (
          unresolvedAssignments.has(receiverSymbol)
          || [
            ...(mutableReceiverDeclaration.initializer ? [mutableReceiverDeclaration.initializer] : []),
            ...(assignedValues.get(receiverSymbol) ?? []),
          ].some(candidateContainsBootstrapAccess)
        ));
        if (mutableObjectReceiver) return true;
        if (object && receiverSymbol && (aliasSetHas(unstableContainers, receiverSymbol)
          || aliasSetHas(escapedSymbols, receiverSymbol)
          || unresolvedAssignments.has(receiverSymbol))) return true;
        const memberSymbol = symbolAt(ts.isPropertyAccessExpression(node) ? node.name : node);
        if (object && memberSymbol && unresolvedAssignments.has(memberSymbol)) return true;
        if (memberSymbol) {
          expressions.push(...(assignedValues.get(memberSymbol) ?? []));
          for (const declaration of memberSymbol.declarations ?? []) {
            if (ts.isPropertyDeclaration(declaration) && declaration.initializer
              && projectSources.has(declaration.getSourceFile())) {
              expressions.push(declaration.initializer);
            }
          }
        }
        const method = ts.isPropertyAccessExpression(node) ? node.name.text
          : node.argumentExpression
            ? resolveStaticPropertyKey(node.argumentExpression, checker, check) : undefined;
        const canonicalReceiver = containsStaticSymbolFrom(
          node.expression, checker, check, '@nestjs/core', 'NestFactory', projectSources,
        );
        if (canonicalReceiver && (method === undefined || method === 'create'
          || method === 'createApplicationContext' || method === 'createMicroservice')) return true;
        if (method !== undefined) {
          if (object) {
            expressions.push(...effectiveObjectProperty(
              object, method, checker, projectSources, check,
            ).candidates);
          }
        } else {
          if (object && includeContainers) expressions.push(object);
        }
        continue;
      }
      if (ts.isIdentifier(node)) {
        let symbol = checker.getSymbolAtLocation(node);
        if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) {
          symbol = checker.getAliasedSymbol(symbol);
        }
        const bound = symbol ? parameterBindings.get(symbol) : undefined;
        if (bound) {
          expressions.push(...bound);
          continue;
        }
        if (!symbol || seen.has(symbol)) continue;
        seen.add(symbol);
        if (!asValue && symbol.declarations?.some((declaration) => (
          ts.isFunctionDeclaration(declaration) && projectSources.has(declaration.getSourceFile())
        ))) continue;
        if (includeContainers && (aliasSetHas(unstableContainers, symbol)
          || aliasSetHas(escapedSymbols, symbol)
          || aliasSetHas(unresolvedAssignments, symbol))) return true;
        for (const declaration of symbol.declarations ?? []) {
          if (ts.isVariableDeclaration(declaration) && declaration.initializer
            && projectSources.has(declaration.getSourceFile())) expressions.push(declaration.initializer);
          if (asValue && ts.isFunctionDeclaration(declaration) && declaration.body
            && projectSources.has(declaration.getSourceFile()) && (
              candidateContainsBootstrapAccess(declaration.body)
              || declaration.parameters.some(({ initializer }) => (
                !!initializer && candidateContainsBootstrapAccess(initializer)
              ))
            )) return true;
          if (ts.isBindingElement(declaration)
            && ts.isObjectBindingPattern(declaration.parent)) {
            const variable = declaration.parent.parent;
            const key = declaration.propertyName
              ? ts.isIdentifier(declaration.propertyName) ? declaration.propertyName.text
                : resolveStaticPropertyKey(
                  ts.isComputedPropertyName(declaration.propertyName)
                    ? declaration.propertyName.expression : declaration.propertyName,
                  checker,
                  check,
                )
              : ts.isIdentifier(declaration.name) ? declaration.name.text : undefined;
            const canonicalReceiver = ts.isVariableDeclaration(variable)
              && variable.initializer && containsStaticSymbolFrom(
              variable.initializer, checker, check, '@nestjs/core', 'NestFactory', projectSources,
            );
            if (canonicalReceiver && (key === undefined || key === 'create'
              || key === 'createApplicationContext' || key === 'createMicroservice')) return true;
          }
        }
        expressions.push(...(assignedValues.get(symbol) ?? []));
        continue;
      }
      if (ts.isCallExpression(node)) {
        let callee: ts.Expression = node.expression;
        while (ts.isParenthesizedExpression(callee) || ts.isAsExpression(callee)
          || ts.isTypeAssertionExpression(callee) || ts.isSatisfiesExpression(callee)
          || ts.isNonNullExpression(callee)) callee = callee.expression;
        if (ts.isIdentifier(callee)) {
          let symbol = checker.getSymbolAtLocation(callee);
          if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) {
            symbol = checker.getAliasedSymbol(symbol);
          }
          for (const declaration of symbol?.declarations ?? []) {
            if (!projectSources.has(declaration.getSourceFile())) continue;
            const callable = ts.isFunctionDeclaration(declaration) ? declaration
              : ts.isVariableDeclaration(declaration) && declaration.initializer
                && (ts.isArrowFunction(declaration.initializer)
                  || ts.isFunctionExpression(declaration.initializer))
                ? declaration.initializer : undefined;
            if (!callable?.body) continue;
            const bootstrapEvidence = candidateContainsBootstrapAccess(callable.body)
              || callable.parameters.some(({ initializer }) => (
                !!initializer && candidateContainsBootstrapAccess(initializer)
              )) || node.arguments.some((argument) => candidateContainsBootstrapAccess(argument));
            if (callable.modifiers?.some(({ kind }) => kind === ts.SyntaxKind.AsyncKeyword)
              || ('asteriskToken' in callable && callable.asteriskToken)) {
              if (bootstrapEvidence) return true;
              continue;
            }
            for (const [index, parameter] of callable.parameters.entries()) {
              if (!ts.isIdentifier(parameter.name) || parameter.dotDotDotToken) return true;
              const parameterSymbol = checker.getSymbolAtLocation(parameter.name);
              if (!parameterSymbol) return true;
              if (aliasSetHas(reassignedSymbols, parameterSymbol)
                || aliasSetHas(unresolvedAssignments, parameterSymbol)) {
                if (bootstrapEvidence) return true;
                continue;
              }
              const argument = node.arguments[index];
              let actual = argument && !ts.isSpreadElement(argument) ? argument : undefined;
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
            if (!ts.isBlock(callable.body)) {
              expressions.push(callable.body);
              continue;
            }
            const returns: ts.Node[] = [...callable.body.statements];
            while (returns.length > 0) {
              check();
              const current = returns.pop()!;
              if (ts.isReturnStatement(current) && current.expression
                && !staticallyUnreachable(current)) {
                expressions.push(current.expression);
              } else if (!ts.isFunctionLike(current) && !ts.isClassLike(current)) {
                ts.forEachChild(current, (child) => { returns.push(child); });
              }
            }
          }
        }
        continue;
      }
      if (ts.isAwaitExpression(node)) {
        expressions.push(node.expression);
        continue;
      }
      if (asValue && (ts.isArrowFunction(node) || ts.isFunctionExpression(node))) {
        if (candidateContainsBootstrapAccess(node.body)
          || node.parameters.some(({ initializer }) => (
            !!initializer && candidateContainsBootstrapAccess(initializer)
          ))) return true;
        continue;
      }
      if (ts.isConditionalExpression(node)) {
        const state = staticState(node.condition);
        if (state.truthy !== false) expressions.push(node.whenTrue);
        if (state.truthy !== true) expressions.push(node.whenFalse);
      } else if (ts.isBinaryExpression(node)
        && node.operatorToken.kind === ts.SyntaxKind.CommaToken) expressions.push(node.right);
      else if (ts.isBinaryExpression(node) && (
        node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
        || node.operatorToken.kind === ts.SyntaxKind.BarBarToken
        || node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken
      )) {
        const state = staticState(node.left);
        if (node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) {
          if (state.truthy !== true) expressions.push(node.left);
          if (state.truthy !== false) expressions.push(node.right);
        } else if (node.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
          if (state.truthy !== false) expressions.push(node.left);
          if (state.truthy !== true) expressions.push(node.right);
        } else {
          if (state.nullish !== true) expressions.push(node.left);
          if (state.nullish !== false) expressions.push(node.right);
        }
      }
      else if (includeContainers && ts.isObjectLiteralExpression(node)) {
        for (const property of node.properties) {
          if (ts.isPropertyAssignment(property)) expressions.push(property.initializer);
          else if (ts.isShorthandPropertyAssignment(property)) expressions.push(property.name);
          else if (ts.isSpreadAssignment(property)) {
            if (resolveConstObject(property.expression, checker, projectSources, check)) {
              expressions.push(property.expression);
            } else if (candidateContainsBootstrapAccess(property.expression)) return true;
          } else if (ts.isMethodDeclaration(property) || ts.isAccessor(property)) {
            if (candidateContainsBootstrapAccess(property)) return true;
            const returnedSymbols = new Set<ts.Symbol>();
            const returnedCallableContainsBootstrap = (
              input: ts.Expression, depth = 0,
            ): boolean => {
              if (depth >= 64) return true;
              if (candidateContainsBootstrapAccess(input)) return true;
              let expression = input;
              while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
                || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)
                || ts.isNonNullExpression(expression)) expression = expression.expression;
              if (ts.isIdentifier(expression)) {
                let symbol = checker.getSymbolAtLocation(expression);
                if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) {
                  symbol = checker.getAliasedSymbol(symbol);
                }
                if (!symbol || returnedSymbols.has(symbol)) return false;
                returnedSymbols.add(symbol);
                if (unresolvedAssignments.has(symbol)) return true;
                const writes = assignedValues.get(symbol) ?? [];
                if (reassignedSymbols.has(symbol) && writes.length === 0) return true;
                for (const value of writes) {
                  if (returnedCallableContainsBootstrap(value, depth + 1)) return true;
                }
                for (const declaration of symbol.declarations ?? []) {
                  if (!projectSources.has(declaration.getSourceFile())) continue;
                  if (ts.isBindingElement(declaration) && ts.isObjectBindingPattern(declaration.parent)) {
                    const variable = declaration.parent.parent;
                    const key = declaration.propertyName
                      ? ts.isIdentifier(declaration.propertyName) ? declaration.propertyName.text
                        : ts.isComputedPropertyName(declaration.propertyName)
                          ? resolveStaticPropertyKey(declaration.propertyName.expression, checker, check)
                          : undefined
                      : ts.isIdentifier(declaration.name) ? declaration.name.text : undefined;
                    if (ts.isVariableDeclaration(variable) && variable.initializer
                      && containsStaticSymbolFrom(
                        variable.initializer, checker, check,
                        '@nestjs/core', 'NestFactory', projectSources,
                      ) && (key === undefined || key === 'create'
                        || key === 'createApplicationContext' || key === 'createMicroservice')) return true;
                  }
                  if (ts.isVariableDeclaration(declaration) && declaration.initializer
                    && returnedCallableContainsBootstrap(declaration.initializer, depth + 1)) return true;
                  if (ts.isFunctionDeclaration(declaration) && declaration.body) {
                    if (candidateContainsBootstrapAccess(declaration.body)) return true;
                    const declarationReturns: ts.Node[] = [...declaration.body.statements];
                    while (declarationReturns.length > 0) {
                      const nested = declarationReturns.pop()!;
                      if (ts.isReturnStatement(nested) && nested.expression
                        && !staticallyUnreachable(nested)
                        && returnedCallableContainsBootstrap(nested.expression, depth + 1)) return true;
                      if (!ts.isFunctionLike(nested) && !ts.isClassLike(nested)) {
                        ts.forEachChild(nested, (child) => { declarationReturns.push(child); });
                      }
                    }
                  }
                }
                return false;
              }
              if (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression)) {
                const member = symbolAt(ts.isPropertyAccessExpression(expression)
                  ? expression.name : expression);
                if (member && unresolvedAssignments.has(member)) return true;
                for (const value of member ? assignedValues.get(member) ?? [] : []) {
                  if (returnedCallableContainsBootstrap(value, depth + 1)) return true;
                }
                for (const declaration of member?.declarations ?? []) {
                  if (ts.isPropertyDeclaration(declaration) && declaration.initializer
                    && projectSources.has(declaration.getSourceFile())
                    && returnedCallableContainsBootstrap(declaration.initializer, depth + 1)) return true;
                }
                const key = ts.isPropertyAccessExpression(expression) ? expression.name.text
                  : expression.argumentExpression
                    ? resolveStaticPropertyKey(expression.argumentExpression, checker, check) : undefined;
                const receiver = rootSymbolAt(expression.expression);
                if (key === undefined || (receiver && (unresolvedAssignments.has(receiver)
                  || aliasSetHas(escapedSymbols, receiver)
                  || aliasSetHas(unstableContainers, receiver)))) return true;
                const receiverDeclarations = receiver?.declarations?.filter(ts.isVariableDeclaration) ?? [];
                let immediateReceiver: ts.Expression = expression.expression;
                while (ts.isParenthesizedExpression(immediateReceiver)
                  || ts.isAsExpression(immediateReceiver)
                  || ts.isTypeAssertionExpression(immediateReceiver)
                  || ts.isSatisfiesExpression(immediateReceiver)
                  || ts.isNonNullExpression(immediateReceiver)) immediateReceiver = immediateReceiver.expression;
                const nestedReceiver = ts.isPropertyAccessExpression(immediateReceiver)
                  || ts.isElementAccessExpression(immediateReceiver);
                const receiverValues = nestedReceiver ? [immediateReceiver] : [
                  ...(receiver ? [] : [immediateReceiver]),
                  ...receiverDeclarations.flatMap(({ initializer }) => initializer ? [initializer] : []),
                  ...(receiver ? assignedValues.get(receiver) ?? [] : []),
                ];
                const resolveReceiverObjects = (
                  input: ts.Expression, objectDepth = 0,
                ): ts.ObjectLiteralExpression[] => {
                  if (objectDepth >= 64) return [];
                  let candidate: ts.Expression = input;
                  while (ts.isParenthesizedExpression(candidate) || ts.isAsExpression(candidate)
                    || ts.isTypeAssertionExpression(candidate) || ts.isSatisfiesExpression(candidate)
                    || ts.isNonNullExpression(candidate)) candidate = candidate.expression;
                  const direct = resolveConstObject(candidate, checker, projectSources, check);
                  if (direct) return [direct];
                  if (!ts.isPropertyAccessExpression(candidate)
                    && !ts.isElementAccessExpression(candidate)) return [];
                  const propertyKey = ts.isPropertyAccessExpression(candidate) ? candidate.name.text
                    : candidate.argumentExpression
                      ? resolveStaticPropertyKey(candidate.argumentExpression, checker, check) : undefined;
                  if (propertyKey === undefined) return [];
                  const objects: ts.ObjectLiteralExpression[] = [];
                  for (const object of resolveReceiverObjects(candidate.expression, objectDepth + 1)) {
                    const property = effectiveObjectProperty(
                      object, propertyKey, checker, projectSources, check,
                    );
                    for (const candidate of property.candidates) {
                      objects.push(...resolveReceiverObjects(candidate, objectDepth + 1));
                    }
                  }
                  return objects;
                };
                for (const value of receiverValues) {
                  const objects = resolveReceiverObjects(value);
                  if (objects.length === 0) return true;
                  for (const object of objects) {
                    const property = effectiveObjectProperty(
                      object, key, checker, projectSources, check,
                    );
                    if (!property.present || property.accessor || property.candidates.length === 0) return true;
                    for (const candidate of property.candidates) {
                      if (returnedCallableContainsBootstrap(candidate, depth + 1)) return true;
                    }
                  }
                }
                return false;
              }
              if (!ts.isArrowFunction(expression) && !ts.isFunctionExpression(expression)) return false;
              if (!ts.isBlock(expression.body)) {
                return returnedCallableContainsBootstrap(expression.body, depth + 1);
              }
              const nestedReturns: ts.Node[] = [...expression.body.statements];
              while (nestedReturns.length > 0) {
                const nested = nestedReturns.pop()!;
                if (ts.isReturnStatement(nested) && nested.expression
                  && !staticallyUnreachable(nested)
                  && returnedCallableContainsBootstrap(nested.expression, depth + 1)) return true;
                if (!ts.isFunctionLike(nested) && !ts.isClassLike(nested)) {
                  ts.forEachChild(nested, (child) => { nestedReturns.push(child); });
                }
              }
              return false;
            };
            if (property.body) {
              const returns: ts.Node[] = [...property.body.statements];
              while (returns.length > 0) {
                const returned = returns.pop()!;
                if (ts.isReturnStatement(returned) && returned.expression
                  && !staticallyUnreachable(returned)
                  && returnedCallableContainsBootstrap(returned.expression)) return true;
                if (!ts.isFunctionLike(returned) && !ts.isClassLike(returned)) {
                  ts.forEachChild(returned, (child) => { returns.push(child); });
                }
              }
            }
          }
        }
      } else if (includeContainers && ts.isArrayLiteralExpression(node)) {
        for (const element of node.elements) {
          if (!ts.isOmittedExpression(element)) {
            expressions.push(ts.isSpreadElement(element) ? element.expression : element);
          }
        }
      }
    }
    return false;
  };
  const localFunctionSymbol = (node: ts.SignatureDeclaration): ts.Symbol | undefined => {
    if (ts.isFunctionDeclaration(node) && node.name) return symbolAt(node.name);
    const declaration = (ts.isArrowFunction(node) || ts.isFunctionExpression(node))
      && ts.isVariableDeclaration(node.parent) && node.parent.initializer === node
      && ts.isIdentifier(node.parent.name) ? node.parent : undefined;
    return declaration ? symbolAt(declaration.name) : undefined;
  };
  const invokedLocalFunctions = new Set<ts.Symbol>();
  const functionsWithResolvedBootstrap = new Set<ts.Symbol>();
  for (const sourceFile of projectSources) {
    const nodes: ts.Node[] = [sourceFile];
    while (nodes.length > 0) {
      const node = nodes.pop()!;
      check();
      if (ts.isCallExpression(node) && !staticallyUnreachable(node)) {
        let callee = unwrapModuleExpression(node.expression);
        let functionAncestor: ts.SignatureDeclaration | undefined;
        for (let parent = node.parent; !ts.isSourceFile(parent); parent = parent.parent) {
          if (ts.isFunctionLike(parent)) {
            functionAncestor = parent;
            break;
          }
        }
        if (!functionAncestor && node.arguments.length === 0 && ts.isIdentifier(callee)) {
          const symbol = symbolAt(callee);
          const declarations = symbol?.declarations?.filter((declaration) => (
            (ts.isFunctionDeclaration(declaration) && declaration.body !== undefined
              && !declaration.asteriskToken)
              || (ts.isVariableDeclaration(declaration) && declaration.initializer
                && (ts.isArrowFunction(declaration.initializer)
                  || (ts.isFunctionExpression(declaration.initializer)
                    && !declaration.initializer.asteriskToken)))
          ) && projectSources.has(declaration.getSourceFile())) ?? [];
          if (symbol && declarations.length === 1 && !reassignedSymbols.has(symbol)
            && !unresolvedAssignments.has(symbol)) invokedLocalFunctions.add(symbol);
        }
        const method = ts.isPropertyAccessExpression(callee) ? callee.name.text
          : ts.isElementAccessExpression(callee) && callee.argumentExpression
            ? resolveStaticPropertyKey(callee.argumentExpression, checker, check) : undefined;
        if (functionAncestor && node.arguments[0]
          && (method === 'create' || method === 'createApplicationContext'
            || method === 'createMicroservice')
          && (ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee))
          && containsStaticSymbolFrom(
            callee.expression, checker, check, '@nestjs/core', 'NestFactory', projectSources,
          ) && moduleSymbol(node.arguments[0])) {
          const symbol = localFunctionSymbol(functionAncestor);
          if (symbol) functionsWithResolvedBootstrap.add(symbol);
        }
      }
      ts.forEachChild(node, (child) => { nodes.push(child); });
    }
  }
  for (const sourceFile of projectSources) {
    const nodes: ts.Node[] = [sourceFile];
    while (nodes.length > 0) {
      const node = nodes.pop()!;
      check();
      if (ts.isCallExpression(node) && node.arguments[0] && !staticallyUnreachable(node)) {
        const callee = node.expression;
        const method = ts.isPropertyAccessExpression(callee) ? callee.name.text
          : ts.isElementAccessExpression(callee) && callee.argumentExpression
            ? resolveStaticPropertyKey(callee.argumentExpression, checker, check) : undefined;
        if ((method === 'create' || method === 'createApplicationContext'
          || method === 'createMicroservice')
          && (ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee))
          && containsStaticSymbolFrom(
            callee.expression, checker, check, '@nestjs/core', 'NestFactory', projectSources,
          )) {
          const symbol = moduleSymbol(node.arguments[0]);
          if (symbol) roots.add(symbol);
          else moduleGraphComplete = false;
          for (let parent = node.parent; !ts.isSourceFile(parent); parent = parent.parent) {
            if (ts.isFunctionLike(parent)) {
              const functionSymbol = localFunctionSymbol(parent);
              if (!functionSymbol || !invokedLocalFunctions.has(functionSymbol)
                || !functionsWithResolvedBootstrap.has(functionSymbol)) {
                moduleGraphComplete = false;
              }
              break;
            }
          }
        } else {
          const localFunction = ts.isIdentifier(unwrapModuleExpression(callee))
            ? symbolAt(unwrapModuleExpression(callee)) : undefined;
          if (localFunction && invokedLocalFunctions.has(localFunction)
            && functionsWithResolvedBootstrap.has(localFunction)) {
            ts.forEachChild(node, (child) => { nodes.push(child); });
            continue;
          }
          const target = (ts.isPropertyAccessExpression(callee)
            || ts.isElementAccessExpression(callee)) ? callee.expression : undefined;
          const unwrappedTarget = target ? unwrapModuleExpression(target) : undefined;
          const dynamicTarget = Boolean(unwrappedTarget && ts.isElementAccessExpression(unwrappedTarget)
            && (!unwrappedTarget.argumentExpression
              || resolveStaticPropertyKey(
                unwrappedTarget.argumentExpression, checker, check,
              ) === undefined));
          if ((method === 'call' || method === 'apply' || method === 'bind')
            && target && indirectBootstrapTarget(target, dynamicTarget)) moduleGraphComplete = false;
          else {
            const unwrappedCallee = unwrapModuleExpression(callee);
            const dynamicCallee = ts.isElementAccessExpression(unwrappedCallee)
              && (!unwrappedCallee.argumentExpression || resolveStaticPropertyKey(
                unwrappedCallee.argumentExpression, checker, check,
              ) === undefined);
            if (indirectBootstrapTarget(callee, dynamicCallee)) moduleGraphComplete = false;
          }
        }
        for (const argument of node.arguments) {
          const candidate = ts.isSpreadElement(argument) ? argument.expression : argument;
          if (indirectBootstrapTarget(candidate, false, true)
            || indirectBootstrapTarget(candidate, true, true)) {
            moduleGraphComplete = false;
          }
        }
      }
      ts.forEachChild(node, (child) => { nodes.push(child); });
    }
  }
  const activeModules = new Set(roots.size > 0 ? roots : modulesBySymbol.keys());
  if (roots.size > 0) {
    const pending = [...roots];
    const visitedBaseClasses = new Set<ts.Symbol>();
    const activateInheritedModules = (node: ts.ClassLikeDeclaration): void => {
      const classes = [node];
      let steps = 0;
      while (classes.length > 0) {
        check();
        if (steps >= 256) {
          moduleGraphComplete = false;
          return;
        }
        steps += 1;
        for (const heritage of classes.pop()!.heritageClauses ?? []) {
          if (heritage.token !== ts.SyntaxKind.ExtendsKeyword) continue;
          for (const type of heritage.types) {
            let symbol = checker.getSymbolAtLocation(type.expression);
            if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) {
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
      const entry = modulesBySymbol.get(pending.pop()!);
      if (entry) activateInheritedModules(entry.node);
      const metadataSymbol = entry?.metadataArgument
        ? rootSymbolAt(entry.metadataArgument) : undefined;
      if (metadataSymbol && (aliasSetHas(unstableContainers, metadataSymbol)
        || aliasSetHas(escapedSymbols, metadataSymbol)
        || aliasSetHas(containersWithAssignedImports, metadataSymbol)
        || aliasSetHas(incompleteLocalCallImportSymbols, metadataSymbol)
        || aliasSetHas(unresolvedAssignments, metadataSymbol))) moduleGraphComplete = false;
      if (!entry?.metadata) {
        if (entry?.metadataArgument) moduleGraphComplete = false;
        continue;
      }
      const imports = effectiveObjectProperty(
        entry.metadata, 'imports', checker, projectSources, check,
      );
      const importsSymbol = checker.getTypeAtLocation(entry.metadata).getProperty('imports');
      if (importsSymbol && (reassignedSymbols.has(importsSymbol)
        || unresolvedAssignments.has(importsSymbol)
        || aliasSetHas(unstableContainers, importsSymbol)
        || aliasSetHas(escapedSymbols, importsSymbol)
        || aliasSetHas(incompleteLocalCallImportSymbols, importsSymbol)
        || assignedValues.has(importsSymbol))) moduleGraphComplete = false;
      if (imports.candidates.some((candidate) => {
        const symbol = rootSymbolAt(candidate);
        return Boolean(symbol && (aliasSetHas(unstableContainers, symbol)
          || aliasSetHas(escapedSymbols, symbol)
          || aliasSetHas(incompleteLocalCallImportSymbols, symbol)
          || aliasSetHas(unresolvedAssignments, symbol)));
      })) moduleGraphComplete = false;
      if (imports.candidates.some((candidate) => (
        mutatedContainerExpressions.has(unwrapModuleExpression(candidate))
        || mutatedDynamicExpressions.has(unwrapModuleExpression(candidate))
      ))) moduleGraphComplete = false;
      const expressions = [...imports.candidates];
      while (expressions.length > 0) {
        const expression = expressions.pop()!;
        const unwrapped = unwrapModuleExpression(expression);
        if (ts.isArrayLiteralExpression(unwrapped)) {
          for (const element of unwrapped.elements) {
            if (!ts.isOmittedExpression(element)) {
              expressions.push(ts.isSpreadElement(element) ? element.expression : element);
            }
          }
          continue;
        }
        if (ts.isConditionalExpression(unwrapped)) {
          expressions.push(unwrapped.whenTrue, unwrapped.whenFalse);
          continue;
        }
        const symbol = moduleSymbol(unwrapped);
        if (symbol && !activeModules.has(symbol)) {
          activeModules.add(symbol);
          pending.push(symbol);
        } else if (!symbol) moduleGraphComplete = false;
      }
    }
  }
  if (!moduleGraphComplete) {
    for (const symbol of modulesBySymbol.keys()) activeModules.add(symbol);
  }
  for (const entry of moduleEntries) {
    if (entry.symbol && !activeModules.has(entry.symbol)) continue;
    const { metadataArgument, metadata } = entry;
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
      return {};
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
    const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
    const declaration = declarations.length === 1 ? declarations[0] : undefined;
    if (!declaration?.initializer || !projectSources.has(declaration.getSourceFile())
      || !ts.isVariableDeclarationList(declaration.parent)
      || !(declaration.parent.flags & ts.NodeFlags.Const)) return {};
    seen.add(symbol);
    return staticState(declaration.initializer, seen, depth + 1);
  };
  const staticBoolean = (input: ts.Expression): boolean | undefined => staticState(input).truthy;
  const containsLiteralProviderToken = (input: ts.Expression): boolean => {
    const pending = [input];
    const seen = new Set<ts.Expression>();
    while (pending.length > 0) {
      check();
      steps += 1;
      if (steps > maxSteps) throw new SourceAnalyzerContractError('SOURCE_ANALYZER_AST_NODE_LIMIT');
      let expression = pending.pop()!;
      while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)
        || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)
        || ts.isNonNullExpression(expression)) expression = expression.expression;
      if (seen.has(expression)) continue;
      seen.add(expression);
      if (resolveStaticStrings(
        expression, checker, projectSources, { check, maxSteps },
      )?.includes('APP_GUARD') === true) return true;
      if (ts.isConditionalExpression(expression)) {
        const condition = staticState(expression.condition);
        if (condition.truthy !== false) pending.push(expression.whenTrue);
        if (condition.truthy !== true) pending.push(expression.whenFalse);
      } else if (ts.isBinaryExpression(expression) && (
        expression.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
        || expression.operatorToken.kind === ts.SyntaxKind.BarBarToken
        || expression.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken
      )) {
        const left = staticState(expression.left);
        if (expression.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) {
          if (left.truthy !== true) pending.push(expression.left);
          if (left.truthy !== false) pending.push(expression.right);
        } else if (expression.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
          if (left.truthy !== false) pending.push(expression.left);
          if (left.truthy !== true) pending.push(expression.right);
        } else {
          if (left.nullish !== true) pending.push(expression.left);
          if (left.nullish !== false) pending.push(expression.right);
        }
      }
    }
    return false;
  };
  type ReturnFlow = { candidates: ts.Expression[]; definitelyReturns: boolean; mayThrow: boolean };
  const collectReturns = (statement: ts.Statement): ReturnFlow => {
    check();
    if (ts.isReturnStatement(statement)) {
      return {
        candidates: statement.expression ? [statement.expression] : [],
        definitelyReturns: true,
        mayThrow: Boolean(statement.expression && nodeMayThrow(
          statement.expression, checker, projectSources, check,
        )),
      };
    }
    if (ts.isThrowStatement(statement)) {
      return { candidates: [], definitelyReturns: true, mayThrow: true };
    }
    if (ts.isBlock(statement)) {
      const flow: ReturnFlow = { candidates: [], definitelyReturns: false, mayThrow: false };
      for (const child of statement.statements) {
        const childFlow = collectReturns(child);
        flow.candidates.push(...childFlow.candidates);
        flow.mayThrow ||= childFlow.mayThrow;
        if (childFlow.definitelyReturns) {
          flow.definitelyReturns = true;
          break;
        }
      }
      return flow;
    }
    if (ts.isIfStatement(statement)) {
      const condition = staticBoolean(statement.expression);
      if (condition === true) return collectReturns(statement.thenStatement);
      if (condition === false) return statement.elseStatement
        ? collectReturns(statement.elseStatement)
        : { candidates: [], definitelyReturns: false, mayThrow: false };
      const whenTrue = collectReturns(statement.thenStatement);
      const whenFalse = statement.elseStatement ? collectReturns(statement.elseStatement)
        : { candidates: [], definitelyReturns: false, mayThrow: false };
      return {
        candidates: [...whenTrue.candidates, ...whenFalse.candidates],
        definitelyReturns: whenTrue.definitelyReturns && whenFalse.definitelyReturns,
        mayThrow: nodeMayThrow(statement.expression, checker, projectSources, check)
          || whenTrue.mayThrow || whenFalse.mayThrow,
      };
    }
    if (ts.isTryStatement(statement)) {
      const tryFlow = collectReturns(statement.tryBlock);
      const catchFlow = statement.catchClause && tryFlow.mayThrow
        ? collectReturns(statement.catchClause.block) : undefined;
      let flow: ReturnFlow = {
        candidates: [...tryFlow.candidates, ...(catchFlow?.candidates ?? [])],
        definitelyReturns: tryFlow.definitelyReturns
          && (!tryFlow.mayThrow || Boolean(catchFlow?.definitelyReturns)),
        mayThrow: catchFlow ? catchFlow.mayThrow : tryFlow.mayThrow,
      };
      if (statement.finallyBlock) {
        const finallyFlow = collectReturns(statement.finallyBlock);
        flow = finallyFlow.definitelyReturns ? finallyFlow : {
          candidates: [...flow.candidates, ...finallyFlow.candidates],
          definitelyReturns: flow.definitelyReturns,
          mayThrow: flow.mayThrow || finallyFlow.mayThrow,
        };
      }
      return flow;
    }
    return {
      candidates: [],
      definitelyReturns: false,
      mayThrow: nodeMayThrow(statement, checker, projectSources, check),
    };
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
          if (ts.isBlock(declaration.initializer.body)) {
            expressions.push(...collectReturns(declaration.initializer.body).candidates);
          }
          else expressions.push(declaration.initializer.body);
        } else expressions.push(declaration.initializer);
      } else if (ts.isFunctionDeclaration(declaration) && declaration.body) {
        expressions.push(...collectReturns(declaration.body).candidates);
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
          ) || (name === 'provide' && containsLiteralProviderToken(initializer))) return true;
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
    type StaticExpressionState = {
      truth: boolean | undefined;
      nullish: boolean | undefined;
    };
    const expressions: ts.Expression[] = [input];
    const visited = new Set<ts.Symbol>();
    const assignments = new Map<ts.Symbol, readonly ts.Expression[] | null>();
    const stateCache = new Map<ts.Symbol, StaticExpressionState>();
    const staticExpressionState = (
      inputExpression: ts.Expression,
    ): StaticExpressionState => {
      let value = unwrap(inputExpression);
      const aliases = new Set<ts.Symbol>();
      const traversed: ts.Symbol[] = [];
      const finish = (state: StaticExpressionState): StaticExpressionState => {
        for (const symbol of traversed) stateCache.set(symbol, state);
        return state;
      };
      while (ts.isIdentifier(value)) {
        check();
        let symbol = checker.getSymbolAtLocation(value);
        if (!symbol && value.text === 'undefined') return finish({ truth: false, nullish: true });
        if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
        if (!symbol || aliases.has(symbol) || aliases.size >= 64) {
          return finish({ truth: undefined, nullish: undefined });
        }
        const cached = stateCache.get(symbol);
        if (cached) return finish(cached);
        aliases.add(symbol);
        traversed.push(symbol);
        if (symbol.declarations?.some((declaration) => (
          ts.isFunctionDeclaration(declaration) || ts.isClassDeclaration(declaration)
        ))) {
          const writes = assignmentValues(symbol);
          return finish(writes && writes.length === 0
            ? { truth: true, nullish: false }
            : { truth: undefined, nullish: undefined });
        }
        const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
        const declaration = declarations.length === 1 ? declarations[0] : undefined;
        if (!declaration?.initializer || !projectSources.has(declaration.getSourceFile())
          || !ts.isVariableDeclarationList(declaration.parent)
          || !(declaration.parent.flags & ts.NodeFlags.Const)) {
          return finish({ truth: undefined, nullish: undefined });
        }
        value = unwrap(declaration.initializer);
      }
      const truth = staticTruth(value);
      if (truth !== undefined) return finish({ truth, nullish: staticNullish(value) });
      if (ts.isArrowFunction(value) || ts.isFunctionExpression(value)
        || ts.isClassExpression(value) || ts.isObjectLiteralExpression(value)
        || ts.isArrayLiteralExpression(value) || ts.isNewExpression(value)) {
        return finish({ truth: true, nullish: false });
      }
      return finish({ truth: undefined, nullish: staticNullish(value) });
    };
    function assignmentValues(symbol: ts.Symbol): readonly ts.Expression[] | undefined {
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
    }
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
        const { truth } = staticExpressionState(candidate.condition);
        if (truth !== false) expressions.push(candidate.whenTrue);
        if (truth !== true) expressions.push(candidate.whenFalse);
      } else if (ts.isBinaryExpression(candidate)) {
        const operator = candidate.operatorToken.kind;
        const state = staticExpressionState(candidate.left);
        if (operator === ts.SyntaxKind.AmpersandAmpersandToken) {
          if (state.truth !== true) expressions.push(candidate.left);
          if (state.truth !== false) expressions.push(candidate.right);
        } else if (operator === ts.SyntaxKind.BarBarToken) {
          if (state.truth !== false) expressions.push(candidate.left);
          if (state.truth !== true) expressions.push(candidate.right);
        } else if (operator === ts.SyntaxKind.QuestionQuestionToken) {
          if (state.nullish !== true) expressions.push(candidate.left);
          if (state.nullish !== false) expressions.push(candidate.right);
        } else expressions.push(candidate.left, candidate.right);
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
  return expressionUsesGuardDecorator(expression);
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
    if (resolved.indirectInvocation) {
      result.guardDynamic = true;
      return true;
    }
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
        const symbol = resolveStaticSymbolName(argument, checker, check, projectSources);
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
  type LocalFunction = ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression;
  const localFunctions = new Map<ts.Symbol, { callable: LocalFunction; binding: ts.Identifier }>();
  const localFunctionSymbols = new WeakMap<LocalFunction, ts.Symbol>();
  const localClasses = new Map<ts.Symbol, { declaration: ts.ClassDeclaration; binding: ts.Identifier }>();
  const localClassSymbols = new WeakMap<ts.ClassDeclaration, ts.Symbol>();
  const localObjects = new Map<ts.Symbol, { object: ts.ObjectLiteralExpression; binding: ts.Identifier }>();
  const localObjectSymbols = new WeakMap<ts.ObjectLiteralExpression, ts.Symbol>();
  for (const sourceFile of projectSources) {
    if (!ts.isExternalModule(sourceFile)) continue;
    const nodes: ts.Node[] = [sourceFile];
    while (nodes.length > 0) {
      const node = nodes.pop()!;
      check();
      if (ts.isFunctionDeclaration(node) && node.body && node.name
        && !node.modifiers?.some(({ kind }) => (
          kind === ts.SyntaxKind.ExportKeyword || kind === ts.SyntaxKind.DefaultKeyword
        ))) {
        const symbol = resolvedSymbolAt(node.name, checker);
        const bodies = symbol?.declarations?.filter((declaration) => (
          ts.isFunctionDeclaration(declaration) && declaration.body
        )) ?? [];
        if (symbol && bodies.length === 1) {
          localFunctions.set(symbol, { callable: node, binding: node.name });
          localFunctionSymbols.set(node, symbol);
        }
      } else if (ts.isClassDeclaration(node) && node.name
        && !decorators(node).length
        && !node.members.some((member) => decorators(member).length
          || (ts.isFunctionLike(member) && member.parameters.some((parameter) => (
            decorators(parameter).length > 0
          ))))
        && !node.modifiers?.some(({ kind }) => (
          kind === ts.SyntaxKind.ExportKeyword || kind === ts.SyntaxKind.DefaultKeyword
        )) && !node.members.some((member) => {
          const modifiers = ts.canHaveModifiers(member) ? ts.getModifiers(member) : undefined;
          const isStatic = modifiers?.some(({ kind }) => kind === ts.SyntaxKind.StaticKeyword);
          return ts.isClassStaticBlockDeclaration(member)
            || Boolean(isStatic && ts.isPropertyDeclaration(member) && member.initializer);
        })) {
        const symbol = resolvedSymbolAt(node.name, checker);
        const declarations = symbol?.declarations?.filter(ts.isClassDeclaration) ?? [];
        if (symbol && declarations.length === 1) {
          localClasses.set(symbol, { declaration: node, binding: node.name });
          localClassSymbols.set(node, symbol);
        }
      } else if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer
        && ts.isVariableDeclarationList(node.parent)
        && node.parent.flags & ts.NodeFlags.Const
        && !(ts.isVariableStatement(node.parent.parent)
          && node.parent.parent.modifiers?.some(({ kind }) => kind === ts.SyntaxKind.ExportKeyword))) {
        let initializer = node.initializer;
        while (ts.isParenthesizedExpression(initializer) || ts.isAsExpression(initializer)
          || ts.isTypeAssertionExpression(initializer) || ts.isSatisfiesExpression(initializer)
          || ts.isNonNullExpression(initializer)) initializer = initializer.expression;
        if (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer)) {
          const symbol = resolvedSymbolAt(node.name, checker);
          const declarations = symbol?.declarations?.filter(ts.isVariableDeclaration) ?? [];
          if (symbol && declarations.length === 1) {
            localFunctions.set(symbol, { callable: initializer, binding: node.name });
            localFunctionSymbols.set(initializer, symbol);
          }
        } else if (ts.isObjectLiteralExpression(initializer)) {
          const symbol = resolvedSymbolAt(node.name, checker);
          const declarations = symbol?.declarations?.filter(ts.isVariableDeclaration) ?? [];
          if (symbol && declarations.length === 1) {
            localObjects.set(symbol, { object: initializer, binding: node.name });
            localObjectSymbols.set(initializer, symbol);
          }
        }
      }
      ts.forEachChild(node, (child) => { nodes.push(child); });
    }
  }
  const referencedLocalFunctions = new Set<ts.Symbol>();
  const referencedLocalClasses = new Set<ts.Symbol>();
  const referencedLocalObjects = new Set<ts.Symbol>();
  if (localFunctions.size > 0 || localClasses.size > 0 || localObjects.size > 0) {
    for (const sourceFile of projectSources) {
      const nodes: ts.Node[] = [sourceFile];
      while (nodes.length > 0) {
        const node = nodes.pop()!;
        check();
        if (ts.isIdentifier(node)) {
          const symbol = resolvedSymbolAt(node, checker);
          const local = symbol ? localFunctions.get(symbol) : undefined;
          if (symbol && local) {
            let insideDeclaration = false;
            for (let parent: ts.Node | undefined = node; parent; parent = parent.parent) {
              if (parent === local.callable) {
                insideDeclaration = true;
                break;
              }
              if (ts.isSourceFile(parent)) break;
            }
            if (node !== local.binding && !insideDeclaration) referencedLocalFunctions.add(symbol);
          }
          const localClass = symbol ? localClasses.get(symbol) : undefined;
          if (symbol && localClass) {
            let insideDeclaration = false;
            for (let parent: ts.Node | undefined = node; parent; parent = parent.parent) {
              if (parent === localClass.declaration) {
                insideDeclaration = true;
                break;
              }
              if (ts.isSourceFile(parent)) break;
            }
            if (node !== localClass.binding && !insideDeclaration) referencedLocalClasses.add(symbol);
          }
          const localObject = symbol ? localObjects.get(symbol) : undefined;
          if (symbol && localObject) {
            let insideDeclaration = false;
            for (let parent: ts.Node | undefined = node; parent; parent = parent.parent) {
              if (parent === localObject.object) {
                insideDeclaration = true;
                break;
              }
              if (ts.isSourceFile(parent)) break;
            }
            if (node !== localObject.binding && !insideDeclaration) referencedLocalObjects.add(symbol);
          }
        }
        ts.forEachChild(node, (child) => { nodes.push(child); });
      }
    }
  }
  const provablyUninvokedLocalFunctions = new Set([...localFunctions.keys()].filter((symbol) => (
    !referencedLocalFunctions.has(symbol)
  )));
  const provablyUnusedLocalClasses = new Set([...localClasses.keys()].filter((symbol) => (
    !referencedLocalClasses.has(symbol)
  )));
  const provablyUnusedLocalObjects = new Set([...localObjects.keys()].filter((symbol) => (
    !referencedLocalObjects.has(symbol)
  )));
  const isInsideProvablyUninvokedFunction = (node: ts.Node): boolean => {
    for (let parent = node.parent; !ts.isSourceFile(parent); parent = parent.parent) {
      if (ts.isFunctionDeclaration(parent) || ts.isArrowFunction(parent)
        || ts.isFunctionExpression(parent)) {
        const symbol = localFunctionSymbols.get(parent);
        if (symbol && provablyUninvokedLocalFunctions.has(symbol)) return true;
      }
      if ((ts.isConstructorDeclaration(parent) || ts.isMethodDeclaration(parent)
        || ts.isGetAccessorDeclaration(parent) || ts.isSetAccessorDeclaration(parent))
        && ts.isClassDeclaration(parent.parent)) {
        const symbol = localClassSymbols.get(parent.parent);
        let insideBody = false;
        for (let current: ts.Node | undefined = node; current && current !== parent;
          current = current.parent) insideBody ||= current === parent.body;
        if (insideBody && symbol && provablyUnusedLocalClasses.has(symbol)) return true;
      }
      const objectMember = (ts.isMethodDeclaration(parent) || ts.isGetAccessorDeclaration(parent)
        || ts.isSetAccessorDeclaration(parent)) && ts.isObjectLiteralExpression(parent.parent)
        ? parent : undefined;
      let insideObjectMemberBody = !objectMember;
      if (objectMember) {
        for (let current: ts.Node | undefined = node; current && current !== objectMember;
          current = current.parent) insideObjectMemberBody ||= current === objectMember.body;
      }
      const object: ts.ObjectLiteralExpression | undefined = objectMember
        && ts.isObjectLiteralExpression(objectMember.parent) ? objectMember.parent
          : (ts.isArrowFunction(parent) || ts.isFunctionExpression(parent))
            && ts.isPropertyAssignment(parent.parent)
            && ts.isObjectLiteralExpression(parent.parent.parent) ? parent.parent.parent : undefined;
      const objectSymbol = object ? localObjectSymbols.get(object) : undefined;
      if (insideObjectMemberBody && objectSymbol
        && provablyUnusedLocalObjects.has(objectSymbol)) return true;
    }
    return false;
  };
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
        && !staticallyUnreachable(node)
        && !isInsideProvablyUninvokedFunction(node)
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
        && (containsStaticSymbolFrom(
          node.initializer, checker, check, '@nestjs/core', 'APP_GUARD', projectSources,
        ) || resolveStaticStrings(node.initializer, checker, projectSources, {
          check, maxSteps: context.limits.maxAstNodes,
        })?.includes('APP_GUARD') === true)) || (ts.isShorthandPropertyAssignment(node) && node.name.text === 'provide'
        && isProviderRegistration(node, registeredProviders)
        && (isStaticShorthandSymbolFrom(
          node, checker, check, '@nestjs/core', 'APP_GUARD', projectSources,
        ) || resolveStaticStrings(node.name, checker, projectSources, {
          check, maxSteps: context.limits.maxAstNodes,
        })?.includes('APP_GUARD') === true));
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
