import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';

import ts from 'typescript';

export const NESTJS_ROUTE_DECORATORS = [
  'All', 'Controller', 'Delete', 'Get', 'Head', 'Options', 'Patch', 'Post', 'Put', 'RequestMapping', 'Search', 'Sse', 'Version',
] as const;

export type NestJsRouteDecorator = typeof NESTJS_ROUTE_DECORATORS[number];
export type NestJsRouteDecoratorCandidate = NestJsRouteDecorator | 'Unknown';
const UNKNOWN_NESTJS_ROUTE = Symbol('unknown-nestjs-route');
const MAX_COMPOSED_DECORATORS = 256;
const NESTJS_ORIGIN_CACHE = new WeakMap<ts.Symbol, boolean>();
type MemberEscapeAnalysis = {
  escaped: boolean;
  assigned: ReadonlySet<ts.Symbol>;
  deleted: ReadonlyMap<ts.Symbol, readonly ts.DeleteExpression[]>;
};
const MEMBER_ESCAPE_CACHE = new WeakMap<
  ReadonlySet<ts.SourceFile>, WeakMap<ts.Symbol, MemberEscapeAnalysis>
>();
const MEMBER_REFERENCE_CACHE = new WeakMap<
  ReadonlySet<ts.SourceFile>, ReadonlyMap<ts.Symbol, readonly ts.Expression[]>
>();
const CALLABLE_REFERENCE_CACHE = new WeakMap<ReadonlySet<ts.SourceFile>, WeakMap<ts.Symbol, boolean>>();
const BARE_RECEIVER_STABILITY_CACHE = new WeakMap<
  ReadonlySet<ts.SourceFile>, WeakMap<ts.Symbol, boolean>
>();
const WRAPPER_MUTATION_CACHE = new WeakMap<ReadonlySet<ts.SourceFile>, WeakMap<ts.Symbol, boolean>>();
const WRAPPED_RECEIVER_CACHE = new WeakMap<ReadonlySet<ts.SourceFile>, ReadonlySet<ts.Symbol>>();
type CallableWriteRecord = {
  sourceFile: ts.SourceFile;
  start: number;
  directTopLevel: boolean;
  value?: ts.Expression;
  uncertainCanonical?: boolean;
};
const CALLABLE_WRITE_INDEX_CACHE = new WeakMap<
  ReadonlySet<ts.SourceFile>, ReadonlyMap<ts.Symbol, readonly CallableWriteRecord[]>
>();

function callableWriteIndex(
  projectSources: ReadonlySet<ts.SourceFile>,
  checker: ts.TypeChecker,
  check: () => void,
): ReadonlyMap<ts.Symbol, readonly CallableWriteRecord[]> {
  const cached = CALLABLE_WRITE_INDEX_CACHE.get(projectSources);
  if (cached) return cached;
  const index = new Map<ts.Symbol, CallableWriteRecord[]>();
  const isNestedAssignmentTarget = (node: ts.BinaryExpression): boolean => {
    let child: ts.Node = node;
    while (child.parent && !ts.isStatement(child.parent)) {
      const parent = child.parent;
      if (ts.isBinaryExpression(parent) && parent.left === child
        && parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
        && parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment) return true;
      child = parent;
    }
    return false;
  };
  const recordSymbol = (target: ts.Identifier, record: CallableWriteRecord): void => {
    let symbol = ts.isShorthandPropertyAssignment(target.parent) && target.parent.name === target
      ? checker.getShorthandAssignmentValueSymbol(target.parent)
      : checker.getSymbolAtLocation(target);
    if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    if (!symbol) return;
    const records = index.get(symbol) ?? [];
    records.push(record);
    index.set(symbol, records);
  };
  const fallback = (target: ts.Node, record: CallableWriteRecord): void => {
    const current = ts.isExpression(target) ? unwrapExpression(target) : target;
    if (ts.isIdentifier(current)) {
      recordSymbol(current, record);
    } else if (ts.isBinaryExpression(current)
      && current.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      fallback(current.left, record);
    } else if (ts.isArrayLiteralExpression(current)) {
      for (const element of current.elements) {
        if (!ts.isOmittedExpression(element)) fallback(
          ts.isSpreadElement(element) ? element.expression : element, record,
        );
      }
    } else if (ts.isObjectLiteralExpression(current)) {
      for (const property of current.properties) {
        if (ts.isShorthandPropertyAssignment(property)) fallback(property.name, record);
        else if (ts.isPropertyAssignment(property)) fallback(property.initializer, record);
        else if (ts.isSpreadAssignment(property)) fallback(property.expression, record);
      }
    }
  };
  const undefinedState = (
    input: ts.Expression,
    seen = new Set<ts.Symbol>(),
    depth = 0,
  ): boolean | undefined => {
    if (depth >= 64) return undefined;
    const value = unwrapExpression(input);
    if (ts.isVoidExpression(value)) return true;
    if (value.kind === ts.SyntaxKind.NullKeyword || ts.isStringLiteralLike(value)
      || ts.isNumericLiteral(value) || value.kind === ts.SyntaxKind.TrueKeyword
      || value.kind === ts.SyntaxKind.FalseKeyword || ts.isObjectLiteralExpression(value)
      || ts.isArrayLiteralExpression(value) || ts.isFunctionExpression(value)
      || ts.isArrowFunction(value) || ts.isClassExpression(value)) return false;
    if (!ts.isIdentifier(value)) return undefined;
    let symbol = checker.getSymbolAtLocation(value);
    if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    if (value.text === 'undefined' && (!symbol || !symbol.declarations?.length)) return true;
    if (!symbol || seen.has(symbol)) return undefined;
    const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
    const declaration = declarations.length === 1 ? declarations[0] : undefined;
    if (!declaration?.initializer || !ts.isVariableDeclarationList(declaration.parent)
      || !(declaration.parent.flags & ts.NodeFlags.Const)) return undefined;
    return undefinedState(declaration.initializer, new Set(seen).add(symbol), depth + 1);
  };
  const add = (target: ts.Expression, record: CallableWriteRecord): void => {
    const current = unwrapExpression(target);
    if (ts.isIdentifier(current)) {
      recordSymbol(current, record);
      return;
    }
    if (ts.isBinaryExpression(current)
      && current.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const state = record.value ? undefinedState(record.value) : true;
      if (state !== true) add(current.left, record);
      if (state !== false) {
        add(current.left, { ...record, value: current.right, directTopLevel: false });
      }
      return;
    }
    const value = record.value && unwrapExpression(record.value);
    if (ts.isArrayLiteralExpression(current) && value && ts.isArrayLiteralExpression(value)
      && !current.elements.some(ts.isSpreadElement) && !value.elements.some(ts.isSpreadElement)) {
      for (let index = 0; index < current.elements.length; index += 1) {
        const element = current.elements[index];
        if (ts.isOmittedExpression(element)) continue;
        const assigned = value.elements[index];
        add(element, {
          ...record,
          ...(assigned && !ts.isOmittedExpression(assigned) ? { value: assigned } : { value: undefined }),
          directTopLevel: false,
        });
      }
      return;
    }
    if (ts.isObjectLiteralExpression(current) && value && ts.isObjectLiteralExpression(value)
      && !current.properties.some(ts.isSpreadAssignment)
      && !value.properties.some(ts.isSpreadAssignment)) {
      for (const property of current.properties) {
        const key = ts.isShorthandPropertyAssignment(property) ? property.name.text
          : ts.isPropertyAssignment(property) && (ts.isIdentifier(property.name)
            || ts.isStringLiteral(property.name) || ts.isNumericLiteral(property.name))
            ? property.name.text : undefined;
        const nestedTarget = ts.isShorthandPropertyAssignment(property) ? property.name
          : ts.isPropertyAssignment(property) ? property.initializer : undefined;
        if (!key || !nestedTarget) {
          fallback(property, { ...record, directTopLevel: false, uncertainCanonical: true });
          continue;
        }
        let candidates: Array<{ value?: ts.Expression; uncertainCanonical?: boolean }> = [];
        for (const source of value.properties) {
          if (ts.isSpreadAssignment(source)) {
            candidates.push({ value: source.expression, uncertainCanonical: true });
            continue;
          }
          const sourceKey = ts.isComputedPropertyName(source.name)
              ? resolveStaticPropertyKey(source.name.expression, checker, check)
              : (ts.isIdentifier(source.name)
                || ts.isStringLiteral(source.name) || ts.isNumericLiteral(source.name))
                ? source.name.text : undefined;
          const assigned = ts.isShorthandPropertyAssignment(source) ? source.name
            : ts.isPropertyAssignment(source) ? source.initializer : undefined;
          const uncertainCanonical = !assigned;
          if (sourceKey === key) candidates = [{ ...(assigned ? { value: assigned } : {}), uncertainCanonical }];
          else if (sourceKey === undefined) candidates.push({
            ...(assigned ? { value: assigned } : {}), uncertainCanonical: true,
          });
        }
        if (candidates.length === 0) {
          add(nestedTarget, { ...record, value: undefined, directTopLevel: false });
        } else {
          for (const candidate of candidates) add(nestedTarget, {
            ...record, ...candidate, directTopLevel: false,
          });
        }
      }
      return;
    }
    fallback(current, { ...record, directTopLevel: false, uncertainCanonical: true });
  };
  for (const sourceFile of projectSources) {
    const nodes: ts.Node[] = [sourceFile];
    while (nodes.length > 0) {
      check();
      const node = nodes.pop()!;
      if (ts.isBinaryExpression(node)
        && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
        && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment
        && !isNestedAssignmentTarget(node)) {
        const target = unwrapExpression(node.left);
        add(target, {
          sourceFile,
          start: node.getStart(),
          directTopLevel: node.operatorToken.kind === ts.SyntaxKind.EqualsToken
            && ts.isIdentifier(target) && ts.isExpressionStatement(node.parent)
            && ts.isSourceFile(node.parent.parent),
          ...(node.operatorToken.kind === ts.SyntaxKind.EqualsToken ? { value: node.right } : {}),
        });
      } else if (ts.isForOfStatement(node) || ts.isForInStatement(node)) {
        if (!ts.isVariableDeclarationList(node.initializer)) add(node.initializer, {
          sourceFile, start: node.getStart(), directTopLevel: false,
        });
      } else if ((ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node))
        && (node.operator === ts.SyntaxKind.PlusPlusToken
          || node.operator === ts.SyntaxKind.MinusMinusToken)) {
        add(node.operand, { sourceFile, start: node.getStart(), directTopLevel: false });
      }
      ts.forEachChild(node, (child) => { nodes.push(child); });
    }
  }
  CALLABLE_WRITE_INDEX_CACHE.set(projectSources, index);
  return index;
}

function callableBindingMayBeWritten(
  symbol: ts.Symbol,
  declarations: readonly ts.Declaration[],
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile> | undefined,
  check: () => void,
): boolean {
  let projectCache = projectSources && CALLABLE_REFERENCE_CACHE.get(projectSources);
  if (projectSources && !projectCache) {
    projectCache = new WeakMap();
    CALLABLE_REFERENCE_CACHE.set(projectSources, projectCache);
  }
  const cached = projectCache?.get(symbol);
  if (cached !== undefined) return cached;
  let written = false;
  const references: ts.Node[] = projectSources ? [...projectSources] : [];
  while (references.length > 0 && !written) {
    const reference = references.pop()!;
    check();
    if (ts.isIdentifier(reference)) {
      let referenceSymbol = checker.getSymbolAtLocation(reference);
      if (referenceSymbol?.flags && referenceSymbol.flags & ts.SymbolFlags.Alias) {
        referenceSymbol = checker.getAliasedSymbol(referenceSymbol);
      }
      if (referenceSymbol === symbol) {
        const declarationName = declarations.some((declaration) => (
          'name' in declaration && declaration.name === reference
        ));
        let usage: ts.Expression = reference;
        while (ts.isParenthesizedExpression(usage.parent)
          || ts.isAsExpression(usage.parent) || ts.isTypeAssertionExpression(usage.parent)
          || ts.isSatisfiesExpression(usage.parent) || ts.isNonNullExpression(usage.parent)) {
          usage = usage.parent;
        }
        let target: ts.Node = usage;
        while (!declarationName && target.parent && !ts.isStatement(target)) {
          const parent = target.parent;
          if (ts.isBinaryExpression(parent) && parent.left === target
            && parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
            && parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
            written = true;
            break;
          }
          if ((ts.isPrefixUnaryExpression(parent) || ts.isPostfixUnaryExpression(parent))
            && parent.operand === target) {
            written = true;
            break;
          }
          if ((ts.isForOfStatement(parent) || ts.isForInStatement(parent))
            && parent.initializer === target) {
            written = true;
            break;
          }
          target = parent;
        }
      }
    }
    ts.forEachChild(reference, (child) => { references.push(child); });
  }
  projectCache?.set(symbol, written);
  return written;
}

function unwrapExpression(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (ts.isParenthesizedExpression(current) || ts.isAsExpression(current)
    || ts.isTypeAssertionExpression(current) || ts.isSatisfiesExpression(current)
    || ts.isNonNullExpression(current)) current = current.expression;
  return current;
}

function resolveConstInitializer(
  input: ts.Expression,
  checker: ts.TypeChecker,
  check: () => void,
  projectSources?: ReadonlySet<ts.SourceFile>,
): ts.Expression {
  const seen = new Set<ts.Symbol>();
  let expression = unwrapExpression(input);
  while (ts.isIdentifier(expression)) {
    check();
    let symbol = checker.getSymbolAtLocation(expression);
    if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    if (!symbol || seen.has(symbol)) break;
    seen.add(symbol);
    const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
    const declaration = declarations.length === 1 ? declarations[0] : undefined;
    if (!declaration?.initializer || (projectSources
      && !projectSources.has(declaration.getSourceFile()))
      || !ts.isVariableDeclarationList(declaration.parent)
      || !(declaration.parent.flags & ts.NodeFlags.Const)) break;
    expression = unwrapExpression(declaration.initializer);
  }
  return expression;
}

export function isDefinitelyNonProvidePropertyKey(expression: ts.Expression): boolean {
  const key = unwrapExpression(expression);
  return ts.isPrefixUnaryExpression(key)
    && (key.operator === ts.SyntaxKind.PlusToken || key.operator === ts.SyntaxKind.MinusToken);
}

export function resolveStaticPropertyKey(
  input: ts.Expression,
  checker: ts.TypeChecker,
  check: () => void,
): string | undefined {
  const seen = new Set<ts.Symbol>();
  let current = input;
  while (true) {
    check();
    const expression = unwrapExpression(current);
    if (ts.isStringLiteral(expression)
      || ts.isNoSubstitutionTemplateLiteral(expression)) return expression.text;
    if (ts.isNumericLiteral(expression)) return String(Number(expression.text));
    if (ts.isBigIntLiteral(expression)) return String(BigInt(expression.text.slice(0, -1)));
    if (ts.isPrefixUnaryExpression(expression)
      && (expression.operator === ts.SyntaxKind.PlusToken
        || expression.operator === ts.SyntaxKind.MinusToken)) {
      if (ts.isNumericLiteral(expression.operand)) {
        const value = Number(expression.operand.text);
        return String(expression.operator === ts.SyntaxKind.MinusToken ? -value : value);
      }
      if (ts.isBigIntLiteral(expression.operand)
        && expression.operator === ts.SyntaxKind.MinusToken) {
        return String(-BigInt(expression.operand.text.slice(0, -1)));
      }
      return undefined;
    }
    if (!ts.isIdentifier(expression)) return undefined;
    let symbol = checker.getSymbolAtLocation(expression);
    if (!symbol) return undefined;
    if (symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    if (seen.has(symbol)) return undefined;
    seen.add(symbol);
    const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
    const declaration = declarations.length === 1 ? declarations[0] : undefined;
    if (!declaration?.initializer || !ts.isVariableDeclarationList(declaration.parent)
      || !(declaration.parent.flags & ts.NodeFlags.Const)) return undefined;
    current = declaration.initializer;
  }
}

function isNamespaceImportAccess(expression: ts.Expression, checker: ts.TypeChecker): boolean {
  const callee = unwrapExpression(expression);
  const receiver = ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee)
    ? unwrapExpression(callee.expression)
    : undefined;
  return Boolean(receiver && ts.isIdentifier(receiver)
    && checker.getSymbolAtLocation(receiver)?.declarations?.some(ts.isNamespaceImport));
}

function targetSymbol(
  node: ts.Expression,
  checker: ts.TypeChecker,
  check: () => void,
): ts.Symbol | typeof UNKNOWN_NESTJS_ROUTE | undefined {
  const seen = new Set<ts.Symbol>();
  let current = unwrapExpression(node);
  let selected: ts.Symbol | undefined;
  while (true) {
    check();
    const location = ts.isPropertyAccessExpression(current) ? current.name : current;
    const elementKey = ts.isElementAccessExpression(current) && current.argumentExpression
      ? resolveStaticPropertyKey(current.argumentExpression, checker, check)
      : undefined;
    const symbol = selected ?? (elementKey === undefined
      ? checker.getSymbolAtLocation(location)
      : checker.getTypeAtLocation((current as ts.ElementAccessExpression).expression).getProperty(elementKey));
    selected = undefined;
    if (!symbol) return undefined;
    const target = symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
    if (seen.has(target)) return undefined;
    seen.add(target);
    const alias = target.declarations?.find((declaration): declaration is ts.VariableDeclaration => (
      ts.isVariableDeclaration(declaration)
      && ts.isVariableDeclarationList(declaration.parent)
      && Boolean(declaration.parent.flags & ts.NodeFlags.Const)
      && declaration.initializer !== undefined
    ));
    if (alias?.initializer) {
      const initializer = unwrapExpression(alias.initializer);
      if (!ts.isIdentifier(initializer) && !ts.isPropertyAccessExpression(initializer)
        && !ts.isElementAccessExpression(initializer)) return target;
      current = initializer;
      continue;
    }
    const binding = target.declarations?.find((declaration): declaration is ts.BindingElement => (
      ts.isBindingElement(declaration) && !declaration.dotDotDotToken
      && ts.isObjectBindingPattern(declaration.parent)
      && ts.isVariableDeclaration(declaration.parent.parent)
      && ts.isVariableDeclarationList(declaration.parent.parent.parent)
      && Boolean(declaration.parent.parent.parent.flags & ts.NodeFlags.Const)
      && declaration.parent.parent.initializer !== undefined
    ));
    const property = binding?.propertyName ?? binding?.name;
    if (!binding || !property) return target;
    const initializer = unwrapExpression(binding.parent.parent.initializer!);
    if (ts.isComputedPropertyName(property)) {
      const namespaceType = checker.getTypeAtLocation(initializer);
      return NESTJS_ROUTE_DECORATORS.some((name) => (
        originatesFromNestJsCommon(namespaceType.getProperty(name))
      )) ? UNKNOWN_NESTJS_ROUTE : target;
    }
    if (!ts.isIdentifier(property) && !ts.isStringLiteral(property)) return target;
    selected = checker.getTypeAtLocation(initializer).getProperty(property.text);
    if (!selected) return target;
    current = initializer;
  }
}

function storedDecoratorCall(
  expression: ts.Expression,
  checker: ts.TypeChecker,
  check: () => void,
): ts.CallExpression | undefined {
  const seen = new Set<ts.Symbol>();
  let current = expression;
  while (true) {
    const symbol = targetSymbol(current, checker, check);
    if (!symbol || symbol === UNKNOWN_NESTJS_ROUTE || seen.has(symbol)) return undefined;
    seen.add(symbol);
    const declaration = symbol.declarations?.find((candidate): candidate is (
      ts.VariableDeclaration | ts.PropertyAssignment | ts.ShorthandPropertyAssignment
    ) => (
      (ts.isVariableDeclaration(candidate) || ts.isPropertyAssignment(candidate))
        ? candidate.initializer !== undefined
        : ts.isShorthandPropertyAssignment(candidate)
    ));
    let initializer = declaration && !ts.isShorthandPropertyAssignment(declaration)
      ? declaration.initializer
      : undefined;
    if (declaration && ts.isShorthandPropertyAssignment(declaration)) {
      const valueSymbol = checker.getShorthandAssignmentValueSymbol(declaration);
      initializer = valueSymbol?.declarations?.find((candidate): candidate is ts.VariableDeclaration => (
        ts.isVariableDeclaration(candidate) && candidate.initializer !== undefined
      ))?.initializer;
    }
    const unwrapped = initializer && unwrapExpression(initializer);
    if (!unwrapped) return undefined;
    if (ts.isCallExpression(unwrapped)) return unwrapped;
    if (!ts.isIdentifier(unwrapped) && !ts.isPropertyAccessExpression(unwrapped)) return undefined;
    current = unwrapped;
  }
}

function composesNestJsRoute(
  call: ts.CallExpression,
  checker: ts.TypeChecker,
  check: () => void,
  budget: { remaining: number },
): boolean {
  return call.arguments.some((argument) => {
    check();
    budget.remaining -= 1;
    if (budget.remaining < 0) return true;
    if (ts.isSpreadElement(argument)) return true;
    if (!ts.isCallExpression(argument)) return true;
    const symbol = targetSymbol(argument.expression, checker, check);
    if (!symbol || symbol === UNKNOWN_NESTJS_ROUTE || !originatesFromNestJsCommon(symbol)) return false;
    const name = symbol.getName();
    if (NESTJS_ROUTE_DECORATORS.includes(name as NestJsRouteDecorator)) return true;
    return name === 'applyDecorators' && composesNestJsRoute(argument, checker, check, budget);
  });
}

function importDeclaration(declaration: ts.Declaration): ts.ImportDeclaration | undefined {
  let current: ts.Node | undefined = declaration;
  while (current && !ts.isImportDeclaration(current)) current = current.parent;
  return current;
}

function directNestJsImport(node: ts.Expression, checker: ts.TypeChecker): boolean {
  if (ts.isIdentifier(node)) {
    return Boolean(checker.getSymbolAtLocation(node)?.declarations?.some((declaration) => {
      const imported = importDeclaration(declaration);
      return ts.isImportSpecifier(declaration) && Boolean(imported)
        && ts.isStringLiteral(imported!.moduleSpecifier)
        && imported!.moduleSpecifier.text === '@nestjs/common';
    }));
  }
  if (!ts.isPropertyAccessExpression(node) || !ts.isIdentifier(node.expression)) return false;
  return Boolean(checker.getSymbolAtLocation(node.expression)?.declarations?.some((declaration) => {
    const imported = importDeclaration(declaration);
    return ts.isNamespaceImport(declaration) && Boolean(imported)
      && ts.isStringLiteral(imported!.moduleSpecifier)
      && imported!.moduleSpecifier.text === '@nestjs/common';
  }));
}

function packageRoot(fileName: string, moduleName: string): string | undefined {
  const segments = moduleName.split('/');
  let directory = path.dirname(path.resolve(fileName));
  while (true) {
    let candidate = directory;
    let matches = true;
    for (let index = segments.length - 1; index >= 0; index -= 1) {
      if (path.basename(candidate) !== segments[index]) matches = false;
      candidate = path.dirname(candidate);
    }
    if (matches && path.basename(candidate) === 'node_modules') return directory;
    const parent = path.dirname(directory);
    if (parent === directory) return undefined;
    directory = parent;
  }
}

function originatesFromNestJsCommon(symbol: ts.Symbol | undefined): boolean {
  if (!symbol) return false;
  const cached = NESTJS_ORIGIN_CACHE.get(symbol);
  if (cached !== undefined) return cached;
  const result = Boolean(symbol.declarations?.some((declaration) => {
    const targetRoot = packageRoot(declaration.getSourceFile().fileName, '@nestjs/common');
    if (!targetRoot) return false;
    try {
      const resolvedRoot = packageRoot(
        createRequire(declaration.getSourceFile().fileName).resolve('@nestjs/common'),
        '@nestjs/common',
      );
      return resolvedRoot !== undefined && fs.realpathSync(targetRoot) === fs.realpathSync(resolvedRoot);
    } catch { return false; }
  }));
  NESTJS_ORIGIN_CACHE.set(symbol, result);
  return result;
}

function matchesConsumerModule(
  node: ts.Node,
  symbol: ts.Symbol | undefined,
  moduleName: string,
): boolean {
  let resolvedRoot: string | undefined;
  try {
    resolvedRoot = packageRoot(
      createRequire(node.getSourceFile().fileName).resolve(moduleName),
      moduleName,
    );
  } catch { return false; }
  if (!resolvedRoot) return false;
  return Boolean(symbol?.declarations?.some((declaration) => {
    const targetRoot = packageRoot(declaration.getSourceFile().fileName, moduleName);
    return targetRoot !== undefined && fs.realpathSync(targetRoot) === fs.realpathSync(resolvedRoot);
  }));
}

function matchesConsumerNestJsCommon(node: ts.Expression, symbol: ts.Symbol | undefined): boolean {
  return matchesConsumerModule(node, symbol, '@nestjs/common');
}

function match(
  decorator: ts.Decorator,
  checker: ts.TypeChecker,
  check: () => void,
): { name: NestJsRouteDecoratorCandidate; call: ts.CallExpression; trusted: boolean; nestJsOrigin: boolean } | undefined {
  const expression = unwrapExpression(decorator.expression);
  const storedCall = ts.isCallExpression(expression)
    ? undefined
    : storedDecoratorCall(expression, checker, check);
  const call = ts.isCallExpression(expression) ? expression : storedCall;
  if (!call) return undefined;
  const symbol = targetSymbol(call.expression, checker, check);
  if (symbol === UNKNOWN_NESTJS_ROUTE) {
    return { name: 'Unknown', call, trusted: false, nestJsOrigin: true };
  }
  const name = symbol?.getName();
  if (storedCall && originatesFromNestJsCommon(symbol) && (
    NESTJS_ROUTE_DECORATORS.includes(name as NestJsRouteDecorator)
    || (name === 'applyDecorators' && composesNestJsRoute(
      call, checker, check, { remaining: MAX_COMPOSED_DECORATORS },
    ))
  )) return { name: 'Unknown', call, trusted: false, nestJsOrigin: true };
  if (name === 'applyDecorators' && originatesFromNestJsCommon(symbol)
    && composesNestJsRoute(
      call, checker, check, { remaining: MAX_COMPOSED_DECORATORS },
    )) {
    return { name: 'Unknown', call, trusted: false, nestJsOrigin: true };
  }
  if (!name || !NESTJS_ROUTE_DECORATORS.includes(name as NestJsRouteDecorator)) return undefined;
  const nestJsOrigin = originatesFromNestJsCommon(symbol);
  return {
    name: name as NestJsRouteDecorator,
    call,
    trusted: directNestJsImport(call.expression, checker)
      && matchesConsumerNestJsCommon(call.expression, symbol),
    nestJsOrigin,
  };
}

export function classifyNestJsRouteDecorator(
  decorator: ts.Decorator,
  checker: ts.TypeChecker,
  check: () => void,
): {
    candidate?: { name: NestJsRouteDecoratorCandidate; call: ts.CallExpression; trusted: boolean };
    route?: { name: NestJsRouteDecorator; call: ts.CallExpression };
    unsupported: boolean;
  } {
  const result = match(decorator, checker, check);
  return {
    ...(result?.nestJsOrigin ? {
      candidate: { name: result.name, call: result.call, trusted: result.trusted },
    } : {}),
    ...(result?.trusted && result.name !== 'Unknown' ? {
      route: { name: result.name, call: result.call },
    } : {}),
    unsupported: Boolean(result && (!result.trusted
      || result.name === 'RequestMapping' || result.name === 'Search' || result.name === 'Version')),
  };
}

export function resolveDecoratorSymbol(
  decorator: ts.Decorator,
  checker: ts.TypeChecker,
  check: () => void,
  projectSources?: ReadonlySet<ts.SourceFile>,
): {
  name: string;
  call: ts.CallExpression;
  nestJsCommon: boolean;
  trustedNestJsCommon: boolean;
  indirectInvocation: boolean;
} | undefined {
  const expression = resolveConstInitializer(
    decorator.expression, checker, check, projectSources,
  );
  const call = ts.isCallExpression(expression) ? expression : undefined;
  if (!call) return undefined;
  return resolveDecoratorCallSymbol(call, checker, check);
}

export function resolveBareDecoratorName(
  decorator: ts.Decorator,
  checker: ts.TypeChecker,
  check: () => void,
): string | undefined {
  const expression = unwrapExpression(decorator.expression);
  if (ts.isCallExpression(expression)) return undefined;
  const symbol = targetSymbol(expression, checker, check);
  return !symbol || symbol === UNKNOWN_NESTJS_ROUTE ? undefined : symbol.getName();
}

export function isBareDecoratorBindingStable(
  decorator: ts.Decorator,
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  check: () => void,
): boolean {
  const expression = unwrapExpression(decorator.expression);
  if (ts.isCallExpression(expression)) return false;
  if (ts.isIdentifier(expression)) {
    let bindingExpression: ts.Expression = expression;
    const seen = new Set<ts.Symbol>();
    let binding: ts.BindingElement | undefined;
    while (ts.isIdentifier(bindingExpression)) {
      const symbol = checker.getSymbolAtLocation(bindingExpression);
      if (!symbol || seen.has(symbol)) break;
      seen.add(symbol);
      binding = symbol.declarations
        ?.find((declaration): declaration is ts.BindingElement => ts.isBindingElement(declaration));
      if (binding) break;
      const alias = symbol.declarations?.find((declaration): declaration is ts.VariableDeclaration => (
        ts.isVariableDeclaration(declaration) && declaration.initializer !== undefined
        && ts.isVariableDeclarationList(declaration.parent)
        && Boolean(declaration.parent.flags & ts.NodeFlags.Const)
      ));
      if (!alias) break;
      bindingExpression = unwrapExpression(alias.initializer!);
    }
    if (binding) {
      const declaration = ts.isVariableDeclaration(binding.parent.parent)
        ? binding.parent.parent : undefined;
      const bindingSymbol = ts.isIdentifier(binding.name)
        ? checker.getSymbolAtLocation(binding.name) : undefined;
      if (!declaration || !ts.isVariableDeclarationList(declaration.parent)
        || !(declaration.parent.flags & ts.NodeFlags.Const) || !bindingSymbol
        || callableBindingMayBeWritten(
          bindingSymbol, bindingSymbol.declarations ?? [], checker, projectSources, check,
        )) return false;
      const receiver = declaration?.initializer && unwrapExpression(declaration.initializer);
      if (!receiver) return false;
      const propertyName = binding.propertyName ?? binding.name;
      const key = ts.isIdentifier(propertyName) || ts.isStringLiteral(propertyName)
        ? propertyName.text : undefined;
      const stableObjectProperty = (object: ts.ObjectLiteralExpression): boolean => {
        if (!key || object.properties.some((property) => (
          !ts.isShorthandPropertyAssignment(property)
        ))) return false;
        const properties = object.properties.filter((property): property is (
          ts.ShorthandPropertyAssignment
        ) => (
          ts.isShorthandPropertyAssignment(property)
          && property.name.text === key
        ));
        if (properties.length !== 1) return false;
        const value = checker.getShorthandAssignmentValueSymbol(properties[0]);
        const symbol = value
          ? (value.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(value) : value)
          : undefined;
        return Boolean(symbol && symbol.getName() === key && !callableBindingMayBeWritten(
          symbol, symbol.declarations ?? [], checker, projectSources, check,
        ));
      };
      if (!ts.isObjectLiteralExpression(receiver)) {
        if (!ts.isIdentifier(receiver)) return false;
        const receiverSymbol = checker.getSymbolAtLocation(receiver);
        if (!receiverSymbol) return false;
        const receiverDeclaration = receiverSymbol?.declarations?.find(ts.isVariableDeclaration);
        if (!receiverSymbol.declarations?.some(ts.isNamespaceImport)) {
          if (!receiverDeclaration?.initializer
            || !ts.isObjectLiteralExpression(unwrapExpression(receiverDeclaration.initializer))
            || !stableObjectProperty(unwrapExpression(
              receiverDeclaration.initializer,
            ) as ts.ObjectLiteralExpression)
            || !ts.isVariableDeclarationList(receiverDeclaration.parent)
            || !(receiverDeclaration.parent.flags & ts.NodeFlags.Const)
            || callableBindingMayBeWritten(
              receiverSymbol, receiverSymbol.declarations ?? [], checker, projectSources, check,
            )) return false;
          let cache = BARE_RECEIVER_STABILITY_CACHE.get(projectSources);
          if (!cache) {
            cache = new WeakMap();
            BARE_RECEIVER_STABILITY_CACHE.set(projectSources, cache);
          }
          let isolated = cache.get(receiverSymbol);
          if (isolated === undefined) {
            isolated = true;
            const references: ts.Node[] = [...projectSources];
            while (references.length > 0 && isolated) {
              const reference = references.pop()!;
              check();
              if (ts.isIdentifier(reference) && reference !== receiver
                && reference !== receiverDeclaration.name) {
                let referenceSymbol = checker.getSymbolAtLocation(reference);
                if (referenceSymbol?.flags && referenceSymbol.flags & ts.SymbolFlags.Alias) {
                  referenceSymbol = checker.getAliasedSymbol(referenceSymbol);
                }
                if (referenceSymbol !== receiverSymbol) {
                  ts.forEachChild(reference, (child) => { references.push(child); });
                  continue;
                }
                let usage: ts.Expression = reference;
                while (ts.isParenthesizedExpression(usage.parent)
                  || ts.isAsExpression(usage.parent) || ts.isTypeAssertionExpression(usage.parent)
                  || ts.isSatisfiesExpression(usage.parent) || ts.isNonNullExpression(usage.parent)) {
                  usage = usage.parent;
                }
                const member = (ts.isPropertyAccessExpression(usage.parent)
                  || ts.isElementAccessExpression(usage.parent))
                  && usage.parent.expression === usage ? usage.parent : undefined;
                let memberUsage: ts.Expression | undefined = member;
                while (memberUsage && (ts.isParenthesizedExpression(memberUsage.parent)
                  || ts.isAsExpression(memberUsage.parent)
                  || ts.isTypeAssertionExpression(memberUsage.parent)
                  || ts.isSatisfiesExpression(memberUsage.parent)
                  || ts.isNonNullExpression(memberUsage.parent))) memberUsage = memberUsage.parent;
                let memberUnsafe = false;
                let target: ts.Node | undefined = memberUsage;
                while (target?.parent && !ts.isStatement(target)) {
                  const parent = target.parent;
                  if ((ts.isBinaryExpression(parent) && parent.left === target
                    && parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
                    && parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment)
                    || ((ts.isForOfStatement(parent) || ts.isForInStatement(parent))
                      && parent.initializer === target)
                    || (ts.isDeleteExpression(parent) && parent.expression === target)
                    || ((ts.isPrefixUnaryExpression(parent) || ts.isPostfixUnaryExpression(parent))
                      && parent.operand === target)
                    || (ts.isCallExpression(parent) && parent.expression === target)
                    || (ts.isTaggedTemplateExpression(parent) && parent.tag === target)) {
                    memberUnsafe = true;
                    break;
                  }
                  target = parent;
                }
                const destructuredAgain = ts.isVariableDeclaration(usage.parent)
                  && usage.parent.initializer === usage
                  && ts.isObjectBindingPattern(usage.parent.name);
                if ((!member || memberUnsafe) && !destructuredAgain) isolated = false;
              }
              ts.forEachChild(reference, (child) => { references.push(child); });
            }
            cache.set(receiverSymbol, isolated);
          }
          if (!isolated) return false;
        }
      } else if (!stableObjectProperty(receiver)) {
        return false;
      }
    }
  }
  if ((ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression))
    && !isNamespaceImportAccess(expression, checker)) return false;
  const symbol = targetSymbol(expression, checker, check);
  if (!symbol || symbol === UNKNOWN_NESTJS_ROUTE) return false;
  return !callableBindingMayBeWritten(
    symbol, symbol.declarations ?? [], checker, projectSources, check,
  );
}

export function resolveDecoratorCallSymbol(
  call: ts.CallExpression,
  checker: ts.TypeChecker,
  check: () => void,
): {
  name: string;
  call: ts.CallExpression;
  nestJsCommon: boolean;
  trustedNestJsCommon: boolean;
  indirectInvocation: boolean;
} | undefined {
  let expression = call.expression;
  let indirectInvocation = false;
  while (true) {
    check();
    const callee = unwrapExpression(expression);
    const invocation = ts.isPropertyAccessExpression(callee) ? callee.name.text
      : ts.isElementAccessExpression(callee) && callee.argumentExpression
        ? resolveStaticPropertyKey(callee.argumentExpression, checker, check) : undefined;
    if ((invocation !== 'call' && invocation !== 'apply')
      || (!ts.isPropertyAccessExpression(callee) && !ts.isElementAccessExpression(callee))) break;
    indirectInvocation = true;
    expression = callee.expression;
  }
  const symbol = targetSymbol(expression, checker, check);
  if (!symbol || symbol === UNKNOWN_NESTJS_ROUTE) {
    return !symbol && ts.isElementAccessExpression(unwrapExpression(expression))
      ? {
        name: '', call, nestJsCommon: false, trustedNestJsCommon: false, indirectInvocation,
      }
      : undefined;
  }
  const nestJsCommon = originatesFromNestJsCommon(symbol);
  if (indirectInvocation && (!nestJsCommon
    || (symbol.getName() !== 'UseGuards' && symbol.getName() !== 'applyDecorators'))) return undefined;
  return {
    name: symbol.getName(),
    call,
    nestJsCommon,
    trustedNestJsCommon: !indirectInvocation && nestJsCommon
      && directNestJsImport(expression, checker)
      && matchesConsumerNestJsCommon(expression, symbol),
    indirectInvocation,
  };
}

export function resolveStaticDecoratorWrapperCall(
  call: ts.CallExpression,
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  check: () => void,
): { call?: ts.CallExpression; symbol: ts.Symbol; stable: boolean; dynamic: boolean } | undefined {
  const symbol = targetSymbol(call.expression, checker, check);
  if (!symbol || symbol === UNKNOWN_NESTJS_ROUTE) {
    const callee = unwrapExpression(call.expression);
    const base = ts.isElementAccessExpression(callee)
      ? targetSymbol(callee.expression, checker, check)
      : undefined;
    return base && base !== UNKNOWN_NESTJS_ROUTE && base.declarations?.some((candidate) => (
      projectSources.has(candidate.getSourceFile())
    )) ? { symbol: base, stable: false, dynamic: true } : undefined;
  }
  const declaration = symbol.declarations?.find((candidate): candidate is (
    ts.FunctionDeclaration | ts.VariableDeclaration | ts.PropertyAssignment
  ) => projectSources.has(candidate.getSourceFile()) && (
    (ts.isFunctionDeclaration(candidate) && candidate.body !== undefined)
    || (ts.isVariableDeclaration(candidate) && candidate.initializer !== undefined
      && (ts.isArrowFunction(candidate.initializer) || ts.isFunctionExpression(candidate.initializer)))
    || (ts.isPropertyAssignment(candidate)
      && (ts.isArrowFunction(candidate.initializer) || ts.isFunctionExpression(candidate.initializer)))
  ));
  if (!declaration && symbol.declarations?.some((candidate) => (
    projectSources.has(candidate.getSourceFile())
  ))) return { symbol, stable: false, dynamic: true };
  const implementation = declaration && (ts.isVariableDeclaration(declaration)
    || ts.isPropertyAssignment(declaration))
    ? declaration.initializer
    : declaration;
  if (!implementation || (!ts.isFunctionDeclaration(implementation)
    && !ts.isArrowFunction(implementation) && !ts.isFunctionExpression(implementation))) return undefined;
  const unwrappedCallee = unwrapExpression(call.expression);
  const objectAccess = ts.isPropertyAccessExpression(unwrappedCallee)
    || ts.isElementAccessExpression(unwrappedCallee);
  const stable = Boolean((!objectAccess || isNamespaceImportAccess(unwrappedCallee, checker))
    && declaration && ((ts.isVariableDeclaration(declaration)
      && ts.isVariableDeclarationList(declaration.parent)
      && declaration.parent.flags & ts.NodeFlags.Const)
      || (ts.isFunctionDeclaration(declaration)
        && !callableBindingMayBeWritten(
          symbol, symbol.declarations ?? [], checker, projectSources, check,
        ))));
  const { body } = implementation;
  if (!body) return undefined;
  const resolveReturnedCall = (
    input: ts.Expression,
    resolving: Set<ts.Symbol>,
    depth: number,
  ): { call?: ts.CallExpression; dynamic: boolean } | undefined => {
    check();
    if (depth > 64) return { dynamic: true };
    const expression = unwrapExpression(input);
    if (ts.isCallExpression(expression)) return { call: expression, dynamic: false };
    if (ts.isFunctionLike(expression)) {
      if (!expression.body) return { dynamic: true };
      const nodes: ts.Node[] = [expression.body];
      while (nodes.length > 0) {
        const node = nodes.pop()!;
        check();
        if (ts.isCallExpression(node) || ts.isNewExpression(node)
          || ts.isTaggedTemplateExpression(node)) return { dynamic: true };
        if (node !== expression.body && ts.isFunctionLike(node)) continue;
        ts.forEachChild(node, (child) => { nodes.push(child); });
      }
      return undefined;
    }
    if (ts.isClassLike(expression)) return undefined;
    if (ts.isIdentifier(expression)) {
      const valueSymbol = targetSymbol(expression, checker, check);
      if (!valueSymbol || valueSymbol === UNKNOWN_NESTJS_ROUTE || resolving.has(valueSymbol)) {
        return { dynamic: true };
      }
      const declarations = valueSymbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
      const value = declarations.length === 1 ? declarations[0] : undefined;
      if (!value?.initializer || !projectSources.has(value.getSourceFile())
        || !ts.isVariableDeclarationList(value.parent)
        || !(value.parent.flags & ts.NodeFlags.Const)) return { dynamic: true };
      resolving.add(valueSymbol);
      const resolved = resolveReturnedCall(value.initializer, resolving, depth + 1);
      resolving.delete(valueSymbol);
      return resolved;
    }
    const nodes: ts.Node[] = [expression];
    while (nodes.length > 0) {
      const node = nodes.pop()!;
      check();
      if (ts.isCallExpression(node)) return { dynamic: true };
      if (ts.isFunctionLike(node) || ts.isClassLike(node)) continue;
      ts.forEachChild(node, (child) => { nodes.push(child); });
    }
    return { dynamic: true };
  };
  if (!ts.isBlock(body)) {
    const resolved = resolveReturnedCall(body, new Set(), 0);
    return resolved && { ...resolved, symbol, stable };
  }
  if (body.statements.length === 1 && ts.isReturnStatement(body.statements[0])
    && body.statements[0].expression) {
    const expression = unwrapExpression(body.statements[0].expression);
    if (ts.isCallExpression(expression)) {
      return { call: expression, symbol, stable, dynamic: false };
    }
  }
  return { symbol, stable, dynamic: true };
}

export function resolveStaticSymbolName(
  expression: ts.Expression,
  checker: ts.TypeChecker,
  check: () => void,
  projectSources?: ReadonlySet<ts.SourceFile>,
): string | undefined {
  const reference = unwrapExpression(expression);
  if (projectSources && ts.isIdentifier(reference)) {
    let binding = checker.getSymbolAtLocation(reference);
    if (binding?.flags && binding.flags & ts.SymbolFlags.Alias) binding = checker.getAliasedSymbol(binding);
    if (binding && callableBindingMayBeWritten(
      binding, binding.declarations ?? [], checker, projectSources, check,
    )) return undefined;
  }
  const symbol = targetSymbol(expression, checker, check);
  return !symbol || symbol === UNKNOWN_NESTJS_ROUTE
    || !symbol.declarations?.some(ts.isClassLike) ? undefined : symbol.getName();
}

function isResolvedSymbolFrom(
  symbol: ts.Symbol,
  source: ts.Node,
  moduleName: string,
  importedName: string,
): boolean {
  if (symbol.getName() !== importedName) return false;
  let resolvedRoot: string | undefined;
  try {
    resolvedRoot = packageRoot(
      createRequire(source.getSourceFile().fileName).resolve(moduleName), moduleName,
    );
  } catch { return false; }
  return Boolean(resolvedRoot && symbol.declarations?.some((declaration) => {
    const targetRoot = packageRoot(declaration.getSourceFile().fileName, moduleName);
    return targetRoot !== undefined && fs.realpathSync(targetRoot) === fs.realpathSync(resolvedRoot);
  }));
}

export function isStaticSymbolFrom(
  expression: ts.Expression,
  checker: ts.TypeChecker,
  check: () => void,
  moduleName: string,
  importedName: string,
): boolean {
  const symbol = targetSymbol(expression, checker, check);
  return Boolean(symbol && symbol !== UNKNOWN_NESTJS_ROUTE
    && isResolvedSymbolFrom(symbol, expression, moduleName, importedName));
}

export function containsStaticSymbolFrom(
  expression: ts.Expression,
  checker: ts.TypeChecker,
  check: () => void,
  moduleName: string,
  importedName: string,
  projectSources?: ReadonlySet<ts.SourceFile>,
): boolean {
  const resolving = new Set<ts.Symbol>();
  const resolvingNullish = new Set<ts.Symbol>();
  type Bindings = ReadonlyMap<ts.Symbol, readonly ts.Expression[]>;
  const truthiness = (input: ts.Expression, depth: number, bindings: Bindings): boolean | undefined => {
    check();
    if (depth > 64) return undefined;
    const node = unwrapExpression(input);
    if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
    if (node.kind === ts.SyntaxKind.FalseKeyword || node.kind === ts.SyntaxKind.NullKeyword) return false;
    if (ts.isVoidExpression(node)) return false;
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text.length > 0;
    if (ts.isNumericLiteral(node)) return Number(node.text) !== 0;
    if (ts.isBigIntLiteral(node)) return BigInt(node.text.slice(0, -1)) !== 0n;
    if (ts.isPrefixUnaryExpression(node)) {
      if (ts.isNumericLiteral(node.operand)
        && (node.operator === ts.SyntaxKind.PlusToken || node.operator === ts.SyntaxKind.MinusToken)) {
        return Number(node.operand.text) !== 0;
      }
      if (ts.isBigIntLiteral(node.operand) && node.operator === ts.SyntaxKind.MinusToken) {
        return BigInt(node.operand.text.slice(0, -1)) !== 0n;
      }
    }
    if (ts.isObjectLiteralExpression(node) || ts.isArrayLiteralExpression(node)
      || ts.isFunctionExpression(node) || ts.isArrowFunction(node)
      || ts.isClassExpression(node) || ts.isRegularExpressionLiteral(node)
      || ts.isNewExpression(node)) return true;
    if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.ExclamationToken) {
      const value = truthiness(node.operand, depth + 1, bindings);
      return value === undefined ? undefined : !value;
    }
    if (isStaticSymbolFrom(node, checker, check, moduleName, importedName)) return true;
    if (!ts.isIdentifier(node)) return undefined;
    let symbol = checker.getSymbolAtLocation(node);
    if (!symbol) return undefined;
    if (symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    const bound = bindings.get(symbol);
    if (bound) {
      const values = bound.map((candidate) => truthiness(candidate, depth + 1, bindings));
      return values.length > 0 && values.every((value) => value === values[0])
        ? values[0]
        : undefined;
    }
    if (resolving.has(symbol)) return undefined;
    const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
    const declaration = declarations.length === 1 ? declarations[0] : undefined;
    if (!declaration?.initializer || !ts.isVariableDeclarationList(declaration.parent)
      || !(declaration.parent.flags & ts.NodeFlags.Const)) {
      return node.text === 'undefined' && !symbol.declarations?.length ? false : undefined;
    }
    resolving.add(symbol);
    const result = truthiness(declaration.initializer, depth + 1, bindings);
    resolving.delete(symbol);
    return result;
  };
  const nullishCache = new WeakMap<Bindings, WeakMap<ts.Expression, Map<boolean, boolean | undefined>>>();
  const nullishState = (
    input: ts.Expression,
    includeNull: boolean,
    depth: number,
    bindings: Bindings,
  ): boolean | undefined => {
    let expressions = nullishCache.get(bindings);
    if (!expressions) {
      expressions = new WeakMap();
      nullishCache.set(bindings, expressions);
    }
    let modes = expressions.get(input);
    if (!modes) {
      modes = new Map();
      expressions.set(input, modes);
    }
    if (modes.has(includeNull)) return modes.get(includeNull);
    const result = nullishStateUncached(input, includeNull, depth, bindings);
    modes.set(includeNull, result);
    return result;
  };
  const nullishStateUncached = (
    input: ts.Expression,
    includeNull: boolean,
    depth: number,
    bindings: Bindings,
  ): boolean | undefined => {
    check();
    if (depth > 64) return undefined;
    const node = unwrapExpression(input);
    if (ts.isIdentifier(node)) {
      let symbol = checker.getSymbolAtLocation(node);
      if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
      if (symbol) {
        const bound = bindings.get(symbol);
        if (bound) {
          const states = bound.map((candidate) => (
            nullishState(candidate, includeNull, depth + 1, bindings)
          ));
          return states.length > 0 && states.every((state) => state === states[0])
            ? states[0]
            : undefined;
        }
        if (resolvingNullish.has(symbol)) return undefined;
        const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
        const declaration = declarations.length === 1 ? declarations[0] : undefined;
        if (declaration?.initializer && ts.isVariableDeclarationList(declaration.parent)
          && declaration.parent.flags & ts.NodeFlags.Const) {
          resolvingNullish.add(symbol);
          const result = nullishState(declaration.initializer, includeNull, depth + 1, bindings);
          resolvingNullish.delete(symbol);
          return result;
        }
      }
    }
    const type = checker.getTypeAtLocation(node);
    const mask = ts.TypeFlags.VoidLike | (includeNull ? ts.TypeFlags.Null : 0);
    if (type.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown | ts.TypeFlags.TypeParameter)) {
      return undefined;
    }
    if (type.isUnion()) {
      const hasNullish = type.types.some((part) => Boolean(part.flags & mask));
      return hasNullish
        ? type.types.every((part) => Boolean(part.flags & mask)) || undefined
        : false;
    }
    return Boolean(type.flags & mask);
  };
  const resolutionCache = new WeakMap<Bindings, WeakMap<ts.Expression, boolean>>();
  const maySetObjectPrototype = (expression: ts.Expression): boolean => {
    const type = checker.getTypeAtLocation(expression);
    const definitelyPrimitive = (candidate: ts.Type): boolean => Boolean(candidate.flags & (
      ts.TypeFlags.StringLike | ts.TypeFlags.NumberLike | ts.TypeFlags.BigIntLike
      | ts.TypeFlags.BooleanLike | ts.TypeFlags.ESSymbolLike | ts.TypeFlags.EnumLike
      | ts.TypeFlags.Void | ts.TypeFlags.Null | ts.TypeFlags.Undefined | ts.TypeFlags.Never
    ));
    return type.isUnion()
      ? !type.types.every(definitelyPrimitive)
      : !definitelyPrimitive(type);
  };
  const subtreeContainsTarget = (root: ts.Node): boolean => {
    const nodes: ts.Node[] = [root];
    const seen = new Set<ts.Symbol>();
    while (nodes.length > 0) {
      const node = nodes.pop()!;
      check();
      if (ts.isFunctionLike(node) || ts.isClassLike(node)) continue;
      if ((ts.isIdentifier(node) || ts.isPropertyAccessExpression(node)
        || ts.isElementAccessExpression(node))
        && isStaticSymbolFrom(node, checker, check, moduleName, importedName)) return true;
      if (ts.isIdentifier(node)) {
        let symbol = checker.getSymbolAtLocation(node);
        if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
        if (symbol && !seen.has(symbol)) {
          seen.add(symbol);
          const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
          const declaration = declarations.length === 1 ? declarations[0] : undefined;
          if (declaration?.initializer && ts.isVariableDeclarationList(declaration.parent)
            && declaration.parent.flags & ts.NodeFlags.Const) nodes.push(declaration.initializer);
        }
      }
      ts.forEachChild(node, (child) => { nodes.push(child); });
    }
    return false;
  };
  const deepContainsTarget = (root: ts.Node): boolean => {
    const nodes: ts.Node[] = [root];
    while (nodes.length > 0) {
      const node = nodes.pop()!;
      check();
      if ((ts.isIdentifier(node) || ts.isPropertyAccessExpression(node)
        || ts.isElementAccessExpression(node))
        && isStaticSymbolFrom(node, checker, check, moduleName, importedName)) return true;
      ts.forEachChild(node, (child) => { nodes.push(child); });
    }
    return false;
  };
  const callableUsesThis = (root: ts.Node): boolean => {
    const nodes: ts.Node[] = [root];
    while (nodes.length > 0) {
      const node = nodes.pop()!;
      check();
      if (node !== root && ((ts.isFunctionLike(node) && !ts.isArrowFunction(node))
        || ts.isClassLike(node))) continue;
      if (node.kind === ts.SyntaxKind.ThisKeyword) return true;
      ts.forEachChild(node, (child) => { nodes.push(child); });
    }
    return false;
  };
  const parameterDefaultsMayTarget = (
    parameters: readonly ts.ParameterDeclaration[],
    args: readonly (ts.Expression | undefined)[] | undefined,
    depth: number,
    bindings: Bindings,
  ): boolean => parameters.some((parameter, index) => {
    if (!parameter.initializer || !subtreeContainsTarget(parameter.initializer)) return false;
    if (!args) return true;
    if (args.slice(0, index + 1).some((argument) => argument && ts.isSpreadElement(argument))) {
      return true;
    }
    const argument = args[index];
    if (!argument || ts.isSpreadElement(argument)) return true;
    return nullishState(argument, false, depth + 1, bindings) !== false;
  });
  const resolve = (input: ts.Expression, depth: number, bindings: Bindings): boolean => {
    let expressions = resolutionCache.get(bindings);
    if (!expressions) {
      expressions = new WeakMap();
      resolutionCache.set(bindings, expressions);
    }
    if (expressions.has(input)) return expressions.get(input)!;
    const result = resolveUncached(input, depth, bindings);
    expressions.set(input, result);
    return result;
  };
  type ReturnFlow = {
    target: boolean;
    completes: boolean;
    mayThrow: boolean;
    breaks?: boolean;
    continues?: boolean;
  };
  const expressionMayThrow = (expression: ts.Expression | undefined): boolean => {
    if (!expression) return false;
    const value = unwrapExpression(expression);
    return !(ts.isStringLiteral(value) || ts.isNoSubstitutionTemplateLiteral(value) || ts.isNumericLiteral(value)
      || ts.isBigIntLiteral(value) || ts.isRegularExpressionLiteral(value)
      || value.kind === ts.SyntaxKind.TrueKeyword || value.kind === ts.SyntaxKind.FalseKeyword
      || value.kind === ts.SyntaxKind.NullKeyword);
  };
  const staticSwitchKey = (
    input: ts.Expression,
    switchDepth = 0,
    seen = new Set<ts.Symbol>(),
  ): string | undefined => {
    if (switchDepth > 64) return undefined;
    const value = unwrapExpression(input);
    if (ts.isStringLiteral(value) || ts.isNoSubstitutionTemplateLiteral(value)) return `s:${value.text}`;
    if (ts.isNumericLiteral(value)) return `n:${Number(value.text)}`;
    if (ts.isBigIntLiteral(value)) return `b:${BigInt(value.text.slice(0, -1))}`;
    if (value.kind === ts.SyntaxKind.TrueKeyword) return 'z:true';
    if (value.kind === ts.SyntaxKind.FalseKeyword) return 'z:false';
    if (value.kind === ts.SyntaxKind.NullKeyword) return 'z:null';
    if (ts.isPrefixUnaryExpression(value)
      && (value.operator === ts.SyntaxKind.PlusToken || value.operator === ts.SyntaxKind.MinusToken)
      && ts.isNumericLiteral(value.operand)) {
      const number = Number(value.operand.text);
      return `n:${value.operator === ts.SyntaxKind.MinusToken ? -number : number}`;
    }
    if (!ts.isIdentifier(value)) return undefined;
    let symbol = checker.getSymbolAtLocation(value);
    if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    if (!symbol || seen.has(symbol)) return undefined;
    const declaration = symbol.declarations?.find((candidate): candidate is ts.VariableDeclaration => (
      ts.isVariableDeclaration(candidate) && candidate.initializer !== undefined
      && ts.isVariableDeclarationList(candidate.parent)
      && Boolean(candidate.parent.flags & ts.NodeFlags.Const)
    ));
    if (!declaration?.initializer) return undefined;
    seen.add(symbol);
    return staticSwitchKey(declaration.initializer, switchDepth + 1, seen);
  };
  const callableParametersMayBeWritten = (
    body: ts.ConciseBody,
    parameters: readonly ts.ParameterDeclaration[],
  ): boolean => {
    const parameterSymbols = new Set(parameters.flatMap((parameter) => {
      if (!ts.isIdentifier(parameter.name)) return [];
      const symbol = checker.getSymbolAtLocation(parameter.name);
      return symbol ? [symbol] : [];
    }));
    if (parameterSymbols.size === 0) return false;
    const bodyNodes: ts.Node[] = [];
    ts.forEachChild(body, (child) => { bodyNodes.push(child); });
    while (bodyNodes.length > 0) {
      const child = bodyNodes.pop()!;
      check();
      if (ts.isIdentifier(child) && parameterSymbols.has(checker.getSymbolAtLocation(child)!)) {
        let target: ts.Node = child;
        while (target.parent && !ts.isStatement(target)) {
          const parent = target.parent;
          if (ts.isBinaryExpression(parent) && parent.left === target
            && parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
            && parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment) return true;
          if ((ts.isPrefixUnaryExpression(parent) || ts.isPostfixUnaryExpression(parent))
            && parent.operand === target) return true;
          if ((ts.isForOfStatement(parent) || ts.isForInStatement(parent))
            && parent.initializer === target) return true;
          target = parent;
        }
      }
      ts.forEachChild(child, (descendant) => { bodyNodes.push(descendant); });
    }
    return false;
  };
  const staticallyUnreachable = (
    candidate: ts.Node,
    branchDepth: number,
    branchBindings: Bindings,
  ): boolean => {
    let child = candidate;
    let parent = candidate.parent;
    while (parent) {
      if (ts.isIfStatement(parent)) {
        const condition = truthiness(parent.expression, branchDepth + 1, branchBindings);
        if ((condition === false && child === parent.thenStatement)
          || (condition === true && child === parent.elseStatement)) return true;
      }
      if (ts.isConditionalExpression(parent)) {
        const condition = truthiness(parent.condition, branchDepth + 1, branchBindings);
        if ((condition === false && child === parent.whenTrue)
          || (condition === true && child === parent.whenFalse)) return true;
      }
      if (ts.isWhileStatement(parent) && child === parent.statement
        && truthiness(parent.expression, branchDepth + 1, branchBindings) === false) return true;
      if (ts.isForStatement(parent) && child === parent.statement && parent.condition
        && truthiness(parent.condition, branchDepth + 1, branchBindings) === false) return true;
      child = parent;
      parent = parent.parent;
    }
    return false;
  };
  function statementFlow(
    statement: ts.Statement,
    flowDepth: number,
    callDepth: number,
    localBindings: Bindings,
  ): ReturnFlow {
    check();
    if (flowDepth > 64) return { target: true, completes: true, mayThrow: true };
    if (ts.isReturnStatement(statement)) {
      return {
        target: Boolean(statement.expression
          && resolve(statement.expression, callDepth + 1, localBindings)),
        completes: false,
        mayThrow: expressionMayThrow(statement.expression),
      };
    }
    if (ts.isThrowStatement(statement)) {
      return { target: false, completes: false, mayThrow: true };
    }
    if (ts.isBreakStatement(statement) && !statement.label) {
      return { target: false, completes: false, mayThrow: false, breaks: true };
    }
    if (ts.isContinueStatement(statement) && !statement.label) {
      return { target: false, completes: false, mayThrow: false, continues: true };
    }
    if (ts.isBlock(statement)) {
      return sequenceFlow(statement.statements, flowDepth + 1, callDepth, localBindings);
    }
    if (ts.isIfStatement(statement)) {
      const condition = truthiness(statement.expression, callDepth + 1, localBindings);
      if (condition === true) {
        const selected = statementFlow(statement.thenStatement, flowDepth + 1, callDepth, localBindings);
        return { ...selected, mayThrow: selected.mayThrow || expressionMayThrow(statement.expression) };
      }
      if (condition === false) {
        const selected = statement.elseStatement
          ? statementFlow(statement.elseStatement, flowDepth + 1, callDepth, localBindings)
          : { target: false, completes: true, mayThrow: false };
        return { ...selected, mayThrow: selected.mayThrow || expressionMayThrow(statement.expression) };
      }
      const whenTrue = statementFlow(statement.thenStatement, flowDepth + 1, callDepth, localBindings);
      const whenFalse = statement.elseStatement
        ? statementFlow(statement.elseStatement, flowDepth + 1, callDepth, localBindings)
        : { target: false, completes: true, mayThrow: false };
      return {
        target: whenTrue.target || whenFalse.target,
        completes: whenTrue.completes || whenFalse.completes,
        mayThrow: expressionMayThrow(statement.expression)
          || whenTrue.mayThrow || whenFalse.mayThrow,
        breaks: Boolean(whenTrue.breaks || whenFalse.breaks),
        continues: Boolean(whenTrue.continues || whenFalse.continues),
      };
    }
    if (ts.isWhileStatement(statement)) {
      const condition = truthiness(statement.expression, callDepth + 1, localBindings);
      if (condition === false) {
        return {
          target: false,
          completes: true,
          mayThrow: expressionMayThrow(statement.expression),
        };
      }
    }
    if (ts.isForStatement(statement) && statement.condition) {
      const condition = truthiness(statement.condition, callDepth + 1, localBindings);
      if (condition === false) {
        const initializer = statement.initializer;
        const initializerMayThrow = initializer && ts.isVariableDeclarationList(initializer)
          ? initializer.declarations.some((declaration) => (
            !ts.isIdentifier(declaration.name) || expressionMayThrow(declaration.initializer)
          ))
          : expressionMayThrow(initializer as ts.Expression | undefined);
        return {
          target: false,
          completes: true,
          mayThrow: initializerMayThrow || expressionMayThrow(statement.condition),
        };
      }
    }
    if (ts.isForOfStatement(statement)) {
      const iterable = unwrapExpression(statement.expression);
      const values = ts.isArrayLiteralExpression(iterable)
        && iterable.elements.every((element) => (
          !ts.isSpreadElement(element) && !ts.isOmittedExpression(element)
        )) ? iterable.elements as readonly ts.Expression[] : undefined;
      const declaration = ts.isVariableDeclarationList(statement.initializer)
        && statement.initializer.declarations.length === 1
        ? statement.initializer.declarations[0] : undefined;
      const name = declaration && ts.isIdentifier(declaration.name) ? declaration.name
        : ts.isIdentifier(statement.initializer) ? statement.initializer : undefined;
      const symbol = name && checker.getSymbolAtLocation(name);
      if (values && symbol) {
        let target = false;
        let completes = false;
        let mayThrow = false;
        for (const value of values) {
          const iterationBindings = new Map(localBindings);
          iterationBindings.set(symbol, [value]);
          const flow = statementFlow(statement.statement, flowDepth + 1, callDepth, iterationBindings);
          target ||= flow.target;
          completes ||= Boolean(flow.breaks);
          mayThrow ||= flow.mayThrow;
          if (!flow.completes && !flow.continues) {
            return { target, completes, mayThrow };
          }
        }
        return { target, completes: true, mayThrow: true };
      }
    }
    if (ts.isSwitchStatement(statement)) {
      const selected = staticSwitchKey(statement.expression);
      if (selected !== undefined) {
        let start = statement.caseBlock.clauses.findIndex((clause) => (
          ts.isCaseClause(clause) && staticSwitchKey(clause.expression) === selected
        ));
        if (start < 0) start = statement.caseBlock.clauses.findIndex(ts.isDefaultClause);
        if (start < 0) return { target: false, completes: true, mayThrow: true };
        let target = false;
        let breaks = false;
        let continues = false;
        let mayThrow = false;
        for (const clause of statement.caseBlock.clauses.slice(start)) {
          for (const child of clause.statements) {
            const flow = statementFlow(child, flowDepth + 1, callDepth, localBindings);
            target ||= flow.target;
            breaks ||= Boolean(flow.breaks);
            continues ||= Boolean(flow.continues);
            mayThrow ||= flow.mayThrow;
            if (!flow.completes) return {
              target,
              completes: breaks,
              mayThrow,
              continues,
            };
          }
        }
        return { target, completes: true, mayThrow: true, continues };
      }
    }
    if (ts.isTryStatement(statement)) {
      const attempted = statementFlow(statement.tryBlock, flowDepth + 1, callDepth, localBindings);
      const caught = statement.catchClause && attempted.mayThrow
        ? statementFlow(statement.catchClause.block, flowDepth + 1, callDepth, localBindings)
        : { target: false, completes: false, mayThrow: false };
      const beforeFinally = {
        target: attempted.target || caught.target,
        completes: attempted.completes || caught.completes,
        mayThrow: statement.catchClause ? caught.mayThrow : attempted.mayThrow,
        breaks: Boolean(attempted.breaks || caught.breaks),
        continues: Boolean(attempted.continues || caught.continues),
      };
      if (!statement.finallyBlock) return beforeFinally;
      const finalized = statementFlow(statement.finallyBlock, flowDepth + 1, callDepth, localBindings);
      return finalized.completes
        ? {
          target: beforeFinally.target || finalized.target,
          completes: beforeFinally.completes,
          mayThrow: beforeFinally.mayThrow || finalized.mayThrow,
          breaks: Boolean(beforeFinally.breaks || finalized.breaks),
          continues: Boolean(beforeFinally.continues || finalized.continues),
        }
        : finalized;
    }
    if (ts.isFunctionLike(statement) || ts.isClassLike(statement)) {
      return { target: false, completes: true, mayThrow: false };
    }
    let target = false;
    const nested: ts.Node[] = [];
    ts.forEachChild(statement, (child) => { nested.push(child); });
    while (nested.length > 0) {
      const child = nested.pop()!;
      check();
      if (ts.isFunctionLike(child) || ts.isClassLike(child)) continue;
      if (ts.isReturnStatement(child)) {
        target ||= Boolean(child.expression
          && resolve(child.expression, callDepth + 1, localBindings));
        continue;
      }
      ts.forEachChild(child, (descendant) => { nested.push(descendant); });
    }
    return { target, completes: true, mayThrow: true };
  }
  function sequenceFlow(
    statements: readonly ts.Statement[],
    flowDepth: number,
    callDepth: number,
    localBindings: Bindings,
  ): ReturnFlow {
    if (flowDepth > 64) return { target: true, completes: true, mayThrow: true };
    let target = false;
    let completes = true;
    let mayThrow = false;
    let breaks = false;
    let continues = false;
    for (const statement of statements) {
      if (!completes) break;
      const flow = statementFlow(statement, flowDepth + 1, callDepth, localBindings);
      target ||= flow.target;
      completes = flow.completes;
      mayThrow ||= flow.mayThrow;
      breaks ||= Boolean(flow.breaks);
      continues ||= Boolean(flow.continues);
    }
    return { target, completes, mayThrow, breaks, continues };
  }
  const resolveUncached = (input: ts.Expression, depth: number, bindings: Bindings): boolean => {
    check();
    if (depth > 64) return true;
    const node = unwrapExpression(input);
    if (isStaticSymbolFrom(node, checker, check, moduleName, importedName)) return true;
    if (ts.isAwaitExpression(node)) {
      const awaited = unwrapExpression(node.expression);
      if (ts.isCallExpression(awaited) && ts.isIdentifier(unwrapExpression(awaited.expression))) {
        const callee = unwrapExpression(awaited.expression) as ts.Identifier;
        let symbol = checker.getSymbolAtLocation(callee);
        if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
        const declarations = symbol?.declarations ?? [];
        const localDeclarations = projectSources
          ? declarations.filter((candidate) => projectSources.has(candidate.getSourceFile())) : [];
        const functionDeclarations = localDeclarations.filter(
          (candidate): candidate is ts.FunctionDeclaration => (
            ts.isFunctionDeclaration(candidate) && candidate.body !== undefined
          ),
        );
        const functionDeclaration = functionDeclarations.length === 1 ? functionDeclarations[0] : undefined;
        const variableDeclarations = localDeclarations.filter(ts.isVariableDeclaration);
        const variableDeclaration = variableDeclarations.length === 1 ? variableDeclarations[0] : undefined;
        const variableInitializer = variableDeclaration?.initializer
          && ts.isVariableDeclarationList(variableDeclaration.parent)
          && variableDeclaration.parent.flags & ts.NodeFlags.Const
          ? unwrapExpression(variableDeclaration.initializer) : undefined;
        if (symbol && functionDeclaration
          && callableBindingMayBeWritten(symbol, declarations, checker, projectSources, check)) return true;
        if (!functionDeclaration && variableDeclaration && !variableInitializer) return true;
        const callable = functionDeclaration ?? variableInitializer;
        if (callable && (ts.isFunctionDeclaration(callable)
          || ts.isFunctionExpression(callable) || ts.isArrowFunction(callable))
          && callable.body
          && callable.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword)
          && !((ts.isFunctionDeclaration(callable) || ts.isFunctionExpression(callable))
            && callable.asteriskToken)) {
          const callableBody = callable.body;
          if (awaited.arguments.some(ts.isSpreadElement)
            || callable.parameters.some((parameter) => (
              !ts.isIdentifier(parameter.name) || Boolean(parameter.dotDotDotToken)
            ))) return deepContainsTarget(callableBody)
              || callable.parameters.some((parameter) => Boolean(
                parameter.initializer && subtreeContainsTarget(parameter.initializer),
              ))
              || awaited.arguments.some((argument) => subtreeContainsTarget(
                ts.isSpreadElement(argument) ? argument.expression : argument,
              ));
          if (parameterDefaultsMayTarget(
            callable.parameters, awaited.arguments, depth, bindings,
          )) return true;
          if (callableParametersMayBeWritten(callableBody, callable.parameters)) return true;
          const awaitedBindings = new Map(bindings);
          for (let index = 0; index < callable.parameters.length; index += 1) {
            const parameter = callable.parameters[index];
            const parameterSymbol = checker.getSymbolAtLocation(parameter.name);
            const argument = awaited.arguments[index];
            if (!parameterSymbol) continue;
            if (!argument) {
              if (parameter.initializer) awaitedBindings.set(parameterSymbol, [parameter.initializer]);
              continue;
            }
            if (!parameter.initializer) {
              awaitedBindings.set(parameterSymbol, [argument]);
              continue;
            }
            const state = nullishState(argument, false, depth + 1, bindings);
            awaitedBindings.set(parameterSymbol, state === true
              ? [parameter.initializer]
              : state === false ? [argument] : [argument, parameter.initializer]);
          }
          return ts.isBlock(callableBody)
            ? sequenceFlow(callableBody.statements, 0, depth, awaitedBindings).target
            : resolve(callableBody, depth + 1, awaitedBindings);
        }
      }
      return resolve(node.expression, depth + 1, bindings) || deepContainsTarget(node.expression);
    }
    if (ts.isTaggedTemplateExpression(node)) {
      if (ts.isTemplateExpression(node.template)
        && node.template.templateSpans.some((span) => resolve(
          span.expression, depth + 1, bindings,
        ))) return true;
      const tag = unwrapExpression(node.tag);
      if (!ts.isIdentifier(tag)) {
        if (ts.isPropertyAccessExpression(tag) || ts.isElementAccessExpression(tag)) {
          const receiver = unwrapExpression(tag.expression);
          if (ts.isIdentifier(receiver)) {
            let receiverSymbol = checker.getSymbolAtLocation(receiver);
            if (receiverSymbol?.flags && receiverSymbol.flags & ts.SymbolFlags.Alias) {
              receiverSymbol = checker.getAliasedSymbol(receiverSymbol);
            }
            if (receiverSymbol?.declarations?.some((candidate) => (
              projectSources?.has(candidate.getSourceFile())
            ))) return true;
          }
        }
        return deepContainsTarget(tag);
      }
      let symbol = checker.getSymbolAtLocation(tag);
      if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
      const declaration = symbol?.declarations?.find((candidate): candidate is (
        ts.FunctionDeclaration | ts.VariableDeclaration
      ) => (ts.isFunctionDeclaration(candidate) && candidate.body !== undefined)
        || (ts.isVariableDeclaration(candidate) && candidate.initializer !== undefined));
      const callable = declaration && ts.isFunctionDeclaration(declaration) ? declaration
        : declaration && ts.isVariableDeclaration(declaration)
          ? unwrapExpression(declaration.initializer!) : undefined;
      if (!callable || (!ts.isFunctionDeclaration(callable)
        && !ts.isFunctionExpression(callable) && !ts.isArrowFunction(callable))) return false;
      if (callable.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword)
        || ((ts.isFunctionDeclaration(callable) || ts.isFunctionExpression(callable))
          && callable.asteriskToken)) return false;
      const tagArguments: ts.Expression[] = [node.template as ts.Expression];
      if (ts.isTemplateExpression(node.template)) {
        tagArguments.push(...node.template.templateSpans.map((span) => span.expression));
      }
      if (parameterDefaultsMayTarget(callable.parameters, tagArguments, depth, bindings)) return true;
      const tagBindings = new Map(bindings);
      for (let index = 0; index < callable.parameters.length; index += 1) {
        const parameter = callable.parameters[index];
        if (!ts.isIdentifier(parameter.name) || parameter.dotDotDotToken) {
          return Boolean(callable.body && deepContainsTarget(callable.body));
        }
        const symbol = checker.getSymbolAtLocation(parameter.name);
        if (!symbol) continue;
        const argument = tagArguments[index];
        if (argument) tagBindings.set(symbol, [argument]);
        else if (parameter.initializer) tagBindings.set(symbol, [parameter.initializer]);
      }
      if (!callable.body) return false;
      if (callableParametersMayBeWritten(callable.body, callable.parameters)) return true;
      if (!ts.isBlock(callable.body)) return resolve(callable.body, depth + 1, tagBindings);
      return sequenceFlow(callable.body.statements, 0, depth, tagBindings).target;
    }
    if (ts.isConditionalExpression(node)) {
      const condition = truthiness(node.condition, depth + 1, bindings);
      return condition === true
        ? resolve(node.whenTrue, depth + 1, bindings)
        : condition === false
          ? resolve(node.whenFalse, depth + 1, bindings)
          : resolve(node.whenTrue, depth + 1, bindings)
            || resolve(node.whenFalse, depth + 1, bindings);
    }
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const staticKey = ts.isPropertyAccessExpression(node)
        ? node.name.text
        : node.argumentExpression
          ? resolveStaticPropertyKey(node.argumentExpression, checker, check)
          : undefined;
      const memberSymbol = (member: ts.PropertyAccessExpression | ts.ElementAccessExpression) => {
        const key = ts.isPropertyAccessExpression(member)
          ? member.name.text
          : member.argumentExpression
            ? resolveStaticPropertyKey(member.argumentExpression, checker, check)
            : undefined;
        return key === undefined
          ? undefined
          : checker.getTypeAtLocation(member.expression).getProperty(key);
      };
      const receiver = unwrapExpression(node.expression);
      if (staticKey === undefined) {
        const dynamicArrayTarget = (array: ts.ArrayLiteralExpression, arrayDepth: number): boolean => {
          if (arrayDepth > 64) return true;
          for (const element of array.elements) {
            check();
            if (ts.isOmittedExpression(element)) continue;
            if (!ts.isSpreadElement(element)) {
              if (resolve(element, depth + 1, bindings)) return true;
              continue;
            }
            const spread = unwrapExpression(element.expression);
            if (!ts.isArrayLiteralExpression(spread) || dynamicArrayTarget(spread, arrayDepth + 1)) {
              return true;
            }
          }
          return false;
        };
        const dynamicObjectTarget = (object: ts.ObjectLiteralExpression): boolean => {
          const values = new Map<string, ts.Expression | undefined>();
          for (const property of object.properties) {
            check();
            if (ts.isGetAccessorDeclaration(property) || ts.isSpreadAssignment(property)) return true;
            const name = property.name;
            const key = ts.isComputedPropertyName(name)
              ? resolveStaticPropertyKey(name.expression, checker, check)
              : ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)
                ? name.text : undefined;
            if (key === undefined) return true;
            if (key === '__proto__' && ts.isPropertyAssignment(property)
              && !ts.isComputedPropertyName(name)) {
              if (maySetObjectPrototype(property.initializer)) return true;
              continue;
            }
            values.set(key, ts.isPropertyAssignment(property) ? property.initializer
              : ts.isShorthandPropertyAssignment(property) ? property.name : undefined);
          }
          return [...values.values()].some((value) => Boolean(
            value && resolve(value, depth + 1, bindings),
          ));
        };
        if (ts.isIdentifier(receiver)) {
          let receiverSymbol = checker.getSymbolAtLocation(receiver);
          if (receiverSymbol?.flags && receiverSymbol.flags & ts.SymbolFlags.Alias) {
            receiverSymbol = checker.getAliasedSymbol(receiverSymbol);
          }
          const declarations = receiverSymbol?.declarations?.filter(ts.isVariableDeclaration) ?? [];
          const declaration = declarations.length === 1 ? declarations[0] : undefined;
          const initializer = declaration?.initializer && ts.isVariableDeclarationList(declaration.parent)
            && declaration.parent.flags & ts.NodeFlags.Const
            ? unwrapExpression(declaration.initializer) : undefined;
          if (!receiverSymbol || !initializer || !ts.isObjectLiteralExpression(initializer)) return true;
          let unsafeReference = false;
          const references: ts.Node[] = projectSources ? [...projectSources] : [];
          while (references.length > 0 && !unsafeReference) {
            check();
            const reference = references.pop()!;
            if (ts.isIdentifier(reference)) {
              let referenceSymbol = checker.getSymbolAtLocation(reference);
              if (referenceSymbol?.flags && referenceSymbol.flags & ts.SymbolFlags.Alias) {
                referenceSymbol = checker.getAliasedSymbol(referenceSymbol);
              }
              if (referenceSymbol === receiverSymbol && reference !== declaration?.name
                && reference !== receiver) {
                const member = (ts.isPropertyAccessExpression(reference.parent)
                  || ts.isElementAccessExpression(reference.parent))
                  && reference.parent.expression === reference ? reference.parent : undefined;
                if (!member || (ts.isBinaryExpression(member.parent) && member.parent.left === member)) {
                  unsafeReference = true;
                }
              }
            }
            ts.forEachChild(reference, (child) => { references.push(child); });
          }
          if (unsafeReference) return true;
          return dynamicObjectTarget(initializer);
        }
        if (ts.isArrayLiteralExpression(receiver)) return dynamicArrayTarget(receiver, 0);
        if (ts.isObjectLiteralExpression(receiver)) return dynamicObjectTarget(receiver);
        return true;
      }
      if (ts.isArrayLiteralExpression(receiver) && staticKey !== undefined
        && /^(0|[1-9]\d*)$/.test(staticKey)) {
        const index = Number(staticKey);
        const flatten = (
          array: ts.ArrayLiteralExpression,
          flattenDepth: number,
        ): Array<ts.Expression | undefined> | undefined => {
          if (flattenDepth > 64) return undefined;
          const values: Array<ts.Expression | undefined> = [];
          for (const element of array.elements) {
            check();
            if (ts.isOmittedExpression(element)) {
              values.push(undefined);
              continue;
            }
            if (!ts.isSpreadElement(element)) {
              values.push(element);
              continue;
            }
            const spread = unwrapExpression(element.expression);
            if (!ts.isArrayLiteralExpression(spread)) return undefined;
            const spreadValues = flatten(spread, flattenDepth + 1);
            if (!spreadValues) return undefined;
            values.push(...spreadValues);
          }
          return values;
        };
        const values = flatten(receiver, 0);
        if (!values) return true;
        const value = values[index];
        return Boolean(value && resolve(value, depth + 1, bindings));
      }
      if (ts.isIdentifier(receiver) && staticKey !== undefined && /^(0|[1-9]\d*)$/.test(staticKey)) {
        let receiverArraySymbol = checker.getSymbolAtLocation(receiver);
        if (receiverArraySymbol?.flags && receiverArraySymbol.flags & ts.SymbolFlags.Alias) {
          receiverArraySymbol = checker.getAliasedSymbol(receiverArraySymbol);
        }
        const declarations = receiverArraySymbol?.declarations?.filter(ts.isVariableDeclaration) ?? [];
        const declaration = declarations.length === 1 ? declarations[0] : undefined;
        if (declaration?.initializer && ts.isVariableDeclarationList(declaration.parent)
          && declaration.parent.flags & ts.NodeFlags.Const
          && ts.isArrayLiteralExpression(unwrapExpression(declaration.initializer))) {
          let escaped = false;
          const references: ts.Node[] = projectSources ? [...projectSources] : [];
          while (references.length > 0 && !escaped) {
            check();
            const reference = references.pop()!;
            if (ts.isIdentifier(reference)) {
              let referenceSymbol = checker.getSymbolAtLocation(reference);
              if (referenceSymbol?.flags && referenceSymbol.flags & ts.SymbolFlags.Alias) {
                referenceSymbol = checker.getAliasedSymbol(referenceSymbol);
              }
              if (referenceSymbol === receiverArraySymbol && reference !== declaration.name
                && reference !== receiver) {
                const member = (ts.isPropertyAccessExpression(reference.parent)
                  || ts.isElementAccessExpression(reference.parent))
                  && reference.parent.expression === reference ? reference.parent : undefined;
                const memberKey = member && (ts.isPropertyAccessExpression(member)
                  ? member.name.text : member.argumentExpression
                    ? resolveStaticPropertyKey(member.argumentExpression, checker, check) : undefined);
                let written = false;
                let invocationUsage: ts.Expression | undefined = member;
                while (invocationUsage && (ts.isParenthesizedExpression(invocationUsage.parent)
                  || ts.isAsExpression(invocationUsage.parent)
                  || ts.isTypeAssertionExpression(invocationUsage.parent)
                  || ts.isSatisfiesExpression(invocationUsage.parent)
                  || ts.isNonNullExpression(invocationUsage.parent))
                  && invocationUsage.parent.expression === invocationUsage) {
                  invocationUsage = invocationUsage.parent;
                }
                const invoked = Boolean(invocationUsage
                  && ((ts.isCallExpression(invocationUsage.parent)
                    && invocationUsage.parent.expression === invocationUsage)
                    || (ts.isTaggedTemplateExpression(invocationUsage.parent)
                      && invocationUsage.parent.tag === invocationUsage)));
                let target: ts.Node | undefined = member;
                while (target?.parent && !ts.isStatement(target)) {
                  const parent = target.parent;
                  if (ts.isBinaryExpression(parent) && parent.left === target
                    && parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
                    && parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
                    written = true;
                    break;
                  }
                  if ((ts.isForOfStatement(parent) || ts.isForInStatement(parent))
                    && parent.initializer === target) {
                    written = true;
                    break;
                  }
                  target = parent;
                }
                if (!member || memberKey === undefined || !/^(0|[1-9]\d*)$/.test(memberKey)
                  || written || invoked) {
                  escaped = true;
                }
              }
            }
            ts.forEachChild(reference, (child) => { references.push(child); });
          }
          if (escaped) return true;
          const array = unwrapExpression(declaration.initializer);
          const flattenArray = (
            input: ts.ArrayLiteralExpression,
            flattenDepth: number,
          ): Array<ts.Expression | undefined> | undefined => {
            if (flattenDepth > 64) return undefined;
            const result: Array<ts.Expression | undefined> = [];
            for (const candidate of input.elements) {
              check();
              if (ts.isOmittedExpression(candidate)) {
                result.push(undefined);
              } else if (!ts.isSpreadElement(candidate)) {
                result.push(candidate);
              } else {
                const spread = unwrapExpression(candidate.expression);
                if (!ts.isArrayLiteralExpression(spread)) return undefined;
                const values = flattenArray(spread, flattenDepth + 1);
                if (!values) return undefined;
                result.push(...values);
              }
            }
            return result;
          };
          if (!ts.isArrayLiteralExpression(array)) return true;
          const values = flattenArray(array, 0);
          if (!values) return true;
          const value = values[Number(staticKey)];
          return Boolean(value && resolve(value, depth + 1, bindings));
        }
      }
      const symbol = memberSymbol(node);
      let receiverSymbol = ts.isIdentifier(receiver)
        ? checker.getSymbolAtLocation(receiver)
        : ts.isPropertyAccessExpression(receiver) || ts.isElementAccessExpression(receiver)
          ? memberSymbol(receiver)
          : undefined;
      if (!receiverSymbol && (ts.isFunctionExpression(receiver) || ts.isArrowFunction(receiver))) {
        return false;
      }
      if (!receiverSymbol && !ts.isIdentifier(receiver) && !ts.isObjectLiteralExpression(receiver)) {
        return true;
      }
      if (receiverSymbol?.flags && receiverSymbol.flags & ts.SymbolFlags.Alias) {
        receiverSymbol = checker.getAliasedSymbol(receiverSymbol);
      }
      const receiverDeclaration = receiverSymbol?.declarations?.filter(ts.isVariableDeclaration);
      const receiverVariable = receiverDeclaration?.length === 1 ? receiverDeclaration[0] : undefined;
      const receiverObject = ts.isObjectLiteralExpression(receiver) ? receiver
        : receiverVariable?.initializer
          && ts.isVariableDeclarationList(receiverVariable.parent)
          && receiverVariable.parent.flags & ts.NodeFlags.Const
          && ts.isObjectLiteralExpression(unwrapExpression(receiverVariable.initializer))
          ? unwrapExpression(receiverVariable.initializer) as ts.ObjectLiteralExpression : undefined;
      const objectProperty = (key: string | undefined) => {
        if (key === undefined || !receiverObject) return undefined;
        let result: ts.PropertyAssignment | ts.ShorthandPropertyAssignment | null | undefined;
        for (const candidate of receiverObject.properties) {
          if (ts.isSpreadAssignment(candidate)) {
            result = null;
            continue;
          }
          const name = candidate.name;
          const propertyKey = ts.isComputedPropertyName(name)
            ? resolveStaticPropertyKey(name.expression, checker, check)
            : ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)
              ? name.text : undefined;
          if (propertyKey === '__proto__' && ts.isPropertyAssignment(candidate)
            && !ts.isComputedPropertyName(name)) {
            if (maySetObjectPrototype(candidate.initializer)) result = null;
            continue;
          }
          if (propertyKey === undefined) {
            if (ts.isComputedPropertyName(name)) result = null;
            continue;
          }
          if (propertyKey !== key) continue;
          result = ts.isPropertyAssignment(candidate) || ts.isShorthandPropertyAssignment(candidate)
            ? candidate : null;
        }
        return result;
      };
      const runtimeProperty = objectProperty(staticKey);
      if (runtimeProperty === null) return true;
      if (!symbol) {
        if (runtimeProperty && ts.isPropertyAssignment(runtimeProperty)) {
          return resolve(runtimeProperty.initializer, depth + 1, bindings);
        }
        if (runtimeProperty && ts.isShorthandPropertyAssignment(runtimeProperty)) {
          return resolve(runtimeProperty.name, depth + 1, bindings);
        }
        if (receiverVariable?.initializer
          && !ts.isObjectLiteralExpression(unwrapExpression(receiverVariable.initializer))
          && !ts.isArrayLiteralExpression(unwrapExpression(receiverVariable.initializer))) return true;
        return false;
      }
      if (resolving.has(symbol)) return true;
      let wrappedReceivers = projectSources && WRAPPED_RECEIVER_CACHE.get(projectSources);
      if (receiverSymbol && projectSources && !wrappedReceivers) {
        const receivers = new Set<ts.Symbol>();
        const candidates: ts.Node[] = [...projectSources];
        while (candidates.length > 0) {
          check();
          const candidate = candidates.pop()!;
          if (ts.isObjectLiteralExpression(candidate)) {
            const properties = new Map<string, ts.ObjectLiteralElementLike>();
            for (const property of candidate.properties) {
              if (ts.isSpreadAssignment(property)) continue;
              const name = property.name;
              const key = ts.isComputedPropertyName(name)
                ? resolveStaticPropertyKey(name.expression, checker, check)
                : ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)
                  ? name.text : undefined;
              if (key !== undefined) properties.set(key, property);
            }
            for (const property of properties.values()) {
              const value = ts.isShorthandPropertyAssignment(property) ? property.name
                : ts.isPropertyAssignment(property) ? unwrapExpression(property.initializer) : undefined;
              if (!value || !ts.isIdentifier(value)) continue;
              let valueSymbol = ts.isShorthandPropertyAssignment(property)
                ? checker.getShorthandAssignmentValueSymbol(property)
                : checker.getSymbolAtLocation(value);
              if (valueSymbol?.flags && valueSymbol.flags & ts.SymbolFlags.Alias) {
                valueSymbol = checker.getAliasedSymbol(valueSymbol);
              }
              if (valueSymbol) receivers.add(valueSymbol);
            }
          }
          ts.forEachChild(candidate, (child) => { candidates.push(child); });
        }
        wrappedReceivers = receivers;
        WRAPPED_RECEIVER_CACHE.set(projectSources, receivers);
      }
      if (receiverSymbol && projectSources && wrappedReceivers?.has(receiverSymbol)) {
        let wrapperMutationCache = WRAPPER_MUTATION_CACHE.get(projectSources);
        if (!wrapperMutationCache) {
          wrapperMutationCache = new WeakMap<ts.Symbol, boolean>();
          WRAPPER_MUTATION_CACHE.set(projectSources, wrapperMutationCache);
        }
        const cachedWrapperMutation = wrapperMutationCache.get(receiverSymbol);
        if (cachedWrapperMutation) return true;
        if (cachedWrapperMutation === undefined) {
        const wrapperAliases = new Set<ts.Symbol>();
        const valueAliasesReceiver = (value: ts.Expression): boolean => {
          const expression = unwrapExpression(value);
          if (!ts.isIdentifier(expression)) return false;
          let valueSymbol = checker.getSymbolAtLocation(expression);
          if (valueSymbol?.flags && valueSymbol.flags & ts.SymbolFlags.Alias) {
            valueSymbol = checker.getAliasedSymbol(valueSymbol);
          }
          return valueSymbol === receiverSymbol;
        };
        const objectPropertyAliasesReceiver = (
          object: ts.ObjectLiteralExpression,
          key: string,
        ): boolean | undefined => {
          let selected: ts.ObjectLiteralElementLike | null | undefined;
          for (const property of object.properties) {
            check();
            if (ts.isSpreadAssignment(property)) {
              selected = null;
              continue;
            }
            const name = property.name;
            const propertyKey = ts.isComputedPropertyName(name)
              ? resolveStaticPropertyKey(name.expression, checker, check)
              : ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)
                ? name.text : undefined;
            if (propertyKey === undefined) {
              if (ts.isComputedPropertyName(name)) selected = null;
              continue;
            }
            if (propertyKey === key) selected = property;
          }
          if (selected === null) return undefined;
          if (!selected) return false;
          const value = ts.isShorthandPropertyAssignment(selected) ? selected.name
            : ts.isPropertyAssignment(selected) ? selected.initializer : undefined;
          return Boolean(value && valueAliasesReceiver(value));
        };
        const objectForSymbol = (candidate: ts.Symbol): ts.ObjectLiteralExpression | undefined => {
          const declarations = candidate.declarations?.filter(ts.isVariableDeclaration) ?? [];
          const declaration = declarations.length === 1 ? declarations[0] : undefined;
          const initializer = declaration?.initializer && ts.isVariableDeclarationList(declaration.parent)
            && declaration.parent.flags & ts.NodeFlags.Const
            ? unwrapExpression(declaration.initializer) : undefined;
          return initializer && ts.isObjectLiteralExpression(initializer) ? initializer : undefined;
        };
        const memberAliasesReceiver = (input: ts.Expression): boolean => {
          let member = unwrapExpression(input);
          while (ts.isPropertyAccessExpression(member) || ts.isElementAccessExpression(member)) {
            check();
            const base = unwrapExpression(member.expression);
            if (ts.isIdentifier(base)) {
              let baseSymbol = checker.getSymbolAtLocation(base);
              if (baseSymbol?.flags && baseSymbol.flags & ts.SymbolFlags.Alias) {
                baseSymbol = checker.getAliasedSymbol(baseSymbol);
              }
              if (baseSymbol && wrapperAliases.has(baseSymbol)) {
                const key = ts.isPropertyAccessExpression(member) ? member.name.text
                  : member.argumentExpression
                    ? resolveStaticPropertyKey(member.argumentExpression, checker, check) : undefined;
                if (key === undefined) return true;
                const object = objectForSymbol(baseSymbol);
                if (!object) return true;
                return objectPropertyAliasesReceiver(object, key) !== false;
              }
            }
            const propertySymbol = memberSymbol(member);
            const matches = propertySymbol?.declarations?.some((property) => {
              const value = ts.isShorthandPropertyAssignment(property) ? property.name
                : ts.isPropertyAssignment(property) ? unwrapExpression(property.initializer) : undefined;
              if (!value || !ts.isIdentifier(value)) return false;
              let valueSymbol = ts.isShorthandPropertyAssignment(property)
                ? checker.getShorthandAssignmentValueSymbol(property)
                : checker.getSymbolAtLocation(value);
              if (valueSymbol?.flags && valueSymbol.flags & ts.SymbolFlags.Alias) {
                valueSymbol = checker.getAliasedSymbol(valueSymbol);
              }
              return valueSymbol === receiverSymbol;
            });
            if (matches) return true;
            member = unwrapExpression(member.expression);
          }
          return false;
        };
        const objectWrapsReceiver = (input: ts.Expression): boolean => {
          const object = unwrapExpression(input);
          if (!ts.isObjectLiteralExpression(object)) return false;
          return object.properties.some((property) => {
            const value = ts.isShorthandPropertyAssignment(property) ? property.name
              : ts.isPropertyAssignment(property) ? unwrapExpression(property.initializer) : undefined;
            if (!value || !ts.isIdentifier(value)) return false;
            let valueSymbol = ts.isShorthandPropertyAssignment(property)
              ? checker.getShorthandAssignmentValueSymbol(property)
              : checker.getSymbolAtLocation(value);
            if (valueSymbol?.flags && valueSymbol.flags & ts.SymbolFlags.Alias) {
              valueSymbol = checker.getAliasedSymbol(valueSymbol);
            }
            return valueSymbol === receiverSymbol;
          });
        };
        const aliasDeclarations: ts.VariableDeclaration[] = [];
        const aliasNodes: ts.Node[] = [...projectSources];
        while (aliasNodes.length > 0) {
          check();
          const candidate = aliasNodes.pop()!;
          if (ts.isVariableDeclaration(candidate) && candidate.initializer) {
            aliasDeclarations.push(candidate);
          }
          ts.forEachChild(candidate, (child) => { aliasNodes.push(child); });
        }
        let aliasesChanged = true;
        while (aliasesChanged) {
          aliasesChanged = false;
          for (const declaration of aliasDeclarations) {
            check();
            const initializer = unwrapExpression(declaration.initializer!);
            let initializerSymbol = ts.isIdentifier(initializer)
              ? checker.getSymbolAtLocation(initializer) : undefined;
            if (initializerSymbol?.flags && initializerSymbol.flags & ts.SymbolFlags.Alias) {
              initializerSymbol = checker.getAliasedSymbol(initializerSymbol);
            }
            const aliasesWrapper = memberAliasesReceiver(initializer) || objectWrapsReceiver(initializer)
              || Boolean(initializerSymbol && wrapperAliases.has(initializerSymbol));
            if (ts.isIdentifier(declaration.name)) {
              const alias = checker.getSymbolAtLocation(declaration.name);
              if (!alias || wrapperAliases.has(alias) || !aliasesWrapper) continue;
              wrapperAliases.add(alias);
              aliasesChanged = true;
              continue;
            }
            if (!ts.isObjectBindingPattern(declaration.name)) continue;
            const initializerType = checker.getTypeAtLocation(initializer);
            for (const element of declaration.name.elements) {
              if (element.dotDotDotToken || !ts.isIdentifier(element.name)) continue;
              const keyNode = element.propertyName ?? element.name;
              const key = ts.isIdentifier(keyNode) || ts.isStringLiteral(keyNode)
                || ts.isNumericLiteral(keyNode) ? keyNode.text : undefined;
              if (key === undefined) continue;
              const initializerObject = initializerSymbol && wrapperAliases.has(initializerSymbol)
                ? objectForSymbol(initializerSymbol) : undefined;
              const objectEdge = initializerObject
                ? objectPropertyAliasesReceiver(initializerObject, key) : false;
              const property = initializerType.getProperty(key);
              const propertyAliasesReceiver = initializerObject ? objectEdge !== false
                : property?.declarations?.some((candidate) => {
                const value = ts.isShorthandPropertyAssignment(candidate) ? candidate.name
                  : ts.isPropertyAssignment(candidate)
                    ? unwrapExpression(candidate.initializer) : undefined;
                if (!value || !ts.isIdentifier(value)) return false;
                let valueSymbol = ts.isShorthandPropertyAssignment(candidate)
                  ? checker.getShorthandAssignmentValueSymbol(candidate)
                  : checker.getSymbolAtLocation(value);
                if (valueSymbol?.flags && valueSymbol.flags & ts.SymbolFlags.Alias) {
                  valueSymbol = checker.getAliasedSymbol(valueSymbol);
                }
                return valueSymbol === receiverSymbol;
                });
              if (!propertyAliasesReceiver) continue;
              const alias = checker.getSymbolAtLocation(element.name);
              if (alias && !wrapperAliases.has(alias)) {
                wrapperAliases.add(alias);
                aliasesChanged = true;
              }
            }
          }
        }
        let wrapperMutated = false;
        const wrapperNodes: ts.Node[] = [...projectSources];
        while (wrapperNodes.length > 0 && !wrapperMutated) {
          check();
          const candidate = wrapperNodes.pop()!;
          if (ts.isIdentifier(candidate)) {
            let candidateSymbol = checker.getSymbolAtLocation(candidate);
            if (candidateSymbol?.flags && candidateSymbol.flags & ts.SymbolFlags.Alias) {
              candidateSymbol = checker.getAliasedSymbol(candidateSymbol);
            }
            if (candidateSymbol && wrapperAliases.has(candidateSymbol)) {
              const declarationName = ts.isVariableDeclaration(candidate.parent)
                && candidate.parent.name === candidate;
              const member = (ts.isPropertyAccessExpression(candidate.parent)
                || ts.isElementAccessExpression(candidate.parent))
                && candidate.parent.expression === candidate ? candidate.parent : undefined;
              const staticDestructure = ts.isVariableDeclaration(candidate.parent)
                && candidate.parent.initializer === candidate
                && ts.isObjectBindingPattern(candidate.parent.name)
                && candidate.parent.name.elements.every((element) => {
                  if (element.dotDotDotToken) return false;
                  const property = element.propertyName ?? element.name;
                  return ts.isIdentifier(property) || ts.isStringLiteral(property)
                    || ts.isNumericLiteral(property);
                });
              if (!declarationName && !member && !staticDestructure) wrapperMutated = true;
            }
          }
          if (ts.isBinaryExpression(candidate)
            && candidate.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
            && candidate.operatorToken.kind <= ts.SyntaxKind.LastAssignment
            && deepContainsTarget(candidate.right)) {
            let root = unwrapExpression(candidate.left);
            while (ts.isPropertyAccessExpression(root) || ts.isElementAccessExpression(root)) {
              root = unwrapExpression(root.expression);
            }
            let rootSymbol = ts.isIdentifier(root) ? checker.getSymbolAtLocation(root) : undefined;
            if (rootSymbol?.flags && rootSymbol.flags & ts.SymbolFlags.Alias) {
              rootSymbol = checker.getAliasedSymbol(rootSymbol);
            }
            if (rootSymbol && wrapperAliases.has(rootSymbol)) wrapperMutated = true;
            let member: ts.Expression = unwrapExpression(candidate.left);
            while (!wrapperMutated
              && (ts.isPropertyAccessExpression(member) || ts.isElementAccessExpression(member))) {
              check();
              const propertySymbol = memberSymbol(member);
              const aliasesReceiver = propertySymbol?.declarations?.some((property) => {
                if (!ts.isShorthandPropertyAssignment(property)) return false;
                let valueSymbol = checker.getShorthandAssignmentValueSymbol(property);
                if (valueSymbol?.flags && valueSymbol.flags & ts.SymbolFlags.Alias) {
                  valueSymbol = checker.getAliasedSymbol(valueSymbol);
                }
                return valueSymbol === receiverSymbol;
              });
              if (aliasesReceiver) wrapperMutated = true;
              member = unwrapExpression(member.expression);
            }
          }
          ts.forEachChild(candidate, (child) => { wrapperNodes.push(child); });
        }
        wrapperMutationCache.set(receiverSymbol, wrapperMutated);
        if (wrapperMutated) return true;
        }
      }
      const resolvesReceiver = (candidate: ts.Expression): boolean => {
        const expression = unwrapExpression(candidate);
        if (!receiverSymbol || !ts.isIdentifier(expression)) return false;
        let candidateSymbol = checker.getSymbolAtLocation(expression);
        if (candidateSymbol?.flags && candidateSymbol.flags & ts.SymbolFlags.Alias) {
          candidateSymbol = checker.getAliasedSymbol(candidateSymbol);
        }
        return candidateSymbol === receiverSymbol;
      };
      const cacheKey = receiverSymbol ?? symbol;
      let escapeCache = projectSources && MEMBER_ESCAPE_CACHE.get(projectSources);
      if (projectSources && !escapeCache) {
        escapeCache = new WeakMap();
        MEMBER_ESCAPE_CACHE.set(projectSources, escapeCache);
      }
      let escapeAnalysis = escapeCache?.get(cacheKey);
      if (!escapeAnalysis) {
        let escaped = false;
        const assignedProperties = new Set<ts.Symbol>();
        const deletedProperties = new Map<ts.Symbol, ts.DeleteExpression[]>();
        let referenceIndex = projectSources && MEMBER_REFERENCE_CACHE.get(projectSources);
        if (projectSources && !referenceIndex) {
          const mutableIndex = new Map<ts.Symbol, ts.Expression[]>();
          const addReference = (candidateSymbol: ts.Symbol | undefined, reference: ts.Expression) => {
            if (!candidateSymbol) return;
            const target = candidateSymbol.flags & ts.SymbolFlags.Alias
              ? checker.getAliasedSymbol(candidateSymbol) : candidateSymbol;
            const existing = mutableIndex.get(target);
            if (existing) existing.push(reference);
            else mutableIndex.set(target, [reference]);
          };
          const projectNodes: ts.Node[] = [...projectSources];
          while (projectNodes.length > 0) {
            const candidate = projectNodes.pop()!;
            check();
            if (ts.isIdentifier(candidate)) {
              addReference(checker.getSymbolAtLocation(candidate), candidate);
              if (ts.isShorthandPropertyAssignment(candidate.parent)
                && candidate.parent.name === candidate) {
                addReference(checker.getShorthandAssignmentValueSymbol(candidate.parent), candidate);
              }
            }
            if (ts.isPropertyAccessExpression(candidate) || ts.isElementAccessExpression(candidate)) {
              addReference(memberSymbol(candidate), candidate);
            }
            ts.forEachChild(candidate, (child) => { projectNodes.push(child); });
          }
          referenceIndex = mutableIndex;
          MEMBER_REFERENCE_CACHE.set(projectSources, referenceIndex);
        }
        const references: ts.Node[] = receiverSymbol && referenceIndex
          ? [...(referenceIndex.get(receiverSymbol) ?? [])]
          : receiverSymbol
            ? [node.getSourceFile(),
              ...(symbol.declarations?.map((declaration) => declaration.getSourceFile()) ?? [])]
            : [];
        const indexed = Boolean(receiverSymbol && referenceIndex);
        while (references.length > 0 && !escaped) {
          const candidate = references.pop()!;
          check();
          const directReceiver = receiverSymbol && (ts.isPropertyAccessExpression(candidate)
            || ts.isElementAccessExpression(candidate)) && memberSymbol(candidate) === receiverSymbol
            ? candidate : undefined;
          if (directReceiver || (ts.isIdentifier(candidate) && resolvesReceiver(candidate))) {
            const namedMember = !directReceiver && ts.isIdentifier(candidate)
              && ts.isPropertyAccessExpression(candidate.parent)
              && candidate.parent.name === candidate && memberSymbol(candidate.parent) === receiverSymbol
              ? candidate.parent : undefined;
            const reference: ts.Expression = directReceiver ?? namedMember ?? candidate as ts.Expression;
            const declarationName = ((ts.isVariableDeclaration(reference.parent)
              || ts.isParameter(reference.parent) || ts.isBindingElement(reference.parent)
              || ts.isPropertyAssignment(reference.parent))
              && reference.parent.name === reference);
            const importName = (ts.isImportSpecifier(reference.parent)
              || ts.isImportClause(reference.parent) || ts.isNamespaceImport(reference.parent))
              && reference.parent.name === reference;
            const wrapperCandidate = ts.isShorthandPropertyAssignment(reference.parent)
              || (ts.isPropertyAssignment(reference.parent)
                && reference.parent.initializer === reference);
            let wrapped = wrapperCandidate;
            if (wrapped && ts.isObjectLiteralExpression(reference.parent.parent)) {
              const property = reference.parent as (
                ts.PropertyAssignment | ts.ShorthandPropertyAssignment
              );
              const name = property.name;
              const key = ts.isComputedPropertyName(name)
                ? resolveStaticPropertyKey(name.expression, checker, check)
                : ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)
                  ? name.text : undefined;
              if (key !== undefined) {
                let selected: ts.ObjectLiteralElementLike | undefined;
                for (const candidateProperty of reference.parent.parent.properties) {
                  if (ts.isSpreadAssignment(candidateProperty)) continue;
                  const candidateName = candidateProperty.name;
                  const candidateKey = ts.isComputedPropertyName(candidateName)
                    ? resolveStaticPropertyKey(candidateName.expression, checker, check)
                    : ts.isIdentifier(candidateName) || ts.isStringLiteral(candidateName)
                      || ts.isNumericLiteral(candidateName) ? candidateName.text : undefined;
                  if (candidateKey === key) selected = candidateProperty;
                }
                wrapped = selected === property;
              }
            }
            if (wrapped) {
              const wrapperObject = reference.parent.parent;
              const wrapperDeclaration = ts.isObjectLiteralExpression(wrapperObject)
                && ts.isVariableDeclaration(wrapperObject.parent)
                && ts.isIdentifier(wrapperObject.parent.name) ? wrapperObject.parent : undefined;
              let wrapperSymbol = wrapperDeclaration
                ? checker.getSymbolAtLocation(wrapperDeclaration.name) : undefined;
              if (wrapperSymbol?.flags && wrapperSymbol.flags & ts.SymbolFlags.Alias) {
                wrapperSymbol = checker.getAliasedSymbol(wrapperSymbol);
              }
              const mutations: ts.Node[] = projectSources ? [...projectSources] : [];
              while (mutations.length > 0 && !escaped) {
                check();
                const mutation = mutations.pop()!;
                if (wrapperSymbol && ts.isIdentifier(mutation)) {
                  let mutationSymbol = checker.getSymbolAtLocation(mutation);
                  if (mutationSymbol?.flags && mutationSymbol.flags & ts.SymbolFlags.Alias) {
                    mutationSymbol = checker.getAliasedSymbol(mutationSymbol);
                  }
                  if (mutationSymbol === wrapperSymbol && mutation !== wrapperDeclaration?.name) {
                    const member = (ts.isPropertyAccessExpression(mutation.parent)
                      || ts.isElementAccessExpression(mutation.parent))
                      && mutation.parent.expression === mutation ? mutation.parent : undefined;
                    const staticDestructure = ts.isVariableDeclaration(mutation.parent)
                      && mutation.parent.initializer === mutation
                      && ts.isObjectBindingPattern(mutation.parent.name)
                      && mutation.parent.name.elements.every((element) => {
                        if (element.dotDotDotToken) return false;
                        const property = element.propertyName ?? element.name;
                        return ts.isIdentifier(property) || ts.isStringLiteral(property)
                          || ts.isNumericLiteral(property);
                      });
                    if (!member && !staticDestructure) escaped = true;
                  }
                }
                if (ts.isBinaryExpression(mutation)
                  && mutation.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
                  && mutation.operatorToken.kind <= ts.SyntaxKind.LastAssignment
                  && deepContainsTarget(mutation.right)) {
                  let root = unwrapExpression(mutation.left);
                  while (ts.isPropertyAccessExpression(root) || ts.isElementAccessExpression(root)) {
                    root = unwrapExpression(root.expression);
                  }
                  let rootSymbol = ts.isIdentifier(root) ? checker.getSymbolAtLocation(root) : undefined;
                  if (rootSymbol?.flags && rootSymbol.flags & ts.SymbolFlags.Alias) {
                    rootSymbol = checker.getAliasedSymbol(rootSymbol);
                  }
                  escaped = Boolean(wrapperSymbol && rootSymbol === wrapperSymbol);
                }
                ts.forEachChild(mutation, (child) => { mutations.push(child); });
              }
              continue;
            }
            if (wrapperCandidate) continue;
            const member = (ts.isPropertyAccessExpression(reference.parent)
              || ts.isElementAccessExpression(reference.parent))
              && reference.parent.expression === reference ? reference.parent : undefined;
            const memberProperty = member && memberSymbol(member);
            const getter = memberProperty?.declarations?.some(ts.isGetAccessorDeclaration);
            const declaredDataProperty = memberProperty?.declarations?.some((declaration) => (
              ts.isPropertyAssignment(declaration) || ts.isShorthandPropertyAssignment(declaration)
            ));
            const runtimeDataProperty = member && objectProperty(
              ts.isPropertyAccessExpression(member) ? member.name.text
                : member.argumentExpression
                  ? resolveStaticPropertyKey(member.argumentExpression, checker, check) : undefined,
            );
            let usage: ts.Expression | undefined = member ?? reference;
            while (usage && (ts.isParenthesizedExpression(usage.parent)
              || ts.isAsExpression(usage.parent) || ts.isTypeAssertionExpression(usage.parent)
              || ts.isSatisfiesExpression(usage.parent) || ts.isNonNullExpression(usage.parent))
              && usage.parent.expression === usage) usage = usage.parent;
            const invoked = usage && ((ts.isCallExpression(usage.parent)
              && usage.parent.expression === usage)
              || (ts.isTaggedTemplateExpression(usage.parent) && usage.parent.tag === usage));
            const deletion = usage && ts.isDeleteExpression(usage.parent)
              && usage.parent.expression === usage ? usage.parent : undefined;
            if (deletion && memberProperty) {
              const deletions = deletedProperties.get(memberProperty);
              if (deletions) deletions.push(deletion);
              else deletedProperties.set(memberProperty, [deletion]);
            }
            let assigned = false;
            let assignmentTarget: ts.Node | undefined = usage;
            while (assignmentTarget?.parent && !ts.isStatement(assignmentTarget)) {
              const parent: ts.Node = assignmentTarget.parent;
              if (ts.isBinaryExpression(parent) && parent.left === assignmentTarget
                && parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
                && parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
                assigned = true;
                break;
              }
              if ((ts.isForOfStatement(parent) || ts.isForInStatement(parent))
                && parent.initializer === assignmentTarget) {
                assigned = true;
                break;
              }
              assignmentTarget = parent;
            }
            if (assigned && memberProperty) assignedProperties.add(memberProperty);
            const memberRead = Boolean(member && memberProperty && !getter && !invoked
              && (declaredDataProperty || runtimeDataProperty)
              && (!assigned || memberProperty !== undefined));
            const usageParent = usage.parent;
            const strictComparison = ts.isBinaryExpression(usageParent)
              && (usageParent.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken
                || usageParent.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken);
            const logicalRead = ts.isBinaryExpression(usageParent)
              && (usageParent.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
                || usageParent.operatorToken.kind === ts.SyntaxKind.BarBarToken
                || usageParent.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken);
            const readOnlyReference = !member && !assigned && !invoked && (
              strictComparison || logicalRead
              || (ts.isIfStatement(usageParent) && usageParent.expression === usage)
              || (ts.isConditionalExpression(usageParent) && usageParent.condition === usage)
              || (ts.isPrefixUnaryExpression(usageParent)
                && usageParent.operator === ts.SyntaxKind.ExclamationToken)
              || (ts.isTypeOfExpression(usageParent) || ts.isVoidExpression(usageParent))
              || ts.isExpressionStatement(usageParent)
            );
            escaped = !declarationName && !importName && !memberRead && !readOnlyReference;
          }
          if (!indexed) ts.forEachChild(candidate, (child) => { references.push(child); });
        }
        escapeAnalysis = { escaped, assigned: assignedProperties, deleted: deletedProperties };
        escapeCache?.set(cacheKey, escapeAnalysis);
      }
      if (escapeAnalysis.escaped) return true;
      if (escapeAnalysis.assigned.has(symbol)) {
        let topLevelStatement: ts.Node = node;
        let delayed = false;
        while (!ts.isSourceFile(topLevelStatement.parent)) {
          topLevelStatement = topLevelStatement.parent;
          delayed ||= ts.isFunctionLike(topLevelStatement) || ts.isClassLike(topLevelStatement);
        }
        if (delayed) return true;
        let sawDirectAssignment = false;
        let uncertainAssignment = false;
        let latestAssignment: ts.Expression | undefined;
        let latestStart = -1;
        for (const sourceFile of projectSources ?? [node.getSourceFile()]) {
          const assignments: ts.Node[] = [sourceFile];
          while (assignments.length > 0) {
            const candidate = assignments.pop()!;
            check();
            if (ts.isBinaryExpression(candidate)
              && (ts.isPropertyAccessExpression(unwrapExpression(candidate.left))
              || ts.isElementAccessExpression(unwrapExpression(candidate.left)))) {
              const left = unwrapExpression(candidate.left);
              if (memberSymbol(left as ts.PropertyAccessExpression | ts.ElementAccessExpression) === symbol) {
                sawDirectAssignment = true;
                if (staticallyUnreachable(candidate, depth, bindings)) {
                  ts.forEachChild(candidate, (child) => { assignments.push(child); });
                  continue;
                }
                const direct = candidate.operatorToken.kind === ts.SyntaxKind.EqualsToken
                  && ts.isExpressionStatement(candidate.parent)
                  && ts.isSourceFile(candidate.parent.parent)
                  && candidate.getSourceFile() === node.getSourceFile();
                if (!direct) uncertainAssignment = true;
                else if (candidate.getStart() < topLevelStatement.getStart()
                  && candidate.getStart() > latestStart) {
                  latestAssignment = candidate.right;
                  latestStart = candidate.getStart();
                }
              }
            }
            ts.forEachChild(candidate, (child) => { assignments.push(child); });
          }
        }
        if (!sawDirectAssignment || uncertainAssignment) return true;
        if (latestAssignment) return resolve(latestAssignment, depth + 1, bindings);
      }
      const deletions = escapeAnalysis.deleted.get(symbol);
      if (deletions?.length) {
        const sourceFile = node.getSourceFile();
        let topLevelStatement: ts.Node = node;
        let delayed = false;
        while (!ts.isSourceFile(topLevelStatement.parent)) {
          topLevelStatement = topLevelStatement.parent;
          delayed ||= ts.isFunctionLike(topLevelStatement) || ts.isClassLike(topLevelStatement);
        }
        const staticallyDeleted = deletions.every((deletion) => (
          node === unwrapExpression(expression) && !delayed
          && deletion.getSourceFile() === sourceFile
          && deletion.end <= topLevelStatement.getStart()
          && ts.isExpressionStatement(deletion.parent) && ts.isSourceFile(deletion.parent.parent)
        ));
        return !staticallyDeleted;
      }
      if (symbol.declarations?.some(ts.isGetAccessorDeclaration)) return true;
      resolving.add(symbol);
      const property = symbol.declarations?.find((candidate): candidate is (
        ts.PropertyAssignment | ts.PropertyDeclaration
      ) => (
        (ts.isPropertyAssignment(candidate) || ts.isPropertyDeclaration(candidate))
          && candidate.initializer !== undefined
      ));
      const shorthand = symbol.declarations?.find(ts.isShorthandPropertyAssignment);
      const resolvedProperty = runtimeProperty !== undefined
        ? runtimeProperty && ts.isPropertyAssignment(runtimeProperty) ? runtimeProperty : undefined
        : property;
      const resolvedShorthand = runtimeProperty !== undefined
        ? runtimeProperty && ts.isShorthandPropertyAssignment(runtimeProperty) ? runtimeProperty : undefined
        : shorthand;
      let result = Boolean(resolvedProperty?.initializer
        && resolve(resolvedProperty.initializer, depth + 1, bindings));
      if (!result && resolvedShorthand) {
        const valueSymbol = checker.getShorthandAssignmentValueSymbol(resolvedShorthand);
        const declaration = valueSymbol?.declarations?.find(
          (candidate): candidate is ts.VariableDeclaration => ts.isVariableDeclaration(candidate)
            && candidate.initializer !== undefined
            && ts.isVariableDeclarationList(candidate.parent)
            && Boolean(candidate.parent.flags & ts.NodeFlags.Const),
        );
        result = Boolean(declaration?.initializer
          && resolve(declaration.initializer, depth + 1, bindings));
      }
      resolving.delete(symbol);
      return result;
    }
    if (ts.isBinaryExpression(node)) {
      if (node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        return resolve(node.right, depth + 1, bindings);
      }
      if (node.operatorToken.kind === ts.SyntaxKind.CommaToken) {
        return resolve(node.right, depth + 1, bindings);
      }
      const logicalAnd = node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
        || node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandEqualsToken;
      const logicalOr = node.operatorToken.kind === ts.SyntaxKind.BarBarToken
        || node.operatorToken.kind === ts.SyntaxKind.BarBarEqualsToken;
      if (logicalAnd || logicalOr) {
        const left = truthiness(node.left, depth + 1, bindings);
        if (logicalAnd) {
          if (left === false) return resolve(node.left, depth + 1, bindings);
          if (left === true) return resolve(node.right, depth + 1, bindings);
          return resolve(node.right, depth + 1, bindings);
        }
        if (left === true) return resolve(node.left, depth + 1, bindings);
        if (left === false) return resolve(node.right, depth + 1, bindings);
        return resolve(node.left, depth + 1, bindings)
          || resolve(node.right, depth + 1, bindings);
      }
      if (node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken
        || node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionEqualsToken) {
        const left = nullishState(node.left, true, depth + 1, bindings);
        return left === true
          ? resolve(node.right, depth + 1, bindings)
          : left === false
            ? resolve(node.left, depth + 1, bindings)
            : resolve(node.left, depth + 1, bindings)
              || resolve(node.right, depth + 1, bindings);
      }
    }
    if (ts.isCallExpression(node)) {
      let callee: ts.Expression | ts.FunctionDeclaration | ts.MethodDeclaration = unwrapExpression(node.expression);
      while (ts.isBinaryExpression(callee)
        && callee.operatorToken.kind === ts.SyntaxKind.CommaToken) callee = unwrapExpression(callee.right);
      if (ts.isConditionalExpression(callee)) {
        const condition = truthiness(callee.condition, depth + 1, bindings);
        if (condition === true) callee = unwrapExpression(callee.whenTrue);
        else if (condition === false) callee = unwrapExpression(callee.whenFalse);
        else {
          const callableAnalysis = (candidate: ts.Expression): { sync: boolean; target: boolean } => {
            const target = unwrapExpression(candidate);
            const direct = ts.isFunctionExpression(target) || ts.isArrowFunction(target)
              ? target : undefined;
            if (direct) {
              const sync = !direct.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword)
                && !(ts.isFunctionExpression(direct) && direct.asteriskToken);
              return { sync, target: sync && (parameterDefaultsMayTarget(
                direct.parameters, node.arguments, depth, bindings,
              ) || deepContainsTarget(direct.body)) };
            }
            if (!ts.isIdentifier(target)) {
              if (ts.isPropertyAccessExpression(target) || ts.isElementAccessExpression(target)) {
                let receiver = unwrapExpression(target.expression);
                while (ts.isPropertyAccessExpression(receiver) || ts.isElementAccessExpression(receiver)) {
                  receiver = unwrapExpression(receiver.expression);
                }
                if (ts.isIdentifier(receiver)) {
                  let receiverSymbol = checker.getSymbolAtLocation(receiver);
                  if (receiverSymbol?.flags && receiverSymbol.flags & ts.SymbolFlags.Alias) {
                    receiverSymbol = checker.getAliasedSymbol(receiverSymbol);
                  }
                  if (receiverSymbol?.declarations?.some((item) => (
                    projectSources?.has(item.getSourceFile())
                  ))) return { sync: true, target: true };
                }
              }
              return { sync: true, target: deepContainsTarget(target) };
            }
            let symbol = checker.getSymbolAtLocation(target);
            if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
            const declaration = symbol?.declarations?.find((item): item is (
              ts.FunctionDeclaration | ts.VariableDeclaration
            ) => (ts.isFunctionDeclaration(item) && item.body !== undefined)
              || (ts.isVariableDeclaration(item) && item.initializer !== undefined));
            const implementation = declaration && ts.isFunctionDeclaration(declaration) ? declaration
              : declaration && ts.isVariableDeclaration(declaration)
                ? unwrapExpression(declaration.initializer!) : undefined;
            if (!implementation || (!ts.isFunctionDeclaration(implementation)
              && !ts.isFunctionExpression(implementation)
              && !ts.isArrowFunction(implementation))) return { sync: true, target: false };
            if (implementation.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword)
              || ((ts.isFunctionDeclaration(implementation) || ts.isFunctionExpression(implementation))
                && implementation.asteriskToken)) return { sync: false, target: false };
            return { sync: true, target: parameterDefaultsMayTarget(
              implementation.parameters, node.arguments, depth, bindings,
            ) || Boolean(implementation.body && deepContainsTarget(implementation.body)) };
          };
          const alternatives = [callableAnalysis(callee.whenTrue), callableAnalysis(callee.whenFalse)];
          if (!alternatives.some(({ sync }) => sync)) return false;
          if (node.arguments.some((argument) => subtreeContainsTarget(
            ts.isSpreadElement(argument) ? argument.expression : argument,
          ))) return true;
          return alternatives.some(({ sync, target }) => sync && target);
        }
      }
      if (ts.isIdentifier(callee)) {
        let calleeSymbol = checker.getSymbolAtLocation(callee);
        if (calleeSymbol?.flags && calleeSymbol.flags & ts.SymbolFlags.Alias) {
          calleeSymbol = checker.getAliasedSymbol(calleeSymbol);
        }
        const declarations = calleeSymbol?.declarations ?? [];
        const localDeclarations = projectSources
          ? declarations.filter((declaration) => projectSources.has(declaration.getSourceFile())) : [];
        const functionDeclarations = localDeclarations.filter(
          (declaration): declaration is ts.FunctionDeclaration => (
            ts.isFunctionDeclaration(declaration) && declaration.body !== undefined
          ),
        );
        const functionDeclaration = functionDeclarations.length === 1
          ? functionDeclarations[0] : undefined;
        const variableDeclarations = calleeSymbol?.declarations?.filter(ts.isVariableDeclaration) ?? [];
        const variableDeclaration = variableDeclarations.length === 1 ? variableDeclarations[0] : undefined;
        const variableInitializer = variableDeclaration?.initializer
          && ts.isVariableDeclarationList(variableDeclaration.parent)
          && variableDeclaration.parent.flags & ts.NodeFlags.Const
          ? unwrapExpression(variableDeclaration.initializer) : undefined;
        if (functionDeclaration) {
          if (calleeSymbol && callableBindingMayBeWritten(
            calleeSymbol, declarations, checker, projectSources, check,
          )) return true;
          callee = functionDeclaration;
        }
        else if (variableInitializer && (ts.isArrowFunction(variableInitializer)
          || ts.isFunctionExpression(variableInitializer))) callee = variableInitializer;
        else if (localDeclarations.length > 0) return true;
        else return node.arguments.some((argument) => resolve(
          ts.isSpreadElement(argument) ? argument.expression : argument, depth + 1, bindings,
        ));
      }
      if (!ts.isArrowFunction(callee) && !ts.isFunctionExpression(callee)
        && !ts.isFunctionDeclaration(callee)) {
        if (ts.isCallExpression(callee)) {
          return resolve(callee, depth + 1, bindings) || deepContainsTarget(callee);
        }
        if (node.arguments.some((argument) => subtreeContainsTarget(
          ts.isSpreadElement(argument) ? argument.expression : argument,
        ))) return true;
        if (ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee)) {
          const receiver = unwrapExpression(callee.expression);
          const key = ts.isPropertyAccessExpression(callee) ? callee.name.text
            : callee.argumentExpression
              ? resolveStaticPropertyKey(callee.argumentExpression, checker, check) : undefined;
          if (key === 'valueOf' && node.arguments.length === 0
            && isStaticSymbolFrom(receiver, checker, check, moduleName, importedName)) return true;
          if (!ts.isIdentifier(receiver) && !ts.isFunctionExpression(receiver)
            && !ts.isArrowFunction(receiver)
            && subtreeContainsTarget(receiver)) return true;
          if (ts.isFunctionExpression(receiver) || ts.isArrowFunction(receiver)) {
            if (key === undefined) return true;
            if (key !== 'call' && key !== 'apply') return false;
            if (receiver.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword)
              || (ts.isFunctionExpression(receiver) && receiver.asteriskToken)) return false;
            const invocationArgs = key === 'call'
              ? node.arguments.slice(1)
              : (() => {
                const list = node.arguments[1] && unwrapExpression(node.arguments[1]);
                return list && ts.isArrayLiteralExpression(list)
                  ? list.elements.some(ts.isSpreadElement) ? undefined
                    : [...list.elements].map((element) => (
                      ts.isOmittedExpression(element) ? undefined : element
                    ))
                  : list === undefined ? [] : undefined;
              })();
            if (invocationArgs === undefined) return true;
            if (parameterDefaultsMayTarget(
              receiver.parameters, invocationArgs, depth, bindings,
            )) return true;
            if (ts.isFunctionExpression(receiver) && callableUsesThis(receiver)) return true;
            return ts.isBlock(receiver.body)
              ? receiver.body.statements.some(subtreeContainsTarget)
              : subtreeContainsTarget(receiver.body);
          }
          if (ts.isIdentifier(receiver) && key !== undefined) {
            let localSymbol = checker.getSymbolAtLocation(receiver);
            if (localSymbol?.flags && localSymbol.flags & ts.SymbolFlags.Alias) {
              localSymbol = checker.getAliasedSymbol(localSymbol);
            }
            const declarations = localSymbol?.declarations?.filter(ts.isVariableDeclaration) ?? [];
            const declaration = declarations.length === 1 ? declarations[0] : undefined;
            const initializer = declaration?.initializer
              && ts.isVariableDeclarationList(declaration.parent)
              && declaration.parent.flags & ts.NodeFlags.Const
              ? unwrapExpression(declaration.initializer) : undefined;
            if (initializer && ts.isObjectLiteralExpression(initializer)) {
              const references: ts.Node[] = projectSources ? [...projectSources] : [];
              while (references.length > 0) {
                check();
                const reference = references.pop()!;
                if (ts.isIdentifier(reference)) {
                  let referenceSymbol = checker.getSymbolAtLocation(reference);
                  if (referenceSymbol?.flags && referenceSymbol.flags & ts.SymbolFlags.Alias) {
                    referenceSymbol = checker.getAliasedSymbol(referenceSymbol);
                  }
                  if (referenceSymbol === localSymbol && reference !== declaration?.name
                    && reference !== receiver) {
                    const member = (ts.isPropertyAccessExpression(reference.parent)
                      || ts.isElementAccessExpression(reference.parent))
                      && reference.parent.expression === reference ? reference.parent : undefined;
                    if (!member) return true;
                    const memberKey = ts.isPropertyAccessExpression(member) ? member.name.text
                      : member.argumentExpression
                        ? resolveStaticPropertyKey(member.argumentExpression, checker, check) : undefined;
                    let usage: ts.Expression = member;
                    while ((ts.isParenthesizedExpression(usage.parent)
                      || ts.isAsExpression(usage.parent) || ts.isTypeAssertionExpression(usage.parent)
                      || ts.isSatisfiesExpression(usage.parent) || ts.isNonNullExpression(usage.parent))
                      && usage.parent.expression === usage) usage = usage.parent;
                    const invoked = (ts.isCallExpression(usage.parent)
                      && usage.parent.expression === usage)
                      || (ts.isTaggedTemplateExpression(usage.parent) && usage.parent.tag === usage);
                    const getter = memberKey !== undefined
                      && checker.getTypeAtLocation(member.expression).getProperty(memberKey)
                        ?.declarations?.some(ts.isGetAccessorDeclaration);
                    let written = false;
                    let target: ts.Node = usage;
                    while (target.parent && !ts.isStatement(target)) {
                      const parent = target.parent;
                      if (ts.isBinaryExpression(parent) && parent.left === target
                        && parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
                        && parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
                        written = true;
                        break;
                      }
                      if ((ts.isForOfStatement(parent) || ts.isForInStatement(parent))
                        && parent.initializer === target) {
                        written = true;
                        break;
                      }
                      target = parent;
                    }
                    if (memberKey === undefined || ts.isDeleteExpression(usage.parent)
                      || invoked || getter || written) return true;
                  }
                }
                ts.forEachChild(reference, (child) => { references.push(child); });
              }
              let selected: ts.ObjectLiteralElementLike | null | undefined;
              for (const property of initializer.properties) {
                if (ts.isSpreadAssignment(property)) {
                  selected = null;
                  continue;
                }
                const name = property.name;
                const propertyKey = ts.isComputedPropertyName(name)
                  ? resolveStaticPropertyKey(name.expression, checker, check)
                  : ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)
                    ? name.text : undefined;
                if (propertyKey === undefined) {
                  if (ts.isComputedPropertyName(name)) selected = null;
                  continue;
                }
                if (propertyKey === key) selected = property;
              }
              if (selected === null) return true;
              if (!selected) return false;
              const callable = ts.isMethodDeclaration(selected) ? selected
                : ts.isPropertyAssignment(selected)
                  && (ts.isFunctionExpression(selected.initializer)
                    || ts.isArrowFunction(selected.initializer)) ? selected.initializer : undefined;
              if (!callable) return Boolean(selected);
              if (callable.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword)
                || ((ts.isMethodDeclaration(callable) || ts.isFunctionExpression(callable))
                  && callable.asteriskToken)) return false;
              if (!callable.body) return false;
              callee = callable;
            }
          }
          let rootReceiver = receiver;
          while (ts.isPropertyAccessExpression(rootReceiver) || ts.isElementAccessExpression(rootReceiver)) {
            rootReceiver = unwrapExpression(rootReceiver.expression);
          }
          if (!ts.isArrowFunction(callee) && !ts.isFunctionExpression(callee)
            && !ts.isFunctionDeclaration(callee) && !ts.isMethodDeclaration(callee)
            && ts.isIdentifier(rootReceiver)) {
            let receiverSymbol = checker.getSymbolAtLocation(rootReceiver);
            if (receiverSymbol?.flags && receiverSymbol.flags & ts.SymbolFlags.Alias) {
              receiverSymbol = checker.getAliasedSymbol(receiverSymbol);
            }
            if (receiverSymbol?.declarations?.some((declaration) => (
              projectSources?.has(declaration.getSourceFile())
            ))) return true;
          }
          if (ts.isObjectLiteralExpression(receiver)) {
            if (key === undefined) return true;
            let selected: ts.ObjectLiteralElementLike | null | undefined;
            for (const property of receiver.properties) {
              if (ts.isSpreadAssignment(property)) {
                selected = null;
                continue;
              }
              const name = property.name;
              const propertyKey = ts.isComputedPropertyName(name)
                ? resolveStaticPropertyKey(name.expression, checker, check)
                : ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)
                  ? name.text : undefined;
              if (propertyKey === undefined) {
                if (ts.isComputedPropertyName(name)) selected = null;
                continue;
              }
              if (propertyKey === key) selected = property;
            }
            if (selected === null) return true;
            if (!selected) return false;
            const callable = ts.isMethodDeclaration(selected) ? selected
              : ts.isPropertyAssignment(selected)
                && (ts.isFunctionExpression(selected.initializer)
                  || ts.isArrowFunction(selected.initializer))
                ? selected.initializer : undefined;
            if (!callable) return Boolean(selected);
            if (callable.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword)
              || ((ts.isMethodDeclaration(callable) || ts.isFunctionExpression(callable))
                && callable.asteriskToken)) return false;
            if (!callable.body) return false;
            if (parameterDefaultsMayTarget(
              callable.parameters, node.arguments, depth, bindings,
            )) return true;
            if (!ts.isArrowFunction(callable) && callableUsesThis(callable)) return true;
            callee = callable;
          }
        }
        if (!ts.isArrowFunction(callee) && !ts.isFunctionExpression(callee)
          && !ts.isFunctionDeclaration(callee) && !ts.isMethodDeclaration(callee)) return false;
      }
      const calleeBody = callee.body;
      if (!calleeBody) return false;
      if (callee.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword)
        || ((ts.isFunctionExpression(callee) || ts.isFunctionDeclaration(callee))
          && callee.asteriskToken)) return false;
      if (!ts.isArrowFunction(callee)) {
        const bodyNodes: ts.Node[] = [];
        ts.forEachChild(calleeBody, (child) => { bodyNodes.push(child); });
        while (bodyNodes.length > 0) {
          const child = bodyNodes.pop()!;
          check();
          if ((ts.isFunctionLike(child) && !ts.isArrowFunction(child)) || ts.isClassLike(child)) continue;
          if (ts.isIdentifier(child) && child.text === 'arguments') {
            const parent = child.parent;
            const declarationName = 'name' in parent && parent.name === child
              && !ts.isShorthandPropertyAssignment(parent);
            const bindingKey = ts.isBindingElement(parent) && parent.propertyName === child;
            const accessName = ts.isPropertyAccessExpression(parent) && parent.name === child;
            const label = (ts.isLabeledStatement(parent) || ts.isBreakStatement(parent)
              || ts.isContinueStatement(parent)) && parent.label === child;
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
            if (!declarationName && !bindingKey && !accessName && !label
              && !qualifiedName && !typeOnly) return true;
          }
          ts.forEachChild(child, (descendant) => { bodyNodes.push(descendant); });
        }
      }
      if (callableParametersMayBeWritten(calleeBody, callee.parameters)) return true;
      const localBindings = new Map(bindings);
      const callArguments: ts.Expression[] = [];
      for (const argument of node.arguments) {
        if (!ts.isSpreadElement(argument)) {
          callArguments.push(argument);
          continue;
        }
        const spread = unwrapExpression(argument.expression);
        if (ts.isArrayLiteralExpression(spread)
          && spread.elements.every((element) => (
            !ts.isSpreadElement(element) && !ts.isOmittedExpression(element)
          ))) {
          callArguments.push(...spread.elements as readonly ts.Expression[]);
          continue;
        }
        return subtreeContainsTarget(calleeBody)
          || node.arguments.some((candidate) => subtreeContainsTarget(
            ts.isSpreadElement(candidate) ? candidate.expression : candidate,
          ))
          || callee.parameters.slice(callArguments.length).some((parameter) => (
            Boolean(parameter.initializer && subtreeContainsTarget(parameter.initializer))
          ));
      }
      for (let index = 0; index < callee.parameters.length; index += 1) {
        const parameter = callee.parameters[index];
        if (!ts.isIdentifier(parameter.name) || parameter.dotDotDotToken) {
          return subtreeContainsTarget(calleeBody)
            || node.arguments.some((candidate) => subtreeContainsTarget(
              ts.isSpreadElement(candidate) ? candidate.expression : candidate,
            ))
            || callee.parameters.some((candidate) => Boolean(
              candidate.initializer && subtreeContainsTarget(candidate.initializer),
            ));
        }
        const symbol = checker.getSymbolAtLocation(parameter.name);
        const argument = callArguments[index];
        if (!symbol) continue;
        if (!argument) {
          if (parameter.initializer) localBindings.set(symbol, [parameter.initializer]);
          continue;
        }
        if (!parameter.initializer) {
          localBindings.set(symbol, [argument]);
          continue;
        }
        const state = nullishState(argument, false, depth + 1, bindings);
        localBindings.set(symbol, state === true
          ? [parameter.initializer]
          : state === false
            ? [argument]
            : [argument, parameter.initializer]);
      }
      if (!ts.isBlock(calleeBody)) return resolve(calleeBody, depth + 1, localBindings);
      return sequenceFlow(calleeBody.statements, 0, depth, localBindings).target;
    }
    if (!ts.isIdentifier(node)) return false;
    let symbol = checker.getSymbolAtLocation(node);
    if (!symbol) return false;
    if (symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    const bound = bindings.get(symbol);
    if (bound) return bound.some((candidate) => resolve(candidate, depth + 1, bindings));
    if (resolving.has(symbol)) return true;
    const binding = symbol.declarations?.find((candidate): candidate is ts.BindingElement => (
      ts.isBindingElement(candidate) && !candidate.dotDotDotToken
      && ts.isVariableDeclaration(candidate.parent.parent)
      && ts.isVariableDeclarationList(candidate.parent.parent.parent)
      && Boolean(candidate.parent.parent.parent.flags & ts.NodeFlags.Const)
      && candidate.parent.parent.initializer !== undefined
    ));
    const nestedBinding = symbol.declarations?.find((candidate): candidate is ts.BindingElement => (
      ts.isBindingElement(candidate) && !ts.isVariableDeclaration(candidate.parent.parent)
    ));
    if (nestedBinding) {
      let owner: ts.Node = nestedBinding.parent;
      while (!ts.isVariableDeclaration(owner) && !ts.isSourceFile(owner)) owner = owner.parent;
      return ts.isVariableDeclaration(owner) && Boolean(owner.initializer
        && deepContainsTarget(owner.initializer));
    }
    if (binding) {
      const initializer = unwrapExpression(binding.parent.parent.initializer!);
      const resolveBindingValue = (candidate: ts.Expression | undefined): boolean => {
        if (!binding.initializer) return Boolean(candidate
          && resolve(candidate, depth + 1, bindings));
        if (!candidate) return resolve(binding.initializer, depth + 1, bindings);
        const state = nullishState(candidate, false, depth + 1, bindings);
        return state === true
          ? resolve(binding.initializer, depth + 1, bindings)
          : state === false
            ? resolve(candidate, depth + 1, bindings)
            : resolve(candidate, depth + 1, bindings)
              || resolve(binding.initializer, depth + 1, bindings);
      };
      if (ts.isArrayBindingPattern(binding.parent) && ts.isArrayLiteralExpression(initializer)) {
        const index = binding.parent.elements.indexOf(binding);
        if (initializer.elements.slice(0, index + 1).some(ts.isSpreadElement)) {
          return subtreeContainsTarget(initializer)
            || Boolean(binding.initializer
              && resolve(binding.initializer, depth + 1, bindings));
        }
        const element = initializer.elements[index];
        return resolveBindingValue(element && !ts.isOmittedExpression(element)
          && !ts.isSpreadElement(element) ? element : undefined);
      }
      if (ts.isObjectBindingPattern(binding.parent)) {
        const property = binding.propertyName ?? binding.name;
        const key = ts.isComputedPropertyName(property)
          ? resolveStaticPropertyKey(property.expression, checker, check)
          : ts.isIdentifier(property) || ts.isStringLiteral(property) || ts.isNumericLiteral(property)
            ? property.text
            : undefined;
        if (key !== undefined && ts.isObjectLiteralExpression(initializer)
          && ts.isVariableDeclaration(binding.parent.parent)) {
          let selected: ts.ObjectLiteralElementLike | null | undefined;
          for (const candidate of initializer.properties) {
            check();
            if (ts.isSpreadAssignment(candidate)) {
              selected = null;
              continue;
            }
            const name = candidate.name;
            const candidateKey = ts.isComputedPropertyName(name)
              ? resolveStaticPropertyKey(name.expression, checker, check)
              : ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)
                ? name.text : undefined;
            if (candidateKey === undefined) {
              if (ts.isComputedPropertyName(name)) selected = null;
              continue;
            }
            if (candidateKey === key) selected = candidate;
          }
          if (selected === null) return true;
          if (selected && ts.isShorthandPropertyAssignment(selected)) {
            const valueSymbol = checker.getShorthandAssignmentValueSymbol(selected);
            const valueDeclaration = valueSymbol?.declarations?.find(
              (candidate): candidate is ts.VariableDeclaration => ts.isVariableDeclaration(candidate)
                && candidate.initializer !== undefined
                && ts.isVariableDeclarationList(candidate.parent)
                && Boolean(candidate.parent.flags & ts.NodeFlags.Const),
            );
            return resolveBindingValue(valueDeclaration?.initializer ?? selected.name);
          }
          return resolveBindingValue(selected && ts.isPropertyAssignment(selected)
            ? selected.initializer : undefined);
        }
        const propertySymbol = key === undefined
          ? undefined
          : checker.getTypeAtLocation(initializer).getProperty(key);
        const propertyDeclaration = propertySymbol?.declarations?.find(
          (candidate): candidate is ts.PropertyAssignment => ts.isPropertyAssignment(candidate),
        );
        const shorthand = propertySymbol?.declarations?.find(ts.isShorthandPropertyAssignment);
        const valueSymbol = shorthand && checker.getShorthandAssignmentValueSymbol(shorthand);
        const valueDeclaration = valueSymbol?.declarations?.find(
          (candidate): candidate is ts.VariableDeclaration => ts.isVariableDeclaration(candidate)
            && candidate.initializer !== undefined
            && ts.isVariableDeclarationList(candidate.parent)
            && Boolean(candidate.parent.flags & ts.NodeFlags.Const),
        );
        return resolveBindingValue(propertyDeclaration?.initializer ?? valueDeclaration?.initializer);
      }
    }
    const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
    const declaration = declarations.length === 1 ? declarations[0] : undefined;
    if (!declaration) return false;
    if (!ts.isVariableDeclarationList(declaration.parent)) return true;
    if (!(declaration.parent.flags & ts.NodeFlags.Const)) {
      let latest = declaration.initializer;
      let latestStart = declaration.getStart();
      let uncertainTarget = false;
      resolving.add(symbol);
      const targetsSymbol = (root: ts.Node): boolean => {
        const target = ts.isExpression(root) ? unwrapExpression(root) : root;
        if (ts.isIdentifier(target)) {
          let targetSymbol = checker.getSymbolAtLocation(target);
          if (targetSymbol?.flags && targetSymbol.flags & ts.SymbolFlags.Alias) {
            targetSymbol = checker.getAliasedSymbol(targetSymbol);
          }
          return targetSymbol === symbol;
        }
        if (ts.isPropertyAccessExpression(target) || ts.isElementAccessExpression(target)) return false;
        if (ts.isSpreadElement(target) || ts.isSpreadAssignment(target)) {
          return targetsSymbol(target.expression);
        }
        if (ts.isBindingElement(target)) return targetsSymbol(target.name);
        if (ts.isVariableDeclaration(target)) return targetsSymbol(target.name);
        if (ts.isVariableDeclarationList(target)) return target.declarations.some(targetsSymbol);
        if (ts.isArrayLiteralExpression(target) || ts.isArrayBindingPattern(target)) {
          return target.elements.some((element) => !ts.isOmittedExpression(element)
            && targetsSymbol(element));
        }
        if (ts.isObjectBindingPattern(target)) return target.elements.some(targetsSymbol);
        if (ts.isObjectLiteralExpression(target)) {
          return target.properties.some((property) => ts.isShorthandPropertyAssignment(property)
            ? targetsSymbol(property.name)
            : ts.isPropertyAssignment(property) ? targetsSymbol(property.initializer)
              : ts.isSpreadAssignment(property) ? targetsSymbol(property.expression) : false);
        }
        return false;
      };
      let delayed = false;
      let ancestor: ts.Node = node;
      while (!ts.isSourceFile(ancestor.parent)) {
        ancestor = ancestor.parent;
        delayed ||= ts.isFunctionLike(ancestor) || ts.isClassLike(ancestor);
      }
      if (delayed) {
        resolving.delete(symbol);
        return true;
      }
      for (const sourceFile of projectSources ?? [node.getSourceFile()]) {
        const nodes: ts.Node[] = [sourceFile];
        while (nodes.length > 0) {
          const candidate = nodes.pop()!;
          check();
          if (ts.isBinaryExpression(candidate)
            && candidate.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
            && candidate.operatorToken.kind <= ts.SyntaxKind.LastAssignment
            && targetsSymbol(candidate.left) && !staticallyUnreachable(candidate, depth, bindings)) {
              const direct = candidate.operatorToken.kind === ts.SyntaxKind.EqualsToken
                && ts.isIdentifier(unwrapExpression(candidate.left))
                && ts.isExpressionStatement(candidate.parent)
                && ts.isSourceFile(candidate.parent.parent)
                && candidate.getSourceFile() === node.getSourceFile();
              if (direct && candidate.getStart() < node.getStart()
                && candidate.getStart() > latestStart) {
                latest = candidate.right;
                latestStart = candidate.getStart();
              } else if (!direct) uncertainTarget = true;
          }
          if ((ts.isForOfStatement(candidate) || ts.isForInStatement(candidate))
            && targetsSymbol(candidate.initializer)
            && !staticallyUnreachable(candidate, depth, bindings)) {
            uncertainTarget = true;
          }
          ts.forEachChild(candidate, (child) => { nodes.push(child); });
        }
      }
      const result = uncertainTarget || Boolean(latest && resolve(latest, depth + 1, bindings));
      resolving.delete(symbol);
      return result;
    }
    if (!declaration.initializer) return false;
    resolving.add(symbol);
    const result = resolve(declaration.initializer, depth + 1, bindings);
    resolving.delete(symbol);
    return result;
  };
  return resolve(expression, 0, new Map());
}

export function isStaticShorthandSymbolFrom(
  shorthand: ts.ShorthandPropertyAssignment,
  checker: ts.TypeChecker,
  check: () => void,
  moduleName: string,
  importedName: string,
  projectSources?: ReadonlySet<ts.SourceFile>,
): boolean {
  const symbol = checker.getShorthandAssignmentValueSymbol(shorthand);
  if (!symbol) return false;
  const target = symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
  if (isResolvedSymbolFrom(target, shorthand, moduleName, importedName)) return true;
  const binding = target.declarations?.find((candidate): candidate is ts.BindingElement => (
    ts.isBindingElement(candidate)
  ));
  if (binding && !ts.isIdentifier(binding.name)) return true;
  const expression = binding && ts.isIdentifier(binding.name) ? binding.name : shorthand.name;
  return containsStaticSymbolFrom(
    expression, checker, check, moduleName, importedName, projectSources,
  );
}

export function isNestJsUseGlobalGuardsCall(
  call: ts.CallExpression,
  checker: ts.TypeChecker,
  check: () => void,
  projectSources?: ReadonlySet<ts.SourceFile>,
): boolean {
  const writeIndex = projectSources
    ? callableWriteIndex(projectSources, checker, check) : new Map<ts.Symbol, readonly CallableWriteRecord[]>();
  const resolveUnmodifiedAlias = (input: ts.Expression): ts.Expression => {
    const seen = new Set<ts.Symbol>();
    let value = unwrapExpression(input);
    while (ts.isIdentifier(value)) {
      check();
      let symbol = checker.getSymbolAtLocation(value);
      if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
      if (!symbol || seen.has(symbol) || seen.size >= 64) break;
      seen.add(symbol);
      const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
      const declaration = declarations.length === 1 ? declarations[0] : undefined;
      if (!declaration?.initializer || (projectSources
        && !projectSources.has(declaration.getSourceFile()))
        || !ts.isVariableDeclarationList(declaration.parent)
        || (!(declaration.parent.flags & ts.NodeFlags.Const)
          && (writeIndex.get(symbol)?.length ?? 0) > 0)) break;
      value = unwrapExpression(declaration.initializer);
    }
    return value;
  };
  const canonicalGuardMember = (input: ts.Expression): boolean => {
    const value = resolveUnmodifiedAlias(input);
    const property = ts.isPropertyAccessExpression(value) ? value.name.text
      : ts.isElementAccessExpression(value) && value.argumentExpression
        ? resolveStaticPropertyKey(value.argumentExpression, checker, check) : undefined;
    if (property !== 'useGlobalGuards'
      || (!ts.isPropertyAccessExpression(value) && !ts.isElementAccessExpression(value))) return false;
    const symbol = checker.getNonNullableType(checker.getTypeAtLocation(value.expression)).getProperty(property);
    return matchesConsumerModule(value, symbol, '@nestjs/common')
      || matchesConsumerModule(value, symbol, '@nestjs/core');
  };
  const canonicalExpressionMemo = new WeakMap<ts.Node, boolean | 'visiting'>();
  const canonicalSymbolMemo = new Map<ts.Symbol, boolean | 'visiting'>();
  const canonicalAliasEvidence = (input: ts.Expression, depth = 0): boolean => {
    check();
    if (depth >= 64) return true;
    const value = unwrapExpression(input);
    const cachedExpression = canonicalExpressionMemo.get(value);
    if (cachedExpression !== undefined) return cachedExpression === 'visiting' ? false : cachedExpression;
    canonicalExpressionMemo.set(value, 'visiting');
    let result = canonicalGuardMember(value);
    if (!result && ts.isArrayLiteralExpression(value)) result = value.elements.some((element) => (
      !ts.isOmittedExpression(element) && canonicalAliasEvidence(
        ts.isSpreadElement(element) ? element.expression : element, depth + 1,
      )
    ));
    if (!result && ts.isObjectLiteralExpression(value)) result = value.properties.some((property) => {
      const candidate = ts.isPropertyAssignment(property) ? property.initializer
        : ts.isShorthandPropertyAssignment(property) ? property.name
          : ts.isSpreadAssignment(property) ? property.expression : undefined;
      return Boolean(candidate && canonicalAliasEvidence(candidate, depth + 1));
    });
    if (ts.isConditionalExpression(value)) {
      result ||= canonicalAliasEvidence(value.whenTrue, depth + 1)
        || canonicalAliasEvidence(value.whenFalse, depth + 1);
    }
    if (ts.isBinaryExpression(value)) {
      result ||= canonicalAliasEvidence(value.left, depth + 1)
        || canonicalAliasEvidence(value.right, depth + 1);
    }
    if (!result && ts.isIdentifier(value)) {
      let symbol = checker.getSymbolAtLocation(value);
      if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
      if (symbol) {
        const cachedSymbol = canonicalSymbolMemo.get(symbol);
        if (cachedSymbol !== undefined) result = cachedSymbol === 'visiting' ? false : cachedSymbol;
        else {
          canonicalSymbolMemo.set(symbol, 'visiting');
          const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
          const declaration = declarations.length === 1 ? declarations[0] : undefined;
          result = Boolean(declaration?.initializer && (!projectSources
            || projectSources.has(declaration.getSourceFile()))
            && canonicalAliasEvidence(declaration.initializer, depth + 1))
            || (writeIndex.get(symbol) ?? []).some((record) => Boolean(record.uncertainCanonical
              || (record.value && canonicalAliasEvidence(record.value, depth + 1))));
          canonicalSymbolMemo.set(symbol, result);
        }
      }
    }
    canonicalExpressionMemo.set(value, result);
    return result;
  };
  const callStatement = ts.isExpressionStatement(call.parent)
    && ts.isSourceFile(call.parent.parent) ? call.parent : undefined;
  const mutableAssignmentsAtCall = (symbol: ts.Symbol): {
    latest?: ts.Expression;
    ambiguous: boolean;
    canonicalCandidate: boolean;
  } => {
    let latest: ts.Expression | undefined;
    let latestStart = -1;
    let ambiguous = !callStatement;
    let canonicalCandidate = false;
    for (const record of writeIndex.get(symbol) ?? []) {
      canonicalCandidate ||= Boolean(record.uncertainCanonical
        || (record.value && canonicalAliasEvidence(record.value)));
      const direct = record.directTopLevel && callStatement
        && record.sourceFile === call.getSourceFile();
      if (direct && record.start < call.getStart()) {
        if (record.start > latestStart && record.value) {
          latest = record.value;
          latestStart = record.start;
        }
      } else if (!(direct && record.start > call.getStart())) {
        ambiguous = true;
      }
    }
    return { ...(latest ? { latest } : {}), ambiguous, canonicalCandidate };
  };
  let uncertainCanonicalAlias = false;
  const resolveStableInitializer = (input: ts.Expression): ts.Expression => {
    const seen = new Set<ts.Symbol>();
    let value = unwrapExpression(input);
    while (ts.isIdentifier(value)) {
      check();
      let symbol = checker.getSymbolAtLocation(value);
      if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
      if (!symbol || seen.has(symbol)) break;
      seen.add(symbol);
      const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
      const declaration = declarations.length === 1 ? declarations[0] : undefined;
      if (!declaration?.initializer || (projectSources
        && !projectSources.has(declaration.getSourceFile()))
        || !ts.isVariableDeclarationList(declaration.parent)) break;
      if (declaration.parent.flags & ts.NodeFlags.Const) {
        value = unwrapExpression(declaration.initializer);
        continue;
      }
      if (!projectSources) break;
      const assignments = mutableAssignmentsAtCall(symbol);
      if (assignments.ambiguous) {
        uncertainCanonicalAlias ||= canonicalAliasEvidence(declaration.initializer)
          || assignments.canonicalCandidate;
        break;
      }
      value = unwrapExpression(assignments.latest ?? declaration.initializer);
    }
    return value;
  };
  const flattenArguments = (args: readonly ts.Expression[]): ts.Expression[] | undefined => {
    const pending = [...args];
    const flattened: ts.Expression[] = [];
    let steps = 0;
    while (pending.length > 0) {
      check();
      if (steps++ >= 64) return undefined;
      const argument = pending.shift()!;
      if (!ts.isSpreadElement(argument)) {
        flattened.push(argument);
        continue;
      }
      const spread = unwrapExpression(argument.expression);
      if (!ts.isArrayLiteralExpression(spread)) return undefined;
      if (spread.elements.some(ts.isOmittedExpression)) return undefined;
      pending.unshift(...spread.elements.filter((element): element is ts.Expression => (
        !ts.isOmittedExpression(element)
      )));
    }
    return flattened;
  };
  const isDefinitelyNullish = (input: ts.Expression): boolean => {
    const value = unwrapExpression(input);
    if (value.kind === ts.SyntaxKind.NullKeyword || ts.isVoidExpression(value)) return true;
    return ts.isIdentifier(value) && value.text === 'undefined'
      && !checker.getSymbolAtLocation(value)?.declarations?.length;
  };
  let effectiveArguments = flattenArguments(call.arguments);
  let expression = resolveStableInitializer(call.expression);
  const reflectCall = unwrapExpression(call.expression);
  const reflectMethod = ts.isPropertyAccessExpression(reflectCall) ? reflectCall.name.text
    : ts.isElementAccessExpression(reflectCall) && reflectCall.argumentExpression
      ? resolveStaticPropertyKey(reflectCall.argumentExpression, checker, check) : undefined;
  const reflectReceiver = (ts.isPropertyAccessExpression(reflectCall)
    || ts.isElementAccessExpression(reflectCall))
    ? unwrapExpression(reflectCall.expression) : undefined;
  const reflectSymbol = reflectReceiver && ts.isIdentifier(reflectReceiver)
    ? checker.getSymbolAtLocation(reflectReceiver) : undefined;
  const standardReflectApply = reflectMethod === 'apply' && reflectReceiver
    && ts.isIdentifier(reflectReceiver) && reflectReceiver.text === 'Reflect'
    && !reflectSymbol?.declarations?.some((declaration) => (
      projectSources?.has(declaration.getSourceFile())
    ));
  if (standardReflectApply && call.arguments[0]) {
    expression = resolveStableInitializer(call.arguments[0]);
    const guards = call.arguments[2] ? unwrapExpression(call.arguments[2]) : undefined;
    effectiveArguments = guards && ts.isArrayLiteralExpression(guards)
      ? guards.elements.some(ts.isOmittedExpression) ? undefined
        : flattenArguments(guards.elements.filter((element): element is ts.Expression => (
          !ts.isOmittedExpression(element)
        ))) : guards ? undefined : [];
  }
  let depthLimitReached = false;
  for (let depth = 0; depth <= 64; depth += 1) {
    check();
    if (depth === 64) {
      depthLimitReached = true;
      break;
    }
    if (ts.isCallExpression(expression)) {
      const bind = unwrapExpression(expression.expression);
      const bindName = ts.isPropertyAccessExpression(bind) ? bind.name.text
        : ts.isElementAccessExpression(bind) && bind.argumentExpression
          ? resolveStaticPropertyKey(bind.argumentExpression, checker, check) : undefined;
      if (bindName === 'bind'
        && (ts.isPropertyAccessExpression(bind) || ts.isElementAccessExpression(bind))) {
        const bound = flattenArguments(expression.arguments.slice(1));
        effectiveArguments = bound && effectiveArguments
          ? [...bound, ...effectiveArguments] : undefined;
        expression = resolveStableInitializer(bind.expression);
        continue;
      }
    }
    const invocation = ts.isPropertyAccessExpression(expression) ? expression.name.text
      : ts.isElementAccessExpression(expression) && expression.argumentExpression
        ? resolveStaticPropertyKey(expression.argumentExpression, checker, check) : undefined;
    if ((invocation === 'call' || invocation === 'apply')
      && (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression))) {
      if (invocation === 'call') {
        effectiveArguments = effectiveArguments?.slice(1);
      } else if (effectiveArguments) {
        const argument = effectiveArguments[1];
        if (!argument || isDefinitelyNullish(argument)) effectiveArguments = [];
        else {
          const guards = unwrapExpression(argument);
          effectiveArguments = ts.isArrayLiteralExpression(guards)
            ? guards.elements.some(ts.isOmittedExpression) ? undefined
              : flattenArguments(guards.elements.filter((element): element is ts.Expression => (
                !ts.isOmittedExpression(element)
              ))) : undefined;
        }
      }
      expression = resolveStableInitializer(expression.expression);
      continue;
    }
    break;
  }
  if (depthLimitReached) {
    const nodes: ts.Node[] = [expression];
    let steps = 0;
    while (nodes.length > 0 && steps++ < 4096) {
      check();
      const node = nodes.pop()!;
      if (ts.isCallExpression(node)) {
        nodes.push(node.expression);
        continue;
      }
      if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
        const key = ts.isPropertyAccessExpression(node) ? node.name.text
          : node.argumentExpression
            ? resolveStaticPropertyKey(node.argumentExpression, checker, check) : undefined;
        if (key === 'useGlobalGuards') {
          const symbol = checker.getNonNullableType(
            checker.getTypeAtLocation(node.expression),
          ).getProperty(key);
          if (matchesConsumerModule(node, symbol, '@nestjs/common')
            || matchesConsumerModule(node, symbol, '@nestjs/core')) return true;
        }
        nodes.push(node.expression);
        continue;
      } else if (ts.isIdentifier(node)) {
        const resolved = resolveStableInitializer(node);
        if (resolved !== node) nodes.push(resolved);
        const binding = checker.getSymbolAtLocation(node)?.declarations?.find(ts.isBindingElement);
        const pattern = binding?.parent;
        const declaration = pattern && ts.isObjectBindingPattern(pattern)
          && ts.isVariableDeclaration(pattern.parent) ? pattern.parent : undefined;
        const key = binding?.propertyName && (ts.isIdentifier(binding.propertyName)
          || ts.isStringLiteral(binding.propertyName))
          ? binding.propertyName.text
          : binding && ts.isIdentifier(binding.name) ? binding.name.text : undefined;
        if (key === 'useGlobalGuards' && declaration?.initializer) {
          const bindingSymbol = checker.getSymbolAtLocation(node);
          if (!bindingSymbol || !projectSources || callableBindingMayBeWritten(
            bindingSymbol, bindingSymbol.declarations ?? [], checker, projectSources, check,
          )) continue;
          const symbol = checker.getNonNullableType(
            checker.getTypeAtLocation(declaration.initializer),
          ).getProperty(key);
          if (matchesConsumerModule(node, symbol, '@nestjs/common')
            || matchesConsumerModule(node, symbol, '@nestjs/core')) return true;
        }
        continue;
      }
      ts.forEachChild(node, (child) => { nodes.push(child); });
    }
    return nodes.length > 0;
  }
  let property = ts.isPropertyAccessExpression(expression)
    ? expression.name.text
    : ts.isElementAccessExpression(expression) && expression.argumentExpression
      ? resolveStaticPropertyKey(expression.argumentExpression, checker, check)
      : undefined;
  let receiver: ts.Expression | undefined = (ts.isPropertyAccessExpression(expression)
    || ts.isElementAccessExpression(expression))
    ? expression.expression : undefined;
  const hasGuardArgument = !effectiveArguments || effectiveArguments.length > 0;
  if (uncertainCanonicalAlias && hasGuardArgument) return true;
  if (!receiver && ts.isIdentifier(expression)) {
    const binding = checker.getSymbolAtLocation(expression)?.declarations?.find(ts.isBindingElement);
    const pattern = binding?.parent;
    const declaration = pattern && ts.isObjectBindingPattern(pattern)
      && ts.isVariableDeclaration(pattern.parent) ? pattern.parent : undefined;
    if (binding && declaration?.initializer && ts.isVariableDeclarationList(declaration.parent)) {
      const bindingSymbol = checker.getSymbolAtLocation(expression);
      property = binding.propertyName && (ts.isIdentifier(binding.propertyName)
        || ts.isStringLiteral(binding.propertyName))
        ? binding.propertyName.text : ts.isIdentifier(binding.name) ? binding.name.text : undefined;
      receiver = declaration.initializer;
      if (!bindingSymbol || !projectSources) return false;
      if (callableBindingMayBeWritten(
        bindingSymbol, bindingSymbol.declarations ?? [], checker, projectSources, check,
      )) {
        const assignments = mutableAssignmentsAtCall(bindingSymbol);
        if (assignments.ambiguous) {
          const symbol = property ? checker.getNonNullableType(
            checker.getTypeAtLocation(receiver),
          ).getProperty(property) : undefined;
          return hasGuardArgument && Boolean(property === 'useGlobalGuards'
            && (matchesConsumerModule(expression, symbol, '@nestjs/common')
              || matchesConsumerModule(expression, symbol, '@nestjs/core')
              || assignments.canonicalCandidate));
        }
        if (assignments.latest) return hasGuardArgument && canonicalGuardMember(assignments.latest);
      }
    }
  }
  if (!hasGuardArgument || property !== 'useGlobalGuards' || !receiver) return false;
  const symbol = checker.getNonNullableType(checker.getTypeAtLocation(receiver)).getProperty(property);
  return matchesConsumerModule(expression, symbol, '@nestjs/common')
    || matchesConsumerModule(expression, symbol, '@nestjs/core');
}
