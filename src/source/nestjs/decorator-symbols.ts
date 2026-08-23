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

function unwrapExpression(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (ts.isParenthesizedExpression(current) || ts.isAsExpression(current)
    || ts.isTypeAssertionExpression(current) || ts.isSatisfiesExpression(current)
    || ts.isNonNullExpression(current)) current = current.expression;
  return current;
}

function staticPropertyKey(
  input: ts.Expression,
  checker: ts.TypeChecker,
  check: () => void,
): string | undefined {
  const seen = new Set<ts.Symbol>();
  let current = input;
  while (true) {
    check();
    const expression = unwrapExpression(current);
    if (ts.isStringLiteral(expression) || ts.isNumericLiteral(expression)
      || ts.isNoSubstitutionTemplateLiteral(expression)) return expression.text;
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
      ? staticPropertyKey(current.argumentExpression, checker, check)
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
): {
  name: string;
  call: ts.CallExpression;
  nestJsCommon: boolean;
  trustedNestJsCommon: boolean;
} | undefined {
  const expression = unwrapExpression(decorator.expression);
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

export function resolveDecoratorCallSymbol(
  call: ts.CallExpression,
  checker: ts.TypeChecker,
  check: () => void,
): {
  name: string;
  call: ts.CallExpression;
  nestJsCommon: boolean;
  trustedNestJsCommon: boolean;
} | undefined {
  const symbol = targetSymbol(call.expression, checker, check);
  if (!symbol || symbol === UNKNOWN_NESTJS_ROUTE) {
    return !symbol && ts.isElementAccessExpression(unwrapExpression(call.expression))
      ? { name: '', call, nestJsCommon: false, trustedNestJsCommon: false }
      : undefined;
  }
  const nestJsCommon = originatesFromNestJsCommon(symbol);
  return {
    name: symbol.getName(),
    call,
    nestJsCommon,
    trustedNestJsCommon: nestJsCommon && directNestJsImport(call.expression, checker)
      && matchesConsumerNestJsCommon(call.expression, symbol),
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
    && declaration && ts.isVariableDeclaration(declaration)
    && ts.isVariableDeclarationList(declaration.parent)
    && declaration.parent.flags & ts.NodeFlags.Const);
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
    if (ts.isFunctionLike(expression) || ts.isClassLike(expression)) return undefined;
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
): string | undefined {
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

export function isStaticShorthandSymbolFrom(
  shorthand: ts.ShorthandPropertyAssignment,
  checker: ts.TypeChecker,
  check: () => void,
  moduleName: string,
  importedName: string,
): boolean {
  const symbol = checker.getShorthandAssignmentValueSymbol(shorthand);
  if (!symbol) return false;
  const target = symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
  if (isResolvedSymbolFrom(target, shorthand, moduleName, importedName)) return true;
  const declaration = symbol.declarations?.find((candidate): candidate is ts.VariableDeclaration => (
    ts.isVariableDeclaration(candidate) && candidate.initializer !== undefined
    && ts.isVariableDeclarationList(candidate.parent)
    && Boolean(candidate.parent.flags & ts.NodeFlags.Const)
  ));
  return Boolean(declaration?.initializer && isStaticSymbolFrom(
    declaration.initializer, checker, check, moduleName, importedName,
  ));
}

export function isNestJsUseGlobalGuardsCall(
  call: ts.CallExpression,
  checker: ts.TypeChecker,
): boolean {
  if (!ts.isPropertyAccessExpression(call.expression)
    || call.expression.name.text !== 'useGlobalGuards') {
    return false;
  }
  const symbol = checker.getSymbolAtLocation(call.expression.name);
  return matchesConsumerModule(call.expression, symbol, '@nestjs/common')
    || matchesConsumerModule(call.expression, symbol, '@nestjs/core');
}
