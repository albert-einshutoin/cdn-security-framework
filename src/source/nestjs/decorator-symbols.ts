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

function targetSymbol(
  node: ts.Expression,
  checker: ts.TypeChecker,
): ts.Symbol | typeof UNKNOWN_NESTJS_ROUTE | undefined {
  const unwrap = (expression: ts.Expression): ts.Expression => {
    let current = expression;
    while (ts.isParenthesizedExpression(current) || ts.isAsExpression(current)
      || ts.isTypeAssertionExpression(current) || ts.isSatisfiesExpression(current)
      || ts.isNonNullExpression(current)) current = current.expression;
    return current;
  };
  const seen = new Set<ts.Symbol>();
  let current = unwrap(node);
  let selected: ts.Symbol | undefined;
  while (true) {
    const location = ts.isPropertyAccessExpression(current) ? current.name : current;
    const symbol = selected ?? checker.getSymbolAtLocation(location);
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
      const initializer = unwrap(alias.initializer);
      if (!ts.isIdentifier(initializer) && !ts.isPropertyAccessExpression(initializer)) return target;
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
    const initializer = unwrap(binding.parent.parent.initializer!);
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

function packageRoot(fileName: string): string | undefined {
  let directory = path.dirname(path.resolve(fileName));
  while (true) {
    if (path.basename(directory) === 'common'
      && path.basename(path.dirname(directory)) === '@nestjs'
      && path.basename(path.dirname(path.dirname(directory))) === 'node_modules') return directory;
    const parent = path.dirname(directory);
    if (parent === directory) return undefined;
    directory = parent;
  }
}

function originatesFromNestJsCommon(symbol: ts.Symbol | undefined): boolean {
  return Boolean(symbol?.declarations?.some((declaration) => {
    const targetRoot = packageRoot(declaration.getSourceFile().fileName);
    if (!targetRoot) return false;
    try {
      const resolvedRoot = packageRoot(createRequire(declaration.getSourceFile().fileName).resolve('@nestjs/common'));
      return resolvedRoot !== undefined && fs.realpathSync(targetRoot) === fs.realpathSync(resolvedRoot);
    } catch { return false; }
  }));
}

function matchesConsumerNestJsCommon(node: ts.Expression, symbol: ts.Symbol | undefined): boolean {
  let resolvedRoot: string | undefined;
  try {
    resolvedRoot = packageRoot(createRequire(node.getSourceFile().fileName).resolve('@nestjs/common'));
  } catch { return false; }
  if (!resolvedRoot) return false;
  return Boolean(symbol?.declarations?.some((declaration) => {
    const targetRoot = packageRoot(declaration.getSourceFile().fileName);
    return targetRoot !== undefined && fs.realpathSync(targetRoot) === fs.realpathSync(resolvedRoot);
  }));
}

function match(
  decorator: ts.Decorator,
  checker: ts.TypeChecker,
): { name: NestJsRouteDecoratorCandidate; call: ts.CallExpression; trusted: boolean; nestJsOrigin: boolean } | undefined {
  if (!ts.isCallExpression(decorator.expression)) return undefined;
  const symbol = targetSymbol(decorator.expression.expression, checker);
  if (symbol === UNKNOWN_NESTJS_ROUTE) {
    return { name: 'Unknown', call: decorator.expression, trusted: false, nestJsOrigin: true };
  }
  const name = symbol?.getName() as NestJsRouteDecorator | undefined;
  if (!name || !NESTJS_ROUTE_DECORATORS.includes(name)) return undefined;
  const nestJsOrigin = originatesFromNestJsCommon(symbol);
  return {
    name,
    call: decorator.expression,
    trusted: directNestJsImport(decorator.expression.expression, checker)
      && matchesConsumerNestJsCommon(decorator.expression.expression, symbol),
    nestJsOrigin,
  };
}

export function nestJsRouteDecoratorCandidate(
  decorator: ts.Decorator,
  checker: ts.TypeChecker,
): { name: NestJsRouteDecoratorCandidate; call: ts.CallExpression; trusted: boolean } | undefined {
  const result = match(decorator, checker);
  return result?.nestJsOrigin
    ? { name: result.name, call: result.call, trusted: result.trusted }
    : undefined;
}

export function nestJsRouteDecorator(
  decorator: ts.Decorator,
  checker: ts.TypeChecker,
): { name: NestJsRouteDecorator; call: ts.CallExpression } | undefined {
  const result = match(decorator, checker);
  return result?.trusted && result.name !== 'Unknown'
    ? { name: result.name, call: result.call }
    : undefined;
}

export function isUnsupportedNestJsDecorator(
  decorator: ts.Decorator,
  checker: ts.TypeChecker,
): boolean {
  const result = match(decorator, checker);
  return Boolean(result && (!result.trusted
    || result.name === 'RequestMapping' || result.name === 'Search' || result.name === 'Version'));
}
