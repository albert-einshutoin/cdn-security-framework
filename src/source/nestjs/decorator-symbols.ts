import path from 'node:path';

import ts from 'typescript';

export const NESTJS_ROUTE_DECORATORS = [
  'All', 'Controller', 'Delete', 'Get', 'Head', 'Options', 'Patch', 'Post', 'Put', 'Version',
] as const;

export type NestJsRouteDecorator = typeof NESTJS_ROUTE_DECORATORS[number];

function targetSymbol(node: ts.Expression, checker: ts.TypeChecker): ts.Symbol | undefined {
  const location = ts.isPropertyAccessExpression(node) ? node.name : node;
  const symbol = checker.getSymbolAtLocation(location);
  if (!symbol) return undefined;
  return symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
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

function originatesFromNestJsCommon(
  node: ts.Expression,
  symbol: ts.Symbol | undefined,
  checker: ts.TypeChecker,
): boolean {
  const importSymbol = checker.getSymbolAtLocation(ts.isPropertyAccessExpression(node) ? node.expression : node);
  const sourceFile = importSymbol?.declarations?.[0]?.getSourceFile();
  if (!sourceFile) return false;
  return Boolean(symbol?.declarations?.some((declaration) => {
    const target = path.resolve(declaration.getSourceFile().fileName);
    let directory = path.dirname(path.resolve(sourceFile.fileName));
    while (true) {
      const packageRoot = path.join(directory, 'node_modules', '@nestjs', 'common');
      if (target === packageRoot || target.startsWith(`${packageRoot}${path.sep}`)) return true;
      const parent = path.dirname(directory);
      if (parent === directory) return false;
      directory = parent;
    }
  }));
}

function match(
  decorator: ts.Decorator,
  checker: ts.TypeChecker,
): { name: NestJsRouteDecorator; call: ts.CallExpression; trusted: boolean } | undefined {
  if (!ts.isCallExpression(decorator.expression)) return undefined;
  const symbol = targetSymbol(decorator.expression.expression, checker);
  const name = symbol?.getName() as NestJsRouteDecorator | undefined;
  if (!name || !NESTJS_ROUTE_DECORATORS.includes(name)) return undefined;
  return {
    name,
    call: decorator.expression,
    trusted: directNestJsImport(decorator.expression.expression, checker)
      && originatesFromNestJsCommon(decorator.expression.expression, symbol, checker),
  };
}

export function nestJsRouteDecorator(
  decorator: ts.Decorator,
  checker: ts.TypeChecker,
): { name: NestJsRouteDecorator; call: ts.CallExpression } | undefined {
  const result = match(decorator, checker);
  return result?.trusted ? { name: result.name, call: result.call } : undefined;
}

export function isUnsupportedNestJsDecorator(
  decorator: ts.Decorator,
  checker: ts.TypeChecker,
): boolean {
  const result = match(decorator, checker);
  return Boolean(result && !result.trusted);
}
