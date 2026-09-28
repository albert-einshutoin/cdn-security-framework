import { createHash } from 'node:crypto';
import path from 'node:path';

import ts from 'typescript';

import { SourceAnalyzerContractError } from '../../source-analysis';
import {
  strategyNameIsSafe,
  type PassportStrategyDefinition,
  type PassportStrategyProvider,
} from '../../contract/passport-strategy-observation';
import { isDirectImportedSymbolFrom, isStaticSymbolFrom } from './decorator-symbols';

function location(node: ts.Node, root: string) {
  const file = node.getSourceFile();
  const point = file.getLineAndCharacterOfPosition(node.getStart(file));
  return { sourceUri: path.relative(root, file.fileName).replaceAll('\\', '/'),
    line: point.line + 1, column: point.character + 1,
    sourceDigest: `sha256:${createHash('sha256').update(file.text).digest('hex')}` };
}

function identity(kind: string, value: { sourceUri: string; line: number; column: number }) {
  return `sha256:${createHash('sha256').update(JSON.stringify([
    kind, value.sourceUri, value.line, value.column,
  ])).digest('hex')}`;
}

function resolvedSymbol(node: ts.Identifier, checker: ts.TypeChecker): ts.Symbol | undefined {
  let symbol = checker.getSymbolAtLocation(node);
  if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
  return symbol;
}

function isPassportStrategyShape(expression: ts.Expression, checker: ts.TypeChecker): boolean {
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text === 'PassportStrategy';
  if (!ts.isIdentifier(expression)) return false;
  if (expression.text === 'PassportStrategy') return true;
  return checker.getSymbolAtLocation(expression)?.declarations?.some((declaration) => (
    ts.isImportSpecifier(declaration)
    && (declaration.propertyName?.text ?? declaration.name.text) === 'PassportStrategy'
  )) ?? false;
}

function directImportedValue(
  expression: ts.Expression, checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>, check: () => void,
  moduleName: string, importedName: string,
): boolean {
  if (ts.isIdentifier(expression)) {
    if (!isDirectImportedSymbolFrom(expression, checker, check,
      moduleName, importedName, projectSources)) return false;
    if (moduleName !== 'passport-jwt' || importedName !== 'ExtractJwt') return true;
    const binding = checker.getSymbolAtLocation(expression);
    if (!binding) return false;
    for (const file of projectSources) {
      const nodes: ts.Node[] = [file];
      while (nodes.length) {
        const node = nodes.pop()!;
        check();
        if (ts.isIdentifier(node) && checker.getSymbolAtLocation(node) === binding
          && !ts.isImportSpecifier(node.parent)) {
          const member = node.parent;
          if (!ts.isPropertyAccessExpression(member) || member.expression !== node
            || member.name.text !== 'fromAuthHeaderAsBearerToken'
            || !ts.isCallExpression(member.parent) || member.parent.expression !== member) return false;
        }
        ts.forEachChild(node, child => { nodes.push(child); });
      }
    }
    return true;
  }
  if (!ts.isPropertyAccessExpression(expression) || expression.name.text !== importedName
    || !ts.isIdentifier(expression.expression)) return false;
  const binding = checker.getSymbolAtLocation(expression.expression);
  const directNamespace = binding?.declarations?.some((declaration) => {
    if (!ts.isNamespaceImport(declaration)
      || !ts.isImportClause(declaration.parent)
      || !ts.isImportDeclaration(declaration.parent.parent)) return false;
    const specifier = declaration.parent.parent.moduleSpecifier;
    return ts.isStringLiteral(specifier) && specifier.text === moduleName;
  });
  if (!directNamespace || !isStaticSymbolFrom(expression, checker, check,
    moduleName, importedName)) return false;
  // A namespace is stable for this bounded observation only while every use
  // remains a direct read of the supported member syntax. Escapes and writes
  // cannot be treated as genuine static bindings.
  for (const file of projectSources) {
    const nodes: ts.Node[] = [file];
    while (nodes.length) {
      const node = nodes.pop()!;
      check();
      if (ts.isIdentifier(node) && checker.getSymbolAtLocation(node) === binding
        && !(ts.isNamespaceImport(node.parent) && node.parent.name === node)) {
        const member = node.parent;
        if (!ts.isPropertyAccessExpression(member) || member.expression !== node) return false;
        if (moduleName === '@nestjs/passport') {
          if (!['AuthGuard', 'PassportStrategy'].includes(member.name.text)
            || !ts.isCallExpression(member.parent) || member.parent.expression !== member) return false;
        } else if (moduleName === 'passport-jwt') {
          if (member.name.text === 'Strategy') {
            if (!ts.isCallExpression(member.parent)
              || !member.parent.arguments.includes(member)) return false;
          } else if (member.name.text === 'ExtractJwt') {
            const method = member.parent;
            if (!ts.isPropertyAccessExpression(method) || method.expression !== member
              || method.name.text !== 'fromAuthHeaderAsBearerToken'
              || !ts.isCallExpression(method.parent) || method.parent.expression !== method) return false;
          } else return false;
        } else return false;
      }
      ts.forEachChild(node, child => { nodes.push(child); });
    }
  }
  return true;
}

function directBearerExtractor(
  declaration: ts.ClassDeclaration, checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>, check: () => void, root: string,
): PassportStrategyDefinition['extractor'] {
  const constructors = declaration.members.filter(ts.isConstructorDeclaration);
  const body = constructors.length === 1 ? constructors[0].body : undefined;
  if (!body) return { status: 'unconfirmed' };
  const superCalls: ts.CallExpression[] = [];
  const visit = (node: ts.Node) => {
    check();
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.SuperKeyword) {
      superCalls.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(body);
  if (superCalls.length !== 1 || !ts.isExpressionStatement(superCalls[0].parent)
    || superCalls[0].parent.parent !== body || superCalls[0].arguments.length !== 1
    || !ts.isObjectLiteralExpression(superCalls[0].arguments[0])) return { status: 'unconfirmed' };
  const object = superCalls[0].arguments[0];
  if (object.properties.some((property) => ts.isSpreadAssignment(property)
    || ts.isGetAccessorDeclaration(property) || ts.isSetAccessorDeclaration(property)
    || 'name' in property && ts.isComputedPropertyName(property.name))) return { status: 'unconfirmed' };
  const properties = object.properties.filter((property) => 'name' in property && property.name
    && (ts.isIdentifier(property.name) || ts.isStringLiteral(property.name))
    && property.name.text === 'jwtFromRequest');
  if (properties.length !== 1 || !ts.isPropertyAssignment(properties[0])) return { status: 'unconfirmed' };
  const value = properties[0].initializer;
  if (!ts.isCallExpression(value) || value.arguments.length !== 0
    || !ts.isPropertyAccessExpression(value.expression)
    || value.expression.name.text !== 'fromAuthHeaderAsBearerToken'
    || !directImportedValue(value.expression.expression, checker, projectSources, check,
      'passport-jwt', 'ExtractJwt')) return { status: 'unconfirmed' };
  const at = location(value, root);
  return { status: 'observed', kind: 'bearer-header-call', id: identity('extractor', at), ...at };
}

export function createPassportStrategyCollector(
  checker: ts.TypeChecker, projectSources: ReadonlySet<ts.SourceFile>,
  root: string, check: () => void, limit: number,
) {
  const definitions: PassportStrategyDefinition[] = [];
  let incompleteDefinitionNames = 0;
  const definitionSymbols = new Map<ts.Symbol, string>();
  const directProviders: Array<{ element: ts.Identifier; moduleClass: string }> = [];
  const visit = (node: ts.Node) => {
    check();
    if (ts.isClassDeclaration(node) && node.name) {
      const heritage = node.heritageClauses?.find(({ token }) => token === ts.SyntaxKind.ExtendsKeyword);
      const base = heritage?.types.length === 1 ? heritage.types[0] : undefined;
      if (base && ts.isCallExpression(base.expression)
        && isPassportStrategyShape(base.expression.expression, checker)) {
        if (base.expression.arguments.length !== 2
          || !ts.isStringLiteral(base.expression.arguments[1])
          || !strategyNameIsSafe(base.expression.arguments[1].text)) {
          incompleteDefinitionNames += 1;
        } else {
          const factoryVerified = directImportedValue(base.expression.expression,
            checker, projectSources, check, '@nestjs/passport', 'PassportStrategy');
          const strategyVerified = directImportedValue(base.expression.arguments[0],
            checker, projectSources, check, 'passport-jwt', 'Strategy');
          const at = location(node.name, root);
          const id = identity('definition', at);
          definitions.push({ id, strategy: base.expression.arguments[1].text,
            className: node.name.text, ...at,
            baseStatus: factoryVerified && strategyVerified ? 'verified' : 'unverified',
            ...(factoryVerified && strategyVerified ? { baseModule: 'passport-jwt' as const } : {}),
            extractor: factoryVerified && strategyVerified
              ? directBearerExtractor(node, checker, projectSources, check, root)
              : { status: 'unconfirmed' },
          });
          const symbol = resolvedSymbol(node.name, checker);
          if (symbol) definitionSymbols.set(symbol, id);
        }
      }
      for (const decorator of ts.getDecorators(node) ?? []) {
        if (!ts.isCallExpression(decorator.expression)
          || decorator.expression.arguments.length !== 1
          || !ts.isObjectLiteralExpression(decorator.expression.arguments[0])
          || !isDirectImportedSymbolFrom(decorator.expression.expression,
            checker, check, '@nestjs/common', 'Module', projectSources)) continue;
        const members = decorator.expression.arguments[0].properties;
        if (members.some((member) => ts.isSpreadAssignment(member)
          || 'name' in member && ts.isComputedPropertyName(member.name)
          || ts.isGetAccessorDeclaration(member) || ts.isSetAccessorDeclaration(member))) continue;
        const providers = members.filter((member) => 'name' in member && member.name
          && (ts.isIdentifier(member.name) || ts.isStringLiteral(member.name))
          && member.name.text === 'providers');
        if (providers.length !== 1 || !ts.isPropertyAssignment(providers[0])
          || !ts.isArrayLiteralExpression(providers[0].initializer)
          || providers[0].initializer.elements.some(ts.isSpreadElement)) continue;
        for (const element of providers[0].initializer.elements) {
          if (ts.isIdentifier(element)) directProviders.push({ element, moduleClass: node.name.text });
        }
      }
    }
    if (definitions.length + incompleteDefinitionNames > limit || directProviders.length > limit) {
      throw new SourceAnalyzerContractError('SOURCE_ANALYZER_AST_NODE_LIMIT');
    }
  };
  const finish = (): { definitions: PassportStrategyDefinition[];
    providers: PassportStrategyProvider[]; incompleteDefinitionNames: number } => {
    const providers: PassportStrategyProvider[] = [];
    for (const { element, moduleClass } of directProviders) {
      check();
      const symbol = resolvedSymbol(element, checker);
      const definitionId = symbol && definitionSymbols.get(symbol);
      if (!definitionId) continue;
      const at = location(element, root);
      providers.push({ id: identity('provider', at), definitionId, moduleClass, ...at });
    }
    return { definitions, providers, incompleteDefinitionNames };
  };
  return { visit, finish };
}
