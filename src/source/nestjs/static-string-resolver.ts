import ts from 'typescript';

const MAX_STATIC_VALUES = 128;

export interface StaticStringResolverOptions {
  check?: () => void;
  maxSteps?: number;
  maxStringLength?: number;
}

interface ResolvedStrings {
  values: string[];
  array: boolean;
}

function unwrap(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (ts.isParenthesizedExpression(current)
    || ts.isAsExpression(current)
    || ts.isTypeAssertionExpression(current)
    || ts.isSatisfiesExpression(current)) current = current.expression;
  return current;
}

function isConstDeclaration(declaration: ts.VariableDeclaration): boolean {
  return Boolean(declaration.parent.flags & ts.NodeFlags.Const);
}

function isConstAssertion(expression: ts.Expression): boolean {
  let current = expression;
  while (ts.isParenthesizedExpression(current) || ts.isSatisfiesExpression(current)) current = current.expression;
  return (ts.isAsExpression(current) || ts.isTypeAssertionExpression(current))
    && current.type.getText(current.getSourceFile()) === 'const';
}

function isReadonlyTuple(declaration: ts.VariableDeclaration): boolean {
  return Boolean(declaration.type && ts.isTypeOperatorNode(declaration.type)
    && declaration.type.operator === ts.SyntaxKind.ReadonlyKeyword
    && ts.isTupleTypeNode(declaration.type.type));
}

export function resolveStaticStrings(
  expression: ts.Expression | undefined,
  checker: ts.TypeChecker,
  projectSources: ReadonlySet<ts.SourceFile>,
  options: StaticStringResolverOptions = {},
): string[] | undefined {
  if (!expression) return [''];
  const maxSteps = options.maxSteps ?? 100_000;
  const maxStringLength = options.maxStringLength ?? 16_384;
  const resolving = new Set<ts.Symbol>();
  const memo = new Map<ts.Symbol, ResolvedStrings | null>();
  let steps = 0;

  const resolve = (input: ts.Expression, depth: number): ResolvedStrings | undefined => {
    options.check?.();
    steps += 1;
    if (steps > maxSteps || depth > 64) return undefined;
    const node = unwrap(input);
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      return node.text.length <= maxStringLength ? { values: [node.text], array: false } : undefined;
    }
    if (ts.isArrayLiteralExpression(node)) {
      const values: string[] = [];
      for (const element of node.elements) {
        if (ts.isSpreadElement(element)) return undefined;
        const resolved = resolve(element as ts.Expression, depth + 1);
        if (!resolved || resolved.array) return undefined;
        values.push(...resolved.values);
        if (values.length > MAX_STATIC_VALUES) return undefined;
      }
      return { values, array: true };
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const left = resolve(node.left, depth + 1);
      const right = resolve(node.right, depth + 1);
      if (left?.array || right?.array || left?.values.length !== 1 || right?.values.length !== 1
        || left.values[0].length + right.values[0].length > maxStringLength) return undefined;
      return { values: [`${left.values[0]}${right.values[0]}`], array: false };
    }
    if (!ts.isIdentifier(node)) return undefined;
    let symbol = checker.getSymbolAtLocation(node);
    if (!symbol) return undefined;
    if (symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    if (memo.has(symbol)) return memo.get(symbol) ?? undefined;
    if (resolving.has(symbol)) return undefined;
    const declarations = symbol.declarations?.filter(ts.isVariableDeclaration) ?? [];
    if (declarations.length !== 1 || !isConstDeclaration(declarations[0])
      || !declarations[0].initializer || !projectSources.has(declarations[0].getSourceFile())) return undefined;
    resolving.add(symbol);
    const result = resolve(declarations[0].initializer, depth + 1);
    resolving.delete(symbol);
    const immutable = !result?.array || isConstAssertion(declarations[0].initializer)
      || isReadonlyTuple(declarations[0])
      || ts.isIdentifier(unwrap(declarations[0].initializer));
    const safeResult = result && immutable ? result : undefined;
    memo.set(symbol, safeResult ?? null);
    return safeResult;
  };

  const resolved = resolve(expression, 0);
  return resolved ? [...new Set(resolved.values)] : undefined;
}
