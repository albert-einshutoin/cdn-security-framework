import type { FindingEvidenceV1, SecurityFindingV1 } from '../finding';
import type { ApiOperationContractV1, SecurityContractV1 } from '../security-ir';
import { makeFinding, normalizedPathShape, stableFindings } from './shared';

const MAX_COMPARISON_VISITS = 1_000_000;
const SOURCE_SCOPE = 'Source metadata does not prove Guard runtime behavior.';

export interface SourceOpenApiDriftInput {
  declared: SecurityContractV1;
  implemented: SecurityContractV1;
  declaredEvidence: FindingEvidenceV1;
  implementedEvidence: FindingEvidenceV1;
}

export interface SourceOpenApiDriftOptions {
  declaredPrivilegedRoles?: Readonly<Record<string, readonly string[]>>;
}

interface ComparisonBudget {
  remaining: number;
}

function consumeComparison(budget: ComparisonBudget, count: number): void {
  if (!Number.isSafeInteger(count) || count < 0 || budget.remaining < count) {
    throw new Error('source OpenAPI drift comparison exceeds visit budget');
  }
  budget.remaining -= count;
}

function validateInput(
  input: SourceOpenApiDriftInput,
  options: SourceOpenApiDriftOptions,
): ComparisonBudget {
  if (!input?.declared || !input.implemented || !input.declaredEvidence || !input.implementedEvidence
    || !options || typeof options !== 'object' || Array.isArray(options)
    || input.declared.schemaVersion !== 1 || input.implemented.schemaVersion !== 1
    || input.declared.source !== 'openapi' || input.implemented.source !== 'source-ast'
    || input.declaredEvidence?.source !== 'openapi'
    || input.implementedEvidence?.source !== 'source-ast'
    || !Array.isArray(input.declared.operations) || !Array.isArray(input.implemented.operations)
    || input.declared.operations.length > MAX_COMPARISON_VISITS
    || input.implemented.operations.length > MAX_COMPARISON_VISITS
    || input.declared.operations.length
      > MAX_COMPARISON_VISITS - input.implemented.operations.length) {
    throw new Error('invalid source OpenAPI drift input');
  }
  const budget = { remaining: MAX_COMPARISON_VISITS };
  consumeComparison(budget, input.declared.operations.length + input.implemented.operations.length);
  const validateOperation = (operation: ApiOperationContractV1): void => {
    const roles = operation.auth.analysis?.roles ?? [];
    if (roles.some((role) => typeof role !== 'string' || role.length > 16_384)) {
      throw new Error('invalid source role metadata');
    }
    consumeComparison(budget, operation.provenance.length + operation.auth.alternatives.length
      + (operation.auth.analysis?.guards.length ?? 0) + roles.length);
    for (const alternative of operation.auth.alternatives) {
      consumeComparison(budget, alternative.schemes.length);
    }
  };
  for (const operation of input.declared.operations) validateOperation(operation);
  for (const operation of input.implemented.operations) validateOperation(operation);
  if (options.declaredPrivilegedRoles !== undefined
    && (!options.declaredPrivilegedRoles || typeof options.declaredPrivilegedRoles !== 'object'
      || Array.isArray(options.declaredPrivilegedRoles))) {
    throw new Error('invalid declared privileged roles');
  }
  const rolesByRoute = options.declaredPrivilegedRoles ?? {};
  for (const routeKey in rolesByRoute) {
    if (!Object.hasOwn(rolesByRoute, routeKey)) continue;
    const roles = rolesByRoute[routeKey];
    if (!routeKey || routeKey.length > 16_384
      || !Array.isArray(roles)
      || roles.some((role) => typeof role !== 'string' || role.length > 16_384)) {
      throw new Error('invalid declared privileged roles');
    }
    consumeComparison(budget, roles.length + 1);
  }
  return budget;
}

function groupedByShape(operations: readonly ApiOperationContractV1[]) {
  const groups = new Map<string, ApiOperationContractV1[]>();
  for (const operation of operations) {
    const shape = normalizedPathShape(operation.path);
    const group = groups.get(shape) ?? [];
    group.push(operation);
    groups.set(shape, group);
  }
  return groups;
}

function route(operation: ApiOperationContractV1) {
  return { method: operation.method, path: operation.path, operationId: operation.operationId };
}

function inventoryFindings(input: SourceOpenApiDriftInput): SecurityFindingV1[] {
  const declared = groupedByShape(input.declared.operations);
  const implemented = groupedByShape(input.implemented.operations);
  const findings: SecurityFindingV1[] = [];
  for (const shape of [...new Set([...declared.keys(), ...implemented.keys()])].sort()) {
    const declaredOperations = declared.get(shape) ?? [];
    const implementedOperations = implemented.get(shape) ?? [];
    if (declaredOperations.length === 0) {
      for (const operation of implementedOperations) findings.push(makeFinding({
        ruleId: 'SC-INVENTORY-001',
        severity: input.declared.capabilities.routes === 'complete' ? 'error' : 'warning',
        confidence: input.declared.capabilities.routes === 'complete' ? 'deterministic' : 'heuristic',
        category: 'inventory',
        title: 'Implemented operation is not declared',
        message: 'A statically detected Source operation has no corresponding OpenAPI route shape.',
        route: route(operation),
        expected: { declaredOperation: true },
        actual: { implementedOperation: true },
        evidence: [...operation.provenance, input.declaredEvidence],
        remediation: { summary: 'Declare the operation or remove the unintended implementation.', safeAutoFix: false },
      }));
      continue;
    }
    if (implementedOperations.length === 0) {
      for (const operation of declaredOperations) findings.push(makeFinding({
        ruleId: 'SC-INVENTORY-003',
        severity: input.implemented.capabilities.routes === 'complete' ? 'error' : 'warning',
        confidence: input.implemented.capabilities.routes === 'complete' ? 'deterministic' : 'heuristic',
        category: 'inventory',
        title: 'Declared operation has no statically detected implementation',
        message: input.implemented.capabilities.routes === 'complete'
          ? 'No Source operation matches this OpenAPI route shape.'
          : 'No Source operation was detected, but Source route analysis is incomplete; absence is not proven.',
        route: route(operation),
        expected: { implementedOperation: true },
        actual: { sourceRouteCapability: input.implemented.capabilities.routes },
        evidence: [...operation.provenance, input.implementedEvidence],
        remediation: { summary: 'Implement the operation or remove the stale declaration.', safeAutoFix: false },
      }));
      continue;
    }
    const declaredMethods = [...new Set(declaredOperations.map(({ method }) => method))].sort();
    const implementedMethods = [...new Set(implementedOperations.map(({ method }) => method))].sort();
    if (declaredMethods.join('\0') !== implementedMethods.join('\0')) findings.push(makeFinding({
      ruleId: 'SC-INVENTORY-004',
      severity: input.declared.capabilities.routes === 'complete'
        && input.implemented.capabilities.routes === 'complete' ? 'error' : 'warning',
      confidence: input.declared.capabilities.routes === 'complete'
        && input.implemented.capabilities.routes === 'complete' ? 'deterministic' : 'heuristic',
      category: 'inventory',
      title: 'Implemented and declared methods differ',
      message: 'The same normalized route shape has a different HTTP method set in Source and OpenAPI.',
      route: { path: declaredOperations[0].path },
      expected: { methods: declaredMethods },
      actual: { methods: implementedMethods },
      evidence: [
        ...declaredOperations.flatMap(({ provenance }) => provenance),
        ...implementedOperations.flatMap(({ provenance }) => provenance),
      ],
      remediation: { summary: 'Align the implemented and declared HTTP method sets.', safeAutoFix: false },
    }));
  }
  return findings;
}

function explicitSourceAuth(operation: ApiOperationContractV1) {
  const analysis = operation.auth.analysis;
  if (!analysis || analysis.enforcementConfidence !== 'high') return undefined;
  if (operation.auth.mode === 'none' && analysis.explicitPublic) return { mode: 'public' as const, kinds: [] };
  if (operation.auth.mode !== 'alternatives' || analysis.explicitPublic || analysis.guards.length === 0
    || analysis.guards.some(({ authKind }) => !authKind || authKind === 'unknown')) return undefined;
  return {
    mode: 'authenticated' as const,
    kinds: analysis.guards.map(({ authKind }) => authKind!).sort(),
  };
}

function explicitDeclaredAuth(operation: ApiOperationContractV1) {
  if (operation.exposure === 'public' && (operation.auth.mode === 'none'
    || operation.auth.alternatives.some(({ anonymous }) => anonymous))) {
    return { mode: 'public' as const, kinds: [] };
  }
  if (operation.auth.mode !== 'alternatives' || operation.auth.alternatives.some(
    ({ anonymous, schemes }) => anonymous || schemes.some(
      ({ kind, capability }) => kind === 'unknown' || capability !== 'supported',
    ),
  )) return undefined;
  return {
    mode: 'authenticated' as const,
    alternatives: operation.auth.alternatives.map(({ schemes }) => schemes
      .map(({ kind }) => kind).sort()),
  };
}

function groupedByMethodShape(operations: readonly ApiOperationContractV1[]) {
  const groups = new Map<string, ApiOperationContractV1[]>();
  for (const operation of operations) {
    const key = `${operation.method} ${normalizedPathShape(operation.path)}`;
    const group = groups.get(key) ?? [];
    group.push(operation);
    groups.set(key, group);
  }
  return groups;
}

function authMatches(
  expected: NonNullable<ReturnType<typeof explicitDeclaredAuth>>,
  actual: NonNullable<ReturnType<typeof explicitSourceAuth>>,
): boolean {
  return expected.mode === actual.mode && (expected.mode === 'public'
    || expected.alternatives.some((kinds) => sameStrings(kinds, actual.kinds)));
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function authFindings(input: SourceOpenApiDriftInput, budget: ComparisonBudget): SecurityFindingV1[] {
  if (input.implemented.capabilities.authentication === 'unsupported') return [];
  const implemented = groupedByMethodShape(input.implemented.operations);
  const sourceAuth = new Map(input.implemented.operations.map(
    (operation) => [operation, explicitSourceAuth(operation)] as const,
  ));
  const findings: SecurityFindingV1[] = [];
  for (const declared of input.declared.operations) {
    const sources = implemented.get(`${declared.method} ${normalizedPathShape(declared.path)}`) ?? [];
    const expected = explicitDeclaredAuth(declared);
    if (!expected) continue;
    const expectedWidth = expected.mode === 'authenticated'
      ? expected.alternatives.reduce((total, kinds) => total + kinds.length, 0) : 0;
    const contradictions = sources.flatMap((source) => {
      const actual = sourceAuth.get(source);
      consumeComparison(
        budget,
        1 + source.provenance.length + expectedWidth + 2 * (actual?.kinds.length ?? 0),
      );
      return actual && !authMatches(expected, actual) ? [{ source, actual }] : [];
    });
    if (contradictions.length === 0) continue;
    findings.push(makeFinding({
      ruleId: 'SC-AUTHN-005',
      severity: 'warning',
      confidence: 'high-confidence',
      category: 'authentication',
      title: 'Declared authentication differs from Source metadata',
      message: `Explicit OpenAPI authentication and high-confidence Source decorator metadata differ. ${SOURCE_SCOPE}`,
      route: route(declared),
      expected,
      actual: { candidates: contradictions.map(({ actual }) => actual) },
      evidence: [
        ...declared.provenance,
        ...contradictions.flatMap(({ source }) => source.provenance),
      ],
      remediation: { summary: 'Align the explicit OpenAPI contract and Source auth decorators.', safeAutoFix: false },
    }));
  }
  return findings;
}

function authorizationFindings(
  input: SourceOpenApiDriftInput,
  rolesByRoute: Readonly<Record<string, readonly string[]>> | undefined,
  budget: ComparisonBudget,
): SecurityFindingV1[] {
  if (!rolesByRoute) return [];
  const implemented = groupedByMethodShape(input.implemented.operations);
  const sourceRoles = new Map(input.implemented.operations.map((operation) => {
    const analysis = operation.auth.analysis;
    return [operation, analysis?.enforcementConfidence === 'high'
      ? [...new Set(analysis.roles)].sort() : undefined] as const;
  }));
  const findings: SecurityFindingV1[] = [];
  for (const declared of input.declared.operations) {
    const roles = rolesByRoute[declared.routeKey];
    if (!roles) continue;
    const expected = [...new Set(roles)].sort();
    const contradictions = (implemented.get(
      `${declared.method} ${normalizedPathShape(declared.path)}`,
    ) ?? []).flatMap((source) => {
      const actual = sourceRoles.get(source);
      consumeComparison(
        budget,
        1 + source.provenance.length + expected.length + 2 * (actual?.length ?? 0),
      );
      if (!actual) return [];
      return sameStrings(expected, actual) ? [] : [{ source, actual }];
    });
    if (contradictions.length === 0) continue;
    findings.push(makeFinding({
      ruleId: 'SC-AUTHZ-001',
      severity: 'warning',
      confidence: 'high-confidence',
      category: 'authorization',
      title: 'Declared privileged roles differ from Source metadata',
      message: `Explicit privileged-role configuration and high-confidence Source metadata differ. ${SOURCE_SCOPE}`,
      route: route(declared),
      expected: { roles: expected },
      actual: { candidates: contradictions.map(({ actual }) => ({ roles: actual })) },
      evidence: [
        ...declared.provenance,
        ...contradictions.flatMap(({ source }) => source.provenance),
      ],
      remediation: { summary: 'Align explicit privileged-role configuration and Source decorators.', safeAutoFix: false },
    }));
  }
  return findings;
}

export function compareSourceOpenApiContracts(
  input: SourceOpenApiDriftInput,
  options: SourceOpenApiDriftOptions = {},
): SecurityFindingV1[] {
  const budget = validateInput(input, options);
  return stableFindings([
    ...inventoryFindings(input),
    ...authFindings(input, budget),
    ...authorizationFindings(input, options.declaredPrivilegedRoles, budget),
  ]);
}
