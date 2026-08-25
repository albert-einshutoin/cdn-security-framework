import type {
  AllowedRouteRuleV1,
  AllowedSurfaceModelV1,
  AllowedSurfaceTarget,
} from '../allowed-surface';
import type { FindingEvidenceV1, SecurityFindingV1 } from '../finding';
import type { ApiOperationContractV1, SecurityContractV1 } from '../security-ir';
import {
  makeFinding,
  matchingAuthRules,
  normalizedPathShape,
  pathRelation,
  policyEvidence,
  stableFindings,
  validateComparisonInput,
} from './shared';

const AUTH_SCOPE = 'Source metadata does not prove Guard runtime behavior.';
const ROLE_SCOPE = 'Role metadata does not prove authorization enforcement.';
const ROUTE_SCOPE = 'Route identity is incomplete because Source route analysis is partial.';
const MAX_COMPARISON_VISITS = 1_000_000;

interface ComparisonBudget { remaining: number }

function consumeComparison(budget: ComparisonBudget, count: number): void {
  if (!Number.isSafeInteger(count) || count < 0 || budget.remaining < count) {
    throw new Error('source Policy drift comparison exceeds visit budget');
  }
  budget.remaining -= count;
}

function provenanceWidth(operations: readonly ApiOperationContractV1[]): number {
  return operations.reduce((total, operation) => total + operation.provenance.length, 0);
}

export interface SourcePolicyDriftInput {
  implemented: SecurityContractV1;
  implementedEvidence: FindingEvidenceV1;
  allowed: AllowedSurfaceModelV1;
  target: AllowedSurfaceTarget;
}

function route(operation: ApiOperationContractV1) {
  return { method: operation.method, path: operation.path, operationId: operation.operationId };
}

function exactSourceAuth(operation: ApiOperationContractV1): 'public' | 'authenticated' | undefined {
  const analysis = operation.auth.analysis;
  if (!analysis || analysis.enforcementConfidence !== 'high') return undefined;
  if (analysis.explicitPublic && operation.auth.mode === 'none') return 'public';
  if (!analysis.explicitPublic && operation.auth.mode === 'alternatives'
    && analysis.guards.length > 0
    && analysis.guards.every(({ authKind }) => authKind && authKind !== 'unknown')) {
    return 'authenticated';
  }
  return undefined;
}

function policyPaths(rule: AllowedRouteRuleV1): string[] {
  return rule.auth.kind === 'none' ? [] : rule.match.authEffectiveValues;
}

function sourceRelation(
  operation: ApiOperationContractV1,
  rule: AllowedRouteRuleV1,
  value: string,
  input: SourcePolicyDriftInput,
): ReturnType<typeof pathRelation> {
  return pathRelation(operation, value, input.allowed, rule.auth.exactPath ? 'exact' : 'prefix');
}

function pathMethodFindings(
  input: SourcePolicyDriftInput,
  budget: ComparisonBudget,
): SecurityFindingV1[] {
  const { implemented, allowed } = input;
  const findings: SecurityFindingV1[] = [];
  const methodsPointer = allowed.defaults.methodSource === 'configured'
    ? '/request/allow_methods' : '/request';
  const scopedOperations = new Set<ApiOperationContractV1>();
  for (const operation of implemented.operations) {
    consumeComparison(budget, 1);
    if (allowed.defaults.methods.includes(operation.method)) continue;
    consumeComparison(budget, operation.provenance.length + 1);
    const monitor = allowed.defaults.requestDecision === 'would-block';
    findings.push(makeFinding({
      ruleId: 'SC-EXPOSURE-004',
      severity: monitor ? 'warning' : 'error',
      confidence: 'deterministic',
      category: 'exposure',
      title: monitor ? 'Implemented operation would be blocked in enforce mode' : 'Implemented operation is blocked by Policy',
      message: monitor
        ? 'Monitor mode currently permits an implemented operation that the effective method policy would reject in enforce mode.'
        : 'The selected Edge target rejects a statically detected Source operation.',
      route: route(operation),
      expected: { methods: [operation.method] },
      actual: { methods: allowed.defaults.methods, decision: allowed.defaults.requestDecision },
      evidence: [
        ...operation.provenance,
        policyEvidence(allowed, methodsPointer, 'source-policy-drift-v1'),
      ],
      remediation: { summary: 'Align the implemented operation and effective Policy method set.', safeAutoFix: false },
    }));
  }

  for (const rule of allowed.orderedRules) {
    for (const value of policyPaths(rule)) {
      consumeComparison(budget, implemented.operations.length);
      const candidates = implemented.operations.map((operation) => ({
        operation,
        relation: sourceRelation(operation, rule, value, input),
      }));
      const operations = candidates.filter(({ relation }) => relation === 'definitely-covered')
        .map(({ operation }) => operation);
      const uncertain = candidates.some(({ relation }) => (
        relation === 'possibly-overlapping' || relation === 'unknown'
      ));
      for (const operation of operations) scopedOperations.add(operation);
      if (operations.length === 0) {
        if (rule.auth.exactPath) {
          consumeComparison(budget, 2);
          const deterministic = implemented.capabilities.routes === 'complete' && !uncertain;
          findings.push(makeFinding({
            ruleId: 'SC-INVENTORY-005',
            severity: deterministic ? 'error' : 'warning',
            confidence: deterministic ? 'deterministic' : 'heuristic',
            category: 'inventory',
            title: 'Exact Policy route has no detected implementation',
            message: deterministic
              ? 'No statically detected Source route matches this exact Policy route.'
              : uncertain
                ? 'A Source route may overlap this exact Policy route, but an implementation match is not proven.'
                : 'No Source route was detected, but Source route analysis is incomplete; absence is not proven.',
            route: { path: value },
            expected: { implementedRoute: true },
            actual: {
              policyRule: rule.name,
              sourceRouteCapability: implemented.capabilities.routes,
              relations: [...new Set(candidates.map(({ relation }) => relation))].sort(),
            },
            evidence: [
              input.implementedEvidence,
              policyEvidence(allowed, `${rule.pointer}/auth_gate/exact_path`, 'source-policy-drift-v1'),
            ],
            remediation: { summary: 'Implement the route or remove the stale exact Policy rule.', safeAutoFix: false },
          }));
        }
        continue;
      }
      const implementedMethods = [...new Set(operations.map(({ method }) => method))].sort();
      const methodSet = new Set<string>(implementedMethods);
      const extraMethods = allowed.defaults.methods.filter((method) => !methodSet.has(method));
      const monitor = allowed.defaults.requestDecision === 'would-block';
      if (extraMethods.length === 0 && !monitor) continue;
      consumeComparison(
        budget,
        provenanceWidth(operations) + implementedMethods.length + extraMethods.length + 2,
      );
      const deterministic = !monitor && !uncertain && rule.auth.exactPath
        && implemented.capabilities.routes === 'complete';
      findings.push(makeFinding({
        ruleId: 'SC-EXPOSURE-005',
        severity: deterministic ? 'error' : 'warning',
        confidence: deterministic ? 'deterministic' : 'heuristic',
        category: 'exposure',
        title: 'Policy allows methods not detected in Source',
        message: rule.auth.exactPath
          ? 'The effective method policy permits methods absent from the detected Source route.'
          : 'This prefix covers detected Source routes without all globally allowed methods; other routes may exist under the prefix.',
        route: { path: value },
        expected: { methods: implementedMethods },
        actual: {
          methods: allowed.defaults.methods, extraMethods, policyRule: rule.name,
          ...(monitor ? { methodSurface: 'unrestricted-by-edge-in-monitor-mode' } : {}),
        },
        evidence: [
          ...operations.flatMap(({ provenance }) => provenance),
          policyEvidence(allowed, methodsPointer, 'source-policy-drift-v1'),
          policyEvidence(allowed, `${rule.pointer}/auth_gate`, 'source-policy-drift-v1'),
        ],
        remediation: { summary: 'Narrow the effective method set or implement the intended operations.', safeAutoFix: false },
      }));
    }
  }
  const unscopedByShape = new Map<string, ApiOperationContractV1[]>();
  consumeComparison(budget, implemented.operations.length);
  for (const operation of implemented.operations) {
    if (scopedOperations.has(operation)) continue;
    const shape = normalizedPathShape(operation.path);
    const operations = unscopedByShape.get(shape) ?? [];
    operations.push(operation);
    unscopedByShape.set(shape, operations);
  }
  for (const operations of unscopedByShape.values()) {
    const implementedMethods = [...new Set(operations.map(({ method }) => method))].sort();
    const methodSet = new Set<string>(implementedMethods);
    const extraMethods = allowed.defaults.methods.filter((method) => !methodSet.has(method));
    const monitor = allowed.defaults.requestDecision === 'would-block';
    if (extraMethods.length === 0 && !monitor) continue;
    consumeComparison(
      budget,
      provenanceWidth(operations) + implementedMethods.length + extraMethods.length + 1,
    );
    const deterministic = !monitor && implemented.capabilities.routes === 'complete';
    findings.push(makeFinding({
      ruleId: 'SC-EXPOSURE-005',
      severity: deterministic ? 'error' : 'warning',
      confidence: deterministic ? 'deterministic' : 'heuristic',
      category: 'exposure',
      title: 'Policy allows methods not detected in Source',
      message: 'The effective method policy permits methods absent from this detected Source route.',
      route: { path: operations[0].path },
      expected: { methods: implementedMethods },
      actual: {
        methods: allowed.defaults.methods, extraMethods,
        ...(monitor ? { methodSurface: 'unrestricted-by-edge-in-monitor-mode' } : {}),
      },
      evidence: [
        ...operations.flatMap(({ provenance }) => provenance),
        policyEvidence(allowed, methodsPointer, 'source-policy-drift-v1'),
      ],
      remediation: { summary: 'Narrow the effective method set or implement the intended operations.', safeAutoFix: false },
    }));
  }
  return findings;
}

function bypassesAuth(
  input: SourcePolicyDriftInput,
  operation: ApiOperationContractV1,
  rule: AllowedRouteRuleV1,
): boolean {
  const origins = input.allowed.defaults.corsPreflight.origins;
  const originCanMatch = origins.kind === 'any'
    || (origins.kind === 'allowlist' && origins.values.some((origin) => origin.length > 0));
  return originCanMatch && rule.auth.preAuthBypassMethods.includes(operation.method);
}

function matchingRuleWidth(input: SourcePolicyDriftInput): number {
  return input.allowed.orderedRules.reduce(
    (total, rule) => total + rule.match.authEffectiveValues.length + 1,
    0,
  );
}

function authFindings(
  input: SourcePolicyDriftInput,
  budget: ComparisonBudget,
): SecurityFindingV1[] {
  if (input.implemented.capabilities.authentication === 'unsupported') return [];
  const findings: SecurityFindingV1[] = [];
  for (const operation of input.implemented.operations) {
    consumeComparison(budget, 1);
    if (input.allowed.defaults.requestDecision === 'block'
      && !input.allowed.defaults.methods.includes(operation.method)) continue;
    const sourceAuth = exactSourceAuth(operation);
    if (!sourceAuth) continue;
    consumeComparison(budget, matchingRuleWidth(input));
    const matches = matchingAuthRules(operation, input.allowed);
    const definite = matches.filter(({ relation, rule }) => relation === 'definitely-covered'
      && rule.auth.verifiability[input.target] === 'enforced'
      && !bypassesAuth(input, operation, rule));
    const uncertain = matches.filter(({ relation, rule }) => relation !== 'definitely-covered'
      || rule.auth.verifiability[input.target] !== 'enforced'
      || bypassesAuth(input, operation, rule));
    if ((sourceAuth === 'public' && definite.length === 0)
      || (sourceAuth === 'authenticated' && (definite.length > 0 || uncertain.length > 0))) continue;
    const rules = definite.length > 0 ? definite : uncertain;
    consumeComparison(budget, operation.provenance.length + rules.length + 1);
    const routeComplete = input.implemented.capabilities.routes === 'complete';
    findings.push(makeFinding({
      ruleId: 'SC-AUTHN-006',
      severity: sourceAuth === 'public' && routeComplete ? 'error' : 'warning',
      confidence: routeComplete ? 'deterministic' : 'heuristic',
      category: 'authentication',
      title: sourceAuth === 'public'
        ? 'Explicitly public Source route is gated at the Edge'
        : 'Mapped Source authentication has no Edge gate',
      message: `${sourceAuth === 'public'
        ? 'High-confidence Source metadata explicitly marks this route public, but the selected Edge target requires authentication.'
        : 'High-confidence Source metadata maps a local authentication Guard, but no Edge auth gate covers the route.'} ${AUTH_SCOPE}${routeComplete ? '' : ` ${ROUTE_SCOPE}`}`,
      route: route(operation),
      expected: { sourceAuth },
      actual: {
        edgeAuth: rules.map(({ rule, relation }) => ({
          policyRule: rule.name, kind: rule.auth.kind,
          verifiability: rule.auth.verifiability[input.target], relation,
        })),
        target: input.target,
      },
      evidence: [
        ...operation.provenance,
        ...(rules.length > 0
          ? rules.map(({ rule }) => policyEvidence(
            input.allowed, `${rule.pointer}/auth_gate`, 'source-policy-drift-v1',
          ))
          : [policyEvidence(input.allowed, '/routes', 'source-policy-drift-v1')]),
      ],
      remediation: { summary: 'Align the explicit Source auth contract and Edge defense-in-depth posture.', safeAutoFix: false },
    }));
  }
  return findings;
}

function authorizationFindings(
  input: SourcePolicyDriftInput,
  budget: ComparisonBudget,
): SecurityFindingV1[] {
  const findings: SecurityFindingV1[] = [];
  for (const operation of input.implemented.operations) {
    consumeComparison(budget, 1);
    if (input.allowed.defaults.requestDecision === 'block'
      && !input.allowed.defaults.methods.includes(operation.method)) continue;
    const analysis = operation.auth.analysis;
    if (!analysis || analysis.enforcementConfidence !== 'high' || analysis.roles.length === 0
      || !operation.provenance.some(
        ({ capability, complete }) => capability === 'authorization' && complete,
      )) continue;
    consumeComparison(budget, matchingRuleWidth(input));
    const matches = matchingAuthRules(operation, input.allowed);
    const definite = matches.filter(({ relation, rule }) => relation === 'definitely-covered'
      && rule.auth.verifiability[input.target] === 'enforced'
      && !bypassesAuth(input, operation, rule));
    const rules = definite.length > 0 ? definite : matches;
    consumeComparison(
      budget,
      operation.provenance.length + analysis.roles.length + rules.length + 1,
    );
    const routeComplete = input.implemented.capabilities.routes === 'complete';
    findings.push(makeFinding({
      ruleId: 'SC-AUTHZ-002',
      severity: definite.length > 0 ? 'info' : 'warning',
      confidence: !routeComplete
        ? 'heuristic'
        : definite.length > 0 ? 'high-confidence' : matches.length === 0 ? 'deterministic' : 'heuristic',
      category: 'authorization',
      title: 'Privileged Source metadata has no stricter Edge authorization posture',
      message: `Explicit Source role metadata is not represented by a stricter role-aware Edge posture. ${ROLE_SCOPE}${routeComplete ? '' : ` ${ROUTE_SCOPE}`}`,
      route: route(operation),
      expected: { roles: analysis.roles, posture: 'role-aware-defense-in-depth' },
      actual: {
        edgeAuth: rules.map(({ rule, relation }) => ({
          policyRule: rule.name, kind: rule.auth.kind,
          verifiability: rule.auth.verifiability[input.target], relation,
        })),
        target: input.target,
      },
      evidence: [
        ...operation.provenance,
        ...(rules.length > 0
          ? rules.map(({ rule }) => policyEvidence(
            input.allowed, `${rule.pointer}/auth_gate`, 'source-policy-drift-v1',
          ))
          : [policyEvidence(input.allowed, '/routes', 'source-policy-drift-v1')]),
      ],
      remediation: { summary: 'Review whether an additional Edge authorization control is required.', safeAutoFix: false },
    }));
  }
  return findings;
}

export function compareSourcePolicyContracts(input: SourcePolicyDriftInput): SecurityFindingV1[] {
  if (!input || input.implemented?.source !== 'source-ast'
    || input.implementedEvidence?.source !== 'source-ast') {
    throw new Error('invalid source Policy drift input');
  }
  validateComparisonInput({
    declared: input.implemented,
    allowed: input.allowed,
    target: input.target,
  });
  const budget = { remaining: MAX_COMPARISON_VISITS };
  consumeComparison(
    budget,
    input.implemented.operations.length + input.allowed.orderedRules.length + 1,
  );
  return stableFindings([
    ...pathMethodFindings(input, budget),
    ...authFindings(input, budget),
    ...authorizationFindings(input, budget),
  ]);
}
