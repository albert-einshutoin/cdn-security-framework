import type { ApiOperationContractV1, SecurityContractV1 } from '../security-ir';
import type { AllowedRouteRuleV1, AllowedSurfaceModelV1, AllowedSurfaceTarget } from '../allowed-surface';
import type { FindingEvidenceV1, FindingInputV1, SecurityFindingV1 } from '../finding';
import { createFinding } from '../finding';
import { sortFindings } from '../finding-order';
import { relatePath, type RouteRelation } from '../route-relation';

const MAX_COMPARISON_VISITS = 1_000_000;

export interface ContractDriftInput {
  declared: SecurityContractV1;
  allowed: AllowedSurfaceModelV1;
  target: AllowedSurfaceTarget;
}

export function pathRelation(
  operation: ApiOperationContractV1,
  policyPath: string,
  allowed: AllowedSurfaceModelV1,
  policyKind: 'exact' | 'prefix' = 'prefix',
): RouteRelation {
  return relatePath(
    { kind: operation.path.includes('{') ? 'template' : 'exact', value: operation.path },
    { kind: policyKind, value: policyPath },
    {
      phase: 'normalized-path',
      collapseSlashes: allowed.defaults.pathNormalization.collapseSlashes,
      removeDotSegments: allowed.defaults.pathNormalization.removeDotSegments,
    },
  );
}

export function policyEvidence(
  allowed: AllowedSurfaceModelV1,
  pointer: string,
  capability: string,
): FindingEvidenceV1 {
  const evidence = allowed.provenance[0];
  if (!evidence) throw new Error('allowed surface provenance is required');
  return { ...evidence, pointer, capability };
}

export function evidenceFor(
  operation: ApiOperationContractV1,
  allowed: AllowedSurfaceModelV1,
  pointer: string,
  capability: string,
): FindingEvidenceV1[] {
  return [...operation.provenance, policyEvidence(allowed, pointer, capability)];
}

export function makeFinding(input: FindingInputV1): SecurityFindingV1 {
  return createFinding(input);
}

export function stableFindings(findings: readonly SecurityFindingV1[]): SecurityFindingV1[] {
  return sortFindings([...new Map(findings.map((finding) => [finding.instanceId, finding])).values()]);
}

export function matchingAuthRules(
  operation: ApiOperationContractV1,
  allowed: AllowedSurfaceModelV1,
): Array<{ rule: AllowedRouteRuleV1; relation: RouteRelation }> {
  return allowed.orderedRules.flatMap((rule): Array<{
    rule: AllowedRouteRuleV1;
    relation: RouteRelation;
  }> => {
    const relations = rule.match.authEffectiveValues.map(
      (policyPath) => pathRelation(
        operation,
        policyPath,
        allowed,
        rule.auth.exactPath ? 'exact' : 'prefix',
      ),
    );
    if (relations.includes('definitely-covered')) {
      return [{ rule, relation: 'definitely-covered' as const }];
    }
    if (relations.includes('possibly-overlapping')) {
      return [{ rule, relation: 'possibly-overlapping' as const }];
    }
    if (relations.includes('unknown')) return [{ rule, relation: 'unknown' as const }];
    return [];
  });
}

export function validateComparisonInput(input: ContractDriftInput): void {
  if (!input || input.declared.schemaVersion !== 1 || input.allowed.schemaVersion !== 1
    || !['aws', 'cloudflare'].includes(input.target)
    || !Array.isArray(input.declared.operations) || !Array.isArray(input.allowed.orderedRules)
    || !Array.isArray(input.allowed.defaults?.methods)
    || (input.allowed.defaults.requiredHeaders !== undefined
      && !Array.isArray(input.allowed.defaults.requiredHeaders.values))) {
    throw new Error('invalid contract drift input');
  }
  let comparisonWidth = input.allowed.defaults.methods.length
    + (input.allowed.defaults.requiredHeaders?.values.length ?? 0);
  for (const rule of input.allowed.orderedRules) {
    if (!Array.isArray(rule.match?.values) || !Array.isArray(rule.match.authEffectiveValues)) {
      throw new Error('invalid contract drift input');
    }
    comparisonWidth += rule.match.values.length + rule.match.authEffectiveValues.length + 1;
    if (!Number.isSafeInteger(comparisonWidth) || comparisonWidth > MAX_COMPARISON_VISITS) {
      throw new Error('contract drift comparison exceeds visit budget');
    }
  }
  const operationWidth = Math.max(1, comparisonWidth);
  let visits = 0;
  const ruleCount = Math.max(1, input.allowed.orderedRules.length);
  for (const operation of input.declared.operations) {
    if (!Array.isArray(operation.auth?.alternatives)) throw new Error('invalid contract drift input');
    if (visits > MAX_COMPARISON_VISITS - operationWidth) {
      throw new Error('contract drift comparison exceeds visit budget');
    }
    visits += operationWidth;
    for (const alternative of operation.auth.alternatives) {
      if (!Array.isArray(alternative.schemes)) throw new Error('invalid contract drift input');
      if (visits >= MAX_COMPARISON_VISITS) {
        throw new Error('contract drift comparison exceeds visit budget');
      }
      visits += 1;
      if (alternative.schemes.length > Math.floor((MAX_COMPARISON_VISITS - visits) / ruleCount)) {
        throw new Error('contract drift comparison exceeds visit budget');
      }
      visits += alternative.schemes.length * ruleCount;
    }
  }
}

export function normalizedPathShape(value: string): string {
  return value.replace(/\{[^{}\/]+\}/g, '{}');
}
