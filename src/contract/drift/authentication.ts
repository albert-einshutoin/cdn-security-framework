import type { ApiAuthSchemeV1, ApiOperationContractV1 } from '../security-ir';
import type { AllowedRouteRuleV1 } from '../allowed-surface';
import type { SecurityFindingV1 } from '../finding';
import {
  makeFinding,
  matchingAuthRules,
  policyEvidence,
  stableFindings,
  validateComparisonInput,
  type ContractDriftInput,
} from './shared';

const SCOPE_DISCLAIMER = 'This compares the selected Edge contract only; Application authentication is not evaluated.';

type Compatibility = 'compatible' | 'incompatible' | 'unknown';

function schemeCompatibility(scheme: ApiAuthSchemeV1, rule: AllowedRouteRuleV1): Compatibility {
  if (scheme.capability === 'unsupported') return 'unknown';
  if (!rule.auth.credential) return 'unknown';
  if (scheme.kind === 'api-key') {
    if (scheme.location !== rule.auth.credential.location || !scheme.parameterName) return 'incompatible';
    return rule.auth.kind === 'static_token'
      && rule.auth.credential.names.includes(scheme.parameterName.toLowerCase())
      ? 'compatible'
      : 'incompatible';
  }
  if (scheme.kind === 'basic') return rule.auth.kind === 'basic_auth' ? 'compatible' : 'incompatible';
  if (scheme.kind === 'bearer') return rule.auth.kind === 'jwt' ? 'unknown' : 'incompatible';
  return 'unknown';
}

function authCompatibility(
  operation: ApiOperationContractV1,
  rules: readonly AllowedRouteRuleV1[],
): Compatibility {
  let sawUnknown = false;
  for (const alternative of operation.auth.alternatives) {
    if (alternative.anonymous) continue;
    const matrix = alternative.schemes.map((scheme) => (
      rules.map((rule) => schemeCompatibility(scheme, rule))
    ));
    const schemeRelations = matrix.map((relations) => relations.includes('compatible')
      ? 'compatible' : relations.includes('unknown') ? 'unknown' : 'incompatible');
    const ruleRelations = rules.map((_, ruleIndex) => {
      const relations = matrix.map((row) => row[ruleIndex]);
      return relations.includes('compatible')
        ? 'compatible' : relations.includes('unknown') ? 'unknown' : 'incompatible';
    });
    const relations = [...schemeRelations, ...ruleRelations];
    if (relations.every((relation) => relation === 'compatible')) return 'compatible';
    if (!relations.includes('incompatible') && relations.includes('unknown')) sawUnknown = true;
  }
  return sawUnknown ? 'unknown' : 'incompatible';
}

function actualAuth(rules: readonly AllowedRouteRuleV1[], target: ContractDriftInput['target']) {
  return rules.map((rule) => ({
    policyRule: rule.name,
    kind: rule.auth.kind,
    ...(rule.auth.credential
      ? { credential: rule.auth.credential }
      : { credentialStatus: 'unknown-v1-field' }),
    verifiability: rule.auth.verifiability[target],
  }));
}

export function compareAuthContracts(input: ContractDriftInput): SecurityFindingV1[] {
  validateComparisonInput(input);
  const { declared, allowed, target } = input;
  const findings: SecurityFindingV1[] = [];
  const corsOriginCanMatch = allowed.defaults.corsPreflight.origins.kind === 'any'
    || (allowed.defaults.corsPreflight.origins.kind === 'allowlist'
      && allowed.defaults.corsPreflight.origins.values.length > 0);
  for (const operation of declared.operations) {
    const matches = matchingAuthRules(operation, allowed);
    const bypassesAuth = (rule: AllowedRouteRuleV1) => corsOriginCanMatch
      && rule.auth.preAuthBypassMethods.includes(operation.method);
    const definiteRules = matches
      .filter(({ relation, rule }) => relation === 'definitely-covered'
        && rule.auth.verifiability[target] === 'enforced'
        && !bypassesAuth(rule))
      .map(({ rule }) => rule);
    const uncertainRules = matches.filter(({ relation, rule }) => relation !== 'definitely-covered'
      || rule.auth.verifiability[target] !== 'enforced'
      || bypassesAuth(rule));
    const evidenceRules = [
      ...definiteRules,
      ...uncertainRules.map(({ rule }) => rule),
    ];
    const evidence = [
      ...operation.provenance,
      ...(evidenceRules.length > 0
        ? evidenceRules.map((rule) => policyEvidence(
          allowed, `${rule.pointer}/auth_gate`, 'authentication-drift-v1',
        ))
        : [policyEvidence(allowed, '/request', 'authentication-drift-v1')]),
    ];

    if (operation.exposure === 'public') {
      if (definiteRules.length > 0) findings.push(makeFinding({
        ruleId: 'SC-AUTHN-002',
        severity: 'error',
        confidence: 'deterministic',
        category: 'authentication',
        title: 'Edge authentication is applied to an explicitly public operation',
        message: `OpenAPI explicitly permits anonymous access, but the selected Edge target requires authentication. ${SCOPE_DISCLAIMER}`,
        route: { method: operation.method, path: operation.path, operationId: operation.operationId },
        expected: { auth: operation.auth },
        actual: { auth: actualAuth(definiteRules, target), decision: allowed.defaults.authenticationDecision },
        evidence,
        remediation: { summary: 'Remove the Edge gate or change the declared operation contract.', safeAutoFix: false },
      }));
      else if (uncertainRules.length > 0) findings.push(makeFinding({
        ruleId: 'SC-AUTHN-004',
        severity: 'info',
        confidence: 'heuristic',
        category: 'authentication',
        title: 'Analyzer cannot prove authentication compatibility',
        message: `A possibly overlapping or unsupported Edge auth gate may affect this explicitly public operation. ${SCOPE_DISCLAIMER}`,
        route: { method: operation.method, path: operation.path, operationId: operation.operationId },
        expected: { auth: operation.auth },
        actual: { auth: actualAuth(uncertainRules.map(({ rule }) => rule), target), target },
        evidence,
        remediation: { summary: 'Review the overlapping route and intended public access boundary.', safeAutoFix: false },
      }));
      continue;
    }

    if (operation.auth.mode === 'unknown') {
      findings.push(makeFinding({
        ruleId: 'SC-AUTHN-004',
        severity: 'info',
        confidence: 'heuristic',
        category: 'authentication',
        title: 'Analyzer cannot prove authentication compatibility',
        message: `OpenAPI authentication is incomplete or unknown. ${SCOPE_DISCLAIMER}`,
        route: { method: operation.method, path: operation.path, operationId: operation.operationId },
        expected: { authMode: 'unknown' },
        actual: { auth: actualAuth(definiteRules, target), capability: declared.capabilities.authentication },
        evidence,
      }));
      continue;
    }

    if (definiteRules.length === 0) {
      const uncertain = uncertainRules.length > 0;
      findings.push(makeFinding({
        ruleId: uncertain ? 'SC-AUTHN-004' : 'SC-AUTHN-001',
        severity: uncertain ? 'info' : 'warning',
        confidence: uncertain ? 'heuristic' : 'deterministic',
        category: 'authentication',
        title: uncertain
          ? 'Analyzer cannot prove authentication compatibility'
          : 'Declared authentication is not enforced at the selected Edge target',
        message: `${uncertain
          ? 'Route overlap or target support prevents a deterministic authentication decision.'
          : 'No enforced Edge auth gate covers this authenticated OpenAPI operation.'} ${SCOPE_DISCLAIMER}`,
        route: { method: operation.method, path: operation.path, operationId: operation.operationId },
        expected: { auth: operation.auth },
        actual: {
          auth: actualAuth(uncertainRules.map(({ rule }) => rule), target),
          target,
          mode: allowed.defaults.mode,
        },
        evidence,
        remediation: { summary: 'Review Edge target support and the intended defense-in-depth boundary.', safeAutoFix: false },
      }));
      continue;
    }

    const definiteCompatibility = authCompatibility(operation, definiteRules);
    const compatibility = definiteCompatibility === 'compatible' && uncertainRules.length > 0
      ? 'unknown' : definiteCompatibility;
    if (compatibility !== 'compatible') findings.push(makeFinding({
      ruleId: compatibility === 'unknown' ? 'SC-AUTHN-004' : 'SC-AUTHN-003',
      severity: compatibility === 'unknown' ? 'info' : 'warning',
      confidence: compatibility === 'unknown' ? 'heuristic' : 'deterministic',
      category: 'authentication',
      title: compatibility === 'unknown'
        ? 'Analyzer cannot prove authentication compatibility'
        : 'OpenAPI and Edge authentication shapes are incompatible',
      message: `${compatibility === 'unknown'
        ? 'The analyzer does not infer Bearer/JWT or unsupported scheme compatibility.'
        : 'Credential kind, location, or parameter name differs between OpenAPI and the selected Edge target.'} ${SCOPE_DISCLAIMER}`,
      route: { method: operation.method, path: operation.path, operationId: operation.operationId },
      expected: { alternatives: operation.auth.alternatives },
      actual: {
        auth: actualAuth([
          ...definiteRules,
          ...uncertainRules.map(({ rule }) => rule),
        ], target),
        mode: allowed.defaults.mode,
      },
      evidence,
      remediation: { summary: 'Align credential shape without exposing credential values.', safeAutoFix: false },
    }));
  }
  return stableFindings(findings);
}
