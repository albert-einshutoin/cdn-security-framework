import type { OpenApiInspectionV1 } from '../openapi/inspect';
import type { SourceAnalysisExecution } from '../source-analysis';
import type { AllowedSurfaceModelV1, AllowedSurfaceTarget, AllowedTargetCapabilityV1 } from './allowed-surface';
import {
  compareSecurityContracts,
  compareSourceOpenApiContracts,
  compareSourcePolicyContracts,
} from './drift';
import type { FindingEvidenceV1, SecurityFindingV1 } from './finding';
import type { SecurityContractCapabilitiesV1 } from './security-ir';

type StageStatus = 'complete' | 'partial' | 'omitted' | 'failed';

type StageState = {
  status: StageStatus;
  code?: string;
  diagnosticCodes: string[];
};

type ComparisonState =
  | { status: 'complete' | 'partial'; findings: SecurityFindingV1[]; code?: never }
  | { status: 'omitted' | 'failed'; code: string; findings?: never };

export interface SourceAwareInternalInput {
  declared?: OpenApiInspectionV1;
  declaredEvidence?: FindingEvidenceV1;
  declaredFailure?: string;
  allowed?: AllowedSurfaceModelV1;
  allowedFailure?: string;
  target: AllowedSurfaceTarget;
  source?: SourceAnalysisExecution;
  implementedEvidence?: FindingEvidenceV1;
}

export interface SourceAwareInternalResult {
  stages: {
    declared: StageState;
    implemented: StageState;
    allowed: StageState & { targetCapabilities: AllowedTargetCapabilityV1[] };
  };
  comparisons: {
    declaredAllowed: ComparisonState;
    implementedDeclared: ComparisonState;
    implementedAllowed: ComparisonState;
  };
}

function capabilityStatus(capabilities: SecurityContractCapabilitiesV1): 'complete' | 'partial' {
  return Object.values(capabilities).every((level) => level === 'complete') ? 'complete' : 'partial';
}

function diagnosticCodes(codes: readonly string[]): string[] {
  return [...new Set(codes)].sort();
}

function sourceStage(source: SourceAnalysisExecution | undefined, evidence: FindingEvidenceV1 | undefined): StageState {
  if (!source) return { status: 'omitted', code: 'SOURCE_NOT_REQUESTED', diagnosticCodes: [] };
  if (source.status === 'failed') {
    const codes = diagnosticCodes(source.diagnostics.map(({ code }) => code));
    return { status: 'failed', code: codes[0] ?? 'SOURCE_ANALYZER_FAILED', diagnosticCodes: codes };
  }
  if (!evidence) return { status: 'failed', code: 'SOURCE_EVIDENCE_MISSING', diagnosticCodes: [] };
  const { result } = source;
  const partial = capabilityStatus(result.contract.capabilities) === 'partial'
    || result.unresolvedOperations.length > 0 || result.diagnostics.length > 0;
  return {
    status: partial ? 'partial' : 'complete',
    diagnosticCodes: diagnosticCodes(result.diagnostics.map(({ code }) => code)),
  };
}

function compare(status: 'complete' | 'partial', run: () => SecurityFindingV1[]): ComparisonState {
  try {
    return { status, findings: run() };
  } catch (error) {
    // Comparators own their visit budgets; never turn a failed comparison into zero Findings.
    const code = error instanceof Error && error.message.includes('exceeds visit budget')
      ? 'COMPARISON_RESOURCE_LIMIT' : 'COMPARISON_FAILED';
    return { status: 'failed', code };
  }
}

// Internal only: callers own safe loading and evidence identity; this function performs no I/O.
export function composeSourceAwareComparisons(input: SourceAwareInternalInput): SourceAwareInternalResult {
  const declared: StageState = input.declared && input.declaredEvidence ? {
    status: capabilityStatus(input.declared.contract.capabilities),
    diagnosticCodes: diagnosticCodes(input.declared.diagnostics.map(({ code }) => code)),
  } : { status: 'failed', code: input.declaredFailure ?? 'OPENAPI_EVIDENCE_MISSING', diagnosticCodes: [] };
  const implementedEvidence = input.implementedEvidence;
  const implemented = sourceStage(input.source, implementedEvidence);
  // Projection completed; provider support is a separate capability, never inferred from this status.
  const allowed = input.allowed ? {
    status: 'complete' as const, diagnosticCodes: [],
    targetCapabilities: input.allowed.targetCapabilities[input.target].map(({ id, status }) => ({ id, status })),
  } : { status: 'failed' as const, code: input.allowedFailure ?? 'POLICY_INPUT_FAILED', diagnosticCodes: [], targetCapabilities: [] };
  const missing = (stage: StageState): ComparisonState => stage.status === 'omitted'
    ? { status: 'omitted', code: stage.code ?? 'SOURCE_NOT_REQUESTED' }
    : { status: 'failed', code: stage.code ?? 'INPUT_FAILED' };
  const declaredAllowed = !input.declared || !input.declaredEvidence ? missing(declared)
    : !input.allowed ? missing(allowed)
      : compare(declared.status === 'partial' ? 'partial' : 'complete', () => (
        compareSecurityContracts({ declared: input.declared!.contract, allowed: input.allowed!, target: input.target })
      ));
  const source = input.source?.status === 'success' && implementedEvidence ? input.source.result.contract : undefined;
  const implementedDeclared = !source ? missing(implemented)
    : !input.declared || !input.declaredEvidence ? missing(declared)
      : compare(implemented.status === 'partial' || declared.status === 'partial' ? 'partial' : 'complete', () => (
        compareSourceOpenApiContracts({
          declared: input.declared!.contract, implemented: source,
          declaredEvidence: input.declaredEvidence!, implementedEvidence: implementedEvidence!,
        })
      ));
  const implementedAllowed = !source ? missing(implemented)
    : !input.allowed ? missing(allowed)
      : compare(implemented.status === 'partial' ? 'partial' : 'complete', () => (
        compareSourcePolicyContracts({
          implemented: source, implementedEvidence: implementedEvidence!,
          allowed: input.allowed!, target: input.target,
        })
      ));
  return {
    stages: { declared, implemented, allowed },
    comparisons: { declaredAllowed, implementedDeclared, implementedAllowed },
  };
}
