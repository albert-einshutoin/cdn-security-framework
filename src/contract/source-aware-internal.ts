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
  declared: OpenApiInspectionV1;
  declaredEvidence: FindingEvidenceV1;
  allowed: AllowedSurfaceModelV1;
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
  const declared: StageState = {
    status: capabilityStatus(input.declared.contract.capabilities),
    diagnosticCodes: diagnosticCodes(input.declared.diagnostics.map(({ code }) => code)),
  };
  const implementedEvidence = input.implementedEvidence;
  const implemented = sourceStage(input.source, implementedEvidence);
  // Projection completed; provider support is a separate capability, never inferred from this status.
  const allowed = {
    status: 'complete' as const, diagnosticCodes: [],
    targetCapabilities: input.allowed.targetCapabilities[input.target].map(({ id, status }) => ({ id, status })),
  };
  const declaredAllowed = compare(declared.status === 'partial' ? 'partial' : 'complete', () => (
    compareSecurityContracts({ declared: input.declared.contract, allowed: input.allowed, target: input.target })
  ));
  if (!input.source || input.source.status === 'failed' || implemented.status === 'failed'
    || !implementedEvidence) {
    const unavailable: ComparisonState = implemented.status === 'omitted'
      ? { status: 'omitted', code: implemented.code ?? 'SOURCE_NOT_REQUESTED' }
      : { status: 'failed', code: implemented.code ?? 'SOURCE_ANALYZER_FAILED' };
    return {
      stages: { declared, implemented, allowed },
      comparisons: {
        declaredAllowed,
        implementedDeclared: unavailable,
        implementedAllowed: unavailable,
      },
    };
  }
  const source = input.source.result.contract;
  const sourceStatus = implemented.status === 'partial' || declared.status === 'partial' ? 'partial' : 'complete';
  const implementedDeclared = compare(sourceStatus, () => compareSourceOpenApiContracts({
    declared: input.declared.contract,
    implemented: source,
    declaredEvidence: input.declaredEvidence,
    implementedEvidence,
  }));
  const implementedAllowed = compare(implemented.status === 'partial' ? 'partial' : 'complete', () => (
    compareSourcePolicyContracts({
      implemented: source,
      implementedEvidence,
      allowed: input.allowed,
      target: input.target,
    })
  ));
  return {
    stages: { declared, implemented, allowed },
    comparisons: { declaredAllowed, implementedDeclared, implementedAllowed },
  };
}
