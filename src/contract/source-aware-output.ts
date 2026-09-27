import type { AllowedTargetCapabilityV1 } from './allowed-surface';
import {
  finalizeSourceAwareWorkspace, SOURCE_AWARE_COMPARISONS, SourceAwareFinalizationError,
  type SourceAwareFinalizedResult, type SourceAwareFinalizerOptions,
} from './source-aware-finalizer';
import type { SourceAwareWorkspaceResult } from './source-aware-workspace';
import { previewPassportFactoryObservation } from './passport-factory-observation';
import { previewPassportStrategyObservation } from './passport-strategy-observation';
import { redactEvidenceFilename } from './sensitive-text';

type StageName = 'declared' | 'implemented' | 'allowed';
type StageStatus = SourceAwareWorkspaceResult['stages'][StageName]['status'];
type ComparisonName = typeof SOURCE_AWARE_COMPARISONS[number];
type ComparisonStatus = SourceAwareWorkspaceResult['comparisons'][ComparisonName]['status'];

export interface SourceAwareOutputBundle {
  target: SourceAwareWorkspaceResult['target'];
  metadata: {
    openapi?: { graphDigest: string; digestKind: 'raw-document-graph' };
    policy?: { inputDigest: string; semanticDigest: string; digestKind: 'decoded-input-text' };
    source?: { projectDigest: string; configDigest: string; digestKind: 'decoded-project-text' };
    routingAssumption?: { globalPrefix?: string; sourceVersioning?: 'uri'; versionPrefix?: 'v';
      digest: string; comparisonContractDigest?: string; origin: 'explicit-option' };
    sourceVersionMetadata?: { digest: string; origin: 'source-ast'; total: number; omitted: number;
      routes: Array<{ status: 'resolved' | 'unresolved'; sourceUri: string; line: number;
        reason?: string; method?: string; localPath?: string; version?: string;
        versionOrigin?: 'controller' | 'method'; comparisonPath?: string }> };
    passportFactoryObservation?: ReturnType<typeof previewPassportFactoryObservation>;
    passportStrategyObservation?: ReturnType<typeof previewPassportStrategyObservation>;
    targetCapabilities: AllowedTargetCapabilityV1[];
  };
  finalized?: SourceAwareFinalizedResult;
  finalizationError?: { code: SourceAwareFinalizationError['code']; exitCode: 2 | 3;
    stages: Record<StageName, StageStatus>; comparisons: Record<ComparisonName, ComparisonStatus> };
}

function digest(value: string): string | undefined {
  return /^sha256:[0-9a-f]{64}$/.test(value) ? value : undefined;
}

// Only same-run, fixed-shape metadata crosses the reporter boundary. Workspace paths and raw inputs stay behind it.
export function finalizeSourceAwareOutput(
  workspace: SourceAwareWorkspaceResult,
  options: SourceAwareFinalizerOptions,
): SourceAwareOutputBundle {
  const capabilities = workspace.stages.allowed.targetCapabilities.map(({ id, status }) => ({
    id: /^[a-zA-Z0-9_.-]{1,80}$/.test(id) ? id : 'UNKNOWN_CAPABILITY',
    status: (['supported', 'partial', 'unsupported', 'warning-only'] as const).includes(status)
      ? status : 'unsupported' as const,
  }));
  const graphDigest = workspace.evidence.openapi && digest(workspace.evidence.openapi.digest);
  const inputDigest = workspace.evidence.policy && digest(workspace.evidence.policy.digest);
  const semanticDigest = workspace.evidence.policy && digest(workspace.evidence.policy.policyDigest);
  const projectDigest = workspace.evidence.source && digest(workspace.evidence.source.projectDigest);
  const configDigest = workspace.evidence.source && digest(workspace.evidence.source.configDigest);
  const routing = workspace.evidence.routingAssumption;
  const versions = workspace.evidence.sourceVersionMetadata;
  const versionRoutes = versions?.routes.slice(0, 20).map((route) => ({
    status: route.status, sourceUri: redactEvidenceFilename(route.sourceUri), line: route.line,
    ...(route.status === 'resolved' ? {
      method: route.method, localPath: redactEvidenceFilename(route.localPath!),
      version: route.version, versionOrigin: route.origin,
      comparisonPath: redactEvidenceFilename(route.comparisonPath!),
    } : { reason: route.reason }),
  }));
  // The CI record has a 64 KiB read limit; keep its route preview well below that while preserving the full digest and count.
  while (versionRoutes && Buffer.byteLength(JSON.stringify(versionRoutes, null, 2)) > 24_576) {
    versionRoutes.pop();
  }
  const bundle: SourceAwareOutputBundle = {
    target: workspace.target,
    metadata: {
      ...(graphDigest ? { openapi: { graphDigest, digestKind: 'raw-document-graph' } as const } : {}),
      ...(inputDigest && semanticDigest ? { policy: { inputDigest, semanticDigest,
        digestKind: 'decoded-input-text' } as const } : {}),
      ...(projectDigest && configDigest ? { source: { projectDigest, configDigest,
        digestKind: 'decoded-project-text' } as const } : {}),
      ...(routing ? { routingAssumption: {
        ...(routing.globalPrefix ? { globalPrefix: redactEvidenceFilename(routing.globalPrefix) } : {}),
        ...(routing.sourceVersioning ? { sourceVersioning: routing.sourceVersioning,
          versionPrefix: 'v' as const } : {}),
        digest: routing.digest,
        ...(routing.comparisonContractDigest ? { comparisonContractDigest: routing.comparisonContractDigest } : {}),
        origin: 'explicit-option' as const,
      } } : {}),
      ...(versions ? { sourceVersionMetadata: {
        digest: versions.digest, origin: 'source-ast' as const,
        total: versions.routes.length, omitted: versions.routes.length - versionRoutes!.length,
        routes: versionRoutes!,
      } } : {}),
      ...(workspace.evidence.passportFactoryObservation ? { passportFactoryObservation:
        previewPassportFactoryObservation(workspace.evidence.passportFactoryObservation) } : {}),
      ...(workspace.evidence.passportStrategyObservation ? { passportStrategyObservation:
        previewPassportStrategyObservation(workspace.evidence.passportStrategyObservation) } : {}),
      targetCapabilities: capabilities,
    },
  };
  try {
    return { ...bundle, finalized: finalizeSourceAwareWorkspace(workspace, options) };
  } catch (error) {
    if (!(error instanceof SourceAwareFinalizationError)) throw error;
    return { ...bundle, finalizationError: {
      code: error.code, exitCode: error.exitCode,
      stages: { declared: workspace.stages.declared.status,
        implemented: workspace.stages.implemented.status, allowed: workspace.stages.allowed.status },
      comparisons: { declaredAllowed: workspace.comparisons.declaredAllowed.status,
        implementedDeclared: workspace.comparisons.implementedDeclared.status,
        implementedAllowed: workspace.comparisons.implementedAllowed.status },
    } };
  }
}
