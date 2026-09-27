import { createHash } from 'node:crypto';
import path from 'node:path';

import { inspectOpenApiForCli, type OpenApiInspectionForCli } from '../openapi/inspect';
import { OpenApiAnalysisError, type OpenApiAnalysisLimits } from '../openapi';
import {
  DEFAULT_SOURCE_ANALYSIS_LIMITS,
  type SourceAnalysisExecution,
  type SourceAnalysisLimits,
} from '../source-analysis';
import type { TypeScriptAnalysisCache } from '../source/typescript/project-loader';
import type { UriComparison } from '../source/nestjs/analyzer';
import { canonicalizePath } from './canonical-route';
import { projectPolicyToAllowedSurface, type AllowedSurfaceModelV1, type AllowedSurfaceTarget } from './allowed-surface';
import { ContractDiffInputError, loadPolicyForInternal } from './contract-diff';
import { redactEvidenceFilename } from './sensitive-text';
import { composeSourceAwareComparisons, type SourceAwareInternalResult } from './source-aware-internal';

export interface SourceAwareWorkspaceInput {
  workspaceRoot: string;
  openapiPath: string;
  policyPath: string;
  target: AllowedSurfaceTarget;
  /** Internal file-save guard; receives paths during the existing input loads. */
  onInputPath?: (path: string) => void;
  openapiLimits?: Partial<OpenApiAnalysisLimits>;
  source?: {
    tsconfigPath: string;
    authConfig?: unknown;
    globalPrefix?: string;
    versioning?: 'uri';
    limits?: Partial<SourceAnalysisLimits>;
    cancellationSignal?: AbortSignal;
    cache?: TypeScriptAnalysisCache;
  };
}

interface InputEvidence {
  digest: string;
  sources: readonly { uri: string; digest: string }[];
}

export interface SourceAwareWorkspaceResult extends SourceAwareInternalResult {
  evidence: {
    // OpenAPI digests identify raw bytes for every document consumed by the resolved graph.
    openapi?: InputEvidence & { analyzer: string; limits: Readonly<OpenApiAnalysisLimits> };
    // Policy input digests identify decoded text; policyDigest identifies the parsed semantic Policy.
    policy?: InputEvidence & { policyDigest: string; projector: 'allowed-surface@1' };
    // Source digest identifies decoded project input text, not raw bytes or analyzer output.
    source?: { projectDigest: string; analyzer: string; configDigest: string; limits: SourceAnalysisLimits };
    routingAssumption?: { globalPrefix?: string; sourceVersioning?: 'uri'; versionPrefix?: 'v';
      digest: string; comparisonContractDigest?: string };
    sourceVersionMetadata?: { digest: string; routes: UriComparison['routes'] };
  };
  target: AllowedSurfaceTarget;
}

function digest(value: unknown): string {
  return `sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`;
}

function safeUri(uri: string): string {
  return redactEvidenceFilename(uri);
}

function openApiEvidence(inspection: OpenApiInspectionForCli): NonNullable<SourceAwareWorkspaceResult['evidence']['openapi']> {
  const sources = inspection.sourceDigests.map(({ sourceUri, contentDigest }) => ({
    uri: safeUri(sourceUri), digest: contentDigest,
  }));
  return {
    digest: digest(inspection.sourceDigests), sources,
    analyzer: `${inspection.report.analyzer.name}@${inspection.report.analyzer.version}`,
    limits: inspection.limits,
  };
}

function safeCode(error: unknown, kind: 'openapi' | 'policy'): string {
  if (kind === 'openapi' && error instanceof OpenApiAnalysisError) return error.code;
  if (kind === 'policy' && error instanceof ContractDiffInputError) return error.code;
  return kind === 'openapi' ? 'OPENAPI_ANALYSIS_FAILED' : 'POLICY_PROJECTION_FAILED';
}

// Internal adapter only. Each stage retains its own consumed-input evidence; no atomic workspace snapshot is claimed.
export async function analyzeSourceAwareWorkspace(input: SourceAwareWorkspaceInput): Promise<SourceAwareWorkspaceResult> {
  if (!input || !['aws', 'cloudflare'].includes(input.target)) throw new ContractDiffInputError('CONTRACT_DIFF_TARGET_INVALID', 'Target is invalid.');
  const requestedPrefix = input.source?.globalPrefix;
  const sourceVersioning = input.source?.versioning;
  if (sourceVersioning !== undefined && sourceVersioning !== 'uri') {
    throw new ContractDiffInputError('CONTRACT_DIFF_SOURCE_INVALID', 'Source versioning is invalid.');
  }
  const prefixModule = requestedPrefix === undefined && sourceVersioning === undefined
    ? undefined : await import('./source-global-prefix');
  const globalPrefix = requestedPrefix === undefined ? undefined
    : prefixModule!.normalizeSourceGlobalPrefix(requestedPrefix);
  let inspection: OpenApiInspectionForCli | undefined;
  let declaredFailure: string | undefined;
  try {
    inspection = inspectOpenApiForCli({
      workspaceRoot: input.workspaceRoot, inputPath: input.openapiPath, limits: input.openapiLimits,
      onInputPath: input.onInputPath,
    });
  } catch (error) { declaredFailure = safeCode(error, 'openapi'); }

  let allowed: AllowedSurfaceModelV1 | undefined;
  let policyEvidence: SourceAwareWorkspaceResult['evidence']['policy'];
  let allowedFailure: string | undefined;
  try {
    const loaded = loadPolicyForInternal(input.workspaceRoot, input.policyPath, input.onInputPath);
    const sources = loaded.sources.map(({ filePath, digest: contentDigest }) => ({
      uri: safeUri(path.relative(loaded.root, filePath).split(path.sep).map(encodeURIComponent).join('/')),
      digest: contentDigest,
    }));
    const policyUri = safeUri(path.relative(loaded.root, path.resolve(loaded.root, input.policyPath))
      .split(path.sep).map(encodeURIComponent).join('/'));
    allowed = projectPolicyToAllowedSurface(loaded.policy, {
      policyDigest: loaded.policyDigest, sourceUri: policyUri,
    });
    policyEvidence = { digest: digest(loaded.sources.map(({ filePath, digest: contentDigest }) => ({
      uri: path.relative(loaded.root, filePath).split(path.sep).join('/'), digest: contentDigest,
    }))), sources, policyDigest: loaded.policyDigest, projector: 'allowed-surface@1' };
  } catch (error) { allowedFailure = safeCode(error, 'policy'); }

  let source: SourceAnalysisExecution | undefined;
  let uriComparison: UriComparison | undefined;
  let sourceEvidence: SourceAwareWorkspaceResult['evidence']['source'];
  if (input.source) {
    const { runNestJsSourceAnalysisInternal, validateNestJsAuthConfig } = await import('../source/nestjs/analyzer');
    const limits = { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, ...(input.source.limits ?? {}) };
    try {
      if (input.source.authConfig !== undefined) validateNestJsAuthConfig(input.source.authConfig);
    } catch {
      source = { status: 'failed', diagnostics: [{
        code: 'SOURCE_ANALYZER_INPUT_INVALID', safeMessage: 'Source input is invalid.',
      }] };
    }
    if (!source) {
      try {
        const analyzed = await runNestJsSourceAnalysisInternal({
          workspaceRoot: input.workspaceRoot,
          entrypoints: [input.source.tsconfigPath], limits,
          cancellationSignal: input.source.cancellationSignal,
          logger: { log() {} },
        }, input.source.authConfig, input.source.cache, input.onInputPath, sourceVersioning);
        source = analyzed.execution;
        uriComparison = analyzed.uriComparison;
        if (source.status === 'success' && analyzed.snapshotDigest) {
          sourceEvidence = {
            projectDigest: `sha256:${analyzed.snapshotDigest}`, analyzer: analyzed.analyzer,
            configDigest: analyzed.configDigest, limits,
          };
        }
      } catch {
        // Config validation above is input-classified; an unexpected runner rejection is internal.
        source = { status: 'failed', diagnostics: [{
          code: 'SOURCE_ANALYZER_INTERNAL', safeMessage: 'Source analysis failed.',
        }] };
      }
    }
  }

  let comparedSource = source;
  const routingAssumption: SourceAwareWorkspaceResult['evidence']['routingAssumption'] =
    globalPrefix || sourceVersioning ? {
      ...(globalPrefix ? { globalPrefix } : {}),
      ...(sourceVersioning ? { sourceVersioning, versionPrefix: 'v' as const } : {}),
      digest: sourceVersioning ? prefixModule!.sourceUriRoutingAssumptionDigest(globalPrefix)
        : prefixModule!.sourceRoutingAssumptionDigest(globalPrefix!),
    } : undefined;
  let sourceVersionMetadata: SourceAwareWorkspaceResult['evidence']['sourceVersionMetadata'];
  if (routingAssumption && source?.status === 'success' && sourceEvidence) {
    try {
      if (sourceVersioning && !uriComparison) throw new Error('missing URI candidates');
      const original = sourceVersioning ? uriComparison!.contract : source.result.contract;
      const contract = globalPrefix ? prefixModule!.prefixSourceContract(original, globalPrefix) : original;
      const unresolvedOperations = sourceVersioning
        ? uriComparison!.unresolvedOperations : source.result.unresolvedOperations;
      const diagnostics = sourceVersioning ? uriComparison!.diagnostics : source.result.diagnostics;
      comparedSource = { status: 'success', result: { ...source.result,
        contract, unresolvedOperations, diagnostics } };
      routingAssumption.comparisonContractDigest = prefixModule!.sourceComparisonContractDigest(contract);
      if (sourceVersioning) {
        const routes = uriComparison!.routes.map((route) => ({ ...route,
          ...(route.comparisonPath && globalPrefix ? { comparisonPath: canonicalizePath(
            `${globalPrefix}${route.comparisonPath}`,
          ) } : {}),
        }));
        const astMetadata = uriComparison!.routes.map(({ comparisonPath: _path, ...route }) => route);
        sourceVersionMetadata = { digest: digest(astMetadata), routes };
      }
    } catch {
      comparedSource = { status: 'failed', diagnostics: [{
        code: 'SOURCE_ROUTING_TRANSFORM_FAILED', safeMessage: 'Source routing comparison failed.',
      }] };
    }
  }

  const openapiEvidence = inspection ? openApiEvidence(inspection) : undefined;
  const declaredEvidence = inspection && openapiEvidence ? {
    source: 'openapi' as const,
    uri: safeUri(inspection.rootSourceUri),
    digest: openapiEvidence.digest, analyzer: 'openapi-graph@1', capability: 'openapi-operations-v1',
    complete: Object.values(inspection.report.contract.capabilities).every((status) => status === 'complete'),
  } : undefined;
  const implementedEvidence = sourceEvidence ? {
    source: 'source-ast' as const, uri: 'source-project',
    digest: routingAssumption?.comparisonContractDigest ?? sourceEvidence.projectDigest,
    analyzer: routingAssumption?.comparisonContractDigest
      ? sourceVersioning ? 'explicit-uri-version@1' : 'explicit-global-prefix@1'
      : sourceEvidence.analyzer,
    capability: routingAssumption?.comparisonContractDigest ? 'explicit-routing-assumption-v1' : 'nestjs-routes-v1',
    complete: comparedSource?.status === 'success'
      && Object.values(comparedSource.result.contract.capabilities).every((status) => status === 'complete')
      && comparedSource.result.unresolvedOperations.length === 0 && comparedSource.result.diagnostics.length === 0,
  } : undefined;
  const compared = composeSourceAwareComparisons({
    declared: inspection?.report, declaredEvidence, declaredFailure,
    allowed, allowedFailure, target: input.target, source: comparedSource, implementedEvidence,
  });
  return {
    ...compared, target: input.target,
    evidence: {
      ...(openapiEvidence ? { openapi: openapiEvidence } : {}),
      ...(policyEvidence ? { policy: policyEvidence } : {}),
      ...(sourceEvidence ? { source: sourceEvidence } : {}),
      ...(routingAssumption ? { routingAssumption } : {}),
      ...(sourceVersionMetadata ? { sourceVersionMetadata } : {}),
    },
  };
}
