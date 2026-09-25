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
import { projectPolicyToAllowedSurface, type AllowedSurfaceModelV1, type AllowedSurfaceTarget } from './allowed-surface';
import { ContractDiffInputError, loadPolicyForInternal } from './contract-diff';
import { redactEvidenceFilename } from './sensitive-text';
import { composeSourceAwareComparisons, type SourceAwareInternalResult } from './source-aware-internal';

export interface SourceAwareWorkspaceInput {
  workspaceRoot: string;
  openapiPath: string;
  policyPath: string;
  target: AllowedSurfaceTarget;
  openapiLimits?: Partial<OpenApiAnalysisLimits>;
  source?: {
    tsconfigPath: string;
    authConfig?: unknown;
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
  let inspection: OpenApiInspectionForCli | undefined;
  let declaredFailure: string | undefined;
  try {
    inspection = inspectOpenApiForCli({
      workspaceRoot: input.workspaceRoot, inputPath: input.openapiPath, limits: input.openapiLimits,
    });
  } catch (error) { declaredFailure = safeCode(error, 'openapi'); }

  let allowed: AllowedSurfaceModelV1 | undefined;
  let policyEvidence: SourceAwareWorkspaceResult['evidence']['policy'];
  let allowedFailure: string | undefined;
  try {
    const loaded = loadPolicyForInternal(input.workspaceRoot, input.policyPath);
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
        }, input.source.authConfig, input.source.cache);
        source = analyzed.execution;
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

  const openapiEvidence = inspection ? openApiEvidence(inspection) : undefined;
  const declaredEvidence = inspection && openapiEvidence ? {
    source: 'openapi' as const,
    uri: safeUri(inspection.rootSourceUri),
    digest: openapiEvidence.digest, analyzer: 'openapi-graph@1', capability: 'openapi-operations-v1',
    complete: Object.values(inspection.report.contract.capabilities).every((status) => status === 'complete'),
  } : undefined;
  const implementedEvidence = sourceEvidence ? {
    source: 'source-ast' as const, uri: 'source-project', digest: sourceEvidence.projectDigest,
    analyzer: sourceEvidence.analyzer, capability: 'nestjs-routes-v1',
    complete: source?.status === 'success'
      && Object.values(source.result.contract.capabilities).every((status) => status === 'complete')
      && source.result.unresolvedOperations.length === 0 && source.result.diagnostics.length === 0,
  } : undefined;
  const compared = composeSourceAwareComparisons({
    declared: inspection?.report, declaredEvidence, declaredFailure,
    allowed, allowedFailure, target: input.target, source, implementedEvidence,
  });
  return {
    ...compared, target: input.target,
    evidence: {
      ...(openapiEvidence ? { openapi: openapiEvidence } : {}),
      ...(policyEvidence ? { policy: policyEvidence } : {}),
      ...(sourceEvidence ? { source: sourceEvidence } : {}),
    },
  };
}
