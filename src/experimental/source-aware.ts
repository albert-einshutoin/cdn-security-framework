import path from 'node:path';
import { types } from 'node:util';

import type { SecurityFindingV1 } from '../contract/finding';
import type { previewPassportFactoryObservation } from '../contract/passport-factory-observation';
import type { previewPassportStrategyObservation } from '../contract/passport-strategy-observation';
import { hasUnsafeSensitiveText, redactEvidenceFilename } from '../contract/sensitive-text';
import { assertSupportedNode } from '../lib/node-engine';

assertSupportedNode();

export interface SourceDiffOptions {
  readonly workspaceRoot: string;
  readonly openapiPath: string;
  readonly policyPath: string;
  readonly target: 'aws' | 'cloudflare';
  readonly currentDate: string;
  readonly failOn: 'error' | 'warning' | 'never';
  readonly environment?: string;
  readonly exceptionsPath?: string;
  readonly source?: {
    readonly tsconfigPath: string;
    readonly authConfigPath?: string;
    readonly globalPrefix?: string;
    readonly versioning?: 'uri';
  };
}

export type SourceDiffStage = Readonly<{
  status: 'complete' | 'partial' | 'omitted' | 'failed';
  code?: string;
  diagnosticCodes: readonly string[];
}>;
export type SourceDiffComparison = Readonly<
  | { status: 'complete' | 'partial'; count: number; active: number; suppressed: number }
  | { status: 'omitted' | 'failed'; code: string }
>;
export type SourceDiffFinding = Readonly<SecurityFindingV1>;
export type SourceDiffMetadata = Readonly<{
  openapi?: { graphDigest: string; digestKind: 'raw-document-graph' };
  policy?: { inputDigest: string; semanticDigest: string; digestKind: 'decoded-input-text' };
  source?: { projectDigest: string; configDigest: string; digestKind: 'decoded-project-text' };
  routingAssumption?: { globalPrefix?: string; sourceVersioning?: 'uri'; versionPrefix?: 'v';
    digest: string; comparisonContractDigest?: string; origin: 'explicit-option' };
  sourceVersionMetadata?: { digest: string; origin: 'source-ast'; total: number; omitted: number;
    routes: readonly { status: 'resolved' | 'unresolved'; sourceUri: string; line: number;
      reason?: string; method?: string; localPath?: string; version?: string;
      versionOrigin?: 'controller' | 'method'; comparisonPath?: string }[] };
  passportFactoryObservation?: ReturnType<typeof previewPassportFactoryObservation>;
  passportStrategyObservation?: ReturnType<typeof previewPassportStrategyObservation>;
  targetCapabilities: readonly { id: string;
    status: 'supported' | 'partial' | 'unsupported' | 'warning-only' }[];
}>;

export interface SourceDiffReport {
  readonly kind: 'report';
  readonly contract: 'experimental-source-aware@1';
  readonly target: 'aws' | 'cloudflare';
  readonly stages: Readonly<Record<'declared' | 'implemented' | 'allowed', SourceDiffStage>>;
  readonly comparisons: Readonly<Record<'declaredAllowed' | 'implementedDeclared' | 'implementedAllowed', SourceDiffComparison>>;
  readonly findings: readonly SourceDiffFinding[];
  readonly suppressedFindings: readonly SourceDiffFinding[];
  readonly exceptionDiagnostics: readonly SourceDiffFinding[];
  readonly appliedExceptionIds: readonly string[];
  readonly memberships: readonly { readonly instanceId: string;
    readonly comparisons: readonly ('declaredAllowed' | 'implementedDeclared' | 'implementedAllowed')[] }[];
  readonly summary: Readonly<{ unique: number; active: number; suppressed: number; governance: number }>;
  readonly analysis: Readonly<{ status: 'complete' | 'partial' | 'failed';
    outcome: 'ok' | 'input-error' | 'internal-error'; codes: readonly string[] }>;
  readonly threshold: Readonly<{ failOn: 'error' | 'warning' | 'never' | 'invalid'; reached: boolean }>;
  readonly metadata: SourceDiffMetadata;
  readonly exitCode: 0 | 1 | 2 | 3;
}

export interface SourceDiffError {
  readonly kind: 'error';
  readonly contract: 'experimental-source-aware@1';
  readonly code: string;
  readonly message: string;
  readonly exitCode: 2 | 3;
}

export type SourceDiffResult = SourceDiffReport | SourceDiffError;

const CONTRACT = 'experimental-source-aware@1' as const;
const TOP_KEYS = ['workspaceRoot', 'openapiPath', 'policyPath', 'target', 'currentDate',
  'failOn', 'environment', 'exceptionsPath', 'source'] as const;
const SOURCE_KEYS = ['tsconfigPath', 'authConfigPath', 'globalPrefix', 'versioning'] as const;

function dataObject(value: unknown, allowed: readonly string[], required: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error('invalid options');
  const result: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !allowed.includes(key)) throw new Error('invalid options');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !('value' in descriptor)) throw new Error('invalid options');
    result[key] = descriptor.value;
  }
  if (required.some((key) => !Object.hasOwn(result, key))) throw new Error('invalid options');
  return result;
}

function validatedOptions(value: unknown): SourceDiffOptions {
  const options = dataObject(value, TOP_KEYS, TOP_KEYS.slice(0, 6));
  for (const key of TOP_KEYS.slice(0, 6)) {
    if (typeof options[key] !== 'string') throw new Error('invalid options');
  }
  for (const key of ['environment', 'exceptionsPath']) {
    if (options[key] !== undefined && typeof options[key] !== 'string') throw new Error('invalid options');
  }
  if (options.source !== undefined) {
    const source = dataObject(options.source, SOURCE_KEYS, ['tsconfigPath']);
    if (typeof source.tsconfigPath !== 'string' || source.tsconfigPath === '') throw new Error('invalid options');
    for (const key of SOURCE_KEYS) {
      if (source[key] !== undefined && typeof source[key] !== 'string') throw new Error('invalid options');
    }
    options.source = source;
  }
  return options as unknown as SourceDiffOptions;
}

function error(code: string, exitCode: 2 | 3): SourceDiffError {
  return { kind: 'error', contract: CONTRACT, code,
    message: exitCode === 2 ? 'Source-aware input is invalid.' : 'Source-aware analysis failed.', exitCode };
}

function safeResult(value: unknown, workspaceRoot: string): boolean {
  const pending: { value: unknown; key: string }[] = [{ value, key: '' }];
  const seen = new Set<object>();
  while (pending.length) {
    const { value: current, key } = pending.pop()!;
    if (typeof current === 'string') {
      if (workspaceRoot && current.includes(workspaceRoot)) return false;
      let decoded = current;
      for (let i = 0; i < 3; i += 1) {
        if (hasUnsafeSensitiveText(decoded)) return false;
        try {
          const next = decodeURIComponent(decoded);
          if (next === decoded) break;
          decoded = next;
        } catch { break; }
      }
      if (/(?:uri|path|prefix)$/i.test(key) && redactEvidenceFilename(current) !== current) return false;
      continue;
    }
    if (!current || typeof current !== 'object') continue;
    if (types.isProxy(current) || seen.has(current)) return false;
    seen.add(current);
    for (const name of Reflect.ownKeys(current)) {
      if (typeof name !== 'string') return false;
      const descriptor = Object.getOwnPropertyDescriptor(current, name);
      if (!descriptor || !('value' in descriptor)) return false;
      pending.push({ value: descriptor.value, key: name });
    }
  }
  return true;
}

/** Executes one bounded analysis. exitCode is data; this function never changes the caller's process. */
export async function analyzeSourceDiff(options: SourceDiffOptions): Promise<SourceDiffResult> {
  try { assertSupportedNode(); }
  catch { return error('ERR_CSF_UNSUPPORTED_NODE', 2); }
  let input: SourceDiffOptions;
  try { input = validatedOptions(options); }
  catch { return error('SOURCE_DIFF_ARGUMENT_INVALID', 2); }
  try {
    const { prepareSourceDiff } = await import('../bin/commands/source-diff');
    const prepared = await prepareSourceDiff({
      workspaceRoot: input.workspaceRoot, openapi: input.openapiPath, policy: input.policyPath,
      target: input.target, currentDate: input.currentDate, failOn: input.failOn,
      format: 'json', exceptions: input.exceptionsPath, environment: input.environment,
      source: input.source?.tsconfigPath, sourceAuthConfig: input.source?.authConfigPath,
      sourceGlobalPrefix: input.source?.globalPrefix, sourceVersioning: input.source?.versioning,
    });
    if (!prepared.ok) return error(/^[A-Z][A-Z0-9_]{1,79}$/.test(prepared.code)
      ? prepared.code : 'SOURCE_DIFF_INTERNAL', prepared.exitCode);
    const final = prepared.bundle.finalized;
    if (!final) return error('SOURCE_DIFF_INTERNAL', 3);
    const report: SourceDiffReport = {
      kind: 'report', contract: CONTRACT, target: final.target,
      stages: final.stages, comparisons: final.comparisons,
      findings: final.findings, suppressedFindings: final.suppressedFindings,
      exceptionDiagnostics: final.exceptionDiagnostics,
      appliedExceptionIds: final.appliedExceptionIds, memberships: final.memberships,
      summary: final.summary, analysis: final.analysis, threshold: final.threshold,
      metadata: prepared.bundle.metadata, exitCode: final.exitCode,
    };
    return safeResult(report, path.resolve(input.workspaceRoot)) ? report : error('SOURCE_DIFF_RESULT_UNSAFE', 3);
  } catch {
    return error('SOURCE_DIFF_INTERNAL', 3);
  }
}
