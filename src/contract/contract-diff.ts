import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import * as yaml from 'js-yaml';

import type { OpenApiInspectionDiagnosticV1 } from '../openapi/inspect';
import type { CDNSecurityFrameworkPolicy } from '../types/policy';
import {
  projectPolicyToAllowedSurface,
  type AllowedSurfaceTarget,
  type AllowedTargetCapabilityV1,
} from './allowed-surface';
import { compareSecurityContracts } from './drift';
import {
  applyFindingExceptions,
  loadFindingExceptionsWithIdentity,
  type FindingExceptionSetV1,
} from './finding-exceptions';
import {
  FINDING_CATEGORIES,
  FINDING_CONFIDENCES,
  FINDING_SEVERITIES,
  type FindingCategory,
  type FindingConfidence,
  type FindingSeverity,
  type SecurityFindingV1,
} from './finding';
import { serializeSecurityContract, type SecurityContractCapabilitiesV1 } from './security-ir';
import { renderUnifiedContractDiffText } from '../reporters/text';

export const CONTRACT_DIFF_FAIL_ON = ['error', 'warning', 'never'] as const;
export type ContractDiffFailOn = typeof CONTRACT_DIFF_FAIL_ON[number];

export interface DiffSecurityContractsOptions {
  openapiPath: string;
  policyPath: string;
  target: AllowedSurfaceTarget;
  workspaceRoot: string;
  exceptionsPath?: string;
  currentDate?: string;
  environment?: string;
  includeSuppressed?: boolean;
}

export interface ContractDiffSummaryV1 {
  total: number;
  error: number;
  warning: number;
  info: number;
  suppressed: number;
  bySeverity: Record<FindingSeverity, number>;
  byConfidence: Record<FindingConfidence, number>;
  byCategory: Record<FindingCategory, number>;
}

export interface ContractDiffReportV1 {
  schemaVersion: 1;
  inputDigests: {
    openapi: string;
    policy: string;
    exceptions: string | null;
  };
  target: AllowedSurfaceTarget;
  summary: ContractDiffSummaryV1;
  findings: SecurityFindingV1[];
  suppressedFindings: SecurityFindingV1[];
  exceptionDiagnostics: SecurityFindingV1[];
  appliedExceptionIds: string[];
  analyzerCapabilities: {
    openapi: SecurityContractCapabilitiesV1;
    policy: AllowedTargetCapabilityV1[];
  };
  analyzerDiagnostics: OpenApiInspectionDiagnosticV1[];
  omittedComparisons: string[];
}

export class ContractDiffInputError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = 'ContractDiffInputError';
  }
}

interface ContractDiffExecution {
  report: ContractDiffReportV1;
  sourceIdentities: SourceIdentity[];
  workspace: { root: string; device: number; inode: number };
}

interface SourceIdentity {
  sourcePath: string;
  device: number;
  inode: number;
}

interface PolicySource {
  content: string;
  digest: string;
  filePath: string;
  device: number;
  inode: number;
}

interface PolicySnapshot {
  aliases: Map<string, string>;
  sources: PolicySource[];
}

const MAX_POLICY_FILE_BYTES = 1_048_576;
const MAX_POLICY_GRAPH_BYTES = 4_194_304;
const MAX_POLICY_SOURCES = 32;

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function within(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative);
}

function packageRoot(): string {
  const compiled = path.join(__dirname, '..');
  return fs.existsSync(path.join(compiled, 'policy', 'schema.json'))
    ? compiled
    : path.join(__dirname, '..', '..');
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort(compareText)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

function digest(value: string): string {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function semanticDigest(value: unknown): string {
  return digest(canonicalJson(value));
}

function workspaceRoot(input: string): string {
  if (typeof input !== 'string' || !input.trim()) {
    throw new ContractDiffInputError('CONTRACT_DIFF_WORKSPACE_INVALID', 'Workspace root is invalid.');
  }
  try {
    const root = fs.realpathSync(path.resolve(input));
    if (!fs.statSync(root).isDirectory()) throw new Error('not a directory');
    return root;
  } catch {
    throw new ContractDiffInputError('CONTRACT_DIFF_WORKSPACE_INVALID', 'Workspace root was not found.');
  }
}

function inputFile(root: string, input: string, code: string, label: string): string {
  if (typeof input !== 'string' || !input.trim()) {
    throw new ContractDiffInputError(code, `${label} path is required.`);
  }
  const candidate = path.resolve(root, input);
  try {
    const resolved = fs.realpathSync(candidate);
    if (!within(root, resolved) || !fs.statSync(resolved).isFile()) throw new Error('invalid input');
    return resolved;
  } catch {
    throw new ContractDiffInputError(code, `${label} was not found inside the workspace root.`);
  }
}

function readBoundedPolicyFile(root: string, filePath: string): {
  document: Record<string, unknown>;
  content: string;
  digest: string;
  bytes: number;
  device: number;
  inode: number;
} {
  let descriptor: number | undefined;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0),
    );
    const stat = fs.fstatSync(descriptor);
    const currentPath = fs.realpathSync(filePath);
    const currentStat = fs.statSync(currentPath);
    if (!within(root, currentPath) || currentStat.dev !== stat.dev || currentStat.ino !== stat.ino) {
      throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_OUTSIDE_ROOT', 'Policy input changed outside the workspace boundary.');
    }
    if (!stat.isFile() || stat.size > MAX_POLICY_FILE_BYTES) {
      throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_INVALID', 'Policy input is not a bounded regular file.');
    }
    const source = Buffer.allocUnsafe(MAX_POLICY_FILE_BYTES + 1);
    let bytes = 0;
    while (bytes < source.length) {
      const count = fs.readSync(descriptor, source, bytes, source.length - bytes, bytes);
      if (count === 0) break;
      bytes += count;
    }
    if (bytes > MAX_POLICY_FILE_BYTES) {
      throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_LIMIT', 'Policy input exceeds the file size limit.');
    }
    const content = source.subarray(0, bytes).toString('utf8');
    let parsed: unknown;
    try {
      parsed = yaml.load(content, {
        schema: yaml.JSON_SCHEMA,
        json: false,
        maxAliases: 50,
        maxDepth: 64,
      });
    } catch {
      throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_INVALID', 'Policy input could not be parsed safely.');
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
      || Object.getPrototypeOf(parsed) !== Object.prototype) {
      throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_INVALID', 'Policy input root is invalid.');
    }
    return {
      document: parsed as Record<string, unknown>, content, digest: digest(content), bytes,
      device: stat.dev, inode: stat.ino,
    };
  } catch (error: unknown) {
    if (error instanceof ContractDiffInputError) throw error;
    throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_INVALID', 'Policy input could not be read safely.');
  } finally {
    if (descriptor !== undefined) try { fs.closeSync(descriptor); } catch {}
  }
}

function policySources(root: string, entryPath: string): PolicySnapshot {
  const sources: PolicySource[] = [];
  const aliases = new Map<string, string>();
  const active = new Set<string>();
  let totalBytes = 0;
  let visits = 0;
  const visit = (filePath: string, lexicalPath = filePath): void => {
    aliases.set(lexicalPath, filePath);
    if (active.has(lexicalPath)) {
      throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_INVALID', 'Policy extends contains a cycle.');
    }
    visits += 1;
    if (visits > MAX_POLICY_SOURCES) {
      throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_LIMIT', 'Policy source count limit was exceeded.');
    }
    active.add(lexicalPath);
    const loaded = readBoundedPolicyFile(root, filePath);
    totalBytes += loaded.bytes;
    if (totalBytes > MAX_POLICY_GRAPH_BYTES) {
      throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_LIMIT', 'Policy source size limit was exceeded.');
    }
    const parent = loaded.document.extends;
    if (parent !== undefined) {
      if (typeof parent !== 'string' || !parent.trim()) {
        throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_INVALID', 'Policy extends is invalid.');
      }
      const lexicalParentPath = path.resolve(path.dirname(lexicalPath), parent.trim());
      const parentPath = inputFile(
        root,
        lexicalParentPath,
        'CONTRACT_DIFF_POLICY_OUTSIDE_ROOT',
        'Policy extends target',
      );
      visit(parentPath, lexicalParentPath);
    }
    active.delete(lexicalPath);
    if (!sources.some((source) => source.filePath === filePath)) {
      sources.push({
        filePath, digest: loaded.digest, content: loaded.content,
        device: loaded.device, inode: loaded.inode,
      });
    }
  };
  visit(entryPath);
  return { aliases, sources };
}

function loadPolicy(root: string, policyPath: string): {
  policy: CDNSecurityFrameworkPolicy;
  sources: PolicySource[];
} {
  const { parsePolicyFile } = require(path.join(packageRoot(), 'parser')) as typeof import('../parser');
  const { validatePolicy } = require(path.join(packageRoot(), 'validator')) as typeof import('../validator');
  const before = policySources(root, policyPath);
  const snapshots = new Map(before.sources.map(({ filePath, content }) => [filePath, content]));
  const parsed = parsePolicyFile({
    policyPath,
    readPolicyFile: (absolutePath) => {
      const lexicalPath = path.resolve(absolutePath);
      const resolvedPath = before.aliases.get(lexicalPath) ?? lexicalPath;
      const content = snapshots.get(resolvedPath);
      if (content === undefined) throw new Error('policy source is outside the verified snapshot');
      return content;
    },
  });
  if (!parsed.ok || !parsed.policy) {
    throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_INVALID', 'Policy input is invalid.');
  }
  const validation = validatePolicy({ policy: parsed.policy, pkgRoot: packageRoot(), env: {} });
  if (!validation.ok) {
    throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_INVALID', 'Policy input failed schema validation.');
  }
  const after = policySources(root, policyPath);
  const identity = ({ aliases, sources }: PolicySnapshot) => ({
    aliases: [...aliases].sort(([left], [right]) => compareText(left, right)),
    sources: sources.map(({ filePath, digest }) => ({ filePath, digest })),
  });
  if (canonicalJson(identity(before)) !== canonicalJson(identity(after))) {
    throw new ContractDiffInputError('CONTRACT_DIFF_POLICY_CHANGED', 'Policy input changed during analysis.');
  }
  return { policy: parsed.policy as CDNSecurityFrameworkPolicy, sources: before.sources };
}

function sourceUri(root: string, filePath: string): string {
  return path.relative(root, filePath).split(path.sep).map(encodeURIComponent).join('/');
}

function emptyCounts<T extends string>(values: readonly T[]): Record<T, number> {
  return Object.fromEntries(values.map((value) => [value, 0])) as Record<T, number>;
}

function summary(
  active: readonly SecurityFindingV1[],
  suppressed: readonly SecurityFindingV1[],
): ContractDiffSummaryV1 {
  const bySeverity = emptyCounts(FINDING_SEVERITIES);
  const byConfidence = emptyCounts(FINDING_CONFIDENCES);
  const byCategory = emptyCounts(FINDING_CATEGORIES);
  for (const finding of active) {
    bySeverity[finding.severity] += 1;
    byConfidence[finding.confidence] += 1;
    byCategory[finding.category] += 1;
  }
  return {
    total: active.length,
    error: bySeverity.error,
    warning: bySeverity.warning,
    info: bySeverity.info,
    suppressed: suppressed.length,
    bySeverity,
    byConfidence,
    byCategory,
  };
}

function omittedComparisons(
  capabilities: SecurityContractCapabilitiesV1,
  policyCapabilities: readonly AllowedTargetCapabilityV1[],
): string[] {
  return [
    ...Object.entries(capabilities)
      .filter(([, status]) => status !== 'complete')
      .map(([name, status]) => `openapi.${name}:${status}`),
    ...policyCapabilities
      .filter(({ status }) => status !== 'supported')
      .map(({ id, status }) => `policy.${id}:${status}`),
  ].sort(compareText);
}

function execute(options: DiffSecurityContractsOptions): ContractDiffExecution {
  if (!options || !['aws', 'cloudflare'].includes(options.target)) {
    throw new ContractDiffInputError('CONTRACT_DIFF_TARGET_INVALID', 'Target must be aws or cloudflare.');
  }
  if (options.environment !== undefined
    && (!options.environment.trim() || options.environment.length > 128)) {
    throw new ContractDiffInputError('CONTRACT_DIFF_ENVIRONMENT_INVALID', 'Environment must be 1 to 128 characters.');
  }
  const root = workspaceRoot(options.workspaceRoot);
  const rootStat = fs.statSync(root);
  const openapiPath = inputFile(root, options.openapiPath, 'CONTRACT_DIFF_OPENAPI_INVALID', 'OpenAPI input');
  const policyPath = inputFile(root, options.policyPath, 'CONTRACT_DIFF_POLICY_INVALID', 'Policy input');
  const { inspectOpenApiForCli } = require(path.join(
    packageRoot(), 'openapi', 'inspect',
  )) as typeof import('../openapi/inspect');
  const inspection = inspectOpenApiForCli({ inputPath: openapiPath, workspaceRoot: root });
  const loadedPolicy = loadPolicy(root, policyPath);
  const policyDigest = semanticDigest(loadedPolicy.policy);
  const allowed = projectPolicyToAllowedSurface(loadedPolicy.policy, {
    policyDigest,
    sourceUri: sourceUri(root, policyPath),
  });
  let findings: SecurityFindingV1[];
  try {
    findings = compareSecurityContracts({
      declared: inspection.report.contract,
      allowed,
      target: options.target,
    });
  } catch (error: unknown) {
    if (error instanceof Error && /invalid contract drift input|visit budget/.test(error.message)) {
      throw new ContractDiffInputError('CONTRACT_DIFF_COMPARISON_LIMIT', 'Contract comparison input is invalid or exceeds its limit.');
    }
    throw error;
  }

  let suppressedFindings: SecurityFindingV1[] = [];
  let exceptionDiagnostics: SecurityFindingV1[] = [];
  let appliedExceptionIds: string[] = [];
  let exceptionsDigest: string | null = null;
  const sourceIdentities: SourceIdentity[] = [
    ...inspection.sourceIdentities,
    ...loadedPolicy.sources.map(({ filePath: sourcePath, device, inode }) => ({ sourcePath, device, inode })),
  ];
  if (options.exceptionsPath) {
    const exceptionsPath = inputFile(
      root,
      options.exceptionsPath,
      'CONTRACT_DIFF_EXCEPTIONS_INVALID',
      'Finding exceptions input',
    );
    let exceptions: FindingExceptionSetV1;
    try {
      const currentDate = options.currentDate ?? new Date().toISOString().slice(0, 10);
      const loadedExceptions = loadFindingExceptionsWithIdentity({
        inputPath: exceptionsPath,
        workspaceRoot: root,
        currentDate,
      });
      exceptions = loadedExceptions.exceptions;
      sourceIdentities.push(loadedExceptions.sourceIdentity);
      const applied = applyFindingExceptions(findings, exceptions, {
        currentDate,
        target: options.target,
        environment: options.environment,
        sourceUri: sourceUri(root, exceptionsPath),
      });
      findings = applied.findings.filter(({ category }) => category !== 'governance');
      exceptionDiagnostics = applied.findings.filter(({ category }) => category === 'governance');
      suppressedFindings = applied.suppressedFindings;
      appliedExceptionIds = applied.appliedExceptionIds;
      exceptionsDigest = semanticDigest({
        exceptions, currentDate, environment: options.environment ?? null,
      });
    } catch (error: unknown) {
      if (error instanceof ContractDiffInputError) throw error;
      throw new ContractDiffInputError('CONTRACT_DIFF_EXCEPTIONS_INVALID', 'Finding exceptions input is invalid.');
    }
  }
  const active = [...findings, ...exceptionDiagnostics];
  const policyCapabilities = allowed.targetCapabilities[options.target];
  return {
    report: {
      schemaVersion: 1,
      inputDigests: {
        openapi: digest(serializeSecurityContract(inspection.report.contract)),
        policy: policyDigest,
        exceptions: exceptionsDigest,
      },
      target: options.target,
      summary: summary(active, suppressedFindings),
      findings,
      suppressedFindings: options.includeSuppressed ? suppressedFindings : [],
      exceptionDiagnostics,
      appliedExceptionIds,
      analyzerCapabilities: {
        openapi: inspection.report.capabilities,
        policy: policyCapabilities,
      },
      analyzerDiagnostics: inspection.report.diagnostics,
      omittedComparisons: omittedComparisons(inspection.report.capabilities, policyCapabilities),
    },
    sourceIdentities: sourceIdentities
      .filter((identity, index, values) => values.findIndex(({ device, inode }) => (
        device === identity.device && inode === identity.inode
      )) === index)
      .sort((left, right) => compareText(left.sourcePath, right.sourcePath)),
    workspace: { root, device: rootStat.dev, inode: rootStat.ino },
  };
}

export function diffSecurityContracts(options: DiffSecurityContractsOptions): ContractDiffReportV1 {
  return execute(options).report;
}

export function diffSecurityContractsForCli(options: DiffSecurityContractsOptions): ContractDiffExecution {
  return execute(options);
}

export function contractDiffExitCode(
  report: ContractDiffReportV1,
  failOn: ContractDiffFailOn,
): 0 | 1 {
  if (!CONTRACT_DIFF_FAIL_ON.includes(failOn)) {
    throw new ContractDiffInputError('CONTRACT_DIFF_FAIL_ON_INVALID', 'fail-on must be error, warning, or never.');
  }
  if (failOn === 'never') return 0;
  if (report.summary.error > 0) return 1;
  return failOn === 'warning' && report.summary.warning > 0 ? 1 : 0;
}

export function formatContractDiffJson(report: ContractDiffReportV1): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

export function formatContractDiffText(
  report: ContractDiffReportV1,
  options: { color?: boolean } = {},
): string {
  return renderUnifiedContractDiffText(report, options);
}
