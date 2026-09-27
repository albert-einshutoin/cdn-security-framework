import { createHash } from 'node:crypto';

import { canonicalizePath, createRouteKey } from './canonical-route';
import { hasUnsafeSensitiveText } from './sensitive-text';
import { securityContractSemanticDigest } from './semantic-digest';
import { createSecurityContract, type SecurityContractV1 } from './security-ir';

const MAX_PREFIX_LENGTH = 256;
const FIXED_SEGMENTS = /^\/?[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/;

/** One explicit fixed routing assumption; this does not inspect application bootstrap code. */
export function normalizeSourceGlobalPrefix(value: unknown): string {
  if (typeof value !== 'string' || !FIXED_SEGMENTS.test(value) || hasUnsafeSensitiveText(value)) {
    throw new Error('SOURCE_GLOBAL_PREFIX_INVALID');
  }
  const normalized = value.startsWith('/') ? value : `/${value}`;
  if (normalized.length > MAX_PREFIX_LENGTH) throw new Error('SOURCE_GLOBAL_PREFIX_INVALID');
  return normalized;
}

export function sourceRoutingAssumptionDigest(prefix: string): string {
  const normalized = normalizeSourceGlobalPrefix(prefix);
  return `sha256:${createHash('sha256').update(JSON.stringify({ version: 1, globalPrefix: normalized })).digest('hex')}`;
}

export function sourceUriRoutingAssumptionDigest(prefix?: string): string {
  const globalPrefix = prefix === undefined ? undefined : normalizeSourceGlobalPrefix(prefix);
  return `sha256:${createHash('sha256').update(JSON.stringify({ version: 2,
    sourceVersioning: 'uri', versionPrefix: 'v', ...(globalPrefix ? { globalPrefix } : {}),
  })).digest('hex')}`;
}

/** Return a comparison-only IR copy. The analyzer result and original provenance are left intact. */
export function prefixSourceContract(contract: SecurityContractV1, prefix: string): SecurityContractV1 {
  const normalized = normalizeSourceGlobalPrefix(prefix);
  if (contract.source !== 'source-ast') throw new Error('SOURCE_GLOBAL_PREFIX_CONTRACT_INVALID');
  const operations = contract.operations.map((operation) => {
    if (canonicalizePath(operation.path) !== operation.path
      || createRouteKey(operation.method, operation.path) !== operation.routeKey) {
      throw new Error('SOURCE_GLOBAL_PREFIX_CONTRACT_INVALID');
    }
    const { routeKey: _routeKey, ...rest } = operation;
    return { ...rest, path: canonicalizePath(`${normalized}${operation.path === '/' ? '' : operation.path}`) };
  });
  return createSecurityContract({ source: contract.source, capabilities: contract.capabilities, operations });
}

export function sourceComparisonContractDigest(contract: SecurityContractV1): string {
  return securityContractSemanticDigest(contract);
}
