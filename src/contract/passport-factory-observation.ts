import { hasUnsafeSensitiveText, redactEvidenceFilename } from './sensitive-text';

export const PASSPORT_FACTORY_OBSERVER = 'nestjs-passport-direct-factory@1' as const;

export type PassportFactoryReason =
  | 'factory-origin-unverified' | 'factory-arguments-unsupported'
  | 'strategy-not-literal' | 'strategy-unsafe' | 'indirect-guard-value';

export interface PassportFactoryCallSite {
  id: string;
  scope: 'class' | 'method';
  sourceUri: string;
  line: number;
  column: number;
  sourceDigest: string;
  module?: '@nestjs/passport';
  export?: 'AuthGuard';
  strategy?: string;
  reason?: PassportFactoryReason;
}

export interface PassportFactoryAssociation {
  callSiteId: string;
  method: string;
  localPath: string;
  comparisonPath: string;
  authMode: 'none' | 'alternatives' | 'unknown';
}

export interface PassportFactoryOperation {
  method: string;
  comparisonPath: string;
  status: 'observed' | 'unsupported' | 'no-direct-factory';
  authMode: 'none' | 'alternatives' | 'unknown';
}

export interface PassportFactoryObservation {
  observer: typeof PASSPORT_FACTORY_OBSERVER;
  digest: string;
  callSites: PassportFactoryCallSite[];
  associations: PassportFactoryAssociation[];
  operations: PassportFactoryOperation[];
}

const MAX_CALL_SITES = 20;
const MAX_ASSOCIATIONS = 40;
const MAX_OPERATIONS = 40;
const MAX_PREVIEW_BYTES = 20_480;

function safeUri(value: string): string {
  if (value.length > 256 || value.startsWith('/') || value.split('/').includes('..')
    || !/^[A-Za-z0-9._/-]+$/u.test(value) || hasUnsafeSensitiveText(value)) return '[REDACTED_URI]';
  return redactEvidenceFilename(value);
}

function safeRoute(value: string): string {
  if (value.length > 256 || !value.startsWith('/') || value.split('/').includes('..')
    || !/^\/[A-Za-z0-9._~{}:/-]*$/u.test(value) || hasUnsafeSensitiveText(value)) return '[REDACTED_ROUTE]';
  return redactEvidenceFilename(value);
}

// A display-only projection. Counts and digest always describe the full same-run observation.
export function previewPassportFactoryObservation(observation: PassportFactoryObservation) {
  const callSites = observation.callSites.slice(0, MAX_CALL_SITES).map((site) => ({
    id: site.id, scope: site.scope, sourceUri: safeUri(site.sourceUri),
    line: site.line, column: site.column, sourceDigest: site.sourceDigest,
    ...(site.module && site.export ? { module: site.module, export: site.export } : {}),
    ...(site.strategy ? { strategy: site.strategy } : {}),
    ...(site.reason ? { reason: site.reason } : {}),
  }));
  const associations = observation.associations.slice(0, MAX_ASSOCIATIONS).map((item) => ({
    callSiteId: item.callSiteId, method: item.method, localPath: safeRoute(item.localPath),
    comparisonPath: safeRoute(item.comparisonPath), authMode: item.authMode,
  }));
  const operations = observation.operations.slice(0, MAX_OPERATIONS).map((item) => ({
    method: item.method, comparisonPath: safeRoute(item.comparisonPath),
    status: item.status, authMode: item.authMode,
  }));
  const make = () => ({
    observer: observation.observer, digest: observation.digest,
    totalCallSites: observation.callSites.length,
    totalAssociations: observation.associations.length,
    totalOperations: observation.operations.length,
    omittedCallSites: observation.callSites.length - callSites.length,
    omittedAssociations: observation.associations.length - associations.length,
    omittedOperations: observation.operations.length - operations.length,
    callSites, associations, operations,
    runtimeStrategyRegistrationVerified: false as const,
    runtimeEnforcementVerified: false as const,
  });
  while (Buffer.byteLength(JSON.stringify(make())) > MAX_PREVIEW_BYTES
    && (operations.length || associations.length || callSites.length)) {
    if (operations.length) operations.pop();
    else if (associations.length) associations.pop();
    else callSites.pop();
  }
  return make();
}
