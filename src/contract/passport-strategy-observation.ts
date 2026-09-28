import { createHash } from 'node:crypto';

import { hasUnsafeSensitiveText, redactEvidenceFilename } from './sensitive-text';
import type { PassportFactoryObservation } from './passport-factory-observation';

export const PASSPORT_STRATEGY_OBSERVER = 'nestjs-passport-static-strategy-link@1' as const;

export interface PassportStrategyDefinition {
  id: string;
  strategy: string;
  className: string;
  sourceUri: string;
  line: number;
  column: number;
  sourceDigest: string;
  baseStatus: 'verified' | 'unverified';
  baseModule?: 'passport-jwt';
  extractor: { status: 'observed'; kind: 'bearer-header-call'; id: string;
    sourceUri: string; line: number; column: number; sourceDigest: string }
    | { status: 'unconfirmed' };
}

export interface PassportStrategyProvider {
  id: string;
  definitionId: string;
  moduleClass: string;
  sourceUri: string;
  line: number;
  column: number;
  sourceDigest: string;
}

export interface PassportStrategyMatch {
  callSiteId: string;
  strategy?: string;
  status: 'one' | 'multiple' | 'none' | 'unmatchable';
  reason?: 'factory-input' | 'definition-name-unverified';
  candidateIds: string[];
}

export interface PassportStrategyObservation {
  observer: typeof PASSPORT_STRATEGY_OBSERVER;
  digest: string;
  factoryDigest: string;
  incompleteDefinitionNames: number;
  definitions: PassportStrategyDefinition[];
  providers: PassportStrategyProvider[];
  matches: PassportStrategyMatch[];
}

export function strategyNameIsSafe(name: string): boolean {
  return /^[A-Za-z][A-Za-z0-9._-]{0,63}$/u.test(name)
    && !/^(?:sk-|gh[opsur]_|github_pat_|AKIA|(?:sk|pk)_)/iu.test(name)
    && !hasUnsafeSensitiveText(name);
}

function safeUri(value: string): string {
  if (value.length > 256 || value.startsWith('/') || value.split('/').includes('..')
    || !/^[A-Za-z0-9._/-]+$/u.test(value) || hasUnsafeSensitiveText(value)) return '[REDACTED_URI]';
  return redactEvidenceFilename(value);
}

function safeName(value: string): string {
  return strategyNameIsSafe(value) ? value : '[REDACTED_NAME]';
}

// Full candidate matching happens before any display redaction or truncation.
export function previewPassportStrategyObservation(observation: PassportStrategyObservation) {
  const definitions = observation.definitions.slice(0, 20).map((item) => ({
    ...item, strategy: safeName(item.strategy), className: safeName(item.className),
    sourceUri: safeUri(item.sourceUri), extractor: item.extractor.status === 'observed'
      ? { ...item.extractor, sourceUri: safeUri(item.extractor.sourceUri) } : item.extractor,
  }));
  const providers = observation.providers.slice(0, 40).map((item) => ({
    ...item, moduleClass: safeName(item.moduleClass), sourceUri: safeUri(item.sourceUri),
  }));
  const matches = observation.matches.slice(0, 40).map((item) => ({
    ...item, ...(item.strategy ? { strategy: safeName(item.strategy) } : {}),
    totalCandidates: item.candidateIds.length,
    omittedCandidates: Math.max(0, item.candidateIds.length - 20),
    candidateIds: item.candidateIds.slice(0, 20),
  }));
  const make = () => ({
    observer: observation.observer, digest: observation.digest, factoryDigest: observation.factoryDigest,
    incompleteDefinitionNames: observation.incompleteDefinitionNames,
    totalDefinitions: observation.definitions.length, totalProviders: observation.providers.length,
    totalMatches: observation.matches.length,
    omittedDefinitions: observation.definitions.length - definitions.length,
    omittedProviders: observation.providers.length - providers.length,
    omittedMatches: observation.matches.length - matches.length,
    definitions, providers, matches,
    runtimeRegistrationVerified: false as const, runtimeEnforcementVerified: false as const,
  });
  while (Buffer.byteLength(JSON.stringify(make())) > 20_480
    && (matches.length || providers.length || definitions.length)) {
    if (matches.length) matches.pop();
    else if (providers.length) providers.pop();
    else definitions.pop();
  }
  return make();
}

export function linkPassportStrategies(
  snapshotDigest: string,
  factory: PassportFactoryObservation,
  definitions: PassportStrategyDefinition[],
  providers: PassportStrategyProvider[],
  incompleteDefinitionNames: number,
): PassportStrategyObservation {
  const orderedDefinitions = [...definitions].sort((a, b) => a.id.localeCompare(b.id));
  const orderedProviders = [...providers].sort((a, b) => a.id.localeCompare(b.id));
  const candidatesByName = new Map<string, string[]>();
  for (const definition of orderedDefinitions) {
    const ids = candidatesByName.get(definition.strategy) ?? [];
    ids.push(definition.id);
    candidatesByName.set(definition.strategy, ids);
  }
  const matches: PassportStrategyMatch[] = factory.callSites.map((site) => {
    const candidateIds = site.strategy ? candidatesByName.get(site.strategy) ?? [] : [];
    return { callSiteId: site.id, ...(site.strategy ? { strategy: site.strategy } : {}),
      ...(!site.strategy ? { reason: 'factory-input' as const }
        : candidateIds.length === 0 && incompleteDefinitionNames > 0
          ? { reason: 'definition-name-unverified' as const } : {}),
      status: !site.strategy || candidateIds.length === 0 && incompleteDefinitionNames > 0
        ? 'unmatchable' as const : candidateIds.length === 0 ? 'none' as const
        : candidateIds.length === 1 ? 'one' as const : 'multiple' as const, candidateIds };
  }).sort((a, b) => a.callSiteId.localeCompare(b.callSiteId));
  const observer = PASSPORT_STRATEGY_OBSERVER;
  const digest = `sha256:${createHash('sha256').update(JSON.stringify({ observer,
    input: snapshotDigest, factoryDigest: factory.digest,
    definitions: orderedDefinitions, providers: orderedProviders, matches, incompleteDefinitionNames,
  })).digest('hex')}`;
  return { observer, digest, factoryDigest: factory.digest,
    definitions: orderedDefinitions, providers: orderedProviders, matches,
    incompleteDefinitionNames };
}
