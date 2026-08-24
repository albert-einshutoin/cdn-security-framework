import { FINDING_EVIDENCE_SOURCES, type FindingEvidenceV1 } from './finding';
import { canonicalizePath, createRouteKey, normalizeHttpMethod, type HttpMethod } from './canonical-route';

export const CONTRACT_SOURCES = ['openapi', 'source-ast', 'policy', 'runtime'] as const;
export const CAPABILITY_LEVELS = ['complete', 'partial', 'unsupported'] as const;
export const EXPOSURES = ['public', 'authenticated', 'privileged', 'unknown'] as const;
export const VALUE_TYPES = ['string', 'integer', 'number', 'boolean', 'array', 'object', 'unknown'] as const;
export const AUTH_SCHEME_KINDS = [
  'basic', 'bearer', 'api-key', 'oauth2', 'openid-connect', 'mutual-tls', 'unknown',
] as const;

export type ContractSourceV1 = typeof CONTRACT_SOURCES[number];
export type CapabilityLevelV1 = typeof CAPABILITY_LEVELS[number];
export type ExposureV1 = typeof EXPOSURES[number];
export type ValueTypeV1 = typeof VALUE_TYPES[number];
export type AuthSchemeKindV1 = typeof AUTH_SCHEME_KINDS[number];

export interface SecurityContractCapabilitiesV1 {
  routes: CapabilityLevelV1;
  parameters: CapabilityLevelV1;
  requestBodies: CapabilityLevelV1;
  authentication: CapabilityLevelV1;
}

export interface ValueConstraintsV1 {
  type: ValueTypeV1;
  format?: string;
  enum?: Array<string | number | boolean | null>;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  minItems?: number;
  maxItems?: number;
  maxProperties?: number;
  properties?: Record<string, ValueConstraintsV1>;
  requiredProperties?: string[];
  additionalProperties?: boolean;
  items?: ValueConstraintsV1;
}

export interface ApiParameterContractV1 {
  name: string;
  required: boolean;
  constraints: ValueConstraintsV1;
  style?: string;
  explode?: boolean;
  unsupportedReasons: string[];
}

export interface ApiRequestBodyContractV1 {
  required: boolean;
  constraints: ValueConstraintsV1;
  unsupportedReasons: string[];
}

export interface ApiRequestContractV1 {
  contentTypes: string[];
  requiredHeaders: string[];
  queryParameters: ApiParameterContractV1[];
  pathParameters: ApiParameterContractV1[];
  headerParameters: ApiParameterContractV1[];
  cookieParameters: ApiParameterContractV1[];
  body?: ApiRequestBodyContractV1;
}

export interface ApiAuthSchemeV1 {
  name: string;
  kind: AuthSchemeKindV1;
  location?: 'header' | 'query' | 'cookie';
  parameterName?: string;
  scopes: string[];
  flows?: string[];
  capability: 'supported' | 'unsupported';
  unsupportedReason?: string;
}

export interface ApiAuthAlternativeV1 {
  anonymous: boolean;
  schemes: ApiAuthSchemeV1[];
}

export interface ApiAuthGuardAnalysisV1 {
  symbol: string;
  authKind?: AuthSchemeKindV1;
}

export interface ApiAuthAnalysisV1 {
  guards: ApiAuthGuardAnalysisV1[];
  explicitPublic: boolean;
  roles: string[];
  enforcementConfidence: 'high' | 'unknown';
  capabilityReasons: string[];
}

export interface ApiAuthenticationContractV1 {
  mode: 'none' | 'unknown' | 'alternatives';
  alternatives: ApiAuthAlternativeV1[];
  analysis?: ApiAuthAnalysisV1;
}

export interface ApiOperationContractV1 {
  routeKey: string;
  method: HttpMethod;
  path: string;
  operationId?: string;
  exposure: ExposureV1;
  auth: ApiAuthenticationContractV1;
  request: ApiRequestContractV1;
  provenance: FindingEvidenceV1[];
  metadata?: { deprecated: boolean; tags: string[] };
}

export interface SecurityContractV1 {
  schemaVersion: 1;
  source: ContractSourceV1;
  capabilities: SecurityContractCapabilitiesV1;
  operations: ApiOperationContractV1[];
}

export interface SecurityContractInputV1 {
  source: ContractSourceV1;
  capabilities: SecurityContractCapabilitiesV1;
  operations: ApiOperationInputV1[];
}

export type ApiOperationInputV1 = Omit<ApiOperationContractV1, 'routeKey' | 'method'> & {
  routeKey?: string;
  method: string;
};

const SECRET_PATTERN = /\b(?:Bearer|Basic)\s+\S+|\b(?:sk-(?:proj-)?|ghp_|github_pat_|AKIA|(?:sk|pk)_)[A-Za-z0-9_-]{8,}|\b(?:authorization|proxy-authorization|cookie|set-cookie|password|secret|client_secret|access_token|refresh_token|token|api[_-]?key)\s*[=:]\s*\S+/i;
const MAX_STRING_LENGTH = 16_384;
const MAX_IR_NODES = 100_000;
const MAX_CONSTRAINT_DEPTH = 256;

interface NormalizationState { nodes: number }

function consume(state: NormalizationState, count: number): void {
  state.nodes += count;
  if (state.nodes > MAX_IR_NODES) throw new Error('security contract exceeds size limit');
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function nonEmpty(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length > MAX_STRING_LENGTH || !value.trim()) {
    throw new Error(`invalid ${field}`);
  }
  const normalized = value.trim();
  if (SECRET_PATTERN.test(normalized)) throw new Error('secret-like value is not allowed');
  return normalized;
}

function booleanValue(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') throw new Error(`invalid ${field}`);
  return value;
}

function sortedSet(
  values: readonly string[],
  field: string,
  state: NormalizationState,
  transform = (value: string) => value,
): string[] {
  if (!Array.isArray(values)) throw new Error(`invalid ${field}`);
  consume(state, values.length);
  return [...new Set(values.map((value) => nonEmpty(transform(nonEmpty(value, field)), field)))].sort(compareText);
}

function sortedRawSet(values: readonly string[], field: string, state: NormalizationState): string[] {
  if (!Array.isArray(values)) throw new Error(`invalid ${field}`);
  consume(state, values.length);
  for (const value of values) {
    if (typeof value !== 'string' || value.length > MAX_STRING_LENGTH) throw new Error(`invalid ${field}`);
    if (SECRET_PATTERN.test(value.trim())) throw new Error('secret-like value is not allowed');
  }
  return [...new Set(values)].sort(compareText);
}

function normalizeConstraints(
  input: ValueConstraintsV1,
  state: NormalizationState,
  depth = 0,
  ancestors = new Set<object>(),
): ValueConstraintsV1 {
  if (!input || typeof input !== 'object' || !VALUE_TYPES.includes(input.type)) {
    throw new Error('invalid value constraints');
  }
  if (depth >= MAX_CONSTRAINT_DEPTH) throw new Error('value constraints exceed depth limit');
  if (ancestors.has(input)) throw new Error('cyclic value constraints are not allowed');
  consume(state, 1);
  const nextAncestors = new Set(ancestors).add(input);
  const output: ValueConstraintsV1 = { type: input.type };
  if (input.format !== undefined) output.format = nonEmpty(input.format, 'constraint format');
  if (input.enum !== undefined) {
    if (!Array.isArray(input.enum)) throw new Error('invalid constraint enum');
    consume(state, input.enum.length);
    for (const value of input.enum) {
      if (!['string', 'number', 'boolean'].includes(typeof value) && value !== null) {
        throw new Error('invalid constraint enum');
      }
      if (typeof value === 'number' && !Number.isFinite(value)) {
        throw new Error('invalid constraint enum');
      }
      if (typeof value === 'string' && (value.length > MAX_STRING_LENGTH || SECRET_PATTERN.test(value))) {
        throw new Error('secret-like value is not allowed');
      }
    }
    const byValue = new Map(input.enum.map((value) => [JSON.stringify(value), value]));
    output.enum = [...byValue.entries()].sort(([left], [right]) => compareText(left, right))
      .map(([, value]) => value);
  }
  for (const field of [
    'minimum', 'maximum', 'minLength', 'maxLength', 'minItems', 'maxItems', 'maxProperties',
  ] as const) {
    const value = input[field];
    if (value === undefined) continue;
    const isCount = field !== 'minimum' && field !== 'maximum';
    if (!Number.isFinite(value) || (isCount && (!Number.isInteger(value) || value < 0))) {
      throw new Error(`invalid constraint ${field}`);
    }
    output[field] = value;
  }
  if (output.minimum !== undefined && output.maximum !== undefined && output.minimum > output.maximum) {
    throw new Error('invalid constraint range');
  }
  for (const [minimum, maximum] of [
    [output.minLength, output.maxLength],
    [output.minItems, output.maxItems],
  ]) {
    if (minimum !== undefined && maximum !== undefined && minimum > maximum) {
      throw new Error('invalid constraint range');
    }
  }
  if (input.properties !== undefined) {
    if (input.type !== 'object' || !input.properties || typeof input.properties !== 'object'
      || Array.isArray(input.properties)) throw new Error('invalid constraint properties');
    const entries = Object.entries(input.properties).sort(([left], [right]) => compareText(left, right));
    consume(state, entries.length);
    const properties = Object.fromEntries(entries.map(([name, constraints]) => [
      nonEmpty(name, 'constraint property'), normalizeConstraints(constraints, state, depth + 1, nextAncestors),
    ]));
    output.properties = properties;
  }
  if (input.requiredProperties !== undefined) {
    if (input.type !== 'object') throw new Error('invalid constraint required properties');
    output.requiredProperties = sortedSet(input.requiredProperties, 'constraint required property', state);
    const properties = output.properties;
    if (properties && output.requiredProperties.some((name) => !(name in properties))) {
      throw new Error('invalid constraint required properties');
    }
  }
  if (input.additionalProperties !== undefined) {
    if (input.type !== 'object' || typeof input.additionalProperties !== 'boolean') {
      throw new Error('invalid constraint additional properties');
    }
    output.additionalProperties = input.additionalProperties;
  }
  if (input.items !== undefined) {
    if (input.type !== 'array') throw new Error('invalid constraint items');
    output.items = normalizeConstraints(input.items, state, depth + 1, nextAncestors);
  }
  return output;
}

function normalizeParameter(input: ApiParameterContractV1, state: NormalizationState): ApiParameterContractV1 {
  if (!input || typeof input !== 'object') throw new Error('invalid parameter');
  return {
    name: nonEmpty(input.name, 'parameter name'),
    required: booleanValue(input.required, 'parameter required'),
    constraints: normalizeConstraints(input.constraints, state),
    ...(input.style === undefined ? {} : { style: nonEmpty(input.style, 'parameter style') }),
    ...(input.explode === undefined ? {} : { explode: booleanValue(input.explode, 'parameter explode') }),
    unsupportedReasons: sortedSet(input.unsupportedReasons, 'unsupported reason', state),
  };
}

function normalizeParameters(
  values: ApiParameterContractV1[],
  field: string,
  state: NormalizationState,
  normalizeName = (name: string) => name,
): ApiParameterContractV1[] {
  if (!Array.isArray(values)) throw new Error(`invalid ${field}`);
  consume(state, values.length);
  const normalized = values.map((value) => normalizeParameter(value, state)).map((parameter) => ({
    ...parameter,
    name: normalizeName(parameter.name),
  })).sort((a, b) => compareText(a.name, b.name));
  if (new Set(normalized.map(({ name }) => name)).size !== normalized.length) {
    throw new Error(`duplicate ${field}`);
  }
  return normalized;
}

function normalizeRequest(input: ApiRequestContractV1, state: NormalizationState): ApiRequestContractV1 {
  if (!input) throw new Error('invalid request contract');
  return {
    contentTypes: sortedSet(input.contentTypes, 'content type', state, (value) => value.split(';', 1)[0].trim().toLowerCase()),
    requiredHeaders: sortedSet(input.requiredHeaders, 'required header', state, (value) => value.toLowerCase()),
    queryParameters: normalizeParameters(input.queryParameters, 'query parameters', state),
    pathParameters: normalizeParameters(input.pathParameters, 'path parameters', state),
    headerParameters: normalizeParameters(input.headerParameters, 'header parameters', state, (name) => name.toLowerCase()),
    cookieParameters: normalizeParameters(input.cookieParameters, 'cookie parameters', state),
    ...(input.body === undefined ? {} : {
      body: {
        required: booleanValue(input.body.required, 'request body required'),
        constraints: normalizeConstraints(input.body.constraints, state),
        unsupportedReasons: sortedSet(input.body.unsupportedReasons, 'unsupported reason', state),
      },
    }),
  };
}

function stableSerialize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableSerialize).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableSerialize(record[key])}`).join(',')}}`;
}

function normalizeEvidence(input: FindingEvidenceV1): FindingEvidenceV1 {
  if (!input || typeof input !== 'object') throw new Error('invalid provenance');
  const uri = nonEmpty(input.uri, 'provenance uri').replace(/\\/g, '/');
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(uri)
    || uri.startsWith('/') || /[?#]/.test(uri) || uri.split('/').includes('..')) {
    throw new Error('invalid provenance uri');
  }
  if (!FINDING_EVIDENCE_SOURCES.includes(input.source)
    || typeof input.complete !== 'boolean') throw new Error('invalid provenance');
  return {
    source: input.source,
    uri: uri.replace(/^\.\//, ''),
    ...(input.pointer === undefined ? {} : {
      pointer: (() => {
        const pointer = nonEmpty(input.pointer, 'provenance pointer');
        if (/[?#]/.test(pointer)) throw new Error('invalid provenance pointer');
        return pointer;
      })(),
    }),
    digest: nonEmpty(input.digest, 'provenance digest'),
    analyzer: nonEmpty(input.analyzer, 'provenance analyzer'),
    capability: nonEmpty(input.capability, 'provenance capability'),
    complete: input.complete,
  };
}

function normalizeAuth(input: ApiAuthenticationContractV1, state: NormalizationState): ApiAuthenticationContractV1 {
  if (!input || !['none', 'unknown', 'alternatives'].includes(input.mode) || !Array.isArray(input.alternatives)) {
    throw new Error('invalid authentication contract');
  }
  if ((input.mode !== 'alternatives' && input.alternatives.length > 0)
    || (input.mode === 'alternatives' && input.alternatives.length === 0)) {
    throw new Error('authentication alternatives require alternatives mode');
  }
  consume(state, input.alternatives.length);
  const alternatives = input.alternatives.map((alternative) => {
    if (!alternative || typeof alternative !== 'object') throw new Error('invalid authentication alternative');
    const { schemes } = alternative;
    if (!Array.isArray(schemes)) throw new Error('invalid authentication alternative');
    const anonymous = booleanValue(alternative.anonymous, 'authentication alternative');
    if (anonymous !== (schemes.length === 0)) throw new Error('invalid authentication alternative');
    consume(state, schemes.length);
    const byName = new Map<string, string>();
    const normalizedSchemes = schemes.map((scheme) => {
      if (!scheme || typeof scheme !== 'object'
        || !AUTH_SCHEME_KINDS.includes(scheme.kind)
        || !['supported', 'unsupported'].includes(scheme.capability)
        || (scheme.location !== undefined && !['header', 'query', 'cookie'].includes(scheme.location))
        || (scheme.capability === 'unsupported' && scheme.unsupportedReason === undefined)) {
        throw new Error('invalid authentication scheme');
      }
      const normalized = {
        name: nonEmpty(scheme.name, 'authentication scheme name'),
        kind: scheme.kind,
        ...(scheme.location === undefined ? {} : { location: scheme.location }),
        ...(scheme.parameterName === undefined ? {} : {
          parameterName: nonEmpty(scheme.parameterName, 'authentication parameter name'),
        }),
        scopes: sortedSet(scheme.scopes, 'authentication scope', state),
        ...(scheme.flows === undefined ? {} : {
          flows: sortedSet(scheme.flows, 'authentication flow', state),
        }),
        capability: scheme.capability,
        ...(scheme.unsupportedReason === undefined ? {} : {
          unsupportedReason: nonEmpty(scheme.unsupportedReason, 'unsupported reason'),
        }),
      };
      if (('parameterName' in normalized
          && (normalized.kind !== 'api-key' || !('location' in normalized)))
        || ('flows' in normalized && normalized.kind !== 'oauth2')
        || (normalized.flows !== undefined && normalized.flows.length === 0)
        || (normalized.kind === 'unknown' && normalized.capability !== 'unsupported')
        || ((normalized.capability === 'unsupported') !== ('unsupportedReason' in normalized))) {
        throw new Error('invalid authentication scheme metadata');
      }
      const serialized = stableSerialize(normalized);
      const previous = byName.get(normalized.name);
      if (previous !== undefined && previous !== serialized) throw new Error('conflicting authentication scheme');
      byName.set(normalized.name, serialized);
      return normalized;
    });
    return {
      anonymous,
      schemes: [...new Map(normalizedSchemes.map((scheme) => [stableSerialize(scheme), scheme])).entries()]
        .sort(([left], [right]) => compareText(left, right)).map(([, scheme]) => scheme),
    };
  });
  const canonicalAlternatives = [...new Map(alternatives.map((alternative) => (
    [stableSerialize(alternative), alternative]
  ))).entries()].sort(([left], [right]) => compareText(left, right)).map(([, alternative]) => alternative);
  let analysis: ApiAuthAnalysisV1 | undefined;
  if (input.analysis !== undefined) {
    if (!input.analysis || typeof input.analysis !== 'object'
      || !Array.isArray(input.analysis.guards)
      || !['high', 'unknown'].includes(input.analysis.enforcementConfidence)) {
      throw new Error('invalid authentication analysis');
    }
    consume(state, input.analysis.guards.length);
    const guards = input.analysis.guards.map((guard) => {
      if (!guard || typeof guard !== 'object'
        || (guard.authKind !== undefined && !AUTH_SCHEME_KINDS.includes(guard.authKind))) {
        throw new Error('invalid authentication guard analysis');
      }
      return {
        symbol: nonEmpty(guard.symbol, 'authentication guard symbol'),
        ...(guard.authKind === undefined ? {} : { authKind: guard.authKind }),
      };
    });
    analysis = {
      guards,
      explicitPublic: booleanValue(input.analysis.explicitPublic, 'explicit public override'),
      roles: sortedRawSet(input.analysis.roles, 'authorization role', state),
      enforcementConfidence: input.analysis.enforcementConfidence,
      capabilityReasons: sortedSet(input.analysis.capabilityReasons, 'authentication capability reason', state),
    };
  }
  return {
    mode: input.mode,
    alternatives: canonicalAlternatives,
    ...(analysis === undefined ? {} : { analysis }),
  };
}

function normalizeOperation(input: ApiOperationInputV1, state: NormalizationState): ApiOperationContractV1 {
  if (!input || typeof input !== 'object') throw new Error('invalid operation');
  consume(state, 1);
  const method = normalizeHttpMethod(input.method);
  const routePath = canonicalizePath(nonEmpty(input.path, 'route path'));
  if (!EXPOSURES.includes(input.exposure)) throw new Error('invalid exposure');
  if (!Array.isArray(input.provenance)) throw new Error('invalid operation provenance');
  consume(state, input.provenance.length);
  const provenanceByValue = new Map(input.provenance.map(normalizeEvidence)
    .map((item) => [stableSerialize(item), item]));
  const provenance = [...provenanceByValue.entries()].sort(([left], [right]) => compareText(left, right))
    .map(([, item]) => item);
  if (provenance.length === 0) throw new Error('operation provenance is required');
  const auth = normalizeAuth(input.auth, state);
  const hasAnonymousAlternative = auth.mode === 'alternatives'
    && auth.alternatives.some(({ anonymous }) => anonymous);
  const authMatchesExposure = (input.exposure === 'unknown' && auth.mode === 'unknown')
    || (input.exposure === 'public' && (auth.mode === 'none' || hasAnonymousAlternative))
    || (['authenticated', 'privileged'].includes(input.exposure)
      && auth.mode === 'alternatives' && !hasAnonymousAlternative);
  if (!authMatchesExposure) throw new Error('authentication and exposure are inconsistent');
  return {
    routeKey: createRouteKey(method, routePath),
    method,
    path: routePath,
    ...(input.operationId === undefined ? {} : { operationId: nonEmpty(input.operationId, 'operationId') }),
    exposure: input.exposure,
    auth,
    request: normalizeRequest(input.request, state),
    provenance,
    ...(input.metadata === undefined ? {} : {
      metadata: {
        deprecated: booleanValue(input.metadata.deprecated, 'operation metadata'),
        tags: sortedSet(input.metadata.tags, 'operation tag', state),
      },
    }),
  };
}

export function createSecurityContract(input: SecurityContractInputV1): SecurityContractV1 {
  if (!input || !CONTRACT_SOURCES.includes(input.source)
    || !input.capabilities || !Array.isArray(input.operations)) throw new Error('invalid security contract');
  if (Object.keys(input.capabilities).sort().join(',') !== 'authentication,parameters,requestBodies,routes') {
    throw new Error('invalid contract capabilities');
  }
  const capabilities: SecurityContractCapabilitiesV1 = {
    routes: input.capabilities.routes,
    parameters: input.capabilities.parameters,
    requestBodies: input.capabilities.requestBodies,
    authentication: input.capabilities.authentication,
  };
  for (const value of Object.values(capabilities)) {
    if (!CAPABILITY_LEVELS.includes(value)) throw new Error('invalid contract capability');
  }
  const state: NormalizationState = { nodes: 0 };
  const operations = input.operations.map((operation) => normalizeOperation(operation, state))
    .sort((a, b) => compareText(a.routeKey, b.routeKey));
  for (let index = 1; index < operations.length; index += 1) {
    if (operations[index - 1].routeKey === operations[index].routeKey) throw new Error('duplicate route');
  }
  return {
    schemaVersion: 1,
    source: input.source,
    capabilities,
    operations,
  };
}

export function serializeSecurityContract(contract: SecurityContractV1): string {
  if (contract?.schemaVersion !== 1) throw new Error('invalid security contract version');
  return `${stableSerialize(createSecurityContract(contract))}\n`;
}
