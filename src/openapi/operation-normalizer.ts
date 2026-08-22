import {
  canonicalizePath,
  createSecurityContract,
  HTTP_METHODS,
  VALUE_TYPES,
  type ApiOperationInputV1,
  type ApiParameterContractV1,
  type SecurityContractV1,
  type ValueConstraintsV1,
  type ValueTypeV1,
} from '../contract';
import { OpenApiAnalysisError } from './analysis-error';
import {
  DEFAULT_OPENAPI_ANALYSIS_LIMITS,
  validateOpenApiAnalysisLimits,
  type OpenApiAnalysisLimits,
} from './analysis-limits';
import type { ResolvedOpenApiGraph } from './document-graph';
import { isResolvedOpenApiGraph, resolveJsonPointer } from './ref-resolver';

export interface NormalizationOptions {
  limits?: Partial<OpenApiAnalysisLimits>;
}

interface LocatedValue {
  value: unknown;
  sourceUri: string;
  pointer: string;
}

interface ConstraintResult {
  constraints: ValueConstraintsV1;
  unsupportedReasons: string[];
}

const METHOD_KEYS = new Set(HTTP_METHODS.map((method) => method.toLowerCase()));
const PARAMETER_LOCATIONS = new Set(['path', 'query', 'header', 'cookie']);

function fail(
  location?: LocatedValue,
  code: 'OPENAPI_OPERATION_INVALID' | 'OPENAPI_OPERATION_LIMIT' | 'OPENAPI_NODE_LIMIT' = 'OPENAPI_OPERATION_INVALID',
): never {
  throw new OpenApiAnalysisError(code, location ? {
    sourceUri: location.sourceUri,
    pointer: location.pointer,
  } : {});
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function pointerChild(pointer: string, token: string): string {
  return `${pointer}/${token.replace(/~/g, '~0').replace(/\//g, '~1')}`;
}

function asObject(location: LocatedValue): Record<string, unknown> {
  if (location.value === null || typeof location.value !== 'object' || Array.isArray(location.value)) {
    fail(location);
  }
  return location.value as Record<string, unknown>;
}

function stableValue(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableValue).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableValue(record[key])}`).join(',')}}`;
}

function normalizeType(value: unknown, reasons: Set<string>): ValueTypeV1 {
  if (typeof value === 'string' && VALUE_TYPES.includes(value as ValueTypeV1)) {
    return value as ValueTypeV1;
  }
  if (Array.isArray(value)) {
    const nonNull = value.filter((item) => item !== 'null');
    if (value.includes('null') && nonNull.length === 1
      && typeof nonNull[0] === 'string' && VALUE_TYPES.includes(nonNull[0] as ValueTypeV1)) {
      reasons.add('schema:nullable-union');
      return nonNull[0] as ValueTypeV1;
    }
  }
  if (value !== undefined) reasons.add('schema:type');
  return 'unknown';
}

function normalizeConstraints(
  schemaLocation: LocatedValue | undefined,
  materialize: (
    location: LocatedValue,
    visitReference?: (reference: Record<string, unknown>) => void,
  ) => LocatedValue,
): ConstraintResult {
  if (!schemaLocation) return { constraints: { type: 'unknown' }, unsupportedReasons: ['schema:missing'] };
  const reasons = new Set<string>();
  const resolved = materialize(schemaLocation, (reference) => {
    if (Object.keys(reference).some((key) => (
      !['$ref', 'description', 'summary', 'example', 'default'].includes(key)
    ))) reasons.add('schema:ref-siblings');
  });
  const schema = asObject(resolved);
  const constraints: ValueConstraintsV1 = { type: normalizeType(schema.type, reasons) };
  if (schema.nullable === true) reasons.add('schema:nullable');
  for (const composition of ['allOf', 'anyOf', 'oneOf', 'not'] as const) {
    if (schema[composition] !== undefined) reasons.add(`schema:${composition}`);
  }
  if (typeof schema.format === 'string' && schema.format.trim()) {
    constraints.format = schema.format.trim();
  } else if (schema.format !== undefined) reasons.add('schema:format');
  if (Array.isArray(schema.enum)) {
    const safe = schema.enum.every((value) => (
      value === null || typeof value === 'boolean'
      || (typeof value === 'number' && Number.isFinite(value))
      || typeof value === 'string'
    ));
    if (safe) constraints.enum = schema.enum as Array<string | number | boolean | null>;
    else reasons.add('schema:enum');
  } else if (schema.enum !== undefined) reasons.add('schema:enum');
  for (const field of [
    'minimum', 'maximum', 'minLength', 'maxLength', 'minItems', 'maxItems', 'maxProperties',
  ] as const) {
    const value = schema[field];
    if (value === undefined) continue;
    const isCount = !['minimum', 'maximum'].includes(field);
    if (typeof value === 'number' && Number.isFinite(value)
      && (!isCount || (Number.isInteger(value) && value >= 0))) {
      constraints[field] = value;
    } else reasons.add(`schema:${field}`);
  }
  return { constraints, unsupportedReasons: [...reasons].sort(compareText) };
}

export function normalizeOpenApiOperations(
  graph: ResolvedOpenApiGraph,
  options: NormalizationOptions = {},
): SecurityContractV1 {
  if (!isResolvedOpenApiGraph(graph)) fail();
  const limits = validateOpenApiAnalysisLimits({
    ...DEFAULT_OPENAPI_ANALYSIS_LIMITS,
    ...(options.limits ?? {}),
  });
  const documents = new Map(graph.documents.map((document) => [document.sourceUri, document]));
  const rootDocument = documents.get(graph.root.sourceUri);
  if (!rootDocument) fail();
  const edges = new Map(graph.references.map((edge) => [edge.from.id, edge]));
  let resolutionVisits = 0;

  const materialize = (
    input: LocatedValue,
    visitReference?: (reference: Record<string, unknown>) => void,
  ): LocatedValue => {
    let current = input;
    const seen = new Set<string>();
    while (current.value !== null && typeof current.value === 'object' && !Array.isArray(current.value)
      && typeof (current.value as Record<string, unknown>).$ref === 'string') {
      resolutionVisits += 1;
      if (resolutionVisits > limits.maxNodes) fail(current, 'OPENAPI_NODE_LIMIT');
      visitReference?.(current.value as Record<string, unknown>);
      const id = `${current.sourceUri}#${current.pointer}`;
      if (seen.has(id)) fail(current);
      seen.add(id);
      const edge = edges.get(id);
      if (!edge) fail(current);
      const document = documents.get(edge.target.sourceUri);
      if (!document) fail(current);
      current = {
        value: resolveJsonPointer(
          document.document,
          `#${edge.target.pointer.replace(/%/g, '%25')}`,
          document.sourceUri,
        ).value,
        sourceUri: document.sourceUri,
        pointer: edge.target.pointer,
      };
    }
    return current;
  };

  const locatedChild = (parent: LocatedValue, key: string, value: unknown): LocatedValue => ({
    value,
    sourceUri: parent.sourceUri,
    pointer: pointerChild(parent.pointer, key),
  });

  let parameterCapability: 'complete' | 'partial' = 'complete';
  let bodyCapability: 'complete' | 'partial' = 'complete';

  const normalizeParameter = (input: LocatedValue): { key: string; parameter: ApiParameterContractV1 } => {
    const resolved = materialize(input);
    const parameter = asObject(resolved);
    if (typeof parameter.name !== 'string' || !parameter.name.trim()
      || typeof parameter.in !== 'string' || !PARAMETER_LOCATIONS.has(parameter.in)
      || (parameter.required !== undefined && typeof parameter.required !== 'boolean')
      || (parameter.style !== undefined && (typeof parameter.style !== 'string' || !parameter.style.trim()))
      || (parameter.explode !== undefined && typeof parameter.explode !== 'boolean')) fail(resolved);
    const parameterLocation = parameter.in as 'path' | 'query' | 'header' | 'cookie';
    const name = parameterLocation === 'header' ? parameter.name.trim().toLowerCase() : parameter.name.trim();
    const required = parameter.required === true;
    if (parameterLocation === 'path' && !required) fail(resolved);
    const constraintResult = normalizeConstraints(
      parameter.schema === undefined ? undefined : locatedChild(resolved, 'schema', parameter.schema),
      materialize,
    );
    const unsupportedReasons = [...constraintResult.unsupportedReasons];
    if (parameter.content !== undefined) unsupportedReasons.push('parameter:content');
    if (unsupportedReasons.length > 0) parameterCapability = 'partial';
    return {
      key: `${parameterLocation}:${name}`,
      parameter: {
        name,
        required,
        constraints: constraintResult.constraints,
        ...(typeof parameter.style === 'string' && parameter.style.trim() ? { style: parameter.style.trim() } : {}),
        ...(typeof parameter.explode === 'boolean' ? { explode: parameter.explode } : {}),
        unsupportedReasons: [...new Set(unsupportedReasons)].sort(compareText),
      },
    };
  };

  const parameterMap = (owner: LocatedValue, input: unknown): Map<string, ApiParameterContractV1> => {
    if (input === undefined) return new Map();
    if (!Array.isArray(input) || input.length > limits.maxParametersPerOperation) fail(owner);
    const result = new Map<string, ApiParameterContractV1>();
    for (let index = 0; index < input.length; index += 1) {
      const parameters = locatedChild(owner, 'parameters', input);
      const normalized = normalizeParameter(locatedChild(parameters, String(index), input[index]));
      if (result.has(normalized.key)) fail(owner);
      result.set(normalized.key, normalized.parameter);
    }
    return result;
  };

  const normalizeBody = (operation: LocatedValue, input: unknown) => {
    if (input === undefined) return undefined;
    const resolved = materialize(locatedChild(operation, 'requestBody', input));
    const body = asObject(resolved);
    if (body.required !== undefined && typeof body.required !== 'boolean') fail(resolved);
    const content = body.content === undefined ? {} : asObject(locatedChild(resolved, 'content', body.content));
    const contentTypes = Object.keys(content).map((mediaType) => mediaType.split(';', 1)[0].trim().toLowerCase());
    if (contentTypes.some((mediaType) => !/^[^/\s]+\/[^/\s]+$/.test(mediaType))) fail(resolved);
    const schemas = Object.keys(content).sort(compareText).map((mediaType) => {
      const contentLocation = locatedChild(resolved, 'content', content);
      const mediaLocation = locatedChild(contentLocation, mediaType, content[mediaType]);
      const media = asObject(mediaLocation);
      return normalizeConstraints(
        media.schema === undefined ? undefined : locatedChild(mediaLocation, 'schema', media.schema),
        materialize,
      );
    });
    let normalized: ConstraintResult = schemas[0] ?? {
      constraints: { type: 'unknown' },
      unsupportedReasons: ['requestBody:content-missing'],
    };
    if (schemas.some((schema) => stableValue(schema) !== stableValue(normalized))) {
      normalized = { constraints: { type: 'unknown' }, unsupportedReasons: ['requestBody:multiple-schemas'] };
    }
    if (normalized.unsupportedReasons.length > 0) bodyCapability = 'partial';
    return {
      contentTypes: [...new Set(contentTypes)].sort(compareText),
      body: {
        required: body.required === true,
        constraints: normalized.constraints,
        unsupportedReasons: normalized.unsupportedReasons,
      },
    };
  };

  const rootLocation: LocatedValue = {
    value: rootDocument.document,
    sourceUri: rootDocument.sourceUri,
    pointer: '',
  };
  const root = asObject(rootLocation);
  const pathsLocation = locatedChild(rootLocation, 'paths', root.paths ?? {});
  const paths = asObject(pathsLocation);
  const operations: ApiOperationInputV1[] = [];
  for (const routePath of Object.keys(paths).sort(compareText)) {
    const rawPathItem = locatedChild(pathsLocation, routePath, paths[routePath]);
    let canonicalPath: string;
    try {
      canonicalPath = canonicalizePath(routePath);
    } catch {
      fail(rawPathItem);
    }
    const templateNames = [...canonicalPath.matchAll(/\{([^{}]+)\}/g)].map((match) => match[1]);
    if (canonicalPath.replace(/\{[^{}]+\}/g, '').match(/[{}]/)) fail(rawPathItem);
    const pathItemLocation = materialize(rawPathItem);
    const pathItem = asObject(pathItemLocation);
    const inherited = parameterMap(pathItemLocation, pathItem.parameters);
    for (const methodKey of Object.keys(pathItem).filter((key) => METHOD_KEYS.has(key.toLowerCase())).sort(compareText)) {
      if (operations.length >= limits.maxOperations) fail(pathItemLocation, 'OPENAPI_OPERATION_LIMIT');
      const operationLocation = materialize(locatedChild(pathItemLocation, methodKey, pathItem[methodKey]));
      const operation = asObject(operationLocation);
      if ((operation.operationId !== undefined
          && (typeof operation.operationId !== 'string' || !operation.operationId.trim()))
        || (operation.deprecated !== undefined && typeof operation.deprecated !== 'boolean')
        || (operation.tags !== undefined
          && (!Array.isArray(operation.tags) || operation.tags.some((tag) => typeof tag !== 'string')))) {
        fail(operationLocation);
      }
      const merged = new Map(inherited);
      for (const [key, value] of parameterMap(operationLocation, operation.parameters)) merged.set(key, value);
      if (merged.size > limits.maxParametersPerOperation) fail(operationLocation);
      const byLocation = (location: string) => [...merged.entries()]
        .filter(([key]) => key.startsWith(`${location}:`)).map(([, value]) => value);
      const pathParameters = byLocation('path');
      const pathParameterNames = new Set(pathParameters.map(({ name }) => name));
      if (templateNames.some((name) => !pathParameterNames.has(name))
        || pathParameters.some(({ name }) => !templateNames.includes(name))) fail(operationLocation);
      const body = normalizeBody(operationLocation, operation.requestBody);
      const headerParameters = byLocation('header');
      const digest = documents.get(operationLocation.sourceUri)?.contentDigest;
      if (!digest) fail(operationLocation);
      operations.push({
        method: methodKey,
        path: canonicalPath,
        ...(typeof operation.operationId === 'string' && operation.operationId.trim()
          ? { operationId: operation.operationId.trim() } : {}),
        exposure: 'unknown',
        auth: { mode: 'unknown', alternatives: [] },
        request: {
          contentTypes: body?.contentTypes ?? [],
          requiredHeaders: headerParameters.filter(({ required }) => required).map(({ name }) => name),
          queryParameters: byLocation('query'),
          pathParameters,
          headerParameters,
          cookieParameters: byLocation('cookie'),
          ...(body ? { body: body.body } : {}),
        },
        provenance: [{
          source: 'openapi',
          uri: operationLocation.sourceUri,
          pointer: operationLocation.pointer,
          digest,
          analyzer: 'openapi-operation-normalizer-v1',
          capability: 'request-surface-v1',
          complete: true,
        }],
        metadata: {
          deprecated: operation.deprecated === true,
          tags: Array.isArray(operation.tags)
            ? operation.tags.filter((tag): tag is string => typeof tag === 'string') : [],
        },
      });
    }
  }
  try {
    return createSecurityContract({
      source: 'openapi',
      capabilities: {
        routes: 'complete',
        parameters: parameterCapability,
        requestBodies: bodyCapability,
        authentication: 'unsupported',
      },
      operations,
    });
  } catch {
    fail();
  }
}
