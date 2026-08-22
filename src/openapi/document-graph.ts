import { OpenApiAnalysisError } from './analysis-error';
import { OPENAPI_ANALYSIS_LIMIT_RANGES } from './analysis-limits';

export interface OpenApiNodeLocation {
  id: string;
  sourceUri: string;
  pointer: string;
}

export interface ResolvedOpenApiDocument {
  sourceUri: string;
  contentDigest: string;
  byteSize: number;
  document: unknown;
}

export interface OpenApiReferenceEdge {
  from: OpenApiNodeLocation;
  ref: string;
  target: OpenApiNodeLocation;
}

export interface ResolvedOpenApiGraph {
  readonly root: OpenApiNodeLocation;
  readonly documents: readonly ResolvedOpenApiDocument[];
  readonly references: readonly OpenApiReferenceEdge[];
  readonly totalByteSize: number;
}

interface SerializationState {
  nodes: number;
  ancestors: Set<object>;
}

const SERIALIZATION_NODE_LIMIT = OPENAPI_ANALYSIS_LIMIT_RANGES.maxNodes.max * 12;
const SERIALIZATION_DEPTH_LIMIT = OPENAPI_ANALYSIS_LIMIT_RANGES.maxSchemaDepth.max + 16;

function stableValue(value: unknown, state: SerializationState, depth = 0): unknown {
  state.nodes += 1;
  if (state.nodes > SERIALIZATION_NODE_LIMIT || depth > SERIALIZATION_DEPTH_LIMIT) {
    throw new OpenApiAnalysisError('OPENAPI_NODE_LIMIT');
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new OpenApiAnalysisError('OPENAPI_PARSE_ERROR');
  }
  if (value === null || typeof value === 'string' || typeof value === 'number'
    || typeof value === 'boolean') return value;
  if (typeof value !== 'object') throw new OpenApiAnalysisError('OPENAPI_PARSE_ERROR');
  if (state.ancestors.has(value)) throw new OpenApiAnalysisError('OPENAPI_REF_CYCLE_LIMIT');
  state.ancestors.add(value);
  let result: unknown;
  if (Array.isArray(value)) {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const items: unknown[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !('value' in descriptor)) {
        throw new OpenApiAnalysisError('OPENAPI_PARSE_ERROR');
      }
      items.push(stableValue(descriptor.value, state, depth + 1));
    }
    result = items;
  } else {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    result = Object.fromEntries(Object.keys(descriptors).sort().map((key) => {
      const descriptor = descriptors[key];
      if (!descriptor || !('value' in descriptor)) {
        throw new OpenApiAnalysisError('OPENAPI_PARSE_ERROR');
      }
      return [key, stableValue(descriptor.value, state, depth + 1)];
    }));
  }
  state.ancestors.delete(value);
  return result;
}

export function serializeResolvedOpenApiGraph(graph: ResolvedOpenApiGraph): string {
  return JSON.stringify(stableValue(graph, { nodes: 0, ancestors: new Set() }), null, 2);
}
