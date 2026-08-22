"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.serializeResolvedOpenApiGraph = serializeResolvedOpenApiGraph;
const analysis_error_1 = require("./analysis-error");
const analysis_limits_1 = require("./analysis-limits");
const SERIALIZATION_NODE_LIMIT = analysis_limits_1.OPENAPI_ANALYSIS_LIMIT_RANGES.maxNodes.max * 12;
const SERIALIZATION_DEPTH_LIMIT = analysis_limits_1.OPENAPI_ANALYSIS_LIMIT_RANGES.maxSchemaDepth.max + 16;
function stableValue(value, state, depth = 0) {
    state.nodes += 1;
    if (state.nodes > SERIALIZATION_NODE_LIMIT || depth > SERIALIZATION_DEPTH_LIMIT) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_NODE_LIMIT');
    }
    if (typeof value === 'number' && !Number.isFinite(value)) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_PARSE_ERROR');
    }
    if (value === null || typeof value === 'string' || typeof value === 'number'
        || typeof value === 'boolean')
        return value;
    if (typeof value !== 'object')
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_PARSE_ERROR');
    if (state.ancestors.has(value))
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_REF_CYCLE_LIMIT');
    state.ancestors.add(value);
    let result;
    if (Array.isArray(value)) {
        const descriptors = Object.getOwnPropertyDescriptors(value);
        const items = [];
        for (let index = 0; index < value.length; index += 1) {
            const descriptor = descriptors[String(index)];
            if (!descriptor || !('value' in descriptor)) {
                throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_PARSE_ERROR');
            }
            items.push(stableValue(descriptor.value, state, depth + 1));
        }
        result = items;
    }
    else {
        const descriptors = Object.getOwnPropertyDescriptors(value);
        result = Object.fromEntries(Object.keys(descriptors).sort().map((key) => {
            const descriptor = descriptors[key];
            if (!descriptor || !('value' in descriptor)) {
                throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_PARSE_ERROR');
            }
            return [key, stableValue(descriptor.value, state, depth + 1)];
        }));
    }
    state.ancestors.delete(value);
    return result;
}
function serializeResolvedOpenApiGraph(graph) {
    return JSON.stringify(stableValue(graph, { nodes: 0, ancestors: new Set() }), null, 2);
}
