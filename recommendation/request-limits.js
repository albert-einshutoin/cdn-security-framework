"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.applySafetyMargin = applySafetyMargin;
exports.recommendRequestLimits = recommendRequestLimits;
const DEFAULT_MARGIN = { absolute: 0, ratio: 0.1 };
const MAX_ABSOLUTE_MARGIN = 1_000_000_000;
const MAX_RATIO_MARGIN = 10;
function compareText(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
function safeAdd(...values) {
    const result = values.reduce((sum, value) => sum + value, 0);
    return Number.isSafeInteger(result) && result >= 0 ? result : null;
}
function safeMultiply(left, right) {
    const result = left * right;
    return Number.isSafeInteger(result) && result >= 0 ? result : null;
}
function worstComponentLength(value) {
    return safeMultiply(Buffer.byteLength(value), 3);
}
function worstPathLiteralLength(value) {
    let total = 0;
    for (const part of value.split('/')) {
        const partLength = worstComponentLength(part);
        if (partLength === null)
            return null;
        const next = safeAdd(total, partLength);
        if (next === null)
            return null;
        total = next;
    }
    return safeAdd(total, Math.max(0, value.split('/').length - 1));
}
function worstJsonStringLength(value) {
    const contentLength = safeMultiply([...value].length, 12);
    return contentLength === null ? null : safeAdd(2, contentLength);
}
function applySafetyMargin(value, options = DEFAULT_MARGIN) {
    const absolute = options.absolute ?? DEFAULT_MARGIN.absolute;
    const ratio = options.ratio ?? DEFAULT_MARGIN.ratio;
    if (!Number.isSafeInteger(value) || value < 0
        || !Number.isSafeInteger(absolute) || absolute < 0 || absolute > MAX_ABSOLUTE_MARGIN
        || !Number.isFinite(ratio) || ratio < 0 || ratio > MAX_RATIO_MARGIN) {
        throw new Error('invalid safety margin');
    }
    const after = value + absolute + Math.ceil(value * ratio);
    if (!Number.isSafeInteger(after))
        throw new Error('safety margin overflow');
    return { absolute, ratio, before: value, after };
}
function basisFor(operation) {
    return [...new Set(operation.provenance
            .filter(({ source, pointer }) => source === 'openapi' && pointer !== undefined)
            .map(({ pointer }) => pointer))].sort(compareText);
}
function categorical(value, basis, complete, unsupportedReasons = []) {
    return {
        value,
        basis,
        estimateKind: complete ? 'exact' : 'partial',
        margin: null,
        confidence: complete ? 'high' : 'medium',
        unsupportedReasons: [...new Set(unsupportedReasons)].sort(compareText),
    };
}
function numeric(before, basis, kind, marginOptions, unsupportedReasons = []) {
    const margin = before === null ? null : applySafetyMargin(before, marginOptions);
    return {
        value: margin?.after ?? null,
        basis,
        estimateKind: before === null ? (kind === 'partial' ? 'partial' : 'unknown') : kind,
        margin,
        confidence: before === null ? 'low' : kind === 'exact' ? 'high' : 'medium',
        unsupportedReasons: [...new Set(unsupportedReasons)].sort(compareText),
    };
}
function enumParameterLength(values) {
    if (values.some((value) => typeof value === 'number'))
        return null;
    return Math.max(0, ...values.map((value) => Buffer.byteLength(String(value)) * 3));
}
function enumJsonLength(values) {
    if (values.some((value) => typeof value === 'number'))
        return null;
    const lengths = values.map((value) => typeof value === 'string'
        ? worstJsonStringLength(value)
        : Buffer.byteLength(JSON.stringify(value)));
    return lengths.some((value) => value === null) ? null : Math.max(0, ...lengths);
}
function parameterValueLength(parameter) {
    const { constraints } = parameter;
    if (parameter.unsupportedReasons.length > 0)
        return null;
    if (constraints.enum)
        return enumParameterLength(constraints.enum);
    switch (constraints.type) {
        case 'string': return constraints.maxLength === undefined ? null : safeMultiply(constraints.maxLength, 12);
        case 'boolean': return 5;
        default: return null;
    }
}
function jsonValueLength(constraints, seen = new Set()) {
    if (seen.has(constraints))
        return null;
    if (constraints.enum)
        return enumJsonLength(constraints.enum);
    const nextSeen = new Set(seen).add(constraints);
    switch (constraints.type) {
        case 'string': {
            if (constraints.maxLength === undefined)
                return null;
            const contentLength = safeMultiply(constraints.maxLength, 12);
            return contentLength === null ? null : safeAdd(2, contentLength);
        }
        case 'boolean': return 5;
        case 'integer': return null;
        case 'number': return null;
        case 'array': {
            if (constraints.maxItems === undefined || !constraints.items)
                return null;
            const itemLength = jsonValueLength(constraints.items, nextSeen);
            if (itemLength === null)
                return null;
            const itemsLength = safeMultiply(constraints.maxItems, itemLength);
            return itemsLength === null ? null : safeAdd(2, itemsLength, Math.max(0, constraints.maxItems - 1));
        }
        case 'object': {
            if (constraints.additionalProperties !== false || !constraints.properties)
                return null;
            const entries = Object.entries(constraints.properties).sort(([left], [right]) => compareText(left, right));
            let total = 2 + Math.max(0, entries.length - 1);
            for (const [name, child] of entries) {
                const childLength = jsonValueLength(child, nextSeen);
                if (childLength === null)
                    return null;
                const nameLength = worstJsonStringLength(name);
                if (nameLength === null)
                    return null;
                const next = safeAdd(total, nameLength, 1, childLength);
                if (next === null)
                    return null;
                total = next;
            }
            return total;
        }
        default: return null;
    }
}
function queryLength(parameters) {
    let total = Math.max(0, parameters.length - 1);
    const reasons = [];
    for (const parameter of parameters) {
        const valueLength = parameterValueLength(parameter);
        if (valueLength === null)
            reasons.push(`query:${parameter.name}:unbounded-or-unsupported`);
        else {
            const nameLength = worstComponentLength(parameter.name);
            const next = nameLength === null ? null : safeAdd(total, nameLength, 1, valueLength);
            if (next === null)
                reasons.push('query:encoding-or-overflow');
            else
                total = next;
        }
    }
    return { value: reasons.length > 0 ? null : total, reasons };
}
function queryParameterCount(parameters) {
    let total = 0;
    const reasons = [];
    for (const parameter of parameters) {
        const style = parameter.style ?? 'form';
        const explode = parameter.explode ?? style === 'form';
        let count = 1;
        if (explode && style === 'form' && parameter.constraints.type === 'array') {
            if (parameter.constraints.maxItems === undefined) {
                reasons.push(`query:${parameter.name}:unbounded-count`);
                continue;
            }
            count = parameter.constraints.maxItems;
        }
        else if ((explode && style === 'form' || style === 'deepObject')
            && parameter.constraints.type === 'object') {
            if (parameter.constraints.maxProperties === undefined) {
                reasons.push(`query:${parameter.name}:unbounded-count`);
                continue;
            }
            count = parameter.constraints.maxProperties;
        }
        const next = safeAdd(total, count);
        if (next === null)
            reasons.push('query:count-overflow');
        else
            total = next;
    }
    return { value: reasons.length > 0 ? null : total, reasons };
}
function uriLength(operation) {
    let total = 0;
    const reasons = [];
    const parameters = new Map(operation.request.pathParameters.map((parameter) => [parameter.name, parameter]));
    let cursor = 0;
    for (const match of operation.path.matchAll(/\{([^{}]+)\}/g)) {
        const literalLength = worstPathLiteralLength(operation.path.slice(cursor, match.index));
        const parameter = parameters.get(match[1]);
        const valueLength = parameter ? parameterValueLength(parameter) : null;
        const next = literalLength === null || valueLength === null
            ? null : safeAdd(total, literalLength, valueLength);
        if (next === null)
            reasons.push(`path:${match[1]}:unbounded-or-unsupported`);
        else
            total = next;
        cursor = match.index + match[0].length;
    }
    const trailingLength = worstPathLiteralLength(operation.path.slice(cursor));
    const final = trailingLength === null ? null : safeAdd(total, trailingLength);
    if (final === null)
        reasons.push('path:overflow');
    else
        total = final;
    return { value: reasons.length > 0 ? null : total, reasons };
}
function bodyLength(operation) {
    const { body, contentTypes } = operation.request;
    if (!body)
        return { value: 0, reasons: [] };
    if (contentTypes.some((value) => value === 'multipart/form-data')) {
        return { value: null, reasons: ['body:multipart'] };
    }
    if (contentTypes.some((value) => value !== 'application/json' && !value.endsWith('+json'))) {
        return { value: null, reasons: ['body:unsupported-content-type'] };
    }
    if (body.unsupportedReasons.length > 0)
        return { value: null, reasons: body.unsupportedReasons };
    const value = jsonValueLength(body.constraints);
    if (value !== null)
        return { value, reasons: [] };
    const reason = body.constraints.type === 'array' && body.constraints.maxItems === undefined
        ? 'body:unbounded-array'
        : body.constraints.type === 'object' && body.constraints.additionalProperties !== false
            ? 'body:free-form-object'
            : 'body:unsupported-or-unbounded-schema';
    return { value: null, reasons: [reason] };
}
function operationRecommendation(contract, operation, margin) {
    const basis = basisFor(operation);
    const queryCount = queryParameterCount(operation.request.queryParameters);
    const query = queryLength(operation.request.queryParameters);
    const uri = uriLength(operation);
    const body = bodyLength(operation);
    const parameterConstraints = [
        ['query', operation.request.queryParameters],
        ['path', operation.request.pathParameters],
        ['header', operation.request.headerParameters],
        ['cookie', operation.request.cookieParameters],
    ].flatMap(([location, parameters]) => parameters.map((parameter) => ({
        name: parameter.name,
        location,
        required: parameter.required,
        constraints: parameter.constraints,
    })));
    const parametersComplete = contract.capabilities.parameters === 'complete';
    const bodiesComplete = contract.capabilities.requestBodies === 'complete';
    return {
        routeKey: operation.routeKey,
        requiredHeaders: categorical(operation.request.requiredHeaders, basis, parametersComplete),
        allowedContentTypes: categorical(operation.request.contentTypes, basis, bodiesComplete),
        maxQueryParams: numeric(queryCount.value, basis, queryCount.value === null ? 'unknown' : parametersComplete ? 'upper-bound' : 'partial', margin, queryCount.reasons),
        maxQueryLength: numeric(query.value, basis, query.value === null ? 'unknown' : parametersComplete ? 'upper-bound' : 'partial', margin, query.reasons),
        maxUriLength: numeric(uri.value, basis, uri.value === null ? 'unknown' : parametersComplete ? 'upper-bound' : 'partial', margin, uri.reasons),
        maxBodyBytes: numeric(body.value, basis, body.value === null ? 'unknown' : bodiesComplete ? 'upper-bound' : 'partial', margin, body.reasons),
        parameterConstraints: categorical(parameterConstraints, basis, parametersComplete, parameterConstraints.flatMap(({ name, constraints }) => constraints.type === 'unknown'
            ? [`parameter:${name}:unknown`] : [])),
    };
}
function recommendRequestLimits(contract, options = {}) {
    if (!contract || contract.schemaVersion !== 1 || !Array.isArray(contract.operations)) {
        throw new Error('invalid security contract');
    }
    const margin = options.margin ?? DEFAULT_MARGIN;
    applySafetyMargin(0, margin);
    const byPath = new Map();
    for (const operation of contract.operations) {
        const operations = byPath.get(operation.path) ?? [];
        operations.push(operation);
        byPath.set(operation.path, operations);
    }
    return {
        schemaVersion: 1,
        routes: [...byPath.entries()].sort(([left], [right]) => compareText(left, right))
            .map(([path, operations]) => {
            const sorted = operations.sort((left, right) => compareText(left.routeKey, right.routeKey));
            const basis = [...new Set(sorted.flatMap(basisFor))].sort(compareText);
            return {
                path,
                allowedMethods: categorical(sorted.map(({ method }) => method), basis, contract.capabilities.routes === 'complete'),
                operations: sorted.map((operation) => operationRecommendation(contract, operation, margin)),
            };
        }),
    };
}
