"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AUTH_SCHEME_KINDS = exports.VALUE_TYPES = exports.EXPOSURES = exports.CAPABILITY_LEVELS = exports.CONTRACT_SOURCES = void 0;
exports.createSecurityContract = createSecurityContract;
exports.serializeSecurityContract = serializeSecurityContract;
const finding_1 = require("./finding");
const canonical_route_1 = require("./canonical-route");
exports.CONTRACT_SOURCES = ['openapi', 'source-ast', 'policy', 'runtime'];
exports.CAPABILITY_LEVELS = ['complete', 'partial', 'unsupported'];
exports.EXPOSURES = ['public', 'authenticated', 'privileged', 'unknown'];
exports.VALUE_TYPES = ['string', 'integer', 'number', 'boolean', 'array', 'object', 'unknown'];
exports.AUTH_SCHEME_KINDS = [
    'basic', 'bearer', 'api-key', 'oauth2', 'openid-connect', 'mutual-tls', 'unknown',
];
const SECRET_PATTERN = /\b(?:Bearer|Basic)\s+\S+|\b(?:sk-(?:proj-)?|ghp_|github_pat_|AKIA|(?:sk|pk)_)[A-Za-z0-9_-]{8,}|\b(?:authorization|proxy-authorization|cookie|set-cookie|password|secret|client_secret|access_token|refresh_token|token|api[_-]?key)\s*[=:]\s*\S+/i;
const MAX_STRING_LENGTH = 16_384;
const MAX_IR_NODES = 100_000;
function consume(state, count) {
    state.nodes += count;
    if (state.nodes > MAX_IR_NODES)
        throw new Error('security contract exceeds size limit');
}
function compareText(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
function nonEmpty(value, field) {
    if (typeof value !== 'string' || value.length > MAX_STRING_LENGTH || !value.trim()) {
        throw new Error(`invalid ${field}`);
    }
    const normalized = value.trim();
    if (SECRET_PATTERN.test(normalized))
        throw new Error('secret-like value is not allowed');
    return normalized;
}
function booleanValue(value, field) {
    if (typeof value !== 'boolean')
        throw new Error(`invalid ${field}`);
    return value;
}
function sortedSet(values, field, state, transform = (value) => value) {
    if (!Array.isArray(values))
        throw new Error(`invalid ${field}`);
    consume(state, values.length);
    return [...new Set(values.map((value) => nonEmpty(transform(nonEmpty(value, field)), field)))].sort(compareText);
}
function normalizeConstraints(input, state) {
    if (!input || typeof input !== 'object' || !exports.VALUE_TYPES.includes(input.type)) {
        throw new Error('invalid value constraints');
    }
    const output = { type: input.type };
    if (input.format !== undefined)
        output.format = nonEmpty(input.format, 'constraint format');
    if (input.enum !== undefined) {
        if (!Array.isArray(input.enum))
            throw new Error('invalid constraint enum');
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
    ]) {
        const value = input[field];
        if (value === undefined)
            continue;
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
    return output;
}
function normalizeParameter(input, state) {
    if (!input || typeof input !== 'object')
        throw new Error('invalid parameter');
    return {
        name: nonEmpty(input.name, 'parameter name'),
        required: booleanValue(input.required, 'parameter required'),
        constraints: normalizeConstraints(input.constraints, state),
        ...(input.style === undefined ? {} : { style: nonEmpty(input.style, 'parameter style') }),
        ...(input.explode === undefined ? {} : { explode: booleanValue(input.explode, 'parameter explode') }),
        unsupportedReasons: sortedSet(input.unsupportedReasons, 'unsupported reason', state),
    };
}
function normalizeParameters(values, field, state, normalizeName = (name) => name) {
    if (!Array.isArray(values))
        throw new Error(`invalid ${field}`);
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
function normalizeRequest(input, state) {
    if (!input)
        throw new Error('invalid request contract');
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
function stableSerialize(value) {
    if (value === null || typeof value !== 'object')
        return JSON.stringify(value);
    if (Array.isArray(value))
        return `[${value.map(stableSerialize).join(',')}]`;
    const record = value;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableSerialize(record[key])}`).join(',')}}`;
}
function normalizeEvidence(input) {
    if (!input || typeof input !== 'object')
        throw new Error('invalid provenance');
    const uri = nonEmpty(input.uri, 'provenance uri').replace(/\\/g, '/');
    if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(uri)
        || uri.startsWith('/') || /[?#]/.test(uri) || uri.split('/').includes('..')) {
        throw new Error('invalid provenance uri');
    }
    if (!finding_1.FINDING_EVIDENCE_SOURCES.includes(input.source)
        || typeof input.complete !== 'boolean')
        throw new Error('invalid provenance');
    return {
        source: input.source,
        uri: uri.replace(/^\.\//, ''),
        ...(input.pointer === undefined ? {} : {
            pointer: (() => {
                const pointer = nonEmpty(input.pointer, 'provenance pointer');
                if (/[?#]/.test(pointer))
                    throw new Error('invalid provenance pointer');
                return pointer;
            })(),
        }),
        digest: nonEmpty(input.digest, 'provenance digest'),
        analyzer: nonEmpty(input.analyzer, 'provenance analyzer'),
        capability: nonEmpty(input.capability, 'provenance capability'),
        complete: input.complete,
    };
}
function normalizeAuth(input, state) {
    if (!input || !['none', 'unknown', 'alternatives'].includes(input.mode) || !Array.isArray(input.alternatives)) {
        throw new Error('invalid authentication contract');
    }
    if ((input.mode !== 'alternatives' && input.alternatives.length > 0)
        || (input.mode === 'alternatives' && input.alternatives.length === 0)) {
        throw new Error('authentication alternatives require alternatives mode');
    }
    consume(state, input.alternatives.length);
    const alternatives = input.alternatives.map((alternative) => {
        if (!alternative || typeof alternative !== 'object')
            throw new Error('invalid authentication alternative');
        const { schemes } = alternative;
        if (!Array.isArray(schemes))
            throw new Error('invalid authentication alternative');
        const anonymous = booleanValue(alternative.anonymous, 'authentication alternative');
        if (anonymous !== (schemes.length === 0))
            throw new Error('invalid authentication alternative');
        consume(state, schemes.length);
        const byName = new Map();
        const normalizedSchemes = schemes.map((scheme) => {
            if (!scheme || typeof scheme !== 'object'
                || !exports.AUTH_SCHEME_KINDS.includes(scheme.kind)
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
            if (previous !== undefined && previous !== serialized)
                throw new Error('conflicting authentication scheme');
            byName.set(normalized.name, serialized);
            return normalized;
        });
        return {
            anonymous,
            schemes: [...new Map(normalizedSchemes.map((scheme) => [stableSerialize(scheme), scheme])).entries()]
                .sort(([left], [right]) => compareText(left, right)).map(([, scheme]) => scheme),
        };
    });
    const canonicalAlternatives = [...new Map(alternatives.map((alternative) => ([stableSerialize(alternative), alternative]))).entries()].sort(([left], [right]) => compareText(left, right)).map(([, alternative]) => alternative);
    return { mode: input.mode, alternatives: canonicalAlternatives };
}
function normalizeOperation(input, state) {
    if (!input || typeof input !== 'object')
        throw new Error('invalid operation');
    consume(state, 1);
    const method = (0, canonical_route_1.normalizeHttpMethod)(input.method);
    const routePath = (0, canonical_route_1.canonicalizePath)(nonEmpty(input.path, 'route path'));
    if (!exports.EXPOSURES.includes(input.exposure))
        throw new Error('invalid exposure');
    if (!Array.isArray(input.provenance))
        throw new Error('invalid operation provenance');
    consume(state, input.provenance.length);
    const provenanceByValue = new Map(input.provenance.map(normalizeEvidence)
        .map((item) => [stableSerialize(item), item]));
    const provenance = [...provenanceByValue.entries()].sort(([left], [right]) => compareText(left, right))
        .map(([, item]) => item);
    if (provenance.length === 0)
        throw new Error('operation provenance is required');
    const auth = normalizeAuth(input.auth, state);
    const hasAnonymousAlternative = auth.mode === 'alternatives'
        && auth.alternatives.some(({ anonymous }) => anonymous);
    const authMatchesExposure = (input.exposure === 'unknown' && auth.mode === 'unknown')
        || (input.exposure === 'public' && (auth.mode === 'none' || hasAnonymousAlternative))
        || (['authenticated', 'privileged'].includes(input.exposure)
            && auth.mode === 'alternatives' && !hasAnonymousAlternative);
    if (!authMatchesExposure)
        throw new Error('authentication and exposure are inconsistent');
    return {
        routeKey: (0, canonical_route_1.createRouteKey)(method, routePath),
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
function createSecurityContract(input) {
    if (!input || !exports.CONTRACT_SOURCES.includes(input.source)
        || !input.capabilities || !Array.isArray(input.operations))
        throw new Error('invalid security contract');
    if (Object.keys(input.capabilities).sort().join(',') !== 'authentication,parameters,requestBodies,routes') {
        throw new Error('invalid contract capabilities');
    }
    const capabilities = {
        routes: input.capabilities.routes,
        parameters: input.capabilities.parameters,
        requestBodies: input.capabilities.requestBodies,
        authentication: input.capabilities.authentication,
    };
    for (const value of Object.values(capabilities)) {
        if (!exports.CAPABILITY_LEVELS.includes(value))
            throw new Error('invalid contract capability');
    }
    const state = { nodes: 0 };
    const operations = input.operations.map((operation) => normalizeOperation(operation, state))
        .sort((a, b) => compareText(a.routeKey, b.routeKey));
    for (let index = 1; index < operations.length; index += 1) {
        if (operations[index - 1].routeKey === operations[index].routeKey)
            throw new Error('duplicate route');
    }
    return {
        schemaVersion: 1,
        source: input.source,
        capabilities,
        operations,
    };
}
function serializeSecurityContract(contract) {
    if (contract?.schemaVersion !== 1)
        throw new Error('invalid security contract version');
    return `${stableSerialize(createSecurityContract(contract))}\n`;
}
