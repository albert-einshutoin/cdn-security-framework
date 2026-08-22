"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeOpenApiOperations = normalizeOpenApiOperations;
const contract_1 = require("../contract");
const analysis_error_1 = require("./analysis-error");
const analysis_limits_1 = require("./analysis-limits");
const ref_resolver_1 = require("./ref-resolver");
const METHOD_KEYS = new Set(contract_1.HTTP_METHODS.map((method) => method.toLowerCase()));
const PARAMETER_LOCATIONS = new Set(['path', 'query', 'header', 'cookie']);
function fail(location, code = 'OPENAPI_OPERATION_INVALID') {
    throw new analysis_error_1.OpenApiAnalysisError(code, location ? {
        sourceUri: location.sourceUri,
        pointer: location.pointer,
    } : {});
}
function compareText(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
function pointerChild(pointer, token) {
    return `${pointer}/${token.replace(/~/g, '~0').replace(/\//g, '~1')}`;
}
function locatedChild(parent, key, value) {
    return { value, sourceUri: parent.sourceUri, pointer: pointerChild(parent.pointer, key) };
}
function asObject(location) {
    if (location.value === null || typeof location.value !== 'object' || Array.isArray(location.value)) {
        fail(location);
    }
    return location.value;
}
function stableValue(value) {
    if (value === null || typeof value !== 'object')
        return JSON.stringify(value);
    if (Array.isArray(value))
        return `[${value.map(stableValue).join(',')}]`;
    const record = value;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableValue(record[key])}`).join(',')}}`;
}
function normalizeType(value, reasons) {
    if (typeof value === 'string' && contract_1.VALUE_TYPES.includes(value)) {
        return value;
    }
    if (Array.isArray(value)) {
        const nonNull = value.filter((item) => item !== 'null');
        if (value.includes('null') && nonNull.length === 1
            && typeof nonNull[0] === 'string' && contract_1.VALUE_TYPES.includes(nonNull[0])) {
            reasons.add('schema:nullable-union');
            return nonNull[0];
        }
    }
    if (value !== undefined)
        reasons.add('schema:type');
    return 'unknown';
}
function normalizeConstraints(schemaLocation, materialize, shapeOptions) {
    if (!schemaLocation)
        return { constraints: { type: 'unknown' }, unsupportedReasons: ['schema:missing'] };
    const reasons = new Set();
    const resolved = materialize(schemaLocation, (reference) => {
        if (Object.keys(reference).some((key) => (!['$ref', 'description', 'summary', 'example', 'default'].includes(key))))
            reasons.add('schema:ref-siblings');
    });
    const resolvedId = `${resolved.sourceUri}#${resolved.pointer}`;
    const depth = shapeOptions?.depth ?? 0;
    if (shapeOptions?.ancestors?.has(resolvedId)) {
        return { constraints: { type: 'unknown' }, unsupportedReasons: ['schema:recursive'] };
    }
    if (shapeOptions && depth >= shapeOptions.maxDepth) {
        return { constraints: { type: 'unknown' }, unsupportedReasons: ['schema:max-depth'] };
    }
    const schema = asObject(resolved);
    const constraints = { type: normalizeType(schema.type, reasons) };
    if (schema.nullable === true)
        reasons.add('schema:nullable');
    for (const composition of ['allOf', 'anyOf', 'oneOf', 'not']) {
        if (schema[composition] !== undefined)
            reasons.add(`schema:${composition}`);
    }
    if (typeof schema.format === 'string' && schema.format.trim()) {
        constraints.format = schema.format.trim();
    }
    else if (schema.format !== undefined)
        reasons.add('schema:format');
    if (Array.isArray(schema.enum)) {
        const safe = schema.enum.every((value) => (value === null || typeof value === 'boolean'
            || (typeof value === 'number' && Number.isFinite(value))
            || typeof value === 'string'));
        if (safe)
            constraints.enum = schema.enum;
        else
            reasons.add('schema:enum');
    }
    else if (schema.enum !== undefined)
        reasons.add('schema:enum');
    for (const field of [
        'minimum', 'maximum', 'minLength', 'maxLength', 'minItems', 'maxItems', 'maxProperties',
    ]) {
        const value = schema[field];
        if (value === undefined)
            continue;
        const isCount = !['minimum', 'maximum'].includes(field);
        if (typeof value === 'number' && Number.isFinite(value)
            && (!isCount || (Number.isInteger(value) && value >= 0))) {
            constraints[field] = value;
        }
        else
            reasons.add(`schema:${field}`);
    }
    if (shapeOptions) {
        const nestedOptions = {
            maxDepth: shapeOptions.maxDepth,
            depth: depth + 1,
            ancestors: new Set(shapeOptions.ancestors).add(resolvedId),
        };
        if (constraints.type === 'object') {
            if (schema.properties !== undefined) {
                if (schema.properties === null || typeof schema.properties !== 'object'
                    || Array.isArray(schema.properties))
                    reasons.add('schema:properties');
                else {
                    const properties = schema.properties;
                    const normalizedProperties = [];
                    for (const name of Object.keys(properties).sort(compareText)) {
                        const child = normalizeConstraints(locatedChild(locatedChild(resolved, 'properties', properties), name, properties[name]), materialize, nestedOptions);
                        normalizedProperties.push([name, child.constraints]);
                        child.unsupportedReasons.forEach((reason) => reasons.add(reason));
                    }
                    constraints.properties = Object.fromEntries(normalizedProperties);
                }
            }
            if (schema.required !== undefined) {
                if (!Array.isArray(schema.required)
                    || schema.required.some((name) => typeof name !== 'string' || !name.trim())) {
                    reasons.add('schema:required');
                }
                else
                    constraints.requiredProperties = [...new Set(schema.required)].sort(compareText);
            }
            if (typeof schema.additionalProperties === 'boolean') {
                constraints.additionalProperties = schema.additionalProperties;
            }
            else if (schema.additionalProperties !== undefined)
                reasons.add('schema:additionalProperties');
        }
        if (constraints.type === 'array') {
            if (schema.items === undefined)
                reasons.add('schema:items');
            else {
                const child = normalizeConstraints(locatedChild(resolved, 'items', schema.items), materialize, nestedOptions);
                constraints.items = child.constraints;
                child.unsupportedReasons.forEach((reason) => reasons.add(reason));
            }
        }
    }
    return { constraints, unsupportedReasons: [...reasons].sort(compareText) };
}
function normalizeOpenApiOperations(graph, options = {}) {
    if (!(0, ref_resolver_1.isResolvedOpenApiGraph)(graph))
        fail();
    const limits = (0, analysis_limits_1.validateOpenApiAnalysisLimits)({
        ...analysis_limits_1.DEFAULT_OPENAPI_ANALYSIS_LIMITS,
        ...(options.limits ?? {}),
    });
    const documents = new Map(graph.documents.map((document) => [document.sourceUri, document]));
    const rootDocument = documents.get(graph.root.sourceUri);
    if (!rootDocument)
        fail();
    const edges = new Map(graph.references.map((edge) => [edge.from.id, edge]));
    let resolutionVisits = 0;
    const materialize = (input, visitReference) => {
        let current = input;
        const seen = new Set();
        while (current.value !== null && typeof current.value === 'object' && !Array.isArray(current.value)
            && typeof current.value.$ref === 'string') {
            resolutionVisits += 1;
            if (resolutionVisits > limits.maxNodes)
                fail(current, 'OPENAPI_NODE_LIMIT');
            visitReference?.(current.value);
            const id = `${current.sourceUri}#${current.pointer}`;
            if (seen.has(id))
                fail(current);
            seen.add(id);
            const edge = edges.get(id);
            if (!edge)
                fail(current);
            const document = documents.get(edge.target.sourceUri);
            if (!document)
                fail(current);
            current = {
                value: (0, ref_resolver_1.resolveJsonPointer)(document.document, `#${edge.target.pointer.replace(/%/g, '%25')}`, document.sourceUri).value,
                sourceUri: document.sourceUri,
                pointer: edge.target.pointer,
            };
        }
        return current;
    };
    let parameterCapability = 'complete';
    let bodyCapability = 'complete';
    const normalizeParameter = (input) => {
        const resolved = materialize(input);
        const parameter = asObject(resolved);
        if (typeof parameter.name !== 'string' || !parameter.name.trim()
            || typeof parameter.in !== 'string' || !PARAMETER_LOCATIONS.has(parameter.in)
            || (parameter.required !== undefined && typeof parameter.required !== 'boolean')
            || (parameter.style !== undefined && (typeof parameter.style !== 'string' || !parameter.style.trim()))
            || (parameter.explode !== undefined && typeof parameter.explode !== 'boolean'))
            fail(resolved);
        const parameterLocation = parameter.in;
        const name = parameterLocation === 'header' ? parameter.name.trim().toLowerCase() : parameter.name.trim();
        const required = parameter.required === true;
        if (parameterLocation === 'path' && !required)
            fail(resolved);
        const constraintResult = normalizeConstraints(parameter.schema === undefined ? undefined : locatedChild(resolved, 'schema', parameter.schema), materialize);
        const unsupportedReasons = [...constraintResult.unsupportedReasons];
        if (parameter.content !== undefined)
            unsupportedReasons.push('parameter:content');
        if (unsupportedReasons.length > 0)
            parameterCapability = 'partial';
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
    const parameterMap = (owner, input) => {
        if (input === undefined)
            return new Map();
        if (!Array.isArray(input) || input.length > limits.maxParametersPerOperation)
            fail(owner);
        const result = new Map();
        for (let index = 0; index < input.length; index += 1) {
            const parameters = locatedChild(owner, 'parameters', input);
            const normalized = normalizeParameter(locatedChild(parameters, String(index), input[index]));
            if (result.has(normalized.key))
                fail(owner);
            result.set(normalized.key, normalized.parameter);
        }
        return result;
    };
    const normalizeBody = (operation, input) => {
        if (input === undefined)
            return undefined;
        const resolved = materialize(locatedChild(operation, 'requestBody', input));
        const body = asObject(resolved);
        if (body.required !== undefined && typeof body.required !== 'boolean')
            fail(resolved);
        const content = body.content === undefined ? {} : asObject(locatedChild(resolved, 'content', body.content));
        const contentTypes = Object.keys(content).map((mediaType) => mediaType.split(';', 1)[0].trim().toLowerCase());
        if (contentTypes.some((mediaType) => !/^[^/\s]+\/[^/\s]+$/.test(mediaType)))
            fail(resolved);
        const schemas = Object.keys(content).sort(compareText).map((mediaType) => {
            const contentLocation = locatedChild(resolved, 'content', content);
            const mediaLocation = locatedChild(contentLocation, mediaType, content[mediaType]);
            const media = asObject(mediaLocation);
            return normalizeConstraints(media.schema === undefined ? undefined : locatedChild(mediaLocation, 'schema', media.schema), materialize, { maxDepth: limits.maxSchemaDepth });
        });
        let normalized = schemas[0] ?? {
            constraints: { type: 'unknown' },
            unsupportedReasons: ['requestBody:content-missing'],
        };
        if (schemas.some((schema) => stableValue(schema) !== stableValue(normalized))) {
            normalized = { constraints: { type: 'unknown' }, unsupportedReasons: ['requestBody:multiple-schemas'] };
        }
        if (normalized.unsupportedReasons.length > 0)
            bodyCapability = 'partial';
        return {
            contentTypes: [...new Set(contentTypes)].sort(compareText),
            body: {
                required: body.required === true,
                constraints: normalized.constraints,
                unsupportedReasons: normalized.unsupportedReasons,
            },
        };
    };
    const rootLocation = {
        value: rootDocument.document,
        sourceUri: rootDocument.sourceUri,
        pointer: '',
    };
    const root = asObject(rootLocation);
    const evidenceFor = (location, capability, complete = true) => {
        const digest = documents.get(location.sourceUri)?.contentDigest;
        if (!digest)
            fail(location);
        return {
            source: 'openapi',
            uri: location.sourceUri,
            pointer: location.pointer,
            digest,
            analyzer: 'openapi-auth-normalizer-v1',
            capability,
            complete,
        };
    };
    let authenticationCapability = 'complete';
    const componentsLocation = locatedChild(rootLocation, 'components', root.components ?? {});
    const components = asObject(componentsLocation);
    const securitySchemesLocation = locatedChild(componentsLocation, 'securitySchemes', components.securitySchemes ?? {});
    const securitySchemes = asObject(securitySchemesLocation);
    if (Object.keys(securitySchemes).length > limits.maxSecuritySchemes)
        fail(securitySchemesLocation);
    const schemeDefinitions = new Map();
    for (const name of Object.keys(securitySchemes).sort(compareText)) {
        const definitionLocation = materialize(locatedChild(securitySchemesLocation, name, securitySchemes[name]));
        const definition = asObject(definitionLocation);
        if (typeof definition.type !== 'string' || !definition.type.trim())
            fail(definitionLocation);
        let scheme;
        if (definition.type === 'http') {
            if (typeof definition.scheme !== 'string' || !definition.scheme.trim())
                fail(definitionLocation);
            const httpScheme = definition.scheme.trim().toLowerCase();
            scheme = httpScheme === 'basic' || httpScheme === 'bearer'
                ? { name, kind: httpScheme, capability: 'supported' }
                : { name, kind: 'unknown', capability: 'unsupported', unsupportedReason: `http-scheme:${httpScheme}` };
        }
        else if (definition.type === 'apiKey') {
            if (typeof definition.name !== 'string' || !definition.name.trim()
                || typeof definition.in !== 'string' || !PARAMETER_LOCATIONS.has(definition.in)
                || definition.in === 'path')
                fail(definitionLocation);
            const location = definition.in;
            scheme = {
                name,
                kind: 'api-key',
                location,
                parameterName: location === 'header' ? definition.name.trim().toLowerCase() : definition.name.trim(),
                capability: 'supported',
            };
        }
        else if (definition.type === 'oauth2') {
            const flowsLocation = locatedChild(definitionLocation, 'flows', definition.flows);
            const flows = asObject(flowsLocation);
            const names = ['authorizationCode', 'clientCredentials', 'implicit', 'password']
                .filter((flow) => flows[flow] !== undefined);
            if (names.length === 0)
                fail(flowsLocation);
            for (const flow of names) {
                const flowLocation = locatedChild(flowsLocation, flow, flows[flow]);
                const value = asObject(flowLocation);
                const requiredUrls = flow === 'implicit' ? ['authorizationUrl']
                    : flow === 'authorizationCode' ? ['authorizationUrl', 'tokenUrl'] : ['tokenUrl'];
                if (requiredUrls.some((field) => typeof value[field] !== 'string' || !value[field].trim())) {
                    fail(flowLocation);
                }
                const scopes = asObject(locatedChild(flowLocation, 'scopes', value.scopes));
                if (Object.values(scopes).some((description) => typeof description !== 'string'))
                    fail(flowLocation);
            }
            scheme = { name, kind: 'oauth2', flows: names.sort(compareText), capability: 'supported' };
        }
        else if (definition.type === 'openIdConnect') {
            if (typeof definition.openIdConnectUrl !== 'string' || !definition.openIdConnectUrl.trim()) {
                fail(definitionLocation);
            }
            scheme = { name, kind: 'openid-connect', capability: 'supported' };
        }
        else if (definition.type === 'mutualTLS') {
            scheme = { name, kind: 'mutual-tls', capability: 'supported' };
        }
        else {
            scheme = {
                name,
                kind: 'unknown',
                capability: 'unsupported',
                unsupportedReason: `security-scheme:type:${definition.type.trim().toLowerCase()}`,
            };
        }
        if (scheme.capability === 'unsupported')
            authenticationCapability = 'partial';
        schemeDefinitions.set(name, {
            scheme,
            evidence: evidenceFor(definitionLocation, 'openapi-security-scheme-v1', scheme.capability === 'supported'),
        });
    }
    const normalizeAuthentication = (input, location) => {
        if (location === undefined) {
            authenticationCapability = 'partial';
            return { auth: { mode: 'unknown', alternatives: [] }, exposure: 'unknown', evidence: [] };
        }
        if (!Array.isArray(input) || input.length > limits.maxSecuritySchemes)
            fail(location);
        const evidence = [evidenceFor(location, 'openapi-auth-requirement-v1')];
        if (input.length === 0) {
            return { auth: { mode: 'none', alternatives: [] }, exposure: 'public', evidence };
        }
        const alternatives = input.map((value, index) => {
            const requirementLocation = locatedChild(location, String(index), value);
            const requirement = asObject(requirementLocation);
            const names = Object.keys(requirement).sort(compareText);
            if (names.length > limits.maxSecuritySchemes)
                fail(requirementLocation);
            const schemes = names.map((name) => {
                const scopes = requirement[name];
                const definition = schemeDefinitions.get(name);
                if (!definition || !Array.isArray(scopes)
                    || scopes.some((scope) => typeof scope !== 'string' || !scope.trim()))
                    fail(requirementLocation);
                if (!['oauth2', 'openid-connect', 'unknown'].includes(definition.scheme.kind) && scopes.length > 0) {
                    fail(requirementLocation);
                }
                evidence.push(definition.evidence);
                return { ...definition.scheme, scopes };
            });
            return { anonymous: schemes.length === 0, schemes };
        });
        return {
            auth: { mode: 'alternatives', alternatives },
            exposure: alternatives.some(({ anonymous }) => anonymous) ? 'public' : 'authenticated',
            evidence,
        };
    };
    const rootSecurityLocation = Object.prototype.hasOwnProperty.call(root, 'security')
        ? locatedChild(rootLocation, 'security', root.security)
        : undefined;
    const pathsLocation = locatedChild(rootLocation, 'paths', root.paths ?? {});
    const paths = asObject(pathsLocation);
    const operations = [];
    for (const routePath of Object.keys(paths).sort(compareText)) {
        const rawPathItem = locatedChild(pathsLocation, routePath, paths[routePath]);
        let canonicalPath;
        try {
            canonicalPath = (0, contract_1.canonicalizePath)(routePath);
        }
        catch {
            fail(rawPathItem);
        }
        const templateNames = [...canonicalPath.matchAll(/\{([^{}]+)\}/g)].map((match) => match[1]);
        if (canonicalPath.replace(/\{[^{}]+\}/g, '').match(/[{}]/))
            fail(rawPathItem);
        const pathItemLocation = materialize(rawPathItem);
        const pathItem = asObject(pathItemLocation);
        const inherited = parameterMap(pathItemLocation, pathItem.parameters);
        for (const methodKey of Object.keys(pathItem).filter((key) => METHOD_KEYS.has(key.toLowerCase())).sort(compareText)) {
            if (operations.length >= limits.maxOperations)
                fail(pathItemLocation, 'OPENAPI_OPERATION_LIMIT');
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
            for (const [key, value] of parameterMap(operationLocation, operation.parameters))
                merged.set(key, value);
            if (merged.size > limits.maxParametersPerOperation)
                fail(operationLocation);
            const byLocation = (location) => [...merged.entries()]
                .filter(([key]) => key.startsWith(`${location}:`)).map(([, value]) => value);
            const pathParameters = byLocation('path');
            const pathParameterNames = new Set(pathParameters.map(({ name }) => name));
            if (templateNames.some((name) => !pathParameterNames.has(name))
                || pathParameters.some(({ name }) => !templateNames.includes(name)))
                fail(operationLocation);
            const body = normalizeBody(operationLocation, operation.requestBody);
            const headerParameters = byLocation('header');
            const digest = documents.get(operationLocation.sourceUri)?.contentDigest;
            if (!digest)
                fail(operationLocation);
            const operationSecurityLocation = Object.prototype.hasOwnProperty.call(operation, 'security')
                ? locatedChild(operationLocation, 'security', operation.security)
                : undefined;
            const authentication = normalizeAuthentication(operationSecurityLocation === undefined
                ? rootSecurityLocation?.value
                : operationSecurityLocation.value, operationSecurityLocation ?? rootSecurityLocation);
            operations.push({
                method: methodKey,
                path: canonicalPath,
                ...(typeof operation.operationId === 'string' && operation.operationId.trim()
                    ? { operationId: operation.operationId.trim() } : {}),
                exposure: authentication.exposure,
                auth: authentication.auth,
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
                    }, ...authentication.evidence],
                metadata: {
                    deprecated: operation.deprecated === true,
                    tags: Array.isArray(operation.tags)
                        ? operation.tags.filter((tag) => typeof tag === 'string') : [],
                },
            });
        }
    }
    try {
        return (0, contract_1.createSecurityContract)({
            source: 'openapi',
            capabilities: {
                routes: 'complete',
                parameters: parameterCapability,
                requestBodies: bodyCapability,
                authentication: authenticationCapability,
            },
            operations,
        });
    }
    catch {
        fail();
    }
}
