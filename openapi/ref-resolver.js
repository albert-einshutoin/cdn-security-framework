"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.serializeResolvedOpenApiGraph = void 0;
exports.isResolvedOpenApiGraph = isResolvedOpenApiGraph;
exports.resolveJsonPointer = resolveJsonPointer;
exports.resolveJsonPointerValue = resolveJsonPointerValue;
exports.resolveOpenApiReferences = resolveOpenApiReferences;
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const analysis_error_1 = require("./analysis-error");
const analysis_limits_1 = require("./analysis-limits");
const load_document_1 = require("./load-document");
const ref_boundary_1 = require("./ref-boundary");
const RESOLVED_OPENAPI_GRAPHS = new WeakSet();
const LITERAL_VALUE_KEYS = new Set(['const', 'default', 'enum', 'example', 'value']);
const NAMED_OBJECT_MAP_KEYS = new Set([
    '$defs', 'callbacks', 'content', 'definitions', 'dependentSchemas', 'encoding', 'examples',
    'headers', 'links', 'parameters', 'pathItems', 'paths', 'patternProperties', 'properties',
    'requestBodies', 'responses', 'schemas', 'securitySchemes', 'webhooks',
]);
const SCHEMA_MAP_KEYS = new Set([
    '$defs', 'definitions', 'dependentSchemas', 'patternProperties', 'properties',
]);
const SCHEMA_NAMED_MAP_KEYS = new Set([...SCHEMA_MAP_KEYS, 'schemas']);
const SCHEMA_SINGLE_KEYS = new Set([
    'additionalProperties', 'contains', 'contentSchema', 'else', 'if', 'items', 'not',
    'propertyNames', 'then', 'unevaluatedItems', 'unevaluatedProperties',
]);
const SCHEMA_ARRAY_KEYS = new Set(['allOf', 'anyOf', 'oneOf', 'prefixItems']);
var document_graph_1 = require("./document-graph");
Object.defineProperty(exports, "serializeResolvedOpenApiGraph", { enumerable: true, get: function () { return document_graph_1.serializeResolvedOpenApiGraph; } });
function isResolvedOpenApiGraph(value) {
    return typeof value === 'object' && value !== null
        && RESOLVED_OPENAPI_GRAPHS.has(value)
        && Object.isFrozen(value);
}
function pointerError(code, sourceUri, pointer) {
    throw new analysis_error_1.OpenApiAnalysisError(code, { sourceUri, pointer });
}
function resolveJsonPointer(document, fragment, sourceUri) {
    const resolved = resolveJsonPointerValue(document, fragment, sourceUri);
    if (resolved.value === null || typeof resolved.value !== 'object') {
        pointerError('OPENAPI_REF_NOT_FOUND', sourceUri, resolved.pointer);
    }
    return resolved;
}
function resolveJsonPointerValue(document, fragment, sourceUri) {
    if (!fragment.startsWith('#'))
        pointerError('OPENAPI_REF_POINTER_INVALID', sourceUri, fragment);
    let decoded;
    try {
        decoded = decodeURIComponent(fragment.slice(1));
    }
    catch {
        pointerError('OPENAPI_REF_POINTER_INVALID', sourceUri, fragment);
    }
    if (decoded !== '' && !decoded.startsWith('/')) {
        pointerError('OPENAPI_REF_POINTER_INVALID', sourceUri, decoded);
    }
    const tokens = decoded === '' ? [] : decoded.slice(1).split('/').map((token) => {
        if (/~(?:[^01]|$)/.test(token))
            pointerError('OPENAPI_REF_POINTER_INVALID', sourceUri, decoded);
        return token.replace(/~1/g, '/').replace(/~0/g, '~');
    });
    let value = document;
    for (const token of tokens) {
        if (value === null || typeof value !== 'object'
            || !Object.prototype.hasOwnProperty.call(value, token)) {
            pointerError('OPENAPI_REF_NOT_FOUND', sourceUri, decoded);
        }
        value = value[token];
    }
    return { value, pointer: decoded };
}
function encodePointerToken(token) {
    return token.replace(/~/g, '~0').replace(/\//g, '~1');
}
function location(sourceUri, pointer) {
    return { id: `${sourceUri}#${pointer}`, sourceUri, pointer };
}
function compareText(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
function sourcePath(workspaceRoot, sourceUri) {
    try {
        return node_path_1.default.resolve(workspaceRoot, ...sourceUri.split('/').map(decodeURIComponent));
    }
    catch {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_REF_POINTER_INVALID', { sourceUri });
    }
}
function countNodes(value, limit, ancestors = new Set()) {
    let count = 0;
    const visit = (node) => {
        count += 1;
        if (count > limit)
            throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_NODE_LIMIT');
        if (node === null || typeof node !== 'object')
            return;
        if (ancestors.has(node))
            throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_REF_CYCLE_LIMIT');
        ancestors.add(node);
        for (const child of Object.values(node))
            visit(child);
        ancestors.delete(node);
    };
    visit(value);
    return count;
}
function resolveOpenApiReferences(options) {
    if (!options || typeof options.workspaceRoot !== 'string'
        || !(0, load_document_1.isLoadedOpenApiDocument)(options.root)) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_INVALID_ROOT');
    }
    const limits = (0, analysis_limits_1.validateOpenApiAnalysisLimits)(options.limits);
    let workspaceRoot;
    try {
        workspaceRoot = node_fs_1.default.realpathSync(options.workspaceRoot);
    }
    catch {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND');
    }
    const rootMetadata = (0, load_document_1.loadedOpenApiDocumentMetadata)(options.root);
    if (rootMetadata.workspaceRoot !== workspaceRoot) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_INVALID_ROOT');
    }
    (0, load_document_1.validateLoadedOpenApiDocumentLimits)(options.root, limits);
    const rootSourcePath = (0, ref_boundary_1.resolveOpenApiRefPath)({
        workspaceRoot,
        sourcePath: sourcePath(workspaceRoot, options.root.sourceUri),
        ref: '#',
    });
    if (rootMetadata.sourcePath !== rootSourcePath) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_INVALID_ROOT');
    }
    const documents = new Map();
    documents.set(options.root.sourceUri, options.root);
    const documentsByPath = new Map();
    documentsByPath.set(rootSourcePath, options.root);
    let totalByteSize = options.root.byteSize;
    let totalNodes = countNodes(options.root.document, limits.maxNodes);
    if (totalByteSize > limits.maxGraphBytes) {
        throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_GRAPH_SIZE_LIMIT');
    }
    const references = [];
    const seenReferenceLocations = new Set();
    let resolutionVisits = 0;
    const loadDocument = (absolutePath) => {
        const cachedByPath = documentsByPath.get(absolutePath);
        if (cachedByPath)
            return cachedByPath;
        if (documents.size >= limits.maxResolvedDocuments) {
            throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_DOCUMENT_COUNT_LIMIT');
        }
        const loaded = (0, load_document_1.loadOpenApiSourceDocument)({
            inputPath: absolutePath,
            workspaceRoot,
            limits,
        });
        const cached = documents.get(loaded.sourceUri);
        if (cached)
            return cached;
        totalByteSize += loaded.byteSize;
        if (totalByteSize > limits.maxGraphBytes) {
            throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_GRAPH_SIZE_LIMIT', { sourceUri: loaded.sourceUri });
        }
        totalNodes += countNodes(loaded.document, limits.maxNodes - totalNodes);
        documents.set(loaded.sourceUri, loaded);
        documentsByPath.set(absolutePath, loaded);
        return loaded;
    };
    const followReference = (ref, fromDocument, fromPointer, depth, ancestors, linkObject = false, schemaObject = false) => {
        if (depth >= limits.maxRefDepth) {
            throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_REF_DEPTH_LIMIT', {
                sourceUri: fromDocument.sourceUri,
                pointer: fromPointer,
            });
        }
        const hash = ref.indexOf('#');
        const rawPath = hash === -1 ? ref : ref.slice(0, hash);
        let refPath;
        try {
            refPath = decodeURIComponent(rawPath);
        }
        catch {
            throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_REF_POINTER_INVALID', {
                sourceUri: fromDocument.sourceUri,
                pointer: fromPointer,
            });
        }
        const fragment = hash === -1 ? '#' : ref.slice(hash);
        const currentPath = sourcePath(workspaceRoot, fromDocument.sourceUri);
        const targetPath = rawPath === ''
            ? currentPath
            : (0, ref_boundary_1.resolveOpenApiRefPath)({
                workspaceRoot, sourcePath: currentPath, ref: refPath, fragmentSeparated: true,
            });
        const targetDocument = rawPath === '' ? fromDocument : loadDocument(targetPath);
        const resolved = resolveJsonPointerValue(targetDocument.document, fragment, targetDocument.sourceUri);
        if (resolved.value === null || (typeof resolved.value !== 'object'
            && !(schemaObject && options.root.version === '3.1'
                && typeof resolved.value === 'boolean'))) {
            pointerError('OPENAPI_REF_NOT_FOUND', targetDocument.sourceUri, resolved.pointer);
        }
        const target = location(targetDocument.sourceUri, resolved.pointer);
        const refLocation = `${fromDocument.sourceUri}#${fromPointer}`;
        if (!seenReferenceLocations.has(refLocation)) {
            seenReferenceLocations.add(refLocation);
            references.push({
                from: location(fromDocument.sourceUri, fromPointer),
                ref,
                target,
            });
        }
        if (ancestors.has(target.id))
            return;
        walk(resolved.value, targetDocument, resolved.pointer, depth + 1, new Set([
            ...ancestors,
            target.id,
        ]), undefined, linkObject, schemaObject);
    };
    const walk = (value, document, pointer, depth, ancestors, namedMap, linkObject = false, schemaObject = false, schemaArray = false) => {
        resolutionVisits += 1;
        if (resolutionVisits > limits.maxNodes) {
            throw new analysis_error_1.OpenApiAnalysisError('OPENAPI_NODE_LIMIT', {
                sourceUri: document.sourceUri,
                pointer,
            });
        }
        if (value === null || typeof value !== 'object')
            return;
        if (!Array.isArray(value) && typeof value.$ref === 'string') {
            followReference(value.$ref, document, pointer, depth, ancestors, linkObject, schemaObject);
        }
        for (const [key, child] of Object.entries(value)) {
            if (key === '$ref')
                continue;
            if (schemaObject && !SCHEMA_MAP_KEYS.has(key)
                && !SCHEMA_SINGLE_KEYS.has(key) && !SCHEMA_ARRAY_KEYS.has(key))
                continue;
            if (linkObject && (key === 'parameters' || key === 'requestBody'))
                continue;
            if (!namedMap && (LITERAL_VALUE_KEYS.has(key) || key.startsWith('x-')
                || (key === 'examples' && Array.isArray(child))))
                continue;
            const childNamedMap = !namedMap && NAMED_OBJECT_MAP_KEYS.has(key) && !Array.isArray(child)
                ? key
                : undefined;
            walk(child, document, `${pointer}/${encodePointerToken(key)}`, depth, ancestors, childNamedMap, namedMap === 'links', schemaArray
                || (namedMap !== undefined && SCHEMA_NAMED_MAP_KEYS.has(namedMap))
                || (!schemaObject && key === 'schema')
                || (schemaObject && SCHEMA_SINGLE_KEYS.has(key) && !Array.isArray(child)), schemaObject && (SCHEMA_ARRAY_KEYS.has(key)
                || (key === 'items' && Array.isArray(child))));
        }
    };
    walk(options.root.document, options.root, '', 0, new Set());
    const resolvedDocuments = [...documents.values()]
        .map(({ sourceUri, contentDigest, byteSize, document }) => ({
        sourceUri,
        contentDigest,
        byteSize,
        document,
    }))
        .sort((left, right) => compareText(left.sourceUri, right.sourceUri));
    references.sort((left, right) => (compareText(left.from.id, right.from.id)
        || compareText(left.ref, right.ref)
        || compareText(left.target.id, right.target.id)));
    const root = Object.freeze(location(options.root.sourceUri, ''));
    const frozenDocuments = Object.freeze(resolvedDocuments.map((document) => Object.freeze(document)));
    const frozenReferences = Object.freeze(references.map((reference) => Object.freeze({
        ...reference,
        from: Object.freeze(reference.from),
        target: Object.freeze(reference.target),
    })));
    const graph = Object.freeze({
        root,
        documents: frozenDocuments,
        references: frozenReferences,
        totalByteSize,
    });
    RESOLVED_OPENAPI_GRAPHS.add(graph);
    return graph;
}
