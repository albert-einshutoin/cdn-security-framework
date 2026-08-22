import fs from 'node:fs';
import path from 'node:path';

import { OpenApiAnalysisError } from './analysis-error';
import { validateOpenApiAnalysisLimits, type OpenApiAnalysisLimits } from './analysis-limits';
import {
  type OpenApiNodeLocation,
  type OpenApiReferenceEdge,
  type ResolvedOpenApiDocument,
  type ResolvedOpenApiGraph,
  serializeResolvedOpenApiGraph,
} from './document-graph';
import {
  loadedOpenApiDocumentMetadata,
  loadOpenApiSourceDocument,
  isLoadedOpenApiDocument,
  validateLoadedOpenApiDocumentLimits,
  type LoadedOpenApiDocument,
  type LoadedOpenApiSourceDocument,
} from './load-document';
import { resolveOpenApiRefPath } from './ref-boundary';

const RESOLVED_OPENAPI_GRAPHS = new WeakSet<object>();
const LITERAL_VALUE_KEYS = new Set(['const', 'default', 'enum', 'example', 'value']);

export { serializeResolvedOpenApiGraph } from './document-graph';
export type {
  OpenApiNodeLocation,
  OpenApiReferenceEdge,
  ResolvedOpenApiDocument,
  ResolvedOpenApiGraph,
} from './document-graph';

export interface ResolveOpenApiReferencesOptions {
  root: LoadedOpenApiDocument;
  workspaceRoot: string;
  limits: OpenApiAnalysisLimits;
}

export interface ResolvedJsonPointer {
  value: Record<string, unknown> | unknown[];
  pointer: string;
}

export interface ResolvedJsonPointerValue {
  value: unknown;
  pointer: string;
}

export function isResolvedOpenApiGraph(value: unknown): value is ResolvedOpenApiGraph {
  return typeof value === 'object' && value !== null
    && RESOLVED_OPENAPI_GRAPHS.has(value)
    && Object.isFrozen(value);
}

function pointerError(
  code: 'OPENAPI_REF_NOT_FOUND' | 'OPENAPI_REF_POINTER_INVALID',
  sourceUri: string,
  pointer: string,
): never {
  throw new OpenApiAnalysisError(code, { sourceUri, pointer });
}

export function resolveJsonPointer(
  document: unknown,
  fragment: string,
  sourceUri: string,
): ResolvedJsonPointer {
  const resolved = resolveJsonPointerValue(document, fragment, sourceUri);
  if (resolved.value === null || typeof resolved.value !== 'object') {
    pointerError('OPENAPI_REF_NOT_FOUND', sourceUri, resolved.pointer);
  }
  return resolved as ResolvedJsonPointer;
}

export function resolveJsonPointerValue(
  document: unknown,
  fragment: string,
  sourceUri: string,
): ResolvedJsonPointerValue {
  if (!fragment.startsWith('#')) pointerError('OPENAPI_REF_POINTER_INVALID', sourceUri, fragment);
  let decoded: string;
  try {
    decoded = decodeURIComponent(fragment.slice(1));
  } catch {
    pointerError('OPENAPI_REF_POINTER_INVALID', sourceUri, fragment);
  }
  if (decoded !== '' && !decoded.startsWith('/')) {
    pointerError('OPENAPI_REF_POINTER_INVALID', sourceUri, decoded);
  }
  const tokens = decoded === '' ? [] : decoded.slice(1).split('/').map((token) => {
    if (/~(?:[^01]|$)/.test(token)) pointerError('OPENAPI_REF_POINTER_INVALID', sourceUri, decoded);
    return token.replace(/~1/g, '/').replace(/~0/g, '~');
  });
  let value = document;
  for (const token of tokens) {
    if (value === null || typeof value !== 'object'
      || !Object.prototype.hasOwnProperty.call(value, token)) {
      pointerError('OPENAPI_REF_NOT_FOUND', sourceUri, decoded);
    }
    value = (value as Record<string, unknown>)[token];
  }
  return { value, pointer: decoded };
}

function encodePointerToken(token: string): string {
  return token.replace(/~/g, '~0').replace(/\//g, '~1');
}

function location(sourceUri: string, pointer: string): OpenApiNodeLocation {
  return { id: `${sourceUri}#${pointer}`, sourceUri, pointer };
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sourcePath(workspaceRoot: string, sourceUri: string): string {
  try {
    return path.resolve(workspaceRoot, ...sourceUri.split('/').map(decodeURIComponent));
  } catch {
    throw new OpenApiAnalysisError('OPENAPI_REF_POINTER_INVALID', { sourceUri });
  }
}

function countNodes(
  value: unknown,
  limit: number,
  ancestors = new Set<object>(),
): number {
  let count = 0;
  const visit = (node: unknown): void => {
    count += 1;
    if (count > limit) throw new OpenApiAnalysisError('OPENAPI_NODE_LIMIT');
    if (node === null || typeof node !== 'object') return;
    if (ancestors.has(node)) throw new OpenApiAnalysisError('OPENAPI_REF_CYCLE_LIMIT');
    ancestors.add(node);
    for (const child of Object.values(node)) visit(child);
    ancestors.delete(node);
  };
  visit(value);
  return count;
}

export function resolveOpenApiReferences(
  options: ResolveOpenApiReferencesOptions,
): ResolvedOpenApiGraph {
  if (!options || typeof options.workspaceRoot !== 'string'
    || !isLoadedOpenApiDocument(options.root)) {
    throw new OpenApiAnalysisError('OPENAPI_INVALID_ROOT');
  }
  const limits = validateOpenApiAnalysisLimits(options.limits);
  let workspaceRoot: string;
  try {
    workspaceRoot = fs.realpathSync(options.workspaceRoot);
  } catch {
    throw new OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND');
  }
  const rootMetadata = loadedOpenApiDocumentMetadata(options.root);
  if (rootMetadata.workspaceRoot !== workspaceRoot) {
    throw new OpenApiAnalysisError('OPENAPI_INVALID_ROOT');
  }
  validateLoadedOpenApiDocumentLimits(options.root, limits);
  const rootSourcePath = resolveOpenApiRefPath({
    workspaceRoot,
    sourcePath: sourcePath(workspaceRoot, options.root.sourceUri),
    ref: '#',
  });
  if (rootMetadata.sourcePath !== rootSourcePath) {
    throw new OpenApiAnalysisError('OPENAPI_INVALID_ROOT');
  }
  const documents = new Map<string, LoadedOpenApiSourceDocument>();
  documents.set(options.root.sourceUri, options.root);
  const documentsByPath = new Map<string, LoadedOpenApiSourceDocument>();
  documentsByPath.set(rootSourcePath, options.root);
  let totalByteSize = options.root.byteSize;
  let totalNodes = countNodes(options.root.document, limits.maxNodes);
  if (totalByteSize > limits.maxGraphBytes) {
    throw new OpenApiAnalysisError('OPENAPI_GRAPH_SIZE_LIMIT');
  }

  const references: OpenApiReferenceEdge[] = [];
  const seenReferenceLocations = new Set<string>();
  let resolutionVisits = 0;

  const loadDocument = (absolutePath: string): LoadedOpenApiSourceDocument => {
    const cachedByPath = documentsByPath.get(absolutePath);
    if (cachedByPath) return cachedByPath;
    if (documents.size >= limits.maxResolvedDocuments) {
      throw new OpenApiAnalysisError('OPENAPI_DOCUMENT_COUNT_LIMIT');
    }
    const loaded = loadOpenApiSourceDocument({
      inputPath: absolutePath,
      workspaceRoot,
      limits,
    });
    const cached = documents.get(loaded.sourceUri);
    if (cached) return cached;
    totalByteSize += loaded.byteSize;
    if (totalByteSize > limits.maxGraphBytes) {
      throw new OpenApiAnalysisError('OPENAPI_GRAPH_SIZE_LIMIT', { sourceUri: loaded.sourceUri });
    }
    totalNodes += countNodes(loaded.document, limits.maxNodes - totalNodes);
    documents.set(loaded.sourceUri, loaded);
    documentsByPath.set(absolutePath, loaded);
    return loaded;
  };

  const followReference = (
    ref: string,
    fromDocument: LoadedOpenApiSourceDocument,
    fromPointer: string,
    depth: number,
    ancestors: ReadonlySet<string>,
  ): void => {
    if (depth >= limits.maxRefDepth) {
      throw new OpenApiAnalysisError('OPENAPI_REF_DEPTH_LIMIT', {
        sourceUri: fromDocument.sourceUri,
        pointer: fromPointer,
      });
    }
    const hash = ref.indexOf('#');
    const rawPath = hash === -1 ? ref : ref.slice(0, hash);
    let refPath: string;
    try {
      refPath = decodeURIComponent(rawPath);
    } catch {
      throw new OpenApiAnalysisError('OPENAPI_REF_POINTER_INVALID', {
        sourceUri: fromDocument.sourceUri,
        pointer: fromPointer,
      });
    }
    const fragment = hash === -1 ? '#' : ref.slice(hash);
    const currentPath = sourcePath(workspaceRoot, fromDocument.sourceUri);
    const targetPath = rawPath === ''
      ? currentPath
      : resolveOpenApiRefPath({
        workspaceRoot, sourcePath: currentPath, ref: refPath, fragmentSeparated: true,
      });
    const targetDocument = rawPath === '' ? fromDocument : loadDocument(targetPath);
    const resolved = resolveJsonPointerValue(targetDocument.document, fragment, targetDocument.sourceUri);
    if (resolved.value === null
      || (typeof resolved.value !== 'object' && typeof resolved.value !== 'boolean')) {
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
    if (ancestors.has(target.id)) return;
    walk(resolved.value, targetDocument, resolved.pointer, depth + 1, new Set([
      ...ancestors,
      target.id,
    ]));
  };

  const walk = (
    value: unknown,
    document: LoadedOpenApiSourceDocument,
    pointer: string,
    depth: number,
    ancestors: ReadonlySet<string>,
  ): void => {
    resolutionVisits += 1;
    if (resolutionVisits > limits.maxNodes) {
      throw new OpenApiAnalysisError('OPENAPI_NODE_LIMIT', {
        sourceUri: document.sourceUri,
        pointer,
      });
    }
    if (value === null || typeof value !== 'object') return;
    if (!Array.isArray(value) && typeof (value as Record<string, unknown>).$ref === 'string') {
      followReference(
        (value as Record<string, string>).$ref,
        document,
        pointer,
        depth,
        ancestors,
      );
    }
    for (const [key, child] of Object.entries(value)) {
      if (key === '$ref') continue;
      if (LITERAL_VALUE_KEYS.has(key) || key.startsWith('x-')
        || (key === 'examples' && Array.isArray(child))) continue;
      walk(child, document, `${pointer}/${encodePointerToken(key)}`, depth, ancestors);
    }
  };

  walk(options.root.document, options.root, '', 0, new Set());
  const resolvedDocuments: ResolvedOpenApiDocument[] = [...documents.values()]
    .map(({ sourceUri, contentDigest, byteSize, document }) => ({
      sourceUri,
      contentDigest,
      byteSize,
      document,
    }))
    .sort((left, right) => compareText(left.sourceUri, right.sourceUri));
  references.sort((left, right) => (
    compareText(left.from.id, right.from.id)
      || compareText(left.ref, right.ref)
      || compareText(left.target.id, right.target.id)
  ));
  const root = Object.freeze(location(options.root.sourceUri, ''));
  const frozenDocuments = Object.freeze(
    resolvedDocuments.map((document) => Object.freeze(document)),
  );
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
