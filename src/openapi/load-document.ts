import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import * as yaml from 'js-yaml';

import { OpenApiAnalysisError } from './analysis-error';
import {
  DEFAULT_OPENAPI_ANALYSIS_LIMITS,
  validateOpenApiAnalysisLimits,
  type OpenApiAnalysisLimits,
} from './analysis-limits';
import { isPathWithinWorkspace, resolveOpenApiRefPath } from './ref-boundary';

export interface OpenApiRootDocument {
  openapi: string;
  paths?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface LoadedOpenApiDocument {
  document: OpenApiRootDocument;
  sourceUri: string;
  contentDigest: string;
  version: '3.0' | '3.1';
  byteSize: number;
  refStatus: 'unresolved';
}

export interface LoadOpenApiDocumentOptions {
  inputPath: string;
  workspaceRoot: string;
  limits?: Partial<OpenApiAnalysisLimits>;
}

const FORBIDDEN_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

function parseError(sourceUri: string, error?: unknown): OpenApiAnalysisError {
  const mark = error instanceof yaml.YAMLException ? error.mark : undefined;
  const reason = error instanceof yaml.YAMLException ? error.reason : '';
  if (/alias(?:es)?.*(?:limit|maxAliases)/i.test(reason)) {
    return new OpenApiAnalysisError('OPENAPI_YAML_ALIAS_LIMIT', { sourceUri });
  }
  if (/depth.*limit|maximum.*depth|maxDepth|nesting.*depth/i.test(reason)) {
    return new OpenApiAnalysisError('OPENAPI_NODE_LIMIT', { sourceUri });
  }
  return new OpenApiAnalysisError('OPENAPI_PARSE_ERROR', {
    sourceUri,
    ...(mark ? { line: mark.line + 1, column: mark.column + 1 } : {}),
  });
}

function parseDocument(
  source: string,
  sourceUri: string,
  limits: Readonly<OpenApiAnalysisLimits>,
): unknown {
  const yamlOptions: yaml.LoadOptions = {
    schema: yaml.JSON_SCHEMA,
    json: false,
    maxAliases: limits.maxYamlAliases,
    maxDepth: limits.maxSchemaDepth,
  };
  try {
    const json = JSON.parse(source) as unknown;
    yaml.load(source, yamlOptions); // JSON subset pass also rejects duplicate mapping keys.
    return json;
  } catch (jsonError: unknown) {
    try {
      return yaml.load(source, yamlOptions);
    } catch (yamlError: unknown) {
      throw parseError(sourceUri, yamlError ?? jsonError);
    }
  }
}

interface ValidationState {
  nodes: number;
}

function validateSafeValue(
  value: unknown,
  limits: Readonly<OpenApiAnalysisLimits>,
  state: ValidationState,
  ancestors: Set<object>,
  depth = 0,
): void {
  state.nodes += 1;
  if (state.nodes > limits.maxNodes || depth > limits.maxSchemaDepth) {
    throw new OpenApiAnalysisError('OPENAPI_NODE_LIMIT');
  }
  if (typeof value === 'string') {
    if (value.length > limits.maxStringLength) throw new OpenApiAnalysisError('OPENAPI_NODE_LIMIT');
    return;
  }
  if (value === null || typeof value !== 'object') return;
  if (ancestors.has(value)) throw new OpenApiAnalysisError('OPENAPI_REF_CYCLE_LIMIT');

  if (!Array.isArray(value)) {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new OpenApiAnalysisError('OPENAPI_PARSE_ERROR');
  }
  ancestors.add(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!('value' in descriptor)
      || key.length > limits.maxStringLength
      || FORBIDDEN_KEYS.has(key)) {
      throw new OpenApiAnalysisError('OPENAPI_PARSE_ERROR');
    }
    validateSafeValue(descriptor.value, limits, state, ancestors, depth + 1);
  }
  ancestors.delete(value);
}

function asRootDocument(value: unknown): OpenApiRootDocument {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new OpenApiAnalysisError('OPENAPI_INVALID_ROOT');
  }
  const document = value as Record<string, unknown>;
  if (typeof document.openapi !== 'string'
    || (document.paths !== undefined
      && (document.paths === null || typeof document.paths !== 'object' || Array.isArray(document.paths)))) {
    throw new OpenApiAnalysisError('OPENAPI_INVALID_ROOT');
  }
  return document as OpenApiRootDocument;
}

function detectVersion(version: string): '3.0' | '3.1' {
  const match = /^3\.(0|1)\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.exec(version);
  if (!match) throw new OpenApiAnalysisError('OPENAPI_UNSUPPORTED_VERSION');
  return match[1] === '0' ? '3.0' : '3.1';
}

export function loadOpenApiDocument(options: LoadOpenApiDocumentOptions): LoadedOpenApiDocument {
  if (!options || typeof options.inputPath !== 'string' || typeof options.workspaceRoot !== 'string') {
    throw new OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND');
  }
  const isNativeAbsolute = path.isAbsolute(options.inputPath);
  const isWindowsAbsolute = path.win32.isAbsolute(options.inputPath);
  if (!isNativeAbsolute && !isWindowsAbsolute
    && /^[A-Za-z][A-Za-z0-9+.-]*:/.test(options.inputPath)) {
    throw new OpenApiAnalysisError('OPENAPI_REMOTE_REF_DISABLED');
  }
  const limits = validateOpenApiAnalysisLimits({
    ...DEFAULT_OPENAPI_ANALYSIS_LIMITS,
    ...(options.limits ?? {}),
  });
  const candidate = isNativeAbsolute || isWindowsAbsolute
    ? options.inputPath
    : path.resolve(options.workspaceRoot, options.inputPath);
  const resolvedPath = resolveOpenApiRefPath({
    workspaceRoot: options.workspaceRoot,
    sourcePath: candidate,
    ref: '#',
  });
  let rootRealPath: string;
  try {
    rootRealPath = fs.realpathSync(options.workspaceRoot);
  } catch {
    throw new OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND', { sourceUri: options.inputPath });
  }
  if (!isPathWithinWorkspace(rootRealPath, resolvedPath)) {
    throw new OpenApiAnalysisError('OPENAPI_REF_OUTSIDE_ROOT', { sourceUri: candidate });
  }
  const sourceUri = path.relative(rootRealPath, resolvedPath).split(path.sep)
    .map((segment) => encodeURIComponent(segment)).join('/');

  let beforeRead: fs.Stats;
  try {
    beforeRead = fs.statSync(resolvedPath);
  } catch {
    throw new OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND', { sourceUri });
  }
  if (!beforeRead.isFile()) throw new OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND', { sourceUri });
  if (beforeRead.size > limits.maxDocumentBytes) {
    throw new OpenApiAnalysisError('OPENAPI_DOCUMENT_TOO_LARGE', { sourceUri });
  }

  let descriptor: number | undefined;
  let bytes: Buffer;
  try {
    descriptor = fs.openSync(resolvedPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || opened.dev !== beforeRead.dev || opened.ino !== beforeRead.ino) {
      throw new OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND', { sourceUri });
    }
    const openedRealPath = fs.realpathSync(resolvedPath);
    const openedPath = fs.statSync(openedRealPath);
    if (!isPathWithinWorkspace(rootRealPath, openedRealPath)
      || openedPath.dev !== opened.dev
      || openedPath.ino !== opened.ino) {
      throw new OpenApiAnalysisError('OPENAPI_REF_OUTSIDE_ROOT', { sourceUri });
    }
    if (opened.size > limits.maxDocumentBytes) {
      throw new OpenApiAnalysisError('OPENAPI_DOCUMENT_TOO_LARGE', { sourceUri });
    }
    const bounded = Buffer.allocUnsafe(limits.maxDocumentBytes + 1);
    let offset = 0;
    while (offset < bounded.length) {
      const read = fs.readSync(descriptor, bounded, offset, bounded.length - offset, null);
      if (read === 0) break;
      offset += read;
    }
    if (offset > limits.maxDocumentBytes) {
      throw new OpenApiAnalysisError('OPENAPI_DOCUMENT_TOO_LARGE', { sourceUri });
    }
    bytes = bounded.subarray(0, offset);
  } catch (error: unknown) {
    if (error instanceof OpenApiAnalysisError) throw error;
    throw new OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND', { sourceUri });
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }

  let source: string;
  try {
    source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new OpenApiAnalysisError('OPENAPI_PARSE_ERROR', { sourceUri });
  }
  const parsed = parseDocument(source, sourceUri, limits);
  validateSafeValue(parsed, limits, {
    nodes: 0,
  }, new Set<object>());
  const document = asRootDocument(parsed);
  return {
    document,
    sourceUri,
    contentDigest: `sha256:${createHash('sha256').update(bytes).digest('hex')}`,
    version: detectVersion(document.openapi),
    byteSize: bytes.length,
    refStatus: 'unresolved',
  };
}
