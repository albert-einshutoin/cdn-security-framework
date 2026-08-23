import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import ts from 'typescript';

import {
  validateSourceAnalysisLimits,
  type SourceAnalysisLimits,
} from '../../source-analysis';

export const TYPESCRIPT_PROJECT_LOADER_VERSION = '1.0.0';

export const TYPESCRIPT_PROJECT_DIAGNOSTIC_CODES = [
  'TS_PROJECT_CANCELLED',
  'TS_PROJECT_TIMEOUT',
  'TS_PROJECT_INVALID_CONFIG',
  'TS_PROJECT_CONFIG_MISSING',
  'TS_PROJECT_EXTENDS_UNSUPPORTED',
  'TS_PROJECT_PATH_OUTSIDE_ROOT',
  'TS_PROJECT_EXTENSION_UNSUPPORTED',
  'TS_PROJECT_FILE_LIMIT',
  'TS_PROJECT_FILE_BYTES_LIMIT',
  'TS_PROJECT_TOTAL_BYTES_LIMIT',
  'TS_PROJECT_AST_NODE_LIMIT',
  'TS_PROJECT_DEPTH_LIMIT',
  'TS_PROJECT_DIAGNOSTIC_LIMIT',
  'TS_PROJECT_REFERENCES_PARTIAL',
  'TS_PROJECT_TYPESCRIPT_DIAGNOSTIC',
  'TS_PROJECT_INTERNAL',
] as const;

export type TypeScriptProjectDiagnosticCode = typeof TYPESCRIPT_PROJECT_DIAGNOSTIC_CODES[number];

export interface TypeScriptProjectDiagnostic {
  code: TypeScriptProjectDiagnosticCode;
  safeMessage: string;
  sourceUri?: string;
  line?: number;
  column?: number;
  typescriptCode?: number;
}

export interface TypeScriptProjectMetrics {
  files: number;
  totalSourceBytes: number;
  largestFileBytes: number;
  astNodes: number;
  maxDepth: number;
  operations: 0;
  cacheHits: 0 | 1;
  cacheMisses: 0 | 1;
  cacheInvalidations: 0 | 1;
}

export interface LoadedTypeScriptProject {
  program: ts.Program;
  sourceFiles: readonly ts.SourceFile[];
  compilerOptions: Readonly<ts.CompilerOptions>;
  pathAliases: Readonly<Record<string, readonly string[]>>;
  projectReferences: 'supported' | 'partial';
  diagnostics: readonly TypeScriptProjectDiagnostic[];
  metrics: Readonly<TypeScriptProjectMetrics>;
}

export interface TypeScriptProjectFileSystem {
  realpath(filePath: string): string;
  readFile(filePath: string): string;
  stat(filePath: string): fs.Stats;
  exists(filePath: string): boolean;
  readDirectory(
    rootDir: string,
    extensions: readonly string[],
    excludes: readonly string[] | undefined,
    includes: readonly string[],
    depth?: number,
  ): string[];
}

export const nodeTypeScriptProjectFileSystem: TypeScriptProjectFileSystem = Object.freeze({
  realpath: fs.realpathSync,
  readFile: (filePath: string) => fs.readFileSync(filePath, 'utf8'),
  stat: fs.statSync,
  exists: fs.existsSync,
  readDirectory: (
    rootDir: string,
    extensions: readonly string[],
    excludes: readonly string[] | undefined,
    includes: readonly string[],
    depth?: number,
  ) => (
    ts.sys.readDirectory(rootDir, [...extensions], excludes ? [...excludes] : undefined, [...includes], depth)
  ),
});

export interface LoadTypeScriptProjectOptions {
  tsconfigPath: string;
  workspaceRoot: string;
  limits: SourceAnalysisLimits;
  cancellationSignal?: AbortSignal;
  cache?: TypeScriptAnalysisCache;
  fileSystem?: TypeScriptProjectFileSystem;
}

const SAFE_MESSAGES: Readonly<Record<TypeScriptProjectDiagnosticCode, string>> = Object.freeze({
  TS_PROJECT_CANCELLED: 'TypeScript project loading was cancelled.',
  TS_PROJECT_TIMEOUT: 'TypeScript project loading timed out.',
  TS_PROJECT_INVALID_CONFIG: 'TypeScript project configuration is invalid.',
  TS_PROJECT_CONFIG_MISSING: 'TypeScript project configuration was not found.',
  TS_PROJECT_EXTENDS_UNSUPPORTED: 'TypeScript configuration extends an unsupported location.',
  TS_PROJECT_PATH_OUTSIDE_ROOT: 'TypeScript project input is outside the workspace root.',
  TS_PROJECT_EXTENSION_UNSUPPORTED: 'TypeScript project contains an unsupported source extension.',
  TS_PROJECT_FILE_LIMIT: 'TypeScript project file limit was exceeded.',
  TS_PROJECT_FILE_BYTES_LIMIT: 'TypeScript project file byte limit was exceeded.',
  TS_PROJECT_TOTAL_BYTES_LIMIT: 'TypeScript project total byte limit was exceeded.',
  TS_PROJECT_AST_NODE_LIMIT: 'TypeScript project AST node limit was exceeded.',
  TS_PROJECT_DEPTH_LIMIT: 'TypeScript project AST depth limit was exceeded.',
  TS_PROJECT_DIAGNOSTIC_LIMIT: 'TypeScript project diagnostic limit was exceeded.',
  TS_PROJECT_REFERENCES_PARTIAL: 'TypeScript project references are not loaded by this analyzer version.',
  TS_PROJECT_TYPESCRIPT_DIAGNOSTIC: 'TypeScript reported a project diagnostic.',
  TS_PROJECT_INTERNAL: 'TypeScript project loading failed unexpectedly.',
});

const SOURCE_EXTENSIONS = Object.freeze(['.ts', '.tsx', '.mts', '.cts']);
const GLOB_MARKER = /[*?]/u;

function diagnostic(
  code: TypeScriptProjectDiagnosticCode,
  options: Omit<TypeScriptProjectDiagnostic, 'code' | 'safeMessage'> = {},
): TypeScriptProjectDiagnostic {
  return { code, safeMessage: SAFE_MESSAGES[code], ...options };
}

export class TypeScriptProjectLoadError extends Error {
  readonly diagnostics: readonly TypeScriptProjectDiagnostic[];

  constructor(code: TypeScriptProjectDiagnosticCode, options: Omit<TypeScriptProjectDiagnostic, 'code' | 'safeMessage'> = {}) {
    super(SAFE_MESSAGES[code]);
    this.name = 'TypeScriptProjectLoadError';
    this.diagnostics = Object.freeze([Object.freeze(diagnostic(code, options))]);
  }
}

interface CacheRead {
  value?: LoadedTypeScriptProject;
  invalidated: 0 | 1;
}

export class TypeScriptAnalysisCache {
  private readonly entries = new Map<string, LoadedTypeScriptProject>();
  private readonly currentKeys = new Map<string, string>();

  read(identity: string, key: string): CacheRead {
    const current = this.currentKeys.get(identity);
    return { value: this.entries.get(key), invalidated: current && current !== key ? 1 : 0 };
  }

  latest(identity: string): LoadedTypeScriptProject | undefined {
    const key = this.currentKeys.get(identity);
    return key ? this.entries.get(key) : undefined;
  }

  write(identity: string, key: string, value: LoadedTypeScriptProject): void {
    const previous = this.currentKeys.get(identity);
    if (previous && previous !== key) this.entries.delete(previous);
    this.currentKeys.set(identity, key);
    this.entries.set(key, value);
  }
}

function checkInterruption(signal: AbortSignal | undefined, deadline: number): void {
  if (signal?.aborted) throw new TypeScriptProjectLoadError('TS_PROJECT_CANCELLED');
  if (performance.now() >= deadline) throw new TypeScriptProjectLoadError('TS_PROJECT_TIMEOUT');
}

function normalizeRelative(value: string): string {
  return value.replaceAll('\\', '/');
}

function relativeWithin(workspaceRoot: string, absolutePath: string): string | undefined {
  const relative = normalizeRelative(path.relative(workspaceRoot, absolutePath));
  if (!relative || relative === '..' || relative.startsWith('../') || path.isAbsolute(relative)) return undefined;
  return relative;
}

function realFileWithin(
  fileSystem: TypeScriptProjectFileSystem,
  workspaceRoot: string,
  candidate: string,
  missingCode: TypeScriptProjectDiagnosticCode,
): { absolute: string; relative: string } {
  let absolute: string;
  try {
    absolute = fileSystem.realpath(candidate);
  } catch {
    throw new TypeScriptProjectLoadError(missingCode);
  }
  const relative = relativeWithin(workspaceRoot, absolute);
  if (!relative) throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
  let stat: fs.Stats;
  try { stat = fileSystem.stat(absolute); } catch { throw new TypeScriptProjectLoadError(missingCode); }
  if (!stat.isFile()) throw new TypeScriptProjectLoadError(missingCode);
  return { absolute, relative };
}

function safeConfigPath(
  fileSystem: TypeScriptProjectFileSystem,
  workspaceRoot: string,
  configDirectory: string,
  configuredPath: string,
): void {
  if (!configuredPath || path.isAbsolute(configuredPath) || /^[a-z][a-z0-9+.-]*:/iu.test(configuredPath)) {
    throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
  }
  const marker = configuredPath.search(GLOB_MARKER);
  const staticPart = marker < 0 ? configuredPath : configuredPath.slice(0, marker);
  const candidate = path.resolve(configDirectory, staticPart || '.');
  if (!relativeWithin(workspaceRoot, candidate) && candidate !== workspaceRoot) {
    throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
  }
  if (fileSystem.exists(candidate)) {
    let realPath: string;
    try { realPath = fileSystem.realpath(candidate); } catch {
      throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
    }
    if (!relativeWithin(workspaceRoot, realPath) && realPath !== workspaceRoot) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
    }
  }
}

interface ConfigState {
  readonly digests: Map<string, string>;
  totalBytes: number;
  hasReferences: boolean;
}

function resolveExtendsCandidate(
  fileSystem: TypeScriptProjectFileSystem,
  configDirectory: string,
  specifier: string,
): string {
  if (path.isAbsolute(specifier)) throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
  if (!specifier.startsWith('.') || /^[a-z][a-z0-9+.-]*:/iu.test(specifier)) {
    throw new TypeScriptProjectLoadError('TS_PROJECT_EXTENDS_UNSUPPORTED');
  }
  const base = path.resolve(configDirectory, specifier);
  for (const candidate of [base, `${base}.json`, path.join(base, 'tsconfig.json')]) {
    if (fileSystem.exists(candidate)) return candidate;
  }
  throw new TypeScriptProjectLoadError('TS_PROJECT_CONFIG_MISSING');
}

function validateConfigTree(
  fileSystem: TypeScriptProjectFileSystem,
  workspaceRoot: string,
  configPath: string,
  limits: Readonly<SourceAnalysisLimits>,
  signal: AbortSignal | undefined,
  deadline: number,
  state: ConfigState,
  visiting: Set<string>,
  depth = 1,
): Record<string, unknown> {
  checkInterruption(signal, deadline);
  if (depth > limits.maxAnalysisDepth) throw new TypeScriptProjectLoadError('TS_PROJECT_DEPTH_LIMIT');
  const resolved = realFileWithin(fileSystem, workspaceRoot, configPath, 'TS_PROJECT_CONFIG_MISSING');
  if (visiting.has(resolved.absolute)) throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
  const text = fileSystem.readFile(resolved.absolute);
  const bytes = Buffer.byteLength(text);
  if (bytes > limits.maxFileBytes) {
    throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_BYTES_LIMIT', { sourceUri: resolved.relative });
  }
  const parsed = ts.parseConfigFileTextToJson(resolved.absolute, text);
  if (parsed.error || !parsed.config || typeof parsed.config !== 'object' || Array.isArray(parsed.config)) {
    throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG', {
      typescriptCode: parsed.error?.code,
      sourceUri: resolved.relative,
    });
  }
  state.digests.set(resolved.relative, crypto.createHash('sha256').update(text).digest('hex'));
  state.totalBytes += bytes;
  if (state.digests.size > limits.maxFiles) throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
  if (state.totalBytes > limits.maxTotalSourceBytes) {
    throw new TypeScriptProjectLoadError('TS_PROJECT_TOTAL_BYTES_LIMIT');
  }
  const config = parsed.config as Record<string, unknown>;
  const configDirectory = path.dirname(resolved.absolute);
  for (const key of ['files', 'include', 'exclude'] as const) {
    const values = config[key];
    if (values === undefined) continue;
    if (!Array.isArray(values) || values.some((value) => typeof value !== 'string')) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG', { sourceUri: resolved.relative });
    }
    for (const value of values as string[]) safeConfigPath(fileSystem, workspaceRoot, configDirectory, value);
  }
  const compilerOptions = config.compilerOptions;
  if (compilerOptions !== undefined) {
    if (!compilerOptions || typeof compilerOptions !== 'object' || Array.isArray(compilerOptions)) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
    }
    const compiler = compilerOptions as Record<string, unknown>;
    for (const key of ['baseUrl', 'rootDir'] as const) {
      const value = compiler[key];
      if (value !== undefined) {
        if (typeof value !== 'string') throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
        safeConfigPath(fileSystem, workspaceRoot, configDirectory, value);
      }
    }
    for (const key of ['rootDirs', 'typeRoots'] as const) {
      const values = compiler[key];
      if (values === undefined) continue;
      if (!Array.isArray(values) || values.some((value) => typeof value !== 'string')) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
      }
      for (const value of values as string[]) safeConfigPath(fileSystem, workspaceRoot, configDirectory, value);
    }
    if (compiler.paths !== undefined) {
      if (!compiler.paths || typeof compiler.paths !== 'object' || Array.isArray(compiler.paths)) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
      }
      for (const values of Object.values(compiler.paths as Record<string, unknown>)) {
        if (!Array.isArray(values) || values.some((value) => typeof value !== 'string')) {
          throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
        }
        for (const value of values as string[]) safeConfigPath(fileSystem, workspaceRoot, configDirectory, value);
      }
    }
  }
  const references = config.references;
  if (references !== undefined) {
    if (!Array.isArray(references)) throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
    state.hasReferences ||= references.length > 0;
    for (const reference of references) {
      if (!reference || typeof reference !== 'object' || typeof (reference as { path?: unknown }).path !== 'string') {
        throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
      }
      safeConfigPath(fileSystem, workspaceRoot, configDirectory, (reference as { path: string }).path);
    }
  }
  const extended = config.extends;
  if (extended !== undefined) {
    const values = typeof extended === 'string' ? [extended] : extended;
    if (!Array.isArray(values) || values.some((value) => typeof value !== 'string')) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
    }
    visiting.add(resolved.absolute);
    try {
      for (const specifier of values as string[]) {
        const candidate = resolveExtendsCandidate(fileSystem, configDirectory, specifier);
        validateConfigTree(fileSystem, workspaceRoot, candidate, limits, signal, deadline, state, visiting, depth + 1);
      }
    } finally {
      visiting.delete(resolved.absolute);
    }
  }
  return config;
}

function createParseHost(
  fileSystem: TypeScriptProjectFileSystem,
  workspaceRoot: string,
  limits: Readonly<SourceAnalysisLimits>,
  signal: AbortSignal | undefined,
  deadline: number,
): ts.ParseConfigHost {
  const safeRealPath = (candidate: string): string | undefined => {
    let absolute: string;
    try {
      absolute = fileSystem.realpath(candidate);
    } catch { return undefined; }
    if (!relativeWithin(workspaceRoot, absolute)) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
    }
    return absolute;
  };
  return {
    useCaseSensitiveFileNames: ts.sys.useCaseSensitiveFileNames,
    fileExists: (candidate) => safeRealPath(candidate) !== undefined,
    readFile: (candidate) => {
      const safe = safeRealPath(candidate);
      return safe ? fileSystem.readFile(safe) : undefined;
    },
    readDirectory: (rootDir, extensions, excludes, includes, depth) => {
      checkInterruption(signal, deadline);
      if (!relativeWithin(workspaceRoot, path.resolve(rootDir)) && path.resolve(rootDir) !== workspaceRoot) return [];
      const files = fileSystem.readDirectory(rootDir, extensions, excludes, includes, depth);
      checkInterruption(signal, deadline);
      if (files.length > limits.maxFiles) throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
      return files.filter((candidate) => (
        safeRealPath(candidate) !== undefined
      ));
    },
  };
}

function safeTypeScriptDiagnostic(
  value: ts.Diagnostic,
  workspaceRoot: string,
): TypeScriptProjectDiagnostic {
  let sourceUri: string | undefined;
  let line: number | undefined;
  let column: number | undefined;
  if (value.file) {
    const relative = relativeWithin(workspaceRoot, path.resolve(value.file.fileName));
    if (relative) {
      sourceUri = relative;
      if (typeof value.start === 'number') {
        const position = value.file.getLineAndCharacterOfPosition(value.start);
        line = position.line + 1;
        column = position.character + 1;
      }
    }
  }
  return diagnostic('TS_PROJECT_TYPESCRIPT_DIAGNOSTIC', {
    typescriptCode: value.code,
    sourceUri,
    line,
    column,
  });
}

function projectIdentity(workspaceRoot: string, configRelative: string): string {
  const workspace = crypto.createHash('sha256').update(workspaceRoot).digest('hex');
  return `typescript-project:${workspace}:${configRelative}`;
}

function contentKey(
  configDigests: ReadonlyMap<string, string>,
  compilerOptions: Readonly<ts.CompilerOptions>,
  sources: readonly { relative: string; text: string }[],
): string {
  const hash = crypto.createHash('sha256').update(TYPESCRIPT_PROJECT_LOADER_VERSION);
  hash.update(ts.version);
  for (const [relative, digest] of [...configDigests].sort(([left], [right]) => left.localeCompare(right))) {
    hash.update(relative).update(digest);
  }
  hash.update(JSON.stringify(compilerOptions));
  for (const source of [...sources].sort((left, right) => left.relative.localeCompare(right.relative))) {
    hash.update(source.relative).update(crypto.createHash('sha256').update(source.text).digest());
  }
  return hash.digest('hex');
}

async function loadTypeScriptProjectInternal(
  options: LoadTypeScriptProjectOptions,
): Promise<LoadedTypeScriptProject> {
  const fileSystem = options.fileSystem ?? nodeTypeScriptProjectFileSystem;
  let limits: Readonly<SourceAnalysisLimits>;
  try { limits = validateSourceAnalysisLimits(options.limits); } catch {
    throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
  }
  const deadline = performance.now() + limits.timeoutMs;
  checkInterruption(options.cancellationSignal, deadline);
  if (path.isAbsolute(options.tsconfigPath)) throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
  let workspaceRoot: string;
  try { workspaceRoot = fileSystem.realpath(options.workspaceRoot); } catch {
    throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
  }
  const configPath = path.resolve(workspaceRoot, options.tsconfigPath);
  const resolvedConfig = realFileWithin(fileSystem, workspaceRoot, configPath, 'TS_PROJECT_CONFIG_MISSING');
  const configState: ConfigState = { digests: new Map(), totalBytes: 0, hasReferences: false };
  validateConfigTree(
    fileSystem,
    workspaceRoot,
    resolvedConfig.absolute,
    limits,
    options.cancellationSignal,
    deadline,
    configState,
    new Set(),
  );
  checkInterruption(options.cancellationSignal, deadline);

  const read = ts.readConfigFile(resolvedConfig.absolute, (candidate) => {
    try { return fileSystem.readFile(candidate); } catch { return undefined; }
  });
  if (read.error) {
    throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG', {
      sourceUri: resolvedConfig.relative,
      typescriptCode: read.error.code,
    });
  }
  const parsed = ts.parseJsonConfigFileContent(
    read.config,
    createParseHost(fileSystem, workspaceRoot, limits, options.cancellationSignal, deadline),
    path.dirname(resolvedConfig.absolute),
    { noEmit: true, plugins: [] },
    resolvedConfig.absolute,
  );
  if (parsed.errors.length > 0) {
    throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG', {
      sourceUri: resolvedConfig.relative,
      typescriptCode: parsed.errors[0].code,
    });
  }
  checkInterruption(options.cancellationSignal, deadline);

  const rootNames: string[] = [];
  const rootContents = new Map<string, { relative: string; text: string; size: number }>();
  let totalSourceBytes = 0;
  let largestFileBytes = 0;
  for (const fileName of parsed.fileNames) {
    checkInterruption(options.cancellationSignal, deadline);
    const resolved = realFileWithin(fileSystem, workspaceRoot, fileName, 'TS_PROJECT_CONFIG_MISSING');
    if (!SOURCE_EXTENSIONS.some((extension) => resolved.relative.endsWith(extension))) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_EXTENSION_UNSUPPORTED', { sourceUri: resolved.relative });
    }
    if (rootContents.has(resolved.absolute)) continue;
    const text = fileSystem.readFile(resolved.absolute);
    const size = Buffer.byteLength(text);
    if (size > limits.maxFileBytes) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_BYTES_LIMIT', { sourceUri: resolved.relative });
    }
    rootContents.set(resolved.absolute, { relative: resolved.relative, text, size });
    rootNames.push(resolved.absolute);
    totalSourceBytes += size;
    largestFileBytes = Math.max(largestFileBytes, size);
    if (rootNames.length > limits.maxFiles) throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
    if (totalSourceBytes > limits.maxTotalSourceBytes) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_TOTAL_BYTES_LIMIT');
    }
  }

  const compilerOptions: ts.CompilerOptions = { ...parsed.options, noEmit: true, plugins: [] };
  const identity = projectIdentity(workspaceRoot, resolvedConfig.relative);
  const defaultHost = ts.createCompilerHost(compilerOptions, true);
  const defaultLibraryRoot = fileSystem.realpath(path.dirname(ts.getDefaultLibFilePath(compilerOptions)));
  const isStandardLibrary = (absolute: string): boolean => (
    path.dirname(absolute) === defaultLibraryRoot && /^lib(?:\.[a-z0-9_-]+)*\.d\.ts$/iu.test(path.basename(absolute))
  );
  let boundaryViolation = false;
  const workspaceContents = new Map(rootContents);
  const libraryContents = new Map<string, string>();
  const metadataContents = new Map<string, { relative: string; text: string }>();
  const validateReferences = (text: string, relative: string): void => {
    const references = ts.preProcessFile(text).referencedFiles;
    if (references.some(({ fileName }) => path.isAbsolute(fileName) || /^[a-z][a-z0-9+.-]*:/iu.test(fileName))) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT', { sourceUri: relative });
    }
    checkInterruption(options.cancellationSignal, deadline);
  };
  const safeExistingPath = (candidate: string): {
    absolute: string;
    kind: 'workspace' | 'library' | 'package-metadata';
  } | undefined => {
    try {
      const absolute = fileSystem.realpath(candidate);
      if (isStandardLibrary(absolute)) return { absolute, kind: 'library' };
      const workspaceRelative = relativeWithin(workspaceRoot, absolute);
      if (workspaceRelative && SOURCE_EXTENSIONS.some((extension) => workspaceRelative.endsWith(extension))) {
        return { absolute, kind: 'workspace' };
      }
      if (workspaceRelative && path.basename(workspaceRelative) === 'package.json'
        && normalizeRelative(workspaceRelative).split('/').includes('node_modules')) {
        return { absolute, kind: 'package-metadata' };
      }
      if (SOURCE_EXTENSIONS.some((extension) => absolute.endsWith(extension))) boundaryViolation = true;
      return undefined;
    } catch { return undefined; }
  };
  const readProgramFile = (candidate: string): string | undefined => {
    const safe = safeExistingPath(candidate);
    if (!safe) return undefined;
    if (safe.kind === 'library') {
      const existingLibrary = libraryContents.get(safe.absolute);
      if (existingLibrary !== undefined) return existingLibrary;
      const text = defaultHost.readFile(safe.absolute);
      if (text !== undefined) libraryContents.set(safe.absolute, text);
      return text;
    }
    if (safe.kind === 'package-metadata') {
      const existingMetadata = metadataContents.get(safe.absolute);
      if (existingMetadata) return existingMetadata.text;
      const relative = relativeWithin(workspaceRoot, safe.absolute);
      if (!relative) throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
      const text = fileSystem.readFile(safe.absolute);
      const size = Buffer.byteLength(text);
      if (size > limits.maxFileBytes) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_BYTES_LIMIT', { sourceUri: relative });
      }
      metadataContents.set(safe.absolute, { relative, text });
      totalSourceBytes += size;
      largestFileBytes = Math.max(largestFileBytes, size);
      if (workspaceContents.size + metadataContents.size > limits.maxFiles) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
      }
      if (totalSourceBytes > limits.maxTotalSourceBytes) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_TOTAL_BYTES_LIMIT');
      }
      checkInterruption(options.cancellationSignal, deadline);
      return text;
    }
    const existing = workspaceContents.get(safe.absolute);
    if (existing) {
      validateReferences(existing.text, existing.relative);
      return existing.text;
    }
    const relative = relativeWithin(workspaceRoot, safe.absolute);
    if (!relative || !SOURCE_EXTENSIONS.some((extension) => relative.endsWith(extension))) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_EXTENSION_UNSUPPORTED');
    }
    const text = fileSystem.readFile(safe.absolute);
    const size = Buffer.byteLength(text);
    if (size > limits.maxFileBytes) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_BYTES_LIMIT', { sourceUri: relative });
    }
    workspaceContents.set(safe.absolute, { relative, text, size });
    totalSourceBytes += size;
    largestFileBytes = Math.max(largestFileBytes, size);
    if (workspaceContents.size > limits.maxFiles) throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
    if (totalSourceBytes > limits.maxTotalSourceBytes) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_TOTAL_BYTES_LIMIT');
    }
    validateReferences(text, relative);
    return text;
  };
  const host: ts.CompilerHost = {
    ...defaultHost,
    fileExists: (candidate) => safeExistingPath(candidate) !== undefined,
    readFile: readProgramFile,
    getSourceFile: (candidate, languageVersion) => {
      checkInterruption(options.cancellationSignal, deadline);
      const text = readProgramFile(candidate);
      return text === undefined ? undefined : ts.createSourceFile(candidate, text, languageVersion, true);
    },
    realpath: (candidate) => safeExistingPath(candidate)?.absolute ?? candidate,
    directoryExists: (candidate) => {
      try {
        const absolute = fileSystem.realpath(candidate);
        return absolute === workspaceRoot || relativeWithin(workspaceRoot, absolute) !== undefined
          || absolute === defaultLibraryRoot;
      } catch { return false; }
    },
    getDirectories: (candidate) => (defaultHost.getDirectories?.(candidate) ?? []).filter((directory) => {
      try {
        const absolute = fileSystem.realpath(path.isAbsolute(directory) ? directory : path.join(candidate, directory));
        return absolute === workspaceRoot || relativeWithin(workspaceRoot, absolute) !== undefined
          || absolute === defaultLibraryRoot;
      } catch { return false; }
    }),
  };
  let program: ts.Program;
  try {
    program = ts.createProgram({
      rootNames,
      options: compilerOptions,
      host,
      oldProgram: options.cache?.latest(identity)?.program,
    });
  } catch (error) {
    if (error instanceof TypeScriptProjectLoadError) throw error;
    throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
  }
  if (boundaryViolation) throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
  checkInterruption(options.cancellationSignal, deadline);

  const sourceFiles = program.getSourceFiles().filter(({ fileName }) => {
    try { return relativeWithin(workspaceRoot, fileSystem.realpath(fileName)) !== undefined; } catch { return false; }
  }).sort((left, right) => left.fileName.localeCompare(right.fileName));
  let astNodes = 0;
  let maxDepth = 0;
  for (const sourceFile of sourceFiles) {
    const stack: Array<readonly [ts.Node, number]> = [[sourceFile, 1]];
    while (stack.length > 0) {
      checkInterruption(options.cancellationSignal, deadline);
      const current = stack.pop();
      if (!current) break;
      const [node, depth] = current;
      astNodes += 1;
      maxDepth = Math.max(maxDepth, depth);
      if (astNodes > limits.maxAstNodes) throw new TypeScriptProjectLoadError('TS_PROJECT_AST_NODE_LIMIT');
      if (depth > limits.maxAnalysisDepth) throw new TypeScriptProjectLoadError('TS_PROJECT_DEPTH_LIMIT');
      node.forEachChild((child) => { stack.push([child, depth + 1]); });
    }
  }

  const diagnostics: TypeScriptProjectDiagnostic[] = [];
  if (configState.hasReferences) diagnostics.push(diagnostic('TS_PROJECT_REFERENCES_PARTIAL'));
  const compilerDiagnostics = ts.getPreEmitDiagnostics(program);
  checkInterruption(options.cancellationSignal, deadline);
  for (const value of compilerDiagnostics) {
    checkInterruption(options.cancellationSignal, deadline);
    diagnostics.push(safeTypeScriptDiagnostic(value, workspaceRoot));
    if (diagnostics.length > limits.maxDiagnostics) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_DIAGNOSTIC_LIMIT');
    }
  }
  const sources = [
    ...[...workspaceContents.values()].map(({ relative, text }) => ({ relative, text })),
    ...[...libraryContents].map(([absolute, text]) => ({ relative: `typescript-lib:${path.basename(absolute)}`, text })),
    ...[...metadataContents.values()].map(({ relative, text }) => ({ relative, text })),
  ];
  const key = contentKey(configState.digests, compilerOptions, sources);
  checkInterruption(options.cancellationSignal, deadline);
  const cached = options.cache?.read(identity, key);
  if (cached?.value) {
    return {
      ...cached.value,
      metrics: Object.freeze({
        ...cached.value.metrics,
        cacheHits: 1,
        cacheMisses: 0,
        cacheInvalidations: 0,
      }),
    };
  }
  const loaded: LoadedTypeScriptProject = {
    program,
    sourceFiles: Object.freeze([...sourceFiles]),
    compilerOptions: Object.freeze({ ...compilerOptions }),
    pathAliases: Object.freeze(Object.fromEntries(Object.entries(compilerOptions.paths ?? {}).map(([name, values]) => (
      [name, Object.freeze([...(values ?? [])])]
    )))),
    projectReferences: configState.hasReferences ? 'partial' : 'supported',
    diagnostics: Object.freeze(diagnostics.map((value) => Object.freeze(value))),
    metrics: Object.freeze({
      files: sourceFiles.length,
      totalSourceBytes,
      largestFileBytes,
      astNodes,
      maxDepth,
      operations: 0,
      cacheHits: 0,
      cacheMisses: 1,
      cacheInvalidations: cached?.invalidated ?? 0,
    }),
  };
  options.cache?.write(identity, key, loaded);
  return loaded;
}

export async function loadTypeScriptProject(
  options: LoadTypeScriptProjectOptions,
): Promise<LoadedTypeScriptProject> {
  try {
    return await loadTypeScriptProjectInternal(options);
  } catch (error) {
    if (error instanceof TypeScriptProjectLoadError) throw error;
    throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
  }
}
