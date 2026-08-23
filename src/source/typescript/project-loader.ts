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
  readFileBounded(filePath: string, maxBytes: number): string;
  stat(filePath: string): fs.Stats;
  exists(filePath: string): boolean;
  readDirectory(
    rootDir: string,
    extensions: readonly string[],
    excludes: readonly string[] | undefined,
    includes: readonly string[],
    depth?: number,
    maxEntries?: number,
    checkInterruption?: () => void,
    boundaryRoot?: string,
  ): string[];
  getDirectories(
    rootDir: string,
    maxEntries?: number,
    checkInterruption?: () => void,
    boundaryRoot?: string,
  ): string[];
}

type TypeScriptMatchFiles = (
  rootDir: string,
  extensions: readonly string[],
  excludes: readonly string[] | undefined,
  includes: readonly string[],
  useCaseSensitiveFileNames: boolean,
  currentDirectory: string,
  depth: number | undefined,
  getFileSystemEntries: (directory: string) => { files: string[]; directories: string[] },
  realpath: (candidate: string) => string,
) => string[];

const matchFiles = (ts as typeof ts & { matchFiles: TypeScriptMatchFiles }).matchFiles;

export const nodeTypeScriptProjectFileSystem: TypeScriptProjectFileSystem = Object.freeze({
  realpath: fs.realpathSync,
  readFile: (filePath: string) => fs.readFileSync(filePath, 'utf8'),
  readFileBounded: (filePath: string, maxBytes: number) => {
    let descriptor: number | undefined;
    try {
      descriptor = fs.openSync(
        filePath,
        fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
      );
      const opened = fs.fstatSync(descriptor);
      const currentPath = fs.realpathSync(filePath);
      const current = fs.statSync(filePath);
      if (currentPath !== filePath || opened.dev !== current.dev || opened.ino !== current.ino) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
      }
      if (!opened.isFile()) throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
      if (opened.size > maxBytes) throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_BYTES_LIMIT');
      const chunks: Buffer[] = [];
      const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, maxBytes + 1));
      let total = 0;
      for (;;) {
        const bytesRead = fs.readSync(descriptor, chunk, 0, chunk.length, null);
        if (bytesRead === 0) break;
        total += bytesRead;
        if (total > maxBytes) throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_BYTES_LIMIT');
        chunks.push(Buffer.from(chunk.subarray(0, bytesRead)));
      }
      return Buffer.concat(chunks, total).toString('utf8');
    } catch (error) {
      if (error instanceof TypeScriptProjectLoadError) throw error;
      if ((error as NodeJS.ErrnoException).code === 'ELOOP') {
        throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
      }
      throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
    }
  },
  stat: fs.statSync,
  exists: fs.existsSync,
  readDirectory: (
    rootDir: string,
    extensions: readonly string[],
    excludes: readonly string[] | undefined,
    includes: readonly string[],
    depth?: number,
    maxEntries = Number.POSITIVE_INFINITY,
    check = () => {},
    boundaryRoot?: string,
  ) => {
    let entriesEnumerated = 0;
    const matchesExtension = (name: string): boolean => extensions.some((extension) => (
      ts.sys.useCaseSensitiveFileNames
        ? name.endsWith(extension)
        : name.toLowerCase().endsWith(extension.toLowerCase())
    ));
    try {
      return matchFiles(
        rootDir,
        extensions,
        excludes,
        includes,
        ts.sys.useCaseSensitiveFileNames,
        process.cwd(),
        depth,
        (directory) => {
          const files: string[] = [];
          const directories: string[] = [];
          let handle: fs.Dir | undefined;
          try {
            handle = fs.opendirSync(directory || '.');
            for (let entry = handle.readSync(); entry; entry = handle.readSync()) {
              check();
              entriesEnumerated += 1;
              if (entriesEnumerated > maxEntries) throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
              let stat: fs.Dirent | fs.Stats = entry;
              if (entry.isSymbolicLink()) {
                try { stat = fs.statSync(path.join(directory, entry.name)); } catch {
                  throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
                }
              }
              if (stat.isFile()) {
                if (matchesExtension(entry.name)) files.push(entry.name);
              } else if (stat.isDirectory()) {
                if (boundaryRoot) {
                  const realDirectory = fs.realpathSync(path.join(directory, entry.name));
                  if (realDirectory !== boundaryRoot && !relativeWithin(boundaryRoot, realDirectory)) {
                    throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
                  }
                }
                directories.push(entry.name);
              }
            }
          } catch (error) {
            if (error instanceof TypeScriptProjectLoadError) throw error;
            throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
          } finally {
            handle?.closeSync();
          }
          return { files, directories };
        },
        fs.realpathSync,
      );
    } catch (error) {
      if (error instanceof TypeScriptProjectLoadError) throw error;
      throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
    }
  },
  getDirectories: (
    rootDir: string,
    maxEntries = Number.POSITIVE_INFINITY,
    check = () => {},
    boundaryRoot?: string,
  ) => {
    const directories: string[] = [];
    let handle: fs.Dir | undefined;
    try {
      handle = fs.opendirSync(rootDir);
      let entriesEnumerated = 0;
      for (let entry = handle.readSync(); entry; entry = handle.readSync()) {
        check();
        entriesEnumerated += 1;
        if (entriesEnumerated > maxEntries) throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
        let stat: fs.Dirent | fs.Stats = entry;
        if (entry.isSymbolicLink()) stat = fs.statSync(path.join(rootDir, entry.name));
        if (!stat.isDirectory()) continue;
        if (boundaryRoot) {
          const realDirectory = fs.realpathSync(path.join(rootDir, entry.name));
          if (realDirectory !== boundaryRoot && !relativeWithin(boundaryRoot, realDirectory)) {
            throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
          }
        }
        directories.push(entry.name);
      }
      return directories;
    } catch (error) {
      if (error instanceof TypeScriptProjectLoadError) throw error;
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
    } finally {
      handle?.closeSync();
    }
  },
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

function isMissingPathError(error: unknown): boolean {
  return ['ENOENT', 'ENOTDIR'].includes((error as NodeJS.ErrnoException).code ?? '');
}

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

async function yieldAndCheckInterruption(signal: AbortSignal | undefined, deadline: number): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve));
  checkInterruption(signal, deadline);
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
): { absolute: string; relative: string; stat: fs.Stats } {
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
  return { absolute, relative, stat };
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
  const resolvedPattern = path.resolve(configDirectory, configuredPath);
  if (!relativeWithin(workspaceRoot, resolvedPattern) && resolvedPattern !== workspaceRoot) {
    throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
  }
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
  readonly contents: Map<string, string>;
  totalBytes: number;
  largestFileBytes: number;
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
    try {
      if (fileSystem.stat(candidate).isFile()) return candidate;
    } catch (error) {
      if (!isMissingPathError(error)) throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
    }
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
): void {
  checkInterruption(signal, deadline);
  if (depth > limits.maxAnalysisDepth) throw new TypeScriptProjectLoadError('TS_PROJECT_DEPTH_LIMIT');
  const resolved = realFileWithin(fileSystem, workspaceRoot, configPath, 'TS_PROJECT_CONFIG_MISSING');
  if (visiting.has(resolved.absolute)) throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
  if (state.digests.has(resolved.relative)) return;
  if (resolved.stat.size > limits.maxFileBytes) {
    throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_BYTES_LIMIT', { sourceUri: resolved.relative });
  }
  if (!state.digests.has(resolved.relative) && state.digests.size + 1 > limits.maxFiles) {
    throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
  }
  if (state.totalBytes + resolved.stat.size > limits.maxTotalSourceBytes) {
    throw new TypeScriptProjectLoadError('TS_PROJECT_TOTAL_BYTES_LIMIT');
  }
  const text = fileSystem.readFileBounded(resolved.absolute, limits.maxFileBytes);
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
  state.contents.set(resolved.absolute, text);
  state.totalBytes += bytes;
  state.largestFileBytes = Math.max(state.largestFileBytes, bytes);
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
      }
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
}

function createParseHost(
  fileSystem: TypeScriptProjectFileSystem,
  workspaceRoot: string,
  limits: Readonly<SourceAnalysisLimits>,
  signal: AbortSignal | undefined,
  deadline: number,
  maxEnumerationEntries: number,
  validatedConfigs: ReadonlyMap<string, string>,
): ts.ParseConfigHost {
  const safeRealPath = (candidate: string): string | undefined => {
    let absolute: string;
    try {
      absolute = fileSystem.realpath(candidate);
    } catch (error) {
      if (isMissingPathError(error)) return undefined;
      throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
    }
    if (!relativeWithin(workspaceRoot, absolute)) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
    }
    return absolute;
  };
  return {
    useCaseSensitiveFileNames: ts.sys.useCaseSensitiveFileNames,
    fileExists: (candidate) => {
      const safe = safeRealPath(candidate);
      return safe !== undefined && validatedConfigs.has(safe);
    },
    readFile: (candidate) => {
      const safe = safeRealPath(candidate);
      return safe ? validatedConfigs.get(safe) : undefined;
    },
    readDirectory: (rootDir, extensions, excludes, includes, depth) => {
      checkInterruption(signal, deadline);
      if (!relativeWithin(workspaceRoot, path.resolve(rootDir)) && path.resolve(rootDir) !== workspaceRoot) return [];
      const files = fileSystem.readDirectory(
        rootDir,
        extensions,
        excludes,
        includes,
        depth,
        maxEnumerationEntries,
        () => checkInterruption(signal, deadline),
        workspaceRoot,
      );
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
  const configState: ConfigState = {
    digests: new Map(), contents: new Map(), totalBytes: 0, largestFileBytes: 0,
  };
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

  const read = ts.readConfigFile(resolvedConfig.absolute, (candidate) => {
    try { return configState.contents.get(fileSystem.realpath(candidate)); } catch { return undefined; }
  });
  if (read.error) {
    throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG', {
      sourceUri: resolvedConfig.relative,
      typescriptCode: read.error.code,
    });
  }
  const parsed = ts.parseJsonConfigFileContent(
    read.config,
    createParseHost(
      fileSystem,
      workspaceRoot,
      limits,
      options.cancellationSignal,
      deadline,
      limits.maxFiles,
      configState.contents,
    ),
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
  await yieldAndCheckInterruption(options.cancellationSignal, deadline);
  const pathsBase = parsed.options.baseUrl
    ?? (parsed.options as ts.CompilerOptions & { pathsBasePath?: string }).pathsBasePath
    ?? path.dirname(resolvedConfig.absolute);
  for (const values of Object.values(parsed.options.paths ?? {})) {
    for (const value of values) safeConfigPath(fileSystem, workspaceRoot, pathsBase, value);
  }
  for (const reference of parsed.projectReferences ?? []) {
    const absolute = path.resolve(reference.path);
    if (absolute !== workspaceRoot && !relativeWithin(workspaceRoot, absolute)) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
    }
    if (fileSystem.exists(absolute)) {
      let realPath: string;
      try { realPath = fileSystem.realpath(absolute); } catch {
        throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
      }
      if (realPath !== workspaceRoot && !relativeWithin(workspaceRoot, realPath)) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
      }
    }
  }
  checkInterruption(options.cancellationSignal, deadline);

  const rootNames: string[] = [];
  const rootContents = new Map<string, { relative: string; text: string; size: number }>();
  let totalSourceBytes = configState.totalBytes;
  let largestFileBytes = configState.largestFileBytes;
  for (const fileName of parsed.fileNames) {
    checkInterruption(options.cancellationSignal, deadline);
    const resolved = realFileWithin(fileSystem, workspaceRoot, fileName, 'TS_PROJECT_CONFIG_MISSING');
    if (!SOURCE_EXTENSIONS.some((extension) => resolved.relative.endsWith(extension))) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_EXTENSION_UNSUPPORTED', { sourceUri: resolved.relative });
    }
    if (rootContents.has(resolved.absolute)) continue;
    if (resolved.stat.size > limits.maxFileBytes) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_BYTES_LIMIT', { sourceUri: resolved.relative });
    }
    if (configState.digests.size + rootNames.length + 1 > limits.maxFiles) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
    }
    if (totalSourceBytes + resolved.stat.size > limits.maxTotalSourceBytes) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_TOTAL_BYTES_LIMIT');
    }
    const text = fileSystem.readFileBounded(resolved.absolute, limits.maxFileBytes);
    const size = Buffer.byteLength(text);
    if (size > limits.maxFileBytes) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_BYTES_LIMIT', { sourceUri: resolved.relative });
    }
    rootContents.set(resolved.absolute, { relative: resolved.relative, text, size });
    rootNames.push(resolved.absolute);
    totalSourceBytes += size;
    largestFileBytes = Math.max(largestFileBytes, size);
    if (configState.digests.size + rootNames.length > limits.maxFiles) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
    }
    if (totalSourceBytes > limits.maxTotalSourceBytes) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_TOTAL_BYTES_LIMIT');
    }
    if (rootNames.length % 64 === 0) {
      await yieldAndCheckInterruption(options.cancellationSignal, deadline);
    }
  }
  await yieldAndCheckInterruption(options.cancellationSignal, deadline);

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
  let directoryEntriesEnumerated = 0;
  const preflightProgramRead = (absolute: string, sourceUri?: string): void => {
    let stat: fs.Stats;
    try { stat = fileSystem.stat(absolute); } catch {
      throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
    }
    if (!stat.isFile()) throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
    const size = stat.size;
    if (size > limits.maxFileBytes) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_BYTES_LIMIT', sourceUri ? { sourceUri } : {});
    }
    if (configState.digests.size + workspaceContents.size + metadataContents.size + libraryContents.size + 1
      > limits.maxFiles) throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
    if (totalSourceBytes + size > limits.maxTotalSourceBytes) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_TOTAL_BYTES_LIMIT');
    }
  };
  const validateReferences = (text: string, relative: string): void => {
    const preprocessed = ts.preProcessFile(text, true, true);
    const references = [...preprocessed.referencedFiles, ...preprocessed.importedFiles];
    const sourceDirectory = path.dirname(path.resolve(workspaceRoot, relative));
    if (preprocessed.referencedFiles.some(({ fileName }) => (
      path.isAbsolute(fileName.replaceAll('\\', '/')) || /^[a-z][a-z0-9+.-]*:/iu.test(fileName)
    )) || preprocessed.importedFiles.some(({ fileName }) => (
      path.isAbsolute(fileName.replaceAll('\\', '/')) || /^[a-z]:[\\/]/iu.test(fileName)
    ))) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT', { sourceUri: relative });
    }
    if (references.some(({ fileName }) => {
      const normalized = fileName.replaceAll('\\', '/');
      if (!normalized.startsWith('.')) return false;
      const candidate = path.resolve(sourceDirectory, normalized);
      return candidate !== workspaceRoot && relativeWithin(workspaceRoot, candidate) === undefined;
    })) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT', { sourceUri: relative });
    }
    checkInterruption(options.cancellationSignal, deadline);
  };
  const safeExistingPath = (candidate: string): {
    absolute: string;
    kind: 'workspace' | 'library' | 'package-metadata' | 'unsupported';
  } | undefined => {
    try {
      const absolute = fileSystem.realpath(candidate);
      if (isStandardLibrary(absolute)) return { absolute, kind: 'library' };
      const workspaceRelative = relativeWithin(workspaceRoot, absolute);
      if (!workspaceRelative) {
        if (SOURCE_EXTENSIONS.some((extension) => absolute.endsWith(extension))
          || /\.(?:[cm]?js|jsx|json)$/iu.test(absolute)) boundaryViolation = true;
        return undefined;
      }
      if (workspaceRelative && SOURCE_EXTENSIONS.some((extension) => workspaceRelative.endsWith(extension))) {
        return { absolute, kind: 'workspace' };
      }
      if (workspaceRelative && path.basename(workspaceRelative) === 'package.json') {
        return { absolute, kind: 'package-metadata' };
      }
      if (workspaceRelative && /\.(?:[cm]?js|jsx|json)$/iu.test(workspaceRelative)) {
        return { absolute, kind: 'unsupported' };
      }
      return undefined;
    } catch (error) {
      if (error instanceof TypeScriptProjectLoadError) throw error;
      if (isMissingPathError(error)) return undefined;
      throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
    }
  };
  const resolvedProgramPaths = new Set(rootNames.map((candidate) => path.resolve(candidate)));
  const resolveProgramPath = (candidate: string): ReturnType<typeof safeExistingPath> => {
    const lexical = path.resolve(candidate);
    const safe = safeExistingPath(candidate);
    if (safe) {
      resolvedProgramPaths.add(lexical);
      resolvedProgramPaths.add(path.resolve(safe.absolute));
      return safe;
    }
    if (resolvedProgramPaths.has(lexical)) throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
    return undefined;
  };
  const readProgramFile = (candidate: string): string | undefined => {
    const safe = resolveProgramPath(candidate);
    if (!safe) return undefined;
    if (safe.kind === 'unsupported') return undefined;
    if (safe.kind === 'library') {
      const existingLibrary = libraryContents.get(safe.absolute);
      if (existingLibrary !== undefined) return existingLibrary;
      preflightProgramRead(safe.absolute);
      const text = defaultHost.readFile(safe.absolute);
      if (text !== undefined) {
        const size = Buffer.byteLength(text);
        if (size > limits.maxFileBytes) throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_BYTES_LIMIT');
        libraryContents.set(safe.absolute, text);
        totalSourceBytes += size;
        largestFileBytes = Math.max(largestFileBytes, size);
        if (configState.digests.size + workspaceContents.size + metadataContents.size + libraryContents.size
          > limits.maxFiles) throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
        if (totalSourceBytes > limits.maxTotalSourceBytes) {
          throw new TypeScriptProjectLoadError('TS_PROJECT_TOTAL_BYTES_LIMIT');
        }
        checkInterruption(options.cancellationSignal, deadline);
      }
      return text;
    }
    if (safe.kind === 'package-metadata') {
      const existingMetadata = metadataContents.get(safe.absolute);
      if (existingMetadata) return existingMetadata.text;
      const relative = relativeWithin(workspaceRoot, safe.absolute);
      if (!relative) throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
      preflightProgramRead(safe.absolute, relative);
      const text = fileSystem.readFileBounded(safe.absolute, limits.maxFileBytes);
      const size = Buffer.byteLength(text);
      if (size > limits.maxFileBytes) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_BYTES_LIMIT', { sourceUri: relative });
      }
      metadataContents.set(safe.absolute, { relative, text });
      totalSourceBytes += size;
      largestFileBytes = Math.max(largestFileBytes, size);
      if (configState.digests.size + workspaceContents.size + metadataContents.size + libraryContents.size
        > limits.maxFiles) {
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
    preflightProgramRead(safe.absolute, relative);
    const text = fileSystem.readFileBounded(safe.absolute, limits.maxFileBytes);
    const size = Buffer.byteLength(text);
    if (size > limits.maxFileBytes) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_BYTES_LIMIT', { sourceUri: relative });
    }
    workspaceContents.set(safe.absolute, { relative, text, size });
    totalSourceBytes += size;
    largestFileBytes = Math.max(largestFileBytes, size);
    if (configState.digests.size + workspaceContents.size + metadataContents.size + libraryContents.size
      > limits.maxFiles) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
    }
    if (totalSourceBytes > limits.maxTotalSourceBytes) {
      throw new TypeScriptProjectLoadError('TS_PROJECT_TOTAL_BYTES_LIMIT');
    }
    validateReferences(text, relative);
    return text;
  };
  let astNodes = 0;
  let maxDepth = 0;
  const accountedSourceFiles = new WeakSet<ts.SourceFile>();
  const accountSourceFile = (sourceFile: ts.SourceFile): void => {
    if (accountedSourceFiles.has(sourceFile)) return;
    accountedSourceFiles.add(sourceFile);
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
  };
  const host: ts.CompilerHost = {
    ...defaultHost,
    fileExists: (candidate) => resolveProgramPath(candidate) !== undefined,
    readFile: readProgramFile,
    getSourceFile: (candidate, languageVersion) => {
      checkInterruption(options.cancellationSignal, deadline);
      const kind = resolveProgramPath(candidate)?.kind;
      if (kind === 'unsupported' || kind === 'package-metadata') {
        throw new TypeScriptProjectLoadError('TS_PROJECT_EXTENSION_UNSUPPORTED');
      }
      const text = readProgramFile(candidate);
      if (text === undefined) return undefined;
      const sourceFile = ts.createSourceFile(candidate, text, languageVersion, true);
      if (kind === 'workspace' || kind === 'library') accountSourceFile(sourceFile);
      return sourceFile;
    },
    realpath: (candidate) => resolveProgramPath(candidate)?.absolute ?? candidate,
    directoryExists: (candidate) => {
      try {
        const lexical = path.resolve(candidate);
        const absolute = fileSystem.realpath(candidate);
        if ((lexical === workspaceRoot || relativeWithin(workspaceRoot, lexical) !== undefined)
          && absolute !== workspaceRoot && relativeWithin(workspaceRoot, absolute) === undefined) {
          boundaryViolation = true;
          return false;
        }
        return absolute === workspaceRoot || relativeWithin(workspaceRoot, absolute) !== undefined
          || absolute === defaultLibraryRoot;
      } catch (error) {
        if (isMissingPathError(error)) return false;
        throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
      }
    },
    getDirectories: (candidate) => {
      try {
        const lexical = path.resolve(candidate);
        const absolute = fileSystem.realpath(candidate);
        const boundaryRoot = absolute === defaultLibraryRoot ? defaultLibraryRoot : workspaceRoot;
        if (absolute !== defaultLibraryRoot && absolute !== workspaceRoot
          && relativeWithin(workspaceRoot, absolute) === undefined) {
          if (lexical === workspaceRoot || relativeWithin(workspaceRoot, lexical) !== undefined) {
            throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
          }
          return [];
        }
        const filesConsumed = configState.digests.size + workspaceContents.size
          + metadataContents.size + libraryContents.size;
        const remainingEntries = limits.maxFiles - filesConsumed - directoryEntriesEnumerated;
        if (remainingEntries <= 0) throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
        return fileSystem.getDirectories(
          absolute,
          remainingEntries,
          () => {
            directoryEntriesEnumerated += 1;
            checkInterruption(options.cancellationSignal, deadline);
          },
          boundaryRoot,
        );
      } catch (error) {
        if (error instanceof TypeScriptProjectLoadError) throw error;
        if (isMissingPathError(error)) return [];
        throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
      }
    },
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
  await yieldAndCheckInterruption(options.cancellationSignal, deadline);

  const sourceFiles = program.getSourceFiles()
    .filter(({ fileName }) => resolveProgramPath(fileName)?.kind === 'workspace')
    .sort((left, right) => left.fileName.localeCompare(right.fileName));
  if (boundaryViolation) throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
  for (const sourceFile of sourceFiles) accountSourceFile(sourceFile);

  const diagnostics: TypeScriptProjectDiagnostic[] = [];
  if ((parsed.projectReferences?.length ?? 0) > 0) diagnostics.push(diagnostic('TS_PROJECT_REFERENCES_PARTIAL'));
  for (const sourceFile of sourceFiles) {
    const syntaxDiagnostics = (sourceFile as ts.SourceFile & {
      parseDiagnostics?: readonly ts.Diagnostic[];
    }).parseDiagnostics ?? [];
    for (const value of syntaxDiagnostics) {
      checkInterruption(options.cancellationSignal, deadline);
      diagnostics.push(safeTypeScriptDiagnostic(value, workspaceRoot));
      if (diagnostics.length > limits.maxDiagnostics) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_DIAGNOSTIC_LIMIT');
      }
      if (diagnostics.length % 64 === 0) {
        await yieldAndCheckInterruption(options.cancellationSignal, deadline);
      }
    }
  }
  if (diagnostics.length > limits.maxDiagnostics) {
    throw new TypeScriptProjectLoadError('TS_PROJECT_DIAGNOSTIC_LIMIT');
  }
  const sources = [
    ...[...workspaceContents.values()].map(({ relative, text }) => ({ relative, text })),
    ...[...libraryContents].map(([absolute, text]) => ({ relative: `typescript-lib:${path.basename(absolute)}`, text })),
    ...[...metadataContents.values()].map(({ relative, text }) => ({ relative, text })),
  ];
  const key = contentKey(configState.digests, compilerOptions, sources);
  await yieldAndCheckInterruption(options.cancellationSignal, deadline);
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
    projectReferences: (parsed.projectReferences?.length ?? 0) > 0 ? 'partial' : 'supported',
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
