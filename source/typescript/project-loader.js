"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TypeScriptAnalysisCache = exports.TypeScriptProjectLoadError = exports.nodeTypeScriptProjectFileSystem = exports.TYPESCRIPT_PROJECT_DIAGNOSTIC_CODES = exports.TYPESCRIPT_PROJECT_LOADER_VERSION = void 0;
exports.loadTypeScriptProject = loadTypeScriptProject;
const node_crypto_1 = __importDefault(require("node:crypto"));
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const typescript_1 = __importDefault(require("typescript"));
const source_analysis_1 = require("../../source-analysis");
exports.TYPESCRIPT_PROJECT_LOADER_VERSION = '1.0.0';
exports.TYPESCRIPT_PROJECT_DIAGNOSTIC_CODES = [
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
];
const matchFiles = typescript_1.default.matchFiles;
exports.nodeTypeScriptProjectFileSystem = Object.freeze({
    realpath: node_fs_1.default.realpathSync,
    readFile: (filePath) => node_fs_1.default.readFileSync(filePath, 'utf8'),
    readFileBounded: (filePath, maxBytes) => {
        let descriptor;
        try {
            descriptor = node_fs_1.default.openSync(filePath, node_fs_1.default.constants.O_RDONLY | node_fs_1.default.constants.O_NOFOLLOW | node_fs_1.default.constants.O_NONBLOCK);
            const opened = node_fs_1.default.fstatSync(descriptor);
            const currentPath = node_fs_1.default.realpathSync(filePath);
            const current = node_fs_1.default.statSync(filePath);
            if (currentPath !== filePath || opened.dev !== current.dev || opened.ino !== current.ino) {
                throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
            }
            if (!opened.isFile())
                throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
            if (opened.size > maxBytes)
                throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_BYTES_LIMIT');
            const chunks = [];
            const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, maxBytes + 1));
            let total = 0;
            for (;;) {
                const bytesRead = node_fs_1.default.readSync(descriptor, chunk, 0, chunk.length, null);
                if (bytesRead === 0)
                    break;
                total += bytesRead;
                if (total > maxBytes)
                    throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_BYTES_LIMIT');
                chunks.push(Buffer.from(chunk.subarray(0, bytesRead)));
            }
            return Buffer.concat(chunks, total).toString('utf8');
        }
        catch (error) {
            if (error instanceof TypeScriptProjectLoadError)
                throw error;
            if (error.code === 'ELOOP') {
                throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
            }
            throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
        }
        finally {
            if (descriptor !== undefined)
                node_fs_1.default.closeSync(descriptor);
        }
    },
    stat: node_fs_1.default.statSync,
    exists: node_fs_1.default.existsSync,
    readDirectory: (rootDir, extensions, excludes, includes, depth, maxEntries = Number.POSITIVE_INFINITY, check = () => { }, boundaryRoot) => {
        let entriesEnumerated = 0;
        const matchesExtension = (name) => extensions.some((extension) => (typescript_1.default.sys.useCaseSensitiveFileNames
            ? name.endsWith(extension)
            : name.toLowerCase().endsWith(extension.toLowerCase())));
        try {
            return matchFiles(rootDir, extensions, excludes, includes, typescript_1.default.sys.useCaseSensitiveFileNames, process.cwd(), depth, (directory) => {
                const files = [];
                const directories = [];
                let handle;
                try {
                    handle = node_fs_1.default.opendirSync(directory || '.');
                    for (let entry = handle.readSync(); entry; entry = handle.readSync()) {
                        check();
                        entriesEnumerated += 1;
                        if (entriesEnumerated > maxEntries)
                            throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
                        let stat = entry;
                        if (entry.isSymbolicLink()) {
                            try {
                                stat = node_fs_1.default.statSync(node_path_1.default.join(directory, entry.name));
                            }
                            catch {
                                throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
                            }
                        }
                        if (stat.isFile()) {
                            if (matchesExtension(entry.name))
                                files.push(entry.name);
                        }
                        else if (stat.isDirectory()) {
                            if (boundaryRoot) {
                                const realDirectory = node_fs_1.default.realpathSync(node_path_1.default.join(directory, entry.name));
                                if (realDirectory !== boundaryRoot && !relativeWithin(boundaryRoot, realDirectory)) {
                                    throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
                                }
                            }
                            directories.push(entry.name);
                        }
                    }
                }
                catch (error) {
                    if (error instanceof TypeScriptProjectLoadError)
                        throw error;
                    throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
                }
                finally {
                    handle?.closeSync();
                }
                return { files, directories };
            }, node_fs_1.default.realpathSync);
        }
        catch (error) {
            if (error instanceof TypeScriptProjectLoadError)
                throw error;
            throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
        }
    },
    getDirectories: (rootDir, maxEntries = Number.POSITIVE_INFINITY, check = () => { }, boundaryRoot) => {
        const directories = [];
        let handle;
        try {
            handle = node_fs_1.default.opendirSync(rootDir);
            let entriesEnumerated = 0;
            for (let entry = handle.readSync(); entry; entry = handle.readSync()) {
                check();
                entriesEnumerated += 1;
                if (entriesEnumerated > maxEntries)
                    throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
                let stat = entry;
                if (entry.isSymbolicLink())
                    stat = node_fs_1.default.statSync(node_path_1.default.join(rootDir, entry.name));
                if (!stat.isDirectory())
                    continue;
                if (boundaryRoot) {
                    const realDirectory = node_fs_1.default.realpathSync(node_path_1.default.join(rootDir, entry.name));
                    if (realDirectory !== boundaryRoot && !relativeWithin(boundaryRoot, realDirectory)) {
                        throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
                    }
                }
                directories.push(entry.name);
            }
            return directories;
        }
        catch (error) {
            if (error instanceof TypeScriptProjectLoadError)
                throw error;
            if (error.code === 'ENOENT')
                return [];
            throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
        }
        finally {
            handle?.closeSync();
        }
    },
});
const SAFE_MESSAGES = Object.freeze({
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
function isMissingPathError(error) {
    return ['ENOENT', 'ENOTDIR'].includes(error.code ?? '');
}
function diagnostic(code, options = {}) {
    return { code, safeMessage: SAFE_MESSAGES[code], ...options };
}
class TypeScriptProjectLoadError extends Error {
    diagnostics;
    constructor(code, options = {}) {
        super(SAFE_MESSAGES[code]);
        this.name = 'TypeScriptProjectLoadError';
        this.diagnostics = Object.freeze([Object.freeze(diagnostic(code, options))]);
    }
}
exports.TypeScriptProjectLoadError = TypeScriptProjectLoadError;
class TypeScriptAnalysisCache {
    entries = new Map();
    currentKeys = new Map();
    read(identity, key) {
        const current = this.currentKeys.get(identity);
        return { value: this.entries.get(key), invalidated: current && current !== key ? 1 : 0 };
    }
    latest(identity) {
        const key = this.currentKeys.get(identity);
        return key ? this.entries.get(key) : undefined;
    }
    write(identity, key, value) {
        const previous = this.currentKeys.get(identity);
        if (previous && previous !== key)
            this.entries.delete(previous);
        this.currentKeys.set(identity, key);
        this.entries.set(key, value);
    }
}
exports.TypeScriptAnalysisCache = TypeScriptAnalysisCache;
function checkInterruption(signal, deadline) {
    if (signal?.aborted)
        throw new TypeScriptProjectLoadError('TS_PROJECT_CANCELLED');
    if (performance.now() >= deadline)
        throw new TypeScriptProjectLoadError('TS_PROJECT_TIMEOUT');
}
async function yieldAndCheckInterruption(signal, deadline) {
    await new Promise((resolve) => setImmediate(resolve));
    checkInterruption(signal, deadline);
}
function normalizeRelative(value) {
    return value.replaceAll('\\', '/');
}
function isPathLikeSpecifier(value) {
    const normalized = normalizeRelative(value);
    return node_path_1.default.isAbsolute(normalized) || /^[a-z]:\//iu.test(normalized)
        || normalized.split('/').some((segment) => segment === '.' || segment === '..');
}
function relativeWithin(workspaceRoot, absolutePath) {
    const relative = normalizeRelative(node_path_1.default.relative(workspaceRoot, absolutePath));
    if (!relative || relative === '..' || relative.startsWith('../') || node_path_1.default.isAbsolute(relative))
        return undefined;
    return relative;
}
function realFileWithin(fileSystem, workspaceRoot, candidate, missingCode) {
    let absolute;
    try {
        absolute = fileSystem.realpath(candidate);
    }
    catch {
        throw new TypeScriptProjectLoadError(missingCode);
    }
    const relative = relativeWithin(workspaceRoot, absolute);
    if (!relative)
        throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
    let stat;
    try {
        stat = fileSystem.stat(absolute);
    }
    catch {
        throw new TypeScriptProjectLoadError(missingCode);
    }
    if (!stat.isFile())
        throw new TypeScriptProjectLoadError(missingCode);
    return { absolute, relative, stat };
}
function safeConfigPath(fileSystem, workspaceRoot, configDirectory, configuredPath) {
    if (!configuredPath || node_path_1.default.isAbsolute(configuredPath) || /^[a-z][a-z0-9+.-]*:/iu.test(configuredPath)) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
    }
    const marker = configuredPath.search(GLOB_MARKER);
    const staticPart = marker < 0 ? configuredPath : configuredPath.slice(0, marker);
    const resolvedPattern = node_path_1.default.resolve(configDirectory, configuredPath);
    if (!relativeWithin(workspaceRoot, resolvedPattern) && resolvedPattern !== workspaceRoot) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
    }
    const candidate = node_path_1.default.resolve(configDirectory, staticPart || '.');
    if (!relativeWithin(workspaceRoot, candidate) && candidate !== workspaceRoot) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
    }
    if (fileSystem.exists(candidate)) {
        let realPath;
        try {
            realPath = fileSystem.realpath(candidate);
        }
        catch {
            throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
        }
        if (!relativeWithin(workspaceRoot, realPath) && realPath !== workspaceRoot) {
            throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
        }
    }
}
function resolveExtendsCandidate(fileSystem, configDirectory, specifier) {
    if (node_path_1.default.isAbsolute(specifier))
        throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
    if (!specifier.startsWith('.') || /^[a-z][a-z0-9+.-]*:/iu.test(specifier)) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_EXTENDS_UNSUPPORTED');
    }
    const base = node_path_1.default.resolve(configDirectory, specifier);
    for (const candidate of [base, `${base}.json`, node_path_1.default.join(base, 'tsconfig.json')]) {
        try {
            if (fileSystem.stat(candidate).isFile())
                return candidate;
        }
        catch (error) {
            if (!isMissingPathError(error))
                throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
        }
    }
    throw new TypeScriptProjectLoadError('TS_PROJECT_CONFIG_MISSING');
}
function validateConfigTree(fileSystem, workspaceRoot, configPath, limits, signal, deadline, state, visiting, depth = 1) {
    checkInterruption(signal, deadline);
    if (depth > limits.maxAnalysisDepth)
        throw new TypeScriptProjectLoadError('TS_PROJECT_DEPTH_LIMIT');
    const resolved = realFileWithin(fileSystem, workspaceRoot, configPath, 'TS_PROJECT_CONFIG_MISSING');
    if (visiting.has(resolved.absolute))
        throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
    if (state.digests.has(resolved.relative))
        return;
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
    const parsed = typescript_1.default.parseConfigFileTextToJson(resolved.absolute, text);
    if (parsed.error || !parsed.config || typeof parsed.config !== 'object' || Array.isArray(parsed.config)) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG', {
            typescriptCode: parsed.error?.code,
            sourceUri: resolved.relative,
        });
    }
    state.digests.set(resolved.relative, node_crypto_1.default.createHash('sha256').update(text).digest('hex'));
    state.contents.set(resolved.absolute, text);
    state.totalBytes += bytes;
    state.largestFileBytes = Math.max(state.largestFileBytes, bytes);
    if (state.digests.size > limits.maxFiles)
        throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
    if (state.totalBytes > limits.maxTotalSourceBytes) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_TOTAL_BYTES_LIMIT');
    }
    const config = parsed.config;
    const configDirectory = node_path_1.default.dirname(resolved.absolute);
    for (const key of ['files', 'include', 'exclude']) {
        const values = config[key];
        if (values === undefined)
            continue;
        if (!Array.isArray(values) || values.some((value) => typeof value !== 'string')) {
            throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG', { sourceUri: resolved.relative });
        }
        for (const value of values)
            safeConfigPath(fileSystem, workspaceRoot, configDirectory, value);
    }
    const compilerOptions = config.compilerOptions;
    if (compilerOptions !== undefined) {
        if (!compilerOptions || typeof compilerOptions !== 'object' || Array.isArray(compilerOptions)) {
            throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
        }
        const compiler = compilerOptions;
        for (const key of ['baseUrl', 'rootDir']) {
            const value = compiler[key];
            if (value !== undefined) {
                if (typeof value !== 'string')
                    throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
                safeConfigPath(fileSystem, workspaceRoot, configDirectory, value);
            }
        }
        for (const key of ['rootDirs', 'typeRoots']) {
            const values = compiler[key];
            if (values === undefined)
                continue;
            if (!Array.isArray(values) || values.some((value) => typeof value !== 'string')) {
                throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
            }
            for (const value of values)
                safeConfigPath(fileSystem, workspaceRoot, configDirectory, value);
        }
        if (compiler.types !== undefined) {
            if (!Array.isArray(compiler.types) || compiler.types.some((value) => typeof value !== 'string')) {
                throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
            }
            for (const value of compiler.types) {
                if (isPathLikeSpecifier(value)) {
                    safeConfigPath(fileSystem, workspaceRoot, configDirectory, normalizeRelative(value));
                }
            }
        }
        if (compiler.jsxImportSource !== undefined) {
            if (typeof compiler.jsxImportSource !== 'string') {
                throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
            }
        }
        if (compiler.paths !== undefined) {
            if (!compiler.paths || typeof compiler.paths !== 'object' || Array.isArray(compiler.paths)) {
                throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
            }
            for (const values of Object.values(compiler.paths)) {
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
            for (const specifier of values) {
                const candidate = resolveExtendsCandidate(fileSystem, configDirectory, specifier);
                validateConfigTree(fileSystem, workspaceRoot, candidate, limits, signal, deadline, state, visiting, depth + 1);
            }
        }
        finally {
            visiting.delete(resolved.absolute);
        }
    }
}
function createParseHost(fileSystem, workspaceRoot, limits, signal, deadline, maxEnumerationEntries, validatedConfigs) {
    const safeRealPath = (candidate) => {
        let absolute;
        try {
            absolute = fileSystem.realpath(candidate);
        }
        catch (error) {
            if (isMissingPathError(error))
                return undefined;
            throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
        }
        if (!relativeWithin(workspaceRoot, absolute)) {
            throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
        }
        return absolute;
    };
    return {
        useCaseSensitiveFileNames: typescript_1.default.sys.useCaseSensitiveFileNames,
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
            if (!relativeWithin(workspaceRoot, node_path_1.default.resolve(rootDir)) && node_path_1.default.resolve(rootDir) !== workspaceRoot)
                return [];
            const files = fileSystem.readDirectory(rootDir, extensions, excludes, includes, depth, maxEnumerationEntries, () => checkInterruption(signal, deadline), workspaceRoot);
            checkInterruption(signal, deadline);
            if (files.length > limits.maxFiles)
                throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
            return files.filter((candidate) => (safeRealPath(candidate) !== undefined));
        },
    };
}
function safeTypeScriptDiagnostic(value, workspaceRoot) {
    let sourceUri;
    let line;
    let column;
    if (value.file) {
        const relative = relativeWithin(workspaceRoot, node_path_1.default.resolve(value.file.fileName));
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
function projectIdentity(workspaceRoot, configRelative) {
    const workspace = node_crypto_1.default.createHash('sha256').update(workspaceRoot).digest('hex');
    return `typescript-project:${workspace}:${configRelative}`;
}
function contentKey(configDigests, compilerOptions, sources) {
    const hash = node_crypto_1.default.createHash('sha256').update(exports.TYPESCRIPT_PROJECT_LOADER_VERSION);
    hash.update(typescript_1.default.version);
    for (const [relative, digest] of [...configDigests].sort(([left], [right]) => left.localeCompare(right))) {
        hash.update(relative).update(digest);
    }
    hash.update(JSON.stringify(compilerOptions));
    for (const source of [...sources].sort((left, right) => left.relative.localeCompare(right.relative))) {
        hash.update(source.relative).update(node_crypto_1.default.createHash('sha256').update(source.text).digest());
    }
    return hash.digest('hex');
}
async function loadTypeScriptProjectInternal(options) {
    const fileSystem = options.fileSystem ?? exports.nodeTypeScriptProjectFileSystem;
    let limits;
    try {
        limits = (0, source_analysis_1.validateSourceAnalysisLimits)(options.limits);
    }
    catch {
        throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
    }
    const deadline = performance.now() + limits.timeoutMs;
    checkInterruption(options.cancellationSignal, deadline);
    if (node_path_1.default.isAbsolute(options.tsconfigPath))
        throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
    let workspaceRoot;
    try {
        workspaceRoot = fileSystem.realpath(options.workspaceRoot);
    }
    catch {
        throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
    }
    const configPath = node_path_1.default.resolve(workspaceRoot, options.tsconfigPath);
    const resolvedConfig = realFileWithin(fileSystem, workspaceRoot, configPath, 'TS_PROJECT_CONFIG_MISSING');
    const configState = {
        digests: new Map(), contents: new Map(), totalBytes: 0, largestFileBytes: 0,
    };
    validateConfigTree(fileSystem, workspaceRoot, resolvedConfig.absolute, limits, options.cancellationSignal, deadline, configState, new Set());
    const read = typescript_1.default.readConfigFile(resolvedConfig.absolute, (candidate) => {
        try {
            return configState.contents.get(fileSystem.realpath(candidate));
        }
        catch {
            return undefined;
        }
    });
    if (read.error) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG', {
            sourceUri: resolvedConfig.relative,
            typescriptCode: read.error.code,
        });
    }
    const parsed = typescript_1.default.parseJsonConfigFileContent(read.config, createParseHost(fileSystem, workspaceRoot, limits, options.cancellationSignal, deadline, limits.maxFiles, configState.contents), node_path_1.default.dirname(resolvedConfig.absolute), { noEmit: true, plugins: [] }, resolvedConfig.absolute);
    if (parsed.errors.length > 0) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG', {
            sourceUri: resolvedConfig.relative,
            typescriptCode: parsed.errors[0].code,
        });
    }
    await yieldAndCheckInterruption(options.cancellationSignal, deadline);
    const pathsBase = parsed.options.baseUrl
        ?? parsed.options.pathsBasePath
        ?? node_path_1.default.dirname(resolvedConfig.absolute);
    for (const values of Object.values(parsed.options.paths ?? {})) {
        for (const value of values)
            safeConfigPath(fileSystem, workspaceRoot, pathsBase, value);
    }
    for (const reference of parsed.projectReferences ?? []) {
        const absolute = node_path_1.default.resolve(reference.path);
        if (absolute !== workspaceRoot && !relativeWithin(workspaceRoot, absolute)) {
            throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
        }
        if (fileSystem.exists(absolute)) {
            let realPath;
            try {
                realPath = fileSystem.realpath(absolute);
            }
            catch {
                throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
            }
            if (realPath !== workspaceRoot && !relativeWithin(workspaceRoot, realPath)) {
                throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
            }
        }
    }
    checkInterruption(options.cancellationSignal, deadline);
    const rootNames = [];
    const rootContents = new Map();
    let totalSourceBytes = configState.totalBytes;
    let largestFileBytes = configState.largestFileBytes;
    for (const fileName of parsed.fileNames) {
        checkInterruption(options.cancellationSignal, deadline);
        const resolved = realFileWithin(fileSystem, workspaceRoot, fileName, 'TS_PROJECT_CONFIG_MISSING');
        if (!SOURCE_EXTENSIONS.some((extension) => resolved.relative.endsWith(extension))) {
            throw new TypeScriptProjectLoadError('TS_PROJECT_EXTENSION_UNSUPPORTED', { sourceUri: resolved.relative });
        }
        if (rootContents.has(resolved.absolute))
            continue;
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
    const compilerOptions = { ...parsed.options, noEmit: true, plugins: [] };
    const identity = projectIdentity(workspaceRoot, resolvedConfig.relative);
    const defaultHost = typescript_1.default.createCompilerHost(compilerOptions, true);
    const defaultLibraryRoot = fileSystem.realpath(node_path_1.default.dirname(typescript_1.default.getDefaultLibFilePath(compilerOptions)));
    const isStandardLibrary = (absolute) => (node_path_1.default.dirname(absolute) === defaultLibraryRoot && /^lib(?:\.[a-z0-9_-]+)*\.d\.ts$/iu.test(node_path_1.default.basename(absolute)));
    const isStandardLibraryDirectory = (absolute) => (absolute === defaultLibraryRoot || relativeWithin(absolute, defaultLibraryRoot) !== undefined);
    let boundaryViolation = false;
    const workspaceContents = new Map(rootContents);
    const libraryContents = new Map();
    const metadataContents = new Map();
    let directoryEntriesEnumerated = 0;
    const preflightProgramRead = (absolute, sourceUri) => {
        let stat;
        try {
            stat = fileSystem.stat(absolute);
        }
        catch {
            throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
        }
        if (!stat.isFile())
            throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
        const size = stat.size;
        if (size > limits.maxFileBytes) {
            throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_BYTES_LIMIT', sourceUri ? { sourceUri } : {});
        }
        if (configState.digests.size + workspaceContents.size + metadataContents.size + libraryContents.size + 1
            > limits.maxFiles)
            throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
        if (totalSourceBytes + size > limits.maxTotalSourceBytes) {
            throw new TypeScriptProjectLoadError('TS_PROJECT_TOTAL_BYTES_LIMIT');
        }
    };
    const validateReferences = (text, relative) => {
        const preprocessed = typescript_1.default.preProcessFile(text, true, true);
        const references = [
            ...preprocessed.referencedFiles,
            ...preprocessed.importedFiles,
            ...preprocessed.typeReferenceDirectives,
        ];
        const sourceDirectory = node_path_1.default.dirname(node_path_1.default.resolve(workspaceRoot, relative));
        if (preprocessed.referencedFiles.some(({ fileName }) => (node_path_1.default.isAbsolute(fileName.replaceAll('\\', '/')) || /^[a-z][a-z0-9+.-]*:/iu.test(fileName))) || preprocessed.importedFiles.some(({ fileName }) => (node_path_1.default.isAbsolute(fileName.replaceAll('\\', '/')) || /^[a-z]:[\\/]/iu.test(fileName))) || preprocessed.typeReferenceDirectives.some(({ fileName }) => (node_path_1.default.isAbsolute(fileName.replaceAll('\\', '/')) || /^[a-z]:[\\/]/iu.test(fileName)))) {
            throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT', { sourceUri: relative });
        }
        if (references.some(({ fileName }) => {
            const normalized = normalizeRelative(fileName);
            if (!isPathLikeSpecifier(normalized))
                return false;
            const candidate = node_path_1.default.resolve(sourceDirectory, normalized);
            return candidate !== workspaceRoot && relativeWithin(workspaceRoot, candidate) === undefined;
        })) {
            throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT', { sourceUri: relative });
        }
        checkInterruption(options.cancellationSignal, deadline);
    };
    const safeExistingPath = (candidate) => {
        try {
            const absolute = fileSystem.realpath(candidate);
            if (isStandardLibrary(absolute))
                return { absolute, kind: 'library' };
            const workspaceRelative = relativeWithin(workspaceRoot, absolute);
            if (!workspaceRelative) {
                if (SOURCE_EXTENSIONS.some((extension) => absolute.endsWith(extension))
                    || /\.(?:[cm]?js|jsx|json)$/iu.test(absolute))
                    boundaryViolation = true;
                return undefined;
            }
            if (workspaceRelative && SOURCE_EXTENSIONS.some((extension) => workspaceRelative.endsWith(extension))) {
                return { absolute, kind: 'workspace' };
            }
            if (workspaceRelative && node_path_1.default.basename(workspaceRelative) === 'package.json') {
                return { absolute, kind: 'package-metadata' };
            }
            if (workspaceRelative && /\.(?:[cm]?js|jsx|json)$/iu.test(workspaceRelative)) {
                return { absolute, kind: 'unsupported' };
            }
            return undefined;
        }
        catch (error) {
            if (error instanceof TypeScriptProjectLoadError)
                throw error;
            if (isMissingPathError(error))
                return undefined;
            throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
        }
    };
    const resolvedProgramPaths = new Set(rootNames.map((candidate) => node_path_1.default.resolve(candidate)));
    const isHoistedNodeModulesPath = (candidate) => {
        let current = node_path_1.default.resolve(candidate);
        while (node_path_1.default.dirname(current) !== current && node_path_1.default.basename(current) !== 'node_modules') {
            current = node_path_1.default.dirname(current);
        }
        if (node_path_1.default.basename(current) !== 'node_modules')
            return false;
        const packageRoot = node_path_1.default.dirname(current);
        return packageRoot === workspaceRoot || relativeWithin(packageRoot, workspaceRoot) !== undefined;
    };
    const resolveProgramPath = (candidate) => {
        const lexical = node_path_1.default.resolve(candidate);
        const safe = safeExistingPath(candidate);
        if (safe) {
            resolvedProgramPaths.add(lexical);
            resolvedProgramPaths.add(node_path_1.default.resolve(safe.absolute));
            return safe;
        }
        if (resolvedProgramPaths.has(lexical))
            throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
        return undefined;
    };
    const readProgramFile = (candidate) => {
        const safe = resolveProgramPath(candidate);
        if (!safe)
            return undefined;
        if (safe.kind === 'unsupported')
            return undefined;
        if (safe.kind === 'workspace' && safe.absolute.endsWith('.tsx')
            && compilerOptions.jsxImportSource && isPathLikeSpecifier(compilerOptions.jsxImportSource)) {
            safeConfigPath(fileSystem, workspaceRoot, node_path_1.default.dirname(safe.absolute), normalizeRelative(compilerOptions.jsxImportSource));
        }
        if (safe.kind === 'library') {
            const existingLibrary = libraryContents.get(safe.absolute);
            if (existingLibrary !== undefined)
                return existingLibrary;
            preflightProgramRead(safe.absolute);
            const text = defaultHost.readFile(safe.absolute);
            if (text !== undefined) {
                const size = Buffer.byteLength(text);
                if (size > limits.maxFileBytes)
                    throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_BYTES_LIMIT');
                libraryContents.set(safe.absolute, text);
                totalSourceBytes += size;
                largestFileBytes = Math.max(largestFileBytes, size);
                if (configState.digests.size + workspaceContents.size + metadataContents.size + libraryContents.size
                    > limits.maxFiles)
                    throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
                if (totalSourceBytes > limits.maxTotalSourceBytes) {
                    throw new TypeScriptProjectLoadError('TS_PROJECT_TOTAL_BYTES_LIMIT');
                }
                checkInterruption(options.cancellationSignal, deadline);
            }
            return text;
        }
        if (safe.kind === 'package-metadata') {
            const existingMetadata = metadataContents.get(safe.absolute);
            if (existingMetadata)
                return existingMetadata.text;
            const relative = relativeWithin(workspaceRoot, safe.absolute);
            if (!relative)
                throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
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
    const accountedSourceFiles = new WeakSet();
    const accountSourceFile = (sourceFile) => {
        if (accountedSourceFiles.has(sourceFile))
            return;
        accountedSourceFiles.add(sourceFile);
        const stack = [[sourceFile, 1]];
        while (stack.length > 0) {
            checkInterruption(options.cancellationSignal, deadline);
            const current = stack.pop();
            if (!current)
                break;
            const [node, depth] = current;
            astNodes += 1;
            maxDepth = Math.max(maxDepth, depth);
            if (astNodes > limits.maxAstNodes)
                throw new TypeScriptProjectLoadError('TS_PROJECT_AST_NODE_LIMIT');
            if (depth > limits.maxAnalysisDepth)
                throw new TypeScriptProjectLoadError('TS_PROJECT_DEPTH_LIMIT');
            node.forEachChild((child) => { stack.push([child, depth + 1]); });
        }
    };
    const host = {
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
            if (text === undefined)
                return undefined;
            const sourceFile = typescript_1.default.createSourceFile(candidate, text, languageVersion, true);
            if (kind === 'workspace' || kind === 'library')
                accountSourceFile(sourceFile);
            return sourceFile;
        },
        realpath: (candidate) => resolveProgramPath(candidate)?.absolute ?? candidate,
        directoryExists: (candidate) => {
            try {
                const lexical = node_path_1.default.resolve(candidate);
                const absolute = fileSystem.realpath(candidate);
                if (((lexical === workspaceRoot || relativeWithin(workspaceRoot, lexical) !== undefined)
                    && absolute !== workspaceRoot && relativeWithin(workspaceRoot, absolute) === undefined)
                    || (absolute !== workspaceRoot && relativeWithin(workspaceRoot, absolute) === undefined
                        && !isStandardLibraryDirectory(absolute) && isHoistedNodeModulesPath(lexical))) {
                    boundaryViolation = true;
                    return false;
                }
                return absolute === workspaceRoot || relativeWithin(workspaceRoot, absolute) !== undefined
                    || absolute === defaultLibraryRoot;
            }
            catch (error) {
                if (isMissingPathError(error))
                    return false;
                throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
            }
        },
        getDirectories: (candidate) => {
            try {
                const lexical = node_path_1.default.resolve(candidate);
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
                if (remainingEntries <= 0)
                    throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
                return fileSystem.getDirectories(absolute, remainingEntries, () => {
                    directoryEntriesEnumerated += 1;
                    checkInterruption(options.cancellationSignal, deadline);
                }, boundaryRoot);
            }
            catch (error) {
                if (error instanceof TypeScriptProjectLoadError)
                    throw error;
                if (isMissingPathError(error))
                    return [];
                throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
            }
        },
    };
    let program;
    try {
        program = typescript_1.default.createProgram({
            rootNames,
            options: compilerOptions,
            host,
            oldProgram: options.cache?.latest(identity)?.program,
        });
    }
    catch (error) {
        if (error instanceof TypeScriptProjectLoadError)
            throw error;
        throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
    }
    if (boundaryViolation)
        throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
    await yieldAndCheckInterruption(options.cancellationSignal, deadline);
    const sourceFiles = program.getSourceFiles()
        .filter(({ fileName }) => resolveProgramPath(fileName)?.kind === 'workspace')
        .sort((left, right) => left.fileName.localeCompare(right.fileName));
    if (boundaryViolation)
        throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
    for (const sourceFile of sourceFiles)
        accountSourceFile(sourceFile);
    const diagnostics = [];
    if ((parsed.projectReferences?.length ?? 0) > 0)
        diagnostics.push(diagnostic('TS_PROJECT_REFERENCES_PARTIAL'));
    for (const sourceFile of sourceFiles) {
        const syntaxDiagnostics = sourceFile.parseDiagnostics ?? [];
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
        ...[...libraryContents].map(([absolute, text]) => ({ relative: `typescript-lib:${node_path_1.default.basename(absolute)}`, text })),
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
    const loaded = {
        program,
        sourceFiles: Object.freeze([...sourceFiles]),
        compilerOptions: Object.freeze({ ...compilerOptions }),
        pathAliases: Object.freeze(Object.fromEntries(Object.entries(compilerOptions.paths ?? {}).map(([name, values]) => ([name, Object.freeze([...(values ?? [])])])))),
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
async function loadTypeScriptProject(options) {
    try {
        return await loadTypeScriptProjectInternal(options);
    }
    catch (error) {
        if (error instanceof TypeScriptProjectLoadError)
            throw error;
        throw new TypeScriptProjectLoadError('TS_PROJECT_INTERNAL');
    }
}
