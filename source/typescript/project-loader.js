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
exports.nodeTypeScriptProjectFileSystem = Object.freeze({
    realpath: node_fs_1.default.realpathSync,
    readFile: (filePath) => node_fs_1.default.readFileSync(filePath, 'utf8'),
    stat: node_fs_1.default.statSync,
    exists: node_fs_1.default.existsSync,
    readDirectory: (rootDir, extensions, excludes, includes, depth) => (typescript_1.default.sys.readDirectory(rootDir, [...extensions], excludes ? [...excludes] : undefined, [...includes], depth)),
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
function normalizeRelative(value) {
    return value.replaceAll('\\', '/');
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
    return { absolute, relative };
}
function safeConfigPath(fileSystem, workspaceRoot, configDirectory, configuredPath) {
    if (!configuredPath || node_path_1.default.isAbsolute(configuredPath) || /^[a-z][a-z0-9+.-]*:/iu.test(configuredPath)) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
    }
    const marker = configuredPath.search(GLOB_MARKER);
    const staticPart = marker < 0 ? configuredPath : configuredPath.slice(0, marker);
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
        if (fileSystem.exists(candidate))
            return candidate;
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
    const text = fileSystem.readFile(resolved.absolute);
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
    state.totalBytes += bytes;
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
        if (compiler.paths !== undefined) {
            if (!compiler.paths || typeof compiler.paths !== 'object' || Array.isArray(compiler.paths)) {
                throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
            }
            const pathsBase = typeof compiler.baseUrl === 'string'
                ? node_path_1.default.resolve(configDirectory, compiler.baseUrl)
                : configDirectory;
            for (const values of Object.values(compiler.paths)) {
                if (!Array.isArray(values) || values.some((value) => typeof value !== 'string')) {
                    throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
                }
                for (const value of values)
                    safeConfigPath(fileSystem, workspaceRoot, pathsBase, value);
            }
        }
    }
    const references = config.references;
    if (references !== undefined) {
        if (!Array.isArray(references))
            throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
        state.hasReferences ||= references.length > 0;
        for (const reference of references) {
            if (!reference || typeof reference !== 'object' || typeof reference.path !== 'string') {
                throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG');
            }
            safeConfigPath(fileSystem, workspaceRoot, configDirectory, reference.path);
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
    return config;
}
function createParseHost(fileSystem, workspaceRoot, limits, signal, deadline) {
    const safeRealPath = (candidate) => {
        let absolute;
        try {
            absolute = fileSystem.realpath(candidate);
        }
        catch {
            return undefined;
        }
        if (!relativeWithin(workspaceRoot, absolute)) {
            throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
        }
        return absolute;
    };
    return {
        useCaseSensitiveFileNames: typescript_1.default.sys.useCaseSensitiveFileNames,
        fileExists: (candidate) => safeRealPath(candidate) !== undefined,
        readFile: (candidate) => {
            const safe = safeRealPath(candidate);
            return safe ? fileSystem.readFile(safe) : undefined;
        },
        readDirectory: (rootDir, extensions, excludes, includes, depth) => {
            checkInterruption(signal, deadline);
            if (!relativeWithin(workspaceRoot, node_path_1.default.resolve(rootDir)) && node_path_1.default.resolve(rootDir) !== workspaceRoot)
                return [];
            const files = fileSystem.readDirectory(rootDir, extensions, excludes, includes, depth);
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
    const configState = { digests: new Map(), totalBytes: 0, hasReferences: false };
    validateConfigTree(fileSystem, workspaceRoot, resolvedConfig.absolute, limits, options.cancellationSignal, deadline, configState, new Set());
    checkInterruption(options.cancellationSignal, deadline);
    const read = typescript_1.default.readConfigFile(resolvedConfig.absolute, (candidate) => {
        try {
            return fileSystem.readFile(candidate);
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
    const parsed = typescript_1.default.parseJsonConfigFileContent(read.config, createParseHost(fileSystem, workspaceRoot, limits, options.cancellationSignal, deadline), node_path_1.default.dirname(resolvedConfig.absolute), { noEmit: true, plugins: [] }, resolvedConfig.absolute);
    if (parsed.errors.length > 0) {
        throw new TypeScriptProjectLoadError('TS_PROJECT_INVALID_CONFIG', {
            sourceUri: resolvedConfig.relative,
            typescriptCode: parsed.errors[0].code,
        });
    }
    checkInterruption(options.cancellationSignal, deadline);
    const rootNames = [];
    const rootContents = new Map();
    let totalSourceBytes = configState.totalBytes;
    let largestFileBytes = 0;
    for (const fileName of parsed.fileNames) {
        checkInterruption(options.cancellationSignal, deadline);
        const resolved = realFileWithin(fileSystem, workspaceRoot, fileName, 'TS_PROJECT_CONFIG_MISSING');
        if (!SOURCE_EXTENSIONS.some((extension) => resolved.relative.endsWith(extension))) {
            throw new TypeScriptProjectLoadError('TS_PROJECT_EXTENSION_UNSUPPORTED', { sourceUri: resolved.relative });
        }
        if (rootContents.has(resolved.absolute))
            continue;
        const text = fileSystem.readFile(resolved.absolute);
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
    }
    const compilerOptions = { ...parsed.options, noEmit: true, plugins: [] };
    const identity = projectIdentity(workspaceRoot, resolvedConfig.relative);
    const defaultHost = typescript_1.default.createCompilerHost(compilerOptions, true);
    const defaultLibraryRoot = fileSystem.realpath(node_path_1.default.dirname(typescript_1.default.getDefaultLibFilePath(compilerOptions)));
    const isStandardLibrary = (absolute) => (node_path_1.default.dirname(absolute) === defaultLibraryRoot && /^lib(?:\.[a-z0-9_-]+)*\.d\.ts$/iu.test(node_path_1.default.basename(absolute)));
    let boundaryViolation = false;
    const workspaceContents = new Map(rootContents);
    const libraryContents = new Map();
    const metadataContents = new Map();
    const validateReferences = (text, relative) => {
        const references = typescript_1.default.preProcessFile(text).referencedFiles;
        if (references.some(({ fileName }) => node_path_1.default.isAbsolute(fileName) || /^[a-z][a-z0-9+.-]*:/iu.test(fileName))) {
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
            if (workspaceRelative && SOURCE_EXTENSIONS.some((extension) => workspaceRelative.endsWith(extension))) {
                return { absolute, kind: 'workspace' };
            }
            if (workspaceRelative && node_path_1.default.basename(workspaceRelative) === 'package.json'
                && normalizeRelative(workspaceRelative).split('/').includes('node_modules')) {
                return { absolute, kind: 'package-metadata' };
            }
            if (SOURCE_EXTENSIONS.some((extension) => absolute.endsWith(extension)))
                boundaryViolation = true;
            return undefined;
        }
        catch {
            return undefined;
        }
    };
    const readProgramFile = (candidate) => {
        const safe = safeExistingPath(candidate);
        if (!safe)
            return undefined;
        if (safe.kind === 'library') {
            const existingLibrary = libraryContents.get(safe.absolute);
            if (existingLibrary !== undefined)
                return existingLibrary;
            const text = defaultHost.readFile(safe.absolute);
            if (text !== undefined)
                libraryContents.set(safe.absolute, text);
            return text;
        }
        if (safe.kind === 'package-metadata') {
            const existingMetadata = metadataContents.get(safe.absolute);
            if (existingMetadata)
                return existingMetadata.text;
            const relative = relativeWithin(workspaceRoot, safe.absolute);
            if (!relative)
                throw new TypeScriptProjectLoadError('TS_PROJECT_PATH_OUTSIDE_ROOT');
            const text = fileSystem.readFile(safe.absolute);
            const size = Buffer.byteLength(text);
            if (size > limits.maxFileBytes) {
                throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_BYTES_LIMIT', { sourceUri: relative });
            }
            metadataContents.set(safe.absolute, { relative, text });
            totalSourceBytes += size;
            largestFileBytes = Math.max(largestFileBytes, size);
            if (configState.digests.size + workspaceContents.size + metadataContents.size > limits.maxFiles) {
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
        if (configState.digests.size + workspaceContents.size > limits.maxFiles) {
            throw new TypeScriptProjectLoadError('TS_PROJECT_FILE_LIMIT');
        }
        if (totalSourceBytes > limits.maxTotalSourceBytes) {
            throw new TypeScriptProjectLoadError('TS_PROJECT_TOTAL_BYTES_LIMIT');
        }
        validateReferences(text, relative);
        return text;
    };
    const host = {
        ...defaultHost,
        fileExists: (candidate) => safeExistingPath(candidate) !== undefined,
        readFile: readProgramFile,
        getSourceFile: (candidate, languageVersion) => {
            checkInterruption(options.cancellationSignal, deadline);
            const text = readProgramFile(candidate);
            return text === undefined ? undefined : typescript_1.default.createSourceFile(candidate, text, languageVersion, true);
        },
        realpath: (candidate) => safeExistingPath(candidate)?.absolute ?? candidate,
        directoryExists: (candidate) => {
            try {
                const absolute = fileSystem.realpath(candidate);
                return absolute === workspaceRoot || relativeWithin(workspaceRoot, absolute) !== undefined
                    || absolute === defaultLibraryRoot;
            }
            catch {
                return false;
            }
        },
        getDirectories: (candidate) => (defaultHost.getDirectories?.(candidate) ?? []).filter((directory) => {
            try {
                const absolute = fileSystem.realpath(node_path_1.default.isAbsolute(directory) ? directory : node_path_1.default.join(candidate, directory));
                return absolute === workspaceRoot || relativeWithin(workspaceRoot, absolute) !== undefined
                    || absolute === defaultLibraryRoot;
            }
            catch {
                return false;
            }
        }),
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
    checkInterruption(options.cancellationSignal, deadline);
    const sourceFiles = program.getSourceFiles().filter(({ fileName }) => {
        try {
            return relativeWithin(workspaceRoot, fileSystem.realpath(fileName)) !== undefined;
        }
        catch {
            return false;
        }
    }).sort((left, right) => left.fileName.localeCompare(right.fileName));
    let astNodes = 0;
    let maxDepth = 0;
    for (const sourceFile of sourceFiles) {
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
    }
    const diagnostics = [];
    if (configState.hasReferences)
        diagnostics.push(diagnostic('TS_PROJECT_REFERENCES_PARTIAL'));
    const compilerDiagnostics = typescript_1.default.getPreEmitDiagnostics(program);
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
        ...[...libraryContents].map(([absolute, text]) => ({ relative: `typescript-lib:${node_path_1.default.basename(absolute)}`, text })),
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
    const loaded = {
        program,
        sourceFiles: Object.freeze([...sourceFiles]),
        compilerOptions: Object.freeze({ ...compilerOptions }),
        pathAliases: Object.freeze(Object.fromEntries(Object.entries(compilerOptions.paths ?? {}).map(([name, values]) => ([name, Object.freeze([...(values ?? [])])])))),
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
