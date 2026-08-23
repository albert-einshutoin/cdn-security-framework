import fs from 'node:fs';
import ts from 'typescript';
import { type SourceAnalysisLimits } from '../../source-analysis';
export declare const TYPESCRIPT_PROJECT_LOADER_VERSION = "1.0.0";
export declare const TYPESCRIPT_PROJECT_DIAGNOSTIC_CODES: readonly ["TS_PROJECT_CANCELLED", "TS_PROJECT_TIMEOUT", "TS_PROJECT_INVALID_CONFIG", "TS_PROJECT_CONFIG_MISSING", "TS_PROJECT_EXTENDS_UNSUPPORTED", "TS_PROJECT_PATH_OUTSIDE_ROOT", "TS_PROJECT_EXTENSION_UNSUPPORTED", "TS_PROJECT_FILE_LIMIT", "TS_PROJECT_FILE_BYTES_LIMIT", "TS_PROJECT_TOTAL_BYTES_LIMIT", "TS_PROJECT_AST_NODE_LIMIT", "TS_PROJECT_DEPTH_LIMIT", "TS_PROJECT_DIAGNOSTIC_LIMIT", "TS_PROJECT_REFERENCES_PARTIAL", "TS_PROJECT_TYPESCRIPT_DIAGNOSTIC", "TS_PROJECT_INTERNAL"];
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
    readDirectory(rootDir: string, extensions: readonly string[], excludes: readonly string[] | undefined, includes: readonly string[], depth?: number, maxEntries?: number, checkInterruption?: () => void, boundaryRoot?: string): string[];
    getDirectories(rootDir: string, maxEntries?: number, checkInterruption?: () => void, boundaryRoot?: string): string[];
}
export declare const nodeTypeScriptProjectFileSystem: TypeScriptProjectFileSystem;
export interface LoadTypeScriptProjectOptions {
    tsconfigPath: string;
    workspaceRoot: string;
    limits: SourceAnalysisLimits;
    cancellationSignal?: AbortSignal;
    cache?: TypeScriptAnalysisCache;
    fileSystem?: TypeScriptProjectFileSystem;
}
export declare class TypeScriptProjectLoadError extends Error {
    readonly diagnostics: readonly TypeScriptProjectDiagnostic[];
    constructor(code: TypeScriptProjectDiagnosticCode, options?: Omit<TypeScriptProjectDiagnostic, 'code' | 'safeMessage'>);
}
interface CacheRead {
    value?: LoadedTypeScriptProject;
    invalidated: 0 | 1;
}
export declare class TypeScriptAnalysisCache {
    private readonly entries;
    private readonly currentKeys;
    read(identity: string, key: string): CacheRead;
    latest(identity: string): LoadedTypeScriptProject | undefined;
    write(identity: string, key: string, value: LoadedTypeScriptProject): void;
}
export declare function loadTypeScriptProject(options: LoadTypeScriptProjectOptions): Promise<LoadedTypeScriptProject>;
export {};
