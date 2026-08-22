export type PathFlavor = 'native' | 'posix' | 'win32';
export declare function isPathWithinWorkspace(workspaceRoot: string, candidatePath: string, flavor?: PathFlavor): boolean;
export interface ResolveOpenApiRefPathOptions {
    workspaceRoot: string;
    sourcePath: string;
    ref: string;
    realpath?: (inputPath: string) => string;
    fragmentSeparated?: boolean;
}
export declare function resolveOpenApiRefPath(options: ResolveOpenApiRefPathOptions): string;
