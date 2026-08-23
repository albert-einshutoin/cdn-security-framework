import ts from 'typescript';
export interface StaticStringResolverOptions {
    check?: () => void;
    maxSteps?: number;
    maxStringLength?: number;
}
export declare function resolveStaticStrings(expression: ts.Expression | undefined, checker: ts.TypeChecker, projectSources: ReadonlySet<ts.SourceFile>, options?: StaticStringResolverOptions): string[] | undefined;
