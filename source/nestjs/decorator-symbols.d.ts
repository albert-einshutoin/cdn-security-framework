import ts from 'typescript';
export declare const NESTJS_ROUTE_DECORATORS: readonly ["All", "Controller", "Delete", "Get", "Head", "Options", "Patch", "Post", "Put", "RequestMapping", "Search", "Sse", "Version"];
export type NestJsRouteDecorator = typeof NESTJS_ROUTE_DECORATORS[number];
export type NestJsRouteDecoratorCandidate = NestJsRouteDecorator | 'Unknown';
export declare function classifyNestJsRouteDecorator(decorator: ts.Decorator, checker: ts.TypeChecker, check: () => void): {
    candidate?: {
        name: NestJsRouteDecoratorCandidate;
        call: ts.CallExpression;
        trusted: boolean;
    };
    route?: {
        name: NestJsRouteDecorator;
        call: ts.CallExpression;
    };
    unsupported: boolean;
};
export declare function resolveDecoratorSymbol(decorator: ts.Decorator, checker: ts.TypeChecker, check: () => void): {
    name: string;
    call: ts.CallExpression;
    nestJsCommon: boolean;
    trustedNestJsCommon: boolean;
} | undefined;
export declare function resolveBareDecoratorName(decorator: ts.Decorator, checker: ts.TypeChecker, check: () => void): string | undefined;
export declare function resolveDecoratorCallSymbol(call: ts.CallExpression, checker: ts.TypeChecker, check: () => void): {
    name: string;
    call: ts.CallExpression;
    nestJsCommon: boolean;
    trustedNestJsCommon: boolean;
} | undefined;
export declare function resolveStaticSymbolName(expression: ts.Expression, checker: ts.TypeChecker, check: () => void): string | undefined;
export declare function isStaticSymbolFrom(expression: ts.Expression, checker: ts.TypeChecker, check: () => void, moduleName: string, importedName: string): boolean;
export declare function isStaticShorthandSymbolFrom(shorthand: ts.ShorthandPropertyAssignment, checker: ts.TypeChecker, check: () => void, moduleName: string, importedName: string): boolean;
export declare function isNestJsUseGlobalGuardsCall(call: ts.CallExpression, checker: ts.TypeChecker): boolean;
