import ts from 'typescript';
export declare const NESTJS_ROUTE_DECORATORS: readonly ["All", "Controller", "Delete", "Get", "Head", "Options", "Patch", "Post", "Put", "RequestMapping", "Sse", "Version"];
export type NestJsRouteDecorator = typeof NESTJS_ROUTE_DECORATORS[number];
export declare function nestJsRouteDecorator(decorator: ts.Decorator, checker: ts.TypeChecker): {
    name: NestJsRouteDecorator;
    call: ts.CallExpression;
} | undefined;
export declare function isUnsupportedNestJsDecorator(decorator: ts.Decorator, checker: ts.TypeChecker): boolean;
