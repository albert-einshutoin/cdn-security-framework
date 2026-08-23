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
