export declare const HTTP_METHODS: readonly ["CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"];
export type HttpMethod = typeof HTTP_METHODS[number];
export declare function normalizeHttpMethod(method: string): HttpMethod;
export declare function canonicalizePath(routePath: string): string;
export declare function createRouteKey(method: string, routePath: string): string;
