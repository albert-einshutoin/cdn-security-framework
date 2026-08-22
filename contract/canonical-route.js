"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HTTP_METHODS = void 0;
exports.normalizeHttpMethod = normalizeHttpMethod;
exports.canonicalizePath = canonicalizePath;
exports.createRouteKey = createRouteKey;
exports.HTTP_METHODS = [
    'CONNECT', 'DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT', 'TRACE',
];
const MAX_ROUTE_STRING_LENGTH = 16_384;
function normalizeHttpMethod(method) {
    if (typeof method !== 'string' || method.length > MAX_ROUTE_STRING_LENGTH) {
        throw new Error('unknown HTTP method');
    }
    const normalized = method.trim().toUpperCase();
    if (!exports.HTTP_METHODS.includes(normalized)) {
        throw new Error('unknown HTTP method');
    }
    return normalized;
}
function canonicalizePath(routePath) {
    if (typeof routePath !== 'string' || routePath.length > MAX_ROUTE_STRING_LENGTH) {
        throw new Error('invalid route path');
    }
    const trimmed = routePath.trim();
    if (!trimmed
        || /[\u0000-\u001f\u007f?#\\]/.test(trimmed)
        || /%(?:2e|2f|3f|23|5c)/i.test(trimmed)
        || /(?:authorization|cookie|password|secret|token|api[_-]?key)\s*[=:]/i.test(trimmed)
        || trimmed.split('/').some((segment) => segment === '.' || segment === '..')) {
        throw new Error('invalid route path');
    }
    const canonical = `/${trimmed}`.replace(/\/{2,}/g, '/');
    const withoutTrailingSlash = canonical.length > 1 && canonical.endsWith('/')
        ? canonical.slice(0, -1)
        : canonical;
    if (withoutTrailingSlash.length > MAX_ROUTE_STRING_LENGTH)
        throw new Error('invalid route path');
    return withoutTrailingSlash;
}
function createRouteKey(method, routePath) {
    return `${normalizeHttpMethod(method)} ${canonicalizePath(routePath)}`;
}
