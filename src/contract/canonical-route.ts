export const HTTP_METHODS = [
  'CONNECT', 'DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT', 'TRACE',
] as const;

export type HttpMethod = typeof HTTP_METHODS[number];
const MAX_ROUTE_STRING_LENGTH = 16_384;

export function normalizeHttpMethod(method: string): HttpMethod {
  if (typeof method !== 'string' || method.length > MAX_ROUTE_STRING_LENGTH) {
    throw new Error('unknown HTTP method');
  }
  const normalized = method.trim().toUpperCase();
  if (!HTTP_METHODS.includes(normalized as HttpMethod)) {
    throw new Error('unknown HTTP method');
  }
  return normalized as HttpMethod;
}

export function canonicalizePath(routePath: string): string {
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
  return canonical.length > 1 && canonical.endsWith('/') ? canonical.slice(0, -1) : canonical;
}

export function createRouteKey(method: string, routePath: string): string {
  return `${normalizeHttpMethod(method)} ${canonicalizePath(routePath)}`;
}
