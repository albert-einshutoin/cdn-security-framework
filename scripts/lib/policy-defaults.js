"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_CLEAR_SITE_DATA_TYPES = exports.JWT_CLOCK_SKEW = exports.JWKS_DEFAULTS = exports.LIMITS_DEFAULTS = exports.DEFAULT_SECURITY_HEADERS = exports.DEFAULT_CSP_ADMIN = exports.DEFAULT_CSP_PUBLIC = exports.DEFAULT_REQUIRED_HEADERS = exports.DEFAULT_ALLOW_METHODS = exports.DEFAULT_ADMIN_PATH_PREFIXES = exports.DEFAULT_DROP_QUERY_KEYS = exports.DEFAULT_UA_DENY_CONTAINS = void 0;
// Runtime compiler defaults only. The guided CLI init template stays separate
// until maintainers decide whether sample policies should mirror these values.
exports.DEFAULT_UA_DENY_CONTAINS = Object.freeze([
    'sqlmap',
    'nikto',
    'acunetix',
    'masscan',
    'python-requests',
]);
exports.DEFAULT_DROP_QUERY_KEYS = Object.freeze([
    'utm_source',
    'utm_medium',
    'utm_campaign',
    'utm_term',
    'utm_content',
    'gclid',
    'fbclid',
]);
exports.DEFAULT_ADMIN_PATH_PREFIXES = Object.freeze(['/admin', '/docs', '/swagger']);
exports.DEFAULT_ALLOW_METHODS = Object.freeze(['GET', 'HEAD', 'POST']);
exports.DEFAULT_REQUIRED_HEADERS = Object.freeze(['user-agent']);
exports.DEFAULT_CSP_PUBLIC = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';";
exports.DEFAULT_CSP_ADMIN = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';";
exports.DEFAULT_SECURITY_HEADERS = Object.freeze({
    'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'camera=(), microphone=(), geolocation=()',
});
exports.LIMITS_DEFAULTS = Object.freeze({
    maxQueryLength: 1024,
    maxQueryParams: 30,
    maxUriLength: 2048,
    maxHeaderSize: 0,
    maxHeaderCount: 64,
    headerCountMin: 1,
    headerCountMax: 500,
});
exports.JWKS_DEFAULTS = Object.freeze({
    staleIfErrorSec: 3600,
    staleMax: 86400,
    negativeCacheSec: 60,
    negativeMax: 600,
});
exports.JWT_CLOCK_SKEW = Object.freeze({
    defaultSec: 30,
    min: 0,
    max: 600,
});
exports.DEFAULT_CLEAR_SITE_DATA_TYPES = Object.freeze(['cache', 'cookies', 'storage']);
