// Runtime compiler defaults only. The guided CLI init template stays separate
// until maintainers decide whether sample policies should mirror these values.
export const DEFAULT_UA_DENY_CONTAINS = Object.freeze([
  'sqlmap',
  'nikto',
  'acunetix',
  'masscan',
  'python-requests',
] as const);

export const DEFAULT_DROP_QUERY_KEYS = Object.freeze([
  'utm_source',
  'utm_medium',
  'utm_campaign',
  'utm_term',
  'utm_content',
  'gclid',
  'fbclid',
] as const);

export const DEFAULT_ADMIN_PATH_PREFIXES = Object.freeze(['/admin', '/docs', '/swagger'] as const);
export const DEFAULT_ALLOW_METHODS = Object.freeze(['GET', 'HEAD', 'POST'] as const);
export const DEFAULT_REQUIRED_HEADERS = Object.freeze(['user-agent'] as const);

export const DEFAULT_CSP_PUBLIC = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';";
export const DEFAULT_CSP_ADMIN = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';";

export const DEFAULT_SECURITY_HEADERS = Object.freeze({
  'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
} as const);

export const LIMITS_DEFAULTS = Object.freeze({
  maxQueryLength: 1024,
  maxQueryParams: 30,
  maxUriLength: 2048,
  maxHeaderSize: 0,
  maxHeaderCount: 64,
  headerCountMin: 1,
  headerCountMax: 500,
} as const);

export const JWKS_DEFAULTS = Object.freeze({
  staleIfErrorSec: 3600,
  staleMax: 86400,
  negativeCacheSec: 60,
  negativeMax: 600,
} as const);

export const JWT_CLOCK_SKEW = Object.freeze({
  defaultSec: 30,
  min: 0,
  max: 600,
} as const);

export const DEFAULT_CLEAR_SITE_DATA_TYPES = Object.freeze(['cache', 'cookies', 'storage'] as const);
