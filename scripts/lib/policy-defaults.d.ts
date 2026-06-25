export declare const DEFAULT_UA_DENY_CONTAINS: readonly ["sqlmap", "nikto", "acunetix", "masscan", "python-requests"];
export declare const DEFAULT_DROP_QUERY_KEYS: readonly ["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid"];
export declare const DEFAULT_ADMIN_PATH_PREFIXES: readonly ["/admin", "/docs", "/swagger"];
export declare const DEFAULT_ALLOW_METHODS: readonly ["GET", "HEAD", "POST"];
export declare const DEFAULT_REQUIRED_HEADERS: readonly ["user-agent"];
export declare const DEFAULT_CSP_PUBLIC = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';";
export declare const DEFAULT_CSP_ADMIN = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';";
export declare const DEFAULT_SECURITY_HEADERS: Readonly<{
    readonly 'strict-transport-security': "max-age=31536000; includeSubDomains; preload";
    readonly 'x-content-type-options': "nosniff";
    readonly 'referrer-policy': "strict-origin-when-cross-origin";
    readonly 'permissions-policy': "camera=(), microphone=(), geolocation=()";
}>;
export declare const LIMITS_DEFAULTS: Readonly<{
    readonly maxQueryLength: 1024;
    readonly maxQueryParams: 30;
    readonly maxUriLength: 2048;
    readonly maxHeaderSize: 0;
    readonly maxHeaderCount: 64;
    readonly headerCountMin: 1;
    readonly headerCountMax: 500;
}>;
export declare const JWKS_DEFAULTS: Readonly<{
    readonly staleIfErrorSec: 3600;
    readonly staleMax: 86400;
    readonly negativeCacheSec: 60;
    readonly negativeMax: 600;
}>;
export declare const JWT_CLOCK_SKEW: Readonly<{
    readonly defaultSec: 30;
    readonly min: 0;
    readonly max: 600;
}>;
export declare const DEFAULT_CLEAR_SITE_DATA_TYPES: readonly ["cache", "cookies", "storage"];
