import type { AuthSchemeKindV1 } from '../../contract/security-ir';
export declare const NESTJS_AUTH_KINDS: readonly ["basic", "bearer", "api_key", "oauth2", "openid_connect", "mutual_tls"];
export type NestJsAuthKind = typeof NESTJS_AUTH_KINDS[number];
export interface NestJsAuthConfig {
    public_decorators: readonly string[];
    roles_decorators: readonly string[];
    guard_mappings: Readonly<Record<string, Readonly<{
        auth_kind: NestJsAuthKind;
    }>>>;
}
export declare function validateNestJsAuthConfig(input: unknown): Readonly<NestJsAuthConfig>;
export declare function authKindToIr(kind: NestJsAuthKind): AuthSchemeKindV1;
export declare const EMPTY_NESTJS_AUTH_CONFIG: Readonly<NestJsAuthConfig>;
