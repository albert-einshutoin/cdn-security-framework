import type { CDNSecurityFrameworkPolicy } from '../types/policy';
import type { FindingEvidenceV1 } from './finding';
export type AllowedSurfaceTarget = 'aws' | 'cloudflare';
export type AllowedCapabilityStatus = 'supported' | 'partial' | 'unsupported' | 'warning-only';
export type AuthKind = 'none' | 'static_token' | 'basic_auth' | 'jwt' | 'signed_url';
type AuthVerifiability = 'enforced' | 'not-applicable' | 'unsupported-configuration';
interface AllowedResponseDefaultsV1 {
    headers: Record<string, string>;
    cspPublic: string;
    cspAdmin: string;
    cspNonce: boolean;
    adminPathMatch: {
        kind: 'prefix';
        values: string[];
        boundary: 'path-segment';
        algorithm: 'equal-or-prefix-plus-slash';
        comparison: 'literal-no-percent-decoding';
        phase: 'normalized-path';
    };
    adminCacheControl: string;
    forceVaryAuth: boolean;
    authProtectedCacheControlOverride?: {
        when: 'force-vary-auth-and-auth-protected-path';
        value: string;
        pathMatch: AllowedResponseDefaultsV1['adminPathMatch'];
    };
    clearSiteDataCacheControlOverride?: {
        when: 'matching-path-and-status-200-through-399';
        value: 'no-store';
        order: 'after-auth-protected-override';
        pathMatch: AllowedResponseDefaultsV1['adminPathMatch'];
    };
}
export interface AllowedTargetCapabilityV1 {
    id: string;
    status: AllowedCapabilityStatus;
}
export interface AllowedDefaultsV1 {
    mode: 'enforce' | 'monitor';
    requestDecision: 'block' | 'would-block';
    authenticationDecision: 'block';
    methods: string[];
    configuredMethods: string[];
    corsOptionsBypass: boolean;
    corsPreflight: {
        method: 'OPTIONS';
        allowedOriginDecision: 'early-204-before-request-validation' | 'not-configured';
        allowedOriginResponseCacheControl: 'no-store' | 'not-configured';
        origins: {
            kind: 'not-configured' | 'none' | 'any' | 'allowlist';
            values: string[];
            comparison: 'literal';
            wildcard: 'asterisk-matches-any-origin';
        };
        nonMatchingOriginDecision: 'continue';
        bypassScope: 'all-request-validation-including-host-and-auth' | 'none';
    };
    hosts: {
        kind: 'any' | 'allowlist';
        values: string[];
        configuredValues: string[];
        unsupportedConfiguredValues: string[];
        comparison: 'case-insensitive-first-colon-port-strip';
        wildcard: 'leading-subdomain-only';
        ipv6LiteralSupport: 'unsupported';
    };
    limits: {
        maxQueryLength: number;
        maxQueryParams: number;
        maxUriLength: number;
        maxHeaderSize: number;
        maxHeaderCount: number;
    };
    limitSources?: Partial<Record<keyof AllowedDefaultsV1['limits'], 'configured' | 'runtime-default'>>;
    requiredHeaders?: {
        values: string[];
        source: 'configured' | 'runtime-default';
    };
    pathNormalization: {
        collapseSlashes: boolean;
        removeDotSegments: boolean;
        routeMatchPhase: 'normalized-path';
    };
    response: AllowedResponseDefaultsV1;
}
export interface AllowedRouteRuleV1 {
    index: number;
    name: string;
    pointer: string;
    match: {
        kind: 'prefix';
        values: string[];
        boundary: 'path-segment';
        algorithm: 'equal-or-prefix-plus-slash';
        comparison: 'literal-no-percent-decoding';
        phase: 'normalized-path';
        authEffectiveValues: string[];
    };
    methods: {
        source: 'global';
        effective: string[];
        configuredButNotEnforced?: string[];
    };
    auth: {
        kind: AuthKind;
        typeSource: 'absent' | 'explicit' | 'compiler-default';
        matching: {
            aws: 'static-and-basic-in-policy-order-then-jwt-then-signed-url';
            cloudflare: 'all-matching-rules-in-policy-order';
        };
        exactPath: boolean;
        preAuthBypassMethods: string[];
        preAuthBypassCondition: 'allowed-cors-origin-preflight' | 'none';
        credentialEnvironmentNames: string[];
        credential?: {
            location: 'header' | 'query';
            names: string[];
        };
        configuredAlgorithm?: string;
        effectiveAlgorithm?: 'HS256' | 'RS256' | 'HMAC-SHA256';
        verifiability: Record<AllowedSurfaceTarget, AuthVerifiability>;
    };
    requestLimits: {
        source: 'global';
    };
    response: {
        cacheControl?: string;
        selectedBaseCacheControl?: string;
        selection: 'first-auth-or-cache-rule' | 'not-selected';
    };
    mode: {
        requestDecision: 'block' | 'would-block';
        authenticationDecision: 'block';
    };
}
export interface AllowedSurfaceModelV1 {
    schemaVersion: 1;
    policyDigest: string;
    defaults: AllowedDefaultsV1;
    orderedRules: AllowedRouteRuleV1[];
    targetCapabilities: Record<AllowedSurfaceTarget, AllowedTargetCapabilityV1[]>;
    provenance: FindingEvidenceV1[];
}
export interface ProjectAllowedSurfaceOptions {
    policyDigest: string;
    sourceUri: string;
}
export declare function projectPolicyToAllowedSurface(policy: CDNSecurityFrameworkPolicy, options: ProjectAllowedSurfaceOptions): AllowedSurfaceModelV1;
export {};
