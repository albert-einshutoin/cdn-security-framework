import { type FindingEvidenceV1 } from './finding';
import { type HttpMethod } from './canonical-route';
export declare const CONTRACT_SOURCES: readonly ["openapi", "source-ast", "policy", "runtime"];
export declare const CAPABILITY_LEVELS: readonly ["complete", "partial", "unsupported"];
export declare const EXPOSURES: readonly ["public", "authenticated", "privileged", "unknown"];
export declare const VALUE_TYPES: readonly ["string", "integer", "number", "boolean", "array", "object", "unknown"];
export declare const AUTH_SCHEME_KINDS: readonly ["basic", "bearer", "api-key", "oauth2", "openid-connect", "mutual-tls", "unknown"];
export type ContractSourceV1 = typeof CONTRACT_SOURCES[number];
export type CapabilityLevelV1 = typeof CAPABILITY_LEVELS[number];
export type ExposureV1 = typeof EXPOSURES[number];
export type ValueTypeV1 = typeof VALUE_TYPES[number];
export type AuthSchemeKindV1 = typeof AUTH_SCHEME_KINDS[number];
export interface SecurityContractCapabilitiesV1 {
    routes: CapabilityLevelV1;
    parameters: CapabilityLevelV1;
    requestBodies: CapabilityLevelV1;
    authentication: CapabilityLevelV1;
}
export interface ValueConstraintsV1 {
    type: ValueTypeV1;
    format?: string;
    enum?: Array<string | number | boolean | null>;
    minimum?: number;
    maximum?: number;
    minLength?: number;
    maxLength?: number;
    minItems?: number;
    maxItems?: number;
    maxProperties?: number;
}
export interface ApiParameterContractV1 {
    name: string;
    required: boolean;
    constraints: ValueConstraintsV1;
    style?: string;
    explode?: boolean;
    unsupportedReasons: string[];
}
export interface ApiRequestBodyContractV1 {
    required: boolean;
    constraints: ValueConstraintsV1;
    unsupportedReasons: string[];
}
export interface ApiRequestContractV1 {
    contentTypes: string[];
    requiredHeaders: string[];
    queryParameters: ApiParameterContractV1[];
    pathParameters: ApiParameterContractV1[];
    headerParameters: ApiParameterContractV1[];
    cookieParameters: ApiParameterContractV1[];
    body?: ApiRequestBodyContractV1;
}
export interface ApiAuthSchemeV1 {
    name: string;
    kind: AuthSchemeKindV1;
    location?: 'header' | 'query' | 'cookie';
    parameterName?: string;
    scopes: string[];
    flows?: string[];
    capability: 'supported' | 'unsupported';
    unsupportedReason?: string;
}
export interface ApiAuthAlternativeV1 {
    anonymous: boolean;
    schemes: ApiAuthSchemeV1[];
}
export interface ApiAuthenticationContractV1 {
    mode: 'none' | 'unknown' | 'alternatives';
    alternatives: ApiAuthAlternativeV1[];
}
export interface ApiOperationContractV1 {
    routeKey: string;
    method: HttpMethod;
    path: string;
    operationId?: string;
    exposure: ExposureV1;
    auth: ApiAuthenticationContractV1;
    request: ApiRequestContractV1;
    provenance: FindingEvidenceV1[];
    metadata?: {
        deprecated: boolean;
        tags: string[];
    };
}
export interface SecurityContractV1 {
    schemaVersion: 1;
    source: ContractSourceV1;
    capabilities: SecurityContractCapabilitiesV1;
    operations: ApiOperationContractV1[];
}
export interface SecurityContractInputV1 {
    source: ContractSourceV1;
    capabilities: SecurityContractCapabilitiesV1;
    operations: ApiOperationInputV1[];
}
export type ApiOperationInputV1 = Omit<ApiOperationContractV1, 'routeKey' | 'method'> & {
    routeKey?: string;
    method: string;
};
export declare function createSecurityContract(input: SecurityContractInputV1): SecurityContractV1;
export declare function serializeSecurityContract(contract: SecurityContractV1): string;
