"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EMPTY_NESTJS_AUTH_CONFIG = exports.NESTJS_AUTH_KINDS = void 0;
exports.validateNestJsAuthConfig = validateNestJsAuthConfig;
exports.authKindToIr = authKindToIr;
const node_util_1 = require("node:util");
exports.NESTJS_AUTH_KINDS = [
    'basic', 'bearer', 'api_key', 'oauth2', 'openid_connect', 'mutual_tls',
];
const SYMBOL_NAME = /^[A-Za-z_$][\w$]*$/u;
const AUTH_KIND_TO_IR = Object.freeze({
    basic: 'basic',
    bearer: 'bearer',
    api_key: 'api-key',
    oauth2: 'oauth2',
    openid_connect: 'openid-connect',
    mutual_tls: 'mutual-tls',
});
function record(value) {
    if (!value || typeof value !== 'object' || node_util_1.types.isProxy(value) || Array.isArray(value)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
        throw new Error('invalid NestJS auth config');
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== 'string'
        || descriptors[key].get || descriptors[key].set || !descriptors[key].enumerable)) {
        throw new Error('invalid NestJS auth config');
    }
    return Object.fromEntries(keys.map((key) => [key, descriptors[key].value]));
}
function exactKeys(value, expected) {
    const keys = Object.keys(value).sort();
    const expectedKeys = [...expected].sort();
    if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) {
        throw new Error('invalid NestJS auth config');
    }
}
function symbolNames(value) {
    if (!value || typeof value !== 'object' || node_util_1.types.isProxy(value) || !Array.isArray(value)
        || Object.getPrototypeOf(value) !== Array.prototype)
        throw new Error('invalid NestJS auth config');
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const length = descriptors.length?.value;
    if (!Number.isInteger(length) || length < 0 || length > 128) {
        throw new Error('invalid NestJS auth config');
    }
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== length + 1 || keys.some((key) => typeof key !== 'string'
        || (key !== 'length' && !/^(0|[1-9]\d*)$/u.test(key)))) {
        throw new Error('invalid NestJS auth config');
    }
    const names = [];
    for (let index = 0; index < length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor || descriptor.get || descriptor.set || !descriptor.enumerable
            || typeof descriptor.value !== 'string' || !SYMBOL_NAME.test(descriptor.value)) {
            throw new Error('invalid NestJS auth config');
        }
        names.push(descriptor.value);
    }
    if (new Set(names).size !== names.length)
        throw new Error('invalid NestJS auth config');
    return Object.freeze(names);
}
function validateNestJsAuthConfig(input) {
    const config = record(input);
    exactKeys(config, ['guard_mappings', 'public_decorators', 'roles_decorators']);
    const mappings = record(config.guard_mappings);
    if (Object.keys(mappings).length > 128)
        throw new Error('invalid NestJS auth config');
    const guardMappings = Object.fromEntries(Object.entries(mappings).map(([symbol, value]) => {
        if (!SYMBOL_NAME.test(symbol))
            throw new Error('invalid NestJS auth config');
        const mapping = record(value);
        exactKeys(mapping, ['auth_kind']);
        if (!exports.NESTJS_AUTH_KINDS.includes(mapping.auth_kind)) {
            throw new Error('invalid NestJS auth config');
        }
        return [symbol, Object.freeze({ auth_kind: mapping.auth_kind })];
    }));
    return Object.freeze({
        public_decorators: symbolNames(config.public_decorators),
        roles_decorators: symbolNames(config.roles_decorators),
        guard_mappings: Object.freeze(guardMappings),
    });
}
function authKindToIr(kind) {
    return AUTH_KIND_TO_IR[kind];
}
exports.EMPTY_NESTJS_AUTH_CONFIG = Object.freeze({
    public_decorators: Object.freeze([]),
    roles_decorators: Object.freeze([]),
    guard_mappings: Object.freeze({}),
});
