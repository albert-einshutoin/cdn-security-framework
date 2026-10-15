#!/usr/bin/env node
/** Generated Worker security-path measurements. All outbound requests terminate at a loopback fixture. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import crypto from 'node:crypto';
import { spawn, execFileSync, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { performance, monitorEventLoopDelay, PerformanceObserver } from 'node:perf_hooks';
import { transformSync } from 'esbuild';
import type { CDNSecurityFrameworkPolicy } from '../types/policy';

type Profile = { policy: CDNSecurityFrameworkPolicy };
type Scenario = {
  id: string; group: string; profile: string; target: string; status: number; forwarded: boolean;
  method?: string; headers?: Record<string, string | undefined>; body?: string;
  forwardedPath?: string; responseBody?: string; responseIncludes?: string; responseExcludes?: string;
  responseHeaders?: Record<string, string>; originAuth?: 'hmac' | 'custom'; firstOnly?: boolean;
  authorizationVariants?: string[]; chunked?: boolean; rawParser?: boolean;
  jwksTransition?: { endpoint: string; mode: string; waitMs: number };
  coldBurst?: boolean; jwksExpected?: { endpoint: string; firstFetches: number; totalFetches: number };
};
const secret = 'security-benchmark-synthetic-only';
const userAgent = 'security-benchmark';
const sha = (value: string | Buffer) => crypto.createHash('sha256').update(value).digest('hex');
const hmac = (value: string) => crypto.createHmac('sha256', secret).update(value).digest('base64url');
const base = (): CDNSecurityFrameworkPolicy => ({ version: 2, defaults: { mode: 'enforce' },
  request: { allow_methods: ['GET', 'HEAD', 'POST', 'OPTIONS'],
    allowed_hosts: ['edge.example', '*.edge.example'],
    limits: { max_uri_length: 8192, max_query_length: 4096, max_query_params: 32,
      max_header_count: 32, max_header_size: 8192 },
    anomaly_guards: { enabled: true, max_cookie_bytes: 64, max_cookie_pairs: 4 },
    block: { header_missing: ['user-agent', 'x-required'], ua_contains: ['sqlmap', 'nikto'],
      path_patterns: { contains: ['/../', '%2e%2e', '%2f..', '..%2f', '%5c', '/forbidden'], regex: ['/blocked/[a-z]+$'] } },
    normalize: { drop_query_keys: ['utm_source'] } },
  response_headers: { hsts: 'max-age=100', x_content_type_options: 'nosniff' },
  observability: { sample_rate: 0, log_format: 'json', correlation_id_header: 'x-bench-id' }, routes: [] });

function fixtures() {
  const profiles: Record<string, Profile> = { core: { policy: base() } };
  const cases: Scenario[] = [];
  const profile = (id: string, configure: (policy: CDNSecurityFrameworkPolicy) => void) => {
    const policy = base(); configure(policy); profiles[id] = { policy };
  };
  const add = (id: string, group: string, target = '/public', status = 200, extra: Partial<Scenario> = {}) => {
    cases.push({ id, group, profile: 'core', target, status, forwarded: status === 200, ...extra });
  };
  add('public-get', 'baseline');
  add('public-head', 'baseline', '/public', 200, { method: 'HEAD', responseBody: '' });
  add('public-post-1KiB', 'baseline', '/public', 200, { method: 'POST', body: 'x'.repeat(1024) });
  add('public-post-1MiB', 'baseline', '/public', 200, { method: 'POST', body: 'x'.repeat(1048576) });
  add('upstream-http-503', 'origin-error', '/origin-error', 503, { forwarded: true, responseBody: 'synthetic-origin-failure' });
  add('method-denied', 'request', '/public', 405, { method: 'DELETE' });
  add('host-denied', 'request', '/public', 400, { headers: { host: 'attacker.invalid' }, responseBody: 'Host Not Allowed' });
  add('host-wildcard', 'request', '/public', 200, { headers: { host: 'api.edge.example' } });
  add('header-missing', 'request', '/public', 400, { headers: { 'x-required': undefined }, responseBody: 'Missing x-required' });
  add('ua-missing', 'request', '/public', 400, { headers: { 'user-agent': undefined } });
  add('ua-denied', 'request', '/public', 403, { headers: { 'user-agent': 'sqlmap' } });
  for (const n of [511, 512, 513]) add('ua-' + n, 'limits', '/public', n > 512 ? 400 : 200, { headers: { 'user-agent': 'a'.repeat(n) } });
  for (const n of [8191, 8192, 8193]) add('uri-' + n, 'limits', '/' + 'a'.repeat(n - 1), n > 8192 ? 414 : 200);
  for (const n of [4095, 4096, 4097]) add('query-bytes-' + n, 'limits', '/public?a=' + 'x'.repeat(n - 2), n > 4096 ? 414 : 200);
  for (const n of [31, 32, 33]) add('query-count-' + n, 'limits', '/public?' + Array.from({ length: n }, (_, i) => 'q' + i + '=x').join('&'), n > 32 ? 400 : 200);
  for (const n of [31, 32, 33]) add('header-count-' + n, 'limits', '/public', n > 32 ? 431 : 200,
    { headers: Object.fromEntries(Array.from({ length: n - 5 }, (_, i) => ['x-extra-' + i, 'v'])) });
  for (const n of [8191, 8192, 8193]) {
    const id = 'header-size-' + n;
    const fixed = { ...requestHeaders(id), 'x-padding': '' };
    const length = Object.entries(fixed).reduce((sum, [key, value]) => sum + key.length + value.length, 0);
    add(id, 'limits', '/public', n > 8192 ? 431 : 200, { headers: { 'x-padding': 'a'.repeat(n - length) } });
  }
  for (const [id, target, status, destination] of [
    ['normalized', '/public//a;v/%61', 200, '/public/a/a'],
    ['traversal-encoded', '/%2e%2e/private', 400, ''],
    ['traversal-double', '/%252e%252e/private', 400, ''],
    ['slash-encoded', '/private%2fchild', 400, ''],
    ['backslash-encoded', '/private%5cchild', 400, ''],
    ['percent-literal', '/public/%ZZ', 200, '/public/%ZZ'],
    ['encoding-invalid-mixed', '/public/%61%ZZ', 400, ''],
    ['path-literal-denied', '/forbidden/file', 400, ''],
    ['path-regex-denied', '/blocked/item', 400, ''],
    ['path-regex-after-normalize', '/blocked/%69tem', 400, ''],
    ['crlf-path', '/public/%0d%0aX-Test', 400, ''],
    ['crlf-query', '/public?q=%0d%0aX-Test', 400, ''],
  ] as const) add(id, 'path-anomaly', target, status, destination ? { forwardedPath: destination } : {});
  add('http-parser-invalid-header', 'http-parser', '/public', 400, { rawParser: true });
  add('crlf-header', 'path-anomaly', '/public', 400, { headers: { 'x-test': '%0d%0aInjected' } });
  add('cookie-malformed', 'path-anomaly', '/public', 400, { headers: { cookie: 'a=1;;b=2' }, responseBody: 'Malformed Cookie' });
  for (const n of [3, 4, 5]) add('cookie-pairs-' + n, 'limits', '/public', n > 4 ? 400 : 200,
    { headers: { cookie: Array.from({ length: n }, (_, i) => 'a' + i + '=1').join(';') } });
  for (const n of [63, 64, 65]) add('cookie-bytes-' + n, 'limits', '/public', n > 64 ? 400 : 200,
    { headers: { cookie: 'a=' + 'x'.repeat(n - 2) } });

  profile('geo', p => { p.firewall = { geo: { allow_countries: ['JP', 'US'], block_countries: ['US'] } }; });
  for (const [country, status] of [['JP', 200], ['US', 403], ['DE', 403], ['T1', 403], ['', 403]] as const)
    add('geo-' + (country || 'unknown'), 'geo', '/public', status,
      { profile: 'geo', headers: { 'x-bench-cf': JSON.stringify({ country }) } });

  profile('auth', p => { p.routes = [
    { name: 'static', match: { path_prefixes: ['/private', ...Array.from({ length: 63 }, (_, i) => '/unused' + i)] }, auth_gate: { type: 'static_token', token_env: 'TOKEN' } },
    { name: 'basic', match: { path_prefixes: ['/basic'] }, auth_gate: { type: 'basic_auth', credentials_env: 'BASIC' } },
    { name: 'hs', match: { path_prefixes: ['/hs'] }, auth_gate: { type: 'jwt', algorithm: 'HS256', secret_env: 'SECRET', issuer: 'fixture', audience: 'fixture', clock_skew_sec: 0 } },
    { name: 'signed', match: { path_prefixes: ['/signed'] }, auth_gate: { type: 'signed_url', secret_env: 'SECRET', nonce_param: 'nonce' } },
  ]; });
  const basic = Buffer.from('user:password').toString('base64');
  for (const [kind, target, name, value] of [['static', '/private', 'x-edge-token', secret], ['basic', '/basic', 'authorization', 'Basic ' + basic]] as const) {
    for (const state of ['missing', 'wrong', 'valid']) add(kind + '-' + state, 'auth', target, state === 'valid' ? 200 : 401,
      { profile: 'auth', headers: state === 'missing' ? {} : { [name]: state === 'valid' ? value : 'wrong' } });
  }
  for (const [name, target] of [['encoded', '/%70rivate'], ['slashes', '//private'], ['matrix', '/private;x=1'],
    ['matrix-double', '/private%253bx=1'], ['dot-segments', '/public/../private']])
    add('auth-bypass-' + name, 'auth', target, 401, { profile: 'auth' });
  add('auth-prefix-boundary', 'auth', '/private-other', 200, { profile: 'auth' });
  for (const valid of [false, true]) add('auth-deep-8KiB-' + valid, 'auth', ('/private/' + 'segment/'.repeat(1024)).slice(0, 8192), valid ? 200 : 401,
    { profile: 'auth', headers: valid ? { 'x-edge-token': secret } : {} });
  profile('auth-and', p => { p.routes = [
    { name: 'first', match: { path_prefixes: ['/private'] }, auth_gate: { type: 'static_token', token_env: 'TOKEN' } },
    { name: 'second', match: { path_prefixes: ['/private'] }, auth_gate: { type: 'basic_auth', credentials_env: 'BASIC' } },
  ]; });
  add('auth-and-second-denied', 'auth', '/private', 401, { profile: 'auth-and', headers: { 'x-edge-token': secret } });
  add('auth-and-valid', 'auth', '/private', 200, { profile: 'auth-and', headers: { 'x-edge-token': secret, authorization: 'Basic ' + basic } });
  profile('auth-missing-env', p => { p.routes = [{ name: 'missing', match: { path_prefixes: ['/private'] }, auth_gate: { type: 'static_token', token_env: 'MISSING' } }]; });
  add('auth-misconfigured', 'auth', '/private', 503, { profile: 'auth-missing-env' });
  profile('basic-missing-env', p => { p.routes = [{ name: 'missing', match: { path_prefixes: ['/basic'] }, auth_gate: { type: 'basic_auth', credentials_env: 'MISSING' } }]; });
  add('basic-misconfigured', 'auth', '/basic', 503, { profile: 'basic-missing-env' });

  const now = Math.floor(Date.now() / 1000), claims = { exp: now + 86400, iss: 'fixture', aud: 'fixture', sub: 'synthetic' };
  const jwt = (algorithm: string, payload: object, sign: (value: string) => string, kid = 'known') => {
    const data = [JSON.stringify({ alg: algorithm, kid }), JSON.stringify(payload)].map(v => Buffer.from(v).toString('base64url')).join('.');
    return data + '.' + sign(data);
  };
  for (const [id, token, status] of [
    ['valid', jwt('HS256', claims, hmac), 200],
    ['malformed', 'not.a.jwt', 401], ['missing', '', 401],
    ['alg-none', jwt('none', claims, () => ''), 401], ['alg-confusion', jwt('RS256', claims, hmac), 401],
    ['expired', jwt('HS256', { ...claims, exp: now - 60 }, hmac), 401],
    ['no-exp', jwt('HS256', { iss: 'fixture', aud: 'fixture' }, hmac), 401],
    ['future-nbf', jwt('HS256', { ...claims, nbf: now + 3600 }, hmac), 401],
    ['wrong-issuer', jwt('HS256', { ...claims, iss: 'other' }, hmac), 401],
    ['wrong-audience', jwt('HS256', { ...claims, aud: 'other' }, hmac), 401],
    ['wrong-signature', jwt('HS256', claims, () => 'invalid'), 401],
    ['audience-array', jwt('HS256', { ...claims, aud: ['other', 'fixture'] }, hmac), 200],
    ['payload-4KiB', jwt('HS256', { ...claims, padding: 'x'.repeat(4096) }, hmac), 200],
  ] as const) add('jwt-hs-' + id, 'jwt', '/hs', status, { profile: 'auth', headers: { authorization: 'Bearer ' + token } });
  const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicJwk = { ...keys.publicKey.export({ format: 'jwk' }), kid: 'known', alg: 'RS256' };
  const rsa = (value: string) => crypto.sign('sha256', Buffer.from(value), keys.privateKey).toString('base64url');
  const rsaToken = jwt('RS256', claims, rsa);
  for (const mode of ['ok', 'unknown', '5xx', 'redirect', 'bad-json', 'oversized', 'many-keys', 'hang', 'body-hang']) {
    const name = 'jwks-' + mode;
    profile(name, p => {
      p.routes = [{ name: 'rs', match: { path_prefixes: ['/rs'] }, auth_gate: { type: 'jwt', algorithm: 'RS256',
        jwks_url: 'https://jwks.example/jwks/' + mode, cache_ttl_sec: 3600, clock_skew_sec: 0, issuer: 'fixture', audience: 'fixture' } }];
      p.firewall = { jwks: { allowed_hosts: ['jwks.example'], negative_cache_sec: 60, stale_if_error_sec: 0 } };
    });
    add(name, 'jwks', '/rs', mode === 'ok' ? 200 : 401, { profile: name,
      headers: { authorization: 'Bearer ' + (mode === 'unknown' ? jwt('RS256', claims, rsa, 'unknown') : rsaToken) } });
  }
  add('jwt-rs-bad-signature', 'jwt', '/rs', 401, { profile: 'jwks-ok', headers: { authorization: 'Bearer ' + jwt('RS256', claims, () => 'a'.repeat(342)) } });
  profiles['jwks-flood'] = structuredClone(profiles['jwks-unknown']);
  profiles['jwks-flood'].policy.routes![0].auth_gate!.jwks_url = 'https://jwks.example/jwks/flood';
  add('jwks-unknown-kid-flood-128', 'jwks', '/rs', 401, { profile: 'jwks-flood',
    authorizationVariants: Array.from({ length: 128 }, (_, i) => 'Bearer ' + jwt('RS256', claims, rsa, 'random-' + i)) });
  profiles['jwks-cold-parallel'] = structuredClone(profiles['jwks-flood']);
  profiles['jwks-cold-parallel'].policy.routes![0].auth_gate!.jwks_url = 'https://jwks.example/jwks/cold-parallel';
  add('jwks-unknown-kid-cold-parallel', 'jwks', '/rs', 401, { profile: 'jwks-cold-parallel', coldBurst: true,
    authorizationVariants: Array.from({ length: 128 }, (_, i) => 'Bearer ' + jwt('RS256', claims, rsa, 'parallel-' + i)) });
  const replacementKeys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const replacementJwk = { ...replacementKeys.publicKey.export({ format: 'jwk' }), kid: 'known', alg: 'RS256' };
  for (const mode of ['stale', 'strict', 'rotation', 'replacement']) {
    profiles['jwks-' + mode] = structuredClone(profiles['jwks-ok']);
    profiles['jwks-' + mode].policy.routes![0].auth_gate!.jwks_url = 'https://jwks.example/jwks/' + mode;
    profiles['jwks-' + mode].policy.routes![0].auth_gate!.cache_ttl_sec = mode === 'rotation' ? 3600 : 1;
    profiles['jwks-' + mode].policy.firewall!.jwks!.stale_if_error_sec = mode === 'stale' ? 60 : 0;
    add('jwks-' + mode + '-seed', 'jwks-transition', '/rs', 200, { profile: 'jwks-' + mode, headers: { authorization: 'Bearer ' + rsaToken }, firstOnly: true });
    const token = mode === 'rotation' ? jwt('RS256', claims, rsa, 'rotated') : mode === 'replacement'
      ? jwt('RS256', claims, value => crypto.sign('sha256', Buffer.from(value), replacementKeys.privateKey).toString('base64url')) : rsaToken;
    add('jwks-' + mode + '-transition', 'jwks-transition', '/rs', mode === 'strict' ? 401 : 200,
      { profile: 'jwks-' + mode, headers: { authorization: 'Bearer ' + token }, firstOnly: mode === 'replacement',
        jwksTransition: { endpoint: mode, mode: ['stale', 'strict'].includes(mode) ? '5xx' : mode, waitMs: mode === 'rotation' ? 0 : 1100 } });
  }
  // Fresh services use the same unmodified module but independent caches. First-request cost is separate from warm samples.
  for (let i = 0; i < 16; i++) {
    profiles['jwks-cold-' + i] = profiles['jwks-ok'];
    add('jwks-cold-' + i, 'jwks-first-request', '/rs', 200,
      { profile: 'jwks-cold-' + i, headers: { authorization: 'Bearer ' + rsaToken }, firstOnly: true });
  }
  const nonce = 'synthetic_nonce_123456';
  const signed = (params: Record<string, string>, bad = false) => {
    const entries = Object.entries(params).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    const query = entries.map(([key, value]) => encodeURIComponent(key) + '=' + encodeURIComponent(value)).join('&');
    return '/signed?' + query + '&sig=' + (bad ? 'invalid' : hmac('/signed?' + query));
  };
  for (const [id, target, status] of [
    ['valid', signed({ exp: String(now + 86400), nonce }), 200],
    ['missing', '/signed', 403], ['expired', signed({ exp: String(now - 60), nonce }), 403],
    ['bad-signature', signed({ exp: String(now + 86400), nonce }, true), 403],
    ['missing-nonce', signed({ exp: String(now + 86400) }), 403],
    ['short-nonce', signed({ exp: String(now + 86400), nonce: 'short' }), 403],
  ] as const) add('signed-' + id, 'signed-url', target, status, { profile: 'auth' });

  for (const mode of ['block', 'report'] as const) profile('graphql-' + mode, p => {
    p.request!.graphql_guard = { endpoint_paths: ['/graphql'], max_body_bytes: 65536, max_depth: 4, max_aliases: 2, max_fields: 8, mode };
  });
  const graphql: Array<[string, string, boolean]> = [
    ['valid', '{ viewer { id } }', true], ['depth-at', '{ a { b { c { d } } } }', true],
    ['depth-over', '{ a { b { c { d { e } } } } }', false],
    ['aliases-at', '{ a:x b:y }', true], ['aliases-over', '{ a:x b:y c:z }', false],
    ['fields-at', '{ a b c d e f g h }', true], ['fields-over', '{ a b c d e f g h i }', false],
    ['malformed', '{ viewer {', false],
    ...[65535, 65536, 65537].map(n => ['body-' + n, '{ a'.padEnd(n - 1, ' ') + '}', n <= 65536] as [string, string, boolean]),
  ];
  for (const [id, body, valid] of graphql) add('graphql-' + id, 'graphql', '/graphql', valid ? 200 : 400,
    { profile: 'graphql-block', method: 'POST', body, headers: { 'content-type': 'application/graphql' } });
  add('graphql-invalid-json', 'graphql', '/graphql', 400, { profile: 'graphql-block', method: 'POST', body: '{', headers: { 'content-type': 'application/json' } });
  add('graphql-json-valid', 'graphql', '/graphql', 200, { profile: 'graphql-block', method: 'POST', body: JSON.stringify({ query: '{ viewer { id } }' }), headers: { 'content-type': 'application/json' } });
  add('graphql-report-oversized', 'graphql', '/graphql', 200, { profile: 'graphql-report', method: 'POST', body: '{ a'.padEnd(65536, ' ') + '}', headers: { 'content-type': 'application/graphql' } });

  for (const action of ['mask', 'block', 'report_only'] as const) {
    profile('dlp-' + action, p => { p.response_dlp = { enabled: true, action, mask: '[MASKED]',
      block_body: 'DLP blocked', body: { max_bytes: 65536, content_types: ['text/'] }, headers: { names: ['x-sensitive'] },
      detectors: { built_in: ['api_key', 'credit_card'], custom_regex: [{ name: 'fixture', pattern: 'TOKEN_[A-Z]{8}' }] } }; });
    for (const kind of ['clean', 'api-key', 'card-valid', 'card-invalid', 'custom', 'header'] as const) {
      const hit = !['clean', 'card-invalid'].includes(kind), blocked = hit && action === 'block';
      add('dlp-' + action + '-' + kind, 'dlp', '/dlp/' + kind + '/4096', blocked ? 451 : 200,
        { profile: 'dlp-' + action, forwarded: true,
          ...(blocked ? { responseBody: 'DLP blocked' } : hit && kind !== 'header' ?
            { responseIncludes: action === 'mask' ? '[MASKED]' : dlpValue(kind),
              ...(action === 'mask' ? { responseExcludes: dlpValue(kind) } : {}) } : {}),
          ...(kind === 'header' && !blocked ? { responseHeaders: { 'x-sensitive': action === 'mask' ? '[MASKED]' : dlpValue('api-key') } } : {}) });
    }
    for (const n of [65535, 65536, 65537]) {
      const inspect = n <= 65536, blocked = inspect && action === 'block';
      add('dlp-' + action + '-bytes-' + n, 'dlp', '/dlp/api-key/' + n, blocked ? 451 : 200,
        { profile: 'dlp-' + action, forwarded: true,
          ...(blocked ? { responseBody: 'DLP blocked' } : { responseIncludes: inspect && action === 'mask' ? '[MASKED]' : dlpValue('api-key') }) });
    }
  }
  for (const action of ['mask', 'block', 'report_only'] as const) for (const n of [65536, 65537])
    add('dlp-' + action + '-chunked-' + n, 'dlp', '/dlp/api-key/' + n + '?chunked=1', n <= 65536 && action === 'block' ? 451 : 200,
      { profile: 'dlp-' + action, forwarded: true,
        ...(n <= 65536 && action === 'block' ? { responseBody: 'DLP blocked' } : { responseIncludes: n <= 65536 && action === 'mask' ? '[MASKED]' : dlpValue('api-key') }) });
  const uaHash = sha(userAgent).slice(0, 16), exp = String(now + 86400);
  for (const mode of ['challenge', 'block', 'report'] as const) profile('challenge-' + mode, p => {
    p.firewall = { challenge: { enabled: true, mode, path_prefixes: ['/challenge'], difficulty: 1, secret_env: 'SECRET' } };
  });
  add('challenge-issued', 'challenge', '/challenge', 403, { profile: 'challenge-challenge', responseIncludes: '<!doctype html>' });
  add('challenge-post-denied', 'challenge', '/challenge', 403, { profile: 'challenge-challenge', method: 'POST', body: 'x' });
  add('challenge-invalid-cookie', 'challenge', '/challenge', 403, { profile: 'challenge-challenge', headers: { cookie: '__cdn_challenge=' + exp + '.wrong' } });
  add('challenge-valid-cookie', 'challenge', '/challenge', 200, { profile: 'challenge-challenge', headers: { cookie: '__cdn_challenge=' + exp + '.' + hmac(exp + ':' + uaHash) } });
  const seed = 'synthetic_seed_123456', proofExp = String(now + 3600);
  let proof = 0;
  while (!sha(seed + ':' + proof.toString(16)).startsWith('0')) proof++;
  const proofQuery = new URLSearchParams({ __cdn_challenge_seed: seed, __cdn_challenge_exp: proofExp,
    __cdn_challenge_nonce: proof.toString(16), __cdn_challenge_sig: hmac(seed + ':' + proofExp + ':' + uaHash) }).toString();
  add('challenge-valid-proof', 'challenge', '/challenge?' + proofQuery, 302,
    { profile: 'challenge-challenge', responseHeaders: { location: 'http://edge.example/challenge' } });
  add('challenge-invalid-proof', 'challenge', '/challenge?' + proofQuery.replace('__cdn_challenge_sig=', '__cdn_challenge_sig=wrong'), 403, { profile: 'challenge-challenge' });
  add('challenge-expired-cookie', 'challenge', '/challenge', 403, { profile: 'challenge-challenge', headers: { cookie: '__cdn_challenge=1.wrong' } });
  add('challenge-cookie-ua-mismatch', 'challenge', '/challenge', 403, { profile: 'challenge-challenge', headers: { 'user-agent': 'another-agent', cookie: '__cdn_challenge=' + exp + '.' + hmac(exp + ':' + uaHash) } });
  profiles['challenge-missing-env'] = structuredClone(profiles['challenge-challenge']);
  profiles['challenge-missing-env'].policy.firewall!.challenge!.secret_env = 'MISSING';
  add('challenge-misconfigured', 'challenge', '/challenge', 503, { profile: 'challenge-missing-env' });
  add('challenge-policy-block', 'challenge', '/challenge', 403, { profile: 'challenge-block' });
  add('challenge-policy-report', 'challenge', '/challenge', 200, { profile: 'challenge-report' });
  // The solved cookie exceeds the deliberately small anomaly-cookie fixture limit.
  profiles['challenge-challenge'].policy.request!.anomaly_guards!.max_cookie_bytes = 256;

  for (const kind of ['hmac', 'custom', 'missing'] as const) profile('origin-' + kind, p => {
    p.origin = { auth: kind === 'custom' ? { type: 'custom_header', secret_env: 'SECRET', header: 'X-Origin-Verify' }
      : { type: 'hmac_signature', secret_env: kind === 'missing' ? 'MISSING' : 'SECRET', include_body_hash: true } };
  });
  for (const n of [0, 1024, 1048576]) add('origin-hmac-' + n, 'origin-auth', '/public', 200,
    { profile: 'origin-hmac', method: 'POST', body: 'x'.repeat(n), originAuth: 'hmac' });
  add('origin-custom', 'origin-auth', '/public', 200, { profile: 'origin-custom', originAuth: 'custom' });
  add('origin-missing-secret', 'origin-auth', '/public', 503, { profile: 'origin-missing' });
  add('forwarding-spoofed-headers', 'origin-auth', '/public', 200, { headers: { 'x-forwarded-for': 'attacker', 'x-edge-authenticated': 'spoofed', te: 'trailers', 'proxy-authorization': 'fake' } });
  profile('response', p => {
    p.response_headers = { ...p.response_headers, csp_public: "script-src 'nonce-PLACEHOLDER'", csp_nonce: true,
      cookie_attributes: { secure: true, http_only: true, same_site: 'Lax' },
      clear_site_data_paths: ['/logout'], coop: 'same-origin', coep: 'require-corp', corp: 'same-origin',
      cors: { allow_origins: ['https://app.example'], allow_methods: ['GET', 'POST'], allow_credentials: true } };
  });
  add('response-security-headers', 'response', '/public', 200, { profile: 'response', responseHeaders: { 'cross-origin-opener-policy': 'same-origin' } });
  add('logout-cache-invalidation', 'response', '/logout', 200, { profile: 'response', responseHeaders: { 'cache-control': 'no-store', 'clear-site-data': '"cache", "cookies", "storage"' } });
  add('cors-preflight-allowed', 'response', '/public', 204, { profile: 'response', method: 'OPTIONS', responseHeaders: { 'access-control-allow-origin': 'https://app.example' }, headers: { origin: 'https://app.example', 'access-control-request-method': 'POST' } });
  add('cors-origin-unlisted', 'response', '/public', 200, { profile: 'response', headers: { origin: 'https://other.example' }, responseHeaders: { 'access-control-allow-origin': '' } });
  profile('monitor', p => { p.defaults!.mode = 'monitor'; });
  add('monitor-multiple-violations', 'observability', '/forbidden?q=%0d', 200, { profile: 'monitor', method: 'DELETE', headers: { 'user-agent': 'sqlmap' }, forwardedPath: '/forbidden?q=%0D' });
  profile('logging', p => { p.observability = { ...p.observability, sample_rate: 1 }; });
  add('logging-every-request', 'observability', '/public', 200, { profile: 'logging' });
  profile('combined', p => {
    p.routes = structuredClone(profiles.auth.policy.routes);
    p.request!.graphql_guard = { endpoint_paths: ['/hs'], max_body_bytes: 65536, max_fields: 50000 };
    p.origin = profiles['origin-hmac'].policy.origin;
    p.response_dlp = profiles['dlp-mask'].policy.response_dlp;
    p.response_headers = profiles.response.policy.response_headers;
    p.observability = { ...p.observability, sample_rate: 1, audit_log_auth: true, audit_hash_sub: true };
  });
  for (const valid of [true, false]) add('combined-graphql-jwt-origin-dlp-' + valid, 'combined', '/hs', valid ? 200 : 401,
    { profile: 'combined', method: 'POST', body: '{ a'.padEnd(65535, ' ') + '}',
      headers: { authorization: 'Bearer ' + jwt('HS256', claims, valid ? hmac : () => 'wrong'), 'content-type': 'application/graphql' },
      ...(valid ? { originAuth: 'hmac' as const } : {}) });
  for (const n of [0, 255]) add('regex-256-hit-' + n, 'pattern-scaling', '/blocked-' + n + '/item', 400, { profile: 'patterns' });
  add('regex-256-miss-8KiB', 'pattern-scaling', ('/public/' + 'segment/'.repeat(1024)).slice(0, 8192), 200, { profile: 'patterns' });
  profile('patterns', p => { p.request!.block!.path_patterns = { regex: Array.from({ length: 256 }, (_, i) => '/blocked-' + i + '/[a-z]+$') }; });
  for (const scenario of cases) {
    const gate = profiles[scenario.profile].policy.routes?.find(route => route.auth_gate?.jwks_url)?.auth_gate;
    if (!gate?.jwks_url) continue;
    const endpoint = new URL(gate.jwks_url).pathname.slice(6);
    const fetches = scenario.id === 'jwt-rs-bad-signature' ? 0 : ['unknown', 'flood', 'cold-parallel'].includes(endpoint) ? 2 : 1;
    scenario.jwksExpected = { endpoint, firstFetches: fetches, totalFetches: fetches };
  }
  return { profiles, cases, publicJwk, replacementJwk };
}

function requestHeaders(id: string): Record<string, string> {
  return { host: 'edge.example', 'user-agent': userAgent, 'x-required': 'present', 'x-bench-id': id, connection: 'keep-alive' };
}
function dlpValue(kind: string): string {
  return kind === 'api-key' ? 'sk-live-abcdefghijklmnop' : kind === 'card-valid' ? '4111 1111 1111 1111'
    : kind === 'card-invalid' ? '4111 1111 1111 1112' : kind === 'custom' ? 'TOKEN_ABCDEFGH' : 'clean';
}
function stats(samples: number[]) {
  assert.ok(samples.length > 0);
  const sorted = [...samples].sort((a, b) => a - b);
  const percentile = (p: number) => sorted[Math.max(0, Math.ceil(p * sorted.length) - 1)];
  return { count: sorted.length, min: sorted[0], median: percentile(.5), p95: percentile(.95), p99: percentile(.99), max: sorted.at(-1),
    mean: samples.reduce((a, b) => a + b, 0) / samples.length };
}

async function main() {
  const args = process.argv.slice(2), options: Record<string, string> = {};
  for (let i = 0; i < args.length; i += 2) {
    assert.ok(['--output', '--samples', '--warmup', '--concurrency', '--only', '--compiler-root', '--diagnostics', '--agent-scope'].includes(args[i]), 'Unknown argument: ' + args[i]);
    assert.ok(args[i + 1] && !args[i + 1].startsWith('--'), args[i] + ' requires a value');
    assert.equal(options[args[i]], undefined, 'Duplicate option: ' + args[i]); options[args[i]] = args[i + 1];
  }
  assert.ok(options['--output'], '--output is required');
  const number = (key: string, fallback: number, min: number, max: number) => {
    const value = options[key] === undefined ? fallback : Number(options[key]);
    assert.ok(Number.isSafeInteger(value) && value >= min && value <= max, key + ' out of bounds'); return value;
  };
  const samples = number('--samples', 1000, 1, 10000), warmup = number('--warmup', 200, 0, 2000);
  const concurrency = number('--concurrency', 1, 1, 32);
  const data = fixtures(), matches = data.cases.filter(c => !options['--only'] || c.id.startsWith(options['--only']));
  assert.ok(matches.length > 0, 'Unknown workload selector');
  const selected = data.cases.filter(c => matches.includes(c) || matches.some(m => m.jwksTransition && c.id === m.profile + '-seed'));
  const root = path.resolve(__dirname, '..'), output = path.resolve(options['--output']);
  const compilerRoot = path.resolve(options['--compiler-root'] || root);
  const diagnostics = options['--diagnostics'] === 'true';
  assert.ok(options['--diagnostics'] === undefined || ['true', 'false'].includes(options['--diagnostics']), 'Invalid --diagnostics');
  const agentScope = options['--agent-scope'] || 'all';
  assert.ok(['all', 'profile'].includes(agentScope), 'Invalid --agent-scope');
  const compiler: typeof import('./compile-cloudflare') = require(path.join(compilerRoot, 'scripts/compile-cloudflare'));
  const validator: typeof import('../validator') = require(path.join(compilerRoot, 'validator'));
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-security-bench-'));
  const agent = new http.Agent({ keepAlive: true, maxSockets: concurrency });
  const generated: Record<string, unknown>[] = [], results: Record<string, unknown>[] = [];
  const arrivals = new Map<string, number>(), jwksCalls = new Map<string, number>();
  const jwksModes = new Map(['stale', 'strict', 'rotation', 'replacement'].map(id => [id, 'ok']));
  const observedResponses = new Map<string, { status: number; bytes: number; bodySha256: string; rejectionBody?: string }>();
  const observedEvents = new Map<string, { event: string; reason: string }[]>();
  const expected = new Map(selected.map(c => [c.id, c]));
  const expectedHashes = new Map(selected.map(c => [c.id, sha(c.body || '')]));
  const originTimings = new Map<string, Array<{ readMs: number; verificationMs: number }>>();
  const eventLoop = monitorEventLoopDelay({ resolution: 1 });
  const gc: Array<{ at: number; duration: number }> = [];
  const gcObserver = new PerformanceObserver(list => { for (const entry of list.getEntries()) gc.push({ at: entry.startTime, duration: entry.duration }); });
  if (diagnostics) { eventLoop.enable(); gcObserver.observe({ entryTypes: ['gc'] }); }
  let originError: unknown, runtime: ChildProcess | undefined, closed: Promise<unknown> | undefined, runtimeLog = '', failure: unknown;
  const controller = new AbortController(), abort = () => controller.abort(new Error('Benchmark interrupted'));
  process.once('SIGTERM', abort); process.once('SIGINT', abort);
  const watchdog = setTimeout(() => controller.abort(new Error('Benchmark exceeded ten-minute bound')), 600000);
  const cleanup = { runtimeExited: false, originClosed: false, tempRemoved: false };
  const origin = http.createServer(async (req, res) => {
    try {
      if (req.url?.startsWith('/jwks/')) {
        const endpoint = req.url.slice(6), mode = jwksModes.get(endpoint) || endpoint;
        jwksCalls.set(endpoint, (jwksCalls.get(endpoint) || 0) + 1);
        if (mode === 'hang') return;
        if (mode === 'body-hang') { res.writeHead(200, { 'content-type': 'application/json' }); res.flushHeaders(); res.write('{"keys":'); return; }
        if (mode === 'redirect') { res.writeHead(302, { location: 'http://169.254.169.254/metadata' }); res.end(); return; }
        if (mode === '5xx') { res.writeHead(503); res.end('synthetic outage'); return; }
        res.setHeader('content-type', 'application/json');
        res.end(mode === 'bad-json' ? '{' : mode === 'oversized' ? 'x'.repeat(262145)
          : JSON.stringify({ keys: mode === 'many-keys' ? Array(101).fill(data.publicJwk) : mode === 'rotation'
            ? [{ ...data.publicJwk, kid: 'rotated' }] : [mode === 'replacement' ? data.replacementJwk : data.publicJwk] })); return;
      }
      const id = String(req.headers['x-bench-id']), scenario = expected.get(id);
      assert.ok(scenario?.forwarded, 'Unexpected origin arrival: ' + id + ' ' + req.url);
      const started = performance.now();
      const chunks: Buffer[] = []; let received = 0;
      for await (const chunk of req) { received += chunk.length; assert.ok(received <= 1048576, 'Origin request budget'); chunks.push(chunk); }
      const body = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks), readAt = performance.now();
      const bodyHash = sha(body);
      assert.equal(req.url, scenario.forwardedPath || scenario.target);
      assert.equal(req.method, scenario.method || 'GET');
      assert.equal(bodyHash, expectedHashes.get(id), 'Forwarded body changed');
      for (const header of ['x-forwarded-for', 'x-edge-authenticated', 'te', 'proxy-authorization']) assert.equal(req.headers[header], undefined);
      if (scenario.originAuth === 'custom') assert.equal(req.headers['x-origin-verify'], secret);
      if (scenario.originAuth === 'hmac') {
        const url = new URL(req.url!, 'http://edge.example');
        const query = [...url.searchParams].sort(([a, av], [b, bv]) => a < b ? -1 : a > b ? 1 : av < bv ? -1 : av > bv ? 1 : 0)
          .map(([key, value]) => encodeURIComponent(key) + '=' + encodeURIComponent(value)).join('&');
        assert.equal(req.headers['x-cdn-auth-body-sha256'], bodyHash);
        assert.equal(req.headers['x-cdn-auth-signature'], hmac([req.method, url.pathname, query, bodyHash, req.headers['x-cdn-auth-timestamp'], req.headers['x-cdn-auth-nonce']].join('\n')));
      }
      if (diagnostics) { const timings = originTimings.get(id) || []; timings.push({ readMs: readAt - started, verificationMs: performance.now() - readAt }); originTimings.set(id, timings); }
      arrivals.set(id, (arrivals.get(id) || 0) + 1);
      res.setHeader('content-type', 'text/plain'); res.setHeader('set-cookie', 'fixture=1');
      if (req.url === '/origin-error') { res.writeHead(503); res.end('synthetic-origin-failure'); }
      else if (req.url?.startsWith('/dlp/')) {
        const url = new URL(req.url, 'http://edge.example');
        const [, , kind, size] = url.pathname.split('/');
        if (kind === 'header') res.setHeader('x-sensitive', dlpValue('api-key'));
        const body = dlpValue(kind).padEnd(Number(size), ' ');
        if (url.searchParams.has('chunked')) { res.write(body.slice(0, 128)); res.end(body.slice(128)); }
        else res.end(body);
      } else res.end('origin-ok');
    } catch (error) { originError = error; controller.abort(error); res.destroy(); }
  });
  const record: Record<string, unknown> = { schemaVersion: 1, startedAt: new Date().toISOString(), metric: 'loopback HTTP wall time through response drain; not Worker CPU',
    samples, warmup, concurrency, results, generated, cleanup, compilerRoot, diagnostics, agentScope,
    environment: { node: process.version, platform: process.platform, arch: process.arch, osRelease: os.release(), cpu: os.cpus()[0]?.model, cpuCount: os.cpus().length,
      workerd: require('workerd/package.json').version, compatibilityDate: '2026-07-20' },
    head: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(),
    driverSha256: sha(fs.readFileSync(__filename)), packageLockSha256: sha(fs.readFileSync(path.join(root, 'package-lock.json'))),
    compilerSourceManifest: ['src/scripts/compile-cloudflare.ts', 'templates/cloudflare/index.ts', 'src/scripts/lib/edge-cfg.ts',
      'src/scripts/lib/template-inject.ts', 'src/scripts/lib/path-index.ts', 'src/scripts/lib/path-regex.ts', 'policy/schema.json']
      .map(file => ({ path: file, sha256: fs.existsSync(path.join(compilerRoot, file)) ? sha(fs.readFileSync(path.join(compilerRoot, file))) : null })),
    sourceManifest: ['src/scripts/benchmark-edge-security.ts', 'src/scripts/compile-cloudflare.ts', 'templates/cloudflare/index.ts',
      'src/scripts/lib/edge-cfg.ts', 'src/scripts/lib/template-inject.ts', 'src/scripts/lib/path-index.ts', 'policy/schema.json']
      .map(file => ({ path: file, sha256: sha(fs.readFileSync(path.join(root, file))) })),
    runtimeSha256: sha(fs.readFileSync(require('workerd').default)),
    unmeasured: ['managed CDN PoP/network/TLS', 'provider WAF/rate limits/IP reputation/JA3/JA4', 'CloudFront native CPU',
      'browser proof-of-work solving', 'unbounded input space', 'slow-drip/long-lived streaming clients', 'sustained open-loop saturation'] };
  try {
    origin.listen(0, '127.0.0.1'); await once(origin, 'listening', { signal: controller.signal });
    const originPort = (origin.address() as net.AddressInfo).port;
    const variants = new Map<string, number>();
    for (const id of new Set(selected.map(c => c.profile))) {
      const profile = data.profiles[id], env = { TOKEN: secret, BASIC: Buffer.from('user:password').toString('base64'), SECRET: secret };
      const validation = validator.validatePolicy({ policy: profile.policy, pkgRoot: compilerRoot, env });
      assert.ok(validation.ok, id + ': ' + validation.errors.join('; '));
      const dir = path.join(temp, id);
      const file = compiler.compileCloudflare(profile.policy, { rootDir: compilerRoot, outDir: dir, logger: { log() {}, warn() {}, error() {} } });
      const source = fs.readFileSync(file, 'utf8');
      const module = transformSync(source, { loader: 'ts', format: 'esm', target: 'es2022' }).code;
      fs.writeFileSync(path.join(temp, id + '.mjs'), module);
      const reservation = net.createServer(); reservation.listen(0, '127.0.0.1'); await once(reservation, 'listening');
      const port = (reservation.address() as net.AddressInfo).port;
      await new Promise<void>((resolve, reject) => reservation.close(error => error ? reject(error) : resolve()));
      variants.set(id, port);
      generated.push({ profile: id, policy: profile.policy, policySha256: sha(JSON.stringify(profile.policy)),
        sourceSha256: sha(source), moduleSha256: sha(module), moduleBytes: Buffer.byteLength(module) });
    }
    const config = `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (services = [
${[...variants.keys()].map(id => `(name = "${id}", worker = (modules = [(name = "${id}.mjs", esModule = embed "${id}.mjs")], compatibilityDate = "2026-07-20", bindings = [(name = "TOKEN", text = "${secret}"), (name = "SECRET", text = "${secret}"), (name = "BASIC", text = "${Buffer.from('user:password').toString('base64')}")], globalOutbound = "origin")),`).join('\n')}
(name = "origin", external = (address = "127.0.0.1:${originPort}", http = ())),
(name = "internet", network = (allow = [], deny = ["0.0.0.0/0", "::/0"]))], sockets = [
${[...variants].map(([id, port]) => `(name = "${id}", address = "127.0.0.1:${port}", http = (cfBlobHeader = "x-bench-cf"), service = "${id}")`).join(',\n')}]);`;
    fs.writeFileSync(path.join(temp, 'config.capnp'), config);
    record.configSha256 = sha(config); record.outbound = 'all Worker fetches -> loopback fixture, no network service binding';
    runtime = spawn(require('workerd').default, ['serve', 'config.capnp'], { cwd: temp, env: { PATH: process.env.PATH, TMPDIR: temp }, stdio: ['ignore', 'pipe', 'pipe'] });
    closed = once(runtime, 'close');
    const pendingLogs = { stdout: '', stderr: '' };
    const capture = (stream: keyof typeof pendingLogs, chunk: Buffer) => {
      runtimeLog = (runtimeLog + chunk).slice(-65536); pendingLogs[stream] += chunk;
      const lines = pendingLogs[stream].split('\n'); pendingLogs[stream] = lines.pop()!;
      for (const line of lines) {
        const text = line.slice(line.indexOf('{'));
        if (!text.startsWith('{')) continue;
        let event: { correlation_id?: string; event?: string; block_reason?: string };
        try { event = JSON.parse(text); } catch { continue; }
        if (!event.correlation_id || !expected.has(event.correlation_id)) continue;
        const events = observedEvents.get(event.correlation_id) || [];
        if (event.event && event.block_reason && !events.some(old => old.event === event.event && old.reason === event.block_reason)) {
          events.push({ event: event.event, reason: event.block_reason }); observedEvents.set(event.correlation_id, events);
        }
      }
    };
    runtime.stdout!.on('data', chunk => capture('stdout', chunk));
    runtime.stderr!.on('data', chunk => capture('stderr', chunk));
    const firstPort = variants.values().next().value!;
    let ready = false;
    for (let i = 0; i < 200 && !ready; i++) {
      controller.signal.throwIfAborted(); assert.equal(runtime.exitCode, null, runtimeLog);
      ready = await new Promise<boolean>(resolve => { const socket = net.connect(firstPort, '127.0.0.1');
        socket.on('connect', () => { socket.destroy(); resolve(true); }); socket.on('error', () => { socket.destroy(); resolve(false); }); });
      if (!ready) await new Promise(resolve => setTimeout(resolve, 25));
    }
    assert.ok(ready, 'workerd readiness deadline: ' + runtimeLog);
    const ordinals = new Map<string, number>();
    const send = (scenario: Scenario): Promise<number> => {
      if (scenario.rawParser) return new Promise((resolve, reject) => {
        const start = performance.now(), socket = net.connect(variants.get(scenario.profile)!, '127.0.0.1');
        let response = '';
        socket.setTimeout(6000, () => socket.destroy(new Error('Parser request deadline')));
        const onAbort = () => socket.destroy(new Error('Parser request aborted'));
        controller.signal.addEventListener('abort', onAbort, { once: true });
        socket.on('connect', () => socket.end('GET /public HTTP/1.1\r\nHost: edge.example\r\nx-bad: a\0b\r\nConnection: close\r\n\r\n'));
        socket.on('data', chunk => { response += chunk; }); socket.on('error', reject);
        socket.on('close', () => { controller.signal.removeEventListener('abort', onAbort);
          try { assert.match(response, /^HTTP\/1\.1 400 /); resolve(performance.now() - start); } catch (error) { reject(error); } });
      });
      return new Promise((resolve, reject) => {
      const headers: Record<string, string | undefined> = { ...requestHeaders(scenario.id), ...scenario.headers };
      if (scenario.authorizationVariants) {
        const ordinal = ordinals.get(scenario.id) || 0; ordinals.set(scenario.id, ordinal + 1);
        headers.authorization = scenario.authorizationVariants[ordinal % scenario.authorizationVariants.length];
      }
      for (const key of Object.keys(headers)) if (headers[key] === undefined) delete headers[key];
      const start = performance.now();
      const request = http.request({ hostname: '127.0.0.1', port: variants.get(scenario.profile), path: scenario.target,
        method: scenario.method || 'GET', headers, agent, signal: controller.signal }, response => {
        const chunks: Buffer[] = [];
        let received = 0;
        response.on('data', chunk => { received += chunk.length;
          if (received > 262144) response.destroy(new Error('Response budget exceeded')); else chunks.push(Buffer.from(chunk)); });
        response.on('error', reject);
        response.on('end', () => {
          const elapsed = performance.now() - start;
          try {
            const body = Buffer.concat(chunks).toString();
            if (!observedResponses.has(scenario.id)) observedResponses.set(scenario.id, { status: response.statusCode!, bytes: Buffer.byteLength(body),
              bodySha256: sha(body), rejectionBody: scenario.status >= 400 && body.length <= 256 ? body : undefined });
            assert.equal(response.statusCode, scenario.status, scenario.id + ': ' + body.slice(0, 250));
            if (scenario.responseBody !== undefined) assert.equal(body, scenario.responseBody, scenario.id);
            if (scenario.responseIncludes) assert.ok(body.includes(scenario.responseIncludes), scenario.id + ': response content');
            if (scenario.responseExcludes) assert.ok(!body.includes(scenario.responseExcludes), scenario.id + ': leaked response');
            for (const [key, value] of Object.entries(scenario.responseHeaders || {})) assert.equal(response.headers[key] || '', value, scenario.id + ': ' + key);
            resolve(elapsed);
          } catch (error) { reject(error); }
        });
      });
      const timer = setTimeout(() => request.destroy(new Error(scenario.id + ': request deadline')), 6000);
      request.once('close', () => clearTimeout(timer)); request.on('error', reject);
      if (scenario.chunked && scenario.body) { request.write(scenario.body.slice(0, 128)); request.end(scenario.body.slice(128)); }
      else request.end(scenario.body);
      });
    };
    const usedServices = new Set<string>();
    let previousProfile = '';
    for (const scenario of selected) {
      controller.signal.throwIfAborted();
      if (agentScope === 'profile' && previousProfile !== scenario.profile) agent.destroy();
      previousProfile = scenario.profile;
      if (scenario.jwksTransition) {
        await new Promise<void>((resolve, reject) => {
          const done = () => { controller.signal.removeEventListener('abort', interrupted); resolve(); };
          const timer = setTimeout(done, scenario.jwksTransition!.waitMs);
          const interrupted = () => { clearTimeout(timer); reject(controller.signal.reason); };
          controller.signal.addEventListener('abort', interrupted, { once: true });
        });
        jwksModes.set(scenario.jwksTransition.endpoint, scenario.jwksTransition.mode);
      }
      const firstUseOfService = !usedServices.has(scenario.profile); usedServices.add(scenario.profile);
      const before = arrivals.get(scenario.id) || 0;
      const jwksBefore = Object.fromEntries(jwksCalls);
      const caseStart = performance.now();
      const firstRequestsMs = await Promise.all(Array.from({ length: scenario.coldBurst ? concurrency : 1 }, () => send(scenario)));
      const firstRequestMs = firstRequestsMs[0];
      const endpoint = scenario.jwksExpected?.endpoint;
      const firstFetches = endpoint ? (jwksCalls.get(endpoint) || 0) - (jwksBefore[endpoint] || 0) : 0;
      if (scenario.jwksExpected) assert.equal(firstFetches, scenario.jwksExpected.firstFetches, scenario.id + ': first JWKS fetches');
      const actualWarmup = scenario.firstOnly ? 0 : warmup, count = scenario.firstOnly ? 0 : samples;
      for (let i = 0; i < actualWarmup; i++) await send(scenario);
      const durations: number[] = [], cpu = process.cpuUsage(), start = performance.now();
      eventLoop.reset();
      const originTimingStart = originTimings.get(scenario.id)?.length || 0;
      // Closed-loop load: at most `concurrency` outstanding requests, with an exact shared request budget.
      let next = 0;
      await Promise.all(Array.from({ length: Math.min(concurrency, count) }, async () => {
        while (next++ < count) durations.push(await send(scenario));
      }));
      const batchElapsedMs = performance.now() - start;
      if (diagnostics) await new Promise<void>(resolve => setImmediate(resolve));
      assert.equal(arrivals.get(scenario.id) || 0, before + (scenario.forwarded ? firstRequestsMs.length + actualWarmup + count : 0), scenario.id + ': origin count');
      assert.equal(originError, undefined);
      if (scenario.jwksExpected) {
        assert.ok(performance.now() - caseStart < 5000, scenario.id + ': measurement must remain in one JWKS refresh window');
        assert.equal((jwksCalls.get(endpoint!) || 0) - (jwksBefore[endpoint!] || 0), scenario.jwksExpected.totalFetches, scenario.id + ': total JWKS fetches');
      }
      if (!scenario.forwarded && scenario.status >= 400 && !scenario.rawParser) {
        for (let i = 0; i < 50 && !observedEvents.has(scenario.id); i++) await new Promise(resolve => setTimeout(resolve, 1));
        assert.ok(observedEvents.has(scenario.id), scenario.id + ': missing Worker rejection reason');
      }
      const item = { id: scenario.id, group: scenario.group, profile: scenario.profile, expectedStatus: scenario.status,
        forwarded: scenario.forwarded, method: scenario.method || 'GET', pathBytes: Buffer.byteLength(scenario.target),
        requestTarget: scenario.group === 'signed-url' ? scenario.target.replace(/sig=[^&]*/, 'sig=[synthetic signature]') : scenario.target,
        observedResponse: observedResponses.get(scenario.id), rotatingCredentials: scenario.authorizationVariants?.length,
        observedEvents: observedEvents.get(scenario.id), firstRequestsMs, firstBurstSize: firstRequestsMs.length,
        requestBodyBytes: Buffer.byteLength(scenario.body || ''), firstRequestMs, freshService: firstUseOfService, firstOnly: scenario.firstOnly === true,
        firstUseOfService, setupWaitMs: scenario.jwksTransition?.waitMs || 0,
        warmup: actualWarmup, samplesMs: durations, summaryMs: durations.length ? stats(durations) : undefined,
        batchElapsedMs, throughputRps: count ? count * 1000 / batchElapsedMs : undefined,
        clientOriginCpuMicros: process.cpuUsage(cpu), originArrivals: (arrivals.get(scenario.id) || 0) - before,
        diagnostic: diagnostics ? { eventLoopMs: { p95: eventLoop.percentile(95) / 1e6, max: eventLoop.max / 1e6 },
          gc: gc.filter(entry => entry.at >= start && entry.at <= start + batchElapsedMs),
          originTimings: originTimings.get(scenario.id)?.slice(originTimingStart),
          freeSockets: Object.values(agent.freeSockets).reduce((sum, sockets) => sum + (sockets?.length || 0), 0) } : undefined,
        jwksFetchesBefore: jwksBefore, jwksFetchesAfter: Object.fromEntries(jwksCalls), status: 'passed' };
      results.push(item); console.log(JSON.stringify({ id: scenario.id, firstRequestMs, ...item.summaryMs, status: 'passed' }));
    }
    record.status = 'passed';
  } catch (error) {
    failure = originError || error; record.status = 'failed'; record.error = String(failure); process.exitCode = 1;
  } finally {
    clearTimeout(watchdog); process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); agent.destroy();
    eventLoop.disable(); gcObserver.disconnect();
    if (runtime && closed) {
      runtime.kill('SIGTERM'); const timer = setTimeout(() => runtime?.kill('SIGKILL'), 3000);
      try { await closed; } catch (error) { failure ||= error; } finally { clearTimeout(timer); }
      cleanup.runtimeExited = runtime.exitCode !== null || runtime.signalCode !== null;
    } else cleanup.runtimeExited = true;
    origin.closeAllConnections();
    if (origin.listening) await new Promise<void>((resolve, reject) => origin.close(error => error ? reject(error) : resolve()));
    cleanup.originClosed = !origin.listening;
    fs.rmSync(temp, { recursive: true, force: true }); cleanup.tempRemoved = !fs.existsSync(temp);
    record.runtimeLogTail = failure ? runtimeLog : undefined;
    record.endedAt = new Date().toISOString();
    if (failure || !Object.values(cleanup).every(Boolean)) { record.status = 'failed'; process.exitCode = 1; }
    fs.mkdirSync(path.dirname(output), { recursive: true }); fs.writeFileSync(output, JSON.stringify(record, null, 2));
  }
  console.log(JSON.stringify({ status: record.status, error: record.error, cases: results.length, cleanup }));
}

if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
