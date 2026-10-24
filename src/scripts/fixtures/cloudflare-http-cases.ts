import type { HttpArtifactCase } from '../../contract/verification/artifact-http';
export const HTTP_FIXTURE_POLICY = `version: 2
project: http-e2e
defaults: { mode: enforce }
request:
  allow_methods: [GET, POST]
  limits: { max_uri_length: 200 }
  block:
    header_missing: [x-required]
    ua_contains: [sqlmap]
    path_patterns: { contains: ['/../'] }
  normalize:
    drop_query_keys: [utm_source]
  graphql_guard:
    endpoint_paths: [/graphql]
    max_body_bytes: 1024
    mode: report
response_dlp:
  enabled: true
  action: mask
  body: { max_bytes: 1024, content_types: [application/json] }
routes:
  - name: admin
    match: { path_prefixes: [/admin, ${Array.from({ length: 31 }, (_, i) => '/unused-admin' + i).join(', ')}] }
    auth_gate: { type: static_token, header: x-edge-token, token_env: EDGE_ADMIN_TOKEN }
    response: { cache_control: no-store }
${['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'].map(endpoint => `  - name: jwt-${endpoint}
    match: { path_prefixes: [/jwt-${endpoint}] }
    auth_gate: { type: jwt, algorithm: RS256, jwks_url: 'https://jwks.example.com/jwks/${endpoint}', issuer: synthetic, audience: synthetic, cache_ttl_sec: ${['c', 'd'].includes(endpoint) ? 1 : endpoint === 'h' ? 3 : 3600} }
    response: { cache_control: no-store }`).join('\n')}
  - name: jwt-short
    match: { path_prefixes: [/jwt-short] }
    auth_gate: { type: jwt, algorithm: RS256, jwks_url: 'https://jwks.example.com/jwks/h', issuer: synthetic, audience: synthetic, cache_ttl_sec: 1 }
firewall:
  jwks: { allowed_hosts: [jwks.example.com], negative_cache_sec: 1, stale_if_error_sec: 2 }
response_headers:
  hsts: max-age=100
  x_content_type_options: nosniff
  referrer_policy: same-origin
observability: { log_format: json, correlation_id_header: x-e2e-id, sample_rate: 1 }
`;
export const HTTP_FIXTURE_HEADERS: Readonly<Record<string, string>> = Object.freeze({ 'user-agent': 'http-e2e', 'x-required': 'present' });
function cases(): HttpArtifactCase[] {
    const tests: HttpArtifactCase[] = [
        { id: 'public', artifact: true, publicResponse: true, target: '/public?keep=1&utm_source=discard', status: 200, forwarded: '/public?keep=1' },
        { id: 'post', artifact: true, publicResponse: true, target: '/echo', method: 'POST', body: '{"synthetic":true}', headers: { 'content-type': 'application/json', 'x-forwarded-for': 'spoofed', 'x-edge-authenticated': 'spoofed' }, status: 200, forwarded: '/echo' },
        { id: 'graphql-oversized-report', target: '/graphql', method: 'POST', body: JSON.stringify({ query: '{ viewer { id } }', padding: 'x'.repeat(2048) }), headers: { 'content-type': 'application/json' }, status: 200, forwarded: '/graphql' },
        { id: 'dlp-oversized-pass-through', target: '/echo', method: 'POST', body: JSON.stringify({ value: 'sk-live-abcdefghijklmnop', padding: 'x'.repeat(2048) }), headers: { 'content-type': 'application/json' }, status: 200, forwarded: '/echo' },
        { id: 'admin-missing', artifact: true, target: '/admin', status: 401, reason: 'Unauthorized' },
        { id: 'admin-wrong', artifact: true, target: '/admin', credential: 'wrong', status: 401, reason: 'Unauthorized' },
        { id: 'admin-valid', artifact: true, protectedResponse: true, target: '/admin', credential: 'valid', status: 200, forwarded: '/admin' },
        { id: 'encoded-admin', artifact: true, target: '/%61dmin', status: 401, reason: 'Unauthorized' },
        { id: 'matrix-admin', artifact: true, target: '/admin;x=1', status: 401, reason: 'Unauthorized' },
        { id: 'slashes-admin', artifact: true, target: '//admin', status: 401, reason: 'Unauthorized' },
        { id: 'encoded-slash', target: '/admin%2fchild', status: 400, reason: 'Bad Request' },
        // workerd's Request URL removes dot segments before the Worker sees them.
        // The canonical protected destination must still reject unauthenticated access.
        { id: 'dot-admin', artifact: true, workerUri: '/admin', target: '/public/../admin', status: 401, reason: 'Unauthorized' },
        { id: 'method', target: '/public', method: 'DELETE', status: 405, reason: 'Method Not Allowed' },
        { id: 'uri-length', target: '/' + 'a'.repeat(210), status: 414, reason: 'URI Too Long' },
        { id: 'missing-header', target: '/public', headers: { 'x-required': undefined }, status: 400, reason: 'Missing x-required' },
        { id: 'user-agent', target: '/public', headers: { 'user-agent': 'sqlmap' }, status: 403, reason: 'Forbidden' },
        { id: 'origin-error', target: '/origin-error', status: 503, forwarded: '/origin-error' },
    ];
    // Literal destinations are the contract, not a copy of the normalizer.
    const matrixPaths = [
        ['raw-root', '/admin;x=1', '/admin'],
        ['encoded-root', '/admin%3bx=1', '/admin'],
        ['double-root', '/admin%253bx=1', '/admin'],
        ['raw-child', '/admin;x=1/child;y=2', '/admin/child'],
        ['encoded-child', '/admin%3bx=1/child%3by=2', '/admin/child'],
        ['double-child', '/admin%253bx=1/child%253by=2', '/admin/child'],
        ['triple-root', '/admin%25253bx=1', '/admin'],
    ];
    for (const [name, target, destination] of matrixPaths) {
        for (const auth of ['missing', 'wrong', 'valid']) {
            tests.push({ id: 'matrix-' + name + '-' + auth, target,
                credential: auth === 'missing' ? 'absent' : auth as 'wrong' | 'valid', artifact: true,
                status: auth === 'valid' ? 200 : 401,
                ...(auth === 'valid' ? { forwarded: destination, protectedResponse: true } : { reason: 'Unauthorized' }),
            });
        }
    }
    tests.push({ id: 'matrix-query-post', artifact: true, target: '/admin%253bx=1/child%253by=2?keep=1&utm_source=discard', method: 'POST', body: '{"synthetic":true}', credential: 'valid', headers: { 'content-type': 'application/json' }, status: 200, forwarded: '/admin/child?keep=1', protectedResponse: true }, { id: 'prefix-boundary', artifact: true, target: '/administrator', status: 200, forwarded: '/administrator', publicResponse: true }, { id: 'matrix-prefix-boundary', artifact: true, target: '/administrator%3bx=1', status: 200, forwarded: '/administrator', publicResponse: true }, { id: 'matrix-invalid-encoding', target: '/admin%3bx=%ZZ', status: 400, reason: 'Bad Request' }, { id: 'matrix-decode-overflow', target: '/admin%2525253bx=1', status: 400, reason: 'Bad Request' }, { id: 'matrix-ambiguous-encoding', target: '/admin%3bx=1%2fchild', status: 400, reason: 'Bad Request' });
    for (const auth of ['missing', 'wrong', 'valid'] as const)
        tests.push({
            id: 'admin-child-' + auth, target: '/admin/child', artifact: true,
            credential: auth === 'missing' ? 'absent' : auth, status: auth === 'valid' ? 200 : 401,
            ...(auth === 'valid' ? { forwarded: '/admin/child', protectedResponse: true } : { reason: 'Unauthorized' }),
        });
    return tests.map(test => ({ ...test, headers: { ...HTTP_FIXTURE_HEADERS, ...test.headers } }));
}
function freeze<T>(value: T): T { if (value && typeof value === 'object') {
    for (const v of Object.values(value))
        freeze(v);
    Object.freeze(value);
} return value; }
// Fixed before compilation; no generated handler or normalizer supplies these literals.
export const HTTP_FIXTURE_CASES: readonly HttpArtifactCase[] = freeze(cases());
