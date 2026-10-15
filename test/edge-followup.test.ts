import crypto from 'node:crypto';
import { expect, test, vi } from 'vitest';
import { generatedWorker } from './helpers/generated-worker';
import { buildPathIndex, PATH_INDEX_HELPER } from '../src/scripts/lib/path-index';

test('DLP header rejection cancels an unfinished origin body without waiting for cancellation', async () => {
  const cancel = vi.fn(() => new Promise<void>(() => {}));
  const { handler } = generatedWorker({ response_dlp: { enabled: true, action: 'block',
    headers: { enabled: true, names: ['x-sensitive'] } } }, async () => new Response(
    new ReadableStream({ cancel }), { headers: { 'x-sensitive': 'sk-live-abcdefghijklmnop' } }));
  const response = await handler.fetch(new Request('https://edge.example/public', { headers: { 'user-agent': 'test' } }), {});
  expect(response.status).toBe(451);
  expect(await response.text()).toBe('Response blocked by edge DLP');
  expect(cancel).toHaveBeenCalledTimes(1);
});

test.each([302, 500])('JWKS status %i cancels the discarded response and fails closed', async (status) => {
  const cancel = vi.fn();
  const origin = vi.fn(async () => new Response(new ReadableStream({ cancel }), { status }));
  const { handler } = generatedWorker({ routes: [{ name: 'rsa', match: { path_prefixes: ['/private'] },
    auth_gate: { type: 'jwt', algorithm: 'RS256', jwks_url: 'https://id.example/jwks' } }],
    firewall: { jwks: { allowed_hosts: ['id.example'] } } }, origin);
  const jwt = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'key' })).toString('base64url') + '.'
    + Buffer.from(JSON.stringify({ exp: 4102444800 })).toString('base64url') + '.YWJj';
  const response = await handler.fetch(new Request('https://edge.example/private', {
    headers: { authorization: 'Bearer ' + jwt, 'user-agent': 'test' } }), {});
  expect(response.status).toBe(401);
  expect(cancel).toHaveBeenCalledTimes(1);
  expect(origin).toHaveBeenCalledTimes(1);
});

test('many routes preserve overlapping authentication order, segment boundaries and response cache protection', async () => {
  const routes = Array.from({ length: 100 }, (_, i) => ({ name: `r${i}`, match: { path_prefixes: [`/private${i}`] },
    auth_gate: { type: 'static_token', token_env: 'TOKEN' } }));
  routes.splice(50, 0, { name: 'overlap', match: { path_prefixes: ['/private99/deep'] },
    auth_gate: { type: 'static_token', token_env: 'SECOND' } });
  const fetcher = vi.fn(async () => new Response('ok'));
  const { handler } = generatedWorker({ routes }, fetcher);
  const call = (path: string, value = 'first') => handler.fetch(new Request('https://edge.example' + path, {
    headers: { 'x-edge-token': value, 'user-agent': 'test' } }), { TOKEN: 'first', SECOND: 'second' });
  expect((await call('/private99/deep')).status).toBe(401);
  expect((await call('/private99/deep', 'second')).status).toBe(401);
  expect(fetcher).not.toHaveBeenCalled();
  const allowed = await call('/PRIVATE99/child');
  expect(allowed.status).toBe(200);
  expect(allowed.headers.get('cache-control')).toContain('no-store');
  expect((await call('/private990', '')).status).toBe(200);
});

test.each([31, 32, 500])('one gate with %i prefixes keeps authentication and path boundaries', async (count) => {
  const origin = vi.fn(async () => new Response('ok'));
  const { handler } = generatedWorker({ defaults: { mode: 'monitor' }, routes: [{ name: 'group',
    match: { path_prefixes: Array.from({ length: count }, (_, i) => '/private' + i) },
    auth_gate: { type: 'static_token', token_env: 'TOKEN' } }] }, origin);
  const call = (path: string, env: object = { TOKEN: 'secret' }, token = '') => handler.fetch(
    new Request('https://edge.example' + path, { headers: { 'user-agent': 'test', 'x-edge-token': token } }), env);
  const last = '/private' + (count - 1);
  expect((await call(last + '/child')).status).toBe(401);
  expect((await call(last, {}, 'secret')).status).toBe(503);
  expect(origin).not.toHaveBeenCalled();
  for (const path of [last, last.toUpperCase() + '/child', last + ';v/child', '/%70rivate' + (count - 1)]) {
    const response = await call(path, { TOKEN: 'secret' }, 'secret');
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toContain('no-store');
  }
  expect((await call(last + 'suffix')).status).toBe(200);
});

test('indexed overlapping static/basic gates require both credentials in policy order', async () => {
  const origin = vi.fn(async () => new Response('ok'));
  const { handler } = generatedWorker({ routes: [
    { name: 'token', match: { path_prefixes: Array.from({ length: 32 }, (_, i) => '/private' + i) },
      auth_gate: { type: 'static_token', token_env: 'TOKEN' } },
    { name: 'basic', match: { path_prefixes: ['/private31'] },
      auth_gate: { type: 'basic_auth', credentials_env: 'BASIC' } },
  ] }, origin);
  const call = (headers: Record<string, string>, env = { TOKEN: 'first', BASIC: btoa('user:password') }) => handler.fetch(
    new Request('https://edge.example/private31/child', { headers: { 'user-agent': 'test', ...headers } }), env);
  expect((await call({}, { TOKEN: 'first', BASIC: '' })).status).toBe(401);
  expect((await call({ 'x-edge-token': 'first' })).status).toBe(401);
  expect((await call({ authorization: 'Basic ' + btoa('user:password') })).status).toBe(401);
  expect((await call({ 'x-edge-token': 'first' }, { TOKEN: 'first', BASIC: '' })).status).toBe(503);
  expect(origin).not.toHaveBeenCalled();
  expect((await call({ 'x-edge-token': 'first', authorization: 'Basic ' + btoa('user:password') })).status).toBe(200);
  expect(origin).toHaveBeenCalledTimes(1);
});

test('indexed authentication preserves case-sensitive path matching', async () => {
  const { handler } = generatedWorker({ request: { allow_methods: ['GET'], normalize: { path: { case_insensitive: false } } },
    routes: [{ name: 'group', match: { path_prefixes: Array.from({ length: 32 }, (_, i) => '/private' + i) },
      auth_gate: { type: 'static_token', token_env: 'TOKEN' } }] }, async () => new Response('ok'));
  const call = (path: string) => handler.fetch(new Request('https://edge.example' + path,
    { headers: { 'user-agent': 'test' } }), { TOKEN: 'secret' });
  expect((await call('/private31')).status).toBe(401);
  expect((await call('/PRIVATE31')).status).toBe(200);
});

test.each([false, true])('indexed signed URLs retain exact_path=%s and signature verification', async (exact) => {
  const { handler } = generatedWorker({ routes: [{ name: 'signed',
    match: { path_prefixes: Array.from({ length: 32 }, (_, i) => '/asset' + i) },
    auth_gate: { type: 'signed_url', secret_env: 'SECRET', exact_path: exact } }] }, async () => new Response('ok'));
  const call = (path: string) => handler.fetch(new Request('https://edge.example' + path,
    { headers: { 'user-agent': 'test' } }), { SECRET: 'secret' });
  const payload = '/asset31?exp=4102444800';
  const signature = crypto.createHmac('sha256', 'secret').update(payload).digest('base64url');
  expect((await call(payload + '&sig=' + signature)).status).toBe(200);
  expect((await call(payload + '&sig=invalid')).status).toBe(403);
  expect((await call('/asset31/child')).status).toBe(exact ? 200 : 403);
  expect((await call('/asset310')).status).toBe(200);
});

test('origin signatures omit unselected query while forwarding duplicate query values intact', async () => {
  const fetcher = vi.fn(async (input: RequestInfo | URL) => {
    const req = input as Request;
    const canonical = [req.method, new URL(req.url).pathname,
      req.headers.get('x-cdn-auth-timestamp'), req.headers.get('x-cdn-auth-nonce')].join('\n');
    expect(req.headers.get('x-cdn-auth-signature')).toBe(crypto.createHmac('sha256', 'secret').update(canonical).digest('base64url'));
    expect(new URL(req.url).searchParams.getAll('keep')).toEqual(['a b', '日本語']);
    expect(new URL(req.url).searchParams.has('utm_source')).toBe(false);
    return new Response('ok');
  });
  const { handler } = generatedWorker({ origin: { auth: { type: 'hmac_signature', secret_env: 'SECRET',
    signed_components: ['method', 'path', 'timestamp', 'nonce'] } } }, fetcher);
  expect((await handler.fetch(new Request('https://edge.example/public?keep=a%20b&utm_source=x&keep=%E6%97%A5%E6%9C%AC%E8%AA%9E', {
    headers: { 'user-agent': 'test' } }), { SECRET: 'secret' })).status).toBe(200);
});

test('prefix index preserves root, slash boundaries, duplicate gates and policy order', () => {
  const groups = Array.from({ length: 32 }, (_, i) => ['/unused' + i]);
  groups[0] = ['/']; groups[1] = ['/a/']; groups[2] = ['/a', '/a/deep']; groups[3] = ['/a/deep'];
  const index = buildPathIndex(groups, true);
  const candidates = Function(PATH_INDEX_HELPER + '; return pathCandidates;')();
  expect(candidates('/', index)).toEqual([0]);
  expect(candidates('/a', index)).toEqual([2]);
  expect(candidates('/a/', index)).toEqual([1, 2]);
  expect(candidates('/a/child', index)).toEqual([2]);
  expect(candidates('/a//child', index)).toEqual([1, 2]);
  expect(candidates('/a/deep/child', index)).toEqual([2, 3]);
  expect(candidates('//child', index)).toEqual([0]);
  expect(candidates('/ab', index)).toEqual([]);
  expect(buildPathIndex([['/a']], true)).toBeNull();
});

test('disabled optional features are absent from generated worker code', () => {
  const { code } = generatedWorker({}, async () => new Response('ok'));
  for (const unused of ['async function verifyJwt', 'async function handleChallenge', 'async function enforceGraphqlGuard', 'async function applyResponseDlp', 'async function hmacSha256Base64Url']) {
    expect(code).not.toContain(unused);
  }
});

test('indexed Cloudflare response matching keeps the existing empty-prefix root semantics', async () => {
  const routes = Array.from({ length: 32 }, (_, i) => ({ name: 'r' + i,
    match: { path_prefixes: [i ? '/private' + i : ''] }, auth_gate: { type: 'static_token', token_env: 'TOKEN' } }));
  const { handler } = generatedWorker({ routes }, async () => new Response('ok'));
  const publicResponse = await handler.fetch(new Request('https://edge.example/public', { headers: { 'user-agent': 'test' } }), {});
  expect(publicResponse.status).toBe(200);
  expect(publicResponse.headers.get('cache-control') || '').not.toContain('no-store');
  expect((await handler.fetch(new Request('https://edge.example/', { headers: { 'user-agent': 'test' } }), { TOKEN: 'value' })).status).toBe(401);
});

test('policy strings cannot be mistaken for the code specialization boundary', async () => {
  const csp = "default-src 'self'; report-uri /report?value=// {{RUNTIME}}";
  const { handler } = generatedWorker({ response_headers: { csp_public: csp } }, async () => new Response('ok'));
  const response = await handler.fetch(new Request('https://edge.example/public', { headers: { 'user-agent': 'test' } }), {});
  expect(response.status).toBe(200);
  expect(response.headers.get('content-security-policy')).toBe(csp);
});
