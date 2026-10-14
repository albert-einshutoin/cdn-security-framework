import crypto from 'node:crypto';
import { afterEach, expect, test, vi } from 'vitest';
import { generatedWorker } from './helpers/generated-worker';

afterEach(() => vi.restoreAllMocks());
const origin = async () => new Response('ok');
function token(secret: string, payload: object = {}) {
  const data = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url') + '.'
    + Buffer.from(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600, ...payload })).toString('base64url');
  return data + '.' + crypto.createHmac('sha256', secret).update(data).digest('base64url');
}
function request(jwt: string) {
  return new Request('https://edge.example/PRIVATE', { headers: { 'user-agent': 'test', authorization: 'Bearer ' + jwt } });
}
function instrumentCrypto() {
  const imports = vi.fn((...args: Parameters<SubtleCrypto['importKey']>) =>
    Reflect.apply(crypto.webcrypto.subtle.importKey, crypto.webcrypto.subtle, args));
  const subtle = new Proxy(crypto.webcrypto.subtle, { get(target, key) {
    if (key === 'importKey') return imports;
    const value = Reflect.get(target, key, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
  return { imports, webCrypto: { subtle, getRandomValues: crypto.webcrypto.getRandomValues.bind(crypto.webcrypto) } as Crypto };
}
const hsPolicy = { routes: [{ name: 'jwt', match: { path_prefixes: ['/private'] },
  auth_gate: { type: 'jwt', algorithm: 'HS256', secret_env: 'SECRET' } }] };

test('shares only HMAC key conversion, verifies every signature, and observes secret rotation', async () => {
  const { imports, webCrypto } = instrumentCrypto();
  const { handler } = generatedWorker(hsPolicy, origin, webCrypto);
  const statuses = await Promise.all(Array.from({ length: 4 }, () => handler.fetch(request(token('first')), { SECRET: 'first' })));
  expect(statuses.map(r => r.status)).toEqual([200, 200, 200, 200]);
  expect(imports).toHaveBeenCalledTimes(1);
  expect((await handler.fetch(request(token('second')), { SECRET: 'second' })).status).toBe(200);
  expect((await handler.fetch(request(token('first')), { SECRET: 'second' })).status).toBe(401);
  expect((await handler.fetch(request(token('second', { exp: 1 })), { SECRET: 'second' })).status).toBe(401);
  expect(imports).toHaveBeenCalledTimes(2);
});

test('a failed HMAC import is not retained as a successful or permanently rejected key', async () => {
  const { imports, webCrypto } = instrumentCrypto();
  imports.mockRejectedValueOnce(new Error('synthetic import failure'));
  const { handler } = generatedWorker(hsPolicy, origin, webCrypto);
  await expect(handler.fetch(request(token('first')), { SECRET: 'first' })).rejects.toThrow('synthetic import failure');
  expect((await handler.fetch(request(token('first')), { SECRET: 'first' })).status).toBe(200);
  expect(imports).toHaveBeenCalledTimes(2);
});

test('RS256 key reuse follows JWK object identity even when rotation keeps the same kid', async () => {
  const { imports, webCrypto } = instrumentCrypto();
  const first = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const second = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  let keys = [{ ...first.publicKey.export({ format: 'jwk' }), kid: 'same-kid', alg: 'RS256' }];
  const fetcher = vi.fn(async (input: RequestInfo | URL) => typeof input === 'string'
    ? new Response(JSON.stringify({ keys })) : new Response('ok'));
  const { handler } = generatedWorker({ routes: [{ name: 'rsa', match: { path_prefixes: ['/private'] },
    auth_gate: { type: 'jwt', algorithm: 'RS256', jwks_url: 'https://id.example/jwks', cache_ttl_sec: 1 } }],
    firewall: { jwks: { allowed_hosts: ['id.example'] } } }, fetcher, webCrypto);
  const now = Date.now();
  vi.spyOn(Date, 'now').mockReturnValue(now);
  const signed = (key: crypto.KeyObject) => {
    const data = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'same-kid' })).toString('base64url') + '.'
      + Buffer.from(JSON.stringify({ exp: Math.floor(now / 1000) + 3600 })).toString('base64url');
    return data + '.' + crypto.sign('sha256', Buffer.from(data), key).toString('base64url');
  };
  for (let i = 0; i < 3; i++) expect((await handler.fetch(request(signed(first.privateKey)), {})).status).toBe(200);
  expect(imports).toHaveBeenCalledTimes(1);
  keys = [{ ...second.publicKey.export({ format: 'jwk' }), kid: 'same-kid', alg: 'RS256' }];
  vi.mocked(Date.now).mockReturnValue(now + 6000);
  expect((await handler.fetch(request(signed(second.privateKey)), {})).status).toBe(200);
  expect((await handler.fetch(request(signed(first.privateKey)), {})).status).toBe(401);
  expect(imports).toHaveBeenCalledTimes(2);
});

test('GraphQL and origin body signing forward exact split UTF-8 bytes without teeing the upload', async () => {
  const text = JSON.stringify({ query: '{ viewer { id } }', padding: '日本語'.repeat(64) });
  const bytes = new TextEncoder().encode(text);
  const clone = vi.spyOn(Request.prototype, 'clone');
  let received: Uint8Array | undefined;
  const fetcher = vi.fn(async (input: RequestInfo | URL) => {
    const req = input as Request;
    received = new Uint8Array(await req.arrayBuffer());
    expect(req.headers.get('x-cdn-auth-body-sha256')).toBe(crypto.createHash('sha256').update(bytes).digest('hex'));
    return new Response('ok');
  });
  const { handler } = generatedWorker({ request: { allow_methods: ['POST'], graphql_guard: { endpoint_paths: ['/graphql'], max_body_bytes: 4096 } },
    origin: { auth: { type: 'hmac_signature', secret_env: 'SECRET', include_body_hash: true } } }, fetcher);
  let offset = 0;
  const body = new ReadableStream({ pull(controller) {
    if (offset === bytes.length) { controller.close(); return; }
    controller.enqueue(bytes.slice(offset, ++offset));
  } });
  const response = await handler.fetch(new Request('https://edge.example/graphql', { method: 'POST',
    headers: { 'user-agent': 'test', 'content-type': 'application/json' }, body, ...({ duplex: 'half' } as RequestInit) }), { SECRET: 'synthetic' });
  expect(response.status).toBe(200);
  expect(received).toEqual(bytes);
  expect(clone).not.toHaveBeenCalled();
});

test.each([false, true])('origin hash preserves body absence=%s and signs the actual 1MiB upload bytes', async (absent) => {
  const bytes = absent ? undefined : crypto.randomBytes(1024 * 1024);
  const input = new Request('https://edge.example/upload?b=2&a=1', { method: 'POST', headers: { 'user-agent': 'test' }, body: bytes });
  let consumedAtDigest = false;
  const subtle = new Proxy(crypto.webcrypto.subtle, { get(target, key) {
    const value = Reflect.get(target, key, target);
    if (key === 'digest') return (...args: Parameters<SubtleCrypto['digest']>) => {
      consumedAtDigest = input.bodyUsed;
      return Reflect.apply(value, target, args);
    };
    return typeof value === 'function' ? value.bind(target) : value;
  } });
  const fetcher = vi.fn(async (value: RequestInfo | URL) => {
    const sent = value as Request;
    if (absent) expect(sent.body).toBeNull();
    const actual = Buffer.from(await sent.arrayBuffer());
    expect(actual.equals(bytes ?? Buffer.alloc(0)), 'origin body bytes must match input').toBe(true);
    const hash = crypto.createHash('sha256').update(actual).digest('hex');
    expect(sent.headers.get('x-cdn-auth-body-sha256')).toBe(hash);
    const canonical = ['POST', '/upload', 'a=1&b=2', hash, sent.headers.get('x-cdn-auth-timestamp'), sent.headers.get('x-cdn-auth-nonce')].join('\n');
    expect(sent.headers.get('x-cdn-auth-signature')).toBe(crypto.createHmac('sha256', 'synthetic').update(canonical).digest('base64url'));
    return new Response('ok');
  });
  const { handler } = generatedWorker({ origin: { auth: { type: 'hmac_signature', secret_env: 'SECRET', include_body_hash: true } } }, fetcher,
    { subtle, getRandomValues: crypto.webcrypto.getRandomValues.bind(crypto.webcrypto) } as Crypto);
  expect((await handler.fetch(input, { SECRET: 'synthetic' })).status).toBe(200);
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(consumedAtDigest).toBe(!absent);
  // Includes code-generation subprocesses and WebCrypto under parallel coverage.
}, 15000);

test('oversized DLP replay propagates cancellation to its single origin stream', async () => {
  const cancel = vi.fn();
  const { handler } = generatedWorker({ response_dlp: { enabled: true, body: { max_bytes: 1024, content_types: ['text/plain'] } } }, async () =>
    new Response(new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(2048)); }, cancel }), { headers: { 'content-type': 'text/plain' } }));
  const response = await handler.fetch(new Request('https://edge.example/data', { headers: { 'user-agent': 'test' } }), {});
  await response.body!.cancel('client stopped');
  expect(cancel).toHaveBeenCalledWith('client stopped');
});

test('prepared custom DLP regexes preserve sequential detector results across requests', async () => {
  const { handler } = generatedWorker({ response_dlp: { enabled: true, action: 'mask', mask: 'SECOND',
    detectors: { built_in: [], custom_regex: [{ name: 'first', pattern: 'FIRST' }, { name: 'second', pattern: 'SECOND' }] },
    body: { content_types: ['text/plain'] } } }, async () => new Response('FIRST FIRST', { headers: { 'content-type': 'text/plain' } }));
  for (let i = 0; i < 3; i++) {
    const response = await handler.fetch(new Request('https://edge.example/data', { headers: { 'user-agent': 'test' } }), {});
    expect(response.headers.get('x-edge-dlp')).toBe('mask');
    expect(await response.text()).toBe('SECOND SECOND');
  }
});
