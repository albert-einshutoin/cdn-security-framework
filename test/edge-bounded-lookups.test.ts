import { expect, test, vi } from 'vitest';
import { generatedWorker } from './helpers/generated-worker';

test('GraphQL whitespace preserves alias accounting, limits and non-whitespace boundaries', () => {
  const { code } = generatedWorker({ request: { graphql_guard: {} } }, async () => new Response('ok'));
  const scan = Function('module', 'exports', code + ';return scanGraphqlQuery;')({ exports: {} }, {});
  const guard = { maxDepth: 10, maxAliases: 0, maxFields: 3 };
  // ECMAScript whitespace is also the existing scanner's accepted separator set.
  for (let point = 0; point < 65536; point++) {
    const separator = String.fromCharCode(point);
    if (!/\s/.test(separator)) continue;
    expect(scan('{ a' + separator + ': b }', guard)).toEqual({
      ok: false, reason: 'GraphQL alias limit exceeded', depth: 1, aliases: 1, fields: 0,
    });
  }
  for (const separator of ['\u0085', '\u200b']) {
    expect(scan('{ a' + separator + ': b }', guard)).toEqual({ ok: true, depth: 1, aliases: 0, fields: 2 });
  }
  expect(scan('{ a ' + ' \t\r\n\u2003'.repeat(12000) + ' b c d }', guard)).toEqual({
    ok: false, reason: 'GraphQL field limit exceeded', depth: 1, aliases: 0, fields: 4,
  });
});

test.each(['block', 'report'])('large formatted GraphQL keeps the complete forwarded bytes in %s mode', async mode => {
  const body = ('{ alias' + ' \t\u2003\n'.repeat(16000) + ': field }');
  const forwarded: string[] = [];
  const { handler, logger } = generatedWorker({ request: { allow_methods: ['POST'], graphql_guard: {
    max_aliases: 0, max_body_bytes: 1048576, mode,
  } } }, async (input: RequestInfo | URL) => {
    forwarded.push(await (input as Request).text());
    return new Response('ok');
  });
  const response = await handler.fetch(new Request('https://edge.example/graphql', { method: 'POST', body,
    headers: { 'user-agent': 'test', 'content-type': 'application/graphql' } }), {});
  expect(response.status).toBe(mode === 'block' ? 400 : 200);
  expect(forwarded).toEqual(mode === 'block' ? [] : [body]);
  expect(logger.log.mock.calls.map(call => JSON.parse(call[0]))).toContainEqual(expect.objectContaining({
    block_reason: 'GraphQL alias limit exceeded',
  }));
});

test('indexed authentication and response protection preserve an 8KiB path and credential intersection', async () => {
  const forwarded: string[] = [];
  const { handler } = generatedWorker({ request: { allow_methods: ['GET'], limits: { max_uri_length: 8192 } },
    routes: [
      { name: 'first', match: { path_prefixes: Array.from({ length: 64 }, (_, i) => '/private' + i) },
        auth_gate: { type: 'static_token', token_env: 'TOKEN' } },
      { name: 'second', match: { path_prefixes: ['/private63'] },
        auth_gate: { type: 'basic_auth', credentials_env: 'BASIC' } },
    ] }, async (input: RequestInfo | URL) => {
    forwarded.push(new URL((input as Request).url).pathname);
    return new Response('ok', { headers: { vary: 'Accept-Encoding', 'cache-control': 'public' } });
  });
  const call = (uri: string, headers: Record<string, string>) => handler.fetch(new Request('https://edge.example' + uri,
    { headers: { 'user-agent': 'test', ...headers } }), { TOKEN: 'secret', BASIC: btoa('user:password') });
  const path = ('/private63/' + 'segment/'.repeat(1024)).slice(0, 8192);
  const credentials = { 'x-edge-token': 'secret', authorization: 'Basic ' + btoa('user:password') };
  expect((await call(path, {})).status).toBe(401);
  const secondDenied = await call(path, { 'x-edge-token': 'secret' });
  expect(secondDenied.status).toBe(401);
  expect(secondDenied.headers.get('www-authenticate')).toBe('Basic realm="Protected"');
  expect(forwarded).toEqual([]);
  const accepted = await call(path, credentials);
  expect(accepted.status).toBe(200);
  expect(forwarded).toEqual([path]);
  expect(accepted.headers.get('cache-control')).toBe('no-store, no-cache, must-revalidate, private');
  expect(accepted.headers.get('vary')).toBe('Accept-Encoding, Authorization, Cookie');
  expect((await call(path + 'x', credentials)).status).toBe(414);
  const publicPath = '/private630/' + 'segment/'.repeat(900);
  expect((await call(publicPath, {})).status).toBe(200);
  expect(forwarded.at(-1)).toBe(publicPath);
});

test('an indexed prefix much longer than the other keys retains its final segment boundary', async () => {
  const longest = '/private/' + 'segment/'.repeat(300) + 'end';
  const origin = vi.fn(async () => new Response('ok'));
  const { handler } = generatedWorker({ request: { allow_methods: ['GET'], limits: { max_uri_length: 8192 } },
    routes: [{ name: 'longest', match: { path_prefixes: [longest,
      ...Array.from({ length: 31 }, (_, i) => '/other' + i)] },
    auth_gate: { type: 'static_token', token_env: 'TOKEN' } }] }, origin);
  const call = (uri: string, token = '') => handler.fetch(new Request('https://edge.example' + uri,
    { headers: { 'user-agent': 'test', 'x-edge-token': token } }), { TOKEN: 'secret' });
  for (const uri of [longest, longest + '/', longest + '/child']) {
    expect((await call(uri)).status).toBe(401);
    expect((await call(uri, 'secret')).status).toBe(200);
  }
  const publicResponse = await call(longest + 'suffix');
  expect(publicResponse.status).toBe(200);
  expect(publicResponse.headers.get('cache-control') || '').not.toContain('no-store');
  expect(origin).toHaveBeenCalledTimes(4);
});

test.each(['enforce', 'monitor'])('raw and normalized path checks preserve observable rejection logs in %s mode', async mode => {
  const origin = vi.fn(async () => new Response('ok'));
  const { handler, logger } = generatedWorker({ defaults: { mode }, request: { allow_methods: ['GET'], block: {
    path_patterns: { regex: ['/blocked-0/[a-z]+$', '(?i)/blocked-0/[a-z]+$'] },
  } } }, origin);
  for (const [uri, monitorLogs] of [
    ['/blocked-0/item', 4], ['/blocked%2d0/item', 2], ['/blocked-0/;v/item', 2], ['/public/item', 0],
  ] as const) {
    logger.log.mockClear(); origin.mockClear();
    const response = await handler.fetch(new Request('https://edge.example' + uri,
      { headers: { 'user-agent': 'test' } }), {});
    expect(response.status).toBe(mode === 'enforce' && monitorLogs ? 400 : 200);
    expect(origin).toHaveBeenCalledTimes(mode === 'enforce' && monitorLogs ? 0 : 1);
    const events = logger.log.mock.calls.map(call => JSON.parse(call[0]));
    expect(events).toHaveLength(mode === 'monitor' ? monitorLogs : monitorLogs ? 1 : 0);
    for (const event of events) expect(event).toMatchObject({ event: mode === 'monitor' ? 'monitor' : 'block',
      status: 400, block_reason: 'Bad Request' });
  }
});
