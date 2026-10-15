import { expect, test, vi } from 'vitest';
import { generatedWorker } from './helpers/generated-worker';

test.each(['block', 'report'])('GraphQL names retain limits, Unicode whitespace and diagnostics in %s mode', async mode => {
  const forwarded: string[] = [];
  const origin = vi.fn(async (input: RequestInfo | URL) => {
    forwarded.push(await (input as Request).text());
    return new Response('ok');
  });
  const { handler, logger } = generatedWorker({ request: { allow_methods: ['POST'], graphql_guard: {
    endpoint_paths: ['/graphql'], max_depth: 2, max_aliases: 1, max_fields: 3, mode,
  } } }, origin);
  const cases = [
    ['{ _a0 A_9 z9 }', ''],
    ['{ a\u00a0:\u2003b }', ''],
    ['{ a(arg:"{ ignored fields }") # ignored }\n b }', ''],
    ['{ a(arg:"""{ ignored fields }""") }', ''],
    ['{ a { b { c } } }', 'GraphQL depth limit exceeded'],
    ['{ a0:a a1:b }', 'GraphQL alias limit exceeded'],
    ['{ a b c d }', 'GraphQL field limit exceeded'],
    ['{ a', 'Malformed GraphQL query'],
    ['{ a(arg:"unterminated) }', 'Malformed GraphQL query'],
  ];
  for (const [body, reason] of cases) {
    origin.mockClear(); logger.log.mockClear();
    const response = await handler.fetch(new Request('https://edge.example/graphql', { method: 'POST', body,
      headers: { 'user-agent': 'test', 'content-type': 'application/graphql' } }), {});
    const blocked = Boolean(reason) && mode === 'block';
    expect(response.status, body).toBe(blocked ? 400 : 200);
    expect(origin).toHaveBeenCalledTimes(blocked ? 0 : 1);
    if (!blocked) expect(forwarded.at(-1)).toBe(body);
    if (reason) {
      expect(logger.log.mock.calls.map(call => JSON.parse(call[0]))).toContainEqual(expect.objectContaining({
        block_reason: reason,
      }));
    }
  }
});

test('generated GraphQL name classification matches the ASCII name grammar for every UTF-16 code unit', () => {
  const { code } = generatedWorker({ request: { graphql_guard: {} } }, async () => new Response('ok'));
  const [start, continuation] = Function('module', 'exports', code + ';return [isGraphqlNameStart, isGraphqlNameChar];')({ exports: {} }, {});
  for (let code = 0; code < 65536; code++) {
    const ch = String.fromCharCode(code);
    if (start(ch) !== /^[A-Za-z_]$/.test(ch) || continuation(ch) !== /^[A-Za-z0-9_]$/.test(ch)) {
      throw new Error('GraphQL name grammar mismatch: ' + code);
    }
  }
  for (const value of [undefined, null, 1, '', 'ab', '😀']) {
    expect(start(value)).toBe(false);
    expect(continuation(value)).toBe(false);
  }
});

test.each([true, false])('ordinary and encoded paths retain forwarding and auth with collapse_slashes=%s', async collapse => {
  const forwarded: string[] = [];
  const { handler } = generatedWorker({ request: { allow_methods: ['GET'], limits: { max_uri_length: 8192 },
    normalize: { path: { collapse_slashes: collapse } } }, routes: [{ name: 'private',
    match: { path_prefixes: Array.from({ length: 32 }, (_, i) => '/private' + i) },
    auth_gate: { type: 'static_token', token_env: 'TOKEN' } }] }, async (input: RequestInfo | URL) => {
    forwarded.push(new URL((input as Request).url).pathname);
    return new Response('ok');
  });
  const deep = '/private0/' + Array(256).fill('segment').join('/');
  for (const [uri, expected] of [
    ['/private0/.well-known/a.json', '/private0/.well-known/a.json'],
    [deep, deep],
    ['/private0/a//b', collapse ? '/private0/a/b' : '/private0/a//b'],
    ['/private0/a;v/%62', '/private0/a/b'],
    ['/%2570rivate0/a', '/private0/a'],
  ]) {
    for (const authorized of [false, true]) {
      const before = forwarded.length;
      const response = await handler.fetch(new Request('https://edge.example' + uri, {
        headers: { 'user-agent': 'test', 'x-edge-token': authorized ? 'secret' : '' },
      }), { TOKEN: 'secret' });
      expect(response.status).toBe(authorized ? 200 : 401);
      expect(forwarded.length).toBe(before + (authorized ? 1 : 0));
      if (authorized) {
        expect(forwarded.at(-1)).toBe(expected);
        expect(response.headers.get('cache-control')).toContain('no-store');
        expect(response.headers.get('vary')).toContain('Authorization');
      }
    }
  }
  for (const uri of ['/%E0%A4', '/%25252561', '/%2fprivate0']) {
    expect((await handler.fetch(new Request('https://edge.example' + uri, {
      headers: { 'user-agent': 'test', 'x-edge-token': 'secret' },
    }), { TOKEN: 'secret' })).status).toBe(400);
  }
});

test.each([true, false])('response indexes retain case=%s, slash boundaries, CSP and existing Vary tokens', async insensitive => {
  const prefixes = ['/trail/', '/case', '/', '/__proto__', '/constructor',
    ...Array.from({ length: 27 }, (_, i) => '/other' + i)];
  const { handler } = generatedWorker({ request: { allow_methods: ['GET'], normalize: { path: {
    case_insensitive: insensitive, collapse_slashes: false,
  } } }, routes: [{ name: 'private', match: { path_prefixes: prefixes },
    auth_gate: { type: 'static_token', token_env: 'TOKEN' } }],
  response_headers: { csp_admin: "default-src 'none'", csp_public: "default-src 'self'" } }, async () =>
    new Response('ok', { headers: { vary: 'Accept-Encoding', 'cache-control': 'public' } }));
  for (const [uri, protectedPath] of [
    ['/', true], ['/public', false], ['/trail/', true], ['/trail//child', true],
    ['/trail/child', false], ['/case/child', true], ['/caseSuffix', false],
    ['/CASE/child', insensitive], ['/__proto__/a', true], ['/constructor/a', true],
  ] as const) {
    const response = await handler.fetch(new Request('https://edge.example' + uri, {
      headers: { 'user-agent': 'test', 'x-edge-token': 'secret' },
    }), { TOKEN: 'secret' });
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe(protectedPath ? 'no-store, no-cache, must-revalidate, private' : 'public');
    expect(response.headers.get('vary')).toBe(protectedPath ? 'Accept-Encoding, Authorization, Cookie' : 'Accept-Encoding');
    expect(response.headers.get('content-security-policy')).toBe(protectedPath ? "default-src 'none'" : "default-src 'self'");
  }
});
