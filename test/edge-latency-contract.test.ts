import { expect, test } from 'vitest';
import { generatedWorker } from './helpers/generated-worker';

test.each(['enforce', 'monitor'])('mixed path regexes preserve matching and diagnostic order in %s mode', async mode => {
  const patterns = ['/blocked-0/[a-z]+$', '/blocked-1/[a-z]+$', '(?i)/mixed/[a-z]+$',
    '/foo?', '/bar*', '/baz{0,2}', '/left|/right', '/escaped\\|literal', '^/start/[0-9]+$', '/tail$'];
  const { handler, logger } = generatedWorker({ defaults: { mode }, request: { allow_methods: ['GET'],
    block: { path_patterns: { regex: patterns } } } }, async () => new Response('origin-ok'));
  for (const pathname of ['/public', '/blocked-0/item', '/blocked-1/item', '/MIXED/item', '/fo', '/ba', '/right', '/escaped|literal', '/start/12', '/public/tail']) {
    logger.log.mockClear();
    const matches = patterns.filter(source => new RegExp(source.replace(/^\(\?i\)/, ''), source.startsWith('(?i)') ? 'i' : '').test(pathname)).length;
    const response = await handler.fetch(new Request('https://edge.example' + pathname, { headers: { 'user-agent': 'test' } }), {});
    expect(response.status).toBe(matches && mode === 'enforce' ? 400 : 200);
    const events = logger.log.mock.calls.map(call => JSON.parse(call[0]));
    expect(events.filter(e => e.block_reason === 'Bad Request')).toHaveLength(mode === 'monitor' ? matches * 2 : matches ? 1 : 0);
  }
});

test('GraphQL preserves aliases and fields across long ASCII and Unicode separators', async () => {
  const { handler } = generatedWorker({ request: { allow_methods: ['POST'], graphql_guard: { max_aliases: 1, max_fields: 2, max_body_bytes: 131072 } } }, async () => new Response('ok'));
  for (const spaces of [' ', '  ', ' '.repeat(65536), '\t\r\n', '\u2003'.repeat(1000)]) {
    for (const [query, status] of [['{ a' + spaces + ':field other }', 200], ['{ a' + spaces + ':field b:other }', 400], ['{ a' + spaces + 'b c }', 400]] as const) {
      const response = await handler.fetch(new Request('https://edge.example/graphql', { method: 'POST', body: query,
        headers: { 'user-agent': 'test', 'content-type': 'application/graphql' } }), {});
      expect(response.status).toBe(status);
    }
  }
});

test('origin body hashing preserves original 1MiB input without cloning', async () => {
  const body = Buffer.alloc(1048576, 'x'), arrivals: Buffer[] = [];
  const { handler } = generatedWorker({ request: { allow_methods: ['POST'] }, origin: { auth: { type: 'hmac_signature', secret_env: 'SECRET', include_body_hash: true } } }, async input => {
    arrivals.push(Buffer.from(await (input as Request).arrayBuffer())); return new Response('ok');
  });
  const request = new Request('https://edge.example/upload', { method: 'POST', body, headers: { 'user-agent': 'test' } });
  request.clone = () => { throw new Error('Body ownership must not use clone'); };
  expect((await handler.fetch(request, { SECRET: 'synthetic' })).status).toBe(200);
  expect(arrivals).toHaveLength(1); expect(arrivals[0].equals(body)).toBe(true); expect(request.bodyUsed).toBe(true);
});
