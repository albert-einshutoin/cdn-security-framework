import { expect, test, vi } from 'vitest';
import { generatedWorker as worker } from './helpers/generated-worker';

async function withinDeadline<T>(operation: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([operation, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('body inspection did not return within 500ms')), 500);
    })]);
  } finally { clearTimeout(timer); }
}

function openBody(text: string) {
  let controller: ReadableStreamDefaultController<Uint8Array>;
  let closed = false;
  const body = new ReadableStream<Uint8Array>({
    start(value) { controller = value; value.enqueue(new TextEncoder().encode(text)); },
    cancel() { closed = true; },
  });
  return { body, close: () => { if (!closed) { closed = true; controller.close(); } } };
}

test.each(['block', 'report'] as const)('oversized GraphQL returns in %s mode before the upload ends', async (mode) => {
  const text = JSON.stringify({ query: '{ viewer { id } }', padding: 'x'.repeat(2048) });
  const input = openBody(text);
  const request = new Request('https://edge.example/graphql', {
    method: 'POST', headers: { 'content-type': 'application/json', 'user-agent': 'test' },
    body: input.body, ...({ duplex: 'half' } as RequestInit),
  });
  let forwarded: Request | undefined;
  const origin = vi.fn<typeof fetch>(async (value) => {
    forwarded = value as Request;
    return new Response('origin-ok');
  });
  const { handler } = worker({ request: { allow_methods: ['POST'], graphql_guard: {
    endpoint_paths: ['/graphql'], max_body_bytes: 1024, mode,
  } } }, origin);
  try {
    const response = await withinDeadline(handler.fetch(request, {}));
    expect(response.status).toBe(mode === 'block' ? 400 : 200);
    expect(origin).toHaveBeenCalledTimes(mode === 'block' ? 0 : 1);
    if (mode === 'block') expect(await response.text()).toContain('GraphQL body too large');
  } finally {
    input.close();
    // Release the other tee branch after the assertion, including on a failing baseline.
    if (!forwarded && request.body && !request.body.locked) await request.body.cancel();
  }
  if (forwarded) expect(await withinDeadline(forwarded.text())).toBe(text);
});

test.each(['report_only', 'mask', 'block'] as const)('oversized DLP passes the complete stream through in %s mode', async (action) => {
  const text = 'sk-live-abcdefghijklmnop' + 'x'.repeat(2048);
  const output = openBody(text);
  const origin = vi.fn<typeof fetch>(async () => new Response(output.body, {
    status: 202, headers: { 'content-type': 'text/plain', 'x-origin': 'preserved' },
  }));
  const { handler } = worker({ response_dlp: {
    enabled: true, action, body: { max_bytes: 1024, content_types: ['text/plain'] },
  } }, origin);
  let response: Response | undefined;
  try {
    response = await withinDeadline(handler.fetch(new Request('https://edge.example/data', {
      headers: { 'user-agent': 'test' },
    }), {}));
    expect(response.status).toBe(202);
    expect(response.headers.get('x-origin')).toBe('preserved');
    expect(response.headers.get('x-edge-dlp')).toBeNull();
    expect(origin).toHaveBeenCalledTimes(1);
  } finally { output.close(); }
  expect(await withinDeadline(response!.text())).toBe(text);
});

test('GraphQL report followed by auth rejection cancels the owned unfinished upload', async () => {
  const cancel = vi.fn();
  const body = new ReadableStream<Uint8Array>({
    start(controller) { controller.enqueue(new TextEncoder().encode('x'.repeat(2048))); }, cancel,
  });
  const origin = vi.fn<typeof fetch>(async () => new Response('origin-ok'));
  const { handler } = worker({ request: { allow_methods: ['POST'], graphql_guard: { endpoint_paths: ['/graphql'], max_body_bytes: 1024, mode: 'report' } },
    routes: [{ name: 'private', match: { path_prefixes: ['/graphql'] }, auth_gate: { type: 'static_token', token_env: 'SECRET' } }] }, origin);
  const response = await withinDeadline(handler.fetch(new Request('https://edge.example/graphql', {
    method: 'POST', headers: { 'user-agent': 'test', 'content-type': 'application/json' }, body, ...({ duplex: 'half' } as RequestInit),
  }), { SECRET: 'synthetic' }));
  expect(response.status).toBe(401);
  expect(origin).not.toHaveBeenCalled();
  expect(cancel).toHaveBeenCalledTimes(1);
});
