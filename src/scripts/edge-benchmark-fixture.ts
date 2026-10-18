/** Synthetic fixtures shared by the native runtime, k6 manifest, and disposable Workers. */
export const fixtureSecret = 'synthetic-edge-benchmark-only';
export const compatibilityDate = '2026-10-12';
export type BenchmarkCase = { id: string; profile: string; path: string; method: string; body?: string; status: number };
export const benchmarkCases: BenchmarkCase[] = [
  { id: 'basic', profile: 'basic', path: '/public', method: 'GET', status: 200 },
  { id: 'method-deny', profile: 'basic', path: '/public', method: 'DELETE', status: 405 },
  { id: 'regex', profile: 'regex', path: '/public/' + 'a'.repeat(8184), method: 'GET', status: 200 },
  { id: 'regex-deny', profile: 'regex', path: '/blocked-255/item', method: 'GET', status: 400 },
  { id: 'graphql', profile: 'graphql', path: '/graphql', method: 'POST', body: '{ a'.padEnd(65535, ' ') + '}', status: 200 },
  { id: 'graphql-deny', profile: 'graphql', path: '/graphql', method: 'POST', body: '{ a { b { c { d { e } } } } }', status: 400 },
  { id: 'hmac', profile: 'hmac', path: '/public', method: 'POST', body: 'x'.repeat(1048576), status: 200 },
  { id: 'rs256', profile: 'rs256', path: '/private', method: 'GET', status: 200 },
  { id: 'rs256-deny', profile: 'rs256', path: '/private', method: 'GET', status: 401 },
];
type Service = { fetch(request: Request): Promise<Response> };
export type FixtureEnv = {
  PROBE_KEY: string; EXPIRES: string; ORIGIN: string; RS_JWT: string; PUBLIC_JWKS: string;
  CSF_VERSION_METADATA?: { id: string };
  BASIC: Service; REGEX: Service; GRAPHQL: Service; HMAC: Service; RS256: Service; BARE: Service;
};
const hex = (bytes: ArrayBuffer) => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
const digest = async (bytes: ArrayBuffer | Uint8Array) => hex(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
const live = (env: FixtureEnv) => Number.isFinite(Number(env.EXPIRES)) && Date.now() < Number(env.EXPIRES);
const authorized = (request: Request, env: FixtureEnv) => env.PROBE_KEY?.length >= 32 && request.headers.get('x-csf-key') === env.PROBE_KEY;
const colo = (request: Request) => (request as Request & { cf?: { colo?: string } }).cf?.colo || 'unknown';

export class FixtureBodyError extends Error {
  constructor(readonly status: number) { super('Invalid fixture body'); }
}

declare const FixedLengthStream: { new(length: number): { readable: ReadableStream<Uint8Array>; writable: WritableStream<Uint8Array> } };

export async function readFixtureBody(request: Request, expectedBytes: number): Promise<ArrayBuffer | undefined> {
  if (!request.body) {
    if (expectedBytes) throw new FixtureBodyError(400);
    return undefined;
  }
  // The native fixed-length pipe bounds untrusted input without a JavaScript
  // read/copy callback per chunk. Await both ends so cancellation is complete.
  const stream = new FixedLengthStream(expectedBytes);
  const [written, read] = await Promise.allSettled([
    request.body.pipeTo(stream.writable), new Response(stream.readable).arrayBuffer(),
  ]);
  if (written.status === 'rejected' || read.status === 'rejected') {
    const error = written.status === 'rejected' ? written.reason : (read as PromiseRejectedResult).reason;
    if (error instanceof TypeError && error.message === 'Attempt to write too many bytes through a FixedLengthStream.') throw new FixtureBodyError(413);
    if (error instanceof TypeError && error.message === 'FixedLengthStream did not see all expected bytes before close().') throw new FixtureBodyError(400);
    throw error;
  }
  return read.value;
}

type DirectTarget = { fetch(request: Request, env: FixtureEnv): Promise<Response> };
async function routeFixture(request: Request, env: FixtureEnv, direct?: { profile: string; target: DirectTarget }): Promise<Response> {
  if (!live(env)) return new Response('Expired', { status: 410 });
  if (!authorized(request, env)) return new Response('Denied', { status: 403 });
  const url = new URL(request.url), parts = url.pathname.split('/');
  const spec = benchmarkCases.find(test => test.id === parts[1]), variant = parts[2];
  if (!spec || parts.length !== 3 || !['bare', 'generated'].includes(variant) || url.search) return new Response('Unknown fixture', { status: 404 });
  if (direct && (variant === 'bare' ? direct.profile !== 'bare' : direct.profile !== spec.profile)) return new Response('Wrong fixture target', { status: 404 });
  const id = request.headers.get('x-csf-id');
  if (!id || !/^[a-zA-Z0-9_-]{1,120}$/.test(id) || request.method !== spec.method) return new Response('Bad fixture request', { status: 400 });
  let body: ArrayBuffer | undefined;
  try { body = await readFixtureBody(request, spec.body?.length || 0); }
  catch (error) {
    if (error instanceof FixtureBodyError) return new Response(error.message, { status: error.status });
    throw error;
  }
  const headers = new Headers({ 'user-agent': 'csf-edge-benchmark', 'x-csf-key': env.PROBE_KEY,
    'x-csf-id': id, 'x-csf-case': spec.id, 'x-csf-variant': variant });
  if (spec.profile === 'graphql') headers.set('content-type', 'application/graphql');
  if (spec.profile === 'rs256') headers.set('authorization', 'Bearer ' + (spec.status === 401 ? 'not.a.jwt' : env.RS_JWT));
  const bindings: Record<string, Service> = { basic: env.BASIC, regex: env.REGEX, graphql: env.GRAPHQL, hmac: env.HMAC, rs256: env.RS256 };
  const forwarded = new Request(env.ORIGIN + spec.path, { method: spec.method, headers, body, redirect: 'manual' });
  const response = await (direct ? direct.target.fetch(forwarded, env) : (variant === 'bare' ? env.BARE : bindings[spec.profile]).fetch(forwarded));
  const result = new Response(response.body, response);
  result.headers.set('x-csf-ingress-colo', colo(request));
  result.headers.set('x-csf-id', id);
  if (env.CSF_VERSION_METADATA) result.headers.set('x-csf-version', env.CSF_VERSION_METADATA.id);
  return result;
}

export const gateway = { fetch: (request: Request, env: FixtureEnv) => routeFixture(request, env) };

/** The public invocation retains provider request.cf; generated handler bytes stay unchanged. */
export function createDirectTarget(target: DirectTarget, profile: string): DirectTarget {
  if (!['bare', 'basic', 'regex', 'graphql', 'hmac', 'rs256'].includes(profile)) throw new Error('Unknown direct fixture profile');
  return { fetch: (request, env) => routeFixture(request, env, { profile, target }) };
}

export const origin = { async fetch(request: Request, env: FixtureEnv): Promise<Response> {
  if (!live(env)) return new Response('Expired', { status: 410 });
  const url = new URL(request.url);
  if (url.pathname === '/jwks' && request.method === 'GET') return Response.json(JSON.parse(env.PUBLIC_JWKS), { headers: {
    'cache-control': 'no-store', ...(env.CSF_VERSION_METADATA ? { 'x-csf-version': env.CSF_VERSION_METADATA.id } : {}),
  } });
  if (!authorized(request, env)) return new Response('Denied', { status: 403 });
  const spec = benchmarkCases.find(test => test.id === request.headers.get('x-csf-case'));
  const variant = request.headers.get('x-csf-variant');
  if (!spec || url.pathname !== spec.path || url.search || request.method !== spec.method || !['bare', 'generated'].includes(variant || '')) return new Response('Oracle mismatch', { status: 500 });
  const body = await readFixtureBody(request, spec.body?.length || 0), bytes = body || new ArrayBuffer(0);
  const bodyHash = await digest(bytes);
  let signatureVerified = false;
  if (spec.profile === 'hmac' && variant === 'generated') {
    const timestamp = request.headers.get('x-cdn-auth-timestamp'), nonce = request.headers.get('x-cdn-auth-nonce');
    if (!timestamp || !nonce || !Number.isFinite(Number(timestamp)) || Math.abs(Date.now() / 1000 - Number(timestamp)) > 60 || request.headers.get('x-cdn-auth-body-sha256') !== bodyHash) return new Response('Signature fields mismatch', { status: 500 });
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(fixtureSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode([request.method, url.pathname, '', bodyHash, timestamp, nonce].join('\n')));
    const encoded = btoa(String.fromCharCode(...new Uint8Array(signature))).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
    if (encoded !== request.headers.get('x-cdn-auth-signature')) return new Response('Signature mismatch', { status: 500 });
    signatureVerified = true;
  }
  return Response.json({ id: request.headers.get('x-csf-id'), case: spec.id, variant,
    pathHash: await digest(new TextEncoder().encode(url.pathname)), bodyHash, bodyBytes: bytes.byteLength, signatureVerified, originColo: colo(request) },
  { headers: { 'cache-control': 'no-store', 'x-csf-origin': 'synthetic', ...(env.CSF_VERSION_METADATA ? { 'x-csf-version': env.CSF_VERSION_METADATA.id } : {}) } });
} };
