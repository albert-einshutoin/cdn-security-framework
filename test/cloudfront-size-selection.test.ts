import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { afterEach, expect, test, vi } from 'vitest';

const require = createRequire(import.meta.url);
const { build, loadPolicy } = require('../scripts/lib/compile-core');
const { optimizeCloudFrontFunction } = require('../scripts/lib/template-inject');
const scratch: string[] = [];
const env = { TOKEN: 'synthetic-size-selection', BASIC_AUTH_CREDS: 'dTpw' };
const policy = () => structuredClone(loadPolicy(path.join(process.cwd(), 'policy/base.yml')));
function generate(p: any) {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-size-selection-'));
  scratch.push(outDir);
  build(p, { rootDir: process.cwd(), outDir, env, optimize: true });
  const code = (name: string) => fs.readFileSync(path.join(outDir, 'edge', name + '.js'), 'utf8');
  const requestCode = code('viewer-request'), responseCode = code('viewer-response');
  return { requestCode, responseCode,
    request: Function(requestCode + '; return handler;')(), response: Function(responseCode + '; return handler;')() };
}
function request(uri: string, token = '') {
  return { request: { method: 'GET', uri, querystring: {},
    headers: { 'user-agent': { value: 'test' }, 'x-edge-token': { value: token } } } };
}
afterEach(() => { vi.restoreAllMocks(); scratch.splice(0).forEach(dir => fs.rmSync(dir, { recursive: true, force: true })); });

test.each([32, 64, 80])('%i routes still fit CloudFront and protect the last route with either selected algorithm', count => {
  const p = policy();
  p.routes = Array.from({ length: count }, (_, i) => ({ name: 'r' + i, match: { path_prefixes: ['/private' + i] },
    auth_gate: { type: 'static_token', token_env: 'TOKEN' } }));
  const output = generate(p);
  expect(Buffer.byteLength(output.requestCode)).toBeLessThanOrEqual(10240);
  expect(Buffer.byteLength(output.responseCode)).toBeLessThanOrEqual(10240);
  const uri = '/PRIVATE' + (count - 1) + '/child';
  expect(output.request(request(uri)).statusCode).toBe(401);
  expect(output.request(request(uri, env.TOKEN)).uri).toBe(uri);
  expect(output.request(request('/private' + (count - 1) + 'x')).uri).toBe('/private' + (count - 1) + 'x');
  const response = output.response({ ...request(uri), response: { statusCode: 200, headers: {} } });
  expect(response.headers['cache-control'].value).toContain('no-store');
  // Selection is per artifact: the response index fits even when request arrays are selected.
  expect(output.requestCode.includes('authGateIndex')).toBe(count === 32);
  expect(output.responseCode).toContain('authPathIndex');
});

test('overlapping gates preserve AND evaluation and policy denial order with the selected algorithm', () => {
  const p = policy();
  p.request.anomaly_guards.enabled = false;
  p.routes = [{ name: 'first', match: { path_prefixes: Array.from({ length: 32 }, (_, i) => '/p' + i) },
    auth_gate: { type: 'static_token', token_env: 'TOKEN' } },
  { name: 'second', match: { path_prefixes: ['/p31/deep'] }, auth_gate: { type: 'basic_auth', credentials_env: 'BASIC_AUTH_CREDS' } }];
  const output = generate(p);
  expect(Buffer.byteLength(output.requestCode)).toBeLessThanOrEqual(10240);
  expect(output.request(request('/p31/deep')).headers['www-authenticate']).toBeUndefined();
  expect(output.request(request('/p31/deep', env.TOKEN)).headers['www-authenticate'].value).toContain('Basic');
  const authorized = request('/p31/deep', env.TOKEN);
  Object.assign(authorized.request.headers, { authorization: { value: 'Basic dTpw' } });
  expect(output.request(authorized).uri).toBe('/p31/deep');
  expect(output.request(request('/public')).uri).toBe('/public');
});

test.each([true, false])('response indexes preserve case=%s, trailing slashes and cache headers', insensitive => {
  const p = policy();
  p.request.normalize.path = { case_insensitive: insensitive, collapse_slashes: false };
  p.routes = [{ name: 'private', match: { path_prefixes: ['/trail/', '/case', '/', '/__proto__', '/constructor',
    ...Array.from({ length: 27 }, (_, i) => '/other' + i)] }, auth_gate: { type: 'static_token', token_env: 'TOKEN' } }];
  const output = generate(p);
  for (const [uri, protectedPath] of [['/', true], ['/public', false], ['/trail/', true], ['/trail//child', true],
    ['/trail/child', false], ['/case/child', true], ['/caseSuffix', false], ['/CASE/child', insensitive],
    ['/__proto__/a', true], ['/constructor/a', true]] as const) {
    const response = output.response({ ...request(uri), response: { statusCode: 200,
      headers: { vary: { value: 'Accept-Encoding' }, 'cache-control': { value: 'public' } } } });
    expect(response.headers['cache-control'].value).toBe(protectedPath ? 'no-store, no-cache, must-revalidate, private' : 'public');
    expect(response.headers.vary.value).toBe(protectedPath ? 'Accept-Encoding, Authorization, Cookie' : 'Accept-Encoding');
  }
});

test('response-only large prefix configuration selects arrays and preserves admin cache boundaries', () => {
  const p = policy(), prefix = '/' + 'long'.repeat(6);
  p.routes = [{ name: 'admin', match: { path_prefixes: Array.from({ length: 100 }, (_, i) => prefix + i) },
    response: { cache_control: 'no-store' } }];
  const output = generate(p);
  expect(output.responseCode).not.toContain('adminPathIndex');
  expect(Buffer.byteLength(output.responseCode)).toBeLessThanOrEqual(10240);
  const call = (uri: string) => output.response({ ...request(uri), response: { statusCode: 200, headers: {} } });
  expect(call(prefix + '99/child').headers['cache-control'].value).toBe('no-store');
  expect(call(prefix + '99x').headers['cache-control']).toBeUndefined();
  expect(output.request(request('/public')).uri).toBe('/public');
});

test('specialization preserves monitor/text logs, correlation, case sensitivity and arbitrary policy strings', () => {
  const p = policy();
  p.defaults.mode = 'monitor';
  p.request.anomaly_guards.enabled = false;
  p.observability = { log_format: 'text', correlation_id_header: 'x-correlation', sample_rate: 1 };
  p.request.normalize.path = { case_insensitive: false };
  p.routes = [{ name: 'private', match: { path_prefixes: ['/Private', ...Array.from({ length: 31 }, (_, i) => '/Other' + i)] },
    auth_gate: { type: 'static_token', token_env: 'TOKEN' } }];
  const output = generate(p), log = vi.spyOn(console, 'log').mockImplementation(() => {});
  const event = request('/public'); event.request.method = 'DELETE';
  expect(output.request(event).uri).toBe('/public');
  expect(log.mock.calls.some(call => call[0] === '[monitor]')).toBe(true);
  log.mockClear();
  expect(output.request(request('/private')).uri).toBe('/private');
  expect(log.mock.calls.some(call => call[0] === '[monitor]')).toBe(false);
  expect(output.request(request('/Private')).statusCode).toBe(401);
  p.observability.log_format = 'json';
  const jsonOutput = generate(p), correlated = request('/public');
  Object.assign(correlated.request.headers, { 'x-correlation': { value: 'trace' } });
  log.mockClear(); jsonOutput.request(correlated);
  expect(log.mock.calls.map(call => JSON.parse(call[0])).some(record => record.event === 'allow' && record.correlation_id === 'trace')).toBe(true);
  const literal = 'CFG.mode // {{RUNTIME}}';
  const guarded = policy(); guarded.routes = [{ name: 'literal', match: { path_prefixes: ['/private'] },
    auth_gate: { type: 'static_token', token_env: 'TOKEN' } }];
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-literal-')); scratch.push(dir);
  build(guarded, { rootDir: process.cwd(), outDir: dir, env: { TOKEN: literal }, optimize: true });
  const handler = Function(fs.readFileSync(path.join(dir, 'edge/viewer-request.js'), 'utf8') + ';return handler;')();
  expect(handler(request('/private', literal)).uri).toBe('/private');
});

test('only a measured byte excess selects arrays; both oversized candidates fail', () => {
  const large = 'function handler(){return ' + JSON.stringify('x'.repeat(11000)) + ';}';
  const arrays = vi.fn(() => 'function handler(){return "array";}');
  expect(Function(optimizeCloudFrontFunction(large, 'test.js', {}, arrays) + ';return handler;')()()).toBe('array');
  expect(arrays).toHaveBeenCalledTimes(1);
  expect(() => optimizeCloudFrontFunction(large, 'test.js', {}, () => large)).toThrow(/10240|10 KiB/);
  arrays.mockClear();
  optimizeCloudFrontFunction('function handler(){return "index";}', 'test.js', {}, arrays);
  expect(arrays).not.toHaveBeenCalled();
});

test.each(['function handler( {', 'function other(){return "no-handler";}'])('invalid index code fails without selecting arrays: %s', source => {
  const arrays = vi.fn(() => 'function handler(){return "array";}');
  expect(() => optimizeCloudFrontFunction(source, 'test.js', {}, arrays)).toThrow();
  expect(arrays).not.toHaveBeenCalled();
});

test('an oversized response fails before any request or secret artifact is written', () => {
  const p = policy(); p.response_headers.csp_public = 'x'.repeat(11000);
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-size-fail-')); scratch.push(outDir);
  expect(() => build(p, { rootDir: process.cwd(), outDir, env: { EDGE_ADMIN_TOKEN: env.TOKEN }, optimize: true })).toThrow(/10240|10 KiB/);
  expect(fs.readdirSync(outDir)).toEqual([]);
});
