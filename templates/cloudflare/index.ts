/**
 * Cloudflare Workers — TEMPLATE
 *
 * 【注意】このファイルはテンプレートです。直接デプロイしないでください。
 * security.yml（または policy/security.yml）を編集し、npx cdn-security build --target cloudflare で dist/edge/cloudflare/index.ts を生成してください。
 */

// {{INJECT_CONFIG}}

// {{INJECT_RESPONSE_CFG}}

// {{RUNTIME}}

type WorkerEnv = Record<string, string | undefined>;

type JwksCacheEntry = {
  fetchedAt: number;
  keys: Array<Record<string, any>>;
};

const rsaVerifyKeys = new WeakMap<object, Promise<CryptoKey>>();
const hmacKeys = new WeakMap<object, { secret: string; key: Promise<CryptoKey> }>();

const jwksCache = new Map<string, JwksCacheEntry>();

type JwksNegativeEntry = { failedAt: number; reason: string };
const jwksNegativeCache = new Map<string, JwksNegativeEntry>();
// Only configured endpoints create state; attacker-controlled kids never do.
type JwksRefreshState = { windowStartedAt: number; attempts: number; inFlight?: Promise<Array<Record<string, any>>> };
const jwksRefreshState = new Map<string, JwksRefreshState>();
const JWKS_REFRESH_WINDOW_MS = 5000;
const JWKS_REFRESH_MAX_ATTEMPTS = 2;
const JWKS_FETCH_TIMEOUT_MS = 2000;
const JWKS_MAX_BODY_BYTES = 256 * 1024;
const JWKS_MAX_KEYS = 100;

function deny(code: number, msg: string) {
  return new Response(msg, { status: code, headers: { 'cache-control': 'no-store' } });
}

type ReqCtx = { method: string; uri: string; correlationId: string };

// Structured log emitter. Shape matches the AWS side so downstream pipelines
// can aggregate across CDN vendors with a single schema. Issue #21.
function logEvent(event: string, fields: Record<string, any>) {
  if (CFG.obs && CFG.obs.logFormat === 'text') {
    console.log('[' + event + ']', fields.status != null ? fields.status : '',
      fields.block_reason ? fields.block_reason : '');
    return;
  }
  const rec: Record<string, any> = { ts: Date.now(), level: event === 'block' ? 'warn' : 'info', event };
  for (const k of Object.keys(fields)) {
    if (fields[k] != null && fields[k] !== '') rec[k] = fields[k];
  }
  console.log(JSON.stringify(rec));
}

function readCorrelation(req: Request | null): string {
  if (!CFG.obs || !CFG.obs.correlationHeader || !req) return '';
  return req.headers.get(CFG.obs.correlationHeader) || '';
}

function reqCtx(req: Request | null, pathname?: string): ReqCtx {
  if (!req) return { method: '', uri: '/', correlationId: '' };
  let uri = '/';
  try { uri = pathname === undefined ? new URL(req.url).pathname : pathname; } catch (_e) { /* ignore */ }
  return { method: req.method, uri, correlationId: readCorrelation(req) };
}

function allowSampleKey(ctx: ReqCtx): string {
  return ctx.correlationId || ctx.method + '\n' + ctx.uri;
}

function shouldSampleAllow(key: string): boolean {
  const rate = (CFG.obs && CFG.obs.sampleRate) || 0;
  if (rate <= 0) return false;
  if (rate >= 1) return true;
  let hash = 2166136261;
  for (let i = 0; i < key.length; i++) {
    hash ^= key.charCodeAt(i);
    hash = (hash + ((hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24))) | 0;
  }
  return (hash >>> 0) / 4294967296 < rate;
}

function logAllow(ctx: ReqCtx, samplingKey: string) {
  if (!shouldSampleAllow(samplingKey)) return;
  logEvent('allow', {
    method: ctx.method,
    uri: ctx.uri,
    correlation_id: ctx.correlationId,
  });
}

async function hashSub(sub: string): Promise<string> {
  if (!sub) return '';
  const data = new TextEncoder().encode(sub);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(digest);
  let hex = '';
  for (let i = 0; i < bytes.length && hex.length < 16; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex.slice(0, 16);
}

function shouldBlock(code: number, msg: string, ctx?: ReqCtx | null): Response | null {
  const base = {
    status: code,
    block_reason: msg,
    method: ctx && ctx.method,
    uri: ctx && ctx.uri,
    correlation_id: ctx && ctx.correlationId,
  };
  if (CFG.mode === 'monitor') {
    logEvent('monitor', base);
    return null;
  }
  logEvent('block', base);
  return deny(code, msg);
}

function shouldBlockAuth(code: number, msg: string, ctx?: ReqCtx | null): Response {
  const base = {
    status: code,
    block_reason: msg,
    method: ctx && ctx.method,
    uri: ctx && ctx.uri,
    correlation_id: ctx && ctx.correlationId,
  };
  logEvent(CFG.mode === 'monitor' ? 'monitor' : 'block', base);
  if (code === 401) return deny(401, 'Unauthorized');
  if (code === 403) return deny(403, 'Forbidden');
  if (code === 503) return deny(503, 'Service Unavailable');
  return deny(code, 'Denied');
}

type GraphqlScanResult = {
  ok: boolean;
  reason?: string;
  depth: number;
  aliases: number;
  fields: number;
};

function hasAmbiguousPathEncoding(uri: string): boolean {
  const s = String(uri || '').toLowerCase();
  return s.includes('%2f') || s.includes('%5c') ||
    s.includes('%252f') || s.includes('%255c') || s.includes('%252e');
}

/** Canonicalize for auth/response matching and request rewrite. null = malformed. */
function canonicalizePath(pathname: string): string | null {
  const opts = (CFG.normalizePath || {}) as any;
  const raw = String(pathname || '/');
  // Only bypass rewriting when every normalization option would leave it intact.
  if (raw[0] === '/' && !/[;%]|\/\/|(?:^|\/)\.{1,2}(?:\/|$)/.test(raw)) return raw;
  let p = raw.replace(/;[^/]*/g, '');
  // Decode up to 3 times so double-encoded unreserved bytes (%2561 → %61 → a)
  // cannot slip past auth matching while still looking different from the prefix.
  for (let round = 0; round < 3; round++) {
    if (!/%[0-9A-Fa-f]{2}/.test(p)) break;
    try {
      const next = decodeURIComponent(p);
      if (next === p) break;
      p = next;
    } catch (_e) {
      return null;
    }
  }
  if (/%[0-9A-Fa-f]{2}/.test(p)) return null;
  // Decoding can reveal matrix parameters; auth and origin need the same path.
  p = p.replace(/;[^/]*/g, '');
  if (!p.startsWith('/')) p = '/' + p;
  if (opts.collapseSlashes !== false) p = p.replace(/\/+/g, '/');
  if (opts.removeDotSegments !== false) {
    const out: string[] = [];
    for (const seg of p.split('/')) {
      if (seg === '..') out.pop();
      else if (seg !== '.') out.push(seg);
    }
    p = out.join('/') || '/';
  }
  return p;
}

function normalizeForMatch(value: string): string {
  const raw = value || '/';
  return (CFG.normalizePath as any)?.caseInsensitive !== false ? raw.toLowerCase() : raw;
}

function pathMatchesExact(uri: string, prefix: string): boolean {
  return uri === prefix;
}

function pathMatchesPrefix(uri: string, prefix: string): boolean {
  const left = uri;
  const right = prefix;
  return left === right || left.startsWith(right + '/');
}

const authMatchPrefixes = CFG.authGates.map((gate: any) => gate.protectedPrefixes.map(normalizeForMatch));
const authGateIds = CFG.authGates.map((_gate: any, index: number) => index);
const adminMatchPrefixes = RESPONSE_CFG.adminPathPrefixes.map(normalizeForMatch);
const protectedMatchPrefixes = (RESPONSE_CFG.authProtectedPrefixes || []).map(normalizeForMatch);
const clearSiteDataValue = (RESPONSE_CFG.clearSiteDataTypes || []).map((t: string) => '"' + t + '"').join(', ');
const dlpGlobalRegexes: RegExp[] = (RESPONSE_CFG.responseDlpCustomRegexes || []).map((re: RegExp) =>
  new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g'));

function normalizePath(pathname: string): string | null {
  return canonicalizePath(pathname);
}

function rawPathnameFromRequestUrl(rawUrl: string): string {
  const text = String(rawUrl || '');
  const schemeIdx = text.indexOf('://');
  let pathStart = -1;
  if (schemeIdx !== -1) {
    pathStart = text.indexOf('/', schemeIdx + 3);
  } else if (text.startsWith('/')) {
    pathStart = 0;
  }
  if (pathStart === -1) return '/';

  let pathEnd = text.length;
  const queryStart = text.indexOf('?', pathStart);
  const hashStart = text.indexOf('#', pathStart);
  if (queryStart !== -1 && queryStart < pathEnd) pathEnd = queryStart;
  if (hashStart !== -1 && hashStart < pathEnd) pathEnd = hashStart;
  return text.slice(pathStart, pathEnd) || '/';
}

function blockIfPathPattern(pathname: string, ctx: ReqCtx): Response | null {
  const pathLower = pathname.toLowerCase();
  for (const m of CFG.blockPathContains) {
    if (pathLower.includes(m)) {
      const r = shouldBlock(400, 'Bad Request', ctx);
      if (r) return r;
    }
  }
  for (const group of CFG.blockPathRegexGroups) {
    if (group.required && !pathname.includes(group.required)) continue;
    for (const re of group.regexes) {
      if (re.test(pathname)) {
        const r = shouldBlock(400, 'Bad Request', ctx);
        if (r) return r;
      }
    }
  }
  return null;
}

function hasRawControlLineBreak(s: string): boolean {
  return typeof s === 'string' && (s.indexOf('\r') !== -1 || s.indexOf('\n') !== -1);
}

function hasEncodedCrlfIndicator(s: string): boolean {
  if (typeof s !== 'string' || s.length === 0) return false;
  const lower = s.toLowerCase();
  return lower.indexOf('%0d') !== -1 || lower.indexOf('%0a') !== -1;
}

function hasCrlfIndicator(s: string): boolean {
  return hasRawControlLineBreak(s) || hasEncodedCrlfIndicator(s);
}

function decodeOnceWhenPercent25Present(s: string): string {
  if (typeof s !== 'string' || s.length === 0) return '';
  if (s.toLowerCase().indexOf('%25') === -1) return '';
  try {
    return decodeURIComponent(s);
  } catch (_e) {
    return '';
  }
}

function hasDoubleEncodedTraversalIndicator(s: string): boolean {
  const decoded = decodeOnceWhenPercent25Present(s);
  if (!decoded) return false;
  const lower = decoded.toLowerCase();
  return lower.indexOf('%2e%2e') !== -1 ||
    lower.indexOf('..%2f') !== -1 ||
    lower.indexOf('..%5c') !== -1 ||
    lower.indexOf('%2f..') !== -1 ||
    lower.indexOf('%5c..') !== -1 ||
    lower.indexOf('../') !== -1 ||
    lower.indexOf('..\\') !== -1;
}

function hasCookieControlChar(cookie: string): boolean {
  if (typeof cookie !== 'string') return false;
  for (let i = 0; i < cookie.length; i++) {
    const code = cookie.charCodeAt(i);
    if (code < 32 || code === 127) return true;
  }
  return false;
}

function isMalformedCookie(cookie: string): boolean {
  if (typeof cookie !== 'string' || cookie.length === 0) return false;
  const guards = CFG.anomalyGuards || {};
  if (guards.maxCookieBytes && cookie.length > guards.maxCookieBytes) return true;
  if (hasCookieControlChar(cookie)) return true;

  const parts = cookie.split(';');
  let pairCount = 0;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i].trim();
    if (!part) {
      if (i > 0 && i < parts.length - 1) return true;
      continue;
    }
    const eq = part.indexOf('=');
    if (eq <= 0) return true;
    if (!part.slice(0, eq).trim()) return true;
    pairCount++;
    if (guards.maxCookiePairs && pairCount > guards.maxCookiePairs) return true;
  }
  return false;
}

function blockIfRequestAnomaly(request: Request, rawPathname: string, query: string, ctx: ReqCtx): Response | null {
  const guards = CFG.anomalyGuards || {};
  if (guards.enabled !== true) return null;

  if (guards.crlf !== false && (hasCrlfIndicator(rawPathname) || hasCrlfIndicator(query))) {
    return shouldBlock(400, 'Bad Request', ctx);
  }
  if (guards.doubleEncodedTraversal !== false &&
    (hasDoubleEncodedTraversalIndicator(rawPathname) || hasDoubleEncodedTraversalIndicator(query))) {
    return shouldBlock(400, 'Bad Request', ctx);
  }

  let headerBlock: Response | null = null;
  request.headers.forEach((value) => {
    if (!headerBlock && guards.crlf !== false && hasCrlfIndicator(value)) {
      headerBlock = shouldBlock(400, 'Bad Request', ctx);
    }
  });
  if (headerBlock) return headerBlock;

  const cookie = request.headers.get('cookie') || '';
  if (guards.malformedCookie !== false && isMalformedCookie(cookie)) {
    return shouldBlock(400, 'Malformed Cookie', ctx);
  }
  return null;
}

function isGraphqlPath(pathname: string): boolean {
  const guard = CFG.graphqlGuard;
  if (!guard || !Array.isArray(guard.endpointPaths) || guard.endpointPaths.length === 0) return false;
  return guard.endpointPaths.some((p: string) => pathname === p || pathname.startsWith(p + '/'));
}

type ForwardBody = { body: BodyInit | null };
function cancelForwardBody(state: ForwardBody): void {
  const body = state.body;
  state.body = null;
  if (body instanceof ReadableStream) discardBody(body);
}
function discardBody(body: ReadableStream | null): void {
  if (body) void body.cancel().catch(() => console.error('[body-inspection] cancellation failed'));
}
type InspectedBody = { body: Uint8Array | ReadableStream<Uint8Array>; bytes?: Uint8Array };

async function readBoundedBody(body: ReadableStream<Uint8Array>, maxBytes: number): Promise<InspectedBody> {
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) {
        reader.releaseLock();
        const bytes = chunks.length === 1 ? chunks[0] : new Uint8Array(total);
        if (chunks.length !== 1) {
          let offset = 0;
          for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        }
        return { body: bytes, bytes };
      }
      chunks.push(part.value);
      total += part.value.byteLength;
      if (total > maxBytes) break;
    }
  } catch (error) { reader.releaseLock(); throw error; }
  // Keep one owner: replay exactly the inspected prefix, then pull the remainder
  // only as the origin/client consumes it. No tee branch can buffer independently.
  let index = 0;
  const replay = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (index < chunks.length) {
        const chunk = chunks[index];
        chunks[index++] = new Uint8Array(0);
        controller.enqueue(chunk);
        return;
      }
      try {
        const part = await reader.read();
        if (part.done) { reader.releaseLock(); controller.close(); }
        else controller.enqueue(part.value);
      } catch (error) { reader.releaseLock(); controller.error(error); }
    },
    async cancel(reason) { try { await reader.cancel(reason); } finally { reader.releaseLock(); } },
  });
  return { body: replay };
}

async function readLimitedRequestText(request: Request, state: ForwardBody, maxBytes: number): Promise<{ ok: boolean; text: string; reason?: string }> {
  if (!request.body) return { ok: true, text: '' };
  const inspected = await readBoundedBody(request.body, maxBytes);
  state.body = inspected.body;
  if (!inspected.bytes) return { ok: false, text: '', reason: 'GraphQL body too large' };
  return { ok: true, text: new TextDecoder().decode(inspected.bytes) };
}

function extractGraphqlQuery(bodyText: string, contentType: string): { ok: boolean; query: string; reason?: string } {
  if (/application\/graphql/i.test(contentType)) {
    return { ok: true, query: bodyText };
  }
  try {
    const parsed = JSON.parse(bodyText);
    if (typeof parsed?.query !== 'string' || parsed.query.trim() === '') {
      return { ok: false, query: '', reason: 'Malformed GraphQL query' };
    }
    return { ok: true, query: parsed.query };
  } catch (_e) {
    return { ok: false, query: '', reason: 'Malformed GraphQL body' };
  }
}

function isGraphqlNameStart(ch: string): boolean {
  if (typeof ch !== 'string' || ch.length !== 1) return false;
  const code = ch.charCodeAt(0);
  return code === 95 || (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

function isGraphqlNameChar(ch: string): boolean {
  if (typeof ch !== 'string' || ch.length !== 1) return false;
  const code = ch.charCodeAt(0);
  return code === 95 || (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || (code >= 48 && code <= 57);
}

function skipGraphqlWhitespace(query: string, start: number): number {
  if (query.startsWith('                ', start)) {
    // Native scanning helps long padding; short separators avoid a slice/search per field.
    const next = query.slice(start).search(/\S/);
    return next < 0 ? query.length : start + next;
  }
  while (start < query.length) {
    const ws = query.charCodeAt(start);
    if (ws !== 32 && (ws < 9 || ws > 13) && (ws < 128 || !/\s/.test(query[start]))) break;
    start++;
  }
  return start;
}

const graphqlKeywords = new Set(['query', 'mutation', 'subscription', 'fragment', 'on', 'true', 'false', 'null']);
function scanGraphqlQuery(query: string, guard: any): GraphqlScanResult {
  let depth = 0;
  let maxDepth = 0;
  let aliases = 0;
  let fields = 0;
  let i = 0;
  let selectionDepth = 0;
  let prevToken = '';

  while (i < query.length) {
    const ch = query[i];

    if (ch === ' ') { i = skipGraphqlWhitespace(query, i); continue; }

    if (ch === '#') {
      while (i < query.length && query[i] !== '\n' && query[i] !== '\r') i++;
      continue;
    }

    if (ch === '"') {
      if (query.slice(i, i + 3) === '"""') {
        i += 3;
        const end = query.indexOf('"""', i);
        if (end === -1) return { ok: false, reason: 'Malformed GraphQL query', depth: maxDepth, aliases, fields };
        i = end + 3;
        continue;
      }
      i++;
      let closed = false;
      while (i < query.length) {
        if (query[i] === '\\') {
          i += 2;
          continue;
        }
        if (query[i] === '"') {
          i++;
          closed = true;
          break;
        }
        i++;
      }
      if (!closed) return { ok: false, reason: 'Malformed GraphQL query', depth: maxDepth, aliases, fields };
      continue;
    }

    if (ch === '{') {
      depth++;
      selectionDepth++;
      if (depth > maxDepth) maxDepth = depth;
      if (maxDepth > guard.maxDepth) {
        return { ok: false, reason: 'GraphQL depth limit exceeded', depth: maxDepth, aliases, fields };
      }
      prevToken = '{';
      i++;
      continue;
    }

    if (ch === '}') {
      depth--;
      selectionDepth = Math.max(0, selectionDepth - 1);
      if (depth < 0) return { ok: false, reason: 'Malformed GraphQL query', depth: maxDepth, aliases, fields };
      prevToken = '}';
      i++;
      continue;
    }

    if (isGraphqlNameStart(ch)) {
      const start = i;
      i++;
      while (i < query.length && isGraphqlNameChar(query[i])) i++;
      const name = query.slice(start, i);
      const j = skipGraphqlWhitespace(query, i);

      if (selectionDepth > 0 && !graphqlKeywords.has(name) && prevToken !== '$' && prevToken !== '@') {
        if (query[j] === ':') {
          aliases++;
          if (aliases > guard.maxAliases) {
            return { ok: false, reason: 'GraphQL alias limit exceeded', depth: maxDepth, aliases, fields };
          }
        } else {
          fields++;
          if (fields > guard.maxFields) {
            return { ok: false, reason: 'GraphQL field limit exceeded', depth: maxDepth, aliases, fields };
          }
        }
      }
      prevToken = name;
      i = j;
      continue;
    }

    if (ch === '$' || ch === '@' || ch === ':' || ch === '(' || ch === ')' || ch === '[' || ch === ']') {
      prevToken = ch;
    }
    i++;
  }

  if (depth !== 0) return { ok: false, reason: 'Malformed GraphQL query', depth: maxDepth, aliases, fields };
  if (maxDepth === 0) return { ok: false, reason: 'Malformed GraphQL query', depth: maxDepth, aliases, fields };
  return { ok: true, depth: maxDepth, aliases, fields };
}

async function enforceGraphqlGuard(request: Request, state: ForwardBody, pathname: string, ctx: ReqCtx): Promise<Response | null> {
  const guard = CFG.graphqlGuard;
  if (!guard || request.method !== 'POST' || !isGraphqlPath(pathname)) return null;

  const body = await readLimitedRequestText(request, state, guard.maxBodyBytes || 65536);
  let scan: GraphqlScanResult;
  if (!body.ok) {
    scan = { ok: false, reason: body.reason || 'GraphQL body too large', depth: 0, aliases: 0, fields: 0 };
  } else {
    const extracted = extractGraphqlQuery(body.text, request.headers.get('content-type') || '');
    scan = extracted.ok
      ? scanGraphqlQuery(extracted.query, guard)
      : { ok: false, reason: extracted.reason || 'Malformed GraphQL query', depth: 0, aliases: 0, fields: 0 };
  }

  if (scan.ok) return null;

  const fields = {
    status: 400,
    block_reason: scan.reason || 'GraphQL guard violation',
    method: ctx.method,
    uri: ctx.uri,
    correlation_id: ctx.correlationId,
    graphql_depth: scan.depth,
    graphql_aliases: scan.aliases,
    graphql_fields: scan.fields,
  };
  if (guard.mode === 'report') {
    logEvent('monitor', fields);
    return null;
  }
  return shouldBlock(400, fields.block_reason, ctx);
}

function base64UrlToBytes(input: string): Uint8Array {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(input.length / 4) * 4, '=');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function decodeJwtPart(part: string): any {
  const bytes = base64UrlToBytes(part);
  const text = new TextDecoder().decode(bytes);
  return JSON.parse(text);
}

function timingSafeEqual(a: string, b: string): boolean {
  // Iterates at least PAD (64) positions so short tokens (the common case)
  // take constant time regardless of prefix match — avoids the admin-prefix
  // timing oracle in threat-model §12. Longer tokens scale with max(|a|, |b|),
  // same as Go's hmac.Equal. No early-exit on length mismatch.
  const PAD = 64;
  const sa = typeof a === 'string' ? a : '';
  const sb = typeof b === 'string' ? b : '';
  let len = sa.length > sb.length ? sa.length : sb.length;
  if (len < PAD) len = PAD;
  let diff = (sa.length ^ sb.length) | 0;
  for (let i = 0; i < len; i++) {
    const ca = i < sa.length ? sa.charCodeAt(i) : 0;
    const cb = i < sb.length ? sb.charCodeAt(i) : 0;
    diff |= (ca ^ cb);
  }
  return diff === 0;
}

async function hmacSha256Base64Url(secret: string, message: string, owner: object): Promise<string> {
  let entry = hmacKeys.get(owner);
  if (!entry || entry.secret !== secret) {
    const key = crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    entry = { secret, key };
    hmacKeys.set(owner, entry);
    // Failed and superseded imports must never replace a newer secret's state.
    void key.catch(() => { if (hmacKeys.get(owner) === entry) hmacKeys.delete(owner); });
  }
  const key = await entry.key;
  const msgData = new TextEncoder().encode(message);
  const sig = await crypto.subtle.sign('HMAC', key, msgData);
  const bytes = new Uint8Array(sig);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

// Runtime SSRF guard — mirrors the build-time validator in scripts/lib/
// compile-core.js. Build already rejects unsafe URLs, but re-checking here
// limits the blast radius of any future regression that lets an http:// or
// private-range URL reach the fetcher.
function isUnsafeJwksUrl(rawUrl: string): string | null {
  let u: URL;
  try { u = new URL(rawUrl); } catch { return 'malformed URL'; }
  if (u.protocol !== 'https:') return 'non-https scheme';
  if (u.username || u.password) return 'userinfo present';
  const host = (u.hostname || '').toLowerCase();
  if (!host || host === 'localhost') return 'loopback hostname';
  if (/^127\./.test(host) || host === '::1' || host === '[::1]') return 'loopback literal';
  if (/^10\./.test(host)) return 'rfc1918 10/8';
  if (/^192\.168\./.test(host)) return 'rfc1918 192.168/16';
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return 'rfc1918 172.16/12';
  if (/^169\.254\./.test(host)) return 'link-local / metadata';
  if (/^0\./.test(host)) return 'reserved 0/8';
  return null;
}

async function readLimitedResponseText(res: Response, maxBytes: number): Promise<string> {
  const body = res.body;
  if (!body) {
    const text = await res.text();
    if (new TextEncoder().encode(text).byteLength > maxBytes) {
      throw new Error('JWKS response too large');
    }
    return text;
  }

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  while (true) {
    const chunk = await reader.read();
    if (chunk.done) break;
    total += chunk.value.byteLength;
    if (total > maxBytes) {
      try { await reader.cancel(); } catch (_e) { /* ignore */ }
      throw new Error('JWKS response too large');
    }
    chunks.push(chunk.value);
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}

function validateJwksKeys(body: any): Array<Record<string, any>> {
  const keys = Array.isArray(body?.keys) ? body.keys : [];
  if (keys.length > JWKS_MAX_KEYS) {
    throw new Error('JWKS key count exceeds limit');
  }
  return keys;
}

async function fetchJwks(
  jwksUrl: string,
  ttlSec: number,
  options?: { forceRefresh?: boolean },
): Promise<Array<Record<string, any>>> {
  const unsafe = isUnsafeJwksUrl(jwksUrl);
  if (unsafe) {
    throw new Error('JWKS URL rejected: ' + unsafe);
  }
  const now = Date.now();
  const cached = jwksCache.get(jwksUrl);
  const forceRefresh = options?.forceRefresh === true;

  // Fresh window — serve cache (skipped on explicit rotation refresh)
  if (!forceRefresh && cached && (now - cached.fetchedAt) < ttlSec * 1000) {
    return cached.keys;
  }

  const staleIfErrorSec: number = typeof (CFG as any).jwksStaleIfErrorSec === 'number' ? (CFG as any).jwksStaleIfErrorSec : 3600;
  const negativeCacheSec: number = typeof (CFG as any).jwksNegativeCacheSec === 'number' ? (CFG as any).jwksNegativeCacheSec : 60;
  const staleWindowMs = (ttlSec + staleIfErrorSec) * 1000;
  const negativeWindowMs = negativeCacheSec * 1000;

  // Honor negative cache — skip re-fetch if we just failed and have stale
  // keys to serve. Prevents hammering a broken IdP.
  const neg = jwksNegativeCache.get(jwksUrl);
  if (neg && (now - neg.failedAt) < negativeWindowMs) {
    if (cached && (now - cached.fetchedAt) < staleWindowMs) {
      console.log('[jwks] serving stale keys (negative cache active)');
      return cached.keys;
    }
    throw new Error('JWKS fetch skipped (negative cache): ' + neg.reason);
  }

  let state = jwksRefreshState.get(jwksUrl);
  if (!state) {
    state = { windowStartedAt: now, attempts: 0 };
    jwksRefreshState.set(jwksUrl, state);
  }
  if (!state.inFlight) {
    // A blocked request must not slide the boundary and starve rotation.
    if (now - state.windowStartedAt >= JWKS_REFRESH_WINDOW_MS) {
      state.windowStartedAt = now;
      state.attempts = 0;
    }
    if (state.attempts >= JWKS_REFRESH_MAX_ATTEMPTS) {
      if (cached && now - cached.fetchedAt < ttlSec * 1000) return cached.keys;
      // Throttling alone does not authorize use of expired keys.
      throw new Error('JWKS refresh window exhausted');
    }
    state.attempts++;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), JWKS_FETCH_TIMEOUT_MS);
    state.inFlight = (async () => {
      try {
        // This compatibility date's workerd rejects `error`. Never follow a 3xx,
        // attacker who briefly controls the JWKS host cannot redirect us to a
        // cloud-metadata endpoint or a different tenant's IdP.
        const res = await fetch(jwksUrl, { method: 'GET', redirect: 'manual', signal: controller.signal });
        if (!res.ok) {
          discardBody(res.body);
          throw new Error('Failed to fetch JWKS: ' + res.status);
        }
        const bodyText = await readLimitedResponseText(res, JWKS_MAX_BODY_BYTES);
        const keys = validateJwksKeys(JSON.parse(bodyText));
        jwksCache.set(jwksUrl, { fetchedAt: Date.now(), keys });
        jwksNegativeCache.delete(jwksUrl);
        return keys;
      } catch (err: any) {
        jwksNegativeCache.set(jwksUrl, { failedAt: Date.now(), reason: err?.message || 'unknown' });
        throw err;
      } finally {
        clearTimeout(timer);
      }
    })();
  }
  const inFlight = state.inFlight;
  try {
    return await inFlight;
  } catch (err: any) {
    // Network work is shared, but different gates can impose different TTLs.
    // Judge stale eligibility separately for every caller after a real failure.
    if (cached && Date.now() - cached.fetchedAt < staleWindowMs) {
      console.log('[jwks] refresh failed, serving stale keys:', err?.message);
      return cached.keys;
    }
    throw err;
  } finally {
    // Neither fulfilled nor rejected work is retained across refreshes.
    if (state.inFlight === inFlight) state.inFlight = undefined;
  }
}

function isJwtAlgAllowed(headerAlg: unknown, gate: any, expected: string): boolean {
  if (typeof headerAlg !== 'string' || headerAlg.length === 0) return false;
  if (headerAlg.toLowerCase() === 'none') return false;
  const allowed: string[] = Array.isArray(gate?.allowed_algorithms) && gate.allowed_algorithms.length > 0
    ? gate.allowed_algorithms
    : [expected];
  return allowed.includes(headerAlg);
}

function isMatchingRs256Jwk(key: any, kid: unknown): boolean {
  return typeof kid === 'string' && kid.length > 0
    && key?.kid === kid
    && key?.kty === 'RSA'
    && (!key.alg || key.alg === 'RS256');
}

async function verifyJwt(gate: any, token: string, env: WorkerEnv): Promise<{ valid: boolean; error?: string; payload?: any }> {
  const parts = token.split('.');
  if (parts.length !== 3) return { valid: false, error: 'Invalid token format' };

  const [headerB64, payloadB64, signatureB64] = parts;

  let header: any;
  let payload: any;
  try {
    header = decodeJwtPart(headerB64);
    payload = decodeJwtPart(payloadB64);
  } catch (_e) {
    return { valid: false, error: 'Malformed JWT' };
  }

  // alg whitelist — reject alg=none and any algorithm not explicitly accepted
  // by this gate. This blocks RS256↔HS256 confusion and the classic alg=none
  // bypass.
  if (!isJwtAlgAllowed(header?.alg, gate, gate.algorithm || 'RS256')) {
    return { valid: false, error: 'Unexpected JWT algorithm' };
  }

  const skewSec: number = Number.isFinite(Number(gate?.clock_skew_sec)) ? Number(gate.clock_skew_sec) : 30;
  const nowSec = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(Number(payload.exp))) return { valid: false, error: 'Missing exp claim' };
  if (nowSec >= Number(payload.exp) + skewSec) return { valid: false, error: 'Token expired' };
  if (payload.nbf && nowSec + skewSec < payload.nbf) return { valid: false, error: 'Token not yet valid' };
  if (gate.issuer && payload.iss !== gate.issuer) return { valid: false, error: 'Invalid issuer' };
  if (gate.audience) {
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(gate.audience)) return { valid: false, error: 'Invalid audience' };
  }

  const signData = `${headerB64}.${payloadB64}`;

  if (gate.algorithm === 'HS256') {
    const secret = env[gate.secret_env] || '';
    if (!secret) return { valid: false, error: 'JWT secret not configured' };
    const expected = await hmacSha256Base64Url(secret, signData, gate);
    if (!timingSafeEqual(expected, signatureB64)) return { valid: false, error: 'Invalid signature' };
    return { valid: true, payload };
  }

  if (gate.algorithm === 'RS256') {
    if (!gate.jwks_url) return { valid: false, error: 'JWKS URL missing' };
    try {
      const ttl = gate.cache_ttl_sec || 3600;
      let keys = await fetchJwks(gate.jwks_url, ttl);
      let jwk = keys.find((k) => isMatchingRs256Jwk(k, header.kid));
      // Key rotation: unknown kid → refresh once WITHOUT deleting the cache
      // first, so a failed IdP fetch still has stale-if-error insurance. All
      // kids share the endpoint's fixed refresh budget and in-flight work.
      if (!jwk) {
        keys = await fetchJwks(gate.jwks_url, ttl, { forceRefresh: true });
        jwk = keys.find((k) => isMatchingRs256Jwk(k, header.kid));
      }
      if (!jwk) {
        return { valid: false, error: 'JWK key not found' };
      }

      let imported = rsaVerifyKeys.get(jwk);
      if (!imported) {
        imported = crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
        rsaVerifyKeys.set(jwk, imported);
        void imported.catch(() => { if (rsaVerifyKeys.get(jwk) === imported) rsaVerifyKeys.delete(jwk); });
      }
      const verifyKey = await imported;
      const ok = await crypto.subtle.verify(
        'RSASSA-PKCS1-v1_5',
        verifyKey,
        base64UrlToBytes(signatureB64),
        new TextEncoder().encode(signData),
      );
      return ok ? { valid: true, payload } : { valid: false, error: 'Invalid signature' };
    } catch (err: any) {
      return { valid: false, error: err?.message || 'JWKS verification failed' };
    }
  }

  return { valid: false, error: 'Unsupported JWT algorithm' };
}

async function verifySignedUrl(gate: any, url: URL, env: WorkerEnv): Promise<{ valid: boolean; error?: string; nonce?: string | null }> {
  const exp = url.searchParams.get(gate.expires_param || 'exp');
  const sig = url.searchParams.get(gate.signature_param || 'sig');
  if (!exp || !sig) return { valid: false, error: 'Missing exp or sig' };

  const expSec = Number(exp);
  if (!Number.isFinite(expSec) || Math.floor(Date.now() / 1000) > expSec) {
    return { valid: false, error: 'URL expired' };
  }

  let nonce: string | null = null;
  if (gate.nonce_param) {
    nonce = url.searchParams.get(gate.nonce_param);
    if (!nonce) return { valid: false, error: 'Missing nonce' };
    if (nonce.length < 16 || nonce.length > 256 || !/^[A-Za-z0-9._~-]+$/.test(nonce)) {
      return { valid: false, error: 'Malformed nonce' };
    }
  }

  const secret = env[gate.secret_env] || '';
  if (!secret) return { valid: false, error: 'URL signing secret not configured' };

  const signData = canonicalSignedUrlPayload(url.pathname, url.searchParams, gate.signature_param || 'sig');
  const expected = await hmacSha256Base64Url(secret, signData, gate);
  if (!timingSafeEqual(expected, sig)) return { valid: false, error: 'Invalid signature' };
  return { valid: true, nonce };
}

function canonicalSignedUrlPayload(pathname: string, params: URLSearchParams, signatureParam: string): string {
  const pairs: Array<[string, string]> = [];
  params.forEach((value, key) => {
    if (key !== signatureParam) pairs.push([key, value]);
  });
  pairs.sort((a, b) => {
    if (a[0] === b[0]) return a[1] < b[1] ? -1 : (a[1] > b[1] ? 1 : 0);
    return a[0] < b[0] ? -1 : 1;
  });
  const query = pairs
    .map(([key, value]) => encodeURIComponent(key) + '=' + encodeURIComponent(value))
    .join('&');
  return query ? `${pathname}?${query}` : pathname;
}

function canonicalOriginAuthQuery(params: URLSearchParams): string {
  const pairs: Array<[string, string]> = [];
  params.forEach((value, key) => pairs.push([key, value]));
  pairs.sort((a, b) => {
    if (a[0] === b[0]) return a[1] < b[1] ? -1 : (a[1] > b[1] ? 1 : 0);
    return a[0] < b[0] ? -1 : 1;
  });
  return pairs
    .map(([key, value]) => encodeURIComponent(key) + '=' + encodeURIComponent(value))
    .join('&');
}

function originAuthSignedComponents(auth: any): string[] {
  return Array.isArray(auth.signed_components) && auth.signed_components.length > 0
    ? auth.signed_components
    : ['method', 'path', 'query', 'body', 'timestamp', 'nonce'];
}

function canonicalOriginAuthInput(request: Request, url: URL, auth: any, timestamp: string, nonce: string, bodyHash: string): string {
  const values: Record<string, string> = {
    method: String(request.method || '').toUpperCase(),
    path: url.pathname || '/',
    query: '',
    body: bodyHash || '',
    timestamp,
    nonce,
  };
  return originAuthSignedComponents(auth).map((component) => component === 'query'
    ? canonicalOriginAuthQuery(url.searchParams) : values[component] || '').join('\n');
}

async function sha256HexBytes(input: BufferSource): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', input);
  const bytes = new Uint8Array(digest);
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

function randomOriginAuthNonce(): string {
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b: number) => b.toString(16).padStart(2, '0')).join('');
}

function isHostAllowed(hostHeader: string): boolean {
  const allowedHosts: string[] = Array.isArray(CFG.allowedHosts) ? CFG.allowedHosts : [];
  if (allowedHosts.length === 0) return true;
  let host = (hostHeader || '').toLowerCase();
  const colon = host.indexOf(':');
  if (colon !== -1) host = host.slice(0, colon);
  for (const allowed of allowedHosts) {
    if (allowed === host) return true;
    if (allowed.length > 2 && allowed.startsWith('*.')) {
      const suffix = allowed.slice(1);
      if (host.length > suffix.length && host.endsWith(suffix)) return true;
    }
  }
  return false;
}

function appendVary(headers: Headers, token: string): void {
  const existing = headers.get('vary') || '';
  const tokens = existing.split(',').map((s: string) => s.trim()).filter(Boolean);
  const lower = tokens.map((s: string) => s.toLowerCase());
  if (lower.indexOf(token.toLowerCase()) === -1) tokens.push(token);
  headers.set('Vary', tokens.join(', '));
}

function handleCorsPreflight(request: Request): Response | null {
  if (request.method !== 'OPTIONS' || !CFG.cors) return null;

  const origin = request.headers.get('origin') || '';
  if (!origin) return null;

  const allowedOrigins = CFG.cors.allow_origins || [];
  const isAllowed = allowedOrigins.includes('*') || allowedOrigins.includes(origin);
  if (!isAllowed) return null;

  const headers = new Headers({
    'Access-Control-Allow-Origin': origin,
    'Cache-Control': 'no-store',
  });
  appendVary(headers, 'Origin');

  if (CFG.cors.allow_methods) headers.set('Access-Control-Allow-Methods', CFG.cors.allow_methods.join(', '));
  if (CFG.cors.allow_headers) headers.set('Access-Control-Allow-Headers', CFG.cors.allow_headers.join(', '));
  if (CFG.cors.allow_credentials) headers.set('Access-Control-Allow-Credentials', 'true');
  if (CFG.cors.max_age) headers.set('Access-Control-Max-Age', String(CFG.cors.max_age));

  return new Response(null, { status: 204, headers });
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(digest);
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

function readCookie(request: Request, name: string): string {
  const cookie = request.headers.get('cookie') || '';
  const parts = cookie.split(';');
  for (const part of parts) {
    const i = part.indexOf('=');
    if (i === -1) continue;
    const key = part.slice(0, i).trim();
    if (key === name) return part.slice(i + 1).trim();
  }
  return '';
}

function removeChallengeParams(url: URL): URL {
  const clean = new URL(url.toString());
  clean.searchParams.delete('__cdn_challenge_seed');
  clean.searchParams.delete('__cdn_challenge_exp');
  clean.searchParams.delete('__cdn_challenge_nonce');
  clean.searchParams.delete('__cdn_challenge_sig');
  return clean;
}

function challengeMatches(url: URL, uaLower: string): boolean {
  const ch = CFG.challenge;
  if (!ch || ch.enabled !== true) return false;
  const prefixes: string[] = Array.isArray(ch.pathPrefixes) ? ch.pathPrefixes : [];
  const uaContains: string[] = Array.isArray(ch.uaContains) ? ch.uaContains : [];
  const pathHit = prefixes.some((p: string) => url.pathname === p || url.pathname.startsWith(p + '/'));
  const uaHit = uaLower && uaContains.some((s: string) => s && uaLower.includes(s));
  return pathHit || uaHit;
}

async function challengeUaBinding(ua: string): Promise<string> {
  return (await sha256Hex(ua || '')).slice(0, 16);
}

async function verifyChallengeCookie(request: Request, env: WorkerEnv, ua: string): Promise<boolean> {
  const ch = CFG.challenge;
  if (!ch || ch.enabled !== true) return false;
  const secret = env[ch.secretEnv || 'CHALLENGE_SECRET'] || '';
  if (!secret) return false;
  const raw = readCookie(request, ch.cookieName || '__cdn_challenge');
  const parts = raw.split('.');
  if (parts.length !== 2) return false;
  const exp = Number(parts[0]);
  const sig = parts[1];
  if (!Number.isFinite(exp) || Math.floor(Date.now() / 1000) > exp) return false;
  const uaHash = await challengeUaBinding(ua);
  const expected = await hmacSha256Base64Url(secret, String(exp) + ':' + uaHash, ch);
  return timingSafeEqual(expected, sig);
}

async function verifyChallengeSolution(url: URL, env: WorkerEnv, ua: string): Promise<boolean> {
  const ch = CFG.challenge;
  if (!ch || ch.enabled !== true) return false;
  const secret = env[ch.secretEnv || 'CHALLENGE_SECRET'] || '';
  if (!secret) return false;
  const seed = url.searchParams.get('__cdn_challenge_seed') || '';
  const expRaw = url.searchParams.get('__cdn_challenge_exp') || '';
  const nonce = url.searchParams.get('__cdn_challenge_nonce') || '';
  const sig = url.searchParams.get('__cdn_challenge_sig') || '';
  if (!seed || !expRaw || !nonce || !sig) return false;
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(seed)) return false;
  if (!/^[0-9a-f]{1,16}$/i.test(nonce)) return false;
  const exp = Number(expRaw);
  if (!Number.isFinite(exp) || Math.floor(Date.now() / 1000) > exp) return false;
  const uaHash = await challengeUaBinding(ua);
  const expectedSig = await hmacSha256Base64Url(secret, seed + ':' + expRaw + ':' + uaHash, ch);
  if (!timingSafeEqual(expectedSig, sig)) return false;
  const difficulty = Math.max(1, Math.min(4, Number(ch.difficulty) || 3));
  const digest = await sha256Hex(seed + ':' + nonce);
  return digest.startsWith('0'.repeat(difficulty));
}

function randomChallengeSeed(): string {
  const buf = new Uint8Array(18);
  crypto.getRandomValues(buf);
  let binary = '';
  for (const b of buf) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function challengeResponse(url: URL, env: WorkerEnv, ua: string, ctx: ReqCtx): Promise<Response> {
  const ch = CFG.challenge;
  const secret = ch ? (env[ch.secretEnv || 'CHALLENGE_SECRET'] || '') : '';
  if (!secret) {
    logEvent('block', {
      status: 503,
      block_reason: 'challenge_secret_missing',
      method: ctx.method,
      uri: ctx.uri,
      correlation_id: ctx.correlationId,
    });
    return deny(503, 'Service Unavailable');
  }
  const seed = randomChallengeSeed();
  const exp = String(Math.floor(Date.now() / 1000) + Math.min(300, Math.max(60, Number(ch.ttlSec) || 900)));
  const uaHash = await challengeUaBinding(ua);
  const sig = await hmacSha256Base64Url(secret, seed + ':' + exp + ':' + uaHash, ch);
  const target = removeChallengeParams(url).toString();
  const difficulty = Math.max(1, Math.min(4, Number(ch.difficulty) || 3));
  const payload = JSON.stringify({ seed, exp, sig, target, difficulty }).replace(/</g, '\\u003c');

  logEvent('challenge', {
    status: 403,
    block_reason: 'js_challenge_required',
    method: ctx.method,
    uri: ctx.uri,
    correlation_id: ctx.correlationId,
  });

  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Security check</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:2rem;line-height:1.5;color:#172033}main{max-width:42rem;margin:auto}</style>
</head>
<body>
<main>
<h1>Security check</h1>
<p>This site is running a lightweight browser verification. It should finish automatically.</p>
<noscript><p>JavaScript is required to complete this experimental verification. Contact the site operator if you cannot enable it.</p></noscript>
</main>
<script>
const c=${payload};
async function hex(s){const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s));return Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join('')}
(async()=>{const prefix='0'.repeat(c.difficulty);for(let i=0;i<2000000;i++){const n=i.toString(16);if((await hex(c.seed+':'+n)).startsWith(prefix)){const u=new URL(c.target);u.searchParams.set('__cdn_challenge_seed',c.seed);u.searchParams.set('__cdn_challenge_exp',c.exp);u.searchParams.set('__cdn_challenge_nonce',n);u.searchParams.set('__cdn_challenge_sig',c.sig);location.replace(u.toString());return}}document.body.querySelector('main').insertAdjacentHTML('beforeend','<p>Verification took too long. Please reload.</p>')})().catch(()=>document.body.querySelector('main').insertAdjacentHTML('beforeend','<p>Verification failed. Please reload.</p>'));
</script>
</body>
</html>`;
  return new Response(html, {
    status: 403,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
    },
  });
}

async function handleChallenge(request: Request, url: URL, env: WorkerEnv, ua: string, uaLower: string, ctx: ReqCtx): Promise<Response | null> {
  const ch = CFG.challenge;
  if (!ch || ch.enabled !== true || !challengeMatches(url, uaLower)) return null;

  if (ch.mode === 'report') {
    logEvent('challenge_report', {
      status: 200,
      block_reason: 'js_challenge_report',
      method: ctx.method,
      uri: ctx.uri,
      correlation_id: ctx.correlationId,
    });
    return null;
  }
  if (ch.mode === 'block') {
    return shouldBlock(403, 'Forbidden', ctx);
  }

  if (await verifyChallengeCookie(request, env, ua)) return null;

  const hasSolution = url.searchParams.has('__cdn_challenge_seed') ||
    url.searchParams.has('__cdn_challenge_exp') ||
    url.searchParams.has('__cdn_challenge_nonce') ||
    url.searchParams.has('__cdn_challenge_sig');
  if (hasSolution && await verifyChallengeSolution(url, env, ua)) {
    const clean = removeChallengeParams(url);
    const ttl = Math.max(60, Math.min(86400, Number(ch.ttlSec) || 900));
    const exp = Math.floor(Date.now() / 1000) + ttl;
    const uaHash = await challengeUaBinding(ua);
    const secret = env[ch.secretEnv || 'CHALLENGE_SECRET'] || '';
    const sig = await hmacSha256Base64Url(secret, String(exp) + ':' + uaHash, ch);
    return new Response(null, {
      status: 302,
      headers: {
        location: clean.toString(),
        'cache-control': 'no-store',
        'set-cookie': `${ch.cookieName || '__cdn_challenge'}=${exp}.${sig}; Max-Age=${ttl}; Path=/; Secure; HttpOnly; SameSite=Lax`,
      },
    });
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return shouldBlock(403, 'Forbidden', ctx);
  }
  return challengeResponse(url, env, ua, ctx);
}

type DlpScanResult = { matched: boolean; detectors: string[]; masked: string };

function isDlpEnabled(): boolean {
  return Boolean(RESPONSE_CFG.responseDlp && RESPONSE_CFG.responseDlp.enabled);
}

function responseDlpLog(action: string, detectors: string[], ctx: ReqCtx, surface: string, status: number) {
  logEvent(action === 'report_only' ? 'monitor' : 'block', {
    status,
    block_reason: 'response_dlp_' + action,
    dlp_surface: surface,
    dlp_detectors: detectors.join(','),
    method: ctx.method,
    uri: ctx.uri,
    correlation_id: ctx.correlationId,
  });
}

function luhnOk(value: string): boolean {
  const digits = value.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let doubleIt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (n < 0 || n > 9) return false;
    if (doubleIt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    doubleIt = !doubleIt;
  }
  return sum % 10 === 0;
}

function replaceAllWithDetector(input: string, re: RegExp, detector: string, mask: string, detectors: Set<string>): string {
  re.lastIndex = 0;
  return input.replace(re, (match: string) => {
    detectors.add(detector);
    return mask;
  });
}

function scanAndMaskDlp(input: string): DlpScanResult {
  const dlp = RESPONSE_CFG.responseDlp || {};
  const builtIn: string[] = dlp.detectors && Array.isArray(dlp.detectors.builtIn)
    ? dlp.detectors.builtIn
    : ['api_key', 'credit_card'];
  const mask = typeof dlp.mask === 'string' ? dlp.mask : '[REDACTED]';
  const detectors = new Set<string>();
  let masked = input;

  if (builtIn.indexOf('api_key') !== -1) {
    masked = masked.replace(/\b(?:sk-live-|sk_test_|ghp_)[A-Za-z0-9_=-]{8,}\b/g, (match: string) => {
      detectors.add('api_key');
      return mask;
    });
  }

  if (builtIn.indexOf('credit_card') !== -1) {
    masked = masked.replace(/\b(?:\d[ -]?){13,19}\b/g, (match: string) => {
      if (!luhnOk(match)) return match;
      detectors.add('credit_card');
      return mask;
    });
  }

  const customRegexes = dlpGlobalRegexes;
  const customNames: string[] = dlp.detectors && Array.isArray(dlp.detectors.customRegexNames)
    ? dlp.detectors.customRegexNames
    : [];
  for (let i = 0; i < customRegexes.length; i++) {
    masked = replaceAllWithDetector(masked, customRegexes[i], customNames[i] || 'custom', mask, detectors);
  }

  return { matched: detectors.size > 0, detectors: Array.from(detectors), masked };
}

function dlpCanInspectBody(out: Response): boolean {
  const dlp = RESPONSE_CFG.responseDlp || {};
  if (!dlp.body || !dlp.body.enabled) return false;
  const contentType = (out.headers.get('content-type') || '').toLowerCase();
  const allowed: string[] = Array.isArray(dlp.body.contentTypes) ? dlp.body.contentTypes : [];
  if (allowed.length > 0 && !allowed.some((ct: string) => contentType.indexOf(ct) !== -1)) return false;
  const len = Number(out.headers.get('content-length') || '0');
  const maxBytes = Number(dlp.body.maxBytes) || 32768;
  return !Number.isFinite(len) || len === 0 || len <= maxBytes;
}

async function applyResponseDlp(out: Response, ctx: ReqCtx): Promise<Response> {
  if (!isDlpEnabled()) return out;
  const dlp = RESPONSE_CFG.responseDlp;
  const action = dlp.action || 'report_only';
  const blockStatus = Number(dlp.blockStatus) || 451;

  if (dlp.headers && dlp.headers.enabled) {
    const names: string[] = Array.isArray(dlp.headers.names) ? dlp.headers.names : [];
    for (const name of names) {
      const value = out.headers.get(name);
      if (!value) continue;
      const scan = scanAndMaskDlp(value);
      if (!scan.matched) continue;
      responseDlpLog(action, scan.detectors, ctx, 'header:' + name, blockStatus);
      out.headers.set('X-Edge-DLP', action);
      if (action === 'block') {
        discardBody(out.body);
        return new Response(dlp.blockBody || 'Response blocked by edge DLP', {
          status: blockStatus,
          headers: { 'Cache-Control': 'no-store', 'X-Edge-DLP': 'block' },
        });
      }
      if (action === 'mask') out.headers.set(name, scan.masked);
    }
  }

  if (!dlpCanInspectBody(out)) return out;
  const maxBytes = Number(dlp.body.maxBytes) || 32768;
  if (!out.body) return out;
  const inspected = await readBoundedBody(out.body, maxBytes);
  if (!inspected.bytes) return new Response(inspected.body, out);
  const text = new TextDecoder().decode(inspected.bytes);
  const scan = scanAndMaskDlp(text);
  if (!scan.matched) return new Response(inspected.bytes, out);
  responseDlpLog(action, scan.detectors, ctx, 'body', blockStatus);
  out.headers.set('X-Edge-DLP', action);
  if (action === 'block') {
    return new Response(dlp.blockBody || 'Response blocked by edge DLP', {
      status: blockStatus,
      headers: { 'Cache-Control': 'no-store', 'X-Edge-DLP': 'block' },
    });
  }
  if (action === 'report_only') return new Response(inspected.bytes, out);
  const maskedHeaders = new Headers(out.headers);
  maskedHeaders.delete('content-length');
  maskedHeaders.set('X-Edge-DLP', 'mask');
  return new Response(scan.masked, {
    status: out.status,
    statusText: out.statusText,
    headers: maskedHeaders,
  });
}

export default {
  async fetch(request: Request, env: WorkerEnv): Promise<Response> {
    const url = new URL(request.url);
    const rawPathname = rawPathnameFromRequestUrl(request.url);
    const ctx = reqCtx(request, url.pathname);
    // This key intentionally precedes correlation-ID minting so random IDs do
    // not make repeated requests enter different sample buckets.
    const allowSamplingKey = /* {{FEATURE_ALLOW_SAMPLING_KEY}} */ true ? allowSampleKey(ctx) : '';

    const preflight = /* {{FEATURE_CORS_REQUEST}} */ true ? handleCorsPreflight(request) : null;
    if (preflight) return preflight;

    // Host allowlist — reject requests whose Host does not match before running
    // any other checks.
    if (!isHostAllowed(request.headers.get('host') || url.hostname)) {
      const r = shouldBlock(400, 'Host Not Allowed', ctx);
      if (r) return r;
    }

    // Geo enforcement (issue #12). request.cf.country is free and arrives before
    // any auth/JWKS work. Block list wins; allow list (non-empty) rejects any
    // country not explicitly enumerated. `T1` / empty represent Tor / unknown —
    // the allow list rejects them by design; block lists that include 'T1'
    // get the opt-in.
    {
      const country = (request as any).cf && (request as any).cf.country
        ? String((request as any).cf.country).toUpperCase()
        : '';
      if (CFG.geoBlockCountries.size > 0 && country && CFG.geoBlockCountries.has(country)) {
        const r = shouldBlock(403, 'Geo Blocked', ctx);
        if (r) return r;
      } else if (CFG.geoAllowCountries.size > 0 && (!country || !CFG.geoAllowCountries.has(country))) {
        const r = shouldBlock(403, 'Geo Blocked', ctx);
        if (r) return r;
      }
    }

    if (request.method === 'OPTIONS' && CFG.cors) {
      // let through non-matching origin preflight
    } else if (!CFG.allowMethods.has(request.method)) {
      const r = shouldBlock(405, 'Method Not Allowed', ctx);
      if (r) return r;
    }

    if (rawPathname.length > CFG.maxUriLength) {
      const r = shouldBlock(414, 'URI Too Long', ctx);
      if (r) return r;
    }

    // Header count cap (issue #9). Applied before path normalization because
    // origins that parse header maps don't care about URI shape.
    let headerCount = 0, headerSize = 0;
    if (CFG.maxHeaderCount > 0 || CFG.maxHeaderSize > 0) {
      request.headers.forEach((value, key) => { headerCount++; headerSize += key.length + value.length; });
    }
    if (CFG.maxHeaderCount && CFG.maxHeaderCount > 0) {
      if (headerCount > CFG.maxHeaderCount) {
        const r = shouldBlock(431, 'Request Header Fields Too Large', ctx);
        if (r) return r;
      }
    }

    if (CFG.maxHeaderSize > 0) {
      if (headerSize > CFG.maxHeaderSize) {
        const r = shouldBlock(431, 'Request Header Fields Too Large', ctx);
        if (r) return r;
      }
    }

    const qs = url.search.slice(1);
    if (qs.length > CFG.maxQueryLength) {
      const r = shouldBlock(414, 'URI Too Long', ctx);
      if (r) return r;
    }
    let queryCount = qs ? 1 : 0;
    for (let i = qs.indexOf('&'); i !== -1; i = qs.indexOf('&', i + 1)) queryCount++;
    if (queryCount > CFG.maxQueryParams) {
      const r = shouldBlock(400, 'Too many query params', ctx);
      if (r) return r;
    }

    const anomalyBlock = blockIfRequestAnomaly(request, rawPathname, qs, ctx);
    if (anomalyBlock) return anomalyBlock;

    if ((CFG.normalizePath || {} as any).rejectAmbiguousEncoding !== false) {
      if (hasAmbiguousPathEncoding(rawPathname) || hasAmbiguousPathEncoding(url.pathname)) {
        const r = shouldBlock(400, 'Bad Request', ctx);
        if (r) return r;
      }
    }

    const rawPathBlock = blockIfPathPattern(rawPathname, ctx);
    if (rawPathBlock) return rawPathBlock;

    const canonical = normalizePath(rawPathname);
    if (canonical === null) {
      const r = shouldBlock(400, 'Bad Request', ctx);
      if (r) return r;
    } else {
      url.pathname = canonical;
    }

    // Identical input already passed; monitor must retain both sets of diagnostics.
    const normalizedPathBlock = CFG.mode !== 'monitor' && url.pathname === rawPathname
      ? null : blockIfPathPattern(url.pathname, ctx);
    if (normalizedPathBlock) return normalizedPathBlock;

    for (const h of CFG.requiredHeaders) {
      const val = request.headers.get(h);
      if (!val) {
        const r = shouldBlock(400, 'Missing ' + h, ctx);
        if (r) return r;
      }
    }

    const ua = request.headers.get('user-agent') || '';
    if (ua && ua.length > 512) {
      const r = shouldBlock(400, 'User-Agent Too Long', ctx);
      if (r) return r;
    }
    const uaLower = ua.toLowerCase();
    const challenge = /* {{FEATURE_CHALLENGE}} */ true ? await handleChallenge(request, url, env, ua, uaLower, ctx) : null;
    if (challenge) return challenge;

    for (const s of CFG.uaDenyContains) {
      if (uaLower.includes(s)) {
        const r = shouldBlock(403, 'Forbidden', ctx);
        if (r) return r;
      }
    }

    // Preserve delete()'s serialization behavior when configured keys are absent.
    if (CFG.dropQueryKeys.size > 0) {
      const params = url.searchParams;
      for (const key of CFG.dropQueryKeys) if (params.has(key)) params.delete(key);
      url.search = params.toString();
    }

    const bodyState: ForwardBody = { body: request.body };
    try {
      const graphqlGuardResponse = /* {{FEATURE_GRAPHQL}} */ true ? await enforceGraphqlGuard(request, bodyState, url.pathname, ctx) : null;
      if (graphqlGuardResponse) return graphqlGuardResponse;

      // Nonce to forward to origin after a successful signed_url verification.
      // Collected here and attached when we build the origin-facing Request.
      let signedUrlNonce: string | null = null;
      const matchPath = normalizeForMatch(url.pathname);
      // One character beyond the longest key preserves the '/' boundary. Keep
      // the full matchPath for exact signed URLs and the forwarded URL below.
      const gateIds = CFG.authGateIndex ? pathCandidates(matchPath.slice(0, CFG.authGateIndexMaxLength + 1), CFG.authGateIndex) : authGateIds;
      for (const gateIndex of gateIds) {
        const gate = CFG.authGates[gateIndex];
        const prefixes = authMatchPrefixes[gateIndex];
        // signed_url gates may opt into exact_path matching to prevent a signature
        // for /assets/ from being replayed against /assets/other-file.
        const useExact = gate.type === 'signed_url' && gate.exact_path === true;
        // Indexed candidates already satisfy prefix matching; exact signed URLs
        // still need the narrower check before any credential verification.
        const isProtected = useExact
          ? prefixes.some((p: string) => pathMatchesExact(matchPath, p))
          : (CFG.authGateIndex ? true : prefixes.some((p: string) => pathMatchesPrefix(matchPath, p)));
        if (!isProtected) continue;

        if (/* {{FEATURE_STATIC_TOKEN}} */ true && gate.type === 'static_token') {
          const tok = request.headers.get(gate.tokenHeaderName) || '';
          const expectedToken = env[gate.tokenEnv] || '';
          if (!expectedToken) {
            console.error('[auth] static_token env missing:', gate.tokenEnv);
            return shouldBlockAuth(503, 'Auth misconfigured', ctx);
          }
          if (!timingSafeEqual(tok, expectedToken)) {
            return shouldBlockAuth(401, 'Unauthorized', ctx);
          }
        } else if (/* {{FEATURE_BASIC_AUTH}} */ true && gate.type === 'basic_auth') {
          const authHeader = request.headers.get('authorization') || '';
          const expectedCreds = env[gate.credentialsEnv] || '';
          if (!expectedCreds) {
            console.error('[auth] basic_auth env missing:', gate.credentialsEnv);
            return shouldBlockAuth(503, 'Auth misconfigured', ctx);
          }
          if (!authHeader.startsWith('Basic ')) {
            logEvent(CFG.mode === 'monitor' ? 'monitor' : 'block', {
              status: 401,
              block_reason: 'Missing Basic auth',
              method: ctx.method,
              uri: ctx.uri,
              correlation_id: ctx.correlationId,
            });
            return new Response('Unauthorized', {
              status: 401,
              headers: { 'WWW-Authenticate': 'Basic realm="Protected"', 'Cache-Control': 'no-store' },
            });
          } else {
            const provided = authHeader.slice(6);
            if (!timingSafeEqual(provided, expectedCreds)) {
              logEvent(CFG.mode === 'monitor' ? 'monitor' : 'block', {
                status: 401,
                block_reason: 'Invalid Basic auth credentials',
                method: ctx.method,
                uri: ctx.uri,
                correlation_id: ctx.correlationId,
              });
              return new Response('Unauthorized', {
                status: 401,
                headers: { 'WWW-Authenticate': 'Basic realm="Protected"', 'Cache-Control': 'no-store' },
              });
            }
          }
        } else if (/* {{FEATURE_JWT}} */ true && gate.type === 'jwt') {
          const authHeader = request.headers.get('authorization') || '';
          if (!authHeader.startsWith('Bearer ')) {
            return shouldBlockAuth(401, 'Missing or invalid Authorization header', ctx);
          }
          const token = authHeader.slice(7);
          const verified = await verifyJwt(gate, token, env);
          if (!verified.valid) {
            return shouldBlockAuth(401, verified.error || 'Invalid token', ctx);
          }
          if (CFG.obs && CFG.obs.auditLogAuth) {
            const rawSub = (verified.payload && verified.payload.sub) || '';
            logEvent('audit', {
              auth_event: 'auth_pass',
              gate_type: 'jwt',
              gate_name: gate.name || '',
              sub: CFG.obs.auditHashSub ? await hashSub(rawSub) : rawSub,
              method: ctx.method,
              uri: ctx.uri,
              correlation_id: ctx.correlationId,
            });
          }
        } else if (/* {{FEATURE_SIGNED_URL}} */ true && gate.type === 'signed_url') {
          const verified = await verifySignedUrl(gate, url, env);
          if (!verified.valid) {
            return shouldBlockAuth(403, verified.error || 'Invalid signature', ctx);
          }
          if (gate.nonce_param && verified.nonce) {
            signedUrlNonce = verified.nonce;
          }
          if (CFG.obs && CFG.obs.auditLogAuth) {
            logEvent('audit', {
              auth_event: 'auth_pass',
              gate_type: 'signed_url',
              gate_name: gate.name || '',
              method: ctx.method,
              uri: ctx.uri,
              correlation_id: ctx.correlationId,
            });
          }
        }
      }

      const forwardHeaders = new Headers(request.headers);
      // Strip any client-supplied edge-auth marker before forwarding to origin.
      // Only the edge is allowed to assert this; trusting an incoming value
      // would let a client spoof authenticated state.
      forwardHeaders.delete('x-edge-authenticated');
      // Never trust a viewer-provided nonce. Mint it before origin fetch so the
      // origin can apply the same nonce to the HTML it returns.
      forwardHeaders.delete('x-csp-nonce');
      let cspNonce = '';
      if (/* {{FEATURE_CSP_NONCE}} */ true && RESPONSE_CFG.csp_nonce) {
        const nonceBytes = new Uint8Array(16);
        crypto.getRandomValues(nonceBytes);
        cspNonce = btoa(String.fromCharCode(...nonceBytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        forwardHeaders.set('X-CSP-Nonce', cspNonce);
      }
      // Strip client-supplied X-Forwarded-For unless explicitly trusted. The
      // real client IP is already available via cf-connecting-ip, and a spoofed
      // XFF value can poison downstream rate limiters, IP allowlists, and logs.
      if (!CFG.trustForwardedFor) {
        forwardHeaders.delete('x-forwarded-for');
      }
      // Request-smuggling defense: strip hop-by-hop headers before origin
      // forward. Any client-supplied Transfer-Encoding / Connection / Upgrade
      // can desynchronize Worker ↔ origin framing (CL.TE, TE.CL, H2.TE) and
      // smuggle a second request. Cloudflare re-frames the request, so these
      // headers carry no legitimate meaning from the viewer.
      for (const h of ['transfer-encoding', 'connection', 'keep-alive', 'te', 'upgrade', 'proxy-connection', 'proxy-authenticate', 'proxy-authorization', 'trailer']) {
        forwardHeaders.delete(h);
      }
      if (/* {{FEATURE_ORIGIN_AUTH}} */ true && CFG.originAuth && (CFG.originAuth.type === 'custom_header' || CFG.originAuth.type === 'hmac_signature')) {
        const envName = CFG.originAuth.secret_env || '';
        const secret = envName ? (env[envName] || '') : '';
        if (secret) {
          if (/* {{FEATURE_ORIGIN_HMAC}} */ true && CFG.originAuth.type === 'hmac_signature') {
            const prefix = CFG.originAuth.header_prefix || 'X-CDN-Auth';
            const timestamp = String(Math.floor(Date.now() / 1000));
            const nonce = randomOriginAuthNonce();
            let bodyHash = '';
            if (CFG.originAuth.include_body_hash === true) {
              const hadBody = bodyState.body !== null;
              // The same bytes are signed and forwarded. Temporary Request clones
              // can let Node's GC finalizer cancel the original tee branch.
              const buffered = bodyState.body;
              const bytes = buffered instanceof ArrayBuffer || ArrayBuffer.isView(buffered)
                ? buffered : await new Response(buffered).arrayBuffer();
              bodyState.body = hadBody ? bytes : null;
              bodyHash = await sha256HexBytes(bytes);
            }
            const canonical = canonicalOriginAuthInput(request, url, CFG.originAuth, timestamp, nonce, bodyHash);
            const signature = await hmacSha256Base64Url(secret, canonical, CFG.originAuth);
            forwardHeaders.set(prefix + '-Timestamp', timestamp);
            forwardHeaders.set(prefix + '-Nonce', nonce);
            if (CFG.originAuth.include_body_hash === true) {
              forwardHeaders.set(prefix + '-Body-SHA256', bodyHash);
            }
            forwardHeaders.set(prefix + '-Signature', signature);
          } else {
            const headerName = CFG.originAuth.header || 'X-Origin-Verify';
            forwardHeaders.set(headerName, secret);
          }
        } else {
          console.log(JSON.stringify({
            ts: new Date().toISOString(),
            level: 'error',
            event: 'error',
            block_reason: 'origin_auth_secret_missing',
            secret_env: envName,
            uri: ctx.uri,
            correlation_id: ctx.correlationId,
          }));
          return shouldBlockAuth(503, 'Origin auth misconfigured', ctx);
        }
      }
      // Forward signed-URL nonce so origin can enforce single-use. The edge
      // cannot enforce replay protection statelessly — origin must reject
      // re-use (SET NX in KV/Redis).
      if (signedUrlNonce) {
        forwardHeaders.set('X-Signed-URL-Nonce', signedUrlNonce);
      }

      // Propagate correlation / trace header so origin logs can join edge logs.
      // When the header is missing, mint one so every request has a stable ID.
      let forwardedCorrelationId = ctx.correlationId;
      if (CFG.obs && CFG.obs.correlationHeader) {
        const incoming = request.headers.get(CFG.obs.correlationHeader);
        if (!incoming) {
          const buf = new Uint8Array(16);
          crypto.getRandomValues(buf);
          const id = Array.from(buf, (b: number) => b.toString(16).padStart(2, '0')).join('');
          forwardHeaders.set(CFG.obs.correlationHeader, id);
          forwardedCorrelationId = id;
        }
      }

      if (/* {{FEATURE_ALLOW_SAMPLING}} */ true) logAllow({ ...ctx, correlationId: forwardedCorrelationId }, allowSamplingKey);

      const res = await fetch(new Request(url.toString(), {
        method: request.method,
        headers: forwardHeaders,
        body: bodyState.body,
        redirect: request.redirect,
        ...({ duplex: 'half' } as any),
      }));

      bodyState.body = null;
      const out = new Response(res.body, res);
      const rh = RESPONSE_CFG.headers;
      if (rh['strict-transport-security']) out.headers.set('Strict-Transport-Security', rh['strict-transport-security']);
      if (rh['x-content-type-options']) out.headers.set('X-Content-Type-Options', rh['x-content-type-options']);
      if (rh['referrer-policy']) out.headers.set('Referrer-Policy', rh['referrer-policy']);
      if (rh['permissions-policy']) out.headers.set('Permissions-Policy', rh['permissions-policy']);

      // Cross-Origin isolation (issue #10). Only emitted when operator opts in.
      if (RESPONSE_CFG.coop) out.headers.set('Cross-Origin-Opener-Policy', RESPONSE_CFG.coop);
      if (RESPONSE_CFG.coep) out.headers.set('Cross-Origin-Embedder-Policy', RESPONSE_CFG.coep);
      if (RESPONSE_CFG.corp) out.headers.set('Cross-Origin-Resource-Policy', RESPONSE_CFG.corp);
      if (RESPONSE_CFG.reporting_endpoints) out.headers.set('Reporting-Endpoints', RESPONSE_CFG.reporting_endpoints);

      const isAdminPath = RESPONSE_CFG.adminPathIndex ? pathHasMatch(matchPath.slice(0, RESPONSE_CFG.adminPathIndexMaxLength + 1), RESPONSE_CFG.adminPathIndex)
        : adminMatchPrefixes.some((p: string) => pathMatchesPrefix(matchPath, p));
      const isAuthPath = RESPONSE_CFG.authPathIndex ? pathHasMatch(matchPath.slice(0, RESPONSE_CFG.authPathIndexMaxLength + 1), RESPONSE_CFG.authPathIndex)
        : protectedMatchPrefixes.some((p: string) => pathMatchesPrefix(matchPath, p));

      // Per-response CSP nonce (issue #11). crypto.getRandomValues is a CS-PRNG on Workers.
      if (cspNonce) out.headers.set('X-CSP-Nonce', cspNonce);
      const applyNonce = (csp: string): string => {
        if (!csp || !cspNonce) return csp;
        return csp.split("'nonce-PLACEHOLDER'").join("'nonce-" + cspNonce + "'");
      };

      if (isAdminPath) {
        if (RESPONSE_CFG.adminCacheControl) out.headers.set('Cache-Control', RESPONSE_CFG.adminCacheControl);
        if (RESPONSE_CFG.csp_admin) out.headers.set('Content-Security-Policy', applyNonce(RESPONSE_CFG.csp_admin));
      } else {
        if (RESPONSE_CFG.csp_public) out.headers.set('Content-Security-Policy', applyNonce(RESPONSE_CFG.csp_public));
      }

      if (RESPONSE_CFG.csp_report_only) {
        out.headers.set('Content-Security-Policy-Report-Only', applyNonce(RESPONSE_CFG.csp_report_only));
      }

      // Force no-store + Vary on any auth-gate prefix (issue #8). Broader than adminPathPrefixes
      // which only fires for the first admin-shaped route.
      if (RESPONSE_CFG.forceVaryAuth && isAuthPath) {
        out.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        out.headers.set('Pragma', 'no-cache');
        appendVary(out.headers, 'Authorization');
        appendVary(out.headers, 'Cookie');
      }

      // Clear-Site-Data on configured logout paths (issue #20). Only on 2xx/3xx.
      const status = out.status;
      const isSuccess = status >= 200 && status < 400;
      const hitsClearPath = (RESPONSE_CFG.clearSiteDataPaths || []).some((p: string) =>
        url.pathname === p || url.pathname.startsWith(p + '/'),
      );
      if (hitsClearPath && isSuccess) {
        if (clearSiteDataValue) out.headers.set('Clear-Site-Data', clearSiteDataValue);
        out.headers.set('Cache-Control', 'no-store');
      }

      out.headers.delete('x-powered-by');
      out.headers.delete('server');

      // Cookie attribute append — multi-cookie aware via getAll/append (issue #13).
      if (RESPONSE_CFG.cookie_attributes) {
        const attrs: string[] = [];
        if (RESPONSE_CFG.cookie_attributes.secure) attrs.push('Secure');
        if (RESPONSE_CFG.cookie_attributes.http_only) attrs.push('HttpOnly');
        if (RESPONSE_CFG.cookie_attributes.same_site) attrs.push('SameSite=' + RESPONSE_CFG.cookie_attributes.same_site);

        if (attrs.length > 0) {
          // Workers runtime exposes multiple Set-Cookie via Headers#getSetCookie()
          // (per the Fetch standard). Fall back to get() on older runtimes.
          type HeadersWithGetSetCookie = Headers & { getSetCookie?: () => string[] };
          const h = out.headers as HeadersWithGetSetCookie;
          const cookies: string[] = typeof h.getSetCookie === 'function'
            ? h.getSetCookie()
            : (out.headers.get('set-cookie') ? [out.headers.get('set-cookie') as string] : []);
          if (cookies.length > 0) {
            out.headers.delete('set-cookie');
            for (const cookie of cookies) {
              const needsSecure = RESPONSE_CFG.cookie_attributes.secure && !/(?:^|; *)Secure(?:;|$)/i.test(cookie);
              const needsHttpOnly = RESPONSE_CFG.cookie_attributes.http_only && !/(?:^|; *)HttpOnly(?:;|$)/i.test(cookie);
              const needsSameSite = RESPONSE_CFG.cookie_attributes.same_site && !/(?:^|; *)SameSite=/i.test(cookie);
              if (needsSecure || needsHttpOnly || needsSameSite) {
                const missing: string[] = [];
                if (needsSecure) missing.push('Secure');
                if (needsHttpOnly) missing.push('HttpOnly');
                if (needsSameSite) missing.push('SameSite=' + RESPONSE_CFG.cookie_attributes.same_site);
                out.headers.append('Set-Cookie', cookie + '; ' + missing.join('; '));
              } else {
                out.headers.append('Set-Cookie', cookie);
              }
            }
          }
        }
      }

      if (/* {{FEATURE_CORS_RESPONSE}} */ true && RESPONSE_CFG.cors) {
        const origin = request.headers.get('origin') || '';
        const allowedOrigins = RESPONSE_CFG.cors.allow_origins || [];
        const isAllowed = allowedOrigins.includes('*') || allowedOrigins.includes(origin);

        if (origin && isAllowed) {
          out.headers.set('Access-Control-Allow-Origin', origin);
          appendVary(out.headers, 'Origin');
          if (RESPONSE_CFG.cors.allow_credentials) out.headers.set('Access-Control-Allow-Credentials', 'true');
          if (RESPONSE_CFG.cors.expose_headers?.length > 0) out.headers.set('Access-Control-Expose-Headers', RESPONSE_CFG.cors.expose_headers.join(', '));
        }
      }

      return /* {{FEATURE_DLP}} */ true ? await applyResponseDlp(out, ctx) : out;
    } finally {
      // Auth/config rejection and exceptions must release the inspected upload.
      // A successful fetch above transfers ownership and clears this state.
      cancelForwardBody(bodyState);
    }
  },
};
