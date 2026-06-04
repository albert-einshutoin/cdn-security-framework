/**
 * Lambda@Edge - Origin Request — TEMPLATE
 *
 * 【注意】このファイルはテンプレートです。直接デプロイしないでください。
 * security.yml を編集し、npx cdn-security build で dist/edge/origin-request.js を生成してください。
 *
 * Purpose:
 * - Heavier logic than CloudFront Functions: JWT validation, signature verification, dynamic rules
 * - Final gate before traffic reaches Origin
 *
 * You can also:
 * - Verify Cognito/OIDC JWT (RS256)
 * - Add internal headers visible only to origin
 */

const crypto = require('crypto');
const https = require('https');

const CFG = {
  project: "example-cdn-security",
  mode: "enforce",
  maxHeaderSize: 0,
  trustForwardedFor: false,
  jwtGates: [],
  signedUrlGates: [],
  originAuth: null,
  jwksStaleIfErrorSec: 3600,
  jwksNegativeCacheSec: 60,
  obs: {"logFormat":"json","correlationHeader":"traceparent","sampleRate":0,"auditLogAuth":true,"auditHashSub":true},
};

// JWKS cache (persists across Lambda container reuse).
// Each entry: { keys, time }  — time is ms since epoch of last successful fetch.
// Negative cache: { failedAt } — records last fetch failure timestamp to
// avoid hammering a broken IdP.
let jwksCache = {};
let jwksNegativeCache = {};
const JWKS_CACHE_TTL = 600000; // 10 min fresh window (issue #41 default)
function jwksStaleIfErrorMs() {
  return (CFG && typeof CFG.jwksStaleIfErrorSec === 'number' ? CFG.jwksStaleIfErrorSec : 3600) * 1000;
}
function jwksNegativeCacheMs() {
  return (CFG && typeof CFG.jwksNegativeCacheSec === 'number' ? CFG.jwksNegativeCacheSec : 60) * 1000;
}

function resp(statusCode, body) {
  return {
    status: String(statusCode),
    statusDescription: body,
    headers: {
      'content-type': [{ key: 'Content-Type', value: 'text/plain; charset=utf-8' }],
      'cache-control': [{ key: 'Cache-Control', value: 'no-store' }],
    },
    body: body || 'Denied',
  };
}

function checkHeaderSize(request) {
  if (!CFG.maxHeaderSize || CFG.maxHeaderSize <= 0) return null;
  
  let totalSize = 0;
  const headers = request.headers || {};
  for (const key of Object.keys(headers)) {
    const headerArray = headers[key];
    if (Array.isArray(headerArray)) {
      for (const h of headerArray) {
        totalSize += (key.length + (h.value || '').length);
      }
    }
  }
  
  if (totalSize > CFG.maxHeaderSize) {
    return resp(431, 'Request Header Fields Too Large');
  }
  return null;
}

// Defense-in-depth check before every outbound JWKS fetch. The build-time
// validator already rejects unsafe URLs, but runtime re-validation limits
// the blast radius of any future regression (cache-poisoning, config hot-
// reload bugs, operator typo bypassing lint) that allows an http:// or
// private-range URL to reach here.
function isUnsafeJwksUrl(rawUrl) {
  let u;
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

// Raw network fetch (no cache). Caller handles caching policy.
function fetchJwksNetwork(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, (res) => {
      // Refuse to follow cross-origin redirects (302 to 169.254.169.254,
      // to http://, etc.). Node's https.get does not follow redirects by
      // default, but be explicit in case that ever changes.
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400) {
        res.resume();
        reject(new Error('JWKS fetch refused redirect: ' + res.statusCode));
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error('JWKS fetch failed: ' + res.statusCode));
        return;
      }
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const jwks = JSON.parse(data);
          resolve(jwks.keys);
        } catch (e) {
          reject(e);
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(5000, () => {
      req.destroy();
      reject(new Error('JWKS fetch timeout'));
    });
  });
}

// Fetch JWKS with:
// - Fresh cache window (JWKS_CACHE_TTL, 10 min)
// - Negative cache on failure (CFG.jwksNegativeCacheSec) to avoid hammering
//   a broken IdP
// - Stale-if-error (CFG.jwksStaleIfErrorSec) — on refresh failure, keep
//   serving the last known-good keys until this window expires
async function fetchJwks(url) {
  const unsafe = isUnsafeJwksUrl(url);
  if (unsafe) {
    throw new Error('JWKS URL rejected: ' + unsafe);
  }
  const now = Date.now();
  const cached = jwksCache[url];

  // Serve fresh cache
  if (cached && (now - cached.time) < JWKS_CACHE_TTL) {
    return cached.keys;
  }

  // Honor negative cache window
  const neg = jwksNegativeCache[url];
  if (neg && (now - neg.failedAt) < jwksNegativeCacheMs()) {
    // If we have stale-but-within-stale-window keys, keep serving them
    if (cached && (now - cached.time) < (JWKS_CACHE_TTL + jwksStaleIfErrorMs())) {
      console.log('[jwks] serving stale keys (negative cache active)');
      return cached.keys;
    }
    throw new Error('JWKS fetch skipped (negative cache): ' + (neg.reason || 'unknown'));
  }

  try {
    const keys = await fetchJwksNetwork(url);
    jwksCache[url] = { keys, time: now };
    delete jwksNegativeCache[url];
    return keys;
  } catch (err) {
    jwksNegativeCache[url] = { failedAt: now, reason: err && err.message };
    // Stale-if-error: fall back to last known-good keys if still within the
    // stale-if-error window
    if (cached && (now - cached.time) < (JWKS_CACHE_TTL + jwksStaleIfErrorMs())) {
      console.log('[jwks] refresh failed, serving stale keys:', err && err.message);
      return cached.keys;
    }
    throw err;
  }
}

function invalidateJwksCache(url) {
  delete jwksCache[url];
  delete jwksNegativeCache[url];
}

// Base64URL decode
function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

// Guard against alg-confusion attacks. The configured gate decides which
// header.alg values are acceptable; attackers who flip RS256 → HS256 (or set
// alg=none) must be rejected before any signature math runs.
function isAlgAllowed(headerAlg, gate, expected) {
  if (!headerAlg || typeof headerAlg !== 'string') return false;
  if (headerAlg.toLowerCase() === 'none') return false;
  const allowed = Array.isArray(gate && gate.allowed_algorithms) && gate.allowed_algorithms.length > 0
    ? gate.allowed_algorithms
    : [expected];
  return allowed.indexOf(headerAlg) !== -1;
}

// Verify JWT signature (RS256)
async function verifyJwtRS256(token, gate) {
  const parts = token.split('.');
  if (parts.length !== 3) return { valid: false, error: 'Invalid token format' };

  const [headerB64, payloadB64, signatureB64] = parts;

  try {
    const header = JSON.parse(base64UrlDecode(headerB64).toString());
    const payload = JSON.parse(base64UrlDecode(payloadB64).toString());

    // alg whitelist — reject alg=none and unexpected algorithms (e.g., HS256
    // substituted for RS256 to bypass signature verification with the public
    // JWKS key treated as an HMAC secret).
    if (!isAlgAllowed(header.alg, gate, 'RS256')) {
      return { valid: false, error: 'Unexpected JWT algorithm' };
    }

    const skewMs = (gate && Number.isFinite(Number(gate.clock_skew_sec))
      ? Number(gate.clock_skew_sec) : 30) * 1000;
    const now = Date.now();

    // Check expiration (required, with skew tolerance)
    if (!Number.isFinite(Number(payload.exp))) {
      return { valid: false, error: 'Missing exp claim' };
    }
    if (now >= Number(payload.exp) * 1000 + skewMs) {
      return { valid: false, error: 'Token expired' };
    }

    // Check not-before (with skew tolerance)
    if (payload.nbf && now + skewMs < payload.nbf * 1000) {
      return { valid: false, error: 'Token not yet valid' };
    }

    const issuer = gate && gate.issuer;
    const audience = gate && gate.audience;
    const jwksUrl = gate && gate.jwks_url;

    // Check issuer
    if (issuer && payload.iss !== issuer) {
      return { valid: false, error: 'Invalid issuer' };
    }

    // Check audience
    if (audience) {
      const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!aud.includes(audience)) {
        return { valid: false, error: 'Invalid audience' };
      }
    }

    // Fetch JWKS and find matching key; retry once on kid miss (cache refresh)
    let keys = await fetchJwks(jwksUrl);
    let key = keys.find(k => k.kid === header.kid && k.alg === 'RS256');
    if (!key) {
      invalidateJwksCache(jwksUrl);
      keys = await fetchJwks(jwksUrl);
      key = keys.find(k => k.kid === header.kid && k.alg === 'RS256');
      if (!key) {
        return { valid: false, error: 'Key not found' };
      }
    }

    // Verify signature using Node crypto
    const signData = headerB64 + '.' + payloadB64;
    const signature = base64UrlDecode(signatureB64);

    // Convert JWK to PEM
    const pubKey = crypto.createPublicKey({
      key: key,
      format: 'jwk',
    });

    const isValid = crypto.verify(
      'sha256',
      Buffer.from(signData),
      pubKey,
      signature
    );

    return { valid: isValid, payload };
  } catch (e) {
    return { valid: false, error: e.message };
  }
}

// Verify JWT with HS256 (symmetric key)
function verifyJwtHS256(token, secret, gate) {
  if (!secret) {
    return { valid: false, error: 'JWT secret not configured' };
  }

  const parts = token.split('.');
  if (parts.length !== 3) return { valid: false, error: 'Invalid token format' };

  const [headerB64, payloadB64, signatureB64] = parts;

  try {
    const header = JSON.parse(base64UrlDecode(headerB64).toString());
    const payload = JSON.parse(base64UrlDecode(payloadB64).toString());

    // alg whitelist — reject alg=none and any alg not in the gate's allowlist.
    if (!isAlgAllowed(header.alg, gate, 'HS256')) {
      return { valid: false, error: 'Unexpected JWT algorithm' };
    }

    const skewMs = (gate && Number.isFinite(Number(gate.clock_skew_sec))
      ? Number(gate.clock_skew_sec) : 30) * 1000;
    const now = Date.now();

    // Check expiration (required, with skew tolerance)
    if (!Number.isFinite(Number(payload.exp))) {
      return { valid: false, error: 'Missing exp claim' };
    }
    if (now >= Number(payload.exp) * 1000 + skewMs) {
      return { valid: false, error: 'Token expired' };
    }

    // Check not-before (with skew tolerance)
    if (payload.nbf && now + skewMs < payload.nbf * 1000) {
      return { valid: false, error: 'Token not yet valid' };
    }

    const issuer = gate && gate.issuer;
    const audience = gate && gate.audience;

    // Check issuer
    if (issuer && payload.iss !== issuer) {
      return { valid: false, error: 'Invalid issuer' };
    }

    // Check audience
    if (audience) {
      const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!aud.includes(audience)) {
        return { valid: false, error: 'Invalid audience' };
      }
    }

    // Compute expected signature
    const signData = headerB64 + '.' + payloadB64;
    const expectedSig = crypto.createHmac('sha256', secret)
      .update(signData)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    // Timing-safe comparison
    const expectedBuf = Buffer.from(expectedSig, 'utf8');
    const providedBuf = Buffer.from(signatureB64, 'utf8');
    const isValid = expectedBuf.length === providedBuf.length &&
      crypto.timingSafeEqual(expectedBuf, providedBuf);

    return { valid: isValid, payload };
  } catch (e) {
    return { valid: false, error: e.message };
  }
}

// Verify signed URL
function verifySignedUrl(uri, querystring, gate) {
  const params = new URLSearchParams(querystring);
  const exp = params.get(gate.expires_param);
  const sig = params.get(gate.signature_param);

  if (!exp || !sig) return { valid: false, error: 'Missing exp or sig' };
  if (Date.now() > parseInt(exp) * 1000) return { valid: false, error: 'URL expired' };

  let nonce = null;
  if (gate.nonce_param) {
    nonce = params.get(gate.nonce_param);
    if (!nonce) return { valid: false, error: 'Missing nonce' };
    // Reject empty / overly long nonces before hitting origin. 16..256 chars
    // matches a typical ULID/UUID/base64(16B) envelope; anything outside that
    // is almost certainly crafted noise.
    if (nonce.length < 16 || nonce.length > 256 || !/^[A-Za-z0-9._~-]+$/.test(nonce)) {
      return { valid: false, error: 'Malformed nonce' };
    }
  }

  // Compute expected signature over the path and every query parameter except
  // the signature itself. This prevents a valid URL for one resource selector
  // (for example ?file=a.pdf) from being replayed with a different selector on
  // the same path.
  const secret = process.env[gate.secret_env] || '';
  if (!secret) return { valid: false, error: 'Secret not configured' };

  const signData = canonicalSignedUrlPayload(uri, params, gate.signature_param);
  const expectedSig = crypto.createHmac('sha256', secret)
    .update(signData)
    .digest('base64url');

  // Timing-safe comparison
  const expectedBuf = Buffer.from(expectedSig, 'utf8');
  const providedBuf = Buffer.from(sig, 'utf8');
  const isValid = expectedBuf.length === providedBuf.length &&
    crypto.timingSafeEqual(expectedBuf, providedBuf);

  return { valid: isValid, nonce };
}

function canonicalSignedUrlPayload(uri, params, signatureParam) {
  const pairs = [];
  for (const [key, value] of params.entries()) {
    if (key === signatureParam) continue;
    pairs.push([key, value]);
  }
  pairs.sort((a, b) => {
    if (a[0] === b[0]) return a[1] < b[1] ? -1 : (a[1] > b[1] ? 1 : 0);
    return a[0] < b[0] ? -1 : 1;
  });
  const query = pairs
    .map(([key, value]) => encodeURIComponent(key) + '=' + encodeURIComponent(value))
    .join('&');
  return query ? uri + '?' + query : uri;
}

// Check JWT auth gates
async function checkJwtGates(request) {
  const uri = request.uri || '/';
  
  for (const gate of CFG.jwtGates) {
    const isProtected = gate.protectedPrefixes.some(
      p => uri === p || uri.startsWith(p + '/')
    );
    if (!isProtected) continue;
    
    // Get token from Authorization header
    const authHeader = request.headers['authorization'];
    const token = authHeader && authHeader[0] && authHeader[0].value;
    if (!token || !token.startsWith('Bearer ')) {
      return resp(401, 'Missing or invalid Authorization header');
    }
    
    const jwt = token.slice(7); // Remove 'Bearer '
    
    let result;
    if (gate.algorithm === 'RS256' && gate.jwks_url) {
      result = await verifyJwtRS256(jwt, gate);
    } else if (gate.algorithm === 'HS256' && gate.secret_env) {
      const secret = process.env[gate.secret_env] || '';
      if (!secret) {
        return resp(503, 'JWT gate misconfigured');
      }
      result = verifyJwtHS256(jwt, secret, gate);
    } else {
      return resp(500, 'JWT gate misconfigured');
    }
    
    if (!result.valid) {
      return resp(401, result.error || 'Invalid token');
    }
    
    // Add verified claims to request header for origin
    if (result.payload) {
      request.headers['x-jwt-sub'] = [{ key: 'X-JWT-Sub', value: result.payload.sub || '' }];
    }

    if (CFG.obs && CFG.obs.auditLogAuth) {
      const rawSub = (result.payload && result.payload.sub) || '';
      logEvent('audit', {
        auth_event: 'auth_pass',
        gate_type: 'jwt',
        gate_name: gate.name || '',
        sub: CFG.obs.auditHashSub ? hashSub(rawSub) : rawSub,
        method: request.method,
        uri,
        correlation_id: readCorrelation(request),
      });
    }
  }

  return null;
}

// Check signed URL gates
function checkSignedUrlGates(request) {
  const uri = request.uri || '/';
  const qs = request.querystring || '';

  for (const gate of CFG.signedUrlGates) {
    // exact_path: signature is bound to the exact URI. Without it, a signed
    // URL for /assets/ can be replayed against /assets/other-file if an
    // operator accidentally signs a prefix. exact_path rejects any request
    // whose URI is not one of the protected paths verbatim.
    const isProtected = gate.exact_path
      ? gate.protectedPrefixes.some((p) => uri === p)
      : gate.protectedPrefixes.some((p) => uri === p || uri.startsWith(p + '/'));
    if (!isProtected) continue;

    const result = verifySignedUrl(uri, qs, gate);
    if (!result.valid) {
      return resp(403, result.error || 'Invalid signature');
    }

    // Forward the nonce to origin so it can enforce single-use (SET NX in
    // Redis / conditional write in DynamoDB). The edge alone cannot enforce
    // replay protection statelessly — origin cooperation is required.
    if (gate.nonce_param && result.nonce && request.headers) {
      request.headers['x-signed-url-nonce'] = [{
        key: 'X-Signed-URL-Nonce',
        value: result.nonce,
      }];
    }

    if (CFG.obs && CFG.obs.auditLogAuth) {
      logEvent('audit', {
        auth_event: 'auth_pass',
        gate_type: 'signed_url',
        gate_name: gate.name || '',
        sub: '',
        method: request.method,
        uri,
        correlation_id: readCorrelation(request),
      });
    }
  }

  return null;
}

function titleHeaderName(name) {
  return String(name || '').toLowerCase().replace(/(^|-)([a-z])/g, (_, d, c) => d + c.toUpperCase());
}

function canonicalOriginAuthQuery(querystring) {
  const params = new URLSearchParams(querystring || '');
  const pairs = [];
  for (const [key, value] of params.entries()) pairs.push([key, value]);
  pairs.sort((a, b) => {
    if (a[0] === b[0]) return a[1] < b[1] ? -1 : (a[1] > b[1] ? 1 : 0);
    return a[0] < b[0] ? -1 : 1;
  });
  return pairs
    .map(([key, value]) => encodeURIComponent(key) + '=' + encodeURIComponent(value))
    .join('&');
}

function originAuthBodyHash(request, includeBodyHash) {
  if (!includeBodyHash) return { ok: true, hash: '' };
  const body = request && request.body;
  if (!body || body.data == null) {
    return { ok: true, hash: crypto.createHash('sha256').update(Buffer.alloc(0)).digest('hex') };
  }
  if (body.inputTruncated === true) {
    return { ok: false, error: 'origin_auth_body_truncated' };
  }
  const encoding = body.encoding === 'base64' ? 'base64' : 'utf8';
  const data = Buffer.from(String(body.data || ''), encoding);
  return { ok: true, hash: crypto.createHash('sha256').update(data).digest('hex') };
}

function originAuthSignedComponents(auth) {
  return Array.isArray(auth.signed_components) && auth.signed_components.length > 0
    ? auth.signed_components
    : ['method', 'path', 'query', 'body', 'timestamp', 'nonce'];
}

function canonicalOriginAuthInput(request, auth, timestamp, nonce, bodyHash) {
  const values = {
    method: String((request && request.method) || '').toUpperCase(),
    path: (request && request.uri) || '/',
    query: canonicalOriginAuthQuery((request && request.querystring) || ''),
    body: bodyHash || '',
    timestamp,
    nonce,
  };
  return originAuthSignedComponents(auth).map((component) => values[component] || '').join('\n');
}

function setOriginAuthHeader(request, headerName, value) {
  const key = titleHeaderName(headerName);
  request.headers[String(headerName).toLowerCase()] = [{ key, value: String(value) }];
}

// Add origin auth headers. Refuses to forward when the env var is unset / empty
// so origin cannot mistake a blank proof for a valid edge handoff.
function addOriginAuth(request) {
  if (!CFG.originAuth) return null;

  const envName = CFG.originAuth.secret_env || '';
  const secret = envName ? (process.env[envName] || '') : '';
  if (!secret) {
    logEvent('error', {
      block_reason: 'origin_auth_secret_missing',
      secret_env: envName,
      uri: request.uri || '',
      correlation_id: readCorrelation(request),
    });
    return resp(503, 'Origin auth misconfigured');
  }
  if (CFG.originAuth.type === 'hmac_signature') {
    const body = originAuthBodyHash(request, CFG.originAuth.include_body_hash === true);
    if (!body.ok) {
      logEvent('error', {
        block_reason: body.error || 'origin_auth_body_unavailable',
        secret_env: envName,
        uri: request.uri || '',
        correlation_id: readCorrelation(request),
      });
      return resp(503, 'Origin auth misconfigured');
    }
    const prefix = CFG.originAuth.header_prefix || 'X-CDN-Auth';
    const timestamp = String(Math.floor(Date.now() / 1000));
    const nonce = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
    const canonical = canonicalOriginAuthInput(request, CFG.originAuth, timestamp, nonce, body.hash);
    const signature = crypto.createHmac('sha256', secret).update(canonical).digest('base64url');
    setOriginAuthHeader(request, prefix + '-Timestamp', timestamp);
    setOriginAuthHeader(request, prefix + '-Nonce', nonce);
    if (CFG.originAuth.include_body_hash === true) {
      setOriginAuthHeader(request, prefix + '-Body-SHA256', body.hash);
    }
    setOriginAuthHeader(request, prefix + '-Signature', signature);
    return null;
  }

  const headerName = CFG.originAuth.header || 'X-Origin-Verify';
  setOriginAuthHeader(request, headerName, secret);
  return null;
}

// Propagate the correlation ID header to origin. When the incoming request
// already carries the header, preserve it; otherwise mint a lightweight ID so
// origin logs can always join back to edge logs. Issue #21.
function propagateCorrelation(request) {
  if (!CFG.obs || !CFG.obs.correlationHeader || !request || !request.headers) return;
  const headerName = CFG.obs.correlationHeader;
  const existing = request.headers[headerName];
  const hasIncoming = !!(existing && existing[0] && existing[0].value);
  if (hasIncoming) return;
  // Lambda@Edge has crypto available — use randomUUID as a cheap ID.
  const id = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
  request.headers[headerName] = [{ key: titleHeaderName(headerName), value: id }];
}

// Structured log emitter for Lambda@Edge. Same JSON shape as the CloudFront
// Functions viewer-request layer so downstream Log Insights queries can
// aggregate across layers with a single query.
function logEvent(event, fields) {
  if (CFG.obs && CFG.obs.logFormat === 'text') {
    console.log('[' + event + ']',
      fields && fields.status != null ? fields.status : '',
      fields && fields.block_reason ? fields.block_reason : '');
    return;
  }
  const rec = { ts: Date.now(), level: event === 'block' ? 'warn' : 'info', event };
  if (fields) {
    for (const k of Object.keys(fields)) {
      if (fields[k] != null && fields[k] !== '') rec[k] = fields[k];
    }
  }
  console.log(JSON.stringify(rec));
}

function readCorrelation(request) {
  if (!CFG.obs || !CFG.obs.correlationHeader) return '';
  const h = request && request.headers && request.headers[CFG.obs.correlationHeader];
  return (h && h[0] && h[0].value) || '';
}

function hashSub(sub) {
  if (!sub) return '';
  return crypto.createHash('sha256').update(String(sub)).digest('hex').slice(0, 16);
}

// Monitor mode: log and allow instead of blocking
function shouldBlock(checkResult, request) {
  if (!checkResult) return null;
  const status = parseInt(checkResult.status, 10);
  const reason = checkResult.statusDescription || checkResult.body || 'blocked';
  const base = {
    status,
    block_reason: reason,
    method: request && request.method,
    uri: (request && request.uri) || '/',
    correlation_id: readCorrelation(request),
  };
  if (CFG.mode === 'monitor') {
    logEvent('monitor', base);
    return null;
  }
  logEvent('block', base);
  // In enforce mode, strip detailed error messages from client responses
  if (status === 401) {
    return resp(401, 'Unauthorized');
  } else if (status === 403) {
    return resp(403, 'Forbidden');
  }
  return checkResult;
}

function shouldBlockAuth(checkResult, request) {
  if (!checkResult) return null;
  const status = parseInt(checkResult.status, 10);
  const reason = checkResult.statusDescription || checkResult.body || 'auth_failed';
  logEvent(CFG.mode === 'monitor' ? 'monitor' : 'block', {
    status,
    block_reason: reason,
    method: request && request.method,
    uri: (request && request.uri) || '/',
    correlation_id: readCorrelation(request),
  });
  if (status === 401) {
    return resp(401, 'Unauthorized');
  } else if (status === 403) {
    return resp(403, 'Forbidden');
  }
  return checkResult;
}

exports.handler = async (event) => {
  try {
    const cf = event.Records[0].cf;
    const req = cf.request;

    // Defense-in-depth: viewer-request already strips X-Forwarded-For when
    // trust_forwarded_for is false, but origin-request is the last hop before
    // origin and may be invoked without a preceding CFF in some setups.
    if (req && req.headers && !CFG.trustForwardedFor) {
      delete req.headers['x-forwarded-for'];
    }

    // Request-smuggling defense: strip hop-by-hop headers before origin
    // forward. Any client-supplied `Transfer-Encoding: chunked`,
    // `Connection: ...`, or `Upgrade` can desynchronize the CloudFront ↔
    // origin framing (CL.TE / TE.CL / H2.TE) and smuggle a second request.
    // CloudFront itself re-frames the request, so these headers carry no
    // legitimate meaning from the viewer.
    if (req && req.headers) {
      delete req.headers['transfer-encoding'];
      delete req.headers['connection'];
      delete req.headers['keep-alive'];
      delete req.headers['te'];
      delete req.headers['upgrade'];
      delete req.headers['proxy-connection'];
      delete req.headers['proxy-authenticate'];
      delete req.headers['proxy-authorization'];
      delete req.headers['trailer'];
    }

    // Header size check (Lambda@Edge can access all headers)
    const headerBlock = shouldBlock(checkHeaderSize(req), req);
    if (headerBlock) return headerBlock;

    // JWT auth gates
    const jwtBlock = shouldBlockAuth(await checkJwtGates(req), req);
    if (jwtBlock) return jwtBlock;

    // Signed URL gates
    const signedUrlBlock = shouldBlockAuth(checkSignedUrlGates(req), req);
    if (signedUrlBlock) return signedUrlBlock;

    // Add origin auth header
    const originAuthBlock = addOriginAuth(req);
    if (originAuthBlock) return originAuthBlock;

    // Propagate correlation / trace header to origin so origin logs can join
    // edge block/allow logs.
    propagateCorrelation(req);

    return req;
  } catch (err) {
    logEvent('error', { block_reason: 'unexpected_error: ' + (err && (err.message || err)), uri: '/' });
    return resp(502, 'Bad Gateway');
  }
};
