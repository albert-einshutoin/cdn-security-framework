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
};

// JWKS cache (persists across Lambda container reuse)
let jwksCache = {};
const JWKS_CACHE_TTL = 3600000; // 1 hour

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

// Fetch JWKS from URL with caching
async function fetchJwks(url) {
  const unsafe = isUnsafeJwksUrl(url);
  if (unsafe) {
    throw new Error('JWKS URL rejected: ' + unsafe);
  }
  const now = Date.now();
  if (jwksCache[url] && (now - jwksCache[url].time) < JWKS_CACHE_TTL) {
    return jwksCache[url].keys;
  }

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
          jwksCache[url] = { keys: jwks.keys, time: now };
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

function invalidateJwksCache(url) {
  delete jwksCache[url];
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

    // Check expiration (with skew tolerance)
    if (payload.exp && now >= payload.exp * 1000 + skewMs) {
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

    // Check expiration (with skew tolerance)
    if (payload.exp && now >= payload.exp * 1000 + skewMs) {
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

  // Compute expected signature: HMAC-SHA256(uri + exp [+ nonce], secret)
  const secret = process.env[gate.secret_env] || '';
  if (!secret) return { valid: false, error: 'Secret not configured' };

  // When a nonce is part of the scheme, include it in the signed material so
  // tampering with it invalidates the signature (origin still enforces single-
  // use separately).
  const signData = uri + exp + (nonce ? ('|' + nonce) : '');
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
  }

  return null;
}

// Add origin auth header
function addOriginAuth(request) {
  if (!CFG.originAuth) return;

  const secret = process.env[CFG.originAuth.secret_env] || '';
  if (secret) {
    const headerName = (CFG.originAuth.header || 'X-Origin-Verify').toLowerCase();
    request.headers[headerName] = [{
      key: CFG.originAuth.header || 'X-Origin-Verify',
      value: secret,
    }];
  }
}

// Monitor mode: log and allow instead of blocking
function shouldBlock(checkResult, request) {
  if (!checkResult) return null;
  if (CFG.mode === 'monitor') {
    console.log('[monitor]', checkResult.status, checkResult.statusDescription,
      'uri=' + (request && request.uri || '/'));
    return null;
  }
  // In enforce mode, strip detailed error messages from client responses
  const status = parseInt(checkResult.status, 10);
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
    const jwtBlock = shouldBlock(await checkJwtGates(req), req);
    if (jwtBlock) return jwtBlock;

    // Signed URL gates
    const signedUrlBlock = shouldBlock(checkSignedUrlGates(req), req);
    if (signedUrlBlock) return signedUrlBlock;

    // Add origin auth header
    addOriginAuth(req);

    return req;
  } catch (err) {
    console.log('[origin-request] unexpected error:', err.message || err);
    return resp(502, 'Bad Gateway');
  }
};
