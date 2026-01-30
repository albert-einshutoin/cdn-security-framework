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

// {{INJECT_CONFIG}}

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

// Fetch JWKS from URL with caching
async function fetchJwks(url) {
  const now = Date.now();
  if (jwksCache[url] && (now - jwksCache[url].time) < JWKS_CACHE_TTL) {
    return jwksCache[url].keys;
  }
  
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
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
    }).on('error', reject);
  });
}

// Base64URL decode
function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

// Verify JWT signature (RS256)
async function verifyJwtRS256(token, jwksUrl, issuer, audience) {
  const parts = token.split('.');
  if (parts.length !== 3) return { valid: false, error: 'Invalid token format' };
  
  const [headerB64, payloadB64, signatureB64] = parts;
  
  try {
    const header = JSON.parse(base64UrlDecode(headerB64).toString());
    const payload = JSON.parse(base64UrlDecode(payloadB64).toString());
    
    // Check expiration
    if (payload.exp && Date.now() >= payload.exp * 1000) {
      return { valid: false, error: 'Token expired' };
    }
    
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
    
    // Fetch JWKS and find matching key
    const keys = await fetchJwks(jwksUrl);
    const key = keys.find(k => k.kid === header.kid && k.alg === 'RS256');
    if (!key) {
      return { valid: false, error: 'Key not found' };
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
function verifyJwtHS256(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return { valid: false, error: 'Invalid token format' };
  
  const [headerB64, payloadB64, signatureB64] = parts;
  
  try {
    const payload = JSON.parse(base64UrlDecode(payloadB64).toString());
    
    // Check expiration
    if (payload.exp && Date.now() >= payload.exp * 1000) {
      return { valid: false, error: 'Token expired' };
    }
    
    // Compute expected signature
    const signData = headerB64 + '.' + payloadB64;
    const expectedSig = crypto.createHmac('sha256', secret)
      .update(signData)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
    
    const providedSig = signatureB64;
    
    return { valid: expectedSig === providedSig, payload };
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
  
  // Compute expected signature: HMAC-SHA256(uri + exp, secret)
  const secret = process.env[gate.secret_env] || '';
  if (!secret) return { valid: false, error: 'Secret not configured' };
  
  const signData = uri + exp;
  const expectedSig = crypto.createHmac('sha256', secret)
    .update(signData)
    .digest('base64url');
  
  return { valid: sig === expectedSig };
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
      result = await verifyJwtRS256(jwt, gate.jwks_url, gate.issuer, gate.audience);
    } else if (gate.algorithm === 'HS256' && gate.secret_env) {
      const secret = process.env[gate.secret_env] || '';
      result = verifyJwtHS256(jwt, secret);
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
    const isProtected = gate.protectedPrefixes.some(
      p => uri === p || uri.startsWith(p + '/')
    );
    if (!isProtected) continue;
    
    const result = verifySignedUrl(uri, qs, gate);
    if (!result.valid) {
      return resp(403, result.error || 'Invalid signature');
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

exports.handler = async (event) => {
  const cf = event.Records[0].cf;
  const req = cf.request;

  // Header size check (Lambda@Edge can access all headers)
  const headerCheck = checkHeaderSize(req);
  if (headerCheck) return headerCheck;

  // JWT auth gates
  const jwtCheck = await checkJwtGates(req);
  if (jwtCheck) return jwtCheck;

  // Signed URL gates
  const signedUrlCheck = checkSignedUrlGates(req);
  if (signedUrlCheck) return signedUrlCheck;

  // Add origin auth header
  addOriginAuth(req);

  return req;
};
