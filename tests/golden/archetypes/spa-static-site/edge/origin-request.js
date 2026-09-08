/**
 * Lambda@Edge - Origin Request — TEMPLATE
 *
 * 【注意】このファイルはテンプレートです。直接デプロイしないでください。
 * security.yml を編集し、npx cdn-security build で dist/edge/origin-request.js を生成してください。
 *
 * Purpose: origin access authentication, header limits, and request forwarding.
 * Viewer authentication must execute before the CloudFront cache lookup.
 */

const crypto = require('crypto');

const CFG = {
  project: "example-spa-static-site",
  mode: "enforce",
  maxHeaderSize: 0,
  trustForwardedFor: false,
  originAuth: null,
  obs: {"logFormat":"json","correlationHeader":"","sampleRate":0,"auditLogAuth":false,"auditHashSub":false},
};

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

function titleHeaderName(name) {
  return String(name || '').toLowerCase().replace(/(^|-)([a-z])/g, (_, d, c) => d + c.toUpperCase());
}

function firstHeaderValue(headers, name) {
  const values = headers && headers[String(name || '').toLowerCase()];
  return Array.isArray(values) && values[0] && values[0].value != null
    ? String(values[0].value)
    : '';
}

function originAuthPayloadExpected(request) {
  const contentLength = firstHeaderValue(request && request.headers, 'content-length').trim();
  if (contentLength) {
    const parsed = Number(contentLength);
    return Number.isFinite(parsed) ? parsed > 0 : true;
  }
  return firstHeaderValue(request && request.headers, 'transfer-encoding').trim() !== '';
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
    if (originAuthPayloadExpected(request)) {
      return { ok: false, error: 'origin_auth_body_unavailable' };
    }
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
  const secret = CFG.originAuth.secret || '';
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

function allowSampleKey(request) {
  return readCorrelation(request)
    || ((request && request.method) || '') + '\n' + ((request && request.uri) || '/');
}

function shouldSampleAllow(key) {
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

function logAllow(request, samplingKey) {
  if (!shouldSampleAllow(samplingKey)) return;
  logEvent('allow', {
    method: request && request.method,
    uri: (request && request.uri) || '/',
    correlation_id: readCorrelation(request),
  });
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

    // Add origin auth header
    const originAuthBlock = addOriginAuth(req);
    if (originAuthBlock) return originAuthBlock;

    // Capture the sampling key before propagation. A newly minted random ID
    // must not move identical requests between sample buckets.
    const allowSamplingKey = allowSampleKey(req);

    // Propagate correlation / trace header to origin so origin logs can join
    // edge block/allow logs.
    propagateCorrelation(req);
    logAllow(req, allowSamplingKey);

    return req;
  } catch (err) {
    logEvent('error', { block_reason: 'unexpected_error: ' + (err && (err.message || err)), uri: '/' });
    return resp(502, 'Bad Gateway');
  }
};
