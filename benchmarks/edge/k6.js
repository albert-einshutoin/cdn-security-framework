import http from 'k6/http';
import exec from 'k6/execution';
import { check, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';

const manifest = JSON.parse(open(__ENV.CSF_MANIFEST));
if (!/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(manifest.baseUrl)
  && !/^https:\/\/csf-1026-[a-f0-9]+-gateway\.[a-z0-9-]+\.workers\.dev$/.test(manifest.baseUrl)) throw new Error('Disposable benchmark endpoint required');
const test = manifest.cases.find(item => item.id === __ENV.CSF_CASE);
const variant = __ENV.CSF_VARIANT, phase = __ENV.CSF_PHASE, series = __ENV.CSF_SERIES;
if (!test || !['bare', 'generated'].includes(variant) || !['warmup', 'measured'].includes(phase) || !/^[a-zA-Z0-9_-]+$/.test(series)) throw new Error('Invalid benchmark selection');
const comparison = __ENV.CSF_COMPARISON || 'AB';
if (!['AA', 'AB'].includes(comparison) || !['gateway', 'direct'].includes(manifest.topology)) throw new Error('Invalid comparison/topology');
const targetVariant = comparison === 'AA' ? 'bare' : variant;
const role = targetVariant === 'bare' ? 'bare' : test.profile;
const endpoint = manifest.topology === 'direct' ? manifest.targetUrls?.[role] : manifest.baseUrl;
if (manifest.topology === 'direct') {
  const cloud = /^https:\/\/(csf-1026-[a-f0-9]+)-gateway\.([a-z0-9-]+\.workers\.dev)$/.exec(manifest.baseUrl);
  if (/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(manifest.baseUrl)
    ? !/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(endpoint)
    : !cloud || endpoint !== `https://${cloud[1]}-${role}.${cloud[2]}`) throw new Error('Disposable direct target endpoint required');
}
const latency = new Trend('csf_wall_ms', true), valid = new Counter('csf_valid'), invalid = new Counter('csf_invalid');
const seconds = Number(__ENV.CSF_SECONDS), rate = Number(__ENV.CSF_RATE);
const concurrency = Number(__ENV.CSF_CONCURRENCY || '4');
const model = __ENV.CSF_MODEL || 'arrival';
if (!['arrival', 'iterations'].includes(model)) throw new Error('Unknown load model');
if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 4) throw new Error('Bounded concurrency required');
if (!Number.isInteger(rate) || rate < 1 || rate > 50 || !Number.isInteger(seconds) || seconds < 1 || rate * seconds > 2000) throw new Error('Bounded rate/duration required');
export const options = {
  scenarios: { measured: model === 'arrival'
    ? { executor: 'constant-arrival-rate', rate, timeUnit: '1s', duration: `${seconds}s`, preAllocatedVUs: concurrency, maxVUs: concurrency, gracefulStop: '6s' }
    : { executor: 'shared-iterations', vus: concurrency, iterations: rate * seconds, maxDuration: `${seconds * 2 + 10}s`, gracefulStop: '6s' } },
  maxRedirects: 0, noCookiesReset: false, userAgent: 'csf-edge-benchmark',
  systemTags: ['status', 'method', 'scenario', 'error_code', 'proto'],
  thresholds: { checks: ['rate==1'], dropped_iterations: ['count==0'], csf_invalid: ['count==0'] },
  summaryTrendStats: ['count', 'min', 'med', 'p(95)', 'p(99)', 'max'],
};

export default function () {
  // A scheduler iteration at the duration boundary must not exceed the request cap.
  if (exec.scenario.iterationInTest >= rate * seconds) return;
  const id = `${series}-${exec.scenario.iterationInTest}`;
  const response = http.request(test.method, `${endpoint}/${test.id}/${targetVariant}`, test.body || null, {
    headers: { 'x-csf-key': manifest.probeKey, 'x-csf-id': id }, timeout: '5s', redirects: 0,
    responseCallback: http.expectedStatuses(targetVariant === 'bare' ? 200 : test.status),
    tags: { case: test.id, variant, phase, series, request_id: id },
  });
  let ok = response.status === (targetVariant === 'bare' ? 200 : test.status) && response.headers['X-Csf-Id'] === id;
  if (ok && response.status === 200) {
    let body;
    try { body = response.json(); } catch { ok = false; }
    ok = ok && body.id === id && body.case === test.id && body.variant === targetVariant && body.bodyHash === test.bodyHash
      && body.pathHash === test.pathHash && body.bodyBytes === (test.body || '').length
      && body.signatureVerified === (test.profile === 'hmac' && targetVariant === 'generated')
      && response.headers['X-Csf-Origin'] === 'synthetic'
      && (targetVariant === 'bare' || response.headers['X-Content-Type-Options'] === 'nosniff');
  } else if (ok) ok = response.headers['X-Csf-Origin'] === undefined;
  const colo = response.headers['X-Csf-Ingress-Colo'] || 'unknown';
  latency.add(response.timings.duration, { case: test.id, variant, phase, series, request_id: id, colo });
  valid.add(ok ? 1 : 0); invalid.add(ok ? 0 : 1);
  check(response, { 'fixture expected result': () => ok });
  // A fixed-count characterization preserves concurrency and every input. Its
  // paced, closed model does not certify the arrival-rate stress workload.
  if (model === 'iterations') sleep(concurrency / rate);
}

export function handleSummary(data) { return { [__ENV.CSF_SUMMARY]: JSON.stringify(data, null, 2) }; }
