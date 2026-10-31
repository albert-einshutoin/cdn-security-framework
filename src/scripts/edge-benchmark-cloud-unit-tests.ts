import assert from 'node:assert/strict';
import { freeDiagnosticPreflight, verifyUploadedWorker, cleanupOwned, cloudApi, consumeDiagnosticApproval, diagnosticApproval, diagnosticMarker, diagnosticAuthorizationId, remainingLoadMs } from './edge-benchmark-cloud';
import { sha } from './edge-benchmark-cpu';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fork } from 'node:child_process';

async function main() {
  const account = 'a'.repeat(32), now = Date.now();
  const preflight = { accountSha256: sha(account), plan: 'Workers Free', additionalUSD: 0, requestsRemaining: 1000,
    logEventsRemaining: 1000, otherUsageChecked: true, at: now, workerTokenExpiresAt: now + 3600000, cpuTokenExpiresAt: now + 3600000 };
  assert.equal(freeDiagnosticPreflight(preflight, account, now).clientCap, 26);
  assert.equal(remainingLoadMs(now, now + 5000), 385000, 'Guardian delay must not move the absolute cutoff');
  assert.equal(remainingLoadMs(now, now + 390001), 0);
  const read = fs.readFileSync, realpath = fs.realpathSync, write = fs.writeFileSync;
  const approval = { authorizationId: diagnosticAuthorizationId, issue: 1026, accountSha256: sha(account), maxWindows: 1, clientCap: 26,
    plannedClientCap: 26, invocationCap: 52, maxRps: 1, concurrency: 1, workerCap: 5, windowMs: 600000, additionalUSD: 0 };
  let consumed = false;
  try {
    (fs as any).readFileSync = () => JSON.stringify(approval); (fs as any).realpathSync = () => diagnosticApproval;
    (fs as any).writeFileSync = (file: string, _data: string, options: any) => { assert.equal(file, diagnosticMarker); assert.equal(options.flag, 'wx'); if (consumed) throw new Error('EEXIST'); consumed = true; };
    assert.throws(() => consumeDiagnosticApproval(diagnosticApproval + '.other', account, 'synthetic'), /Canonical/);
    const currentId = approval.authorizationId;
    approval.authorizationId = 'issue-1026-zero-cost-20261018'; approval.clientCap = 300;
    assert.throws(() => consumeDiagnosticApproval(diagnosticApproval, account, 'prior-grant'), /binding mismatch/);
    assert.equal(consumed, false, 'The spent grant must not consume the newly approved window');
    approval.authorizationId = currentId; approval.clientCap = 26;
    consumeDiagnosticApproval(diagnosticApproval, account, 'synthetic');
    assert.throws(() => consumeDiagnosticApproval(diagnosticApproval, account, 'synthetic-2'), /EEXIST/);
    assert.throws(() => consumeDiagnosticApproval(diagnosticApproval, 'b'.repeat(32), 'synthetic'), /binding mismatch/);
    assert.throws(() => consumeDiagnosticApproval(diagnosticApproval + '.alias', account, 'synthetic'), /Canonical/);
  } finally { fs.readFileSync = read; fs.realpathSync = realpath; fs.writeFileSync = write; }
  for (const change of [{ plan: 'Workers Paid' }, { additionalUSD: .01 }, { requestsRemaining: 51 }, { logEventsRemaining: 155 },
    { accountSha256: 'other' }, { otherUsageChecked: false }, { at: now - 60001 }, { at: now + 1 },
    { workerTokenExpiresAt: now + 600000 }, { cpuTokenExpiresAt: now + 600000 }]) {
    assert.throws(() => freeDiagnosticPreflight({ ...preflight, ...change }, account, now), /Fresh Free/);
  }
  for (const change of [{ requestsRemaining: Infinity }, { logEventsRemaining: Infinity }, { workerTokenExpiresAt: Infinity }]) assert.throws(() => freeDiagnosticPreflight({ ...preflight, ...change }, account, now));
  const state = () => ({ prefix: 'csf-1026-abcdef123456', owner: 'owned', startedAt: now, deadline: now + 600000,
    owned: [{ role: 'origin' as const, attempted: true, deleteAttempted: false, absent: false }] });
  const version = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
  const ok = (value: any) => ({ status: 200, body: { success: true, errors: [], result: value } });
  const missing = { status: 404, body: { success: false, errors: [{ code: 10007 }] } };
  const upload = ok({ id: state().prefix + '-origin', deployment_id: version, etag: 'same-upload-content' });
  const settings = { tags: ['owned'], observability: { enabled: true, head_sampling_rate: 1,
    logs: { enabled: true, head_sampling_rate: 1, persist: true, invocation_logs: true } } };
  let loads = 0;
  const goodApi = async (_role: any, suffix: string) => ok(suffix === '/settings' ? settings
    : suffix.startsWith('/versions/') ? { id: version, resources: { script: { etag: 'same-upload-content' } } }
      : suffix === '/deployments' ? { deployments: [{ versions: [{ version_id: version, percentage: 100 }] }] } : { enabled: true });
  await verifyUploadedWorker(goodApi, 'origin', upload, state()).then(() => loads++); assert.equal(loads, 1);
  let propagationReads = 0, mutations = 0;
  const propagated = await verifyUploadedWorker(async (role, suffix, method = 'GET') => {
    if (method === 'PUT' || method === 'DELETE') mutations++;
    if (suffix === '/settings' && ++propagationReads < 6) return missing;
    return goodApi(role, suffix);
  }, 'origin', upload, state());
  assert.equal(propagated.versionId, version);
  assert.equal(propagationReads, 6, 'A newly uploaded script may become readable within the bounded propagation interval');
  assert.equal(mutations, 0, 'Propagation must never reupload or delete a script');
  for (const defect of ['404', 'unknown404', '403', 'version', 'etag', 'deployment', 'sampling', 'ownership', 'string-tag', 'subdomain', 'throw']) {
    loads = 0;
    let settingsReads = 0;
    const api = async (role: any, suffix: string) => {
      if (suffix === '/settings') settingsReads++;
      if (defect === 'throw') throw new Error('Synthetic timeout');
      if (defect === '404') return missing;
      if (defect === 'unknown404') return { status: 404, body: { success: false, errors: [{ code: 999 }] } };
      if (defect === '403') return { status: 403, body: { success: false, errors: [{ code: 10000 }] } };
      if (suffix === '/settings' && defect === 'sampling') return ok({ ...settings, observability: { ...settings.observability, head_sampling_rate: .5 } });
      if (suffix === '/settings' && defect === 'ownership') return ok({ ...settings, tags: ['foreign'] });
      if (suffix === '/settings' && defect === 'string-tag') return ok({ ...settings, tags: 'prefix-owned-suffix' });
      if (suffix.startsWith('/versions/') && defect === 'version') return ok({ id: 'wrong', resources: { script: { etag: 'same-upload-content' } } });
      if (suffix.startsWith('/versions/') && defect === 'etag') return ok({ id: version, resources: { script: { etag: 'other-bytes' } } });
      if (suffix === '/deployments' && defect === 'deployment') return ok({ deployments: [{ versions: [{ version_id: version, percentage: 50 }] }] });
      if (suffix === '/subdomain' && defect === 'subdomain') return ok({ enabled: false });
      return goodApi(role, suffix);
    };
    await assert.rejects(verifyUploadedWorker(api, 'origin', upload, state()).then(() => loads++)); assert.equal(loads, 0, 'Invalid deployment must never release load');
    assert.equal(settingsReads, defect === '404' ? 6 : 1, 'Only the exact post-upload 404/10007 may be retried');
  }
  await assert.rejects(verifyUploadedWorker(goodApi, 'origin', { status: 200, body: { success: false, result: {} } }, state()));
  await assert.rejects(verifyUploadedWorker(goodApi, 'origin', ok({}), state()));
  for (const defect of ['none', 'foreign', 'string-tag', 'unknown404', 'delete-timeout-absent', 'delete-timeout-present', 'prior-delete']) {
    const current = state(); let deletes = 0;
    if (defect === 'prior-delete') current.owned[0].deleteAttempted = true;
    const api = async (_role: any, _suffix: string, method = 'GET') => {
      if (method === 'DELETE') { deletes++; if (defect.startsWith('delete-timeout')) throw new Error('Synthetic timeout'); return ok({}); }
      if (defect === 'foreign') return ok({ tags: ['foreign'] });
      if (defect === 'string-tag') return ok({ tags: 'prefix-owned-suffix' });
      if (defect === 'unknown404') return { status: 404, body: { success: false, errors: [{ code: 999 }] } };
      if (deletes && defect !== 'delete-timeout-present') return missing;
      return ok(settings);
    };
    const complete = await cleanupOwned(api, current, () => {});
    assert.equal(complete, ['none', 'delete-timeout-absent'].includes(defect));
    assert.equal(deletes, ['foreign', 'string-tag', 'unknown404', 'prior-delete'].includes(defect) ? 0 : 1);
    if (defect === 'delete-timeout-present') { assert.equal(await cleanupOwned(api, current, () => {}), false); assert.equal(deletes, 1, 'Unknown DELETE must not be resent'); }
  }
  let deletes = 0;
  const neverUploaded = state(); neverUploaded.owned[0].attempted = false;
  assert.equal(await cleanupOwned(async () => { deletes++; return missing; }, neverUploaded, () => {}), true);
  assert.equal(deletes, 1, 'An absent resource requires a read only');
  const pending = state(); let pendingReads = 0, pendingDeletes = 0;
  assert.equal(await cleanupOwned(async () => { pendingReads++; return missing; }, pending, () => {}), false,
    'An uploaded script that never became readable cannot be declared absent');
  assert.equal(pendingReads, 6); assert.equal(pending.owned[0].absent, false);
  const delayed = state(); let delayedReads = 0;
  assert.equal(await cleanupOwned(async (_role, _suffix, method = 'GET') => {
    if (method === 'DELETE') { pendingDeletes++; return ok({}); }
    if (pendingDeletes || ++delayedReads === 1) return missing;
    return ok(settings);
  }, delayed, () => {}), true, 'Cleanup must wait for a delayed upload, verify ownership and then delete it');
  assert.equal(pendingDeletes, 1); assert.equal(delayedReads, 2);
  const realNow = Date.now, realTimeout = globalThis.setTimeout;
  try {
    for (const remaining of [600000, 30000, 0]) {
      let clock = realNow(), calls = 0, mutations = 0; const started = clock;
      Date.now = () => clock;
      globalThis.setTimeout = ((callback: () => void, ms: number) => { clock += ms; queueMicrotask(callback); return 0; }) as any;
      const slow = { ...state(), deadline: started + remaining,
        owned: (['origin', 'bare', 'basic', 'graphql', 'hmac'] as const).map(role => ({ role, attempted: true, deleteAttempted: false, absent: false })) };
      assert.equal(await cleanupOwned(async (_role, _suffix, method = 'GET') => {
        calls++; if (method !== 'GET') mutations++; clock += 6000; return missing;
      }, slow, () => {}), false);
      assert.equal(mutations, 0); assert.ok(slow.owned.every(row => row.absent === false));
      assert.ok(clock - started < 90000 && clock - started <= remaining, 'All five slow resources must share the guardian budget and hard deadline');
      if (remaining === 0) assert.equal(calls, 0, 'Expired cleanup must not start another API operation');
      if (remaining === 30000) {
        clock = started; let reads = 0, deletes = 0; const late = { ...state(), deadline: started + remaining };
        assert.equal(await cleanupOwned(async (_role, _suffix, method = 'GET') => {
          clock += 6000; if (method === 'DELETE') deletes++;
          return ++reads < 3 ? missing : ok(settings);
        }, late, () => {}), false);
        assert.equal(deletes, 0); assert.equal(late.owned[0].deleteAttempted, false,
          'A known owned script must retain deletion eligibility when DELETE plus readback no longer fits');
      }
    }
  } finally { Date.now = realNow; globalThis.setTimeout = realTimeout; }
  const realFetch = globalThis.fetch, directory = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-cloud-unit-'));
  try {
    let calls = 0;
    globalThis.fetch = async () => { calls++; return new Response('{'); };
    await assert.rejects(cloudApi(account, 'synthetic-test', state(), directory)('origin', '/settings'), /Invalid provider JSON/);
    const controller = new AbortController(); controller.abort();
    await assert.rejects(cloudApi(account, 'synthetic-test', state(), directory, controller.signal)('origin', '', 'PUT'));
    assert.equal(calls, 1, 'Abort must reject before provider access');
    globalThis.fetch = realFetch;
    const stateFile = path.join(directory, 'state.json'), current = state(); current.owned[0].attempted = false;
    fs.writeFileSync(stateFile, JSON.stringify(current));
    const preload = path.join(directory, 'preload.cjs');
    fs.writeFileSync(preload, `globalThis.fetch=async (url,options)=>{if(options.method!=='GET'||!url.endsWith('/settings'))throw Error('Unexpected synthetic network call');return Response.json({success:false,errors:[{code:10007}]},{status:404})};`);
    const guardian = fork(path.join(__dirname, 'edge-benchmark-cloud.js'), ['--guardian'], { execArgv: ['--require', preload], stdio: ['ignore', 'ignore', 'pipe', 'ipc'], env: { PATH: process.env.PATH } });
    guardian.stderr!.resume();
    const closed = new Promise<void>((resolve, reject) => { guardian.once('exit', code => code === 0 ? resolve() : reject(new Error('Synthetic guardian failed'))); guardian.once('error', reject); });
    const timer = setTimeout(() => guardian.kill('SIGKILL'), 10000);
    try {
      await new Promise<void>((resolve, reject) => { guardian.once('message', message => (message as any)?.ready ? resolve() : reject(new Error('Guardian not ready'))); guardian.send({ directory, stateFile, account, workerToken: 'synthetic-only', deadline: now + 600000 }); });
      guardian.disconnect(); await closed;
      assert.equal(JSON.parse(fs.readFileSync(stateFile, 'utf8')).owned[0].absent, true, 'Guardian must verify even unattempted names after parent disconnect');
    } finally { clearTimeout(timer); if (guardian.exitCode === null && guardian.signalCode === null) guardian.kill('SIGKILL'); }
  } finally { globalThis.fetch = realFetch; fs.rmSync(directory, { recursive: true, force: true }); }
  console.log('OK: Free quota/auth/window gates, upload200/404/version/readiness control gates, owned cleanup and no DELETE resend');
}
let completed = false;
void main().then(() => { completed = true; }).catch(error => { console.error(error); process.exitCode = 1; });
process.once('beforeExit', () => { if (!completed) { console.error('Cloud checks did not complete'); process.exitCode = 1; } });
