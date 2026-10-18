/** Explicit, single-window Free diagnostic. Historical CLI runners are evidence only. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fork } from 'node:child_process';
import { prepareBenchmark, runK6Series, sha } from './benchmark-edge-k6';
import { benchmarkCases, compatibilityDate } from './edge-benchmark-fixture';
import { collectCpuEvents, joinProviderCapture, clientPopulation, bindCpuSeries } from './collect-edge-benchmark-cpu';

export const diagnosticRoles = ['origin', 'bare', 'basic', 'graphql', 'hmac'] as const;
type Role = typeof diagnosticRoles[number];
type Reply = { status: number; body: any };
type Api = (role: Role, suffix: string, method?: string, body?: BodyInit) => Promise<Reply>;
type Owned = { role: Role; attempted: boolean; deleteAttempted: boolean; absent?: boolean };
type State = { prefix: string; owner: string; startedAt: number; deadline: number; owned: Owned[]; cleanup?: any[] };
const root = path.resolve(__dirname, '..');
// ponytail: This single approved #1026 window is fixed. A future window needs a
// new reviewed authorization; selecting another receipt must never restart it.
export const diagnosticAuthorizationId = 'issue-1026-zero-cost-20261018';
export const diagnosticApproval = path.join(root, 'reports', diagnosticAuthorizationId, 'cloud-approval.json');
export const diagnosticMarker = path.join(root, 'reports', diagnosticAuthorizationId, 'cloud-window-started.json');
const ownedBy = (settings: any, owner: string) => Array.isArray(settings?.tags)
  && settings.tags.every((tag: unknown) => typeof tag === 'string') && settings.tags.includes(owner);
export const remainingLoadMs = (startedAt: number, now = Date.now()) => Math.max(0, startedAt + 390000 - now);
export function consumeDiagnosticApproval(file: string, account: string, prefix: string) {
  assert.equal(path.resolve(file), diagnosticApproval, 'Canonical diagnostic approval required');
  assert.equal(fs.realpathSync(file), diagnosticApproval, 'Approval alias refused');
  const approval = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.ok(approval.authorizationId === diagnosticAuthorizationId && approval.issue === 1026 && approval.accountSha256 === sha(account)
    && approval.maxWindows === 1 && approval.clientCap === 300 && approval.plannedClientCap === 26 && approval.invocationCap === 52
    && approval.maxRps === 1 && approval.concurrency === 1 && approval.workerCap === 5 && approval.windowMs === 600000
    && approval.additionalUSD === 0, 'Diagnostic approval binding mismatch');
  fs.writeFileSync(diagnosticMarker, JSON.stringify({ authorizationId: diagnosticAuthorizationId, prefix, at: Date.now() }), { mode: 0o600, flag: 'wx' });
}
const save = (file: string, value: unknown) => {
  fs.writeFileSync(file + '.tmp', JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(file + '.tmp', file);
};
const pause = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));
const absent = (reply: Reply) => reply.status === 404 && reply.body?.success === false
  && Array.isArray(reply.body.errors) && reply.body.errors.length === 1 && reply.body.errors[0].code === 10007;
const result = (reply: Reply) => {
  assert.ok(reply.status >= 200 && reply.status < 300 && reply.body?.success === true && !reply.body.errors?.length && reply.body.result, 'Provider operation failed or unknown');
  return reply.body.result;
};
export function freeDiagnosticPreflight(value: any, account: string, now = Date.now()) {
  assert.match(account, /^[a-f0-9]{32}$/);
  assert.ok(value?.accountSha256 === sha(account) && value.plan === 'Workers Free' && value.additionalUSD === 0
    && Number.isSafeInteger(value.requestsRemaining) && value.requestsRemaining >= 52 && value.requestsRemaining <= 100000
    && Number.isSafeInteger(value.logEventsRemaining) && value.logEventsRemaining >= 156 && value.logEventsRemaining <= 200000 && value.otherUsageChecked === true
    && Number.isFinite(value.at) && now >= value.at && now - value.at <= 60000
    && Number.isFinite(value.workerTokenExpiresAt) && value.workerTokenExpiresAt > now + 630000
    && Number.isFinite(value.cpuTokenExpiresAt) && value.cpuTokenExpiresAt > now + 630000, 'Fresh Free quota/authentication proof required');
  return { clientCap: 26, invocationCap: 52, eventCap: 156, windowMs: 600000, loadMs: 390000 };
}

export function cloudApi(account: string, token: string, state: State, directory: string, signal?: AbortSignal): Api {
  assert.match(account, /^[a-f0-9]{32}$/); assert.ok(token.length > 0);
  assert.match(state.prefix, /^csf-1026-[a-f0-9]{12}$/);
  let next = 0;
  return async (role, suffix, method = 'GET', body) => {
    assert.ok(diagnosticRoles.includes(role) && ['', '/settings', '/deployments', '/subdomain'].includes(suffix)
      || diagnosticRoles.includes(role) && /^\/versions\/[a-f0-9-]{36}$/.test(suffix), 'Disposable API endpoint required');
    assert.ok(method === 'GET' || method === 'DELETE' && suffix === '' || method === 'PUT' && suffix === '' || method === 'POST' && suffix === '/subdomain', 'Unexpected provider mutation');
    signal?.throwIfAborted();
    await pause(Math.max(0, next - Date.now())); signal?.throwIfAborted(); next = Date.now() + 1000;
    const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}/workers/scripts/${state.prefix}-${role}${suffix}`, {
      method, body, headers: { authorization: 'Bearer ' + token, ...(body instanceof FormData ? {} : { 'content-type': 'application/json' }) },
      redirect: 'error', signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(5000)]) : AbortSignal.timeout(5000),
    });
    let value: any;
    try { value = await response.json(); } catch { throw new Error('Invalid provider JSON'); }
    fs.appendFileSync(path.join(directory, 'api-receipts.jsonl'), JSON.stringify({ at: Date.now(), role, suffix, method,
      status: response.status, success: value?.success, codes: value?.errors?.map((error: any) => error.code), responseSha256: sha(JSON.stringify(value)),
      identity: value?.result && { id: value.result.id, deployment_id: value.result.deployment_id, etag: value.result.etag, enabled: value.result.enabled, observability: value.result.observability } }) + '\n', { mode: 0o600 });
    return { status: response.status, body: value };
  };
}

async function readUploadedSettings(api: Api, role: Role, deadline = Infinity) {
  for (let attempt = 0; ; attempt++) {
    const reply = await api(role, '/settings');
    // The Oct 18 upload returned 200, then 404/10007, and was readable
    // during cleanup 9.245 seconds later. Bound propagation reads to six;
    // all other failures and the final absent read remain errors.
    if (!absent(reply) || attempt === 5) return reply;
    assert.ok(Date.now() + 8000 <= deadline, 'Settings propagation budget exhausted');
    await pause(2000);
  }
}

export async function verifyUploadedWorker(api: Api, role: Role, upload: Reply, state: State) {
  const uploaded = result(upload), rawVersion = uploaded.deployment_id;
  assert.ok(uploaded.id === `${state.prefix}-${role}` && typeof uploaded.etag === 'string' && uploaded.etag.length
    && typeof rawVersion === 'string' && /^[a-f0-9]{32}$|^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(rawVersion), 'Upload identity unavailable');
  const versionId = rawVersion.includes('-') ? rawVersion : rawVersion.replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
  const settings = result(await readUploadedSettings(api, role));
  assert.ok(ownedBy(settings, state.owner) && settings.observability?.enabled === true
    && settings.observability.head_sampling_rate === 1 && settings.observability.logs?.enabled === true
    && settings.observability.logs.head_sampling_rate === 1 && settings.observability.logs.persist === true
    && settings.observability.logs.invocation_logs === true, 'Ownership or logging configuration mismatch');
  const version = result(await api(role, '/versions/' + versionId));
  assert.ok(version.id === versionId && version.resources?.script?.etag === uploaded.etag, 'Version/content readback mismatch');
  const deployments = result(await api(role, '/deployments')).deployments;
  assert.ok(Array.isArray(deployments) && deployments[0]?.versions?.length === 1
    && deployments[0].versions[0].version_id === versionId && deployments[0].versions[0].percentage === 100, 'Active deployment mismatch');
  result(await api(role, '/subdomain', 'POST', JSON.stringify({ enabled: true, previews_enabled: false })));
  assert.equal(result(await api(role, '/subdomain')).enabled, true, 'workers.dev readback mismatch');
  return { versionId, etag: uploaded.etag };
}

/** One canonical cleanup for parent recovery and the independent guardian; never resend DELETE. */
export async function cleanupOwned(api: Api, state: State, persist: () => void) {
  const rows: any[] = [];
  // One shared budget fits the parent's 90-second guardian wait, leaving room
  // for receipt recovery before the hard deadline. cloudApi takes at most
  // one second of pacing and five seconds of I/O per operation.
  const deadline = Math.min(state.deadline - 1000, Date.now() + 80000);
  const budgetedApi: Api = (...args) => {
    assert.ok(Date.now() + 6000 <= deadline, 'Cleanup operation budget exhausted');
    return api(...args);
  };
  for (const owned of state.owned) {
    try {
      const current = owned.attempted && !owned.deleteAttempted
        ? await readUploadedSettings(budgetedApi, owned.role, deadline) : await budgetedApi(owned.role, '/settings');
      if (absent(current)) {
        assert.ok(!owned.attempted || owned.deleteAttempted, 'Upload absence unresolved; cleanup remains unknown');
        owned.absent = true; rows.push({ role: owned.role, absent: true }); persist(); continue;
      }
      assert.ok(owned.attempted, 'Unowned resource; deletion refused');
      assert.ok(ownedBy(result(current), state.owner), 'Foreign resource; deletion refused');
      assert.ok(!owned.deleteAttempted, 'Prior deletion unknown; readback only');
      assert.ok(Date.now() + 12000 <= deadline, 'Cleanup requires DELETE and readback budget');
      owned.deleteAttempted = true; persist();
      // A lost response cannot authorize a second deletion attempt.
      try { result(await budgetedApi(owned.role, '', 'DELETE')); } catch { /* The following readback decides absence. */ }
      owned.absent = absent(await budgetedApi(owned.role, '/settings'));
      rows.push({ role: owned.role, absent: owned.absent }); persist();
    } catch { rows.push({ role: owned.role, absent: false, status: 'UNKNOWN' }); }
  }
  state.cleanup = rows; persist();
  return rows.every(row => row.absent) && state.owned.every(row => row.absent === true);
}

type Options = { directory: string; approvalFile: string; k6: string; account: string; workerToken: string; cpuToken: string; subdomain: string; preflight: any };
export async function runCloudDiagnostic(options: Options) {
  const { account, workerToken, cpuToken, subdomain } = options;
  const limits = freeDiagnosticPreflight(options.preflight, account);
  assert.match(subdomain, /^[a-z0-9-]+\.workers\.dev$/);
  const directory = path.resolve(options.directory);
  assert.ok(directory.startsWith(path.join(root, 'reports') + path.sep), 'Private reports directory required');
  assert.ok(path.resolve(options.approvalFile).startsWith(path.join(root, 'reports') + path.sep), 'Current approval receipt required');
  fs.mkdirSync(directory, { mode: 0o700 });
  const prefix = 'csf-1026-' + crypto.randomBytes(6).toString('hex'), owner = prefix + '-owned';
  const state: State = { prefix, owner, startedAt: 0, deadline: 0, owned: diagnosticRoles.map(role => ({ role, attempted: false, deleteAttempted: false })) };
  const stateFile = path.join(directory, 'ownership-private.json');
  const prepared = prepareBenchmark(directory, `https://${prefix}-gateway.${subdomain}`, `https://${prefix}-origin.${subdomain}`,
    Object.fromEntries(['bare', 'basic', 'regex', 'graphql', 'hmac', 'rs256'].map(role => [role, `https://${prefix}-${role}.${subdomain}`])));
  prepared.identity.sourceFiles.push({ file: 'src/scripts/edge-benchmark-cloud.ts', sha256: sha(fs.readFileSync(path.join(root, 'src/scripts/edge-benchmark-cloud.ts'))) });
  prepared.identity.builtFiles.push({ file: 'scripts/edge-benchmark-cloud.js', sha256: sha(fs.readFileSync(__filename)) });
  save(path.join(directory, 'identity.json'), prepared.identity);
  const report: any = { status: 'PREPARED', qualification: 'INCONCLUSIVE', objectiveComplete: false, topology: 'direct', series: [],
    clientReserved: 0, clientCap: limits.clientCap, invocationCap: limits.invocationCap, manual: [], deployments: {}, cleanup: {}, cpu: [] };
  const controller = new AbortController(), api = cloudApi(account, workerToken, state, directory, controller.signal);
  const abort = () => controller.abort();
  process.once('SIGINT', abort); process.once('SIGTERM', abort);
  let guardian: ReturnType<typeof fork> | undefined, cutoff: NodeJS.Timeout | undefined;
  let guardianClosed: Promise<void> | undefined;
  try {
    for (const role of diagnosticRoles) assert.ok(absent(await api(role, '/settings')), 'All five names must be absent before ownership');
    freeDiagnosticPreflight(options.preflight, account);
    consumeDiagnosticApproval(options.approvalFile, account, prefix);
    state.startedAt = Date.now(); state.deadline = state.startedAt + limits.windowMs;
    prepared.vars.EXPIRES = String(state.deadline); save(stateFile, state);
    guardian = fork(__filename, ['--guardian'], { detached: true, stdio: ['ignore', 'ignore', 'ignore', 'ipc'], env: { PATH: process.env.PATH } });
    guardianClosed = new Promise(resolve => { guardian!.once('exit', () => resolve()); guardian!.once('error', () => resolve()); });
    const ready = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Guardian readiness timeout')), 5000);
      guardian!.once('error', () => { clearTimeout(timer); reject(new Error('Guardian failed')); });
      guardian!.once('message', message => { clearTimeout(timer); (message as any)?.ready === true ? resolve() : reject(new Error('Guardian not ready')); });
    });
    guardian.once('exit', abort);
    guardian.send({ account, workerToken, directory, stateFile, deadline: state.deadline }); await ready;
    const remaining = remainingLoadMs(state.startedAt);
    assert.ok(remaining > 0, 'Load cutoff already reached');
    cutoff = setTimeout(abort, remaining);
    for (const role of diagnosticRoles) {
      controller.signal.throwIfAborted();
      const bytes = fs.readFileSync(path.join(directory, role + '.mjs'));
      assert.equal(sha(bytes), prepared.identity.generated.find(row => row.role === role)!.moduleSha256, 'Module bytes changed');
      const form = new FormData();
      form.append('metadata', JSON.stringify({ main_module: 'index.mjs', compatibility_date: compatibilityDate, compatibility_flags: ['global_fetch_strictly_public'],
        tags: [owner], logpush: false, observability: { enabled: true, head_sampling_rate: 1, logs: { enabled: true, head_sampling_rate: 1, persist: true, invocation_logs: true } },
        bindings: [...Object.entries(prepared.vars).map(([name, text]) => ({ name, text, type: 'plain_text' })), { name: 'CSF_VERSION_METADATA', type: 'version_metadata' }] }));
      form.append('index.mjs', new Blob([bytes], { type: 'application/javascript+module' }), 'index.mjs');
      state.owned.find(row => row.role === role)!.attempted = true; save(stateFile, state);
      report.stage = 'upload/readback:' + role;
      report.firstDeploymentOperationAt ??= Date.now();
      report.deployments[role] = await verifyUploadedWorker(api, role, await api(role, '', 'PUT', form), state);
      save(path.join(directory, 'report.json'), report);
    }
    let nextClient = 0;
    const request = async (role: Role, route: string, method: string, body: string | null, expected: number) => {
      controller.signal.throwIfAborted(); assert.ok(++report.clientReserved <= limits.clientCap, 'Client cap exceeded');
      await pause(Math.max(0, nextClient - Date.now())); controller.signal.throwIfAborted(); nextClient = Date.now() + 1000;
      const id = 'readiness-' + report.clientReserved, row: any = { id, role, route, expected, sentAt: Date.now(), status: 'UNKNOWN' }; report.manual.push(row); save(path.join(directory, 'report.json'), report);
      const response = await fetch(`https://${prefix}-${role}.${subdomain}${route}`, { method, body, redirect: 'error',
        headers: { 'x-csf-key': prepared.vars.PROBE_KEY, 'x-csf-id': id }, signal: AbortSignal.any([controller.signal, AbortSignal.timeout(5000)]) });
      row.status = response.status; const text = await response.text(); save(path.join(directory, 'report.json'), report);
      assert.equal(response.status, expected, 'Readiness/body-rejection failure');
      if (expected === 200) assert.equal(response.headers.get('x-csf-version'), report.deployments[role].versionId, 'HTTP version mismatch');
      return text;
    };
    report.stage = 'HTTP-readiness';
    await request('origin', '/jwks', 'GET', null, 200);
    for (const role of ['bare', 'basic', 'graphql', 'hmac'] as const) {
      const test = benchmarkCases.find(row => row.id === (role === 'bare' ? 'basic' : role))!;
      const data = JSON.parse(await request(role, `/${test.id}/${role === 'bare' ? 'bare' : 'generated'}`, test.method, test.body || null, 200));
      assert.ok(data.bodyHash === sha(test.body || '') && data.pathHash === sha(test.path) && data.bodyBytes === (test.body?.length || 0), 'Readiness oracle failure');
    }
    for (const [body, status] of [[null, 400], ['x', 400], ['x'.repeat(1048577), 413]] as const) await request('hmac', '/hmac/generated', 'POST', body, status);
    report.identitySha256 = sha(fs.readFileSync(path.join(directory, 'identity.json')));
    for (const id of ['basic', 'graphql', 'hmac']) {
      report.stage = 'measure/CPU:' + id;
      controller.signal.throwIfAborted(); assert.ok(report.clientReserved + 6 <= limits.clientCap, 'Client cap exceeded'); report.clientReserved += 6;
      await pause(Math.max(1000, nextClient - Date.now())); controller.signal.throwIfAborted();
      await runK6Series(directory, options.k6, { selected: [id], samples: 2, warmup: 1, rate: 1, runs: 1, concurrency: 1, model: 'iterations' }, report, controller.signal);
      // Fixed arrival allowance, not a retry of missing events or client requests.
      await pause(20000); controller.signal.throwIfAborted();
      for (const variant of ['bare', 'generated']) {
        const role = variant === 'bare' ? 'bare' : id as Role, series = `r0-${id}-${variant}-measured`;
        const { row, binding } = bindCpuSeries(report, prepared.manifest, series, `${prefix}-${role}`, report.deployments[role].versionId);
        const bytes = fs.readFileSync(path.join(directory, series + '-points.jsonl')); assert.equal(sha(bytes), row.pointsSha256);
        const capture = await collectCpuEvents(account, cpuToken, binding);
        const captureFile = path.join(directory, series + '-provider-private.json'); save(captureFile, capture);
        const joined = joinProviderCapture(clientPopulation(bytes, series, 2), capture, binding);
        report.cpu.push({ case: id, variant, ...joined, clientPointsSha256: sha(bytes), providerCaptureSha256: sha(fs.readFileSync(captureFile)), identitySha256: report.identitySha256 }); save(path.join(directory, 'report.json'), report);
        assert.equal(joined.status, 'CAPTURE_COMPLETE', 'CPU incomplete; next case forbidden');
      }
    }
    report.status = 'CAPTURE_COMPLETE';
  } catch (error) { report.status = 'INCONCLUSIVE'; report.failure = error instanceof Error ? error.message.split('\n')[0] : 'Unknown failure'; }
  finally {
    clearTimeout(cutoff); controller.abort(); process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort);
    if (guardian?.connected) guardian.send({ cleanup: true }, () => {});
    if (guardian && guardianClosed) {
      const stop = setTimeout(() => guardian!.kill('SIGKILL'), Math.max(1000, Math.min(90000, state.deadline - Date.now() - 120000)));
      await guardianClosed; clearTimeout(stop);
    }
    if (state.startedAt) {
      const current = JSON.parse(fs.readFileSync(stateFile, 'utf8')) as State;
      // Incomplete guardian receipts resume once, without resending a mutation.
      if (!current.owned.every(row => row.absent === true)) await cleanupOwned(cloudApi(account, workerToken, current, directory), current, () => save(stateFile, current));
      report.cleanup = { ownedAbsent: current.owned.every(row => row.absent === true), guardianStopped: !guardian || guardian.exitCode !== null || guardian.signalCode !== null,
        endedAt: Date.now(), withinWindow: Date.now() <= state.deadline, stateSha256: sha(fs.readFileSync(stateFile)) };
    }
    if (!report.cleanup.ownedAbsent || !report.cleanup.withinWindow || !report.cleanup.guardianStopped) report.status = 'INCONCLUSIVE';
    save(path.join(directory, 'report.json'), report);
  }
  return report;
}

if (require.main === module && process.argv[2] === '--guardian') {
  process.once('message', (options: any) => {
    const { directory, stateFile, deadline, account, workerToken } = options;
    let cleaning = false;
    const cleanup = async () => {
      if (cleaning) return; cleaning = true;
      try { const state = JSON.parse(fs.readFileSync(stateFile, 'utf8')) as State; await cleanupOwned(cloudApi(account, workerToken, state, directory), state, () => save(stateFile, state)); }
      finally { process.exit(0); }
    };
    process.on('message', (message: any) => { if (message?.cleanup) void cleanup(); });
    process.once('disconnect', () => void cleanup());
    setTimeout(() => void cleanup(), Math.max(0, deadline - 180000 - Date.now()));
    process.send?.({ ready: true });
  });
}
