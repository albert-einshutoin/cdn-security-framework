#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { devNull } from 'node:os';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { TextDecoder } from 'node:util';
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { AuthCacheInputError, compareAuthCacheModels, projectAuthCache } from '../contract/verification/auth-cache';
import { redactEvidenceFilename } from '../contract/sensitive-text';

const MAX_BYTES = 1_048_576;
const MAX_EXAMPLES = 10;
const BUDGET_MS = 2000;
const MODEL_OLD_MIB = 64, MODEL_YOUNG_MIB = 16, MODEL_STACK_MIB = 4;
const OID = /^[a-f0-9]{40}$/;
const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');

export class AuthCacheRegressionError extends Error {
  constructor(readonly kind: 'INPUT' | 'PROCESSING', readonly code: string) {
    super(code); this.name = 'AuthCacheRegressionError';
  }
}
function must(value: unknown, code: string): asserts value {
  if (!value) throw new AuthCacheRegressionError('INPUT', code);
}
function object(value: unknown, keys: string[]): Record<string, unknown> {
  must(value && typeof value === 'object' && !Array.isArray(value), 'INVALID_BUNDLE');
  must(Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k)), 'INVALID_BUNDLE');
  return value as Record<string, unknown>;
}
function evaluate(bytes: Uint8Array) {
  let data: unknown;
  try { data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { throw new AuthCacheRegressionError('INPUT', 'INVALID_UTF8_JSON'); }
  const input = object(data, ['version', 'contract', 'policies', 'models']);
  must(input.version === 1, 'INVALID_BUNDLE_VERSION');
  const policies = object(input.policies, ['aws', 'cloudflare']);
  const models = object(input.models, ['aws', 'cloudflare']);
  type Args = Parameters<typeof projectAuthCache>;
  try {
    return compareAuthCacheModels(
      projectAuthCache(input.contract as Args[0], policies.aws as Args[1], models.aws as Args[2]),
      projectAuthCache(input.contract as Args[0], policies.cloudflare as Args[1], models.cloudflare as Args[2]),
    );
  } catch (e) {
    if (e instanceof AuthCacheInputError) throw new AuthCacheRegressionError('INPUT', 'INVALID_MODEL_INPUT');
    throw new AuthCacheRegressionError('PROCESSING', 'MODEL_EVALUATION_FAILED');
  }
}

// One committed blob per revision: the planner's fetch/deepen recovery and repository diff are not applicable here.
export async function runAuthCacheRegression(workspaceRoot: string, base: string, head: string, inputPath: string) {
  const deadline = performance.now() + BUDGET_MS;
  must(typeof workspaceRoot === 'string' && workspaceRoot.length > 0 && workspaceRoot.length <= 4096, 'INVALID_REPOSITORY');
  must(typeof base === 'string' && OID.test(base) && typeof head === 'string' && OID.test(head), 'INVALID_REVISION');
  must(typeof inputPath === 'string' && inputPath.length <= 240 && /^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*\.json$/.test(inputPath)
    && !inputPath.split('/').some(p => p === '.' || p === '..') && redactEvidenceFilename(inputPath) === inputPath, 'INVALID_INPUT_PATH');
  let root: string;
  try { root = fs.realpathSync(workspaceRoot); }
  catch { throw new AuthCacheRegressionError('INPUT', 'REPOSITORY_UNAVAILABLE'); }
  const engineFiles = [__filename, require.resolve('../contract/verification/auth-cache')];
  const observeEngine = () => {
    try { return engineFiles.map(p => digest(fs.readFileSync(p))); }
    catch { throw new AuthCacheRegressionError('PROCESSING', 'ENGINE_UNAVAILABLE'); }
  };
  const engine = observeEngine();
  // Ambient Git redirection/replacement can silently select a different object store.
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_')));
  Object.assign(env, { GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: devNull, GIT_OPTIONAL_LOCKS: '0',
    GIT_NO_LAZY_FETCH: '1', GIT_ALLOW_PROTOCOL: '', GIT_TERMINAL_PROMPT: '0' });
  const git = (args: string[], missing?: string) => {
    const remaining = Math.floor(deadline - performance.now());
    if (remaining <= 0) throw new AuthCacheRegressionError('PROCESSING', 'GATE_DEADLINE');
    // A promisor object lookup otherwise performs an implicit fetch and mutates the local store.
    const result = spawnSync('git', ['--no-pager', '--no-replace-objects', '--no-lazy-fetch', '--literal-pathspecs',
      '-c', 'core.fsmonitor=false', '-C', root, ...args], {
      env, stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: MAX_BYTES + 1, timeout: remaining,
    });
    if (result.error || result.signal) throw new AuthCacheRegressionError('PROCESSING', 'GIT_READ_FAILED');
    if (result.status !== 0) throw new AuthCacheRegressionError(missing ? 'INPUT' : 'PROCESSING', missing ?? 'GIT_COMMAND_FAILED');
    return result.stdout;
  };
  const text = (args: string[], missing?: string) => git(args, missing).toString('utf8').trim();
  let top: string;
  try { top = fs.realpathSync(git(['rev-parse', '--show-toplevel'], 'REPOSITORY_UNAVAILABLE').toString('utf8').replace(/\n$/, '')); }
  catch (e) { if (e instanceof AuthCacheRegressionError) throw e; throw new AuthCacheRegressionError('INPUT', 'REPOSITORY_UNAVAILABLE'); }
  must(top === root, 'REPOSITORY_ROOT_REQUIRED');
  must(text(['rev-parse', '--verify', 'HEAD'], 'HEAD_UNAVAILABLE') === head, 'HEAD_MISMATCH');
  for (const revision of [base, head]) must(text(['cat-file', '-t', revision], 'REVISION_UNAVAILABLE') === 'commit', 'COMMIT_REQUIRED');
  git(['merge-base', '--is-ancestor', base, head], 'BASE_NOT_ANCESTOR');
  const capture = (commit: string) => {
    const tree = text(['rev-parse', `${commit}^{tree}`]);
    must(OID.test(tree), 'TREE_IDENTITY');
    const entry = git(['ls-tree', '-z', '--full-tree', commit, '--', inputPath]).toString('utf8');
    const match = /^(100644|100755) blob ([a-f0-9]{40})\t([^\0]+)\0$/.exec(entry);
    must(match && match[3] === inputPath, 'REGULAR_INPUT_BLOB_REQUIRED');
    const blob = match[2];
    const sizeText = text(['cat-file', '-s', blob]);
    must(/^(0|[1-9][0-9]*)$/.test(sizeText), 'INPUT_SIZE');
    const size = Number(sizeText);
    must(Number.isSafeInteger(size) && size > 0 && size <= MAX_BYTES, 'INPUT_SIZE');
    const bytes = git(['cat-file', 'blob', blob]);
    must(bytes.length === size, 'BLOB_BINDING');
    const actual = createHash('sha1').update(`blob ${size}\0`).update(bytes).digest('hex');
    must(actual === blob, 'BLOB_BINDING');
    return { bytes, identity: Object.freeze({ commit, tree, blob, path: inputPath, bytes: size, sha256: digest(bytes) }) };
  };
  // Verify both identities and bytes before interpreting either model bundle.
  const before = capture(base), after = capture(head);
  const report = await computeInWorker(before, after, engine, deadline);
  must(text(['rev-parse', '--verify', 'HEAD']) === head, 'HEAD_CHANGED');
  if (JSON.stringify(engine) !== JSON.stringify(observeEngine())) throw new AuthCacheRegressionError('PROCESSING', 'ENGINE_BINDING_CHANGED');
  if (performance.now() > deadline) throw new AuthCacheRegressionError('PROCESSING', 'GATE_DEADLINE');
  return report;
}

type Captured = { bytes: Uint8Array; identity: Readonly<{commit: string; tree: string; blob: string; path: string; bytes: number; sha256: string}> };
function compareSnapshots(before: Captured, after: Captured, engine: string[]) {
  const baseline = evaluate(before.bytes), candidate = evaluate(after.bytes);
  must(baseline.semantic.contractDigest === candidate.semantic.contractDigest
    && JSON.stringify(baseline.semantic.domain) === JSON.stringify(candidate.semantic.domain), 'REQUIRED_DOMAIN_CHANGED');
  if (baseline.semantic.model !== candidate.semantic.model
    || baseline.semantic.bindings.aws.validationSchema.digest !== candidate.semantic.bindings.aws.validationSchema.digest) {
    throw new AuthCacheRegressionError('PROCESSING', 'ENGINE_BINDING_CHANGED');
  }
  const cellKey = (c: typeof baseline.semantic.cells[number]) => JSON.stringify([c.routeKey, c.host, c.credential]);
  const oldCells = new Map(baseline.semantic.cells.map(c => [cellKey(c), c]));
  must(oldCells.size === candidate.semantic.cells.length, 'REQUIRED_DOMAIN_CHANGED');
  type Transition = 'NEW_VIOLATION' | 'LOST_VERIFIABILITY' | 'VERIFIED' | 'VIOLATION_NOW_UNKNOWN';
  const transitions = { NEW_VIOLATION: 0, LOST_VERIFIABILITY: 0, VERIFIED: 0, VIOLATION_NOW_UNKNOWN: 0 };
  const transitionExamples: Array<{ provider: 'aws' | 'cloudflare'; routeKey: string; host: string;
    credential: string; before: string; after: string; kind: Transition }> = [];
  for (const cell of candidate.semantic.cells) {
    const previous = oldCells.get(cellKey(cell)); must(previous, 'REQUIRED_DOMAIN_CHANGED');
    for (const provider of ['aws', 'cloudflare'] as const) {
      const beforeVerdict = previous[provider].verdict, afterVerdict = cell[provider].verdict;
      if (beforeVerdict === afterVerdict) continue;
      const kind: Transition = afterVerdict === 'VIOLATED' ? 'NEW_VIOLATION'
        : afterVerdict === 'VERIFIED' ? 'VERIFIED' : beforeVerdict === 'VERIFIED' ? 'LOST_VERIFIABILITY' : 'VIOLATION_NOW_UNKNOWN';
      transitions[kind]++;
      if (transitionExamples.length < MAX_EXAMPLES) transitionExamples.push({ provider, routeKey: cell.routeKey,
        host: cell.host, credential: cell.credential, before: beforeVerdict, after: afterVerdict, kind });
    }
  }
  const summarize = (snapshot: typeof before, result: typeof baseline) => {
    const unknown = result.semantic.cells.filter(c => c.aws.verdict === 'UNKNOWN' || c.cloudflare.verdict === 'UNKNOWN');
    return Object.freeze({ identity: snapshot.identity, verdict: result.semantic.verdict, semanticDigest: result.semanticDigest,
      contractDigest: result.semantic.contractDigest, domain: result.semantic.domain,
      providers: result.semantic.providers, bindings: result.semantic.bindings, gateCoverageEqual: result.semantic.gateCoverageEqual,
      cells: result.semantic.cells.length, unknownCount: unknown.length, unknownExamples: unknown.slice(0, MAX_EXAMPLES),
      counterexampleCount: result.semantic.counterexamples.length, counterexamples: result.semantic.counterexamples.slice(0, MAX_EXAMPLES),
      findingsByProvider: Object.fromEntries((['aws', 'cloudflare'] as const).map(provider => [provider, {
        count: result.findingsByProvider[provider].length, examples: result.findingsByProvider[provider].slice(0, MAX_EXAMPLES),
      }])) });
  };
  const status = candidate.semantic.verdict === 'VERIFIED' ? 'PASS' as const : 'BLOCK' as const;
  return Object.freeze({ version: 1 as const, scope: 'committed-finite-model-auth-cache' as const, status, exitCode: status === 'PASS' ? 0 : 1,
    resourceBounds: { inputBytesPerBlob: MAX_BYTES, gitAndModelMs: BUDGET_MS,
      workerOldGenerationMiB: MODEL_OLD_MIB, workerYoungGenerationMiB: MODEL_YOUNG_MIB, workerStackMiB: MODEL_STACK_MIB,
      examplesPerGroup: MAX_EXAMPLES, reportBytes: MAX_BYTES },
    engine: { model: baseline.semantic.model, modelVersion: 2, observedGateSha256: engine[0], observedModelSha256: engine[1] },
    baseline: summarize(before, baseline), head: summarize(after, candidate),
    transitions, transitionExamples,
    reason: candidate.semantic.verdict === 'VERIFIED' ? 'REQUIRED_MODELS_VERIFIED'
      : candidate.semantic.verdict === 'VIOLATED' ? 'REQUIRED_MODEL_VIOLATED' : 'REQUIRED_MODEL_UNKNOWN',
    runtime: 'UNKNOWN' as const, deployment: 'UNKNOWN' as const, wafExecution: 'UNKNOWN' as const,
    limits: ['Declared finite models only; no native/runtime/deployment equivalence or automatic product CI adoption',
      'All modeled auth obligations are mandatory; no waiver or automatic weakening',
      'Examples bounded to10 per group; decisions and semantic digests use all cells',
      'Trusted Git executable/object store assumed; observed file digests and input identity are not host/process attestation'] });
}

// Model evaluation is preemptible; an after-the-fact deadline cannot bound synchronous solver work.
function computeInWorker(before: Captured, after: Captured, engine: string[], deadline: number): Promise<ReturnType<typeof compareSnapshots>> {
  return new Promise((resolve, reject) => {
    const remaining = Math.floor(deadline - performance.now());
    if (remaining <= 0) { reject(new AuthCacheRegressionError('PROCESSING', 'GATE_DEADLINE')); return; }
    const worker = new Worker(__filename, {
      workerData: { type: 'csf-auth-cache-model', before, after, engine }, execArgv: [],
      env: { NODE_OPTIONS: '' }, stdout: true, stderr: true,
      resourceLimits: { maxOldGenerationSizeMb: MODEL_OLD_MIB, maxYoungGenerationSizeMb: MODEL_YOUNG_MIB, stackSizeMb: MODEL_STACK_MIB },
    });
    let finished = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (error?: AuthCacheRegressionError, report?: ReturnType<typeof compareSnapshots>) => {
      if (finished) return;
      finished = true;
      if (timer) clearTimeout(timer);
      void worker.terminate().then(() => error ? reject(error) : resolve(report!), () => reject(new AuthCacheRegressionError('PROCESSING', 'MODEL_WORKER_FAILED')));
    };
    timer = setTimeout(() => finish(new AuthCacheRegressionError('PROCESSING', 'GATE_DEADLINE')), remaining);
    worker.stdout?.on('data', () => finish(new AuthCacheRegressionError('PROCESSING', 'MODEL_WORKER_OUTPUT')));
    worker.stderr?.on('data', () => finish(new AuthCacheRegressionError('PROCESSING', 'MODEL_WORKER_OUTPUT')));
    worker.once('error', () => finish(new AuthCacheRegressionError('PROCESSING', 'MODEL_WORKER_FAILED')));
    worker.once('exit', () => { if (!finished) finish(new AuthCacheRegressionError('PROCESSING', 'MODEL_WORKER_FAILED')); });
    worker.once('message', (packet: unknown) => {
      if (finished) return;
      try {
        const data = packet as { ok?: unknown; body?: unknown; kind?: unknown; code?: unknown };
        if (data?.ok === false && (data.kind === 'INPUT' || data.kind === 'PROCESSING') && typeof data.code === 'string' && /^[A-Z0-9_]{1,64}$/.test(data.code)) {
          finish(new AuthCacheRegressionError(data.kind, data.code)); return;
        }
        if (data?.ok !== true || typeof data.body !== 'string' || Buffer.byteLength(data.body) > MAX_BYTES) throw new Error();
        const report = JSON.parse(data.body) as ReturnType<typeof compareSnapshots>;
        if (report.version !== 1 || report.scope !== 'committed-finite-model-auth-cache'
          || JSON.stringify(report.baseline.identity) !== JSON.stringify(before.identity)
          || JSON.stringify(report.head.identity) !== JSON.stringify(after.identity)) throw new Error();
        for (const part of [report.baseline, report.head]) { Object.freeze(part.identity); Object.freeze(part); }
        finish(undefined, Object.freeze(report));
      } catch { finish(new AuthCacheRegressionError('PROCESSING', 'MODEL_WORKER_PROTOCOL')); }
    });
  });
}

async function main(argv: string[]): Promise<number> {
  try {
    must(argv.length === 4, 'ARGUMENT_COUNT');
    const report = await runAuthCacheRegression(argv[0], argv[1], argv[2], argv[3]);
    const body = JSON.stringify(report) + '\n';
    if (Buffer.byteLength(body) > MAX_BYTES) throw new AuthCacheRegressionError('PROCESSING', 'REPORT_SIZE');
    process.stdout.write(body);
    return report.exitCode;
  } catch (e) {
    const error = e instanceof AuthCacheRegressionError ? e : new AuthCacheRegressionError('PROCESSING', 'MODEL_GATE_FAILED');
    process.stderr.write(JSON.stringify({ version: 1, status: 'ERROR', kind: error.kind, code: error.code }) + '\n');
    return 2;
  }
}
if (require.main === module) {
  if (isMainThread) void main(process.argv.slice(2)).then(code => { process.exitCode = code; });
  else {
    try {
      must(workerData?.type === 'csf-auth-cache-model', 'MODEL_WORKER_PROTOCOL');
      const result = compareSnapshots(workerData.before, workerData.after, workerData.engine);
      const body = JSON.stringify(result);
      if (Buffer.byteLength(body) > MAX_BYTES) throw new AuthCacheRegressionError('PROCESSING', 'REPORT_SIZE');
      parentPort?.postMessage({ ok: true, body });
    } catch (e) {
      const error = e instanceof AuthCacheRegressionError ? e : new AuthCacheRegressionError('PROCESSING', 'MODEL_WORKER_FAILED');
      parentPort?.postMessage({ ok: false, kind: error.kind, code: error.code });
    } finally { parentPort?.close(); }
  }
}
