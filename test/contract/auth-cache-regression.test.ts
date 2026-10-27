import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { afterEach, expect, test } from 'vitest';
import input from '../fixtures/auth-cache/input.json';

const cli = path.resolve('scripts/auth-cache-regression.js');
const scratch: string[] = [];
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_')));
Object.assign(env, { GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: os.devNull });
const git = (repo: string, ...args: string[]) => execFileSync('git', [
  '-c', 'user.name=Synthetic Model', '-c', 'user.email=model@example.test',
  '-c', 'commit.gpgsign=false', '-c', `core.hooksPath=${os.devNull}`,
  '-c', 'init.templateDir=', ...args,
], { cwd: repo, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();

function bundle() {
  const aws = structuredClone(input.model);
  aws.associations[0].phase = 'viewer-request';
  const cloudflare = { ...structuredClone(aws), provider: 'cloudflare', cacheNamespace: 'worker.example.test',
    associations: [{ rule: 0, phase: 'worker-before-cache' }] };
  return { version: 1, contract: structuredClone(input.contract),
    policies: { aws: structuredClone(input.policy), cloudflare: structuredClone(input.policy) },
    models: { aws, cloudflare } };
}

function fixture(base = bundle(), head = bundle()) {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-model-gate-'));
  scratch.push(repo);
  git(repo, 'init', '-q');
  fs.writeFileSync(path.join(repo, 'model.json'), JSON.stringify(base));
  git(repo, 'add', 'model.json'); git(repo, 'commit', '-qm', 'base');
  const before = git(repo, 'rev-parse', 'HEAD');
  fs.writeFileSync(path.join(repo, 'model.json'), JSON.stringify(head));
  git(repo, 'add', 'model.json'); git(repo, 'commit', '--allow-empty', '-qm', 'head');
  const after = git(repo, 'rev-parse', 'HEAD');
  return { repo, base: before, head: after };
}

const run = (f: ReturnType<typeof fixture>, extra: Record<string, string> = {}, inputPath = 'model.json') => spawnSync(process.execPath,
  [cli, f.repo, f.base, f.head, inputPath], { env: { ...process.env, ...extra }, encoding: 'utf8', timeout: 3000 });

function replaceInput(f: ReturnType<typeof fixture>, body: string | Buffer) {
  fs.writeFileSync(path.join(f.repo, 'model.json'), body);
  git(f.repo, 'add', 'model.json'); git(f.repo, 'commit', '--allow-empty', '-qm', 'changed input');
  f.head = git(f.repo, 'rev-parse', 'HEAD');
}
function error(result: ReturnType<typeof run>, code: string) {
  expect(result.status).toBe(2);
  expect(result.stdout).toBe('');
  expect(JSON.parse(result.stderr)).toMatchObject({ status: 'ERROR', code });
}
function state(kind: 'safe' | 'violated' | 'unknown') {
  const data: any = bundle();
  if (kind === 'violated') data.models.aws.associations[0].phase = 'origin-request';
  if (kind === 'unknown') delete data.models.cloudflare.associations;
  return data;
}

afterEach(() => { for (const repo of scratch.splice(0)) fs.rmSync(repo, { recursive: true, force: true }); });

test('safe committed base/head snapshots produce an opt-in CI PASS', () => {
  const f = fixture();
  const result = run(f);
  expect(result.status).toBe(0);
  const report = JSON.parse(result.stdout);
  expect(report.status).toBe('PASS');
  expect(report.head.identity.commit).toBe(f.head);
  expect(report.baseline.identity.commit).toBe(f.base);
});

test.each([
  ['safe', 'violated', 1, 'REQUIRED_MODEL_VIOLATED', 'NEW_VIOLATION'],
  ['violated', 'safe', 0, 'REQUIRED_MODELS_VERIFIED', 'VERIFIED'],
  ['violated', 'violated', 1, 'REQUIRED_MODEL_VIOLATED', null],
  ['safe', 'unknown', 1, 'REQUIRED_MODEL_UNKNOWN', 'LOST_VERIFIABILITY'],
  ['unknown', 'safe', 0, 'REQUIRED_MODELS_VERIFIED', 'VERIFIED'],
  ['unknown', 'unknown', 1, 'REQUIRED_MODEL_UNKNOWN', null],
] as const)('%s -> %s retains required-model gate semantics', (before, after, exit, reason, transition) => {
  const f = fixture(state(before), state(after));
  const result = run(f);
  expect(result.status).toBe(exit);
  expect(result.stderr).toBe('');
  const report = JSON.parse(result.stdout);
  expect(report.reason).toBe(reason);
  expect(report.runtime).toBe('UNKNOWN');
  if (transition) expect(report.transitions[transition]).toBe(2);
  else expect(report.transitionExamples).toEqual([]);
});

test('identity is the committed blob and dirty input is ignored', () => {
  const f = fixture();
  const index = fs.readFileSync(path.join(f.repo, '.git', 'index'));
  const blob = git(f.repo, 'rev-parse', `${f.head}:model.json`);
  fs.writeFileSync(path.join(f.repo, 'model.json'), 'private-sentinel-not-json');
  const result = run(f), report = JSON.parse(result.stdout);
  expect(result.status).toBe(0);
  expect(report.head.identity.blob).toBe(blob);
  expect(report.head.identity.tree).toBe(git(f.repo, 'rev-parse', `${f.head}^{tree}`));
  expect(result.stdout + result.stderr).not.toContain('private-sentinel');
  expect(fs.readFileSync(path.join(f.repo, 'model.json'), 'utf8')).toBe('private-sentinel-not-json');
  expect(fs.readFileSync(path.join(f.repo, '.git', 'index'))).toEqual(index);
  expect(git(f.repo, 'rev-parse', 'HEAD')).toBe(f.head);
});

test('ambient Git redirection cannot select a different repository or index', () => {
  const f = fixture(), other = fixture(state('violated'), state('violated'));
  const result = run(f, { GIT_DIR: path.join(other.repo, '.git'), GIT_WORK_TREE: other.repo,
    GIT_INDEX_FILE: path.join(other.repo, 'nonexistent-index'), GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: 'core.worktree', GIT_CONFIG_VALUE_0: other.repo });
  expect(result.status).toBe(0);
  expect(JSON.parse(result.stdout).head.identity.commit).toBe(f.head);
  expect(fs.existsSync(path.join(other.repo, 'nonexistent-index'))).toBe(false);
});

test('replacement refs cannot hide an unsafe committed head', () => {
  const f = fixture(state('safe'), state('violated'));
  git(f.repo, 'replace', f.head, f.base);
  const result = run(f);
  expect(result.status).toBe(1);
  expect(JSON.parse(result.stdout).reason).toBe('REQUIRED_MODEL_VIOLATED');
});

test('partial-clone input is not lazily fetched or written into the object store', () => {
  const f = fixture();
  git(f.repo, 'config', 'uploadpack.allowFilter', 'true');
  const clone = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-model-promisor-'));
  scratch.push(clone);
  git(clone, 'clone', '-q', '--filter=blob:none', '--no-checkout', pathToFileURL(f.repo).href, '.');
  const blob = git(f.repo, 'rev-parse', `${f.head}:model.json`);
  const available = () => spawnSync('git', ['cat-file', '-e', blob], { cwd: clone,
    env: { ...env, GIT_NO_LAZY_FETCH: '1', GIT_ALLOW_PROTOCOL: '' }, encoding: 'utf8' }).status === 0;
  expect(available()).toBe(false);
  const result = run({ ...f, repo: clone });
  expect(result.status).toBe(2);
  expect(available()).toBe(false);
});

test('head must be the checked-out HEAD; arbitrary source labels are rejected', () => {
  const f = fixture();
  error(run({ ...f, head: f.base }), 'HEAD_MISMATCH');
});

test('base must be an ancestor rather than an unrelated branch', () => {
  const f = fixture();
  git(f.repo, 'checkout', '--orphan', 'unrelated');
  git(f.repo, 'commit', '--allow-empty', '-qm', 'unrelated');
  const foreign = git(f.repo, 'rev-parse', 'HEAD');
  git(f.repo, 'checkout', '--detach', f.head);
  error(run({ ...f, base: foreign }), 'BASE_NOT_ANCESTOR');
});

test.each(['bad-sha', 'unknown-sha', 'blob-instead-of-commit'] as const)('%s is an explicit Error', variant => {
  const f = fixture();
  const base = variant === 'bad-sha' ? '--unsafe' : variant === 'unknown-sha' ? '0'.repeat(40) : git(f.repo, 'rev-parse', `${f.base}:model.json`);
  error(run({ ...f, base }), variant === 'bad-sha' ? 'INVALID_REVISION' : variant === 'unknown-sha' ? 'REVISION_UNAVAILABLE' : 'COMMIT_REQUIRED');
});

test.each(['../model.json', '/model.json', 'model.json?token=sentinel', ':(glob)**/*.json'] as const)('invalid path %s is not a Git pathspec or filesystem fallback', file => {
  error(run(fixture(), {}, file), 'INVALID_INPUT_PATH');
});

test('a credential-bearing filename is rejected before Git reads or output', () => {
  const result = run(fixture(), { PATH: '' }, 'models/access_token-opaquecredentialvalue.json');
  error(result, 'INVALID_INPUT_PATH');
  expect(result.stdout + result.stderr).not.toContain('opaquecredentialvalue');
});

test('missing committed input does not fall back to a working-tree file', () => {
  const f = fixture();
  fs.writeFileSync(path.join(f.repo, 'missing.json'), JSON.stringify(bundle()));
  error(run(f, {}, 'missing.json'), 'REGULAR_INPUT_BLOB_REQUIRED');
});

test('a symlink blob is not followed', () => {
  const f = fixture();
  fs.unlinkSync(path.join(f.repo, 'model.json'));
  fs.symlinkSync('outside-sentinel.json', path.join(f.repo, 'model.json'));
  git(f.repo, 'add', 'model.json'); git(f.repo, 'commit', '-qm', 'symlink');
  f.head = git(f.repo, 'rev-parse', 'HEAD');
  error(run(f), 'REGULAR_INPUT_BLOB_REQUIRED');
});

test.each(['invalid-json', 'invalid-utf8', 'oversize'] as const)('%s cannot yield a partial PASS', variant => {
  const f = fixture();
  replaceInput(f, variant === 'invalid-json' ? '{private-sentinel' : variant === 'invalid-utf8' ? Buffer.from([0x80]) : ' '.repeat(1_048_577));
  const result = run(f);
  error(result, variant === 'oversize' ? 'INPUT_SIZE' : 'INVALID_UTF8_JSON');
  expect(result.stderr).not.toContain('private-sentinel');
  expect(result.stderr).not.toContain(f.repo);
});

test.each(['version', 'serialized-result', 'single-model', 'exception', 'provider'] as const)('%s cannot bypass bundle/model admission', variant => {
  const f = fixture(), data: any = bundle();
  if (variant === 'version') data.version = 2;
  if (variant === 'serialized-result') data.verdict = 'VERIFIED';
  if (variant === 'single-model') delete data.models.cloudflare;
  if (variant === 'exception') data.exceptions = [{ owner: 'synthetic', reason: 'bypass', expires: '2099-01-01' }];
  if (variant === 'provider') data.models.cloudflare.provider = 'aws';
  replaceInput(f, JSON.stringify(data));
  error(run(f), variant === 'version' ? 'INVALID_BUNDLE_VERSION' : variant === 'provider' ? 'INVALID_MODEL_INPUT' : 'INVALID_BUNDLE');
});

test('changing or dropping required contract/domain is an Error, not baseline weakening', () => {
  const f = fixture(), data = bundle(); data.contract.operations = [];
  replaceInput(f, JSON.stringify(data));
  error(run(f), 'REQUIRED_DOMAIN_CHANGED');
});

test('unavailable Git is a processing Error with no raw environment or input', () => {
  const result = run(fixture(), { PATH: '' });
  error(result, 'GIT_READ_FAILED');
  expect(JSON.parse(result.stderr).kind).toBe('PROCESSING');
});

test('a subdirectory cannot silently select its parent repository', () => {
  const f = fixture(), sub = path.join(f.repo, 'sub'); fs.mkdirSync(sub);
  error(run({ ...f, repo: sub }), 'REPOSITORY_ROOT_REQUIRED');
});

test('missing command arguments return a structured Error', () => {
  const result = spawnSync(process.execPath, [cli], { encoding: 'utf8' });
  error(result, 'ARGUMENT_COUNT');
});

test('an empty required domain is blocked instead of vacuously passing', () => {
  const data = bundle(); data.contract.operations = [];
  const result = run(fixture(data, data));
  expect(result.status).toBe(1);
  expect(JSON.parse(result.stdout)).toMatchObject({ reason: 'REQUIRED_MODEL_UNKNOWN', head: { cells: 0 } });
});

test('a known violation becoming unknown is not a repaired result', () => {
  const before = state('violated'), after: any = bundle(); delete after.models.aws.associations;
  const result = run(fixture(before, after)), report = JSON.parse(result.stdout);
  expect(result.status).toBe(1);
  expect(report.reason).toBe('REQUIRED_MODEL_UNKNOWN');
  expect(report.transitions.VIOLATION_NOW_UNKNOWN).toBe(2);
});

test('equal unsafe provider coverage remains blocked at the CI boundary', () => {
  const data = state('violated'); data.models.cloudflare.associations[0].phase = 'worker-after-cache';
  const result = run(fixture(data, data)), report = JSON.parse(result.stdout);
  expect(result.status).toBe(1);
  expect(report.head.gateCoverageEqual).toBe(true);
  expect(report.head.providers).toEqual({ aws: 'VIOLATED', cloudflare: 'VIOLATED' });
});

test('bounded examples never hide required UNKNOWN cells from the decision or counts', () => {
  const before = bundle();
  before.contract.operations = Array.from({ length: 12 }, (_, i) => ({ ...structuredClone(before.contract.operations[0]), path: `/api/admin/route-${i}` }));
  const after: any = structuredClone(before); delete after.models.cloudflare.associations;
  const result = run(fixture(before, after)), report = JSON.parse(result.stdout);
  expect(result.status).toBe(1);
  expect(report.head.cells).toBe(24);
  expect(report.head.unknownCount).toBe(24);
  expect(report.head.unknownExamples).toHaveLength(10);
  expect(report.transitions.LOST_VERIFIABILITY).toBe(24);
  expect(report.transitionExamples).toHaveLength(10);
  expect(report.head.findingsByProvider.cloudflare.count).toBe(0);
});

test('the same immutable snapshots give byte-identical output', () => {
  const f = fixture();
  expect(run(f).stdout).toBe(run(f).stdout);
});

test('large valid finite models finish or fail within the shared deadline without an outer kill', () => {
  const data: any = bundle();
  data.contract.operations = Array.from({ length: 128 }, (_, i) => ({ ...structuredClone(data.contract.operations[0]), path: `/api/admin/route-${i}` }));
  for (const provider of ['aws', 'cloudflare'] as const) {
    data.policies[provider].request.allowed_hosts = ['*.example.test'];
    data.policies[provider].routes = Array.from({ length: 128 }, (_, i) => ({ ...structuredClone(data.policies[provider].routes[0]), name: `admin-${i}` }));
    data.models[provider].hosts = ['admin.example.test', ...Array.from({ length: 15 }, (_, i) => `host-${i}.example.test`)];
    data.models[provider].associations = Array.from({ length: 128 }, (_, rule) => ({ rule, phase: provider === 'aws' ? 'viewer-request' : 'worker-before-cache' }));
  }
  const result = run(fixture(data, data));
  expect(result.signal).toBeNull();
  expect([0, 2]).toContain(result.status);
  if (result.status === 2) {
    const error = JSON.parse(result.stderr);
    expect(error.kind).toBe('PROCESSING');
    expect(['GATE_DEADLINE', 'MODEL_WORKER_FAILED']).toContain(error.code);
  } else expect(JSON.parse(result.stdout).status).toBe('PASS');
});

test('the packed internal command resolves its own engine/schema from an unrelated data repository', () => {
  const f = fixture(), stage = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-model-pack-'));
  scratch.push(stage);
  const packed = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--offline', '--json', '--pack-destination', stage], {
    encoding: 'utf8', env: { ...process.env, npm_config_cache: path.join(stage, 'cache'), npm_config_update_notifier: 'false' },
  }));
  expect(packed).toHaveLength(1);
  execFileSync('tar', ['-xzf', path.join(stage, packed[0].filename), '-C', stage]);
  const pkg = path.join(stage, 'package');
  fs.symlinkSync(path.resolve('node_modules'), path.join(pkg, 'node_modules'), 'dir');
  const result = spawnSync(process.execPath, [path.join(pkg, 'scripts/auth-cache-regression.js'), f.repo, f.base, f.head, 'model.json'], {
    cwd: f.repo, encoding: 'utf8', timeout: 3000,
  });
  expect(result.status).toBe(0);
  expect(JSON.parse(result.stdout).status).toBe('PASS');
});
