import { expect, test } from 'vitest';
import { compareAuthCacheModels, projectAuthCache, verifyAuthCache, type ExecutionModel } from '../../src/contract/verification/auth-cache';
import { checkAuthCacheWitness } from '../../src/contract/verification/auth-cache-witness';
import { contract, policy, model } from '../fixtures/auth-cache/input';

const cloudflare: ExecutionModel = {
  version: 2, provider: 'cloudflare', hosts: ['admin.example.test'],
  cacheNamespace: 'worker.example.test', location: 'edge-1', nowMs: 2000,
  flow: 'standard', originResponds: true, effects: [],
  associations: [{ rule: 0, phase: 'worker-before-cache' }],
  cache: {
    enabled: true, cacheable: true, ttlMs: 5000,
    key: { host: 'namespace', credential: 'shared' },
    fills: [{ request: { method: 'GET', host: 'admin.example.test', path: '/api/admin/users', credential: 'valid' }, storedAtMs: 1000, location: 'edge-1' }],
  },
};

test('explicit Cloudflare gate before cache covers both credential states', () => {
  const report = verifyAuthCache(projectAuthCache(contract, policy, cloudflare));
  expect(report.semantic.verdict).toBe('VERIFIED');
  expect(report.semantic.cells.map(c => [c.credential, c.verdict]))
    .toEqual([['absent', 'VERIFIED'], ['valid', 'VERIFIED']]);
});

test('version1 distribution model is rejected without an implicit AWS fallback', () => {
  const legacy: any = structuredClone(model);
  legacy.version = 1;
  legacy.distribution = 'distribution.example.test';
  delete legacy.provider;
  delete legacy.cacheNamespace;
  legacy.cache.key.host = 'distribution';
  expect(() => projectAuthCache(contract, policy, legacy)).toThrow();
});

test.each(['missing-provider', 'unknown-provider', 'old-namespace', 'old-key'] as const)('version2 %s is invalid rather than a legacy fallback', variant => {
  const value: any = structuredClone(cloudflare);
  if (variant === 'missing-provider') delete value.provider;
  if (variant === 'unknown-provider') value.provider = 'other';
  if (variant === 'old-namespace') { value.distribution = value.cacheNamespace; delete value.cacheNamespace; }
  if (variant === 'old-key') value.cache.key.host = 'distribution';
  expect(() => projectAuthCache(contract, policy, value)).toThrow();
});

const safeAws = () => projectAuthCache(contract, policy, { ...model, associations: [{ rule: 0, phase: 'viewer-request' }] });
const cf = (value: ExecutionModel = cloudflare) => projectAuthCache(contract, policy, value);

test('both safe models cover the same finite domain and keep runtime unknown', () => {
  const result = compareAuthCacheModels(safeAws(), cf());
  expect(result.semantic).toMatchObject({ verdict: 'VERIFIED', gateCoverageEqual: true,
    providers: { aws: 'VERIFIED', cloudflare: 'VERIFIED' }, runtime: 'UNKNOWN', deployment: 'UNKNOWN', wafExecution: 'UNKNOWN' });
  expect(result.semantic.cells).toHaveLength(2);
  expect(result.semantic.counterexamples).toEqual([]);
  expect(Object.isFrozen(result.semantic.bindings.cloudflare.artifacts)).toBe(true);
});

test.each(['aws', 'cloudflare'] as const)('one-sided %s bypass is independently replayable', provider => {
  const aws = provider === 'aws' ? projectAuthCache(contract, policy, model) : safeAws();
  const worker = cf(provider === 'cloudflare' ? { ...cloudflare, associations: [{ rule: 0, phase: 'worker-after-cache' }] } : cloudflare);
  const result = compareAuthCacheModels(aws, worker);
  expect(result.semantic.verdict).toBe('VIOLATED');
  expect(result.semantic.gateCoverageEqual).toBe(false);
  expect(result.semantic.counterexamples).toHaveLength(2);
  for (const counterexample of result.semantic.counterexamples) {
    expect(counterexample.provider).toBe(provider);
    expect(checkAuthCacheWitness(provider === 'aws' ? aws : worker, counterexample.witness)).toBe(true);
  }
});

test('matching unsafe coverage never becomes a safety VERIFIED result', () => {
  const result = compareAuthCacheModels(projectAuthCache(contract, policy, model), cf({ ...cloudflare, associations: [{ rule: 0, phase: 'worker-after-cache' }] }));
  expect(result.semantic.verdict).toBe('VIOLATED');
  expect(result.semantic.gateCoverageEqual).toBe(true);
  expect(result.semantic.providers).toEqual({ aws: 'VIOLATED', cloudflare: 'VIOLATED' });
  expect(result.semantic.counterexamples.map(c => c.provider)).toEqual(['aws', 'aws', 'cloudflare', 'cloudflare']);
  expect(result.findingsByProvider.aws).toHaveLength(2);
  expect(result.findingsByProvider.cloudflare).toHaveLength(2);
});

test('Cloudflare auth after cache covers MISS but not a resident HIT', () => {
  const value = { ...cloudflare, associations: [{ rule: 0, phase: 'worker-after-cache' as const }], cache: { enabled: false } };
  const report = verifyAuthCache(cf(value));
  expect(report.semantic.verdict).toBe('VERIFIED');
  expect(report.semantic.cells.map(c => c.reason)).toEqual(['ONLY_MISS_REACHABLE_WORKER_AUTH', 'ONLY_MISS_REACHABLE_WORKER_AUTH']);
});

test('Cloudflare unassociated gate exposes a reachable MISS and its exact origin trace', () => {
  const p = cf({ ...cloudflare, associations: [{ rule: 0, phase: 'unassociated' }], cache: { enabled: false } });
  const report = verifyAuthCache(p);
  expect(report.semantic.verdict).toBe('VIOLATED');
  for (const cell of report.semantic.cells) {
    expect(cell.witness!.trace).toEqual(['worker', 'cache-lookup', 'MISS', 'origin-fetch', 'protected-response']);
    expect(checkAuthCacheWitness(p, cell.witness!)).toBe(true);
  }
});

test.each(['worker-before-cache', 'worker-after-cache'] as const)('an absent-credential fill cannot pass the declared %s gate', phase => {
  const value = structuredClone(cloudflare);
  value.associations = [{ rule: 0, phase }];
  value.cache!.fills![0].request.credential = 'absent';
  expect(() => cf(value)).toThrow('UNREACHABLE_FILL');
});

test('supported static-token gates retain the abstract absent/valid credential obligation', () => {
  const pol = structuredClone(policy);
  pol.routes![0].auth_gate = { type: 'static_token', header: 'x-model-auth', token_env: 'MVP_TOKEN' };
  const result = compareAuthCacheModels(projectAuthCache(contract, pol, { ...model, associations: [{ rule: 0, phase: 'viewer-request' }] }), projectAuthCache(contract, pol, cloudflare));
  expect(result.semantic.verdict).toBe('VERIFIED');
  expect(result.semantic.runtime).toBe('UNKNOWN');
});

test.each(['missing-association', 'unknown-association', 'response', 'missing-cache-key', 'skip', 'effect'] as const)('Cloudflare %s stays narrowly UNKNOWN', variant => {
  const value: any = structuredClone(cloudflare);
  value.associations[0].phase = 'worker-after-cache';
  if (variant === 'missing-association') delete value.associations;
  if (variant === 'unknown-association') value.associations[0].phase = 'unknown';
  if (variant === 'response') value.associations[0].phase = 'worker-response';
  if (variant === 'missing-cache-key') delete value.cache.key;
  if (variant === 'skip' || variant === 'effect') value.effects = [{ kind: variant === 'skip' ? 'skip' : 'unknown', paths: ['/api/admin/users'] }];
  const result = compareAuthCacheModels(safeAws(), cf(value));
  expect(result.semantic.verdict).toBe('UNKNOWN');
  expect(result.semantic.gateCoverageEqual).toBeNull();
  expect(result.semantic.providers.aws).toBe('VERIFIED');
  expect(result.semantic.providers.cloudflare).toBe('UNKNOWN');
  expect(result.semantic.counterexamples).toEqual([]);
});

test('unsupported Cloudflare JWT is not modeled as a supported blocking gate', () => {
  const pol = structuredClone(policy);
  pol.routes![0].auth_gate = { type: 'jwt', algorithm: 'HS256', secret_env: 'MVP_HMAC' };
  const report = verifyAuthCache(projectAuthCache(contract, pol, cloudflare));
  expect(report.semantic.verdict).toBe('UNKNOWN');
  expect(report.semantic.cells.every(c => c.reason === 'AUTH_GATE_UNSUPPORTED')).toBe(true);
});

test.each(['viewer-request', 'origin-request', 'origin-response'] as const)('Cloudflare rejects AWS-only placement %s as invalid input', phase => {
  expect(() => cf({ ...cloudflare, associations: [{ rule: 0, phase }] })).toThrow('INVALID_ASSOCIATION');
});

test.each(['worker-before-cache', 'worker-after-cache', 'worker-response'] as const)('AWS rejects Cloudflare-only placement %s as invalid input', phase => {
  expect(() => projectAuthCache(contract, policy, { ...model, associations: [{ rule: 0, phase }] })).toThrow('INVALID_ASSOCIATION');
});

test.each(['time', 'location', 'hosts'] as const)('different request-domain %s cannot be compared', variant => {
  const value = structuredClone(cloudflare), pol = structuredClone(policy);
  if (variant === 'time') value.nowMs++;
  if (variant === 'location') value.location = 'edge-2';
  if (variant === 'hosts') { value.hosts.push('second.example.test'); pol.request!.allowed_hosts = ['*.example.test']; }
  expect(() => compareAuthCacheModels(safeAws(), projectAuthCache(contract, pol, value))).toThrow('COMPARISON_DOMAIN');
});

test('different requirements, swapped providers and forged projection are Error', () => {
  const changed = structuredClone(contract); changed.operations[0].path = '/api/admin/other';
  expect(() => compareAuthCacheModels(safeAws(), projectAuthCache(changed, policy, cloudflare))).toThrow('COMPARISON_CONTRACT');
  expect(() => compareAuthCacheModels(cf(), safeAws())).toThrow('COMPARISON_PROVIDER');
  expect(() => compareAuthCacheModels(structuredClone(safeAws()), cf())).toThrow('PROJECTION_BINDING');
});

test('empty protected domain is UNKNOWN, not vacuous VERIFIED or equal coverage', () => {
  const empty = structuredClone(contract); empty.operations = [];
  const result = compareAuthCacheModels(projectAuthCache(empty, policy, model), projectAuthCache(empty, policy, cloudflare));
  expect(result.semantic.verdict).toBe('UNKNOWN');
  expect(result.semantic.gateCoverageEqual).toBeNull();
});

test.each(['path', 'host', 'trace', 'fill', 'digest'] as const)('independent Cloudflare replay rejects tampered %s', variant => {
  const p = cf({ ...cloudflare, associations: [{ rule: 0, phase: 'worker-after-cache' }] });
  const witness = structuredClone(verifyAuthCache(p).semantic.cells[0].witness!);
  expect(witness.trace).toEqual(['worker', 'cache-lookup', 'HIT', 'protected-response']);
  if (variant === 'path') witness.request.path = '/api/admin/other';
  if (variant === 'host') witness.request.host = 'second.example.test';
  if (variant === 'trace') witness.trace[0] = 'viewer-request';
  if (variant === 'fill') delete witness.fill;
  if (variant === 'digest') witness.inputDigest = 'sha256:' + '0'.repeat(64);
  expect(() => checkAuthCacheWitness(p, witness)).toThrow('INVALID_AUTH_CACHE_WITNESS');
});

test('Cloudflare before-cache gate invalidates an old bypass even with a rebound digest', () => {
  const unsafe = cf({ ...cloudflare, associations: [{ rule: 0, phase: 'worker-after-cache' }] });
  const safe = cf(), witness = structuredClone(verifyAuthCache(unsafe).semantic.cells[0].witness!);
  witness.inputDigest = safe.digest;
  expect(() => checkAuthCacheWitness(safe, witness)).toThrow('INVALID_AUTH_CACHE_WITNESS');
});

test('deterministic semantic binding changes with policy or declared time and contains no credentials', () => {
  const first = compareAuthCacheModels(safeAws(), cf());
  expect(compareAuthCacheModels(safeAws(), cf()).semanticDigest).toBe(first.semanticDigest);
  const pol = structuredClone(policy); pol.routes![0].name = 'renamed';
  const changed = compareAuthCacheModels(safeAws(), projectAuthCache(contract, pol, cloudflare));
  expect(changed.semantic.verdict).toBe('VERIFIED');
  expect(changed.semanticDigest).not.toBe(first.semanticDigest);
  const later = compareAuthCacheModels(projectAuthCache(contract, policy, { ...model, nowMs: 2001, associations: [{ rule: 0, phase: 'viewer-request' }] }), cf({ ...cloudflare, nowMs: 2001 }));
  expect(later.semanticDigest).not.toBe(first.semanticDigest);
  expect(JSON.stringify(first)).not.toContain('MVP_BASIC');
});
