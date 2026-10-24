import { expect, test } from 'vitest';
import { createHash } from 'node:crypto';
import { createHttpArtifactContract, captureHttpArtifactSnapshot, captureHttpArtifactObservation, verifyHttpArtifact, createHttpArtifactBundle, replayHttpArtifact, type HttpArtifactRawObservation, } from '../../src/contract/verification/artifact-http';
const sha = (bytes: string) => createHash('sha256').update(bytes).digest('hex');
const expected = createHttpArtifactContract('baseline-policy', [
    { id: 'admin-missing', target: '/admin', status: 401, reason: 'Unauthorized', artifact: true },
    { id: 'public', target: '/public', status: 200, forwarded: '/public', publicResponse: true, artifact: true },
]);
function snapshot(options: {
    weak?: boolean;
    missing?: string;
    badDigest?: boolean;
    runId?: string;
    port?: number;
    contract?: typeof expected;
    runtimeBytes?: string;
} = {}) {
    const material = [
        ['policy', 'policy.yml', options.weak ? 'weakened-policy' : 'baseline-policy'],
        ['generated-ts', 'worker.ts', options.weak ? 'weak generated TS' : 'normal generated TS'],
        ['module', 'worker.mjs', options.weak ? 'weak ESM' : 'normal ESM'],
        ['lock', 'package-lock.json', 'fixed-lock'], ['runtime-binary', 'workerd', options.runtimeBytes ?? 'unit-fixture-native-bytes'],
        ['runtime-config', 'config.capnp', 'unit-fixture-config'],
        ['source-module', 'harness.ts', 'fixed-source'], ['source-module', 'harness.js', 'fixed-execution-module'],
        ['compiler-module', 'bin/cli.js', 'fixed-compiler-entry'],
    ].filter(([role]) => role !== options.missing).map(([role, name, bytes]) => ({ role, name, bytes: Buffer.from(bytes), expectedSha256: options.badDigest ? '0'.repeat(64) : sha(bytes) }));
    return captureHttpArtifactSnapshot(options.contract ?? expected, {
        variant: options.weak ? 'weakened-policy' : 'normal', files: material,
        runtime: { version: 'workerd 2026-10-12', packageVersion: '1.20261012.1', compatibilityDate: '2026-07-20', compatibilityFlags: [], network: 'deny-all-loopback-origin' },
        metadata: { runId: options.runId ?? 'normal-run', sourceCommit: 'a'.repeat(40), startedAtMs: 100, finishedAtMs: 200, originPort: options.port ?? 1111, workerPort: 2222 },
        credentials: { valid: 'unit-synthetic-valid', wrong: 'unit-synthetic-wrong' },
    });
}
function rawObservation(s: ReturnType<typeof snapshot>, id = 'admin-missing', bypass = false): HttpArtifactRawObservation {
    const denied = id === 'admin-missing' && !bypass;
    const receipt = { url: id === 'public' ? '/public' : '/admin', method: 'GET', body: '', headers: { host: '127.0.0.1:' + s.metadata.originPort, 'x-e2e-id': id, ...(id === 'admin-valid' ? { 'x-edge-token': 'unit-synthetic-valid' } : {}) } };
    return {
        caseId: id, correlationId: id, recordedAtMs: 150,
        request: { target: receipt.url, method: 'GET', body: '', destination: { host: '127.0.0.1', port: s.metadata.workerPort }, headers: { 'x-e2e-id': id, ...(id === 'admin-valid' ? { 'x-edge-token': 'unit-synthetic-valid' } : {}) } },
        response: { status: denied ? 401 : 200, headers: {}, body: denied ? 'Unauthorized' : JSON.stringify(receipt) },
        origins: denied ? [] : [{ arrival: id === 'public' ? 1 : 0, receipt }],
        events: [{ event: denied ? 'block' : 'allow', correlation_id: id, uri: receipt.url, ...(denied ? { block_reason: 'Unauthorized' } : {}) }],
    };
}
function observation(s: ReturnType<typeof snapshot>, id = 'admin-missing', bypass = false) { return captureHttpArtifactObservation(s, rawObservation(s, id, bypass)); }
test('nonempty complete observations verify only the declared local fixture', () => {
    const s = snapshot(), r = verifyHttpArtifact(expected, s, [observation(s), observation(s, 'public')]);
    expect(r.semantic).toMatchObject({ scope: 'local-artifact-fixture', verdict: 'VERIFIED', unknown: [], counterexamples: [] });
});
test('fixed expectations detect an actual observed auth bypass despite a test detecting it successfully', () => {
    const s = snapshot({ weak: true }), r = verifyHttpArtifact(expected, s, [observation(s, 'admin-missing', true)]);
    expect(r.semantic.verdict).toBe('VIOLATED');
    expect(r.semantic.counterexamples[0]).toMatchObject({ caseId: 'admin-missing', request: { target: '/admin', credential: 'absent' } });
    expect(r.findings[0]).toMatchObject({ severity: 'error', confidence: 'deterministic' });
});
test('zero or missing required cases cannot prove security', () => {
    const s = snapshot();
    expect(verifyHttpArtifact(expected, s, []).semantic.verdict).toBe('UNKNOWN');
    expect(verifyHttpArtifact(expected, s, [observation(s)]).semantic.unknown).toContainEqual({ caseId: 'public', reason: 'OBSERVATION_MISSING' });
});
test('missing runtime identity stays unknown; supplied bytes with a false digest are Error', () => {
    const s = snapshot({ missing: 'runtime-binary' });
    expect(verifyHttpArtifact(expected, s, [observation(s), observation(s, 'public')]).semantic.verdict).toBe('UNKNOWN');
    expect(() => snapshot({ badDigest: true })).toThrow('ARTIFACT_BYTES_MISMATCH');
});
test('duplicate case observations are Error rather than extra passing evidence', () => {
    const s = snapshot(), o = observation(s);
    expect(() => verifyHttpArtifact(expected, s, [o, o])).toThrow('DUPLICATE_CASE');
});
test('mixed-run evidence is scoped unknown', () => {
    const s = snapshot(), other = snapshot({ runId: 'other-run' });
    expect(verifyHttpArtifact(expected, s, [observation(other), observation(s, 'public')]).semantic).toMatchObject({ verdict: 'UNKNOWN', unknown: [{ caseId: 'admin-missing', reason: 'RUN_OR_ARTIFACT_MIXED' }] });
});
test('changed unsealed observation and a mismatched request/case binding are Error', () => {
    const s = snapshot(), o = observation(s);
    expect(() => verifyHttpArtifact(expected, s, [structuredClone(o)])).toThrow('UNISSUED_OBSERVATION');
    expect(() => captureHttpArtifactObservation(s, { caseId: 'admin-missing', correlationId: 'bad', recordedAtMs: 150, request: { target: '/different', method: 'GET', body: '', headers: { 'x-e2e-id': 'bad' } }, response: { status: 401, headers: {}, body: '' }, origins: [], events: [] })).toThrow('CASE_REQUEST_MISMATCH');
});
test('missing event is unknown, while sufficient receipt mismatch is a concrete violation', () => {
    const s = snapshot();
    const input = { caseId: 'admin-missing', correlationId: 'admin-missing', recordedAtMs: 150, request: { target: '/admin', method: 'GET', body: '', destination: { host: '127.0.0.1', port: s.metadata.workerPort }, headers: { 'x-e2e-id': 'admin-missing' } }, response: { status: 401, headers: {}, body: 'Unauthorized' }, origins: [], events: [] };
    const o = captureHttpArtifactObservation(s, input);
    expect(verifyHttpArtifact(expected, s, [o, observation(s, 'public')]).semantic.verdict).toBe('UNKNOWN');
});
test('replay requires the captured trusted root and detects bundle edits', () => {
    const s = snapshot(), obs = [observation(s), observation(s, 'public')], r = verifyHttpArtifact(expected, s, obs), b = createHttpArtifactBundle(expected, s, obs);
    expect(replayHttpArtifact(expected, b, b.digest).semanticDigest).toBe(r.semanticDigest);
    const changed = structuredClone(b);
    changed.observations.pop();
    expect(() => replayHttpArtifact(expected, changed, b.digest)).toThrow('BUNDLE_DIGEST_MISMATCH');
    expect(replayHttpArtifact(expected, b).semantic.verdict).toBe('UNKNOWN');
});
test('execution/cleanup failures are Error even if every observation would pass', () => {
    const s = snapshot();
    expect(() => verifyHttpArtifact(expected, s, [observation(s), observation(s, 'public')], { failure: 'cleanup failed' })).toThrow('HTTP_EXECUTION_FAILED');
});
test('metadata ports/run IDs and item order do not change semantic evidence', () => {
    const a = snapshot(), b = snapshot({ port: 3333, runId: 'different-metadata' });
    expect(verifyHttpArtifact(expected, a, [observation(a), observation(a, 'public')]).semanticDigest)
        .toBe(verifyHttpArtifact(expected, b, [observation(b, 'public'), observation(b)]).semanticDigest);
});
test('stale observations and a different runtime snapshot cannot be used as current proof', () => {
    const s = snapshot(), raw = rawObservation(s);
    raw.recordedAtMs = 99;
    expect(verifyHttpArtifact(expected, s, [captureHttpArtifactObservation(s, raw), observation(s, 'public')]).semantic.unknown).toContainEqual({ caseId: 'admin-missing', reason: 'OBSERVATION_STALE' });
    const other = snapshot({ runtimeBytes: 'a different native binary' });
    expect(verifyHttpArtifact(expected, s, [observation(other), observation(s, 'public')]).semantic.verdict).toBe('UNKNOWN');
});
test('a real receipt path mismatch is a violation; duplicate receipt identities are Error', () => {
    const s = snapshot(), raw = rawObservation(s, 'public');
    raw.origins[0].receipt.url = '/unexpected';
    raw.response.body = JSON.stringify(raw.origins[0].receipt);
    const r = verifyHttpArtifact(expected, s, [observation(s), captureHttpArtifactObservation(s, raw)]);
    expect(r.semantic.verdict).toBe('VIOLATED');
    expect(r.semantic.counterexamples[0].differences).toContain('origin.path');
    raw.origins.push(raw.origins[0]);
    expect(() => captureHttpArtifactObservation(s, raw)).toThrow('DUPLICATE_ORIGIN_RECEIPT');
});
test('protected responses need both no-store and Vary; exported bundles abstract credentials', () => {
    const contract = createHttpArtifactContract('baseline-policy', [{ id: 'admin-valid', target: '/admin', credential: 'valid', status: 200, forwarded: '/admin', protectedResponse: true, artifact: true }]);
    const s = snapshot({ contract });
    for (const [cache, vary, verdict] of [['no-store', undefined, 'VIOLATED'], [undefined, 'Authorization', 'VIOLATED'], ['no-store', 'Authorization', 'VERIFIED']] as const) {
        const raw = rawObservation(s, 'admin-valid');
        raw.response.headers = { 'cache-control': cache, vary };
        const o = captureHttpArtifactObservation(s, raw);
        expect(verifyHttpArtifact(contract, s, [o]).semantic.verdict).toBe(verdict);
        expect(JSON.stringify(createHttpArtifactBundle(contract, s, [o]))).not.toContain('unit-synthetic-valid');
    }
});
test('reported expectedStatus cannot redefine the independent contract', () => {
    const s = snapshot({ weak: true }), raw = { ...rawObservation(s, 'admin-missing', true), expectedStatus: 200 };
    expect(verifyHttpArtifact(expected, s, [captureHttpArtifactObservation(s, raw)]).semantic.verdict).toBe('VIOLATED');
});
test('an observation from another actual socket is unknown, never a proof for this service', () => {
    const s = snapshot(), raw = rawObservation(s);
    raw.request.destination!.port = 3333;
    expect(verifyHttpArtifact(expected, s, [captureHttpArtifactObservation(s, raw), observation(s, 'public')]).semantic).toMatchObject({ verdict: 'UNKNOWN', unknown: [{ caseId: 'admin-missing', reason: 'RUN_OR_ARTIFACT_MIXED' }] });
});
test('foreign decision events are invalid joins', () => {
    const s = snapshot(), raw = rawObservation(s);
    raw.events[0].correlation_id = 'other-case';
    expect(() => captureHttpArtifactObservation(s, raw)).toThrow('INVALID_EVENT_BINDING');
});
