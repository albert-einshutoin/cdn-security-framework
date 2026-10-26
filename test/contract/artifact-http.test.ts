import { expect, test } from 'vitest';
import { createHash } from 'node:crypto';
import { createHttpArtifactContract, captureHttpArtifactSnapshot, captureHttpArtifactObservation, verifyHttpArtifact, createHttpArtifactBundle, replayHttpArtifact, bindHttpArtifactDeployment, type HttpArtifactRawObservation, } from '../../src/contract/verification/artifact-http';
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

function deploymentInput(s: ReturnType<typeof snapshot>) {
    return {
        version: 1, scope: 'saved-deployment-fixture',
        expected: { resourceIdSha256: sha('fixture-resource'), deploymentVersionSha256: sha('fixture-version'), referenceTimeMs: 1000, maxAgeMs: 100 },
        receipts: [{ resourceIdSha256: sha('fixture-resource') as string | null,
            deploymentVersionSha256: sha('fixture-version') as string | null,
            artifactId: s.artifactId as string | null, capturedAtMs: 950 }],
    };
}

test('saved deployment receipt matches only the issued artifact and explicit resource/version/window', () => {
    const s = snapshot(), result = bindHttpArtifactDeployment(s, JSON.stringify(deploymentInput(s)));
    expect(result.semantic).toMatchObject({ scope: 'saved-deployment-fixture', state: 'current', reasons: [], artifactId: s.artifactId, contractDigest: expected.digest });
    expect(result.semantic).not.toHaveProperty('verdict');
});

test('absent deployment receipt and missing artifact identity remain missing', () => {
    const s = snapshot(), input = deploymentInput(s);
    input.receipts = [];
    expect(bindHttpArtifactDeployment(s, undefined).semantic.state).toBe('missing');
    expect(bindHttpArtifactDeployment(s, JSON.stringify(input)).semantic).toMatchObject({ state: 'missing', reasons: ['DEPLOYMENT_RECEIPTS_MISSING'] });
    input.receipts = deploymentInput(s).receipts;
    input.receipts[0].artifactId = null;
    expect(bindHttpArtifactDeployment(s, JSON.stringify(input)).semantic.state).toBe('missing');
});

test('expired receipt and mixed deployment identities do not become current', () => {
    const s = snapshot(), input = deploymentInput(s);
    input.receipts[0].capturedAtMs = 899;
    expect(bindHttpArtifactDeployment(s, JSON.stringify(input)).semantic).toMatchObject({ state: 'stale', reasons: ['DEPLOYMENT_RECEIPT_STALE'] });
    input.receipts[0].capturedAtMs = 950;
    input.receipts.push({ ...input.receipts[0], deploymentVersionSha256: sha('fixture-version-2'), artifactId: sha('different-artifact'), capturedAtMs: 951 });
    expect(bindHttpArtifactDeployment(s, JSON.stringify(input)).semantic).toMatchObject({ state: 'mixed', reasons: expect.arrayContaining(['DEPLOYMENT_MIXED']) });
});

test.each([900, 1000])('deployment freshness includes the explicit window boundary %i', capturedAtMs => {
    const s = snapshot(), input = deploymentInput(s);
    input.receipts[0].capturedAtMs = capturedAtMs;
    expect(bindHttpArtifactDeployment(s, JSON.stringify(input)).semantic.state).toBe('current');
});

test('deployment receipt limits and UTF-8 byte budget reject excess rather than trim it', () => {
    const s = snapshot(), input = deploymentInput(s);
    input.receipts = Array.from({ length: 8 }, (_, i) => ({ ...input.receipts[0], capturedAtMs: 993 + i }));
    expect(bindHttpArtifactDeployment(s, JSON.stringify(input)).semantic.state).toBe('current');
    input.receipts.push({ ...input.receipts[0], capturedAtMs: 992 });
    expect(() => bindHttpArtifactDeployment(s, JSON.stringify(input))).toThrow('DEPLOYMENT_RECEIPT_LIMIT');
    const body = JSON.stringify(deploymentInput(s)).padEnd(8192);
    expect(bindHttpArtifactDeployment(s, body).semantic.state).toBe('current');
    expect(() => bindHttpArtifactDeployment(s, body + ' ')).toThrow('DEPLOYMENT_INPUT_LIMIT');
    expect(() => bindHttpArtifactDeployment(s, JSON.stringify({ version: 2, scope: 'saved-deployment-fixture', note: '😀'.repeat(2048) }))).toThrow('DEPLOYMENT_INPUT_LIMIT');
});

test.each(['resourceIdSha256', 'deploymentVersionSha256', 'artifactId'] as const)('an explicitly uncollected deployment %s is missing', field => {
    const s = snapshot(), input = deploymentInput(s);
    input.receipts[0][field] = null;
    expect(bindHttpArtifactDeployment(s, JSON.stringify(input)).semantic).toMatchObject({ state: 'missing', reasons: ['DEPLOYMENT_IDENTITY_MISSING'] });
});

test('missing artifact snapshot material cannot be repaired by a matching saved receipt', () => {
    const s = snapshot({ missing: 'runtime-binary' });
    expect(bindHttpArtifactDeployment(s, JSON.stringify(deploymentInput(s))).semantic).toMatchObject({ state: 'missing', reasons: ['ARTIFACT_SNAPSHOT_INCOMPLETE'] });
});

test('a different resource is unknown and a different version or artifact is stale', () => {
    const s = snapshot();
    for (const [field, state, reason] of [
        ['resourceIdSha256', 'unknown', 'DEPLOYMENT_RESOURCE_MISMATCH'],
        ['deploymentVersionSha256', 'stale', 'DEPLOYMENT_VERSION_MISMATCH'],
        ['artifactId', 'stale', 'DEPLOYMENT_ARTIFACT_MISMATCH'],
    ] as const) {
        const input = deploymentInput(s);
        input.receipts[0][field] = sha('different-identity');
        expect(bindHttpArtifactDeployment(s, JSON.stringify(input)).semantic).toMatchObject({ state, reasons: [reason] });
    }
});

test('duplicate, future, invalid shape and trust-boundary inputs are Error', () => {
    const s = snapshot(), input = deploymentInput(s);
    input.receipts.push({ ...input.receipts[0] });
    expect(() => bindHttpArtifactDeployment(s, JSON.stringify(input))).toThrow('DUPLICATE_DEPLOYMENT_RECEIPT');
    input.receipts = [{ ...input.receipts[0], capturedAtMs: 1001 }];
    expect(() => bindHttpArtifactDeployment(s, JSON.stringify(input))).toThrow('INVALID_DEPLOYMENT_TIME');
    expect(() => bindHttpArtifactDeployment(structuredClone(s), JSON.stringify(deploymentInput(s)))).toThrow('UNISSUED_SNAPSHOT');
    expect(() => bindHttpArtifactDeployment(s, '{')).toThrow('INVALID_DEPLOYMENT_JSON');
    expect(() => bindHttpArtifactDeployment(s, 'null')).toThrow('INVALID_DEPLOYMENT_INPUT');
    expect(() => bindHttpArtifactDeployment(s, JSON.stringify({ ...deploymentInput(s), scope: 'live-cloud' }))).toThrow('DEPLOYMENT_SCOPE_UNSUPPORTED');
    expect(() => bindHttpArtifactDeployment(s, JSON.stringify({ ...deploymentInput(s), body: 'PRIVATE_SENTINEL' }))).toThrow('INVALID_DEPLOYMENT_INPUT');
    expect(() => bindHttpArtifactDeployment(s, JSON.stringify({ ...deploymentInput(s), expected: { ...deploymentInput(s).expected, maxAgeMs: 86400001 } }))).toThrow('INVALID_DEPLOYMENT_INPUT');
    expect(() => bindHttpArtifactDeployment(s, JSON.stringify({ ...deploymentInput(s), receipts: [{ ...deploymentInput(s).receipts[0], artifactId: 'PRIVATE_SENTINEL' }] }))).toThrow('INVALID_DEPLOYMENT_IDENTITY');
});

test('unknown deployment envelope version is bounded unknown without decoding a v1 receipt', () => {
    const s = snapshot(), body = JSON.stringify({ version: 2, scope: 'saved-deployment-fixture', future: 'PRIVATE_SENTINEL' });
    const result = bindHttpArtifactDeployment(s, body);
    expect(result.semantic).toMatchObject({ state: 'unknown', reasons: ['DEPLOYMENT_VERSION_UNSUPPORTED'], resourceIdSha256: null, deploymentVersionSha256: null, identities: [] });
    expect(result.metadata.inputSha256).toBe(sha(body));
    expect(JSON.stringify(result)).not.toContain('PRIVATE_SENTINEL');
});

test('deployment semantic identity ignores receipt order and window-internal times while preserving input metadata', () => {
    const a = snapshot(), b = snapshot({ port: 3333, runId: 'different-metadata' }), input = deploymentInput(a);
    input.receipts.push({ ...input.receipts[0], capturedAtMs: 951 });
    const first = bindHttpArtifactDeployment(a, JSON.stringify(input));
    input.receipts.reverse();
    const reordered = bindHttpArtifactDeployment(b, JSON.stringify(input));
    expect(reordered.semanticDigest).toBe(first.semanticDigest);
    expect(reordered.metadata.inputSha256).not.toBe(first.metadata.inputSha256);
    expect(reordered.metadata.snapshotDigest).not.toBe(first.metadata.snapshotDigest);
    input.receipts[0].capturedAtMs = 999;
    const changedTime = bindHttpArtifactDeployment(a, JSON.stringify(input));
    expect(changedTime.semanticDigest).toBe(first.semanticDigest);
    expect(changedTime.metadata.capturedAtMs).not.toEqual(first.metadata.capturedAtMs);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.semantic.identities)).toBe(true);
});

test('a current binding for a weakened artifact does not change the independent security verdict or expose raw material', () => {
    const s = snapshot({ weak: true }), input = deploymentInput(s), before = JSON.stringify(s);
    const binding = bindHttpArtifactDeployment(s, JSON.stringify(input));
    expect(binding.semantic.state).toBe('current');
    expect(verifyHttpArtifact(expected, s, [observation(s, 'admin-missing', true)]).semantic.verdict).toBe('VIOLATED');
    expect(JSON.stringify(s)).toBe(before);
    for (const raw of ['unit-synthetic-valid', 'unit-synthetic-wrong', 'fixture-resource', 'baseline-policy', 'normal-run', '127.0.0.1'])
        expect(JSON.stringify(binding)).not.toContain(raw);
});

test('combined deployment problems retain every reason and missing has priority', () => {
    const s = snapshot(), input = deploymentInput(s);
    input.receipts.push({ ...input.receipts[0], artifactId: null, capturedAtMs: 951 });
    input.receipts.push({ ...input.receipts[0], deploymentVersionSha256: sha('version-2'), artifactId: sha('artifact-2'), capturedAtMs: 899 });
    const result = bindHttpArtifactDeployment(s, JSON.stringify(input));
    expect(result.semantic).toMatchObject({ state: 'missing', reasons: [
        'DEPLOYMENT_IDENTITY_MISSING', 'DEPLOYMENT_MIXED', 'DEPLOYMENT_VERSION_MISMATCH',
        'DEPLOYMENT_ARTIFACT_MISMATCH', 'DEPLOYMENT_RECEIPT_STALE',
    ] });
});

test('zero age is explicit and absent fields do not acquire defaults', () => {
    const s = snapshot(), input = deploymentInput(s);
    input.expected.maxAgeMs = 0;
    input.receipts[0].capturedAtMs = 1000;
    expect(bindHttpArtifactDeployment(s, JSON.stringify(input)).semantic.state).toBe('current');
    input.receipts[0].capturedAtMs = 999;
    expect(bindHttpArtifactDeployment(s, JSON.stringify(input)).semantic.state).toBe('stale');
    const { expected: _expected, ...withoutExpected } = input;
    expect(() => bindHttpArtifactDeployment(s, JSON.stringify(withoutExpected))).toThrow('INVALID_DEPLOYMENT_INPUT');
    const { artifactId: _artifact, ...withoutArtifact } = input.receipts[0];
    expect(() => bindHttpArtifactDeployment(s, JSON.stringify({ ...input, receipts: [withoutArtifact] }))).toThrow('INVALID_DEPLOYMENT_INPUT');
});

test('a freshness reason changes deployment semantic identity even when another cause keeps the state stale', () => {
    const s = snapshot(), input = deploymentInput(s);
    input.receipts[0].deploymentVersionSha256 = sha('different-version');
    const fresh = bindHttpArtifactDeployment(s, JSON.stringify(input));
    input.receipts[0].capturedAtMs = 899;
    const expired = bindHttpArtifactDeployment(s, JSON.stringify(input));
    expect(fresh.semantic).toMatchObject({ state: 'stale', reasons: ['DEPLOYMENT_VERSION_MISMATCH'] });
    expect(expired.semantic).toMatchObject({ state: 'stale', reasons: ['DEPLOYMENT_VERSION_MISMATCH', 'DEPLOYMENT_RECEIPT_STALE'] });
    expect(expired.semanticDigest).not.toBe(fresh.semanticDigest);
});
