import { expect, test } from 'vitest';
import { createHash } from 'node:crypto';
import { createHttpArtifactContract, captureHttpArtifactSnapshot, captureHttpArtifactObservation } from '../../src/contract/verification/artifact-http';
import { compareSavedCloudflareWafSubset, type SavedCloudflareWafFixture } from '../../src/contract/verification/cloudflare-deployment';

const sha = (value: string | Uint8Array) => createHash('sha256').update(value).digest('hex');
const json = (value: unknown) => Buffer.from(JSON.stringify(value));
const methodRule = { ref: 'method', enabled: true, expression: 'not (http.request.method in {"GET" "HEAD"})', action: 'block', action_parameters: { response: null } };
const portRule = { ref: 'port', enabled: true, expression: 'not (cf.edge.server_port in {80 443})', action: 'block', action_parameters: { response: null } };
const resources = () => ({ cloudflare_ruleset: { custom: { kind: 'zone', phase: 'http_request_firewall_custom', rules: [structuredClone(methodRule), structuredClone(portRule)] } } });
const generated = () => json({ resource: resources() });
function context(weak = false, missing?: string) {
    const contract = createHttpArtifactContract('synthetic-policy', [{ id: 'denied', target: '/admin', status: 401, reason: 'Unauthorized', artifact: true }]);
    const policy = weak ? 'synthetic-weakened-policy' : 'synthetic-policy';
    const roles = ['policy', 'generated-ts', 'module', 'lock', 'runtime-binary', 'runtime-config', 'source-module', 'compiler-module'];
    const snapshot = captureHttpArtifactSnapshot(contract, {
        variant: weak ? 'weakened-policy' : 'normal',
        files: roles.filter(role => role !== missing).map(role => {
            const bytes = Buffer.from(role === 'policy' ? policy : 'synthetic-' + role);
            return { role, name: role + '.fixture', bytes, expectedSha256: sha(bytes) };
        }),
        runtime: { version: 'unit-native-fixture', packageVersion: 'unit-runtime-fixture', compatibilityDate: '2026-10-27', compatibilityFlags: [], network: 'deny-all-loopback-origin' },
        metadata: { runId: 'synthetic-run', sourceCommit: 'a'.repeat(40), startedAtMs: 100, finishedAtMs: 200, originPort: 1111, workerPort: 2222 },
        credentials: { valid: 'synthetic-valid-credential', wrong: 'synthetic-wrong-credential' },
    });
    const observation = captureHttpArtifactObservation(snapshot, {
        caseId: 'denied', correlationId: 'synthetic-correlation', recordedAtMs: 150,
        request: { target: '/admin', method: 'GET', body: '', headers: { 'x-e2e-id': 'synthetic-correlation' }, destination: { host: '127.0.0.1', port: 2222 } },
        response: { status: weak ? 200 : 401, body: weak ? 'bypassed' : 'Unauthorized', headers: {} }, origins: [],
        events: [{ event: weak ? 'allow' : 'block', correlation_id: 'synthetic-correlation', uri: '/admin', ...(weak ? {} : { block_reason: 'Unauthorized' }) }],
    });
    const fixture: SavedCloudflareWafFixture = {
        version: 1, scope: 'saved-cloudflare-waf-subset',
        expected: { resourceIdSha256: sha('synthetic-resource'), deploymentVersionSha256: sha('synthetic-version'), referenceTimeMs: 1000, maxAgeMs: 100 },
        snapshots: [{ stage: 'observe', sourceSha256: sha('synthetic-saved-source'), httpStatus: 200, complete: true, missing: [],
            resourceIdSha256: sha('synthetic-resource'), deploymentVersionSha256: sha('synthetic-version'),
            artifactId: snapshot.artifactId, capturedAtMs: 950, policySha256: snapshot.actualPolicySha256,
            wafArtifactSha256: sha(generated()), resources: resources() }],
    };
    const run = (input: unknown = fixture) => compareSavedCloudflareWafSubset(contract, snapshot, [observation], generated(), input === undefined ? undefined : json(input));
    return { contract, snapshot, observation, fixture, run };
}

test('saved matching observe configuration remains separate from the independent HTTP verdict and live deployment', () => {
    const c = context(), result = c.run();
    expect(result.semantic.phases.map((p: any) => [p.stage, p.comparison])).toEqual([['plan', 'UNKNOWN'], ['apply', 'UNKNOWN'], ['observe', 'MATCHED']]);
    expect(result.semantic.http).toMatchObject({ scope: 'local-artifact-fixture', verdict: 'VERIFIED', counterexamples: 0 });
    expect(result.semantic.liveDeployment).toBe('UNKNOWN');
    expect(result.semantic.policyCoverage).toBe('UNKNOWN');
    expect(result.semantic).not.toHaveProperty('verdict');
});
test('supported method exception literal changes are reported as configuration differences', () => {
    const c = context();
    (c.fixture.snapshots[0].resources as any).cloudflare_ruleset.custom.rules[0].expression = 'not (http.request.method in {"GET" "HEAD"} or (http.request.method in {"POST"} and lower(http.request.uri.path) eq "/api/required.php"))';
    expect(c.run().semantic.phases[2]).toMatchObject({ comparison: 'DIFFERENT', differences: [expect.objectContaining({ fields: ['expression'] })] });
});
test('rule absence and rule order differ under an explicitly complete supported snapshot', () => {
    const c = context();
    (c.fixture.snapshots[0].resources as any).cloudflare_ruleset.custom.rules.reverse();
    expect(c.run().semantic.phases[2]).toMatchObject({ comparison: 'DIFFERENT', differences: expect.arrayContaining([expect.objectContaining({ fields: ['order'] })]) });
    c.fixture.snapshots[0].resources = {};
    expect(c.run().semantic.phases[2]).toMatchObject({ comparison: 'DIFFERENT', differences: expect.arrayContaining([expect.objectContaining({ fields: ['missing'] })]) });
});
test('403 and a partial readback retain unknown even with a matching issued receipt', () => {
    const c = context(); c.fixture.snapshots[0].httpStatus = 403; c.fixture.snapshots[0].resources = null; c.fixture.snapshots[0].complete = false; c.fixture.snapshots[0].missing = ['rules'];
    expect(c.run().semantic.phases[2]).toMatchObject({ comparison: 'UNKNOWN', reasons: expect.arrayContaining(['SAVED_HTTP_DENIED', 'SAVED_SNAPSHOT_PARTIAL', 'SAVED_COMPONENT_MISSING']) });
});
test('matching plan or apply records never substitutes an observe record, nor hides an HTTP violation', () => {
    const c = context(true); c.fixture.snapshots[0].stage = 'plan';
    const result = c.run(); expect(result.semantic.phases[0].comparison).toBe('MATCHED'); expect(result.semantic.phases[2].comparison).toBe('UNKNOWN');
    expect(result.semantic.http.verdict).toBe('VIOLATED');
});
test('known artifact incompleteness survives absent and future saved envelopes without exposing their body', () => {
    const c = context(false, 'runtime-binary');
    for (const input of [undefined, json({ version: 2, scope: 'saved-cloudflare-waf-subset', body: 'PRIVATE_SENTINEL' })]) {
        const result = compareSavedCloudflareWafSubset(c.contract, c.snapshot, [c.observation], generated(), input);
        expect(result.semantic.phases[2]).toMatchObject({ comparison: 'UNKNOWN', reasons: expect.arrayContaining(['ARTIFACT_SNAPSHOT_INCOMPLETE', input === undefined ? 'SAVED_INPUT_MISSING' : 'SAVED_VERSION_UNSUPPORTED']) });
        expect(JSON.stringify(result)).not.toContain('PRIVATE_SENTINEL');
    }
});

test('an unrecognized resource scope cannot manufacture evidence that expected rules are absent', () => {
    const c = context(); c.fixture.snapshots[0].resources = { future_resource: {} };
    expect(c.run().semantic.phases[2]).toMatchObject({ comparison: 'UNKNOWN', differences: [] });
});

test('stale and mixed saved identities retain every reason without becoming an observed match', () => {
    const c = context(); c.fixture.snapshots[0].capturedAtMs = 899;
    c.fixture.snapshots.push({ ...structuredClone(c.fixture.snapshots[0]), capturedAtMs: 950,
        deploymentVersionSha256: sha('other-version'), artifactId: sha('other-artifact') });
    expect(c.run().semantic.phases[2]).toMatchObject({ comparison: 'UNKNOWN', reasons: expect.arrayContaining([
        'DEPLOYMENT_MIXED', 'DEPLOYMENT_VERSION_MISMATCH', 'DEPLOYMENT_ARTIFACT_MISMATCH', 'DEPLOYMENT_RECEIPT_STALE',
    ]) });
});
test('conflicting supported configurations for the same declared identity are mixed, never first-record wins', () => {
    const c = context(), other = structuredClone(c.fixture.snapshots[0]);
    other.capturedAtMs = 951; (other.resources as any).cloudflare_ruleset.custom.rules[0].enabled = false;
    c.fixture.snapshots.push(other);
    const result = c.run().semantic.phases[2];
    expect(result).toMatchObject({ comparison: 'UNKNOWN', reasons: ['SAVED_CONFIGURATION_MIXED'] });
    expect(result.configurations).toHaveLength(2);
    expect(result.differences).toContainEqual(expect.objectContaining({ fields: ['enabled'] }));
});
test('missing and mismatched Policy/WAF identities remain independent unknown reasons', () => {
    const c = context(); c.fixture.snapshots[0].policySha256 = null; c.fixture.snapshots[0].wafArtifactSha256 = sha('other-waf');
    expect(c.run().semantic.phases[2]).toMatchObject({ comparison: 'UNKNOWN', reasons: expect.arrayContaining(['SAVED_ARTIFACT_IDENTITY_MISSING', 'SAVED_WAF_ARTIFACT_MISMATCH']) });
    c.fixture.snapshots[0].policySha256 = sha('other-policy');
    expect(c.run().semantic.phases[2].reasons).toContain('SAVED_POLICY_MISMATCH');
});
test('a forbidden/error response does not erase a missing issued artifact or stale receipt', () => {
    const c = context(false, 'runtime-binary'), r = c.fixture.snapshots[0];
    r.httpStatus = 503; r.resources = null; r.complete = false; r.capturedAtMs = 899; r.artifactId = null;
    expect(c.run().semantic.phases[2]).toMatchObject({ comparison: 'UNKNOWN', reasons: expect.arrayContaining([
        'ARTIFACT_SNAPSHOT_INCOMPLETE', 'DEPLOYMENT_IDENTITY_MISSING', 'DEPLOYMENT_RECEIPT_STALE', 'SAVED_READ_FAILED', 'SAVED_SNAPSHOT_PARTIAL', 'SAVED_CONFIG_MISSING',
    ]) });
});
test.each(['plan', 'apply'] as const)('a matching %s configuration does not claim a missing observe phase', stage => {
    const c = context(); c.fixture.snapshots[0].stage = stage;
    const result = c.run();
    expect(result.semantic.phases.find((p: any) => p.stage === stage).comparison).toBe('MATCHED');
    expect(result.semantic.phases[2]).toMatchObject({ comparison: 'UNKNOWN', reasons: expect.arrayContaining(['SAVED_PHASE_MISSING', 'DEPLOYMENT_RECEIPTS_MISSING']) });
});
test('no declared WAF requirements remains unknown instead of vacuously proving configuration or security', () => {
    const c = context(); c.fixture.snapshots[0].resources = {};
    const result = compareSavedCloudflareWafSubset(c.contract, c.snapshot, [c.observation], json({ resource: {} }), json(c.fixture));
    expect(result.semantic.phases[2]).toMatchObject({ comparison: 'UNKNOWN', reasons: expect.arrayContaining(['WAF_EXPECTATION_EMPTY']) });
});
test('unknown actions and fields retain known literal differences without claiming supported effects', () => {
    const c = context(), r = (c.fixture.snapshots[0].resources as any).cloudflare_ruleset.custom.rules[0];
    r.action = 'skip'; r.action_parameters = { phases: ['http_request_firewall_managed'] };
    const result = c.run().semantic.phases[2];
    expect(result.comparison).toBe('UNKNOWN');
    expect(result.reasons).toEqual(expect.arrayContaining(['ACTION_NOT_SUPPORTED', 'ACTION_PARAMETERS_NOT_SUPPORTED']));
    expect(result.differences).toContainEqual(expect.objectContaining({ fields: ['action', 'parameters'] }));
});
test('unsupported regex and extra ruleset controls are unknown rather than silently ignored', () => {
    const c = context(), set = (c.fixture.snapshots[0].resources as any).cloudflare_ruleset.custom;
    set.rules[0].expression = '(http.request.uri.path matches "^/admin")';
    expect(c.run().semantic.phases[2]).toMatchObject({ comparison: 'UNKNOWN', reasons: expect.arrayContaining(['REGEX_NOT_FREE']) });
    set.future_control = true;
    expect(c.run().semantic.phases[2]).toMatchObject({ comparison: 'UNKNOWN', reasons: expect.arrayContaining(['WAF_CUSTOM_SCOPE_UNSUPPORTED']), differences: [] });
});
test('source refs, exact bytes and capture metadata are preserved outside the semantic digest', () => {
    const c = context(); c.fixture.snapshots.push({ ...structuredClone(c.fixture.snapshots[0]), capturedAtMs: 951, sourceSha256: sha('second-saved-source') });
    const first = c.run(), original = json(c.fixture);
    c.fixture.snapshots.reverse(); c.fixture.snapshots[0].capturedAtMs = 999;
    const retimed = c.run();
    expect(retimed.semanticDigest).toBe(first.semanticDigest);
    expect(first.metadata.inputSha256).toBe(sha(original));
    expect(retimed.metadata.inputSha256).not.toBe(first.metadata.inputSha256);
    expect(first.metadata.phases[2].sources).toEqual(expect.arrayContaining([expect.objectContaining({ sourceSha256: sha('synthetic-saved-source'), capturedAtMs: 950 })]));
    for (const value of [first, first.semantic, first.semantic.phases, first.semantic.phases[2], first.metadata.phases[2].sources]) expect(Object.isFrozen(value)).toBe(true);
});
test('freshness crossing changes the semantic digest even while another cause already keeps the phase unknown', () => {
    const c = context(); c.fixture.snapshots[0].policySha256 = sha('other-policy');
    const fresh = c.run(); c.fixture.snapshots[0].capturedAtMs = 899;
    const stale = c.run();
    expect(fresh.semantic.phases[2].comparison).toBe('UNKNOWN');
    expect(stale.semantic.phases[2].comparison).toBe('UNKNOWN');
    expect(stale.semantic.phases[2].reasons).toContain('DEPLOYMENT_RECEIPT_STALE');
    expect(stale.semanticDigest).not.toBe(fresh.semanticDigest);
});
test('result minimization does not echo opaque resource data, rule refs, expressions, parameters or generated variables', () => {
    const c = context(), set = (c.fixture.snapshots[0].resources as any).cloudflare_ruleset.custom;
    set.description = 'PRIVATE_SENTINEL'; set.rules[0].ref = 'PRIVATE_SENTINEL';
    set.rules[0].expression = '(lower(http.user_agent) contains "PRIVATE_SENTINEL")';
    set.rules[0].action_parameters = { response: { content: 'PRIVATE_SENTINEL' } };
    const artifact = json({ variable: { private: { default: 'PRIVATE_SENTINEL' } }, resource: resources() });
    const result = compareSavedCloudflareWafSubset(c.contract, c.snapshot, [c.observation], artifact, json(c.fixture));
    for (const raw of ['PRIVATE_SENTINEL', 'synthetic-valid-credential', 'synthetic-wrong-credential', '127.0.0.1', '/admin']) expect(JSON.stringify(result)).not.toContain(raw);
});

const invalid: Array<[string, (input: SavedCloudflareWafFixture) => void, string]> = [
    ['extra raw field', p => { (p as any).cookie = 'PRIVATE_SENTINEL'; }, 'SAVED_WAF_FIELDS_INVALID'],
    ['scope', p => { (p as any).scope = 'live-cloud'; }, 'SAVED_WAF_SCOPE_OR_VERSION_INVALID'],
    ['version zero', p => { (p as any).version = 0; }, 'SAVED_WAF_SCOPE_OR_VERSION_INVALID'],
    ['unknown stage', p => { (p.snapshots[0] as any).stage = 'deployed'; }, 'SAVED_WAF_SNAPSHOT_INVALID'],
    ['raw source ref', p => { p.snapshots[0].sourceSha256 = 'PRIVATE_SENTINEL'; }, 'SAVED_WAF_SNAPSHOT_INVALID'],
    ['status string', p => { (p.snapshots[0] as any).httpStatus = '200'; }, 'SAVED_WAF_SNAPSHOT_INVALID'],
    ['complete truthy', p => { (p.snapshots[0] as any).complete = 1; }, 'SAVED_WAF_SNAPSHOT_INVALID'],
    ['unknown missing field', p => { (p.snapshots[0] as any).missing = ['PRIVATE_SENTINEL']; }, 'SAVED_WAF_SNAPSHOT_INVALID'],
    ['duplicate missing field', p => { p.snapshots[0].missing = ['rules', 'rules']; }, 'SAVED_WAF_SNAPSHOT_INVALID'],
    ['failed status with config', p => { p.snapshots[0].httpStatus = 403; }, 'SAVED_WAF_FAILED_RESPONSE_HAS_CONFIG'],
    ['future capture', p => { p.snapshots[0].capturedAtMs = 1001; }, 'INVALID_DEPLOYMENT_TIME'],
    ['excess window', p => { p.expected.maxAgeMs = 86400001; }, 'INVALID_DEPLOYMENT_INPUT'],
    ['duplicate receipt', p => { p.snapshots.push(structuredClone(p.snapshots[0])); }, 'DUPLICATE_DEPLOYMENT_RECEIPT'],
    ['duplicate rule ref', p => { const rules = (p.snapshots[0].resources as any).cloudflare_ruleset.custom.rules; rules[1].ref = rules[0].ref; }, 'SAVED_WAF_RULE_REF_DUPLICATE'],
    ['too many rules', p => { (p.snapshots[0].resources as any).cloudflare_ruleset.custom.rules = Array.from({ length: 6 }, (_, i) => ({ ...methodRule, ref: 'm' + i })); }, 'SAVED_WAF_RULE_LIMIT'],
    ['too many snapshots', p => { p.snapshots = Array.from({ length: 9 }, (_, i) => ({ ...p.snapshots[0], capturedAtMs: 990 + i })); }, 'SAVED_WAF_SNAPSHOT_LIMIT'],
];
test.each(invalid)('invalid %s is fixed Error with no raw input', (_name, alter, code) => {
    const c = context(); alter(c.fixture);
    expect(() => c.run()).toThrow(code);
    try { c.run(); } catch (error) { expect(String(error)).not.toContain('PRIVATE_SENTINEL'); }
});
test('invalid bytes/JSON and byte limits reject without provider access or trimming', () => {
    const c = context();
    for (const [bytes, code] of [[Buffer.from([255]), 'SAVED_WAF_UTF8_INVALID'], [Buffer.from('{'), 'SAVED_WAF_JSON_INVALID'], [Buffer.alloc(65537, 32), 'SAVED_WAF_BYTES_LIMIT']] as const)
        expect(() => compareSavedCloudflareWafSubset(c.contract, c.snapshot, [c.observation], generated(), bytes)).toThrow(code);
    const future = json({ version: 2, scope: 'saved-cloudflare-waf-subset', future: '😀'.repeat(16384) });
    expect(() => compareSavedCloudflareWafSubset(c.contract, c.snapshot, [], generated(), future)).toThrow('SAVED_WAF_BYTES_LIMIT');
});
test('unissued contracts, snapshots and observations cannot be supplied as saved evidence', () => {
    const c = context();
    expect(() => compareSavedCloudflareWafSubset(structuredClone(c.contract), c.snapshot, [c.observation], generated(), json(c.fixture))).toThrow('UNISSUED_CONTRACT');
    expect(() => compareSavedCloudflareWafSubset(c.contract, structuredClone(c.snapshot), [c.observation], generated(), json(c.fixture))).toThrow('UNISSUED_SNAPSHOT');
    expect(() => compareSavedCloudflareWafSubset(c.contract, c.snapshot, [structuredClone(c.observation)], generated(), json(c.fixture))).toThrow('UNISSUED_OBSERVATION');
});
test('missing HTTP observations remain unknown while config matching remains a separate saved-fixture fact', () => {
    const c = context(), result = compareSavedCloudflareWafSubset(c.contract, c.snapshot, [], generated(), json(c.fixture));
    expect(result.semantic.phases[2].comparison).toBe('MATCHED');
    expect(result.semantic.http).toMatchObject({ verdict: 'UNKNOWN', unknownReasons: ['OBSERVATION_MISSING'] });
});
test('a malformed declared generated-artifact variable envelope is Error, even if its rule subset matches', () => {
    const c = context();
    expect(() => compareSavedCloudflareWafSubset(c.contract, c.snapshot, [c.observation], json({ variable: 7, resource: resources() }), json(c.fixture))).toThrow('SAVED_WAF_ARTIFACT_INVALID');
});

test.each([
    ['extra field plus excess rules', 'SAVED_WAF_RULE_LIMIT', (r: any) => { r.cloudflare_ruleset.custom.future_field = true; r.cloudflare_ruleset.custom.rules = Array.from({ length: 6 }, (_, i) => ({ ...methodRule, ref: 'm' + i })); }],
    ['extra field plus duplicate ref', 'SAVED_WAF_RULE_REF_DUPLICATE', (r: any) => { r.cloudflare_ruleset.custom.future_field = true; r.cloudflare_ruleset.custom.rules[1].ref = r.cloudflare_ruleset.custom.rules[0].ref; }],
    ['extra field plus malformed flag', 'SAVED_WAF_RULE_INVALID', (r: any) => { r.cloudflare_ruleset.custom.future_field = true; r.cloudflare_ruleset.custom.rules[0].enabled = 'true'; }],
    ['additional resource plus excess rules', 'SAVED_WAF_RULE_LIMIT', (r: any) => { r.future_resource = {}; r.cloudflare_ruleset.custom.rules = Array.from({ length: 6 }, (_, i) => ({ ...methodRule, ref: 'm' + i })); }],
    ['two custom rulesets', 'SAVED_WAF_RULESET_LIMIT', (r: any) => { r.cloudflare_ruleset.other = structuredClone(r.cloudflare_ruleset.custom); }],
    ['unsupported kind plus malformed flag', 'SAVED_WAF_RULE_INVALID', (r: any) => { r.cloudflare_ruleset.custom.kind = 'account'; r.cloudflare_ruleset.custom.rules[0].enabled = null; }],
] as Array<[string, string, (r: any) => void]>)('known custom constraints remain Error with %s', (_name, code, alter) => {
    const c = context(); alter(c.fixture.snapshots[0].resources);
    expect(() => c.run()).toThrow(code);
});
test('an unrecognized generated scope does not acquire an empty-expectation diagnosis', () => {
    const c = context();
    const result = compareSavedCloudflareWafSubset(c.contract, c.snapshot, [c.observation], json({ resource: { future_resource: {} } }), json(c.fixture));
    expect(result.semantic.phases[2].comparison).toBe('UNKNOWN');
    expect(result.semantic.phases[2].reasons).not.toContain('WAF_EXPECTATION_EMPTY');
});
