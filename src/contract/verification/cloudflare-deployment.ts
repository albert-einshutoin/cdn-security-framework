// Internal saved-fixture comparison; no provider acquisition or public verifier API.
import {
    HttpArtifactError, httpArtifactDigest, bindHttpArtifactDeployment, verifyHttpArtifact,
    type HttpArtifactContract, type HttpArtifactSnapshot, type HttpArtifactObservation,
    type HttpDeploymentFixtureInput,
} from './artifact-http';
import { createHash } from 'node:crypto';
import { assessCloudflareFreeWaf } from '../../scripts/lib/cloudflare-rate-limit';

export type CloudflareDeploymentStage = 'plan' | 'apply' | 'observe';
export type CloudflareDeploymentMissing = 'identity' | 'rules' | 'rule-order' | 'exceptions';
export type SavedCloudflareWafRecord = HttpDeploymentFixtureInput['receipts'][number] & {
    stage: CloudflareDeploymentStage;
    sourceSha256: string;
    httpStatus: number | null;
    complete: boolean;
    missing: CloudflareDeploymentMissing[];
    policySha256: string | null;
    wafArtifactSha256: string | null;
    resources: unknown | null;
};
export interface SavedCloudflareWafFixture {
    version: 1;
    scope: 'saved-cloudflare-waf-subset';
    expected: HttpDeploymentFixtureInput['expected'];
    snapshots: SavedCloudflareWafRecord[];
}

type Binding = ReturnType<typeof bindHttpArtifactDeployment>;
type Comparison = 'MATCHED' | 'DIFFERENT' | 'UNKNOWN';
interface RuleProjection {
    refSha256: string;
    expressionSha256: string;
    actionSha256: string;
    parametersSha256: string | null;
    enabled: boolean;
}
interface Projection { rows: RuleProjection[]; knownScope: boolean; reasons: string[]; digest: string }
interface Difference {
    refSha256: string;
    expectedIndex: number | null;
    actualIndex: number | null;
    fields: Array<'missing' | 'unexpected' | 'order' | 'enabled' | 'action' | 'expression' | 'parameters'>;
    configurationSha256: string;
}
interface Phase {
    stage: CloudflareDeploymentStage;
    comparison: Comparison;
    binding: Binding['semantic'] | null;
    reasons: string[];
    configurations: string[];
    differences: Difference[];
}
const stages: CloudflareDeploymentStage[] = ['plan', 'apply', 'observe'];
const missingFields: CloudflareDeploymentMissing[] = ['identity', 'rules', 'rule-order', 'exceptions'];
const hex = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const object = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === 'object' && !Array.isArray(value);
const hash = (value: Uint8Array) => createHash('sha256').update(value).digest('hex');
const unique = (values: string[]) => [...new Set(values)].sort();
function must(value: unknown, code: string): asserts value { if (!value) throw new HttpArtifactError(code); }
function record(value: unknown, keys: string[]): Record<string, unknown> {
    must(object(value) && Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k)), 'SAVED_WAF_FIELDS_INVALID');
    return value;
}
function decode(value: Uint8Array): { data: unknown; sha256: string } {
    must(value instanceof Uint8Array && value.byteLength <= 65536, 'SAVED_WAF_BYTES_LIMIT');
    const bytes = Buffer.from(value);
    let text: string;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
    catch { throw new HttpArtifactError('SAVED_WAF_UTF8_INVALID'); }
    let data: unknown;
    try { data = JSON.parse(text); }
    catch { throw new HttpArtifactError('SAVED_WAF_JSON_INVALID'); }
    return { data, sha256: hash(bytes) };
}
function freeze<T>(value: T): T {
    if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
    return value;
}
function projectRules(rules: unknown): RuleProjection[] {
    must(Array.isArray(rules) && rules.length <= 5, 'SAVED_WAF_RULE_LIMIT');
    const refs = new Set<string>();
    return rules.map(rule => {
        must(object(rule) && typeof rule.ref === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(rule.ref)
            && typeof rule.enabled === 'boolean' && typeof rule.expression === 'string' && Buffer.byteLength(rule.expression) <= 4096
            && typeof rule.action === 'string' && /^[a-z_]{1,32}$/.test(rule.action), 'SAVED_WAF_RULE_INVALID');
        must(!refs.has(rule.ref), 'SAVED_WAF_RULE_REF_DUPLICATE'); refs.add(rule.ref);
        const parameters = rule.action_parameters;
        const supportedParameters = object(parameters) && Object.keys(parameters).join() === 'response' && parameters.response === null;
        return { refSha256: httpArtifactDigest(rule.ref), expressionSha256: httpArtifactDigest(rule.expression),
            actionSha256: httpArtifactDigest(rule.action), enabled: rule.enabled,
            parametersSha256: supportedParameters ? httpArtifactDigest({ response: null }) : null };
    });
}
function project(resources: unknown): Projection {
    must(object(resources), 'SAVED_WAF_RESOURCES_INVALID');
    const sets = resources.cloudflare_ruleset;
    const values = object(sets) ? Object.values(sets) : [];
    // Unsupported controls must not bypass constraints on recognizable custom rules.
    const custom = values.filter((s): s is Record<string, unknown> => object(s) && s.phase === 'http_request_firewall_custom');
    must(custom.length <= 1, 'SAVED_WAF_RULESET_LIMIT');
    const customRows = custom.map(s => projectRules(s.rules));
    const assessment = assessCloudflareFreeWaf(resources, undefined, 0);
    const reasons = assessment.localGeneration === 'supported' ? [] : ['WAF_SUBSET_UNSUPPORTED', ...assessment.reasons];
    const supportedScope = Object.keys(resources).every(k => k === 'cloudflare_ruleset') && values.length <= 1
        && values.every(s => object(s) && s.kind === 'zone' && s.phase === 'http_request_firewall_custom'
            && Object.keys(s).every(k => ['zone_id', 'name', 'description', 'kind', 'phase', 'rules'].includes(k)));
    if (!supportedScope) reasons.push('WAF_CUSTOM_SCOPE_UNSUPPORTED');
    const rows = supportedScope && custom.length ? customRows[0] : [];
    const data = { rows, knownScope: supportedScope, reasons: unique(reasons) };
    return { ...data, digest: httpArtifactDigest(data) };
}
function differences(expected: Projection, actual: Projection): Difference[] {
    if (!expected.knownScope || !actual.knownScope) return [];
    const out: Difference[] = [];
    const refs = unique([...expected.rows, ...actual.rows].map(r => r.refSha256));
    for (const refSha256 of refs) {
        const e = expected.rows.findIndex(r => r.refSha256 === refSha256), a = actual.rows.findIndex(r => r.refSha256 === refSha256);
        const fields: Difference['fields'] = e < 0 ? ['unexpected'] : a < 0 ? ['missing'] : [];
        if (e >= 0 && a >= 0) {
            if (e !== a) fields.push('order');
            for (const [key, field] of [['enabled', 'enabled'], ['actionSha256', 'action'], ['expressionSha256', 'expression'], ['parametersSha256', 'parameters']] as const)
                if (expected.rows[e][key] !== actual.rows[a][key]) fields.push(field);
        }
        if (fields.length) out.push({ refSha256, expectedIndex: e < 0 ? null : e, actualIndex: a < 0 ? null : a, fields, configurationSha256: actual.digest });
    }
    return out;
}

export function compareSavedCloudflareWafSubset(
    contract: HttpArtifactContract,
    snapshot: HttpArtifactSnapshot,
    observations: readonly HttpArtifactObservation[],
    generatedWafBytes: Uint8Array,
    savedInput: Uint8Array | undefined,
) {
    const http = verifyHttpArtifact(contract, snapshot, observations);
    const generated = decode(generatedWafBytes);
    must(object(generated.data) && (generated.data.variable === undefined || object(generated.data.variable)), 'SAVED_WAF_ARTIFACT_INVALID');
    const expectedProjection = project(generated.data.resource);
    if (Object.keys(generated.data).some(k => !['variable', 'resource'].includes(k))) expectedProjection.reasons.push('WAF_ARTIFACT_FIELD_UNSUPPORTED');
    if (expectedProjection.knownScope && !expectedProjection.rows.length) expectedProjection.reasons.push('WAF_EXPECTATION_EMPTY');
    const contextReasons = snapshot.missing.length ? ['ARTIFACT_SNAPSHOT_INCOMPLETE'] : [];
    const planReasons = unique([...contextReasons, ...expectedProjection.reasons]);
    const httpSummary = { scope: http.semantic.scope, verdict: http.semantic.verdict, semanticDigest: http.semanticDigest,
        counterexamples: http.semantic.counterexamples.length, unknownReasons: unique(http.semantic.unknown.map(v => v.reason)) };
    let inputSha256: string | null = null;
    const metadata: Array<{ stage: CloudflareDeploymentStage; binding: Binding['metadata'] | null; sources: Array<{ sourceSha256: string; capturedAtMs: number; httpStatus: number | null }> }> = [];
    const finish = (phases: Phase[]) => {
        const semantic = { version: 1 as const, scope: 'saved-cloudflare-waf-subset' as const, artifactId: snapshot.artifactId,
            contractDigest: snapshot.contractDigest, policySha256: snapshot.actualPolicySha256, expectedPolicySha256: contract.policySha256,
            wafArtifactSha256: generated.sha256, phases, http: httpSummary, policyCoverage: 'UNKNOWN' as const, liveDeployment: 'UNKNOWN' as const };
        return freeze({ semantic, semanticDigest: 'sha256:' + httpArtifactDigest(semantic), metadata: { inputSha256, snapshotDigest: snapshot.digest, phases: metadata } });
    };
    const unknown = (reason: string) => finish(stages.map(stage => ({ stage, comparison: 'UNKNOWN', binding: null,
        reasons: unique([...planReasons, reason]), configurations: [], differences: [] })));
    if (savedInput === undefined) return unknown('SAVED_INPUT_MISSING');
    const saved = decode(savedInput); inputSha256 = saved.sha256;
    must(object(saved.data) && saved.data.scope === 'saved-cloudflare-waf-subset'
        && Number.isSafeInteger(saved.data.version) && (saved.data.version as number) >= 1, 'SAVED_WAF_SCOPE_OR_VERSION_INVALID');
    if (saved.data.version !== 1) return unknown('SAVED_VERSION_UNSUPPORTED');
    const envelope = record(saved.data, ['version', 'scope', 'expected', 'snapshots']);
    must(Array.isArray(envelope.snapshots) && envelope.snapshots.length <= 8, 'SAVED_WAF_SNAPSHOT_LIMIT');
    const inputs = envelope.snapshots.map(value => {
        const r = record(value, ['resourceIdSha256', 'deploymentVersionSha256', 'artifactId', 'capturedAtMs',
            'stage', 'sourceSha256', 'httpStatus', 'complete', 'missing', 'policySha256', 'wafArtifactSha256', 'resources']);
        must(stages.includes(r.stage as CloudflareDeploymentStage) && hex(r.sourceSha256)
            && (r.httpStatus === null || (Number.isInteger(r.httpStatus) && (r.httpStatus as number) >= 100 && (r.httpStatus as number) <= 599))
            && typeof r.complete === 'boolean' && Array.isArray(r.missing) && r.missing.length <= 4
            && new Set(r.missing).size === r.missing.length && r.missing.every(v => missingFields.includes(v))
            && [r.policySha256, r.wafArtifactSha256].every(v => v === null || hex(v)), 'SAVED_WAF_SNAPSHOT_INVALID');
        must(r.httpStatus === 200 || r.resources === null, 'SAVED_WAF_FAILED_RESPONSE_HAS_CONFIG');
        return r as unknown as SavedCloudflareWafRecord;
    });
    const phases = stages.map((stage): Phase => {
        const records = inputs.filter(r => r.stage === stage);
        const receipts = records.map(({ resourceIdSha256, deploymentVersionSha256, artifactId, capturedAtMs }) => ({ resourceIdSha256, deploymentVersionSha256, artifactId, capturedAtMs }));
        const binding = bindHttpArtifactDeployment(snapshot, JSON.stringify({ version: 1, scope: 'saved-deployment-fixture', expected: envelope.expected, receipts }));
        const reasons = [...planReasons, ...binding.semantic.reasons];
        if (!records.length) reasons.push('SAVED_PHASE_MISSING');
        const actual: Projection[] = [];
        for (const r of records) {
            if (r.httpStatus !== 200) reasons.push(r.httpStatus === 403 ? 'SAVED_HTTP_DENIED' : 'SAVED_READ_FAILED');
            if (!r.complete) reasons.push('SAVED_SNAPSHOT_PARTIAL');
            if (r.missing.length) reasons.push('SAVED_COMPONENT_MISSING', ...r.missing.map(v => 'SAVED_MISSING_' + v.replace('-', '_').toUpperCase()));
            if (r.policySha256 === null || r.wafArtifactSha256 === null) reasons.push('SAVED_ARTIFACT_IDENTITY_MISSING');
            if (r.policySha256 !== null && r.policySha256 !== snapshot.actualPolicySha256) reasons.push('SAVED_POLICY_MISMATCH');
            if (r.wafArtifactSha256 !== null && r.wafArtifactSha256 !== generated.sha256) reasons.push('SAVED_WAF_ARTIFACT_MISMATCH');
            if (r.resources === null) reasons.push('SAVED_CONFIG_MISSING');
            else { const p = project(r.resources); actual.push(p); reasons.push(...p.reasons); }
        }
        const configurations = unique(actual.map(p => p.digest));
        if (configurations.length > 1) reasons.push('SAVED_CONFIGURATION_MIXED');
        const diffs = new Map(actual.flatMap(p => differences(expectedProjection, p)).map(d => [httpArtifactDigest(d), d]));
        const changes = [...diffs.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, d]) => d);
        metadata.push({ stage, binding: binding.metadata, sources: records.map(r => ({ sourceSha256: r.sourceSha256, capturedAtMs: r.capturedAtMs, httpStatus: r.httpStatus }))
            .sort((a, b) => a.sourceSha256 < b.sourceSha256 ? -1 : a.sourceSha256 > b.sourceSha256 ? 1 : a.capturedAtMs - b.capturedAtMs) });
        return { stage, comparison: reasons.length ? 'UNKNOWN' : changes.length ? 'DIFFERENT' : 'MATCHED', binding: binding.semantic,
            reasons: unique(reasons), configurations, differences: changes };
    });
    return finish(phases);
}
