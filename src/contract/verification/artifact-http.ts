import { createHash } from 'node:crypto';
import { createFinding } from '../finding';
export interface HttpArtifactCase {
    id: string;
    target: string;
    method?: string;
    headers?: Record<string, string | undefined>;
    body?: string;
    credential?: 'absent' | 'wrong' | 'valid';
    status: number;
    forwarded?: string;
    reason?: string;
    protectedResponse?: boolean;
    publicResponse?: boolean;
    artifact?: boolean;
    workerUri?: string;
}
export class HttpArtifactError extends Error {
    constructor(readonly code: string) { super(code); this.name = 'HttpArtifactError'; }
}
function must(value: unknown, code: string): asserts value { if (!value)
    throw new HttpArtifactError(code); }
function canonical(value: unknown): string {
    if (Array.isArray(value))
        return '[' + value.map(canonical).join(',') + ']';
    if (value && typeof value === 'object')
        return '{' + Object.entries(value).filter(([, v]) => v !== undefined).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([k, v]) => JSON.stringify(k) + ':' + canonical(v)).join(',') + '}';
    return JSON.stringify(value);
}
export const httpArtifactDigest = (value: unknown) => createHash('sha256').update(canonical(value)).digest('hex');
const bytesDigest = (value: Uint8Array) => createHash('sha256').update(value).digest('hex');
function freeze<T>(value: T): T { if (value && typeof value === 'object') {
    for (const v of Object.values(value))
        freeze(v);
    Object.freeze(value);
} return value; }
const hex = (s: unknown): s is string => typeof s === 'string' && /^[a-f0-9]{64}$/.test(s);
const text = (s: unknown, max = 65536): s is string => typeof s === 'string' && s.length <= max;
const contracts = new WeakSet<object>(), snapshots = new WeakSet<object>(), observations = new WeakSet<object>();
export interface HttpArtifactContract {
    version: 1;
    scope: 'local-artifact-fixture';
    policySha256: string;
    cases: HttpArtifactCase[];
    digest: string;
}
export function createHttpArtifactContract(policy: string, cases: readonly HttpArtifactCase[]): HttpArtifactContract {
    must(text(policy, 1048576) && cases.length > 0 && cases.length <= 128, 'INVALID_EXPECTED_CONTRACT');
    const ids = new Set<string>();
    for (const c of cases) {
        must(c && text(c.id, 128) && /^[a-z0-9-]+$/.test(c.id) && !ids.has(c.id), 'INVALID_EXPECTED_CASE');
        ids.add(c.id);
        must(text(c.target, 4096) && c.target.startsWith('/') && Number.isInteger(c.status) && c.status >= 100 && c.status <= 599, 'INVALID_EXPECTED_CASE');
        must(!(c.protectedResponse && c.publicResponse), 'CONTRADICTORY_EXPECTATION');
    }
    const data = {
        version: 1 as const, scope: 'local-artifact-fixture' as const, policySha256: bytesDigest(Buffer.from(policy)), cases: structuredClone([...cases])
    };
    const result = freeze({ ...data, digest: httpArtifactDigest(data) });
    contracts.add(result);
    return result;
}
interface RuntimeIdentity {
    version?: string;
    packageVersion?: string;
    compatibilityDate?: string;
    compatibilityFlags?: string[];
    network?: string;
}
interface RunMetadata {
    runId: string;
    sourceCommit: string;
    startedAtMs: number;
    finishedAtMs: number;
    originPort: number;
    workerPort: number;
    [key: string]: unknown;
}
export interface HttpArtifactMaterial {
    variant: 'normal' | 'weakened-policy';
    files: Array<{
        role: string;
        name: string;
        bytes: Uint8Array;
        expectedSha256: string;
    }>;
    runtime: RuntimeIdentity;
    metadata: RunMetadata;
    credentials: {
        valid: string;
        wrong: string;
    };
}
interface FileIdentity {
    role: string;
    name: string;
    sha256: string;
    bytes: number;
}
export interface HttpArtifactSnapshot {
    version: 1;
    scope: 'local-artifact-fixture';
    variant: HttpArtifactMaterial['variant'];
    contractDigest: string;
    expectedPolicySha256: string;
    actualPolicySha256: string | null;
    artifactId: string;
    files: FileIdentity[];
    runtime: RuntimeIdentity;
    metadata: RunMetadata;
    missing: string[];
    artifacts: {
        policy: string | null;
        generatedTs: string | null;
        module: string | null;
    };
    digest: string;
}
const contexts = new WeakMap<HttpArtifactSnapshot, {
    contract: HttpArtifactContract;
    credentials: HttpArtifactMaterial['credentials'];
}>();
export function captureHttpArtifactSnapshot(contract: HttpArtifactContract, material: HttpArtifactMaterial): HttpArtifactSnapshot {
    must(contracts.has(contract), 'UNISSUED_CONTRACT');
    must(material && ['normal', 'weakened-policy'].includes(material.variant) && Array.isArray(material.files) && material.files.length <= 256, 'INVALID_MATERIAL');
    const m = material.metadata;
    must(m && text(m.runId, 128) && /^[a-f0-9]{40}$/.test(m.sourceCommit) && [m.startedAtMs, m.finishedAtMs].every(v => Number.isSafeInteger(v) && v >= 0) && m.finishedAtMs >= m.startedAtMs, 'INVALID_RUN_METADATA');
    must([m.originPort, m.workerPort].every(p => Number.isInteger(p) && p > 0 && p < 65536), 'INVALID_NETWORK_METADATA');
    must(material.credentials && text(material.credentials.valid, 4096) && material.credentials.valid.length > 0 && text(material.credentials.wrong, 4096) && material.credentials.wrong.length > 0 && material.credentials.valid !== material.credentials.wrong, 'INVALID_CREDENTIAL_ABSTRACTION');
    const unique = new Set<string>(), files: FileIdentity[] = [];
    const content = new Map<string, string>();
    const roles = ['policy', 'generated-ts', 'module', 'lock', 'runtime-binary', 'runtime-config', 'source-module', 'compiler-module'];
    for (const f of material.files) {
        must(f && roles.includes(f.role) && text(f.name, 512) && !f.name.startsWith('/') && !f.name.split('/').includes('..') && !/[\\\x00-\x1f]/.test(f.name) && f.bytes instanceof Uint8Array && f.bytes.byteLength <= (f.role === 'runtime-binary' ? 256 : 4) * 1024 * 1024 && hex(f.expectedSha256), 'INVALID_MATERIAL_FILE');
        const key = f.role + ':' + f.name;
        must(!unique.has(key), 'DUPLICATE_MATERIAL');
        unique.add(key);
        must(bytesDigest(f.bytes) === f.expectedSha256, 'ARTIFACT_BYTES_MISMATCH');
        if (!['source-module', 'compiler-module'].includes(f.role))
            must(!files.some(v => v.role === f.role), 'DUPLICATE_MATERIAL');
        files.push({ role: f.role, name: f.name, sha256: f.expectedSha256, bytes: f.bytes.byteLength });
        if (['policy', 'generated-ts', 'module'].includes(f.role)) {
            const value = Buffer.from(f.bytes).toString('utf8');
            must(!value.includes(material.credentials.valid) && !value.includes(material.credentials.wrong), 'CREDENTIAL_IN_ARTIFACT');
            content.set(f.role, value);
        }
    }
    files.sort((a, b) => (a.role + ':' + a.name).localeCompare(b.role + ':' + b.name, 'en'));
    const role = (name: string) => files.find(f => f.role === name)?.sha256 ?? null;
    if (role('policy'))
        must(material.variant === 'normal' ? role('policy') === contract.policySha256 : role('policy') !== contract.policySha256, 'POLICY_PROVENANCE_CONTRADICTION');
    const missing = roles.filter(r => !files.some(f => f.role === r));
    const runtime = structuredClone(material.runtime);
    must(runtime && typeof runtime === 'object', 'INVALID_RUNTIME_IDENTITY');
    for (const k of ['version', 'packageVersion', 'compatibilityDate', 'network'] as const)
        if (runtime[k] !== undefined)
            must(text(runtime[k], 256), 'INVALID_RUNTIME_IDENTITY');
    if (runtime.compatibilityFlags !== undefined)
        must(Array.isArray(runtime.compatibilityFlags) && runtime.compatibilityFlags.length <= 32 && runtime.compatibilityFlags.every(f => text(f, 128)), 'INVALID_RUNTIME_IDENTITY');
    if (!runtime.version || !runtime.packageVersion || !runtime.compatibilityDate || runtime.compatibilityFlags === undefined)
        missing.push('runtime-identity');
    if (runtime.network !== 'deny-all-loopback-origin')
        missing.push('supported-network');
    const artifactId = httpArtifactDigest({ expectedPolicy: contract.policySha256, actualPolicy: role('policy'), generatedTs: role('generated-ts'), module: role('module'), lock: role('lock'), runtimeBinary: role('runtime-binary'), runtime });
    const data = {
        version: 1 as const, scope: 'local-artifact-fixture' as const, variant: material.variant, contractDigest: contract.digest, expectedPolicySha256: contract.policySha256, actualPolicySha256: role('policy'), artifactId, files, runtime, metadata: structuredClone(m), missing, artifacts: { policy: content.get('policy') ?? null, generatedTs: content.get('generated-ts') ?? null, module: content.get('module') ?? null }
    };
    const snapshot = freeze({ ...data, digest: httpArtifactDigest(data) });
    snapshots.add(snapshot);
    contexts.set(snapshot, { contract, credentials: { ...material.credentials } });
    return snapshot;
}
export interface HttpDeploymentFixtureInput {
    version: 1;
    scope: 'saved-deployment-fixture';
    expected: {
        resourceIdSha256: string;
        deploymentVersionSha256: string;
        referenceTimeMs: number;
        maxAgeMs: number;
    };
    receipts: Array<{
        resourceIdSha256: string | null;
        deploymentVersionSha256: string | null;
        artifactId: string | null;
        capturedAtMs: number;
    }>;
}
type DeploymentState = 'current' | 'stale' | 'missing' | 'mixed' | 'unknown';
function deploymentRecord(value: unknown, fields: string[]): Record<string, unknown> {
    must(value && typeof value === 'object' && !Array.isArray(value), 'INVALID_DEPLOYMENT_INPUT');
    const keys = Object.keys(value);
    must(keys.length === fields.length && keys.every(key => fields.includes(key)), 'INVALID_DEPLOYMENT_INPUT');
    return value as Record<string, unknown>;
}
/** Saved fixture provenance only; matching identities never establish runtime enforcement. */
export function bindHttpArtifactDeployment(snapshot: HttpArtifactSnapshot, input: string | undefined) {
    must(snapshots.has(snapshot), 'UNISSUED_SNAPSHOT');
    let expected: HttpDeploymentFixtureInput['expected'] | null = null;
    let receipts: HttpDeploymentFixtureInput['receipts'] = [];
    // Capture times remain provenance; identities and every derived reason determine semantics.
    const finish = (state: DeploymentState, reasons: string[]) => {
        const identities = new Map(receipts.map(({ capturedAtMs: _time, ...identity }) => [canonical(identity), identity]));
        const semantic = {
            version: 1 as const, scope: 'saved-deployment-fixture' as const,
            artifactId: snapshot.artifactId, contractDigest: snapshot.contractDigest,
            resourceIdSha256: expected?.resourceIdSha256 ?? null,
            deploymentVersionSha256: expected?.deploymentVersionSha256 ?? null,
            state, reasons,
            identities: [...identities.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, identity]) => identity),
        };
        return freeze({ semantic, semanticDigest: 'sha256:' + httpArtifactDigest(semantic), metadata: {
            snapshotDigest: snapshot.digest,
            inputSha256: input === undefined ? null : bytesDigest(Buffer.from(input)),
            referenceTimeMs: expected?.referenceTimeMs ?? null,
            maxAgeMs: expected?.maxAgeMs ?? null,
            capturedAtMs: receipts.map(r => r.capturedAtMs).sort((a, b) => a - b),
        } });
    };
    if (input === undefined)
        return finish('missing', ['DEPLOYMENT_RECEIPTS_MISSING']);
    must(typeof input === 'string' && input.length <= 8192 && Buffer.byteLength(input, 'utf8') <= 8192, 'DEPLOYMENT_INPUT_LIMIT');
    let parsed: unknown;
    try { parsed = JSON.parse(input); }
    catch { throw new HttpArtifactError('INVALID_DEPLOYMENT_JSON'); }
    must(parsed && typeof parsed === 'object' && !Array.isArray(parsed), 'INVALID_DEPLOYMENT_INPUT');
    const root = parsed as Record<string, unknown>;
    must(root.scope === 'saved-deployment-fixture', 'DEPLOYMENT_SCOPE_UNSUPPORTED');
    must(Number.isSafeInteger(root.version) && (root.version as number) >= 1, 'INVALID_DEPLOYMENT_INPUT');
    // A future envelope is bounded and hashed, but is never decoded as version 1.
    if (root.version !== 1)
        return finish('unknown', ['DEPLOYMENT_VERSION_UNSUPPORTED']);
    deploymentRecord(root, ['version', 'scope', 'expected', 'receipts']);
    const e = deploymentRecord(root.expected, ['resourceIdSha256', 'deploymentVersionSha256', 'referenceTimeMs', 'maxAgeMs']);
    must(hex(e.resourceIdSha256) && hex(e.deploymentVersionSha256)
        && typeof e.referenceTimeMs === 'number' && Number.isSafeInteger(e.referenceTimeMs) && e.referenceTimeMs >= 0
        && typeof e.maxAgeMs === 'number' && Number.isSafeInteger(e.maxAgeMs) && e.maxAgeMs >= 0 && e.maxAgeMs <= 86400000, 'INVALID_DEPLOYMENT_INPUT');
    expected = { resourceIdSha256: e.resourceIdSha256, deploymentVersionSha256: e.deploymentVersionSha256,
        referenceTimeMs: e.referenceTimeMs, maxAgeMs: e.maxAgeMs };
    const referenceTimeMs = e.referenceTimeMs, maxAgeMs = e.maxAgeMs;
    must(Array.isArray(root.receipts) && root.receipts.length <= 8, 'DEPLOYMENT_RECEIPT_LIMIT');
    const seen = new Set<string>();
    receipts = root.receipts.map(value => {
        const r = deploymentRecord(value, ['resourceIdSha256', 'deploymentVersionSha256', 'artifactId', 'capturedAtMs']);
        for (const field of ['resourceIdSha256', 'deploymentVersionSha256', 'artifactId'])
            must(r[field] === null || hex(r[field]), 'INVALID_DEPLOYMENT_IDENTITY');
        must(typeof r.capturedAtMs === 'number' && Number.isSafeInteger(r.capturedAtMs) && r.capturedAtMs >= 0
            && r.capturedAtMs <= referenceTimeMs, 'INVALID_DEPLOYMENT_TIME');
        const receipt = { resourceIdSha256: r.resourceIdSha256 as string | null,
            deploymentVersionSha256: r.deploymentVersionSha256 as string | null,
            artifactId: r.artifactId as string | null, capturedAtMs: r.capturedAtMs };
        const identity = canonical(receipt);
        must(!seen.has(identity), 'DUPLICATE_DEPLOYMENT_RECEIPT');
        seen.add(identity);
        return receipt;
    });
    const reasons: string[] = [];
    if (snapshot.missing.length)
        reasons.push('ARTIFACT_SNAPSHOT_INCOMPLETE');
    if (!receipts.length)
        reasons.push('DEPLOYMENT_RECEIPTS_MISSING');
    if (receipts.some(r => r.resourceIdSha256 === null || r.deploymentVersionSha256 === null || r.artifactId === null))
        reasons.push('DEPLOYMENT_IDENTITY_MISSING');
    if (receipts.some(r => r.resourceIdSha256 !== null && r.resourceIdSha256 !== e.resourceIdSha256))
        reasons.push('DEPLOYMENT_RESOURCE_MISMATCH');
    const identities = new Set(receipts.filter(r => r.resourceIdSha256 === e.resourceIdSha256
        && r.deploymentVersionSha256 !== null && r.artifactId !== null).map(r => r.deploymentVersionSha256 + ':' + r.artifactId));
    if (identities.size > 1)
        reasons.push('DEPLOYMENT_MIXED');
    if (receipts.some(r => r.deploymentVersionSha256 !== null && r.deploymentVersionSha256 !== e.deploymentVersionSha256))
        reasons.push('DEPLOYMENT_VERSION_MISMATCH');
    if (receipts.some(r => r.artifactId !== null && r.artifactId !== snapshot.artifactId))
        reasons.push('DEPLOYMENT_ARTIFACT_MISMATCH');
    if (receipts.some(r => referenceTimeMs - r.capturedAtMs > maxAgeMs))
        reasons.push('DEPLOYMENT_RECEIPT_STALE');
    const state = reasons.some(r => ['ARTIFACT_SNAPSHOT_INCOMPLETE', 'DEPLOYMENT_RECEIPTS_MISSING', 'DEPLOYMENT_IDENTITY_MISSING'].includes(r)) ? 'missing'
        : reasons.includes('DEPLOYMENT_RESOURCE_MISMATCH') ? 'unknown'
            : reasons.includes('DEPLOYMENT_MIXED') ? 'mixed' : reasons.length ? 'stale' : 'current';
    return finish(state, reasons);
}
type Headers = Record<string, string | string[] | number | undefined>;
interface Receipt {
    url: string;
    method: string;
    headers: Headers;
    body: string;
}
export interface HttpArtifactRawObservation {
    caseId: string;
    correlationId: string;
    recordedAtMs: number;
    request: {
        target: string;
        method: string;
        body: string;
        headers: Headers;
        destination?: {
            host: string;
            port: number;
        };
    };
    response: {
        status: number;
        headers: Headers;
        body: string;
    };
    origins: Array<{
        arrival: number;
        receipt: Receipt;
    }>;
    events: Record<string, unknown>[];
}
type Json = string | number | boolean | null | Json[] | {
    [key: string]: Json;
};
export interface HttpArtifactObservation {
    caseId: string;
    snapshotDigest: string;
    artifactId: string;
    request: {
        target: string;
        method: string;
        body: string;
        credential: string;
    };
    response: {
        status: number;
        cacheControl: string | null;
        vary: string | null;
        body: Json;
    };
    origins: Array<{
        arrival: number;
        receipt: Json;
    }>;
    events: Array<{
        event: string;
        uri: string;
        reason: string | null;
    }>;
    metadata: {
        runId: string;
        correlationId: string;
        recordedAtMs: number;
        rawDigest: string;
        destination?: {
            host: string;
            port: number;
        };
    };
    digest: string;
}
function credential(value: unknown, values: HttpArtifactMaterial['credentials']): string {
    return value === undefined ? 'absent' : value === values.valid ? 'valid' : value === values.wrong ? 'wrong' : 'unrecognized';
}
export function captureHttpArtifactObservation(snapshot: HttpArtifactSnapshot, input: HttpArtifactRawObservation): HttpArtifactObservation {
    must(snapshots.has(snapshot), 'UNISSUED_SNAPSHOT');
    const ctx = contexts.get(snapshot);
    must(ctx, 'CAPTURE_CONTEXT_MISSING');
    must(input && text(input.caseId, 128) && text(input.correlationId, 256) && Number.isSafeInteger(input.recordedAtMs) && input.recordedAtMs >= 0, 'INVALID_OBSERVATION');
    const c = ctx.contract.cases.find(c => c.id === input.caseId);
    must(c, 'UNKNOWN_CASE_ID');
    must(input.request && text(input.request.target, 4096) && text(input.request.method, 32) && text(input.request.body) && input.request.headers?.['x-e2e-id'] === input.correlationId, 'INVALID_HTTP_REQUEST');
    if (input.request.destination)
        must(text(input.request.destination.host, 256) && Number.isInteger(input.request.destination.port) && input.request.destination.port > 0 && input.request.destination.port < 65536, 'INVALID_TRANSPORT_BINDING');
    const request = { target: input.request.target, method: input.request.method, body: input.request.body, credential: credential(input.request.headers['x-edge-token'], ctx.credentials) };
    for (const [name, value] of Object.entries(c.headers ?? {}))
        must(input.request.headers[name] === value, 'CASE_REQUEST_MISMATCH');
    must(request.target === c.target && request.method === (c.method ?? 'GET') && request.body === (c.body ?? '') && request.credential === (c.credential ?? 'absent'), 'CASE_REQUEST_MISMATCH');
    must(input.response && Number.isInteger(input.response.status) && input.response.status >= 100 && input.response.status <= 599 && text(input.response.body), 'INVALID_HTTP_RESPONSE');
    must(Array.isArray(input.origins) && input.origins.length <= 128 && Array.isArray(input.events) && input.events.length <= 256, 'INVALID_OBSERVATION');
    must(input.events.every(e => e && e.correlation_id === input.correlationId), 'INVALID_EVENT_BINDING');
    const arrivals = new Set<number>();
    for (const o of input.origins) {
        must(Number.isSafeInteger(o.arrival) && o.arrival >= 0 && !arrivals.has(o.arrival), 'DUPLICATE_ORIGIN_RECEIPT');
        arrivals.add(o.arrival);
        must(o.receipt && text(o.receipt.url, 4096) && text(o.receipt.method, 32) && text(o.receipt.body) && o.receipt.headers?.['x-e2e-id'] === input.correlationId, 'INVALID_ORIGIN_BINDING');
    }
    const abstract = (value: unknown, key = '', depth = 0): Json => {
        must(depth <= 16, 'OBSERVATION_DEPTH_LIMIT');
        if (value === null || typeof value === 'number' || typeof value === 'boolean')
            return value;
        if (typeof value === 'string') {
            if (key.toLowerCase() === 'x-edge-token' || key.toLowerCase() === 'authorization')
                return '[credential:' + credential(value, ctx.credentials) + ']';
            if (key.toLowerCase() === 'x-e2e-id' && value === input.correlationId)
                return input.caseId;
            return value.replaceAll(ctx.credentials.valid, '[credential:valid]').replaceAll(ctx.credentials.wrong, '[credential:wrong]').replaceAll('127.0.0.1:' + snapshot.metadata.originPort, 'loopback-origin').replaceAll('127.0.0.1:' + snapshot.metadata.workerPort, 'loopback-worker');
        }
        if (Array.isArray(value))
            return value.map(v => abstract(v, key, depth + 1));
        must(value && typeof value === 'object', 'INVALID_OBSERVATION_VALUE');
        return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined).map(([k, v]) => [k, abstract(v, k, depth + 1)]));
    };
    let responseBody: unknown = input.response.body;
    try {
        responseBody = JSON.parse(input.response.body);
    }
    catch { /* A non-JSON response is an observed value, not a transport failure. */ }
    const header = (name: string) => { const v = input.response.headers[name]; must(v === undefined || typeof v === 'string', 'INVALID_RESPONSE_HEADER'); return v ?? null; };
    const events = input.events.filter(e => e.correlation_id === input.correlationId && ['allow', 'block'].includes(String(e.event))).map(e => { must(text(e.event, 32) && text(e.uri, 4096) && (e.block_reason === undefined || text(e.block_reason, 1024)), 'INVALID_WORKER_EVENT'); return { event: e.event, uri: e.uri, reason: typeof e.block_reason === 'string' ? e.block_reason : null }; });
    must(events.length <= 1, 'DUPLICATE_WORKER_DECISION');
    const data = {
        caseId: input.caseId, snapshotDigest: snapshot.digest, artifactId: snapshot.artifactId, request, response: { status: input.response.status, cacheControl: header('cache-control'), vary: header('vary'), body: abstract(responseBody) }, origins: input.origins.map(o => ({ arrival: o.arrival, receipt: abstract(o.receipt) })), events, metadata: { runId: snapshot.metadata.runId, correlationId: input.correlationId, recordedAtMs: input.recordedAtMs, rawDigest: httpArtifactDigest(input), destination: input.request.destination ? { ...input.request.destination } : undefined }
    };
    const o = freeze({ ...data, digest: httpArtifactDigest(data) });
    observations.add(o);
    return o;
}
function result(contract: HttpArtifactContract, snapshot: HttpArtifactSnapshot | null, counterexamples: Record<string, unknown>[], unknown: Array<{
    caseId: string;
    reason: string;
}>, cases: Record<string, unknown>[]) {
    const verdict = counterexamples.length ? 'VIOLATED' : unknown.length ? 'UNKNOWN' : 'VERIFIED';
    const semantic = { scope: 'local-artifact-fixture' as const, contractDigest: contract.digest, artifactId: snapshot?.artifactId ?? null, verdict, cases, counterexamples, unknown };
    const findings = counterexamples.map(c => createFinding({ ruleId: 'SC-ARTIFACT-001', severity: 'error', confidence: 'deterministic', category: 'runtime-evidence', title: 'Generated Worker violates the fixed HTTP fixture', message: 'Actual native HTTP evidence differs from the independent local fixture contract.', expected: c.expected, actual: c.observed, evidence: [{ source: 'generated-artifact', uri: 'local-artifact/worker.mjs', digest: 'sha256:' + snapshot!.artifactId, analyzer: 'artifact-http-fixture-v1', capability: 'local-artifact-fixture', complete: true }], remediation: { summary: 'Repair the generated control and replay the fixed HTTP fixture.', safeAutoFix: false } }));
    return { semantic, semanticDigest: 'sha256:' + httpArtifactDigest(semantic), findings };
}
export function verifyHttpArtifact(contract: HttpArtifactContract, snapshot: HttpArtifactSnapshot, items: readonly HttpArtifactObservation[], execution: {
    failure?: unknown;
} = {}) {
    must(!execution.failure, 'HTTP_EXECUTION_FAILED');
    must(contracts.has(contract), 'UNISSUED_CONTRACT');
    must(snapshots.has(snapshot), 'UNISSUED_SNAPSHOT');
    must(Array.isArray(items) && items.length <= 128, 'INVALID_OBSERVATION_SET');
    const correlations = new Set<string>(), arrivals = new Set<string>();
    const byId = new Map<string, HttpArtifactObservation>();
    for (const o of items) {
        must(observations.has(o), 'UNISSUED_OBSERVATION');
        must(!byId.has(o.caseId), 'DUPLICATE_CASE');
        must(contract.cases.some(c => c.id === o.caseId), 'UNKNOWN_CASE_ID');
        const correlation = o.metadata.runId + ':' + o.metadata.correlationId;
        must(!correlations.has(correlation), 'DUPLICATE_CORRELATION');
        correlations.add(correlation);
        for (const r of o.origins) {
            const arrival = o.metadata.runId + ':' + r.arrival;
            must(!arrivals.has(arrival), 'DUPLICATE_ORIGIN_RECEIPT');
            arrivals.add(arrival);
        }
        byId.set(o.caseId, o);
    }
    const unknown: Array<{
        caseId: string;
        reason: string;
    }> = [], counterexamples: Record<string, unknown>[] = [], cases: Record<string, unknown>[] = [];
    for (const c of [...contract.cases].sort((a, b) => a.id.localeCompare(b.id, 'en'))) {
        const o = byId.get(c.id);
        let reason: string | undefined;
        if (snapshot.contractDigest !== contract.digest)
            reason = 'EXPECTED_CONTRACT_MIXED';
        else if (snapshot.missing.length)
            reason = 'IDENTITY_MISSING:' + snapshot.missing.join(',');
        else if (!o)
            reason = 'OBSERVATION_MISSING';
        else if (o.snapshotDigest !== snapshot.digest || o.artifactId !== snapshot.artifactId || o.metadata.runId !== snapshot.metadata.runId)
            reason = 'RUN_OR_ARTIFACT_MIXED';
        else if (!o.metadata.destination)
            reason = 'TRANSPORT_BINDING_MISSING';
        else if (o.metadata.destination.host !== '127.0.0.1' || o.metadata.destination.port !== snapshot.metadata.workerPort)
            reason = 'RUN_OR_ARTIFACT_MIXED';
        else if (o.metadata.recordedAtMs < snapshot.metadata.startedAtMs || o.metadata.recordedAtMs > snapshot.metadata.finishedAtMs)
            reason = 'OBSERVATION_STALE';
        else if (!o.events.length)
            reason = 'WORKER_EVENT_MISSING';
        if (reason) {
            unknown.push({ caseId: c.id, reason });
            cases.push({ caseId: c.id, verdict: 'UNKNOWN', reason });
            continue;
        }
        const v = o!, diffs: string[] = [];
        const check = (condition: boolean, name: string) => { if (!condition)
            diffs.push(name); };
        check(v.response.status === c.status, 'response.status');
        check(v.origins.length === (c.forwarded ? 1 : 0), 'origin.arrivals');
        check(v.events[0].event === (c.forwarded ? 'allow' : 'block'), 'worker.decision');
        if (c.reason)
            check(v.events[0].reason?.includes(c.reason) === true, 'worker.reason');
        if (c.workerUri)
            check(v.events[0].uri === c.workerUri, 'worker.uri');
        if (c.forwarded && v.origins.length === 1) {
            const r = v.origins[0].receipt as Record<string, Json>;
            check(r.url === c.forwarded, 'origin.path');
            check(r.method === (c.method ?? 'GET'), 'origin.method');
            check(r.body === (c.body ?? ''), 'origin.body');
            check(canonical(v.response.body) === canonical(r), 'response.origin-receipt');
        }
        const tokens = (s: string | null) => s?.split(',').map(v => v.trim().toLowerCase()) ?? [];
        if (c.protectedResponse) {
            check(tokens(v.response.cacheControl).includes('no-store'), 'response.no-store');
            check(tokens(v.response.vary).includes('authorization'), 'response.vary-authorization');
        }
        if (c.publicResponse) {
            check(v.response.cacheControl === null, 'response.public-cache');
            check(!tokens(v.response.vary).includes('authorization'), 'response.public-vary');
        }
        if (diffs.length)
            counterexamples.push({ caseId: c.id, request: v.request, expected: { status: c.status, originArrivals: c.forwarded ? 1 : 0, originPath: c.forwarded ?? null, worker: c.forwarded ? 'allow' : 'block', protectedResponse: c.protectedResponse ?? false, publicResponse: c.publicResponse ?? false }, observed: { response: v.response, origins: v.origins.map(o => o.receipt), events: v.events }, differences: diffs });
        cases.push({ caseId: c.id, verdict: diffs.length ? 'VIOLATED' : 'MATCHED', observationDigest: httpArtifactDigest({ request: v.request, response: v.response, origins: v.origins.map(o => o.receipt), events: v.events }) });
    }
    return result(contract, snapshot, counterexamples, unknown, cases);
}
export interface HttpArtifactBundle {
    version: 1;
    contractDigest: string;
    snapshot: HttpArtifactSnapshot;
    observations: HttpArtifactObservation[];
    digest: string;
}
export function createHttpArtifactBundle(contract: HttpArtifactContract, snapshot: HttpArtifactSnapshot, items: readonly HttpArtifactObservation[]): HttpArtifactBundle {
    verifyHttpArtifact(contract, snapshot, items);
    const data = {
        version: 1 as const, contractDigest: contract.digest, snapshot, observations: [...items].sort((a, b) => a.caseId.localeCompare(b.caseId, 'en'))
    };
    return freeze({ ...data, digest: httpArtifactDigest(data) });
}
export function replayHttpArtifact(contract: HttpArtifactContract, bundle: HttpArtifactBundle, trustedDigest?: string) {
    must(contracts.has(contract), 'UNISSUED_CONTRACT');
    if (trustedDigest === undefined)
        return result(contract, null, [], [{ caseId: '*', reason: 'REPLAY_IDENTITY_MISSING' }], []);
    must(hex(trustedDigest) && bundle && bundle.version === 1, 'INVALID_REPLAY_BUNDLE');
    const { digest, ...data } = bundle;
    must(digest === trustedDigest && httpArtifactDigest(data) === trustedDigest, 'BUNDLE_DIGEST_MISMATCH');
    must(bundle.contractDigest === contract.digest && bundle.snapshot.contractDigest === contract.digest, 'REPLAY_CONTRACT_MISMATCH');
    const { digest: snapshotDigest, ...snapshotData } = bundle.snapshot;
    must(httpArtifactDigest(snapshotData) === snapshotDigest, 'SNAPSHOT_DIGEST_MISMATCH');
    freeze(bundle.snapshot);
    snapshots.add(bundle.snapshot);
    must(Array.isArray(bundle.observations) && bundle.observations.length <= 128, 'INVALID_OBSERVATION_SET');
    for (const o of bundle.observations) {
        const { digest: observationDigest, ...observationData } = o;
        must(httpArtifactDigest(observationData) === observationDigest, 'OBSERVATION_DIGEST_MISMATCH');
        freeze(o);
        observations.add(o);
    }
    return verifyHttpArtifact(contract, bundle.snapshot, bundle.observations);
}
