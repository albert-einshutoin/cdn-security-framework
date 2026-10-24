// Internal, model-only MVP. No barrel/package export or runtime association is installed.
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createSecurityContract, serializeSecurityContract, type SecurityContractInputV1, type SecurityContractV1 } from '../security-ir';
import { securityContractSemanticDigest } from '../semantic-digest';
import { projectPolicyToAllowedSurface, type AllowedSurfaceModelV1 } from '../allowed-surface';
import { relateRoute } from '../route-relation';
import { createFinding } from '../finding';
import { hasUnsafeSensitiveText } from '../sensitive-text';
import Ajv from 'ajv';
import type { CDNSecurityFrameworkPolicy } from '../../types/policy';
import { checkAuthCacheWitness } from './auth-cache-witness';

export interface ModelRequest { method: string; host: string; path: string; credential: 'absent' | 'valid' }
export interface CacheFill { request: ModelRequest; storedAtMs: number; location: string }
export interface ExecutionModel {
  version: 1; hosts: string[]; distribution: string; location: string; nowMs: number;
  flow?: 'standard'; originResponds?: boolean;
  associations?: { rule: number; phase: 'viewer-request' | 'origin-request' | 'unassociated' | 'unknown' | 'origin-response' | 'viewer-response' }[];
  effects?: { kind: 'redirect' | 'custom-error' | 'bypass' | 'unknown'; hosts?: string[]; methods?: string[]; paths?: string[] }[];
  cache?: { enabled: boolean; cacheable?: boolean; ttlMs?: number;
    key?: { host: 'distribution' | 'viewer'; credential: 'shared' | 'partitioned' }; fills?: CacheFill[] };
}
export type Verdict = 'VERIFIED' | 'VIOLATED' | 'UNKNOWN';
export interface Witness {
  inputDigest: string; request: ModelRequest; routeKey: string; cache: 'HIT' | 'MISS';
  fill?: CacheFill; trace: string[];
}
export interface Projection {
  contract: SecurityContractV1; surface: AllowedSurfaceModelV1; model: ExecutionModel; digest: string;
  policyArtifact: {name:string;content:string;digest:string};
  validationSchema: {uri:string;digest:string};
}
export interface Cell { routeKey: string; host: string; credential: 'absent' | 'valid'; verdict: Verdict; reason: string; paths: string[]; witness?: Witness }
export class AuthCacheInputError extends Error {
  constructor(readonly code: string) { super(code); this.name = 'AuthCacheInputError'; }
}
function must(value: unknown, code: string): asserts value { if (!value) throw new AuthCacheInputError(code); }
function assertJson(value: unknown, depth = 0, state = {nodes: 0, ancestors: new Set<object>()}): void {
  must(++state.nodes <= 50000 && depth <= 64, 'JSON_RESOURCE_LIMIT');
  if(value === undefined || value === null || typeof value === 'boolean') return;
  if(typeof value === 'string') { must(value.length <= 16384, 'JSON_STRING_LIMIT'); return; }
  if(typeof value === 'number') { must(Number.isFinite(value), 'INVALID_JSON_NUMBER'); return; }
  must(typeof value === 'object' && (Array.isArray(value) || Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null), 'INVALID_JSON_VALUE');
  must(!state.ancestors.has(value), 'JSON_CYCLE');
  state.ancestors.add(value);
  const descriptors=Object.getOwnPropertyDescriptors(value);
  must(Reflect.ownKeys(descriptors).length <= 50000-state.nodes, 'JSON_RESOURCE_LIMIT');
  for(const key of Reflect.ownKeys(descriptors)) {
    must(typeof key === 'string', 'INVALID_JSON_KEY');
    const d=descriptors[key]; must(!d.get && !d.set, 'INVALID_JSON_ACCESSOR');
    assertJson(d.value,depth+1,state);
  }
  state.ancestors.delete(value);
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`;
  return JSON.stringify(value);
}
export function modelDigest(value: unknown): string { return `sha256:${createHash('sha256').update(canonical(value)).digest('hex')}`; }
const literalPath = (v: string) => typeof v === 'string' && v.length <= 2048 && /^\/(?:[A-Za-z0-9_~.-]+(?:\/[A-Za-z0-9_~.-]+)*)?$/.test(v) && !v.split('/').some(s => s === '.' || s === '..');
const host = (v: string) => typeof v === 'string' && v.length <= 253 && /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+test$/.test(v);
const time = (v: unknown) => Number.isSafeInteger(v) && (v as number) >= 0;
const boundedList = (v: unknown, max = 128): v is unknown[] => Array.isArray(v) && v.length <= max;
const method = (v: unknown) => ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE', 'TRACE', 'CONNECT'].includes(v as string);
function keys(value: object, allowed: string[]): void { must(Object.keys(value).every(k => allowed.includes(k)), 'UNRECOGNIZED_MODEL_FIELD'); }
function stringSet(input: string[], valid: (v: string) => boolean, max = 128): string[] {
  must(boundedList(input, max) && input.every(valid), 'INVALID_MODEL_SET'); return [...new Set(input)].sort();
}
function request(input: ModelRequest): ModelRequest {
  must(input && typeof input === 'object', 'INVALID_REQUEST'); keys(input, ['method', 'host', 'path', 'credential']);
  must(method(input.method) && host(input.host) && literalPath(input.path) && ['absent', 'valid'].includes(input.credential), 'INVALID_REQUEST');
  return { method: input.method, host: input.host, path: input.path, credential: input.credential };
}
function normalizeModel(m: ExecutionModel): ExecutionModel {
  must(m && typeof m === 'object', 'INVALID_MODEL'); keys(m, ['version', 'hosts', 'distribution', 'location', 'nowMs', 'flow', 'originResponds', 'associations', 'effects', 'cache']);
  must(m.version === 1 && time(m.nowMs) && host(m.distribution) && typeof m.location === 'string' && /^[a-z0-9-]{1,32}$/.test(m.location), 'INVALID_MODEL');
  must(m.flow === undefined || m.flow === 'standard', 'INVALID_FLOW');
  must(m.originResponds === undefined || typeof m.originResponds === 'boolean', 'INVALID_ORIGIN');
  const out: ExecutionModel = { version: 1, hosts: stringSet(m.hosts, host, 16), distribution: m.distribution, location: m.location, nowMs: m.nowMs };
  must(out.hosts.length > 0, 'EMPTY_HOST_DOMAIN');
  if (m.flow !== undefined) out.flow = m.flow;
  if (m.originResponds !== undefined) out.originResponds = m.originResponds;
  if (m.associations !== undefined) {
    must(boundedList(m.associations), 'ASSOCIATION_LIMIT');
    out.associations = m.associations.map(a => { keys(a, ['rule', 'phase']); must(time(a.rule) && ['viewer-request', 'origin-request', 'unassociated', 'unknown', 'origin-response', 'viewer-response'].includes(a.phase), 'INVALID_ASSOCIATION'); return { rule: a.rule, phase: a.phase }; }).sort((a,b) => a.rule-b.rule);
    must(new Set(out.associations.map(a => a.rule)).size === out.associations.length, 'DUPLICATE_ASSOCIATION');
  }
  if (m.effects !== undefined) {
    must(boundedList(m.effects), 'EFFECT_LIMIT');
    out.effects = m.effects.map(e => {
      keys(e, ['kind', 'hosts', 'methods', 'paths']); must(['redirect', 'custom-error', 'bypass', 'unknown'].includes(e.kind), 'INVALID_EFFECT');
      return { kind: e.kind, ...(e.hosts === undefined ? {} : { hosts: stringSet(e.hosts, host, 16) }), ...(e.methods === undefined ? {} : { methods: stringSet(e.methods, method) }), ...(e.paths === undefined ? {} : { paths: stringSet(e.paths, literalPath) }) };
    }).sort((a,b) => canonical(a)<canonical(b)?-1:canonical(a)>canonical(b)?1:0);
  }
  if (m.cache !== undefined) {
    const c = m.cache; keys(c, ['enabled', 'cacheable', 'ttlMs', 'key', 'fills']);
    must(typeof c.enabled === 'boolean' && (c.cacheable === undefined || typeof c.cacheable === 'boolean') && (c.ttlMs === undefined || time(c.ttlMs)), 'INVALID_CACHE');
    const cache: NonNullable<ExecutionModel['cache']> = { enabled: c.enabled };
    if (c.cacheable !== undefined) cache.cacheable = c.cacheable;
    if (c.ttlMs !== undefined) cache.ttlMs = c.ttlMs;
    if (c.key !== undefined) { keys(c.key, ['host', 'credential']); must(['distribution', 'viewer'].includes(c.key.host) && ['shared', 'partitioned'].includes(c.key.credential), 'INVALID_CACHE_KEY'); cache.key = { host: c.key.host, credential: c.key.credential }; }
    if (c.fills !== undefined) {
      must(boundedList(c.fills), 'FILL_LIMIT');
      cache.fills = c.fills.map(f => {
        keys(f, ['request', 'storedAtMs', 'location']); must(time(f.storedAtMs) && f.storedAtMs < m.nowMs && typeof f.location === 'string' && /^[a-z0-9-]{1,32}$/.test(f.location), 'INVALID_FILL_TIME_LOCATION');
        const req = request(f.request); must(out.hosts.includes(req.host), 'FILL_HOST_OUTSIDE_DOMAIN');
        return { request: req, storedAtMs: f.storedAtMs, location: f.location };
      }).sort((a,b) => canonical(a)<canonical(b)?-1:canonical(a)>canonical(b)?1:0);
      must(new Set(cache.fills.map(canonical)).size === cache.fills.length, 'DUPLICATE_FILL');
    }
    out.cache = cache;
  }
  return out;
}
function projectionIdentity(p: Pick<Projection, 'contract' | 'surface' | 'model'>) {
  const {policyDigest: _policyDigest, provenance: _provenance, ...surface} = p.surface;
  return {ir:securityContractSemanticDigest(p.contract),surface,model:p.model};
}
// Clean break: only constructor-issued, recursively frozen snapshots cross the verifier boundary.
// Semantic identity intentionally omits provenance; immutability protects all evidence bindings too.
const issuedProjections = new WeakSet<Projection>();
function freezeSnapshot(value: unknown): void {
  if(value && typeof value === 'object' && !Object.isFrozen(value)) {
    for(const child of Object.values(value)) freezeSnapshot(child);
    Object.freeze(value);
  }
}
function admitted(p: Projection, r: ModelRequest): boolean {
  return p.surface.defaults.methods.includes(r.method) && relateRoute(
    { path: {kind:'exact',value:r.path}, methods:[r.method], hosts:{kind:'allowlist',values:[r.host]} },
    { path: {kind:'exact',value:r.path}, methods:[r.method], hosts:p.surface.defaults.hosts },
    {phase:'normalized-path',collapseSlashes:false,removeDotSegments:false},
  ).relation === 'definitely-covered';
}
function matchingRules(p: Projection, r: ModelRequest) {
  return p.surface.orderedRules.filter(rule => rule.auth.kind !== 'none' && rule.match.authEffectiveValues.some(prefix =>
    relateRoute({path:{kind:'exact',value:r.path},methods:[r.method],hosts:{kind:'allowlist',values:[r.host]}},
      {path:{kind:'prefix',value:prefix},methods:rule.methods.effective,hosts:p.surface.defaults.hosts},
      {phase:'normalized-path',collapseSlashes:false,removeDotSegments:false}).relation === 'definitely-covered'));
}
function cacheKey(p: Projection, r: ModelRequest): string {
  const key = p.model.cache!.key!;
  return canonical([p.model.distribution, r.path, r.method === 'HEAD' ? 'GET' : r.method, key.host === 'viewer' ? r.host : null, key.credential === 'partitioned' ? r.credential : null]);
}
export function projectAuthCache(contract: SecurityContractInputV1, policy: CDNSecurityFrameworkPolicy, model: ExecutionModel): Projection {
  // Bound JSON is also a snapshot: later caller mutation cannot alter the projection.
  let snapshot: {contract: SecurityContractInputV1; policy: CDNSecurityFrameworkPolicy; model: ExecutionModel};
  try { assertJson({contract,policy,model}); const raw = JSON.stringify({contract,policy,model}); must(Buffer.byteLength(raw) <= 1_048_576, 'INPUT_SIZE_LIMIT'); snapshot = JSON.parse(raw); } catch(e) { if(e instanceof AuthCacheInputError) throw e; throw new AuthCacheInputError('INVALID_JSON_INPUT'); }
  must(boundedList(snapshot.contract?.operations) && boundedList(snapshot.policy?.routes ?? []), 'OPERATION_RULE_LIMIT');
  const compiledRoot = path.resolve(__dirname, '../..');
  const pkgRoot = fs.existsSync(path.join(compiledRoot, 'policy/schema.json')) ? compiledRoot : path.resolve(compiledRoot, '..');
  const schemaText=fs.readFileSync(path.join(pkgRoot,'policy/schema.json'),'utf8');
  const validate = new Ajv({allErrors:true,strict:true,strictRequired:false,allowUnionTypes:true}).compile(JSON.parse(schemaText));
  const policyContent=canonical(snapshot.policy);
  must(!hasUnsafeSensitiveText(policyContent), 'SECRET_LIKE_POLICY_VALUE');
  const canonicalPolicy=JSON.parse(policyContent) as CDNSecurityFrameworkPolicy;
  must(validate(canonicalPolicy), 'INVALID_POLICY');
  const policyArtifact={name:'model/policy.json',content:policyContent,digest:modelDigest(canonicalPolicy)};
  const validationSchema={uri:'policy/schema.json',digest:`sha256:${createHash('sha256').update(schemaText).digest('hex')}`};
  const ir = createSecurityContract(snapshot.contract), surface = projectPolicyToAllowedSurface(canonicalPolicy, { policyDigest: policyArtifact.digest, sourceUri:policyArtifact.name });
  must(surface.orderedRules.reduce((n,r)=>n+r.match.authEffectiveValues.length,0)<=256 && surface.orderedRules.reduce((n,r)=>n+r.match.authEffectiveValues.join('').length,0)<=65536, 'PREFIX_BUDGET');
  const normalized = normalizeModel(snapshot.model);
  const p: Projection = {contract:ir,surface,model:normalized,digest:'',policyArtifact,validationSchema};
  for (const a of normalized.associations ?? []) must(surface.orderedRules.some(rule => rule.index === a.rule && rule.auth.kind !== 'none'), 'ASSOCIATION_RULE');
  // A fills array is a resident snapshot, not a write history: one object per key/location.
  if(normalized.cache?.key) {
    const slots=new Set<string>();
    for(const f of normalized.cache.fills ?? []) {
      const slot=canonical([f.location,cacheKey(p,f.request)]);
      must(!slots.has(slot),'DUPLICATE_RESIDENT_SLOT');slots.add(slot);
    }
  }
  for (const f of normalized.cache?.fills ?? []) {
    must(['GET','HEAD','OPTIONS'].includes(f.request.method) && admitted(p,f.request), 'INVALID_FILL_REQUEST');
    must(!matchingRules(p,f.request).some(rule => normalized.associations?.some(a => a.rule === rule.index && ['viewer-request','origin-request'].includes(a.phase)) && f.request.credential === 'absent'), 'UNREACHABLE_FILL');
  }
  p.digest = modelDigest(projectionIdentity(p));
  freezeSnapshot(p);issuedProjections.add(p);
  return p;
}
function unknownReason(p: Projection, r: ModelRequest): string | undefined {
  const m = p.model;
  if (m.flow === undefined) return 'EXECUTION_ORDER_UNKNOWN';
  if (m.associations === undefined) return 'ASSOCIATION_UNKNOWN';
  if (m.effects === undefined) return 'EXCEPTION_COVERAGE_UNKNOWN';
  const effect = m.effects.find(e => (!e.hosts || e.hosts.includes(r.host)) && (!e.methods || e.methods.includes(r.method)) && (!e.paths || e.paths.includes(r.path)));
  if (effect) return `UNSUPPORTED_${effect.kind.toUpperCase()}`;
  if (!literalPath(r.path)) return 'PATH_DOMAIN_UNSUPPORTED';
  if (!admitted(p,r)) return 'GLOBAL_ADMISSION_OUTSIDE_MODEL';
  // Header presence is outside this finite request domain; pre-auth rejection cannot be inferred.
  if (p.surface.defaults.requestDecision === 'block' && p.surface.defaults.blockedHeaders?.values.length) return 'HEADER_ADMISSION_UNMODELED';
  if (p.surface.defaults.pathNormalization.caseInsensitive) return 'PATH_CASE_NORMALIZATION_UNSUPPORTED';
  if (r.method === 'OPTIONS' && p.surface.defaults.corsOptionsBypass) return 'CORS_PREAUTH_BYPASS_UNSUPPORTED';
  for (const rule of matchingRules(p,r)) {
    const phase = m.associations?.find(a => a.rule === rule.index)?.phase;
    if (phase === undefined || phase === 'unknown') return 'ASSOCIATION_UNKNOWN';
    if (phase === 'origin-response' || phase === 'viewer-response') return 'RESPONSE_AUTH_PHASE_UNSUPPORTED';
    if (phase !== 'unassociated' && rule.auth.verifiability.aws !== 'enforced') return 'AUTH_GATE_UNSUPPORTED';
  }
  return undefined;
}
function cachePath(p: Projection, r: ModelRequest): {kind:'HIT'|'MISS';fill?:CacheFill} | undefined {
  const c=p.model.cache;
  if (!c) return undefined;
  if (!c.enabled || !['GET','HEAD','OPTIONS'].includes(r.method) || c.cacheable === false || c.ttlMs === 0) return {kind:'MISS'};
  if (!c.key || c.cacheable === undefined || c.ttlMs === undefined || !c.fills) return undefined;
  const fill=c.fills.find(f => f.location === p.model.location && p.model.nowMs-f.storedAtMs < c.ttlMs! && cacheKey(p,f.request) === cacheKey(p,r));
  if(fill && (unknownReason(p,fill.request) || p.model.originResponds!==true)) return undefined;
  return fill ? {kind:'HIT',fill} : {kind:'MISS'};
}
export function verifyAuthCache(p: Projection, metadata: {generatedAt?:string} = {}) {
  must(issuedProjections.has(p), 'PROJECTION_BINDING');
  if(metadata.generatedAt!==undefined) must(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(metadata.generatedAt), 'INVALID_METADATA');
  const cells: Cell[]=[];
  for (const op of p.contract.operations) for (const h of p.model.hosts) for (const credential of ['absent','valid'] as const) {
    const required = ['authenticated','privileged'].includes(op.exposure) || (op.auth.mode==='alternatives' && op.auth.alternatives.every(a=>!a.anonymous));
    if (!required && op.exposure!=='unknown' && op.auth.mode!=='unknown') continue;
    const r:ModelRequest={method:op.method,host:h,path:op.path,credential};
    const cell:Cell={routeKey:op.routeKey,host:h,credential,verdict:'UNKNOWN',reason:'',paths:[]};cells.push(cell);
    const reason = !required ? 'PROTECTION_REQUIREMENT_UNKNOWN' : (p.contract.capabilities.routes!=='complete' || p.contract.capabilities.authentication!=='complete') ? 'IR_COVERAGE_INCOMPLETE' : unknownReason(p,r);
    if(reason){cell.reason=reason;continue;}
    const rules=matchingRules(p,r), phases=rules.map(rule=>p.model.associations!.find(a=>a.rule===rule.index)!.phase);
    // Check both credential partitions: valid-credential HITs can also skip the required gate.
    if(phases.includes('viewer-request')) {cell.verdict='VERIFIED';cell.reason='VIEWER_AUTH_BEFORE_ANY_CACHE_PATH';const suffix=cachePath(p,r);cell.paths=[credential==='absent'?'viewer-request -> auth-check -> rejected':`viewer-request -> auth-check -> cache-lookup -> ${suffix?.kind ?? 'unknown-suffix'}`];continue;}
    const cache=cachePath(p,r);
    if(!cache){cell.reason='CACHE_REACHABILITY_UNKNOWN';continue;}
    if(cache.kind==='MISS' && phases.includes('origin-request')) {cell.verdict='VERIFIED';cell.reason='ONLY_MISS_REACHABLE_ORIGIN_AUTH';cell.paths=[`cache MISS -> origin-request -> auth-check:${credential==='absent'?'rejected':'accepted'}`];continue;}
    if(cache.kind==='MISS' && p.model.originResponds!==true){cell.reason='ORIGIN_RESPONSE_UNKNOWN';continue;}
    const trace=['viewer-request','cache-lookup',cache.kind,...(cache.kind==='MISS'?['origin-request']:[]),'protected-response'];
    const witness:Witness={inputDigest:p.digest,request:r,routeKey:op.routeKey,cache:cache.kind,...(cache.fill?{fill:cache.fill}:{}),trace};
    checkAuthCacheWitness(p,witness);
    cell.verdict='VIOLATED';cell.reason='PROTECTED_RESPONSE_WITHOUT_AUTH';cell.witness=witness;cell.paths=[trace.join(' -> ')];
  }
  const verdict:Verdict=cells.some(c=>c.verdict==='VIOLATED')?'VIOLATED':cells.length>0&&cells.every(c=>c.verdict==='VERIFIED')?'VERIFIED':'UNKNOWN';
  const artifacts=[p.policyArtifact,{name:'security-ir.json',content:serializeSecurityContract(p.contract)},{name:'allowed-surface.json',content:canonical(p.surface)+'\n'},{name:'execution-model.json',content:canonical(p.model)+'\n'}].map(a=>({...a,digest:`sha256:${createHash('sha256').update(a.content).digest('hex')}`}));
  const semantic={model:'cloudfront-auth-cache-v1',inputDigest:p.digest,verdict,cells,emptyDomainReason:cells.length?null:'NO_PROTECTED_DOMAIN',invariant:{R:'Every declared protected admitted request, both credential states and its reachable execution path',E:'Requests whose execution evaluates a supported blocking auth gate',obligation:'R subset E',quantifier:'Exhaustive finite domain; not test sampling'},scope:{hosts:p.model.hosts,operations:p.contract.operations.map(o=>o.routeKey),credentials:['absent','valid'],timeMs:p.model.nowMs,location:p.model.location},assumptions:['Explicit model associations, not deployed configuration','Abstract gates reject absent and accept valid credentials without side effects','Resident fills remain at the specified cache location until input TTL expires','Only canonical literal paths; no query, cookie or other cache key dimensions beyond explicit credential state','Other non-auth request checks admit the modeled request; they never generate protected responses'],limitations:['Model-only coverage; no AWS/Cloudflare runtime, cryptographic, authorization or performance proof','Templates and declared unsupported effects remain UNKNOWN at affected cells','No eviction, revalidation, request rewriting, origin failover or implicit redirect/custom-error semantics']};
  const digest=modelDigest(semantic);
  const findings=cells.map((c,index)=>({c,index})).filter(({c})=>c.verdict==='VIOLATED').map(({c,index})=>createFinding({ruleId:'SC-AUTHCACHE-001',severity:'error',confidence:'deterministic',category:'authentication',title:'Model auth bypass',message:c.paths[0],route:{method:c.witness!.request.method,path:c.witness!.request.path},evidence:[{source:'generated-artifact',uri:'evidence.json',pointer:`/semantic/cells/${index}`,digest,analyzer:'auth-cache@1',capability:'explicit-cloudfront-model-only',complete:true}],remediation:{summary:'Review pre-cache authentication and the explicitly modeled cache configuration',safeAutoFix:false}}));
  return {semantic,semanticDigest:digest,artifacts,validationSchema:p.validationSchema,findings,metadata};
}
