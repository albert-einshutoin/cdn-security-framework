import { describe, expect, test } from 'vitest';
import { projectAuthCache, verifyAuthCache } from '../../src/contract/verification/auth-cache';
import { checkAuthCacheWitness } from '../../src/contract/verification/auth-cache-witness';
import { contract, policy, model } from '../fixtures/auth-cache/input';
describe('auth x cache model', () => {
  test('origin-only gate is bypassed by a resident shared HIT', () => {
    const p = projectAuthCache(contract, policy, model);
    const result = verifyAuthCache(p);
    expect(result.semantic.verdict).toBe('VIOLATED');
    expect(result.semantic.cells[0].witness?.request).toMatchObject({ method: 'GET', host: 'admin.example.test', path: '/api/admin/users', credential: 'absent' });
    expect(result.semantic.cells[0].witness?.trace).toEqual(['viewer-request', 'cache-lookup', 'HIT', 'protected-response']);
    expect(checkAuthCacheWitness(p, result.semantic.cells[0].witness!)).toBe(true);
  });
  test('viewer gate covers every modeled credential state and cache path', () => {
    expect(verifyAuthCache(projectAuthCache(contract, policy, { ...model, associations: [{ rule: 0, phase: 'viewer-request' }] })).semantic.verdict).toBe('VERIFIED');
  });
  test('missing cache key cannot establish a bypass', () => {
    const m = structuredClone(model); delete (m.cache as Partial<typeof m.cache>).key;
    expect(verifyAuthCache(projectAuthCache(contract, policy, m)).semantic.verdict).toBe('UNKNOWN');
  });
  test('bad explicit time is Error, not UNKNOWN', () => {
    expect(() => projectAuthCache(contract, policy, { ...model, nowMs: -1 })).toThrow();
  });
});

test.each(['enabled','cacheable','expired','different-path','different-credential','different-location','empty'] as const)('valid %s setting makes only MISS reachable', variant => {
  const m = structuredClone(model);
  if(variant==='enabled') m.cache.enabled=false;
  if(variant==='cacheable') m.cache.cacheable=false;
  if(variant==='expired') m.nowMs=6000;
  if(variant==='different-path') m.cache.fills[0].request.path='/api/admin/other';
  if(variant==='different-credential') m.cache.key.credential='partitioned';
  if(variant==='different-location') m.cache.fills[0].location='edge-2';
  if(variant==='empty') m.cache.fills=[];
  const p=projectAuthCache(contract,policy,m), report=verifyAuthCache(p);
  expect(report.semantic.cells[0].verdict).toBe('VERIFIED');
  expect(report.semantic.verdict).toBe(variant==='different-credential'?'VIOLATED':'VERIFIED');
  const original=verifyAuthCache(projectAuthCache(contract,policy,model)).semantic.cells[0].witness!;
  expect(()=>checkAuthCacheWitness(p,{...original,inputDigest:p.digest})).toThrow('INVALID_AUTH_CACHE_WITNESS');
});

test.each(['cache','cacheable','ttlMs','fills','associations','effects','flow','originResponds'] as const)('missing %s is never invented', field=>{
  const m: any=structuredClone(model);
  if(['cacheable','ttlMs','fills'].includes(field)) delete m.cache[field]; else delete m[field];
  expect(verifyAuthCache(projectAuthCache(contract,policy,m)).semantic.verdict).toBe('UNKNOWN');
});

test('viewer proof dominates unknown later cache state, while exceptions still prevent VERIFIED',()=>{
  const m:any={...model,associations:[{rule:0,phase:'viewer-request'}]};delete m.cache;
  expect(verifyAuthCache(projectAuthCache(contract,policy,m)).semantic.verdict).toBe('VERIFIED');
  m.effects=[{kind:'custom-error',paths:['/api/admin/users']}];
  expect(verifyAuthCache(projectAuthCache(contract,policy,m)).semantic.cells[0].reason).toBe('UNSUPPORTED_CUSTOM-ERROR');
});

test('UNKNOWN scope remains separate from a known counterexample',()=>{
  const c=structuredClone(contract); c.operations.push({...structuredClone(c.operations[0]),path:'/api/admin/settings'});
  const m:any={...model,effects:[{kind:'redirect',paths:['/api/admin/settings']}]};
  const result=verifyAuthCache(projectAuthCache(c,policy,m));
  expect(result.semantic.verdict).toBe('VIOLATED');
  expect(result.semantic.cells.map(c=>[c.routeKey,c.verdict])).toEqual([['GET /api/admin/settings','UNKNOWN'],['GET /api/admin/settings','UNKNOWN'],['GET /api/admin/users','VIOLATED'],['GET /api/admin/users','VIOLATED']]);
  expect(result.findings).toHaveLength(2);
});

test('finite domain is exhaustively enumerated across hosts and methods',()=>{
  const c=structuredClone(contract); c.operations.push({...structuredClone(c.operations[0]),method:'HEAD'});
  const pol=structuredClone(policy); pol.request!.allowed_hosts=['*.example.test'];
  const m:any={...model,hosts:['second.example.test','admin.example.test'],associations:[{rule:0,phase:'viewer-request'}]};
  const result=verifyAuthCache(projectAuthCache(c,pol,m));
  expect(result.semantic.cells).toHaveLength(8); expect(result.semantic.verdict).toBe('VERIFIED');
});

test('path segment boundary is a bypass on reachable MISS; declaration is not enforcement',()=>{
  const c=structuredClone(contract);c.operations[0].path='/api/administrator';
  const m={...model,cache:{...model.cache,enabled:false}};
  const p=projectAuthCache(c,policy,m),r=verifyAuthCache(p);
  expect(r.semantic.verdict).toBe('VIOLATED');expect(r.semantic.cells[0].witness?.cache).toBe('MISS');
  expect(checkAuthCacheWitness(p,r.semantic.cells[0].witness!)).toBe(true);
});

test('different host/method outside admission cannot be invented as a bypass',()=>{
  const m:any={...model,hosts:['outside.example.test'],cache:{enabled:false}};
  expect(verifyAuthCache(projectAuthCache(contract,policy,m)).semantic.cells[0].reason).toBe('GLOBAL_ADMISSION_OUTSIDE_MODEL');
  const c=structuredClone(contract);c.operations[0].method='POST';
  expect(verifyAuthCache(projectAuthCache(c,policy,model)).semantic.verdict).toBe('UNKNOWN');
});

test('unsupported templates and incomplete IR remain UNKNOWN instead of testing one path',()=>{
  const c=structuredClone(contract);c.operations[0].path='/api/admin/{id}';
  expect(verifyAuthCache(projectAuthCache(c,policy,model)).semantic.cells[0].reason).toBe('PATH_DOMAIN_UNSUPPORTED');
  c.capabilities.routes='partial';
  expect(verifyAuthCache(projectAuthCache(c,policy,model)).semantic.cells[0].reason).toBe('IR_COVERAGE_INCOMPLETE');
});

test.each(['method','host','path','credential','routeKey','trace','fill','inputDigest'] as const)('independent replay rejects changed witness %s',field=>{
  const p=projectAuthCache(contract,policy,model); const w=structuredClone(verifyAuthCache(p).semantic.cells[0].witness!);
  if(field==='method') w.request.method='POST';
  if(field==='host') w.request.host='outside.example.test';
  if(field==='path') w.request.path='/api/administrator';
  if(field==='credential') (w.request as any).credential='forged';
  if(field==='routeKey') w.routeKey='GET /other';
  if(field==='trace') w.trace.splice(1,0,'origin-request');
  if(field==='fill') w.fill!.storedAtMs=0;
  if(field==='inputDigest') w.inputDigest='wrong';
  expect(()=>checkAuthCacheWitness(p,w)).toThrow('INVALID_AUTH_CACHE_WITNESS');
});

test('viewer-phase mutation invalidates the old bypass independently',()=>{
  const old=verifyAuthCache(projectAuthCache(contract,policy,model)).semantic.cells[0].witness!;
  const p=projectAuthCache(contract,policy,{...model,associations:[{rule:0,phase:'viewer-request'}]});
  expect(()=>checkAuthCacheWitness(p,{...old,inputDigest:p.digest})).toThrow();
});

test.each(['future','negative','duplicate','absent-fill','unknown-field','too-many','bad-policy','bad-model'] as const)('invalid %s is Error',variant=>{
  const m:any=structuredClone(model), pol:any=structuredClone(policy);
  if(variant==='future')m.cache.fills[0].storedAtMs=m.nowMs;
  if(variant==='negative')m.cache.ttlMs=-1;
  if(variant==='duplicate')m.associations.push(m.associations[0]);
  if(variant==='absent-fill')m.cache.fills[0].request.credential='absent';
  if(variant==='unknown-field')m.implicitBypass=true;
  if(variant==='too-many')m.hosts=Array.from({length:17},(_,i)=>`host${i}.test`);
  if(variant==='bad-policy')pol.version=999;
  if(variant==='bad-model')m.version=999;
  expect(()=>projectAuthCache(contract,pol,m)).toThrow();
});

test('no protected domain or zero findings is not proof',()=>{
  const c=structuredClone(contract);c.operations=[];
  const report=verifyAuthCache(projectAuthCache(c,policy,model));
  expect(report.findings).toHaveLength(0);expect(report.semantic.verdict).toBe('UNKNOWN');
  const m:any=structuredClone(model);delete m.cache.key;
  const unknown=verifyAuthCache(projectAuthCache(contract,policy,m));
  expect(unknown.findings).toHaveLength(0);expect(unknown.semantic.verdict).toBe('UNKNOWN');
});

test('semantic evidence is deterministic across input object/set order and metadata time',()=>{
  const m:any={...model,hosts:['second.example.test','admin.example.test']};
  const pol=structuredClone(policy);pol.request!.allowed_hosts=['*.example.test'];
  const p1=projectAuthCache(contract,pol,m);
  const p2=projectAuthCache(JSON.parse(JSON.stringify(contract)),pol,{...m,hosts:[...m.hosts].reverse()});
  const a=verifyAuthCache(p1,{generatedAt:'2026-01-01T00:00:00.000Z'}),b=verifyAuthCache(p2,{generatedAt:'2026-10-24T00:00:00.000Z'});
  expect(a.semanticDigest).toBe(b.semanticDigest);expect(a.semantic).toEqual(b.semantic);expect(a.metadata).not.toEqual(b.metadata);
  expect(a.findings[0]).toMatchObject({severity:'error',confidence:'deterministic',remediation:{safeAutoFix:false}});
  expect(a.artifacts).toHaveLength(4);
  const changed=verifyAuthCache(projectAuthCache(contract,pol,{...m,nowMs:2001}));
  expect(changed.semanticDigest).not.toBe(a.semanticDigest);
});

test.each(['origin-response','viewer-response','unknown'] as const)('valid but unsupported %s association stays scoped UNKNOWN', phase=>{
  const m={...model,associations:[{rule:0,phase}]};
  expect(verifyAuthCache(projectAuthCache(contract,policy,m)).semantic.verdict).toBe('UNKNOWN');
});

test('past fill with an unsupported effect cannot be assumed reachable',()=>{
  const m={...model,hosts:['admin.example.test','fill.example.test'],effects:[{kind:'bypass' as const,hosts:['fill.example.test']}],cache:structuredClone(model.cache)};
  const pol=structuredClone(policy);pol.request!.allowed_hosts=['*.example.test'];m.cache.fills[0].request.host='fill.example.test';
  expect(verifyAuthCache(projectAuthCache(contract,pol,m)).semantic.cells[0].verdict).toBe('UNKNOWN');
});

test('credential partition does not prove auth application for valid-credential HITs',()=>{
  const m=structuredClone(model);m.cache.key.credential='partitioned';
  const r=verifyAuthCache(projectAuthCache(contract,policy,m));
  expect(r.semantic.cells.map(c=>[c.credential,c.verdict])).toEqual([['absent','VERIFIED'],['valid','VIOLATED']]);
  expect(r.semantic.cells[1].witness!.request.credential).toBe('valid');
});

test('viewer Host key partition makes another host MISS, without inventing a HIT',()=>{
  const m=structuredClone(model);m.hosts.push('second.example.test');m.cache.key.host='viewer';
  const pol=structuredClone(policy);pol.request!.allowed_hosts=['*.example.test'];
  const p=projectAuthCache(contract,pol,m),r=verifyAuthCache(p),w=structuredClone(r.semantic.cells[0].witness!);
  expect(r.semantic.cells.filter(c=>c.host==='second.example.test').every(c=>c.verdict==='VERIFIED')).toBe(true);
  w.request.host='second.example.test';expect(()=>checkAuthCacheWitness(p,w)).toThrow();
});

test('TTL exact expiration boundary and zero TTL are valid MISS settings',()=>{
  for(const ttlMs of [0,1000]) {
    const m={...model,cache:{...model.cache,ttlMs}};
    expect(verifyAuthCache(projectAuthCache(contract,policy,m)).semantic.verdict).toBe('VERIFIED');
  }
  const live={...model,cache:{...model.cache,ttlMs:1001}};
  expect(verifyAuthCache(projectAuthCache(contract,policy,live)).semantic.verdict).toBe('VIOLATED');
});

test('a fabricated MISS cannot bypass a known resident HIT',()=>{
  const p=projectAuthCache(contract,policy,model);const w=structuredClone(verifyAuthCache(p).semantic.cells[0].witness!);
  w.cache='MISS';delete w.fill;w.trace=['viewer-request','cache-lookup','MISS','origin-request','protected-response'];
  expect(()=>checkAuthCacheWitness(p,w)).toThrow();
});

test('input order, projection mutation, cycles and accessors respect the bounded JSON boundary',()=>{
  const c=structuredClone(contract);c.operations.push({...structuredClone(c.operations[0]),path:'/api/admin/a'});
  const a=verifyAuthCache(projectAuthCache(c,policy,model));c.operations.reverse();
  expect(verifyAuthCache(projectAuthCache(c,policy,model)).semanticDigest).toBe(a.semanticDigest);
  const p=projectAuthCache(contract,policy,model);expect(()=>{p.model.nowMs++;verifyAuthCache(p);}).toThrow();
  expect(()=>verifyAuthCache(structuredClone(p))).toThrow('PROJECTION_BINDING');
  const cyclic:any=structuredClone(model);cyclic.cache.fills.push(cyclic);
  expect(()=>projectAuthCache(contract,policy,cyclic)).toThrow();
  const accessor={...model};Object.defineProperty(accessor,'nowMs',{get(){throw new Error('getter must not execute');},enumerable:true});
  expect(()=>projectAuthCache(contract,policy,accessor)).toThrow('INVALID_JSON_ACCESSOR');
});


test('source provenance is a separate artifact binding, not changed security meaning',()=>{
  const changed=structuredClone(contract);changed.operations[0].provenance[0].digest='sha256:other-source-bytes';
  const a=verifyAuthCache(projectAuthCache(contract,policy,model));
  const b=verifyAuthCache(projectAuthCache(changed,policy,model));
  expect(b.semanticDigest).toBe(a.semanticDigest);
  expect(b.artifacts.find(x=>x.name==='security-ir.json')!.digest).not.toBe(a.artifacts.find(x=>x.name==='security-ir.json')!.digest);
});

test('root prefix follows actual equal-or-prefix-plus-slash semantics',()=>{
  const pol=structuredClone(policy);pol.routes![0].match.path_prefixes=['/'];
  const m={...model,associations:[{rule:0,phase:'viewer-request' as const}],cache:{enabled:false}};
  expect(verifyAuthCache(projectAuthCache(contract,pol,m)).semantic.verdict).toBe('VIOLATED');
  const c=structuredClone(contract);c.operations[0].path='/';
  expect(verifyAuthCache(projectAuthCache(c,pol,m)).semantic.verdict).toBe('VERIFIED');
});

test('independent checker needs explicit associations even when no gate matches',()=>{
  const pol=structuredClone(policy);pol.routes![0].match.path_prefixes=['/other'];
  const m={...model,associations:[],cache:{enabled:false}};
  const old=verifyAuthCache(projectAuthCache(contract,pol,m)).semantic.cells[0].witness!;
  const missing={...m};delete (missing as any).associations;
  const p=projectAuthCache(contract,pol,missing);
  expect(verifyAuthCache(p).semantic.verdict).toBe('UNKNOWN');
  expect(()=>checkAuthCacheWitness(p,{...old,inputDigest:p.digest})).toThrow();
});

test('ambiguous resident slot is Error; older fill cannot be selected over another fill',()=>{
  const m=structuredClone(model);m.hosts.push('second.example.test');
  m.cache.fills.push({...structuredClone(m.cache.fills[0]),storedAtMs:1500,request:{...m.cache.fills[0].request,host:'second.example.test'}});
  m.effects=[{kind:'unknown',hosts:['second.example.test']}];
  const pol=structuredClone(policy);pol.request!.allowed_hosts=['*.example.test'];
  expect(()=>projectAuthCache(contract,pol,m)).toThrow('DUPLICATE_RESIDENT_SLOT');
  const original=projectAuthCache(contract,policy,model),w=verifyAuthCache(original).semantic.cells[0].witness!;
  const p=structuredClone(original);
  p.model.cache!.fills!.push({...structuredClone(w.fill!),storedAtMs:1500});
  expect(()=>checkAuthCacheWitness(p,w)).toThrow();
});

test('canonical Policy source artifact and consumed schema have exact bindings',()=>{
  const r=verifyAuthCache(projectAuthCache(contract,policy,model));
  const source=r.artifacts.find(a=>a.name==='model/policy.json');expect(source).toBeDefined();
  const surface=JSON.parse(r.artifacts.find(a=>a.name==='allowed-surface.json')!.content);
  expect(surface.provenance[0]).toMatchObject({uri:source!.name,digest:source!.digest});
  expect(JSON.parse(source!.content)).toEqual(policy);
  expect(r.validationSchema).toMatchObject({uri:'policy/schema.json',digest:expect.stringMatching(/^sha256:[a-f0-9]{64}$/)});
});

test('Policy source artifact rejects secret-like values before any artifact is returned',()=>{
  const pol=structuredClone(policy);pol.routes![0].auth_gate!.credentials_env='Bearer synthetic-not-a-real-secret';
  expect(()=>projectAuthCache(contract,pol,model)).toThrow('SECRET_LIKE_POLICY_VALUE');
});


test.each(['policy-content','policy-name','policy-digest','schema-uri','schema-digest'] as const)('frozen constructor boundary rejects %s replacement',field=>{
  const p=projectAuthCache(contract,policy,model);
  expect(()=>{
    if(field==='policy-content')p.policyArtifact.content='{}';
    if(field==='policy-name')p.policyArtifact.name='unbound.json';
    if(field==='policy-digest')p.policyArtifact.digest='sha256:'+ '0'.repeat(64);
    if(field==='schema-uri')p.validationSchema.uri='unbound-schema.json';
    if(field==='schema-digest')p.validationSchema.digest='sha256:'+ '0'.repeat(64);
    verifyAuthCache(p);
  }).toThrow();
  expect(Object.isFrozen(p)).toBe(true);expect(Object.isFrozen(p.policyArtifact)).toBe(true);expect(Object.isFrozen(p.validationSchema)).toBe(true);
  expect(verifyAuthCache(p).semantic.verdict).toBe('VIOLATED');
});

test.each(['origin-request','viewer-request'] as const)('new enforced blocked-header boundary remains UNKNOWN before %s auth',phase=>{
  const pol=structuredClone(policy);pol.request!.block!.header_present=['authorization'];
  const r=verifyAuthCache(projectAuthCache(contract,pol,{...model,associations:[{rule:0,phase}]}));
  expect(r.semantic.verdict).toBe('UNKNOWN');
  expect(r.semantic.cells.every(c=>c.reason==='HEADER_ADMISSION_UNMODELED')).toBe(true);
});

test('independent replay rejects a witness whose header admission is no longer modeled',()=>{
  const old=verifyAuthCache(projectAuthCache(contract,policy,model)).semantic.cells[0].witness!;
  const pol=structuredClone(policy);pol.request!.block!.header_present=['authorization'];
  const p=projectAuthCache(contract,pol,model);
  expect(()=>checkAuthCacheWitness(p,{...old,inputDigest:p.digest})).toThrow('INVALID_AUTH_CACHE_WITNESS');
});

test.each(['origin-request','viewer-request'] as const)('monitor-only blocked header cannot change %s auth application',phase=>{
  const pol=structuredClone(policy);pol.defaults!.mode='monitor';pol.request!.block!.header_present=['authorization'];
  const r=verifyAuthCache(projectAuthCache(contract,pol,{...model,associations:[{rule:0,phase}]}));
  expect(r.semantic.verdict).toBe(phase==='origin-request'?'VIOLATED':'VERIFIED');
});

test.each([
  ['Unicode', '/api/café', false],
  ['nonliteral punctuation', '/api/user+id', false],
  ['overlong', '/'+'a'.repeat(2048), false],
  ['root', '/', true],
  ['ASCII segments', '/api/Users_~.-/user-1', true],
  ['maximum length', '/'+'a'.repeat(2047), true],
] as const)('independent replay enforces the literal-path domain: %s', (_name,path,supported)=>{
  const c=structuredClone(contract);c.operations[0].path=path;
  const pol=structuredClone(policy);pol.routes![0].match.path_prefixes=['/unrelated'];
  const p=projectAuthCache(c,pol,{...model,associations:[],cache:{enabled:false}});
  const report=verifyAuthCache(p),op=p.contract.operations[0];
  const w={inputDigest:p.digest,routeKey:op.routeKey,request:{method:op.method,host:'admin.example.test',path:op.path,credential:'absent' as const},cache:'MISS' as const,trace:['viewer-request','cache-lookup','MISS','origin-request','protected-response']};
  if(supported){
    expect(report.semantic.verdict).toBe('VIOLATED');
    expect(checkAuthCacheWitness(p,w)).toBe(true);
  } else {
    expect(report.semantic.cells.every(c=>c.reason==='PATH_DOMAIN_UNSUPPORTED')).toBe(true);
    expect(report.semantic.verdict).toBe('UNKNOWN');
    expect(()=>checkAuthCacheWitness(p,w)).toThrow('INVALID_AUTH_CACHE_WITNESS');
  }
});
