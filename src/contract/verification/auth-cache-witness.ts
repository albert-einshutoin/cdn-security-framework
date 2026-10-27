// Concrete replay is independent of the verifier's route relation, cacheKey and cachePath helpers.
import type { Projection, Witness, ModelRequest, CacheFill } from './auth-cache';
export class AuthCacheWitnessError extends Error {
  constructor() { super('INVALID_AUTH_CACHE_WITNESS'); this.name='AuthCacheWitnessError'; }
}
function assert(v: unknown): asserts v { if(!v) throw new AuthCacheWitnessError(); }
export function checkAuthCacheWitness(p: Projection, w: Witness): true {
  const m=p.model, s=p.surface, r=w.request;
  assert(m.version===2 && ['aws','cloudflare'].includes(m.provider));
  assert(w.inputDigest===p.digest && ['absent','valid'].includes(r.credential) && m.hosts.includes(r.host));
  const op=p.contract.operations.find(o=>o.routeKey===w.routeKey);
  assert(op && op.method===r.method && op.path===r.path);
  assert(typeof r.path==='string' && r.path.length<=2048 && /^\/(?:[A-Za-z0-9_~.-]+(?:\/[A-Za-z0-9_~.-]+)*)?$/.test(r.path)
    && !r.path.split('/').some(segment=>segment==='.' || segment==='..'));
  assert(['authenticated','privileged'].includes(op.exposure) || (op.auth.mode==='alternatives' && op.auth.alternatives.every(a=>!a.anonymous)));
  assert(p.contract.capabilities.routes==='complete' && p.contract.capabilities.authentication==='complete');
  assert(m.flow==='standard' && Array.isArray(m.associations) && m.effects!==undefined && !s.defaults.pathNormalization.caseInsensitive);
  const cleanEffects=(q:ModelRequest)=>!m.effects!.some(e=>(!e.hosts||e.hosts.includes(q.host))&&(!e.methods||e.methods.includes(q.method))&&(!e.paths||e.paths.includes(q.path)));
  const admitted=(q:ModelRequest)=>s.defaults.methods.includes(q.method) && (s.defaults.hosts.kind==='any' || s.defaults.hosts.values.some(h=>h.startsWith('*.') ? q.host.endsWith(h.slice(1)) && q.host!==h.slice(2) : q.host===h.toLowerCase()));
  assert(cleanEffects(r) && admitted(r) && !(r.method==='OPTIONS' && s.defaults.corsOptionsBypass));
  assert(!(s.defaults.requestDecision==='block' && s.defaults.blockedHeaders?.values.length));
  const phases=(q:ModelRequest)=>s.orderedRules.filter(g=>g.auth.kind!=='none' && g.methods.effective.includes(q.method) && g.match.authEffectiveValues.some(prefix=>q.path===prefix||q.path.startsWith(prefix+'/'))).map(g=>{
    const a=m.associations?.find(a=>a.rule===g.index);
    const allowed=m.provider==='aws'?['viewer-request','origin-request','unassociated']:['worker-before-cache','worker-after-cache','unassociated'];
    assert(a && allowed.includes(a.phase) && (a.phase==='unassociated' || (g.auth.verifiability[m.provider]==='enforced' && ['static_token','basic_auth'].includes(g.auth.kind))));
    return a.phase;
  });
  const before=m.provider==='aws'?'viewer-request':'worker-before-cache';
  const after=m.provider==='aws'?'origin-request':'worker-after-cache';
  const entry=m.provider==='aws'?'viewer-request':'worker';
  const origin=m.provider==='aws'?'origin-request':'origin-fetch';
  const requestPhases=phases(r);assert(!requestPhases.includes(before));
  const c=m.cache;assert(c);
  let hits:CacheFill[]=[];
  if(c.enabled && ['GET','HEAD','OPTIONS'].includes(r.method) && c.cacheable!==false && c.ttlMs!==0) {
    assert(c.key && c.cacheable===true && c.ttlMs!==undefined && c.fills!==undefined);
    let slotEntries=0;
    for(const f of c.fills) {
      const q=f.request;
      // Compare each modeled key component directly, independently of cacheKey serialization.
      const sameMethod=q.method===r.method || (['GET','HEAD'].includes(q.method)&&['GET','HEAD'].includes(r.method));
      const sameKey=q.path===r.path && sameMethod && (c.key.host==='namespace'||q.host===r.host) && (c.key.credential==='shared'||q.credential===r.credential);
      if(f.location===m.location && sameKey) slotEntries++;
      assert(slotEntries<=1);
      if(f.location===m.location && f.storedAtMs<m.nowMs && m.nowMs-f.storedAtMs<c.ttlMs && sameKey) hits.push(f);
    }
  }
  let expected:string[];
  if(w.cache==='HIT') {
    assert(m.originResponds===true && w.fill && c.enabled && c.cacheable===true && c.ttlMs!==undefined && c.key);
    const f=w.fill;
    assert(hits.some(h=>h.storedAtMs===f.storedAtMs && h.location===f.location && h.request.host===f.request.host && h.request.path===f.request.path && h.request.method===f.request.method && h.request.credential===f.request.credential));
    assert(cleanEffects(f.request) && admitted(f.request) && ['GET','HEAD','OPTIONS'].includes(f.request.method));
    const fillPhases=phases(f.request);
    assert(f.request.credential==='valid' || !fillPhases.some(phase=>phase===before||phase===after));
    expected=[entry,'cache-lookup','HIT','protected-response'];
  } else {
    assert(w.cache==='MISS' && hits.length===0 && w.fill===undefined && m.originResponds===true && !requestPhases.includes(after));
    expected=[entry,'cache-lookup','MISS',origin,'protected-response'];
  }
  assert(JSON.stringify(w.trace)===JSON.stringify(expected));
  return true;
}
