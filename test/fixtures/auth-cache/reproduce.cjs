// Local fixture reproduction only; not a public CLI or a cloud runner.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '../../..');
const { projectAuthCache, verifyAuthCache } = require(path.join(root,'contract/verification/auth-cache.js'));
const { checkAuthCacheWitness } = require(path.join(root,'contract/verification/auth-cache-witness.js'));
const inputPath=path.join(__dirname,'input.json');
const base=JSON.parse(fs.readFileSync(inputPath,'utf8'));
const sha=b=>'sha256:'+crypto.createHash('sha256').update(b).digest('hex');
const out=path.join(root,'reports/issue-1119/reproduction');fs.mkdirSync(out,{recursive:true});
const summary=[];
for(const name of ['origin-hit','viewer-hit','viewer-miss','origin-miss','unknown-key','invalid-time']) {
  const {contract,policy,model}=structuredClone(base);
  if(name.startsWith('viewer'))model.associations[0].phase='viewer-request';
  if(name.endsWith('miss'))model.cache.enabled=false;
  if(name==='unknown-key')delete model.cache.key;
  if(name==='invalid-time')model.nowMs=-1;
  try {
    const p=projectAuthCache(contract,policy,model),report=verifyAuthCache(p,{generatedAt:new Date().toISOString()});
    const witnesses=report.semantic.cells.filter(c=>c.witness).map(c=>checkAuthCacheWitness(p,c.witness));
    const dir=path.join(out,name);fs.mkdirSync(dir,{recursive:true});
    for(const a of report.artifacts) { if(sha(a.content)!==a.digest)throw Error('artifact binding');const file=path.join(dir,a.name);fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,a.content); }
    fs.writeFileSync(path.join(dir,'evidence.json'),JSON.stringify(report,null,2)+'\n');
    summary.push({case:name,verdict:report.semantic.verdict,semanticDigest:report.semanticDigest,independentWitnesses:witnesses.length,validationSchema:report.validationSchema});
  } catch(e) {
    if(name!=='invalid-time'||e.code!=='INVALID_MODEL')throw e;
    summary.push({case:name,error:e.name,code:e.code});
  }
}
const modules=Object.keys(require.cache).filter(p=>p.startsWith(root+path.sep)&&!p.includes('/node_modules/')).sort().map(p=>({path:path.relative(root,p).replaceAll(path.sep,'/'),digest:sha(fs.readFileSync(p))}));
fs.writeFileSync(path.join(out,'execution-receipt.json'),JSON.stringify({runtime:process.version,inputDigest:sha(fs.readFileSync(inputPath)),lockDigest:sha(fs.readFileSync(path.join(root,'package-lock.json'))),loadedRepositoryModules:modules,cloudCalls:0,summary},null,2)+'\n');
console.log(JSON.stringify(summary,null,2));
