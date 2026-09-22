import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { aggregate, collectResults, matrixRows, verifyTarball } from './single-pack';
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-single-pack-unit-'));
let count = 0;
function test(name: string, fn: () => void): void { fn(); count++; console.log(`OK: ${name}`); }
try {
  fs.mkdirSync(path.join(temp, 'consumer'));
  fs.writeFileSync(path.join(temp, 'candidate.tgz'), 'candidate');
  fs.writeFileSync(path.join(temp, 'consumer/package-lock.json'), '{}');
  const sha = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
  const m = { schemaVersion: 1 as const, source: 'a'.repeat(40), harness: 'a'.repeat(40), tree: 'b'.repeat(40), run: '123', attempt: '1', sha256: sha('candidate'), size: 9, lockSha256: sha('{}') };
  const e = { source: m.source, run: m.run, attempt: m.attempt, sha256: m.sha256 };
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8'));
  const resolution = Object.values(pkg.exports).filter((v: any) => typeof v === 'object').map((v: any) => v.require.slice(2));
  const dependencies = Object.fromEntries(Object.keys(pkg.dependencies).map(k => [k,'1.0.0']));
  const rows = matrixRows.map(row => ({ ...m, runtime: { executable: 'node', sha256: 'f'.repeat(64), platform: 'linux', arch: 'x64' }, row, status: 'pass' as const, node: row.includes('.') ? row : `${row}.1.0`, npm: '10.8.2', switchVerified: true, resolution, dependencies, steps: Array.from({length:row.startsWith('18') || row === '20.16.0' ? 26 : 12},()=>({command:'node',exit:0,expectedExit:0,durationMs:1})), checks: row.startsWith('18') || row === '20.16.0' ? ['node-rejection','resolution','no-side-effects'] : ['package-smoke','resolution','schemas'] }));
  fs.writeFileSync(path.join(temp, 'metadata.json'), JSON.stringify(m));
  test('same candidate and complete rows pass', () => { verifyTarball(temp, e); aggregate(m, rows, e, ['success','success']); });
  test('changed tarball fails', () => { fs.writeFileSync(path.join(temp, 'candidate.tgz'), 'tampered!'); assert.throws(() => verifyTarball(temp, e)); fs.writeFileSync(path.join(temp, 'candidate.tgz'), 'candidate'); });
  test('missing tarball fails', () => { fs.renameSync(path.join(temp,'candidate.tgz'),path.join(temp,'saved')); assert.throws(() => verifyTarball(temp,e));fs.renameSync(path.join(temp,'saved'),path.join(temp,'candidate.tgz')); });
  test('different source fails', () => assert.throws(() => verifyTarball(temp, { ...e, source: 'c'.repeat(40) })));
  test('another run fails', () => assert.throws(() => verifyTarball(temp, { ...e, run: '124' })));
  test('another attempt fails', () => assert.throws(() => verifyTarball(temp, { ...e, attempt: '2' })));
  test('producer digest is independent', () => assert.throws(() => verifyTarball(temp, { ...e, sha256: 'd'.repeat(64) })));
  test('consumer lock mutation fails', () => { fs.writeFileSync(path.join(temp,'consumer/package-lock.json'),'[]');assert.throws(() => verifyTarball(temp,e));fs.writeFileSync(path.join(temp,'consumer/package-lock.json'),'{}'); });
  test('missing runtime identity fails', () => assert.throws(() => aggregate(m, rows.map(r => ({...r,runtime:undefined} as any)), e, ['success','success'])));
  for (const key of ['executable','sha256','platform','arch']) test(`malformed runtime ${key} fails`, () => assert.throws(() => aggregate(m, rows.map(r => ({...r,runtime:{...r.runtime,[key]:''}})), e, ['success','success'])));
  for (const key of ['npm','resolution','dependencies','steps']) test(`missing ${key} evidence fails`, () => assert.throws(() => aggregate(m, rows.map(r => ({...r,[key]:undefined} as any)), e, ['success','success'])));
  test('empty steps fail', () => assert.throws(() => aggregate(m, rows.map(r => ({...r,steps:[]})), e, ['success','success'])));
  test('failed command fails', () => assert.throws(() => aggregate(m, rows.map(r => ({...r,steps:r.steps.map(s=>({...s,exit:3}))})), e, ['success','success'])));
  test('missing runtime subfields fail without string coercion', () => assert.throws(() => aggregate(m, rows.map(r => ({...r,runtime:{...r.runtime,platform:undefined} as any})), e, ['success','success'])));
  test('missing command fails without string coercion', () => assert.throws(() => aggregate(m, rows.map(r => ({...r,steps:r.steps.map(s=>({...s,command:undefined} as any))})), e, ['success','success'])));
  test('missing switch proof fails', () => assert.throws(() => aggregate(m, rows.map(r => ({...r,switchVerified:undefined})), e, ['success','success'])));
  test('duplicate result artifacts are preserved for rejection', () => {
    const dir=path.join(temp,'results');fs.mkdirSync(dir);for(const name of ['artifact-one','artifact-two']){fs.mkdirSync(path.join(dir,name));fs.writeFileSync(path.join(dir,name,'20.17.0.json'),JSON.stringify(rows[0]));}
    assert.equal(collectResults(dir).length,2);assert.throws(()=>aggregate(m,collectResults(dir),e,['success','success']));
  });
  test('missing result fails', () => assert.throws(() => aggregate(m, rows.slice(1), e, ['success','success'])));
  test('empty results fail', () => assert.throws(() => aggregate(m, [], e, ['success','success'])));
  test('duplicate result fails', () => assert.throws(() => aggregate(m, [rows[0],rows[0],...rows.slice(2)], e, ['success','success'])));
  test('failed result fails', () => assert.throws(() => aggregate(m, rows.map((r,i) => i ? r : {...r,status:'fail'} as any), e, ['success','success'])));
  test('different consumer tarball fails', () => assert.throws(() => aggregate(m, rows.map((r,i) => i ? r : {...r,sha256:'d'.repeat(64)}), e, ['success','success'])));
  test('wrong runtime fails', () => assert.throws(() => aggregate(m, rows.map((r,i) => i ? r : {...r,node:'20.16.0'}), e, ['success','success'])));
  test('validation not executed fails', () => assert.throws(() => aggregate(m, rows.map((r,i) => i ? r : {...r,checks:[]}), e, ['success','success'])));
  for (const state of ['failure','cancelled','skipped','']) {
    test(`producer ${state || 'missing'} fails`, () => assert.throws(() => aggregate(m, rows, e, [state,'success'])));
    test(`consumer ${state || 'missing'} fails`, () => assert.throws(() => aggregate(m, rows, e, ['success',state])));
  }
} finally { fs.rmSync(temp, { recursive: true, force: true }); }
const workflow = require('js-yaml').load(fs.readFileSync(path.join(__dirname, '../.github/workflows/policy-lint.yml'), 'utf8'));
test('workflow preserves read-only triggers and all matrix rows', () => {
  assert.equal(workflow.permissions.contents, 'read'); assert.ok(workflow.on.pull_request);
  assert.ok(!workflow.on.pull_request_target);
  assert.deepEqual(workflow.jobs['package-consumer'].strategy.matrix.node, [...matrixRows]);
  assert.equal(workflow.jobs['package-acceptance'].if, 'always()');
  assert.deepEqual(workflow.jobs['package-acceptance'].needs, ['package-producer','package-consumer']);
  assert.ok(workflow.jobs['pr-package-smoke-matrix'].needs.includes('package-acceptance'));
  assert.ok(workflow.jobs['full-release-matrix'].needs.includes('package-acceptance'));
});
test('consumer has no product build/pack or privileged source checkout', () => {
  const steps = workflow.jobs['package-consumer'].steps;
  assert.ok(!steps.some((step: any) => String(step.uses).includes('checkout')));
  const commands = steps.map((step: any) => step.run || '').join('\n');
  assert.ok(!/npm (?:run build|pack)/u.test(commands));
  assert.ok(commands.includes('unshare --net')); assert.ok(commands.includes('npm ci --offline'));
  assert.ok(commands.includes('CSF_SWITCH_PROOF'));
  assert.ok(!JSON.stringify(workflow.jobs['package-consumer']).includes('secrets.'));
});
console.log(`single-pack: ${count} cases passed`);
