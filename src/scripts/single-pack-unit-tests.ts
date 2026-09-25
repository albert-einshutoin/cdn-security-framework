import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { aggregate, collectResults, matrixRows, verifyTarball } from './single-pack';
import { assertSafeOutput, requiredChecks, requiredStepIds, requiredInputKeys, requiredOutputKeys, expectedFindingProof } from './package-journey';
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-single-pack-unit-'));
let count = 0;
function test(name: string, fn: () => void): void { fn(); count++; console.log(`OK: ${name}`); }
try {
  fs.mkdirSync(path.join(temp, 'consumer'));
  fs.writeFileSync(path.join(temp, 'candidate.tgz'), 'candidate');
  fs.writeFileSync(path.join(temp, 'consumer/package-lock.json'), '{}');
  const sha = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
  fs.mkdirSync(path.join(temp, 'validation'));
  fs.copyFileSync(path.join(__dirname, '../test/fixtures/sarif/sarif-schema-2.1.0.json'),
    path.join(temp, 'validation/sarif-schema-2.1.0.json'));
  fs.writeFileSync(path.join(temp, 'validation/official-sarif-test-validator.cjs'), 'validator');
  const m = { schemaVersion: 1 as const, source: 'a'.repeat(40), harness: 'a'.repeat(40), tree: 'b'.repeat(40), run: '123', attempt: '1', sha256: sha('candidate'), size: 9, lockSha256: sha('{}'),
    schemaSha256: crypto.createHash('sha256').update(fs.readFileSync(path.join(temp, 'validation/sarif-schema-2.1.0.json'))).digest('hex'), validatorSha256: sha('validator') };
  const e = { source: m.source, run: m.run, attempt: m.attempt, sha256: m.sha256 };
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8'));
  const resolution = Object.values(pkg.exports).filter((v: any) => typeof v === 'object').map((v: any) => v.require.slice(2));
  const dependencies = Object.fromEntries(Object.keys(pkg.dependencies).map(k => [k,'1.0.0']));
  const journeySteps = [...requiredStepIds,
    'docs-2-1', 'docs-2-2', 'docs-2-3', 'docs-5-4', 'docs-5-5', 'docs-5-6', 'docs-5-7',
    'parity-text', 'parity-json', 'parity-sarif', 'parity-github-summary',
    'parity-text', 'parity-json', 'parity-sarif', 'parity-github-summary'].map(id => {
    const exit = id === 'diff-exit-3' ? 3 : id === 'diff-exit-2'
      || ['boundary-invalid-policy', 'boundary-output-collision', 'boundary-output-symlink', 'boundary-output-hardlink', 'exception-invalid', 'exception-input-error'].includes(id) ? 2
      : id.startsWith('parity-') || id.startsWith('exception-') || id === 'rich-diff-summary'
        || id.startsWith('boundary-') ? 1 : 0;
    return { id, exit, expectedExit: exit, durationMs: 1, stdoutBytes: 1, stderrBytes: 0 };
  });
  const journey = { status: 'pass' as const, checks: [...requiredChecks], steps: journeySteps,
    outputs: Object.fromEntries(requiredOutputKeys.map(key => [key,{sha256:'e'.repeat(64),bytes:1}])),
    inputs: Object.fromEntries(requiredInputKeys.map(key => [key,'e'.repeat(64)])),
    toolchain: { node: '24.1.0' }, onlinePreparationMs: 1, offlineAcceptanceMs: 2,
    findings: expectedFindingProof.map(finding => ({ ...finding, evidence: [...finding.evidence] })) };
  const rows = matrixRows.map(row => {
    const lower = row === '18.20.8' || row === '20.16.0';
    const steps = Array.from({ length: lower ? 26 : 20 }, (_, index) => {
      const cli = !lower && index >= 13;
      const expectedExit = cli && index >= 17 ? index - 16 : 0;
      return { command: cli ? 'cdn-security-source-diff' : 'node', exit: expectedExit, expectedExit, durationMs: 1 };
    });
    return { ...m, runtime: { executable: 'node', sha256: 'f'.repeat(64), platform: 'linux', arch: 'x64' },
      row, status: 'pass' as const, node: row.includes('.') ? row : `${row}.1.0`, npm: '10.8.2',
      switchVerified: true, resolution, dependencies, steps,
      checks: lower ? ['node-rejection','resolution','no-side-effects']
        : ['package-smoke','resolution','schemas','official-sarif-schema','source-aware-cli'],
      ...(row === '24' ? { journey } : {}) };
  });
  fs.writeFileSync(path.join(temp, 'metadata.json'), JSON.stringify(m));
  test('same candidate and complete rows pass', () => { verifyTarball(temp, e); aggregate(m, rows, e, ['success','success']); });
  test('missing internal Source-aware smoke command fails closed', () => assert.throws(() => aggregate(m,
    rows.map(r => r.row === '24' ? { ...r, steps: r.steps.slice(0, 12) } : r), e, ['success','success'])));
  test('changed tarball fails', () => { fs.writeFileSync(path.join(temp, 'candidate.tgz'), 'tampered!'); assert.throws(() => verifyTarball(temp, e)); fs.writeFileSync(path.join(temp, 'candidate.tgz'), 'candidate'); });
  test('missing tarball fails', () => { fs.renameSync(path.join(temp,'candidate.tgz'),path.join(temp,'saved')); assert.throws(() => verifyTarball(temp,e));fs.renameSync(path.join(temp,'saved'),path.join(temp,'candidate.tgz')); });
  test('different source fails', () => assert.throws(() => verifyTarball(temp, { ...e, source: 'c'.repeat(40) })));
  test('another run fails', () => assert.throws(() => verifyTarball(temp, { ...e, run: '124' })));
  test('another attempt fails', () => assert.throws(() => verifyTarball(temp, { ...e, attempt: '2' })));
  test('producer digest is independent', () => assert.throws(() => verifyTarball(temp, { ...e, sha256: 'd'.repeat(64) })));
  test('consumer lock mutation fails', () => { fs.writeFileSync(path.join(temp,'consumer/package-lock.json'),'[]');assert.throws(() => verifyTarball(temp,e));fs.writeFileSync(path.join(temp,'consumer/package-lock.json'),'{}'); });
  test('official schema mutation fails', () => { fs.writeFileSync(path.join(temp,'validation/sarif-schema-2.1.0.json'),'{}');assert.throws(() => verifyTarball(temp,e));fs.copyFileSync(path.join(__dirname,'../test/fixtures/sarif/sarif-schema-2.1.0.json'),path.join(temp,'validation/sarif-schema-2.1.0.json')); });
  test('validator mutation fails', () => { fs.writeFileSync(path.join(temp,'validation/official-sarif-test-validator.cjs'),'changed');assert.throws(() => verifyTarball(temp,e));fs.writeFileSync(path.join(temp,'validation/official-sarif-test-validator.cjs'),'validator'); });
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
  test('official schema evidence missing fails', () => assert.throws(() => aggregate(m, rows.map(r => r.row === '24' ? { ...r, checks: r.checks.filter(check => check !== 'official-sarif-schema') } : r), e, ['success','success'])));
  test('installed source-diff CLI evidence missing fails', () => assert.throws(() => aggregate(m, rows.map(r => r.row === '24' ? { ...r, checks: r.checks.filter(check => check !== 'source-aware-cli') } : r), e, ['success','success'])));
  test('missing onboarding acceptance fails closed', () => assert.throws(() => aggregate(m, rows.map(r => ({ ...r, journey: undefined })), e, ['success','success'])));
  test('incomplete onboarding acceptance fails closed', () => assert.throws(() => aggregate(m, rows.map(r => r.row === '24' ? { ...r, journey: { ...journey, checks: [] } } : r), e, ['success','success'])));
  test('wrong onboarding finding fails closed', () => assert.throws(() => aggregate(m, rows.map(r => r.row === '24' ? { ...r, journey: { ...journey, findings: [{ ...journey.findings[0], ruleId: 'MISSING' }] } } : r), e, ['success','success'])));
  test('wrong onboarding exit fails closed', () => assert.throws(() => aggregate(m, rows.map(r => r.row === '24' ? { ...r, journey: { ...journey, steps: journeySteps.map(s => s.id === 'diff-exit-3' ? { ...s, exit: 0 } : s) } } : r), e, ['success','success'])));
  test('missing onboarding output digest fails closed', () => assert.throws(() => aggregate(m, rows.map(r => r.row === '24' ? { ...r, journey: { ...journey, outputs: {} } } : r), e, ['success','success'])));
  test('missing boundary scenario fails closed', () => assert.throws(() => aggregate(m, rows.map(r => r.row === '24' ? { ...r, journey: { ...journey, steps: journeySteps.filter(s => s.id !== 'boundary-ref-count') } } : r), e, ['success','success'])));
  test('missing input identity fails closed', () => assert.throws(() => aggregate(m, rows.map(r => r.row === '24' ? { ...r, journey: { ...journey, inputs: Object.fromEntries(Object.entries(journey.inputs).filter(([key]) => key !== 'privacy-openapi')) } } : r), e, ['success','success'])));
  test('onboarding privacy scanner detects raw synthetic credential', () => assert.throws(() => assertSafeOutput('Bearer SYNTHETIC_SECRET_890_VALUE', '/workspace', 'unit'), /AC_unit_PRIVACY_VALUE/));
  test('onboarding privacy scanner detects absolute workspace path', () => assert.throws(() => assertSafeOutput('/workspace/private', '/workspace', 'unit'), /AC_unit_PRIVACY_PATH/));
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
