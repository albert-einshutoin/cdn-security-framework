#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import cp from 'node:child_process';

export const matrixRows = ['20.17.0', '22', '24', '18.20.8', '20.16.0'] as const;
type Identity = { schemaVersion: 1; source: string; tree: string; harness: string; run: string; attempt: string; sha256: string; size: number; lockSha256: string;
  schemaSha256: string; validatorSha256: string };
type Step = { command: string; exit: number; expectedExit: number; durationMs: number };
type Result = Identity & { runtime: { executable: string; sha256: string; platform: string; arch: string }; row: string; status: 'pass'; node: string; npm: string; switchVerified?: boolean; checks: string[]; resolution: string[]; steps: Step[]; dependencies: Record<string, string>; journey?: import('./package-journey').JourneyResult; prefixProof?: import('./package-smoke-tests').PrefixProof; controllerOptionsProof?: import('./package-smoke-tests').ControllerOptionsProof };
const root = path.resolve(__dirname, '..');
const OFFICIAL_SARIF_SCHEMA_SHA256 = 'c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e';
const sha = (file: string) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function read(file: string): any {
  assert.ok(fs.statSync(file).isFile() && fs.statSync(file).size <= 2 * 1024 * 1024, 'invalid metadata file');
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
function write(file: string, value: unknown): void { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n'); }
function run(command: string, args: string[], cwd = root): string {
  const r = cp.spawnSync(command, args, { cwd, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
    env: { ...process.env, NODE_PATH: '', NODE_OPTIONS: '', npm_config_audit: 'false', npm_config_fund: 'false' } });
  assert.equal(r.status, 0, 'single-pack command failed'); return r.stdout;
}
export function expectedIdentity(): { source: string; run: string; attempt: string; sha256?: string } {
  const { CSF_SOURCE: source, GITHUB_RUN_ID: run, GITHUB_RUN_ATTEMPT: attempt, CSF_TGZ_SHA256: sha256 } = process.env;
  assert.ok(source && /^[a-f0-9]{40}$/.test(source) && run && /^\d+$/.test(run) && attempt && /^\d+$/.test(attempt), 'missing run identity');
  return { source, run, attempt, sha256 };
}
const expected = expectedIdentity;
export function verifyIdentity(m: Identity, e: ReturnType<typeof expected>): void {
  assert.ok(m && m.schemaVersion === 1 && m.source === e.source && m.harness === e.source && m.run === e.run && m.attempt === e.attempt, 'candidate/run identity mismatch');
  assert.match(m.tree, /^[a-f0-9]{40}$/); assert.match(m.sha256, /^[a-f0-9]{64}$/); assert.match(m.lockSha256, /^[a-f0-9]{64}$/);
  assert.equal(m.schemaSha256, OFFICIAL_SARIF_SCHEMA_SHA256, 'official schema mismatch');
  assert.match(m.validatorSha256, /^[a-f0-9]{64}$/);
  assert.ok(Number.isSafeInteger(m.size) && m.size > 0 && m.size <= 1024 * 1024, 'invalid tarball size');
  if (e.sha256 !== undefined) assert.equal(m.sha256, e.sha256, 'producer digest mismatch');
}
export function verifyTarball(directory: string, e: ReturnType<typeof expected>): Identity {
  assert.ok(e.sha256 && /^[a-f0-9]{64}$/.test(e.sha256), 'missing producer digest');
  const m = read(path.join(directory, 'metadata.json')) as Identity; verifyIdentity(m, e);
  const file = path.join(directory, 'candidate.tgz');
  assert.ok(fs.lstatSync(file).isFile(), 'missing regular tarball');
  assert.equal(fs.statSync(file).size, m.size, 'tarball size mismatch');
  assert.equal(sha(file), m.sha256, 'tarball digest mismatch');
  assert.equal(sha(path.join(directory, 'consumer/package-lock.json')), m.lockSha256, 'consumer lock mismatch');
  assert.equal(sha(path.join(directory, 'validation/sarif-schema-2.1.0.json')), m.schemaSha256, 'official schema digest mismatch');
  assert.equal(sha(path.join(directory, 'validation/official-sarif-test-validator.cjs')), m.validatorSha256, 'validator digest mismatch');
  return m;
}
export function aggregate(m: Identity, results: Result[], e: ReturnType<typeof expected>, states: string[]): void {
  verifyIdentity(m, e);
  assert.ok(states.length === 2 && states.every(s => s === 'success'), 'producer/consumer did not succeed');
  assert.equal(results.length, matrixRows.length, 'missing or extra consumer result');
  assert.equal(new Set(results.map(r => r.row)).size, matrixRows.length, 'duplicate consumer result');
  for (const row of matrixRows) {
    const r = results.find(r => r.row === row); assert.ok(r, 'missing required row'); verifyIdentity(r, e);
    for (const k of ['sha256', 'size', 'tree', 'lockSha256', 'schemaSha256', 'validatorSha256'] as const) assert.equal(r[k], m[k], 'consumer artifact mismatch');
    assert.equal(r.status, 'pass', 'failed consumer');
    assert.ok(r.runtime && ['executable','sha256','platform','arch'].every(k => typeof (r.runtime as any)[k] === 'string') && /^node(?:\.exe)?$/.test(r.runtime.executable) && /^[a-f0-9]{64}$/.test(r.runtime.sha256) && /^[a-z0-9_-]+$/.test(r.runtime.platform) && /^[a-z0-9_]+$/.test(r.runtime.arch), 'missing or invalid runtime identity');
    if (row === '18.20.8' || row === '20.16.0') assert.equal(r.switchVerified, true, 'missing supported-install switch proof');
    assert.ok(r.node === row || (['22', '24'].includes(row) && r.node.startsWith(row + '.')), 'wrong consumer Node');
    assert.match(r.npm, /^\d+\.\d+\.\d+$/);
    const pkg = read(path.join(root, 'package.json'));
    const entries = Object.values(pkg.exports).filter((v: any) => typeof v === 'object').map((v: any) => v.require.slice(2));
    assert.deepEqual(r.resolution, entries, 'missing or invalid module resolution');
    assert.ok(r.dependencies && Object.keys(r.dependencies).sort().join() === Object.keys(pkg.dependencies).sort().join(), 'missing dependency evidence');
    assert.ok(Object.values(r.dependencies).every(v => /^\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?$/.test(v)), 'invalid dependency version');
    const lower = row === '18.20.8' || row === '20.16.0';
    assert.ok(Array.isArray(r.steps) && r.steps.length === (lower ? 26 : row === '24' ? 55 : 37), 'missing command evidence');
    assert.ok(r.steps.every(s => s && typeof s.command === 'string' && /^[a-zA-Z0-9_.-]+$/.test(s.command) && Number.isFinite(s.durationMs) && s.durationMs >= 0 && s.exit === s.expectedExit && (s.expectedExit === 0 || (lower && s.expectedExit === 1) || (s.command === 'cdn-security-source-diff' && [1, 2, 3].includes(s.expectedExit)) || (s.command === 'cdn-security-source-auth-config' && s.expectedExit === 2) || (s.command === 'cdn-security-source-save' && [1, 2, 3].includes(s.expectedExit)) || (s.command === 'cdn-security-source-prefix' && row === '24' && s.expectedExit === 2) || (s.command === 'cdn-security-controller-options' && row === '24' && s.expectedExit === 1))), 'invalid command evidence');
    if (!lower) assert.deepEqual(r.steps.filter(s => s.command === 'cdn-security-source-diff').map(s => s.expectedExit), [0, 0, 0, 0, 1, 2, 3], 'missing installed CLI exit proof');
    if (!lower) assert.deepEqual(r.steps.filter(s => s.command === 'cdn-security-source-auth-config').map(s => s.expectedExit), [0, 0, 0, 0, 0, 0, 2, 2], 'missing configured CLI exit proof');
    if (!lower) assert.deepEqual(r.steps.filter(s => s.command === 'cdn-security-source-save').map(s => s.expectedExit), [0, 0, 0, 0, 0, 1, 2, 2, 3], 'missing installed safe-save exit proof');
    assert.deepEqual(r.checks, lower ? ['node-rejection', 'resolution', 'no-side-effects'] : ['package-smoke', 'resolution', 'schemas', 'official-sarif-schema', 'source-aware-cli', 'source-auth-config', 'source-safe-output', ...(row === '24' ? ['source-global-prefix', 'source-controller-options'] : [])]);
    if (row === '24') {
      assert.deepEqual(r.steps.filter(s => s.command === 'cdn-security-source-prefix').map(s => s.expectedExit),
        [0, 0, 0, 0, 0, 2, 2, 0], 'missing installed prefix scenarios');
      const prefix = r.prefixProof;
      assert.ok(prefix && Object.keys(prefix).sort().join() === [
        'globalPrefix', 'projectDigest', 'configDigest', 'routingDigest',
        'comparisonContractDigest', 'savedSha256', 'inputSha256',
        'unprefixedInventory', 'prefixedInventory'].sort().join(),
      'missing installed prefix identity');
      assert.equal(prefix.globalPrefix, '/api');
      for (const key of ['projectDigest', 'configDigest', 'routingDigest', 'comparisonContractDigest'] as const) {
        assert.match(prefix[key], /^sha256:[a-f0-9]{64}$/);
      }
      assert.match(prefix.savedSha256, /^[a-f0-9]{64}$/);
      assert.match(prefix.inputSha256, /^[a-f0-9]{64}$/);
      assert.deepEqual(prefix.unprefixedInventory, { sourceOnly: 2, declaredOnly: 1, methodMismatch: 1 },
        'missing decorator-local comparison evidence');
      assert.deepEqual(prefix.prefixedInventory, { sourceOnly: 6, declaredOnly: 5, methodMismatch: 0 },
        'missing explicit-prefix comparison evidence');
      assert.deepEqual(r.steps.filter(s => s.command === 'cdn-security-controller-options').map(s => s.expectedExit),
        [0, 0, 0, 0, 0, 1], 'missing installed Controller object CLI scenarios');
      assert.deepEqual(r.steps.filter(s => s.command === 'source-aware-ci-object').map(s => s.expectedExit),
        [0, 0, 0, 0], 'missing installed Controller object CI driver scenarios');
      const object = r.controllerOptionsProof;
      assert.ok(object && Object.keys(object).sort().join() === [
        'inputSha256', 'savedSha256', 'ciRecordSha256', 'routes', 'unsupportedCode', 'ciDelivery',
      ].sort().join(), 'missing installed Controller object identity');
      for (const key of ['inputSha256', 'savedSha256', 'ciRecordSha256'] as const) {
        assert.match(object[key], /^[a-f0-9]{64}$/);
      }
      assert.deepEqual(object.routes, ['GET /users/items']);
      assert.equal(object.unsupportedCode, 'SOURCE_ANALYZER_UNSUPPORTED_DECORATOR');
      assert.equal(object.ciDelivery, 'CI_OK');
      const j = r.journey;
      const { requiredChecks: required, requiredStepIds, requiredInputKeys, requiredOutputKeys, expectedFindingProof } = require('./package-journey') as typeof import('./package-journey');
      assert.ok(j && j.status === 'pass' && Array.isArray(j.checks), 'missing onboarding acceptance');
      assert.deepEqual(j.checks, required, 'incomplete onboarding acceptance');
      assert.ok(Array.isArray(j.steps) && j.steps.length > 0 && j.steps.every(s => s.exit === s.expectedExit && Number.isFinite(s.durationMs) && s.durationMs >= 0), 'invalid onboarding command evidence');
      assert.deepEqual([...new Set(j.steps.map(s => s.expectedExit))].sort(), [0, 1, 2, 3], 'missing exit-code evidence');
      for (const id of requiredStepIds) {
        assert.ok(j.steps.some(s => s.id === id), `missing onboarding step ${id}`);
      }
      assert.ok(j.steps.filter(s => s.id.startsWith('docs-2-')).length >= 3
        && j.steps.filter(s => s.id.startsWith('docs-5-')).length >= 4
        && j.steps.filter(s => s.id.startsWith('parity-')).length >= 12,
      'missing repeated onboarding steps');
      assert.ok(Number.isFinite(j.onlinePreparationMs) && j.onlinePreparationMs >= 0 && Number.isFinite(j.offlineAcceptanceMs) && j.offlineAcceptanceMs > 0, 'missing onboarding timing');
      assert.ok(Object.keys(j.inputs).length >= 5 && Object.values(j.inputs).every(v => /^[a-f0-9]{64}$/.test(v)), 'missing input digests');
      assert.ok(Object.keys(j.outputs).length >= 6 && Object.values(j.outputs).every(v => /^[a-f0-9]{64}$/.test(v.sha256) && Number.isSafeInteger(v.bytes) && v.bytes > 0), 'missing output digests');
      for (const key of requiredInputKeys) assert.ok(j.inputs[key], `missing onboarding input ${key}`);
      for (const key of requiredOutputKeys) assert.ok(j.outputs[key], `missing onboarding output ${key}`);
      assert.deepEqual(j.findings, expectedFindingProof, 'missing onboarding finding proof');
    }
  }
}
export function collectResults(directory: string): Result[] {
  const files: string[] = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name);
    assert.ok(!entry.isSymbolicLink(), 'unsafe result entry');
    if (entry.isDirectory()) {
      const members = fs.readdirSync(file, { withFileTypes: true });
      assert.equal(members.length, 1, 'unexpected result artifact contents');
      assert.ok(members[0].isFile() && members[0].name.endsWith('.json'), 'invalid result artifact');
      files.push(path.join(file, members[0].name));
    } else { assert.ok(entry.isFile() && entry.name.endsWith('.json'), 'invalid result file'); files.push(file); }
  }
  return files.map(read);
}
function produce(directory: string): void {
  const e = expected(); assert.equal(run('git', ['rev-parse', 'HEAD']).trim(), e.source, 'checkout mismatch');
  assert.equal(run('git', ['status', '--porcelain']).trim(), '', 'producer requires clean source');
  fs.mkdirSync(directory, { recursive: true });
  const packs = JSON.parse(run('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', directory]));
  assert.equal(packs.length, 1); const pack = packs[0];
  fs.renameSync(path.join(directory, pack.filename), path.join(directory, 'candidate.tgz')); write(path.join(directory, 'pack.json'), pack);
  const consumer = path.join(directory, 'consumer');
  write(path.join(consumer, 'package.json'), { name: 'csf-isolated-consumer', version: '1.0.0', private: true, dependencies: { 'cdn-security-framework': 'file:../candidate.tgz' } });
  run('npm', ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'], consumer);
  for (const file of ['scripts/single-pack.js', 'scripts/package-smoke-tests.js', 'scripts/package-journey.js', 'docs/api-manifest.json', 'package.json']) {
    fs.mkdirSync(path.dirname(path.join(directory, file)), { recursive: true }); fs.copyFileSync(path.join(root, file), path.join(directory, file));
  }
  const validation = path.join(directory, 'validation');
  fs.mkdirSync(validation, { recursive: true });
  fs.copyFileSync(path.join(root, 'test/fixtures/sarif/sarif-schema-2.1.0.json'), path.join(validation, 'sarif-schema-2.1.0.json'));
  const { buildSync } = require('esbuild') as typeof import('esbuild');
  buildSync({ entryPoints: [path.join(root, 'scripts/official-sarif-test-validator.js')],
    outfile: path.join(validation, 'official-sarif-test-validator.cjs'), bundle: true, platform: 'node',
    format: 'cjs', target: 'node20', logLevel: 'silent' });
  const m: Identity = { schemaVersion: 1, source: e.source, harness: e.source, tree: run('git', ['rev-parse', 'HEAD^{tree}']).trim(), run: e.run, attempt: e.attempt,
    sha256: sha(path.join(directory, 'candidate.tgz')), size: fs.statSync(path.join(directory, 'candidate.tgz')).size, lockSha256: sha(path.join(consumer, 'package-lock.json')),
    schemaSha256: sha(path.join(validation, 'sarif-schema-2.1.0.json')),
    validatorSha256: sha(path.join(validation, 'official-sarif-test-validator.cjs')) };
  verifyIdentity(m, e); write(path.join(directory, 'metadata.json'), m);
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `sha256=${m.sha256}\n`);
  console.log(JSON.stringify(m));
}
function checkResolution(consumer: string): { resolution: string[]; dependencies: Record<string, string> } {
  return JSON.parse(run(process.execPath, ['-e', `
    const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
    const p=fs.realpathSync('node_modules/cdn-security-framework');const pkg=require(path.join(p,'package.json'));
    const entries=Object.keys(pkg.exports).filter(k=>typeof pkg.exports[k]==='object');
    const resolution=entries.map(k=>{const x=fs.realpathSync(require.resolve('cdn-security-framework'+(k==='.'?'':k.slice(1))));assert.ok(x.startsWith(p+path.sep));return path.relative(p,x)});
    assert.equal(fs.realpathSync('node_modules/.bin/cdn-security'),path.join(p,'bin/cli.js'));
    const req=require('node:module').createRequire(path.join(p,'package.json'));const dependencies={};
    for(const key of Object.keys(pkg.dependencies)) {let file;try{file=req.resolve(key+'/package.json');}catch{let dir=path.dirname(req.resolve(key));while(!fs.existsSync(path.join(dir,'package.json')))dir=path.dirname(dir);file=path.join(dir,'package.json');}const dependency=JSON.parse(fs.readFileSync(file));assert.equal(dependency.name,key);dependencies[key]=dependency.version;}
    console.log(JSON.stringify({resolution,dependencies}));
  `], consumer));
}
function rejection(consumer: string): Step[] {
  const steps: Step[] = [];
  const pkgRoot = path.join(consumer, 'node_modules/cdn-security-framework'); const pkg = read(path.join(pkgRoot, 'package.json'));
  const entries = [...new Set([...Object.values(pkg.exports).flatMap((v: any) => typeof v === 'object' ? [v.require.slice(2)] : v.endsWith('.js') ? [v.slice(2)] : []),
    ...['cli-doctor','compile','compile-cloudflare','compile-cloudflare-waf','compile-infra','policy-lint'].map(n => `scripts/${n}.js`)])];
  const before = fs.readdirSync(consumer).sort();
  const policyHash = sha(path.join(pkgRoot, 'policy/base.yml'));
  for (const entry of entries) {
    const file = path.join(pkgRoot, entry);
    const start = process.hrtime.bigint();
    const child = cp.spawnSync(process.execPath, ['-e', `
      const assert=require('node:assert/strict'),Module=require('node:module');
      const original=Module._load;Module._load=function(id,...args){ if(!id.startsWith('.')&&!id.startsWith('/')&&!id.startsWith('node:')) throw new Error('dependency loaded before guard');return original.call(this,id,...args); };
      let caught=false;try{require(process.argv[1]);}catch(e){assert.equal(e.code,'ERR_CSF_UNSUPPORTED_NODE');assert.equal(e.required,'>=20.17.0');assert.equal(e.current,process.versions.node);caught=true;}assert.ok(caught);console.log('caught');
    `, file], { cwd: consumer, encoding: 'utf8', env: { ...process.env, NODE_PATH: '', NODE_OPTIONS: '' } });
    steps.push({command:'node',exit:child.status ?? -1,expectedExit:0,durationMs:Number(process.hrtime.bigint()-start)/1e6});
    assert.equal(child.status, 0, 'API guard not catchable before dependencies'); assert.equal(child.stdout, 'caught\n'); assert.equal(child.stderr, '');
  }
  for (const script of ['bin/cli.js', ...entries.filter(x => x.startsWith('scripts/'))]) {
    for (const args of script === 'bin/cli.js' ? [['--version'], ['--help'], ['build', '--policy', 'absent.yml']] : [['--help']]) {
      const start = process.hrtime.bigint();
      const r = cp.spawnSync(process.execPath, [path.join(pkgRoot, script), ...args], { cwd: consumer, encoding: 'utf8', env: { ...process.env, NODE_PATH: '', NODE_OPTIONS: '' } });
      steps.push({command:'node',exit:r.status ?? -1,expectedExit:1,durationMs:Number(process.hrtime.bigint()-start)/1e6});
      assert.equal(r.status, 1); assert.equal(r.stdout, '');
      assert.equal(r.stderr, `ERR_CSF_UNSUPPORTED_NODE: Node.js >=20.17.0 is required; current ${process.versions.node}. Upgrade Node.js before using cdn-security-framework.\n`);
    }
  }
  assert.deepEqual(fs.readdirSync(consumer).sort(), before, 'rejection created files');
  assert.equal(sha(path.join(pkgRoot, 'policy/base.yml')), policyHash, 'rejection modified policy');
  return steps;
}
function consume(directory: string, row: string, output: string): void {
  assert.ok(matrixRows.includes(row as typeof matrixRows[number]), 'unknown matrix row');
  const m = verifyTarball(directory, expected()); const consumer = path.join(directory, 'consumer');
  const details = checkResolution(consumer); const rejected = row === '18.20.8' || row === '20.16.0';
  let steps: Step[] = [];
  let journey: import('./package-journey').JourneyResult | undefined;
  let prefixProof: import('./package-smoke-tests').PrefixProof | undefined;
  let controllerOptionsProof: import('./package-smoke-tests').ControllerOptionsProof | undefined;
  if (rejected) steps = rejection(consumer);
  else {
    const smoke = require(path.join(directory, 'scripts/package-smoke-tests.js'));
    smoke.assertPackageContents(read(path.join(directory, 'pack.json')));
    const { createOfficialSarifValidator } = require(path.join(directory, 'validation/official-sarif-test-validator.cjs')) as typeof import('./official-sarif-test-validator');
    const validate = createOfficialSarifValidator(path.join(directory, 'validation/sarif-schema-2.1.0.json'));
    const cliVerified = smoke.smokeInstalledPackage(path.join(directory, 'candidate.tgz'), consumer,
      (value: unknown) => assert.ok(validate(value), 'installed SARIF failed pinned official schema'));
    assert.equal(cliVerified, true, 'installed source-diff CLI proof missing');
    steps = smoke.smokeSteps;
    run(process.execPath, ['-e', `const fs=require('node:fs'),path=require('node:path');const p=path.resolve('node_modules/cdn-security-framework');const req=require('node:module').createRequire(path.join(p,'package.json'));const Ajv=req('ajv');const ajv=new Ajv({strict:false});for(const f of ['policy/schema.json',...fs.readdirSync(path.join(p,'schemas')).filter(f=>f.endsWith('.json')).map(f=>'schemas/'+f)]){if(!ajv.validateSchema(JSON.parse(fs.readFileSync(path.join(p,f)))))throw new Error('invalid schema');}`], consumer);
    if (row === '24') {
      const prefix = smoke.smokeInstalledPrefix(consumer,
        (value: unknown) => assert.ok(validate(value), 'installed prefixed SARIF failed pinned official schema'));
      steps.push(...prefix.steps);
      prefixProof = prefix.proof;
      const object = smoke.smokeInstalledControllerOptions(consumer,
        (value: unknown) => assert.ok(validate(value), 'installed object SARIF failed pinned official schema'));
      steps.push(...object.steps);
      controllerOptionsProof = object.proof;
      journey = JSON.parse(run(process.execPath, [path.join(directory, 'scripts/package-journey.js'), directory,
        path.join(consumer, 'node_modules/cdn-security-framework/examples')], consumer));
    }
  }
  const result: Result = { ...m, runtime: { executable: path.basename(process.execPath), sha256: sha(process.execPath), platform: process.platform, arch: process.arch }, row, status: 'pass', node: process.versions.node, npm: run('npm', ['--version'], consumer).trim(), checks: rejected ? ['node-rejection','resolution','no-side-effects'] : ['package-smoke','resolution','schemas','official-sarif-schema','source-aware-cli','source-auth-config','source-safe-output', ...(row === '24' ? ['source-global-prefix','source-controller-options'] : [])], ...details, steps, ...(journey ? { journey } : {}), ...(prefixProof ? { prefixProof } : {}), ...(controllerOptionsProof ? { controllerOptionsProof } : {}) };
  if (rejected && process.env.CSF_SWITCH_PROOF) {
    const switched = read(process.env.CSF_SWITCH_PROOF) as Result;
    verifyIdentity(switched, expected());
    assert.equal(switched.sha256, m.sha256); assert.equal(switched.row, row); assert.equal(switched.node, process.versions.node); assert.equal(switched.status, 'pass');
    assert.deepEqual(switched.checks, result.checks); result.switchVerified = true;
  }
  write(output, result); console.log(JSON.stringify({ row, node: result.node, sha256: m.sha256, status: result.status }));
}
if (require.main === module) {
  try {
    const [command, directory, arg, output] = process.argv.slice(2); assert.ok(directory);
    if (command === 'produce') produce(path.resolve(directory));
    else if (command === 'verify') verifyTarball(path.resolve(directory), expected());
    else if (command === 'consume') consume(path.resolve(directory), arg, output);
    else if (command === 'aggregate') {
      const m = verifyTarball(path.resolve(directory), expected());
      aggregate(m, collectResults(arg), expected(), [process.env.CSF_PRODUCER_STATE || '', process.env.CSF_CONSUMER_STATE || '']);
      write(output, { status: 'pass', ...m, rows: matrixRows });
    } else throw new Error('invalid command');
  } catch { console.error('CSF_PACKAGE_ACCEPTANCE_FAILED: candidate, validation, or required evidence is invalid.'); process.exitCode = 1; }
}
