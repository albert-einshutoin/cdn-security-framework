#!/usr/bin/env node

import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { isRepositoryPath } from './check-docs-sync';

assert.equal(isRepositoryPath('/workspace/repository', '/workspace/repository/docs/ROADMAP.md', path.posix), true);
assert.equal(isRepositoryPath('/workspace/repository', '/workspace/outside.md', path.posix), false);
assert.equal(isRepositoryPath('/workspace/repository', '/workspace/repository-old/ROADMAP.md', path.posix), false);
assert.equal(isRepositoryPath('C:\\workspace\\repository', 'C:\\workspace\\repository\\docs\\ROADMAP.md', path.win32), true);
assert.equal(isRepositoryPath('C:\\workspace\\repository', 'C:\\workspace\\outside.md', path.win32), false);
assert.equal(isRepositoryPath('C:\\workspace\\repository', 'C:\\workspace\\repository-old\\ROADMAP.md', path.win32), false);
assert.equal(isRepositoryPath('C:\\workspace\\repository', 'D:\\outside.md', path.win32), false);

console.log('[docs-sync-unit] OK: repository-relative link boundary');

const root = path.join(__dirname, '..');
const en = fs.readFileSync(path.join(root, 'docs/quickstart.md'), 'utf8');
const ja = fs.readFileSync(path.join(root, 'docs/quickstart.ja.md'), 'utf8');
const bashBlocks = (text: string) => [...text.matchAll(/```bash\n([\s\S]*?)\n```/g)].map(m => m[1]);
assert.deepEqual(bashBlocks(en), bashBlocks(ja), 'Quickstart EN/JA commands must agree');
assert.ok(en.includes('2.0.0-rc.0') && ja.includes('2.0.0-rc.0'));
const verifier = /node - <<'JS'\n([\s\S]*?)\nJS/.exec(bashBlocks(en)[0])?.[1];
assert.ok(verifier, 'missing executable handoff verification');
for (const [language, suffix] of [['EN', ''], ['JA', '.ja']]) {
  const sheet = fs.readFileSync(path.join(root, `test/onboarding/novice-evaluation${suffix}.md`), 'utf8');
  assert.ok(sheet.includes('2.0.0-rc.0') && !sheet.includes('PR_HEAD_SHA'), language + ': candidate identity');
  assert.ok(sheet.includes('Source / harness / tree / main run / attempt / ZIP / tgz / consumer-lock SHA-256; Node/npm; OS/filesystem'), language + ': observation identity');
  assert.ok(sheet.includes(language === 'EN' ? '**Not performed**' : '**未実施**'), language + ': H01 remains blank');
}

// Execute the documented code, using synthetic independent GitHub records.
// These fixtures verify the checker; they are not hosted-candidate evidence.
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-doc-handoff-'));
const hash = (value: Buffer | string, algorithm = 'sha256', encoding: crypto.BinaryToTextEncoding = 'hex') => crypto.createHash(algorithm).update(value).digest(encoding);
try {
  const fakeBin = path.join(temp, 'bin'); fs.mkdirSync(fakeBin);
  fs.writeFileSync(path.join(fakeBin, 'gh'), `#!${process.execPath}
const fs=require('node:fs');
const records=JSON.parse(fs.readFileSync(process.env.DOC_GITHUB_RECORDS,'utf8'));
const args=process.argv.slice(2);
if(args[1]!=='--hostname'||args[2]!=='github.com') process.exit(2);
const endpoint=args.at(-1).split('/').slice(3).join('/');
if(endpoint.endsWith('/zip')) process.stdout.write(fs.readFileSync(process.env.DOC_ZIP));
else {if(!records[endpoint]) process.exit(1);process.stdout.write(JSON.stringify(records[endpoint]));}
`, { mode: 0o700 });
  const source = '1'.repeat(40), tree = '2'.repeat(40);
  const tgz = Buffer.from('synthetic verification bytes'), lock = Buffer.from('{"lockfileVersion":3}');
  let caseNumber = 0;
  const runCase = (name: string, mutate: (f: any) => void, pass = false) => {
    const dir = path.join(temp, String(caseNumber++)); fs.mkdirSync(dir);
    const payload = path.join(dir, 'payload'); fs.mkdirSync(path.join(payload, 'consumer'), { recursive: true });
    const h: any = { source, harness: source, tree, run: '123', attempt: '1', artifactId: '7', artifactZipSha256: '0'.repeat(64), tgzSha256: hash(tgz), consumerLockSha256: hash(lock) };
    const m: any = { schemaVersion: 1, source, harness: source, tree, run: '123', attempt: '1', size: tgz.length, sha256: hash(tgz), lockSha256: hash(lock) };
    const records: any = {
      'actions/runs/123/attempts/1': { id: 123, run_attempt: 1, repository: { full_name: 'albert-einshutoin/cdn-security-framework' }, event: 'push', head_branch: 'main', status: 'completed', conclusion: 'success', head_sha: source, workflow_id: 9 },
      'actions/workflows/9': { path: '.github/workflows/policy-lint.yml' },
      ['git/commits/' + source]: { sha: source, tree: { sha: tree } },
      'actions/artifacts/7': { workflow_run: { id: 123, head_sha: source }, name: 'package-candidate-123-1', expired: false, digest: '' },
    };
    const fixture: any = { h, m, records, tgz, lock, pack: { version: '2.0.0-rc.0', integrity: 'sha512-' + hash(tgz, 'sha512', 'base64') } };
    mutate(fixture);
    fs.writeFileSync(path.join(payload, 'candidate.tgz'), fixture.tgz);
    fs.writeFileSync(path.join(payload, 'consumer/package-lock.json'), fixture.lock);
    fs.writeFileSync(path.join(payload, 'metadata.json'), JSON.stringify(m));
    fs.writeFileSync(path.join(payload, 'pack.json'), JSON.stringify(fixture.pack));
    if (fixture.zipLink) fs.symlinkSync('metadata.json', path.join(payload, 'alias'));
    if (fixture.zipExpansion) fs.writeFileSync(path.join(payload, 'padding'), Buffer.alloc(8 * 1024 * 1024 + 1));
    if (fixture.zipTooMany) for (let i = 0; i < 101; i++) fs.writeFileSync(path.join(payload, 'entry-' + i), '');
    const zip = path.join(dir, 'fixture.zip'); execFileSync('zip', ['-y', '-q', '-r', zip, '.'], { cwd: payload });
    if (fixture.zipTraversal) {
      fs.writeFileSync(path.join(dir, 'escape'), 'synthetic');
      execFileSync('zip', ['-q', zip, '../escape'], { cwd: payload });
    }
    h.artifactZipSha256 = hash(fs.readFileSync(zip));
    records['actions/artifacts/7'].digest = 'sha256:' + h.artifactZipSha256;
    if (fixture.corruptZipBytes) execFileSync('zip', ['-q', '-z', zip], { input: 'changed download comment\n' });
    if (fixture.badZipDigest) h.artifactZipSha256 = 'f'.repeat(64);
    if (fixture.missingZipDigest) delete h.artifactZipSha256;
    fs.writeFileSync(path.join(dir, 'handoff.json'), JSON.stringify(h));
    fs.writeFileSync(path.join(dir, 'records.json'), JSON.stringify(records));
    const consumer = path.join(dir, 'empty-consumer'); fs.mkdirSync(consumer);
    const result = spawnSync(process.execPath, ['-'], { input: verifier, cwd: consumer, encoding: 'utf8', timeout: 15000,
      env: { ...process.env, PATH: fakeBin + path.delimiter + process.env.PATH, NODE_OPTIONS: '', NODE_PATH: '',
        CANDIDATE_HANDOFF: path.join(dir, 'handoff.json'), DOC_GITHUB_RECORDS: path.join(dir, 'records.json'), DOC_ZIP: zip } });
    assert.equal(result.error, undefined, name + ': observation failure');
    assert.equal(result.signal, null, name + ': unexpected signal');
    if (pass) assert.equal(result.status, 0, name + ': ' + result.stderr);
    else assert.ok(result.status !== 0 && !result.stdout.includes('Verified main'), name + ': must reject');
    console.log('[docs-sync-unit] OK:', name, pass ? 'accepted' : 'rejected');
  };
  runCase('valid independent handoff in empty consumer', () => {}, true);
  for (const key of ['source', 'harness', 'tree', 'run', 'attempt', 'tgzSha256', 'consumerLockSha256']) {
    runCase('handoff missing ' + key, f => { delete f.h[key]; });
  }
  runCase('handoff missing artifactId', f => { delete f.h.artifactId; });
  runCase('handoff missing ZIP digest', f => { f.missingZipDigest = true; });
  for (const key of ['source', 'harness', 'tree', 'run', 'attempt', 'sha256', 'lockSha256']) {
    runCase('metadata mismatch ' + key, f => { f.m[key] = key === 'run' || key === 'attempt' ? '2' : 'f'.repeat(key.endsWith('Sha256') || key === 'sha256' ? 64 : 40); });
    runCase('metadata missing ' + key, f => { delete f.m[key]; });
  }
  runCase('coherent fake source rejected by GitHub anchor', f => { f.h.source = f.h.harness = f.m.source = f.m.harness = 'f'.repeat(40); });
  runCase('coherent fake tree rejected by GitHub anchor', f => { f.h.tree = f.m.tree = 'f'.repeat(40); });
  runCase('corrupt tgz bytes', f => { f.tgz = Buffer.from('corrupt tgz bytes'); });
  runCase('corrupt lock bytes', f => { f.lock = Buffer.from('corrupt lock bytes'); });
  runCase('wrong ZIP digest', f => { f.badZipDigest = true; });
  runCase('downloaded ZIP byte mismatch with matching trusted digests', f => { f.corruptZipBytes = true; });
  runCase('wrong npm integrity', f => { f.pack.integrity = 'sha512-bad'; });
  runCase('missing npm integrity', f => { delete f.pack.integrity; });
  runCase('failed run', f => { f.records['actions/runs/123/attempts/1'].conclusion = 'failure'; });
  runCase('PR run cannot replace main candidate', f => { f.records['actions/runs/123/attempts/1'].event = 'pull_request'; });
  runCase('wrong workflow', f => { f.records['actions/workflows/9'].path = '.github/workflows/other.yml'; });
  runCase('expired artifact', f => { f.records['actions/artifacts/7'].expired = true; });
  runCase('artifact from another attempt', f => { f.records['actions/artifacts/7'].name = 'package-candidate-123-2'; });
  runCase('ZIP symlink refused', f => { f.zipLink = true; });
  runCase('ZIP traversal refused', f => { f.zipTraversal = true; });
  runCase('ZIP expansion limit', f => { f.zipExpansion = true; });
  runCase('ZIP entry count limit', f => { f.zipTooMany = true; });
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
