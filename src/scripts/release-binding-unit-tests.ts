import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { loadApproval, selectApproval, verifyBinding, verifyReleaseDiff, verifyPublishTarget, verifyH01Evidence } from './release-binding';
import { verifyTarball } from './single-pack';

type Input = Parameters<typeof verifyBinding>[0];
const final = {
  source: 'a'.repeat(40), tree: 'b'.repeat(40), run: '123', attempt: '1',
  sha256: 'c'.repeat(64), lockSha256: 'd'.repeat(64),
};
const rcPackage = { name: 'cdn-security-framework', version: '1.4.0', dependencies: { ajv: '8.0.0' }, scripts: { test: 'node test.js' }, exports: { '.': './index.js' } };
const finalPackage = { ...rcPackage, version: '2.0.0' };
const rcLock = { name: rcPackage.name, version: rcPackage.version, packages: { '': { name: rcPackage.name, version: rcPackage.version }, 'node_modules/ajv': { version: '8.0.0' } } };
const finalLock = { ...rcLock, version: finalPackage.version, packages: { ...rcLock.packages, '': { ...rcLock.packages[''], version: finalPackage.version } } };
const releasePaths = ['package.json', 'package-lock.json', 'CHANGELOG.md', 'CHANGELOG.ja.md'];
function input(): Input {
  return {
    approval: {
      version: 1, decision: 'GO', rc: { ...final, source: 'e'.repeat(40), run: '100', sha256: 'f'.repeat(64) },
      final: { ...final }, tag: 'v2.0.0', packageVersion: '2.0.0', distTag: 'latest', registry: 'https://registry.npmjs.org/',
      h01Evidence: 'https://github.com/albert-einshutoin/cdn-security-framework/issues/890#issuecomment-123',
      changedPaths: [...releasePaths],
    },
    approvalAuthor: 'albert-einshutoin', repository: 'albert-einshutoin/cdn-security-framework',
    environment: { protection_rules: [{ type: 'required_reviewers', prevent_self_review: true, reviewers: [{}] }] },
    rcRun: { path: '.github/workflows/policy-lint.yml', event: 'push', head_branch: 'main', head_sha: 'e'.repeat(40),
      run_attempt: 1, status: 'completed', conclusion: 'success' },
    run: { path: '.github/workflows/policy-lint.yml', event: 'push', head_branch: 'main', head_sha: final.source,
      run_attempt: 1, status: 'completed', conclusion: 'success' },
    jobs: [
      'full-validation', 'package-producer', 'package-acceptance', 'full-release-matrix',
      ...['20.17.0', '22', '24', '18.20.8', '20.16.0'].map((row) => `package-consumer (${row})`),
    ].map((name) => ({ name, status: 'completed', conclusion: 'success' })),
    checkout: final.source, checkoutTree: final.tree, rcTree: final.tree,
    tagCommit: final.source, tag: 'v2.0.0', packageVersion: '2.0.0',
    changedPaths: [...releasePaths], rcArtifact: { ...final, source: 'e'.repeat(40), run: '100', sha256: 'f'.repeat(64) },
    artifact: { ...final },
  };
}

verifyBinding(input());
const rejects: Array<[string, (value: Input) => void]> = [
  ['untrusted approval', (v) => { v.approvalAuthor = 'random-user'; }],
  ['NO-GO decision', (v) => { v.approval.decision = 'NO_GO'; }],
  ['missing H01 evidence', (v) => { v.approval.h01Evidence = ''; }],
  ['reviewed RC source mismatch', (v) => { v.rcRun.head_sha = '0'.repeat(40); }],
  ['wrong final workflow', (v) => { v.run.path = '.github/workflows/other.yml'; }],
  ['unprotected environment', (v) => { v.environment.protection_rules = []; }],
  ['self-review permitted', (v) => { v.environment.protection_rules![0].prevent_self_review = false; }],
  ['tag mismatch', (v) => { v.tag = 'v2.0.1'; }],
  ['package version mismatch', (v) => { v.packageVersion = '2.0.1'; }],
  ['release checkout mismatch', (v) => { v.checkout = '0'.repeat(40); }],
  ['release tree mismatch', (v) => { v.checkoutTree = '0'.repeat(40); }],
  ['reviewed RC tree mismatch', (v) => { v.rcTree = '0'.repeat(40); }],
  ['tag commit mismatch', (v) => { v.tagCommit = '0'.repeat(40); }],
  ['unapproved final diff', (v) => { v.changedPaths.push('src/other.ts'); }],
  ['owner approved source change', (v) => { v.changedPaths.push('src/other.ts'); v.approval.changedPaths.push('src/other.ts'); }],
  ['owner approved workflow change', (v) => { v.changedPaths.push('.github/workflows/release-npm.yml'); v.approval.changedPaths.push('.github/workflows/release-npm.yml'); }],
  ['owner approved generated runtime change', (v) => { v.changedPaths.push('bin/cli.js'); v.approval.changedPaths.push('bin/cli.js'); }],
  ['another artifact run', (v) => { v.artifact.run = '124'; }],
  ['substituted reviewed RC digest', (v) => { v.rcArtifact.sha256 = '0'.repeat(64); }],
  ['another artifact attempt', (v) => { v.artifact.attempt = '2'; }],
  ['substituted artifact digest', (v) => { v.artifact.sha256 = '0'.repeat(64); }],
  ['2.1 candidate', (v) => { v.run.head_branch = 'dev/2.1-source-aware'; }],
  ['PR validation', (v) => { v.run.event = 'pull_request'; }],
  ['cancelled main run', (v) => { v.run.conclusion = 'cancelled'; }],
  ['missing job', (v) => { v.jobs.pop(); }],
  ['skipped job', (v) => { v.jobs[0].conclusion = 'skipped'; }],
  ['failed consumer', (v) => { v.jobs[4].conclusion = 'failure'; }],
  ['duplicate job', (v) => { v.jobs.push({ ...v.jobs[0] }); }],
  ['prerelease/latest confusion', (v) => { v.approval.tag = 'v2.0.0-rc.1'; v.tag = 'v2.0.0-rc.1'; v.approval.packageVersion = '2.0.0-rc.1'; v.packageVersion = '2.0.0-rc.1'; }],
];
for (const [name, change] of rejects) {
  const value = input();
  change(value);
  assert.throws(() => verifyBinding(value), { name: 'AssertionError' }, name);
}
const prerelease = input();
prerelease.approval.tag = 'v2.0.0-rc.1'; prerelease.tag = 'v2.0.0-rc.1';
prerelease.approval.packageVersion = '2.0.0-rc.1'; prerelease.packageVersion = '2.0.0-rc.1';
prerelease.approval.distTag = 'next';
verifyBinding(prerelease);
const buildMetadata = input();
buildMetadata.approval.tag = 'v2.0.0+build-1'; buildMetadata.tag = 'v2.0.0+build-1';
buildMetadata.approval.packageVersion = '2.0.0+build-1'; buildMetadata.packageVersion = '2.0.0+build-1';
verifyBinding(buildMetadata);

verifyReleaseDiff(releasePaths, rcPackage, finalPackage, rcLock, finalLock);
for (const [label, paths, pkg, lock] of [
  ['source', [...releasePaths, 'src/index.ts'], finalPackage, finalLock],
  ['workflow', [...releasePaths, '.github/workflows/release-npm.yml'], finalPackage, finalLock],
  ['generated runtime', [...releasePaths, 'bin/cli.js'], finalPackage, finalLock],
  ['dependencies', releasePaths, { ...finalPackage, dependencies: { ajv: '9.0.0' } }, finalLock],
  ['exports', releasePaths, { ...finalPackage, exports: { '.': './other.js' } }, finalLock],
  ['scripts', releasePaths, { ...finalPackage, scripts: { test: 'node other.js' } }, finalLock],
  ['lock dependency', releasePaths, finalPackage, { ...finalLock, packages: { ...finalLock.packages, 'node_modules/ajv': { version: '9.0.0' } } }],
] as const) {
  assert.throws(() => verifyReleaseDiff(paths, rcPackage, pkg, rcLock, lock), { name: 'AssertionError' }, label);
}
verifyPublishTarget(finalPackage, finalPackage, {}, 'https://registry.npmjs.org/');
const workflow = fs.readFileSync('.github/workflows/release-npm.yml', 'utf8');
for (const command of ['npm view', 'npm publish', 'npm pack', 'npm install --no-save', 'npm audit signatures']) {
  const line = workflow.split('\n').find((entry) => !entry.trim().startsWith('#') && entry.includes(command));
  assert.ok(line?.includes('--registry=https://registry.npmjs.org/'), `release command has no pinned registry: ${command}`);
}
for (const [label, checkout, packed, env, configured] of [
  ['checkout publishConfig', { ...finalPackage, publishConfig: { registry: 'https://other.example/' } }, finalPackage, {}, 'https://registry.npmjs.org/'],
  ['packed publishConfig', finalPackage, { ...finalPackage, publishConfig: { registry: 'https://other.example/' } }, {}, 'https://registry.npmjs.org/'],
  ['npm env', finalPackage, finalPackage, { NPM_CONFIG_REGISTRY: 'https://other.example/' }, 'https://registry.npmjs.org/'],
  ['npm config', finalPackage, finalPackage, {}, 'https://other.example/'],
  ['packed name', finalPackage, { ...finalPackage, name: 'other-package' }, {}, 'https://registry.npmjs.org/'],
] as const) {
  assert.throws(() => verifyPublishTarget(checkout, packed, env, configured), { name: 'AssertionError' }, label);
}
const h01 = {
  id: 123, issue_url: 'https://api.github.com/repos/albert-einshutoin/cdn-security-framework/issues/890', author_association: 'OWNER', user: { login: 'albert-einshutoin' },
  body: `CSF_H01_ASSESSED_V1\n${JSON.stringify({ rcSource: 'e'.repeat(40), rcSha256: 'f'.repeat(64), finalSource: final.source, finalSha256: final.sha256, finalChangedPaths: releasePaths, en: 'assessed', ja: 'assessed', finalDiffImpact: 'assessed' })}`,
};
verifyH01Evidence(input().approval, h01, 'albert-einshutoin/cdn-security-framework');
verifyH01Evidence(input().approval, { ...h01, body: h01.body.replace(JSON.stringify(releasePaths), JSON.stringify([...releasePaths].reverse())) }, 'albert-einshutoin/cdn-security-framework');
assert.throws(() => verifyH01Evidence(input().approval, { ...h01, body: 'EN/JA preparation complete' }, 'albert-einshutoin/cdn-security-framework'), { name: 'AssertionError' });
assert.throws(() => verifyH01Evidence(input().approval, { ...h01, body: h01.body.replace(JSON.stringify(releasePaths), JSON.stringify([...releasePaths, releasePaths[0]])) }, 'albert-einshutoin/cdn-security-framework'), { name: 'AssertionError' });
assert.throws(() => verifyH01Evidence(input().approval, { ...h01, issue_url: 'https://api.github.com/repos/albert-einshutoin/cdn-security-framework/issues/895' }, 'albert-einshutoin/cdn-security-framework'), { name: 'AssertionError' });
assert.throws(() => verifyH01Evidence(input().approval, { ...h01, body: h01.body.replace('assessed', 'pending') }, 'albert-einshutoin/cdn-security-framework'), { name: 'AssertionError' });
assert.throws(() => verifyH01Evidence(input().approval, { ...h01, body: h01.body.replace(final.sha256, '0'.repeat(64)) }, 'albert-einshutoin/cdn-security-framework'), { name: 'AssertionError' });

const go = input().approval;
const comment = (id: number, decision: 'GO' | 'NO_GO') => ({
  id, body: `CSF_RELEASE_APPROVAL_V1\n${JSON.stringify({ ...go, decision })}`,
  user: { login: 'albert-einshutoin' }, author_association: 'OWNER',
});
const manyComments = Array.from({ length: 101 }, (_, id) => ({
  id, body: 'historical discussion', user: { login: 'albert-einshutoin' }, author_association: 'OWNER',
}));
assert.equal(selectApproval([...manyComments, comment(101, 'GO')], 'v2.0.0').approval.decision, 'GO');
assert.throws(() => selectApproval([...manyComments, comment(101, 'GO'), comment(102, 'NO_GO')], 'v2.0.0'),
  /not GO/, 'a later approval page must be able to revoke GO');

const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-release-binding-'));
try {
  fs.mkdirSync(path.join(directory, 'consumer'));
  const tarball = path.join(directory, 'candidate.tgz');
  const lockfile = path.join(directory, 'consumer/package-lock.json');
  const validation = path.join(directory, 'validation');
  fs.mkdirSync(validation);
  const schema = path.join(validation, 'sarif-schema-2.1.0.json');
  const validator = path.join(validation, 'official-sarif-test-validator.cjs');
  fs.copyFileSync('test/fixtures/sarif/sarif-schema-2.1.0.json', schema);
  fs.writeFileSync(validator, 'synthetic validator');
  fs.writeFileSync(tarball, 'synthetic tarball');
  fs.writeFileSync(lockfile, 'synthetic lock');
  const hash = (file: string) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  const metadata = { schemaVersion: 1, ...final, sha256: hash(tarball), lockSha256: hash(lockfile), size: fs.statSync(tarball).size,
    harness: final.source, schemaSha256: hash(schema), validatorSha256: hash(validator) };
  fs.writeFileSync(path.join(directory, 'metadata.json'), JSON.stringify(metadata));
  verifyTarball(directory, { source: final.source, run: final.run, attempt: final.attempt, sha256: metadata.sha256 });
  fs.writeFileSync(tarball, 'substituted bytes');
  assert.throws(() => verifyTarball(directory, {
    source: final.source, run: final.run, attempt: final.attempt, sha256: metadata.sha256,
  }), /tarball digest mismatch/);
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
(async () => {
  const pages: number[] = [];
  const loaded = await loadApproval('albert-einshutoin/cdn-security-framework', 'synthetic-token', 'v2.0.0', async (page) => {
    pages.push(page);
    return page === 1 ? manyComments.slice(0, 100) : [manyComments[100], comment(101, 'GO')];
  });
  assert.equal(loaded.approval.decision, 'GO');
  assert.deepEqual(pages, [1, 2]);
  await assert.rejects(loadApproval('albert-einshutoin/cdn-security-framework', 'synthetic-token', 'v2.0.0',
    async (page) => page === 1 ? manyComments.slice(0, 100) : [comment(101, 'GO'), comment(102, 'NO_GO')]), /not GO/);
  await assert.rejects(loadApproval('albert-einshutoin/cdn-security-framework', 'synthetic-token', 'v2.0.0',
    async () => manyComments.slice(0, 100)), /page limit/);
  console.log(`[release-binding-unit] PASS: one stable, one prerelease and ${rejects.length + 3} rejection cases`);
})().catch((error: unknown) => { console.error(error); process.exitCode = 1; });
