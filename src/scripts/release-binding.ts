#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import cp from 'node:child_process';
import { verifyTarball } from './single-pack';

type Candidate = {
  source: string; tree: string; run: string; attempt: string;
  sha256: string; lockSha256: string;
};
type Approval = {
  version: 1; decision: 'GO' | 'NO_GO'; rc: Candidate; final: Candidate;
  tag: string; packageVersion: string; distTag: 'latest' | 'next'; registry: 'https://registry.npmjs.org/';
  h01Evidence: string; changedPaths: string[];
};
type Job = { name: string; status: string; conclusion: string | null };
type Run = { path: string; event: string; head_branch: string; head_sha: string; run_attempt: number; status: string; conclusion: string | null };
type Environment = { protection_rules?: Array<{ type: string; reviewers?: unknown[]; prevent_self_review?: boolean }> };
type ApprovalComment = { id: number; body: string; user: { login: string }; author_association: string; issue_url?: string };
type PackageIdentity = { name?: string; version?: string; publishConfig?: unknown; [key: string]: unknown };
type LockIdentity = { version?: string; packages?: Record<string, { version?: string; [key: string]: unknown }>; [key: string]: unknown };
const registry = 'https://registry.npmjs.org/';
const releasePaths = ['package.json', 'package-lock.json', 'CHANGELOG.md', 'CHANGELOG.ja.md'];

const requiredJobs = [
  'full-validation', 'package-producer', 'package-acceptance', 'full-release-matrix',
  ...['20.17.0', '22', '24', '18.20.8', '20.16.0'].map((node) => `package-consumer (${node})`),
];
const sha40 = /^[a-f0-9]{40}$/;
const sha64 = /^[a-f0-9]{64}$/;

function candidateValid(candidate: Candidate): boolean {
  return !!candidate && sha40.test(candidate.source) && sha40.test(candidate.tree)
    && /^\d+$/.test(candidate.run) && /^\d+$/.test(candidate.attempt)
    && sha64.test(candidate.sha256) && sha64.test(candidate.lockSha256);
}

export function verifyReleaseDiff(paths: readonly string[], rcPackage: PackageIdentity, finalPackage: PackageIdentity, rcLock: LockIdentity, finalLock: LockIdentity): void {
  assert.deepEqual([...paths].sort(), [...releasePaths].sort(), 'RC/final changes exceed version and EN/JA Changelog');
  assert.ok(rcPackage?.name === 'cdn-security-framework' && finalPackage?.name === rcPackage.name, 'release package name changed');
  assert.ok(typeof rcPackage.version === 'string' && typeof finalPackage.version === 'string' && rcPackage.version !== finalPackage.version, 'missing final version change');
  assert.equal(rcLock?.version, rcPackage.version, 'reviewed RC lock version mismatch');
  assert.equal(rcLock?.packages?.['']?.version, rcPackage.version, 'reviewed RC lock root version mismatch');
  assert.equal(finalLock?.version, finalPackage.version, 'final lock version mismatch');
  assert.equal(finalLock?.packages?.['']?.version, finalPackage.version, 'final lock root version mismatch');
  const withoutVersion = (value: PackageIdentity | LockIdentity, rootPackage = false) => {
    const copy = structuredClone(value);
    delete copy.version;
    if (rootPackage) delete (copy as LockIdentity).packages?.['']?.version;
    return copy;
  };
  assert.deepEqual(withoutVersion(finalPackage), withoutVersion(rcPackage), 'package change exceeds version');
  assert.deepEqual(withoutVersion(finalLock, true), withoutVersion(rcLock, true), 'lock change exceeds package version');
}

export function verifyPublishTarget(checkout: PackageIdentity, packed: PackageIdentity, env: NodeJS.ProcessEnv, configuredRegistry: string): void {
  assert.equal(configuredRegistry, registry, 'npm registry configuration mismatch');
  assert.equal(checkout.name, 'cdn-security-framework', 'unexpected release package');
  assert.equal(packed.name, checkout.name, 'packed package name mismatch');
  assert.equal(packed.version, checkout.version, 'packed package version mismatch');
  assert.ok(!checkout.publishConfig && !packed.publishConfig, 'package publishConfig is not permitted');
  for (const [key, value] of Object.entries(env)) {
    if (/^npm_config_registry$/i.test(key)) assert.equal(value, registry, 'npm registry environment mismatch');
  }
}

export function verifyH01Evidence(approval: Approval, comment: ApprovalComment, repository: string): void {
  const prefix = `https://github.com/${repository}/issues/890#issuecomment-`;
  const id = approval.h01Evidence.startsWith(prefix) ? approval.h01Evidence.slice(prefix.length) : '';
  assert.ok(/^\d+$/.test(id) && Number(id) === comment?.id, 'H01 result comment identity mismatch');
  assert.equal(comment.issue_url, `https://api.github.com/repos/${repository}/issues/890`, 'H01 result belongs to another Issue');
  assert.equal(comment.user?.login, repository.split('/')[0], 'H01 assessment is not owner-confirmed');
  assert.equal(comment.author_association, 'OWNER', 'H01 assessment author is not repository owner');
  assert.ok(comment.body.startsWith('CSF_H01_ASSESSED_V1\n'), 'H01 preparation is not an assessed result');
  let result: Record<string, unknown>;
  try { result = JSON.parse(comment.body.slice('CSF_H01_ASSESSED_V1\n'.length)); }
  catch { throw new assert.AssertionError({ message: 'invalid H01 assessment record' }); }
  assert.equal(result.rcSource, approval.rc.source, 'H01 assessed source mismatch');
  assert.equal(result.rcSha256, approval.rc.sha256, 'H01 assessed tarball mismatch');
  assert.equal(result.finalSource, approval.final.source, 'H01 final-candidate impact source mismatch');
  assert.equal(result.finalSha256, approval.final.sha256, 'H01 final-candidate impact tarball mismatch');
  assert.ok(Array.isArray(result.finalChangedPaths), 'H01 final-candidate impact diff is missing');
  assert.deepEqual([...result.finalChangedPaths].sort(), [...releasePaths].sort(), 'H01 final-candidate impact diff mismatch');
  assert.equal(result.en, 'assessed', 'EN H01 result has not been assessed');
  assert.equal(result.ja, 'assessed', 'JA H01 result has not been assessed');
  assert.equal(result.finalDiffImpact, 'assessed', 'final-candidate impact has not been assessed');
}

export function verifyBinding(input: {
  approval: Approval; approvalAuthor: string; repository: string;
  environment: Environment; rcRun: Run; run: Run; jobs: Job[];
  checkout: string; checkoutTree: string; rcTree: string; tagCommit: string; tag: string; packageVersion: string;
  changedPaths: string[]; rcArtifact: Candidate; artifact: Candidate;
}): void {
  const { approval: a } = input;
  assert.equal(input.approvalAuthor, input.repository.split('/')[0], 'release approval is not from repository owner');
  assert.ok(a && a.version === 1 && a.decision === 'GO' && candidateValid(a.rc) && candidateValid(a.final), 'invalid approval identity');
  const semver = a.tag.match(/^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/);
  assert.ok(semver, 'invalid release tag');
  assert.equal(a.tag, input.tag, 'approved tag mismatch');
  assert.equal(a.packageVersion, input.packageVersion, 'approved package version mismatch');
  assert.equal(a.tag, `v${a.packageVersion}`, 'tag/package version mismatch');
  assert.equal(a.distTag, semver[1] ? 'next' : 'latest', 'release dist-tag mismatch');
  assert.equal(a.registry, registry, 'release registry mismatch');
  assert.ok(a.h01Evidence.startsWith(`https://github.com/${input.repository}/issues/890#issuecomment-`), 'missing H01 evidence');
  assert.ok(Array.isArray(a.changedPaths) && a.changedPaths.every((file) => typeof file === 'string' && file.length > 0), 'invalid approved diff');
  assert.deepEqual([...new Set(a.changedPaths)].sort(), [...new Set(input.changedPaths)].sort(), 'RC/final diff is not approved');
  assert.deepEqual([...input.changedPaths].sort(), [...releasePaths].sort(), 'RC/final changes exceed version and EN/JA Changelog');
  assert.ok(a.rc.source !== a.final.source || a.changedPaths.length === 0, 'unaccounted candidate change');
  assert.equal(input.checkout, a.final.source, 'release checkout mismatch');
  assert.equal(input.checkoutTree, a.final.tree, 'release tree mismatch');
  assert.equal(input.rcTree, a.rc.tree, 'reviewed RC tree mismatch');
  assert.equal(input.tagCommit, a.final.source, 'release tag commit mismatch');
  assert.ok(input.environment?.protection_rules?.some((rule) => rule.type === 'required_reviewers'
    && rule.prevent_self_review === true && Array.isArray(rule.reviewers) && rule.reviewers.length > 0), 'release environment has no required reviewer');
  assert.ok(input.rcRun && input.rcRun.path === '.github/workflows/policy-lint.yml'
    && input.rcRun.event === 'push' && input.rcRun.head_branch === 'main'
    && input.rcRun.head_sha === a.rc.source && input.rcRun.run_attempt === Number(a.rc.attempt)
    && input.rcRun.status === 'completed' && input.rcRun.conclusion === 'success', 'reviewed RC run is not successful');
  assert.ok(input.run && input.run.path === '.github/workflows/policy-lint.yml'
    && input.run.event === 'push' && input.run.head_branch === 'main'
    && input.run.head_sha === a.final.source && input.run.run_attempt === Number(a.final.attempt)
    && input.run.status === 'completed' && input.run.conclusion === 'success', 'final main run is not successful');
  for (const name of requiredJobs) {
    const matches = input.jobs.filter((job) => job.name === name);
    assert.ok(matches.length === 1 && matches[0].status === 'completed'
      && matches[0].conclusion === 'success', `required release job is not successful: ${name}`);
  }
  assert.deepEqual(input.rcArtifact, a.rc, 'reviewed RC tarball/run identity mismatch');
  assert.deepEqual(input.artifact, a.final, 'approved tarball/run identity mismatch');
}

async function github<T>(repository: string, endpoint: string, token: string): Promise<T> {
  const response = await fetch(`https://api.github.com/repos/${repository}/${endpoint}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' },
  });
  if (!response.ok) throw new Error('trusted GitHub release evidence is unavailable');
  return response.json() as Promise<T>;
}

function git(...args: string[]): string {
  const result = cp.spawnSync('git', args, { encoding: 'utf8', maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, 'release git identity is unavailable');
  return result.stdout.trim();
}

function parseApproval(value: string): Approval | null {
  if (!value.startsWith('CSF_RELEASE_APPROVAL_V1\n')) return null;
  try { return JSON.parse(value.slice('CSF_RELEASE_APPROVAL_V1\n'.length)) as Approval; }
  catch { return null; }
}

export function selectApproval(comments: ApprovalComment[], tag: string): { approval: Approval; author: string } {
  const records = comments.filter((comment) => comment.author_association === 'OWNER')
    .map((comment) => ({ approval: parseApproval(comment.body), author: comment.user.login }))
    .filter((entry): entry is { approval: Approval; author: string } => entry.approval?.tag === tag);
  assert.ok(records.length > 0, 'owner-authored release approval is required');
  const latest = records[records.length - 1];
  assert.equal(latest.approval.decision, 'GO', 'latest owner decision is not GO');
  return latest;
}

export async function loadApproval(
  repository: string, token: string, tag: string,
  getPage: (page: number) => Promise<ApprovalComment[]> = (page) => github<ApprovalComment[]>(
    repository, `issues/895/comments?per_page=100&page=${page}`, token,
  ),
): Promise<{ approval: Approval; author: string }> {
  const comments: ApprovalComment[] = [];
  for (let page = 1; page <= 10; page += 1) {
    const batch = await getPage(page);
    assert.ok(Array.isArray(batch) && batch.length <= 100, 'invalid release approval response');
    comments.push(...batch);
    if (batch.length < 100) {
      comments.sort((left, right) => left.id - right.id);
      return selectApproval(comments, tag);
    }
  }
  throw new Error('release approval history exceeds the verified page limit');
}

async function run(): Promise<void> {
  const repository = process.env.GITHUB_REPOSITORY || '';
  const token = process.env.GITHUB_TOKEN || '';
  const tag = process.env.CSF_RELEASE_TAG || '';
  assert.ok(/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(repository) && token, 'missing trusted GitHub context');
  const { approval, author } = await loadApproval(repository, token, tag);
  const environment = await github<Environment>(repository, 'environments/npm-release', token);
  const h01Id = approval.h01Evidence.match(/^https:\/\/github\.com\/[^/]+\/[^/]+\/issues\/890#issuecomment-(\d+)$/)?.[1];
  assert.ok(h01Id, 'missing H01 assessed result link');
  const h01Comment = await github<ApprovalComment>(repository, `issues/comments/${h01Id}`, token);
  verifyH01Evidence(approval, h01Comment, repository);
  assert.equal(author, repository.split('/')[0], 'release approval is not from repository owner');
  assert.ok(approval.version === 1 && approval.decision === 'GO' && candidateValid(approval.rc) && candidateValid(approval.final)
    && approval.tag === tag && approval.h01Evidence.startsWith(`https://github.com/${repository}/issues/890#issuecomment-`),
  'release approval is incomplete');
  assert.ok(environment?.protection_rules?.some((rule) => rule.type === 'required_reviewers'
    && rule.prevent_self_review === true && Array.isArray(rule.reviewers) && rule.reviewers.length > 0), 'release environment has no required reviewer');
  if (process.argv[2] === 'plan') {
    const output = process.env.GITHUB_OUTPUT;
    assert.ok(output, 'missing release plan output');
    fs.appendFileSync(output, `run=${approval.final.run}\nattempt=${approval.final.attempt}\nrc_run=${approval.rc.run}\nrc_attempt=${approval.rc.attempt}\n`);
    console.log('RELEASE_PLAN_OK: owner record and protected environment found.');
    return;
  }
  assert.equal(process.argv[2], 'verify', 'invalid release binding command');
  const rcRun = await github<Run>(repository, `actions/runs/${approval.rc.run}`, token);
  const releaseRun = await github<Run>(repository, `actions/runs/${approval.final.run}`, token);
  const jobResponse = await github<{ total_count: number; jobs: Job[] }>(
    repository, `actions/runs/${approval.final.run}/attempts/${approval.final.attempt}/jobs?per_page=100`, token,
  );
  assert.ok(jobResponse.total_count <= 100, 'release run has unverified jobs');
  const checkout = git('rev-parse', 'HEAD');
  const checkoutTree = git('rev-parse', 'HEAD^{tree}');
  const rcTree = git('rev-parse', `${approval.rc.source}^{tree}`);
  const tagCommit = git('rev-list', '-n', '1', tag);
  assert.equal(cp.spawnSync('git', ['merge-base', '--is-ancestor', tagCommit, 'origin/main']).status, 0,
    'release tag is not on main');
  assert.equal(cp.spawnSync('git', ['merge-base', '--is-ancestor', approval.rc.source, checkout]).status, 0,
    'reviewed RC is not an ancestor of the final candidate');
  const changedPaths = git('diff', '--name-only', approval.rc.source, checkout).split('\n').filter(Boolean);
  const checkoutPackage = JSON.parse(fs.readFileSync('package.json', 'utf8')) as PackageIdentity;
  const packageVersion = checkoutPackage.version as string;
  const rcPackage = JSON.parse(git('show', `${approval.rc.source}:package.json`)) as PackageIdentity;
  const rcLock = JSON.parse(git('show', `${approval.rc.source}:package-lock.json`)) as LockIdentity;
  const finalLock = JSON.parse(fs.readFileSync('package-lock.json', 'utf8')) as LockIdentity;
  verifyReleaseDiff(changedPaths, rcPackage, checkoutPackage, rcLock, finalLock);
  const artifactDirectory = process.env.CSF_RELEASE_ARTIFACT_DIR;
  const rcDirectory = process.env.CSF_RC_ARTIFACT_DIR;
  assert.ok(artifactDirectory && rcDirectory, 'single-pack artifacts have not been downloaded');
  for (const directory of [rcDirectory, artifactDirectory]) {
    for (const file of ['metadata.json', 'consumer/package-lock.json']) {
      assert.ok(fs.lstatSync(`${directory}/${file}`).isFile(), 'release artifact contains a non-regular file');
    }
  }
  const rcMetadata = verifyTarball(rcDirectory, {
    source: approval.rc.source, run: approval.rc.run,
    attempt: approval.rc.attempt, sha256: approval.rc.sha256,
  });
  const metadata = verifyTarball(artifactDirectory, {
    source: approval.final.source, run: approval.final.run,
    attempt: approval.final.attempt, sha256: approval.final.sha256,
  });
  const packedResult = cp.spawnSync('tar', ['-xOzf', `${artifactDirectory}/candidate.tgz`, 'package/package.json'], { encoding: 'utf8', maxBuffer: 256 * 1024 });
  assert.equal(packedResult.status, 0, 'packed package identity is unavailable');
  const packedPackage = JSON.parse(packedResult.stdout) as PackageIdentity;
  const npmConfig = cp.spawnSync('npm', ['config', 'get', 'registry'], { encoding: 'utf8', maxBuffer: 1024 });
  assert.equal(npmConfig.status, 0, 'npm registry configuration is unavailable');
  verifyPublishTarget(checkoutPackage, packedPackage, process.env, npmConfig.stdout.trim());
  verifyBinding({
    approval, approvalAuthor: author, repository, environment, rcRun, run: releaseRun, jobs: jobResponse.jobs,
    checkout, checkoutTree, rcTree, tagCommit, tag, packageVersion, changedPaths,
    rcArtifact: {
      source: rcMetadata.source, tree: rcMetadata.tree, run: rcMetadata.run, attempt: rcMetadata.attempt,
      sha256: rcMetadata.sha256, lockSha256: rcMetadata.lockSha256,
    },
    artifact: {
      source: metadata.source, tree: metadata.tree, run: metadata.run, attempt: metadata.attempt,
      sha256: metadata.sha256, lockSha256: metadata.lockSha256,
    },
  });
  const output = process.env.GITHUB_OUTPUT;
  if (output) fs.appendFileSync(output, `run=${approval.final.run}\nattempt=${approval.final.attempt}\nsha256=${approval.final.sha256}\ndist_tag=${approval.distTag}\n`);
  console.log('RELEASE_BINDING_OK: approved main candidate and exact tarball verified.');
}

if (require.main === module) run().catch(() => {
  console.error('RELEASE_BINDING_HOLD: approval, environment, CI, tag or tarball identity is unavailable or mismatched.');
  process.exitCode = 1;
});
