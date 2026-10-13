# Quick Start

## 1. Install the unpublished schema2 candidate in an empty consumer

Published `cdn-security-framework@1.4.0` uses Policy schema **version 1**. The current unpublished main candidate is **2.0.0-rc.0** and requires Policy schema **version 2**. These are separate version contracts; npm latest is the published baseline, not this candidate. See the [roadmap](ROADMAP.md). Node 20.17.0, 22 or 24, npm, GitHub CLI (`gh`) with artifact read access, and POSIX `unzip` are prerequisites.

### Maintainer handoff and independent verification

Use a successful **main push** `Policy Lint & Build Check` run and its exact attempt. A PR run is pre-merge evidence and is not automatically the post-merge candidate. The maintainer supplies a trusted handoff JSON through a reviewed channel outside the downloaded archive, using this format (replace every placeholder):

```json
{
  "source": "<40 lowercase hex characters>",
  "harness": "<40 lowercase hex characters>",
  "tree": "<40 lowercase hex characters>",
  "run": "<main push run ID>",
  "attempt": "<attempt number>",
  "artifactId": "<Actions artifact ID>",
  "artifactZipSha256": "<64 lowercase hex characters>",
  "tgzSha256": "<64 lowercase hex characters>",
  "consumerLockSha256": "<64 lowercase hex characters>"
}
```

| Field | Meaning and independent comparison |
| --- | --- |
| `source` | Producer package checkout commit; compare with GitHub run `head_sha` and commit API `sha` |
| `harness` | Checkout supplying the copied single-pack/smoke/journey verification code; the current producer explicitly copies it from `source` and validates equality. Verify it against the independently supplied record and run; do not infer equality for other producers |
| `tree` | Producer checkout Git tree; compare with the commit API `tree.sha` |
| `run`, `attempt` | Exact main push run and attempt; compare with the run-attempt API, completed/success and workflow path |
| `artifactId`, `artifactZipSha256` | Exact named Actions artifact and **ZIP bytes**, compared with GitHub artifact API `digest` |
| `tgzSha256` | **candidate.tgz bytes**, compared with the trusted handoff and downloaded metadata |
| `consumerLockSha256` | **consumer/package-lock.json bytes**, compared with the trusted handoff and metadata |

Do not manufacture the trusted record by copying values from an unverified archive. The maintainer cross-checks run/commit/artifact records and producer/consumer acceptance before handoff. Keep the trusted record and final candidate hashes outside the package (for example, a maintainer evidence directory); never embed the final tgz hash in bundled docs and repack to chase that hash. Every bundled documentation change requires a new candidate artifact.

The following commands start in a new directory, use no development checkout/global installation/NODE_PATH, and fail on a missing field, wrong source/harness/tree/run/attempt, unsuccessful/wrong workflow, unsafe archive, or ZIP/tgz/lock/integrity mismatch. They do not install until verification succeeds. Trust and exclusive management of the local directory and the external handoff are prerequisites; concurrent local edits are not supported.

```bash
set -eu
export CANDIDATE_HANDOFF=/absolute/path/to/trusted-candidate-handoff.json
mkdir consumer
cd consumer
node - <<'JS'
const fs = require('node:fs');
const cp = require('node:child_process');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const repo = 'albert-einshutoin/cdn-security-framework';
const read = file => {
  assert.ok(fs.statSync(file).size <= 2 * 1024 * 1024, 'JSON too large');
  return JSON.parse(fs.readFileSync(file, 'utf8'));
};
const hash = (bytes, algorithm = 'sha256', encoding = 'hex') => crypto.createHash(algorithm).update(bytes).digest(encoding);
const command = (name, args) => cp.execFileSync(name, args, { timeout: 30000, maxBuffer: 8 * 1024 * 1024, env: { ...process.env, LC_ALL: 'C' } });
const api = endpoint => JSON.parse(command('gh', ['api', '--hostname', 'github.com', `repos/${repo}/${endpoint}`]).toString());
assert.ok(process.env.CANDIDATE_HANDOFF, 'Trusted handoff is required');
const h = read(process.env.CANDIDATE_HANDOFF);
for (const key of ['source', 'harness', 'tree']) assert.match(h[key], /^[a-f0-9]{40}$/, key);
for (const key of ['run', 'attempt', 'artifactId']) assert.match(h[key], /^[1-9][0-9]*$/, key);
for (const key of ['artifactZipSha256', 'tgzSha256', 'consumerLockSha256']) assert.match(h[key], /^[a-f0-9]{64}$/, key);
const run = api(`actions/runs/${h.run}/attempts/${h.attempt}`);
assert.equal(String(run.id), h.run); assert.equal(String(run.run_attempt), h.attempt);
assert.equal(run.repository.full_name, repo);
assert.equal(run.event, 'push'); assert.equal(run.head_branch, 'main');
assert.equal(run.status, 'completed'); assert.equal(run.conclusion, 'success');
assert.equal(run.head_sha, h.source);
const workflow = api(`actions/workflows/${run.workflow_id}`);
assert.equal(workflow.path, '.github/workflows/policy-lint.yml');
const commit = api(`git/commits/${h.source}`);
assert.equal(commit.sha, h.source); assert.equal(commit.tree.sha, h.tree);
// Current producer copies the harness from its source checkout; verify, do not infer.
assert.equal(h.harness, run.head_sha);
const artifact = api(`actions/artifacts/${h.artifactId}`);
assert.equal(String(artifact.workflow_run.id), h.run);
assert.equal(artifact.workflow_run.head_sha, h.source);
assert.equal(artifact.name, `package-candidate-${h.run}-${h.attempt}`);
assert.equal(artifact.expired, false);
assert.equal(artifact.digest, 'sha256:' + h.artifactZipSha256);
const zip = command('gh', ['api', '--hostname', 'github.com', `repos/${repo}/actions/artifacts/${h.artifactId}/zip`]);
assert.equal(hash(zip), h.artifactZipSha256, 'Actions ZIP mismatch');
assert.ok(!fs.existsSync('candidate'), 'Use a new empty directory');
fs.writeFileSync('candidate.zip', zip, { flag: 'wx' });
const entries = command('unzip', ['-Z1', 'candidate.zip']).toString().trim().split('\n');
assert.ok(entries.length > 0 && entries.length <= 100);
assert.ok(entries.every(n => n && !n.startsWith('/') && !n.includes('\\') && !n.split('/').includes('..')), 'Unsafe ZIP path');
const modes = command('unzip', ['-Z', '-l', 'candidate.zip']).toString().split('\n').filter(n => /^[bcdlps-][rwxstST-]{9}\s/.test(n));
assert.equal(modes.length, entries.length, 'Unknown ZIP entry type');
assert.ok(modes.every(n => n.startsWith('-') || n.startsWith('d')), 'ZIP links/special files refused');
const totals = /^(\d+) files?, (\d+) bytes uncompressed,/m.exec(command('unzip', ['-Z', '-t', 'candidate.zip']).toString());
assert.ok(totals && Number(totals[1]) === entries.length && Number(totals[2]) <= 8 * 1024 * 1024, 'ZIP expansion limit');
command('unzip', ['-q', 'candidate.zip', '-d', 'candidate']);
const m = read('candidate/metadata.json');
assert.equal(m.schemaVersion, 1);
for (const key of ['source', 'harness', 'tree', 'run', 'attempt']) assert.equal(m[key], h[key], key);
const tgz = fs.readFileSync('candidate/candidate.tgz');
assert.ok(tgz.length > 0 && tgz.length <= 1024 * 1024);
assert.equal(m.size, tgz.length);
assert.equal(hash(tgz), h.tgzSha256, 'Trusted tgz mismatch');
assert.equal(m.sha256, h.tgzSha256);
const lock = fs.readFileSync('candidate/consumer/package-lock.json');
assert.equal(hash(lock), h.consumerLockSha256, 'Trusted consumer lock mismatch');
assert.equal(m.lockSha256, h.consumerLockSha256);
const pack = read('candidate/pack.json');
assert.equal(pack.version, '2.0.0-rc.0');
assert.equal(pack.integrity, 'sha512-' + hash(tgz, 'sha512', 'base64'), 'npm integrity mismatch');
for (const [name, data] of Object.entries({ run, workflow, commit, artifact })) fs.writeFileSync(name + '.json', JSON.stringify(data, null, 2), { flag: 'wx' });
console.log('Verified main source/harness/tree/run/attempt, Actions ZIP, tgz and consumer lock.');
JS
cd candidate/consumer
npm ci --ignore-scripts --no-audit --no-fund
./node_modules/.bin/cdn-security --version
./node_modules/.bin/cdn-security --help
```

Expect exit 0, the `Verified main source/harness/tree/run/attempt, Actions ZIP, tgz and consumer lock.` message, and `--version` **2.0.0-rc.0**. Remain in `consumer/candidate/consumer` for the sections below. The package's `npm integrity` is `sha512-` plus Base64 SHA-512 of the tgz; it is not either SHA-256 digest. `npm ci` uses the verified producer's common lock. An incomplete/unavailable hosted artifact stops handoff; a local repack cannot replace it. Only after a stable 2.0.0 publication may a separate guide use the registry package; that future installation is not validated here.

## 2. Profile init, lint and AWS build

```bash
./node_modules/.bin/cdn-security init --platform aws --profile balanced
export EDGE_ADMIN_TOKEN=docs-fixture-token-not-for-deploy
node node_modules/cdn-security-framework/scripts/policy-lint.js policy/security.yml
./node_modules/.bin/cdn-security build --policy policy/security.yml --target aws --out-dir dist/aws
```

All commands should exit0. Balanced allows GET/HEAD/POST and protects `/admin`, `/docs`, `/swagger` with the `x-edge-token` / `EDGE_ADMIN_TOKEN` static-token gate. The public synthetic value above is only for local fixtures, never production. Do not overwrite an existing policy with `--force`; use a new empty directory to repeat the guide.

`dist/aws/edge/` contains runtime artifacts; `dist/aws/infra/` contains IaC fragments. Build produces reviewable local files without cloud access or deployment. Edit Policy rather than generated JS or CFG.

## 3. Local playground fixtures (stub)

Save this JSON as `cases.json` in the empty consumer:

```json
{
  "fixtures": [
    {"name":"public GET","request":{"method":"GET","path":"/","headers":{"user-agent":"docs-fixture"}}},
    {"name":"PATCH rejected","request":{"method":"PATCH","path":"/","headers":{"user-agent":"docs-fixture"}}},
    {"name":"admin missing token","request":{"method":"GET","path":"/admin","headers":{"user-agent":"docs-fixture"}}},
    {"name":"admin valid synthetic token","request":{"method":"GET","path":"/admin","headers":{"user-agent":"docs-fixture","x-edge-token":"docs-fixture-token-not-for-deploy"}}},
    {"name":"POST JSON","request":{"method":"POST","path":"/api/items","headers":{"user-agent":"docs-fixture","Content-Type":"application/json"},"body":{"name":"synthetic-item"}}}
  ]
}
```

```bash
./node_modules/.bin/cdn-security playground --policy policy/security.yml --target aws --fixture cases.json --json
```

Expect CLI exit0 and, in fixture order:200/pass,405/block,401/block,200/pass,200/pass. A200 is local stub passage, not a production-origin guarantee. AWS viewer-request cannot read bodies: including POST JSON does not prove body inspection. Repository-only commands such as `npm run test:unit` are not needed in a consumer.

Auth gates require their referenced environment variables. `--allow-placeholder-token` is exclusively for non-production fixtures; never deploy placeholder artifacts. Cloudflare playground replaces external fetch with its existing stub and uses built-in non-production environment values. Do not reuse the AWS fixture's custom token unchanged against that stub. See the [CLI fixture contract](cli.md#playground).

Historical B2 evidence used a normally generated Worker on local workerd with real loopback HTTP/JWKS and synthetic RSA signatures ([B2 record at its delivered commit](https://github.com/albert-einshutoin/cdn-security-framework/blob/efb67793054f0c1a26986fd067a3a45718795a8c/docs/reviews/issue-1024-jwks-refresh-fix.md)). This is separate from the consumer playground stub above, and proves neither public TLS/DNS nor deployed Cloudflare POP/AWS behaviour. B3 documentation confirmation is not a fresh runtime test or a real participant H01 result.

## 4. Guided setup and Cloudflare JWT

Instead of a profile, `init --guided` selects application shape and authentication. It prompts in a TTY; this example closes stdin and supplies the selected configuration flags. Use a separate directory rather than overwriting the AWS policy:

```bash
mkdir cf-jwt
(
  cd cf-jwt
  ../node_modules/.bin/cdn-security init --guided --platform cloudflare \
    --app-shape rest-api --auth jwt --admin-paths /api \
    --cors-origins https://app.example.com --waf balanced \
    --geo-block '' --ip-allowlist '' --deployment build-only --project docs-jwt </dev/null
  node ../node_modules/cdn-security-framework/scripts/policy-lint.js policy/security.yml
  ../node_modules/.bin/cdn-security build --policy policy/security.yml --target cloudflare
)
```

Expect exit0. Generated JWT JWKS URL/issuer values at example.com are configuration examples; lint/build do not fetch real JWKS. This is not production authentication validation. Missing-token `/api` returns401 and public `/` returns200 through the existing playground stub. Valid JWT acceptance needs a separate local signing/JWKS fixture. AWS JWT/signed_url builds are unsupported and non-success; do not remove authentication to bypass the boundary. See [CLI init](cli.md#init).


```bash
cat > cf-jwt/cases.json <<'JSON'
{"fixtures":[{"name":"missing JWT","request":{"method":"GET","path":"/api","headers":{"user-agent":"docs-fixture"}}},{"name":"public","request":{"method":"GET","path":"/","headers":{"user-agent":"docs-fixture"}}}]}
JSON
./node_modules/.bin/cdn-security playground --policy cf-jwt/policy/security.yml --target cloudflare --fixture cf-jwt/cases.json --json
```

Expect exit0, then401/block and200/pass in fixture order.

## 5. OpenAPI to review

```bash
cp node_modules/cdn-security-framework/examples/openapi/openapi.yaml openapi.yaml
./node_modules/.bin/cdn-security openapi inspect --input openapi.yaml --workspace-root .
./node_modules/.bin/cdn-security openapi generate-policy --input openapi.yaml \
  --workspace-root . --profile balanced --out policy/openapi.candidate.yml
./node_modules/.bin/cdn-security contract diff --openapi openapi.yaml \
  --policy policy/security.yml --target aws --workspace-root . --fail-on never
```

Expect exit0. `--fail-on never` keeps this finding-review demo non-blocking; it is not advice to weaken a production CI gate. Candidate and `.meta.json` are review-only; active Policy is not overwritten, merged or applied. Review differences and omissions manually. Distinguish the repository workflow in the [OpenAPI guide](openapi-integration.md) from these consumer commands. Source Analyzer core is an Experimental programmatic API; standard Source-aware CLI remains Planned.

## 6. Migration preview and explicit save

Use this disposable single-file v1 fixture. Exclusive creation fails if these files already exist:

```bash
node - <<'JS'
const fs = require('node:fs');
const policy = 'version: 1\nmetadata: { owner: migration-rehearsal }\nrequest: { allow_methods: [HEAD, GET] }\nresponse_headers: {}\n';
fs.writeFileSync('migration-v1.yml', policy, { flag: 'wx' });
fs.writeFileSync('migration-original.yml', policy, { flag: 'wx' });
JS
./node_modules/.bin/cdn-security migrate --policy migration-v1.yml
cmp migration-original.yml migration-v1.yml
./node_modules/.bin/cdn-security migrate --policy migration-v1.yml --write
cmp migration-original.yml migration-v1.yml.v1.bak
node node_modules/cdn-security-framework/scripts/policy-lint.js migration-v1.yml
./node_modules/.bin/cdn-security build --policy migration-v1.yml --target aws --out-dir dist/migrated-aws
./node_modules/.bin/cdn-security build --policy migration-v1.yml --target cloudflare --out-dir dist/migrated-cf
```

Expect exit0. Omitted `--to` means2; preview prints only the fixed `MIGRATION_PREVIEW` summary, not the converted Policy. The API's returned `policy` is an artifact that may contain secrets; do not log it as a diagnostic. Manual decisions (difficulty5/6, AWS nonce/JWT/signed_url, target clarification) exit2; parse/schema/I/O failures exit1. Schema validity, provider build success and production applicability are separate claims.

Graph migration with `extends` or root `$ref` stops as unsupported. Do not bypass it by manually changing version. Before-commit save failures do not commit a new input; successful explicit save replaces it with v2 and retains original bytes in `.v1.bak`. Existing backups and leaf symlink/hardlink inputs are refused. Trust and exclusive management of a POSIX local directory are required; arbitrary post-check races, power loss, Windows/network filesystems are not guaranteed. YAML comments/format/anchor spelling and ACL/xattrs are not retained. See the [complete save contract](schema-migration.md).

## 7. Isolated published1.4.0 rollback rehearsal

This is a non-production rehearsal using the preceding backup. Candidate dependencies stay unchanged. Pin the old package in a new rollback directory and explicitly add its missing Cloudflare build dependency `esbuild@0.28.0`. Do not modify the published tarball:

```bash
(
  set -eu
  mkdir rollback-1.4.0
  npm install --prefix rollback-1.4.0 --save-exact cdn-security-framework@1.4.0 esbuild@0.28.0
  cp migration-v1.yml.v1.bak rollback-1.4.0/policy.yml
  cmp migration-original.yml migration-v1.yml.v1.bak
  cmp migration-original.yml rollback-1.4.0/policy.yml
  shasum -a 256 migration-original.yml migration-v1.yml.v1.bak rollback-1.4.0/policy.yml
  cd rollback-1.4.0
  node node_modules/cdn-security-framework/scripts/policy-lint.js policy.yml
  ./node_modules/.bin/cdn-security build --policy policy.yml --target aws --out-dir dist/aws
  ./node_modules/.bin/cdn-security build --policy policy.yml --target cloudflare --out-dir dist/cloudflare
)
```

Verify identical SHA-256 for original, backup and restored bytes, then old-package lint/AWS/Cloudflare build exit0. Pristine published1.4.0 fails the Cloudflare build without the dependency. This addition is a rollback-environment prerequisite, not a promise that this version will remain safe or approval for production rollback. Returning to the old package loses subsequent safety hardening.

## 8. Before applying artifacts

Generated `dist/edge`/`dist/infra` are review inputs to the operator's IaC/CDN workflow. Read [IaC](iac.md), [Origin authentication](origin-auth.md), [Threat model](threat-model.md), and [Observability](observability.md). Do not deploy this guide's synthetic/placeholder artifacts.
