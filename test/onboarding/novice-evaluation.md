# EN novice walkthrough — unpublished schema 2 candidate

Give this sheet to a person who did not implement the candidate. A maintainer supplies the **final PR run/attempt, PR HEAD SHA, and tgz SHA-256** from the PR acceptance comment. Leave the result fields blank until a real person performs the walkthrough. Do not substitute an AI or an implementer's rehearsal for a novice result.

This evaluates the local first-run path from an empty consumer through a useful Contract Diff finding and local GitHub Summary. It does not deploy, call GitHub APIs, use cloud credentials, or accept the release. Use synthetic examples only. Node.js must be **20.17.0, 22, or 24**; record the exact `node --version` and `npm --version`. Node 18.20.8 and 20.16.0 are expected to be rejected. The retained package `--version` can display 1.4.0; use the SHA/digest below to identify this unpublished schema 2 candidate.

## Facilitator preparation — outside the ten-minute clock

Use a disposable POSIX local directory and a GitHub account with read access to the PR run artifact. Set all four values from the **same final PR evidence**, never from an older run. The artifact container digest shown by GitHub Actions is different from the tgz SHA-256.

```bash
export RUN_ID='<final PR run ID>'
export ATTEMPT='<run attempt>'
export PR_HEAD_SHA='<40-character PR HEAD SHA>'
export EXPECTED_TGZ_SHA256='<64-character tgz SHA-256>'
mkdir novice-evaluation && cd novice-evaluation
gh run download "$RUN_ID" --repo albert-einshutoin/cdn-security-framework \
  --name "package-candidate-${RUN_ID}-${ATTEMPT}" --dir candidate
node - <<'JS'
const fs = require('node:fs');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const m = JSON.parse(fs.readFileSync('candidate/metadata.json', 'utf8'));
const hash = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
assert.equal(m.source, process.env.PR_HEAD_SHA);
assert.equal(m.harness, process.env.PR_HEAD_SHA);
assert.equal(m.run, process.env.RUN_ID);
assert.equal(m.attempt, process.env.ATTEMPT);
assert.equal(hash('candidate/candidate.tgz'), process.env.EXPECTED_TGZ_SHA256);
assert.equal(hash('candidate/candidate.tgz'), m.sha256);
assert.equal(hash('candidate/consumer/package-lock.json'), m.lockSha256);
console.log('Candidate SHA, run/attempt, tgz and common lock verified.');
JS
node --version
npm --version
```

Prepare a **dedicated** npm cache with the producer's lock, then remove the disposable installation before handing the directory to the evaluator. The evaluator's `candidate/consumer` starts without `node_modules`, user Policy, or reports. Online dependency preparation time belongs in the separate field below.

```bash
mkdir .npm-cache
( cd candidate/consumer && npm ci --ignore-scripts --no-audit --no-fund --cache ../../.npm-cache )
rm -rf candidate/consumer/node_modules
```

The timed offline `npm ci` below substitutes for the public Quickstart's `npm install --save-dev "$CANDIDATE_TARBALL"`: it uses the **same tarball** plus the producer's common lock/cache so dependency download variance is excluded. Record this substitution; do not claim it is a byte-for-byte execution of the online install command. No repository source, global install, `NODE_PATH`, or development `node_modules` is permitted. `npm --offline` alone does not prove every child process is network-blocked; the automated CI lane uses an OS network namespace.

## Evaluator instructions — start the clock at the first command

Open the matching [English Quickstart](../../docs/quickstart.md) for explanations. Execute these commands in `candidate/consumer` after the facilitator confirms the directory is empty of installed dependencies. Record each step's start/end time, exit code, uncertainty, and any assistance. Use a terminal with no real secrets.

```bash
cd candidate/consumer
npm ci --offline --ignore-scripts --no-audit --no-fund --cache ../../.npm-cache
./node_modules/.bin/cdn-security --help
./node_modules/.bin/cdn-security init --platform aws --profile balanced
export EDGE_ADMIN_TOKEN=docs-fixture-token-not-for-deploy
node node_modules/cdn-security-framework/scripts/policy-lint.js policy/security.yml
./node_modules/.bin/cdn-security build --policy policy/security.yml --target aws --out-dir dist/aws
cp node_modules/cdn-security-framework/examples/openapi/openapi.yaml openapi.yaml
node - <<'JS'
const fs = require('node:fs');
const crypto = require('node:crypto');
const files = ['openapi.yaml', 'policy/security.yml'];
const hashes = Object.fromEntries(files.map(file => [file, crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')]));
fs.writeFileSync('input-before.json', JSON.stringify(hashes));
JS
./node_modules/.bin/cdn-security openapi inspect --input openapi.yaml --workspace-root .
./node_modules/.bin/cdn-security openapi generate-policy --input openapi.yaml \
  --workspace-root . --profile balanced --out policy/openapi.candidate.yml
node node_modules/cdn-security-framework/scripts/policy-lint.js policy/openapi.candidate.yml
./node_modules/.bin/cdn-security build --policy policy/openapi.candidate.yml \
  --target aws --out-dir dist/candidate
./node_modules/.bin/cdn-security contract diff --openapi openapi.yaml \
  --policy policy/security.yml --target aws --workspace-root . --fail-on never
mkdir reports
./node_modules/.bin/cdn-security contract diff --openapi openapi.yaml \
  --policy policy/security.yml --target aws --workspace-root . --format json \
  --fail-on never --out reports/contract-diff.json
./node_modules/.bin/cdn-security contract diff --openapi openapi.yaml \
  --policy policy/security.yml --target aws --workspace-root . --format sarif \
  --fail-on never --out reports/cdn-security.sarif
./node_modules/.bin/cdn-security contract diff --openapi openapi.yaml \
  --policy policy/security.yml --target aws --workspace-root . --format github-summary \
  --fail-on never --out reports/github-summary.md
cat reports/github-summary.md
node - <<'JS'
const fs = require('node:fs');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const before = JSON.parse(fs.readFileSync('input-before.json', 'utf8'));
for (const [file, digest] of Object.entries(before)) {
  assert.equal(crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'), digest);
}
console.log('Active OpenAPI and Policy SHA-256 unchanged.');
JS
```

Expected: the commands above exit 0 because `--fail-on never` is a review demo, **not** the production CI gate. `openapi inspect` reports five operations. The candidate and `.meta.json` are separate review artifacts; active `policy/security.yml` and `openapi.yaml` remain unchanged. Both `dist/aws/edge` and `dist/aws/infra` are local generated files. Read one `ERROR`/`WARNING` line from Text and find its rule, route, and evidence in JSON/SARIF. Summary shows counts and only its top ten findings, with remaining findings linked to the JSON/SARIF artifacts. Unknown/unsupported/unbounded input is not an allow decision.

To observe the real finding gate after the timed walkthrough, repeat the Text diff **without** `--fail-on never`; on this fixture `--fail-on error` should exit 1. Do not put this expected rejection inside an unconditional `set -e` script. Migration preview/save/backup and isolated published-1.4.0 rollback are [separate Quickstart sections](../../docs/quickstart.md) and separate time fields; no production rollback or deploy is approved here.

## Blank observation form — one person, one language, one candidate

| Field | Human entry |
|---|---|
| Evaluator ID (pseudonym), date, language (EN) | **Not performed** |
| Developer/security background and prior use of this tool | **Not performed** |
| PR HEAD / run / attempt / tgz SHA-256; Node/npm; OS/filesystem | **Not performed** |
| Facilitator online dependency preparation start/end/duration | **Not performed** |
| Timed walkthrough start/end; total through local Summary | **Not performed** |
| Offline install, init/build, inspect, candidate/lint/build, Text finding, JSON/SARIF/Summary: step durations and exit codes | **Not performed** |
| First useful Finding: elapsed time, rule/route/evidence, evaluator's explanation and manual review action | **Not performed** |
| Stuck steps, reason, documentation ambiguity, exact assistance offered and when | **Not performed** |
| Ten-minute first-run target: measured PASS/FAIL, or unmeasured | **Unmeasured** |
| Migration/rollback optional rehearsal time and result (outside first-run clock) | **Not performed** |
| Input Policy/OpenAPI hash before/after, generated files, privacy observations | **Not performed** |

Submit a Markdown copy of the completed table and a short sanitized command/exit log to the maintainer for review; do not submit raw Policy/OpenAPI contents, tokens, Authorization values, URLs with userinfo/query/fragment, personal names, or machine absolute paths. The evaluator should describe any blocker in their own words. Blank fields remain **not performed**, never PASS.
