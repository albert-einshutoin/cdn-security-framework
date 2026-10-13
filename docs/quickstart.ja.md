# クイックスタート

## 1. 未公開schema2候補を空のconsumerへ導入

公開済み`cdn-security-framework@1.4.0`はPolicy schema **version 1**です。現行の未公開main候補は **2.0.0-rc.0**、Policy schema **version 2**を要求します。packageとPolicyのversionは別契約で、npm latestは公開旧版です。[Roadmap](ROADMAP.ja.md)を参照してください。Node 20.17.0、22、24のいずれか、npm、artifactを読めるGitHub CLI（`gh`）、POSIXの`unzip`が前提です。

### 担当者の受け渡しと独立照合

成功した **main push** の`Policy Lint & Build Check` runと正確なattemptを使います。PR runはmerge前の証拠で、merge後候補へ無条件に流用しません。担当者はarchive外のレビュー済み経路で、次の形式の信頼済みhandoff JSONを渡します（placeholderはすべて実値に置き換える）。

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

| Field | 意味と独立した照合元 |
| --- | --- |
| `source` | package producerのcheckout commit。GitHub runの`head_sha`とcommit APIの`sha`に照合 |
| `harness` | 同梱するsingle-pack/smoke/journey検証コードの取得元checkout。現producerは`source`から明示的にコピーし同値を検証する。独立した受け渡し記録とrunに照合し、他producerでも同じだと推測しない |
| `tree` | producer checkoutのGit tree。commit APIの`tree.sha`に照合 |
| `run`, `attempt` | main push runとattempt。run-attempt API、completed/success、workflow pathに照合 |
| `artifactId`, `artifactZipSha256` | 正確な名前のActions artifactと**ZIP bytes**。GitHub artifact APIの`digest`に照合 |
| `tgzSha256` | **candidate.tgz bytes**。信頼済み記録とダウンロードmetadataに照合 |
| `consumerLockSha256` | **consumer/package-lock.json bytes**。信頼済み記録とmetadataに照合 |

未検証archiveの値をコピーして信頼済み記録を作らないでください。担当者はrun/commit/artifactとproducer/consumer受入記録を先に照合します。信頼済み記録と最終候補hashはpackage外の証拠directory等へ保存します。同梱docsへ最終tgz hashを書き、hashを追って再packする循環を作りません。同梱文書が変わるたび新しい候補artifactが必要です。

以下は新規directoryで実行し、開発checkout/global install/NODE_PATHは不要です。必須値欠落、source/harness/tree/run/attempt、run/workflow、archive安全性、ZIP/tgz/lock/integrityの不一致で失敗し、照合成功前にはinstallしません。信頼済み記録とローカルdirectoryの排他的管理が前提で、並行編集は対象外です。

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

期待exitは0、表示は`Verified main source/harness/tree/run/attempt, Actions ZIP, tgz and consumer lock.`、`--version`は **2.0.0-rc.0**です。以降は`consumer/candidate/consumer`内で実行します。npmの`integrity`はtgzのSHA-512をBase64化した`sha512-`形式で、2種類のSHA-256とは別物です。`npm ci`は照合済みproducerの共通lockを使います。hosted artifactが欠落・取得不能なら受け渡しを止め、ローカル再packで代用しません。正式2.0.0公開後のregistry導入は別手順で、今回の検証には含みません。

## 2. Profileからinit・lint・AWS build

```bash
./node_modules/.bin/cdn-security init --platform aws --profile balanced
export EDGE_ADMIN_TOKEN=docs-fixture-token-not-for-deploy
node node_modules/cdn-security-framework/scripts/policy-lint.js policy/security.yml
./node_modules/.bin/cdn-security build --policy policy/security.yml --target aws --out-dir dist/aws
```

期待exitはすべて0。balancedはGET/HEAD/POSTを許可し、`/admin`・`/docs`・`/swagger`に`x-edge-token`/`EDGE_ADMIN_TOKEN`のstatic-token gateがあります。上の値は公開synthetic fixture専用で、本番に使いません。既存policyへ`--force`しません。再実行は別の空directoryを使ってください。

`dist/aws/edge/`はruntime、`dist/aws/infra/`はIaC断片です。buildはreview用ファイル生成であり、クラウドへ接続・deployしません。生成JSやCFGを手編集せずPolicyを編集します。

## 3. ローカルplayground fixture（stub）

空consumerの`cases.json`へ次のJSONを保存します。

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

CLI exit0、fixture順に200/pass、405/block、401/block、200/pass、200/passが期待値です。200はlocal stubの通過結果で、本番originの応答保証ではありません。AWS viewer-requestはbodyを読めないため、POST JSONを渡してもbody検査の証明にはしません。consumerに存在しない`npm run test:unit`等は不要です。

認証gateには参照envが必要です。`--allow-placeholder-token`は非本番fixture専用で、placeholder artifactをdeployしてはいけません。Cloudflare playgroundは既存stubで外部fetchを置き換え、組込みの非本番envを使います。AWS fixtureのcustom tokenをCloudflare stubへそのまま流用しないでください。[CLIのfixture契約](cli.ja.md#playground)を参照。

過去のB2証拠は通常CLI生成Workerをlocal workerdで動かし、loopback HTTP/JWKSと合成RSA署名を実検証しています（[納品commitのB2記録](https://github.com/albert-einshutoin/cdn-security-framework/blob/efb67793054f0c1a26986fd067a3a45718795a8c/docs/reviews/issue-1024-jwks-refresh-fix.md)）。上記consumer playgroundのstubとは別で、public TLS/DNS、実Cloudflare POP/AWSの動作を保証しません。B3文書確認を新規runtime検証や実参加者H01の結果へ置き換えません。

## 4. Guided setupとCloudflare JWT

Cloudflare guided initは5分窓を維持するためBusinessの明示指定が必要です。Freeの10秒policyは[rate-limitプロファイル](cloudflare-waf-parity.ja.md#cloudflare-rate-limit-の設定プロファイル)を参照してください。実アカウントの契約やWAF全体のFree対応を確認するものではありません。

profileの代わりに`init --guided`でapp形状・認証を選べます。TTYでは対話式です。以下はstdinを閉じ、選択する設定をflagで渡す非TTYの例です。既存AWS policyを上書きせず、別directoryに作ります。

```bash
mkdir cf-jwt
(
  cd cf-jwt
  ../node_modules/.bin/cdn-security init --guided --platform cloudflare --cloudflare-rate-limit-plan business \
    --app-shape rest-api --auth jwt --admin-paths /api \
    --cors-origins https://app.example.com --waf balanced \
    --geo-block '' --ip-allowlist '' --deployment build-only --project docs-jwt </dev/null
  node ../node_modules/cdn-security-framework/scripts/policy-lint.js policy/security.yml
  ../node_modules/.bin/cdn-security build --policy policy/security.yml --target cloudflare
)
```

期待exit0。生成JWTのJWKS URL/issuerはexample.comの設定見本で、lint/buildは実JWKSへアクセスしません。本番認証の検証ではありません。`/api`へのtokenなしfixtureは401、public `/`は200を既存playground stubで確認できます。有効JWT検証は別のlocal署名/JWKS fixtureが必要です。AWS JWT/signed_urlは未対応でbuildが非成功になります。認証を削除して成功へ迂回しません。[CLI init](cli.ja.md#init)。


```bash
cat > cf-jwt/cases.json <<'JSON'
{"fixtures":[{"name":"missing JWT","request":{"method":"GET","path":"/api","headers":{"user-agent":"docs-fixture"}}},{"name":"public","request":{"method":"GET","path":"/","headers":{"user-agent":"docs-fixture"}}}]}
JSON
./node_modules/.bin/cdn-security playground --policy cf-jwt/policy/security.yml --target cloudflare --fixture cf-jwt/cases.json --json
```

期待値はCLI exit0、fixture順に401/block、200/passです。

## 5. OpenAPIからreviewへ

```bash
cp node_modules/cdn-security-framework/examples/openapi/openapi.yaml openapi.yaml
./node_modules/.bin/cdn-security openapi inspect --input openapi.yaml --workspace-root .
./node_modules/.bin/cdn-security openapi generate-policy --input openapi.yaml \
  --workspace-root . --profile balanced --out policy/openapi.candidate.yml
./node_modules/.bin/cdn-security contract diff --openapi openapi.yaml \
  --policy policy/security.yml --target aws --workspace-root . --fail-on never
```

期待exit0。`--fail-on never`はfindingをreviewするこのデモの終了条件で、本番CIのgate設定を弱める指示ではありません。candidateと`.meta.json`はreview-onlyで、active policyの上書き・自動merge/applyはありません。差分と省略理由を人が確認します。[OpenAPI詳細](openapi-integration.ja.md)のrepository用手順と、このconsumer手順は区別してください。Source Analyzer coreはExperimentalなprogrammatic APIで、標準Source-aware CLIはPlannedです。

## 6. migrationのpreview・明示保存

以下は使い捨ての単一v1 fixtureです。既存ファイルがあればexclusive作成は失敗します。

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

期待exit0。`--to`省略は2、previewは固定summary `MIGRATION_PREVIEW`のみでPolicy全体を表示しません。APIの`policy`は秘密設定を含み得る成果物なので診断logへ無条件出力しません。手動判断必須（difficulty5/6、AWS nonce/JWT/signed_url、target要確認等）はexit2、parse/schema/I/O等はexit1です。schema妥当性・provider build成功・本番適用可能性は別です。

`extends`/root `$ref`のgraph移行は未対応で停止します。単にversionを手変更する迂回はしません。保存前失敗は原本を確定変更せず、成功時だけ選択入力をv2へ更新して元bytesの`.v1.bak`を残します。既存backupやleaf symlink/hardlink入力は拒否。信頼・排他管理するPOSIX local directoryが前提で、最終check後の任意競合/power loss/Windows/network FSを保証しません。YAMLコメント・整形・anchor表現、ACL/xattrsは保持しません。[完全な保存契約](schema-migration.ja.md)。

## 7. 隔離した公開1.4.0へのrollback rehearsal

直前のbackupを使う非本番rehearsalです。候補の依存は変更しません。新しいrollback directoryへ旧版をpinし、旧版が欠いているCloudflare build依存`esbuild@0.28.0`を明示追加します。公開tarball自体は書き換えません。

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

原本・backup・復元後のSHA-256が一致し、旧版のlint/AWS/Cloudflare buildがexit0になることを確認します。素の公開1.4.0ではCloudflare buildは不足依存で失敗します。この追加はrollback環境の前提であり、将来も安全な依存versionという保証でも本番rollback承認でもありません。旧版へ戻すと後続の安全強化を失います。

## 8. 適用前の確認

生成された`dist/edge`/`dist/infra`はoperatorのIaC/CDN workflowへ引き渡すreview対象です。[IaC](iac.ja.md)、[Origin認証](origin-auth.ja.md)、[脅威モデル](threat-model.ja.md)、[観測](observability.ja.md)を確認してください。本書のsynthetic/placeholder artifactを本番適用しません。
