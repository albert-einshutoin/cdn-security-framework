# JA 初学者評価シート — 未公開schema 2候補

このシートを候補の実装者以外の評価者へ渡してください。担当者は、**最終main pushのsource/harness/tree/run/attempt、Actions ZIP digest、tgz SHA-256、consumer lock SHA-256**を同じ候補の信頼済み受入記録から記入します。実際の人間が実施するまで結果欄は空欄のままです。AI代理実行や実装者の再現を初学者の結果に置き換えません。

測定対象は、空consumerへのローカル導入から、有用なContract Diff Findingの理解とローカルGitHub Summaryまでです。deploy、GitHub API投稿、クラウドcredential、公開承認は含みません。入力はsynthetic例だけを使います。Node.js条件は **20.17.0、22、24**。`node --version`と`npm --version`の実値を記録します。18.20.8と20.16.0は期待どおり拒否される対象です。公開1.4.0はschema1、未公開候補の`--version`は **2.0.0-rc.0**、Policyはschema2です。versionだけで候補を識別せず、評価前にmain artifactを照合します。

## 担当者による準備 — 10分計測の外

使い捨てPOSIX directory、Node 20.17.0/22/24、npm、`gh`、`unzip`を使います。[日本語Quickstartの第1節](../../docs/quickstart.ja.md#1-未公開schema2候補を空のconsumerへ導入)で、信頼済みmain runの受け渡し記録を使い、`Verified main source/harness/tree/run/attempt, Actions ZIP, tgz and consumer lock.`まで実行します。**末尾の`cd candidate/consumer`と`npm ci`の前で止めます。** GitHub run/commit/artifactとZIP/tgz/lockの実bytesを独立記録に照合し、metadata内の自己一致だけでは合格にしません。外側の`consumer`に留まり、`candidate/consumer`は`node_modules`・Policy・reportなしです。

照合済みproducerの共通lockで専用npm cacheをonline準備します。これは人間の10分計測の外です。

```bash
mkdir .npm-cache
( cd candidate/consumer && npm ci --ignore-scripts --no-audit --no-fund --cache ../../.npm-cache )
rm -rf candidate/consumer/node_modules
```

計測中の`npm ci`はQuickstart第1節と同じ照合済みproducer lock/tgzを使い、`--offline`と準備済みcacheを追加してdownloadの揺れを除外します。異なるflagを記録し、online commandのbyte単位実行とは扱いません。repository source、global install、`NODE_PATH`、開発用`node_modules`は利用しません。`npm --offline`だけでは全子processの通信遮断を証明できず、CIではOSのnetwork namespaceを使います。

## 評価者の操作 — 最初のコマンドから計測

説明は[日本語Quickstart](../../docs/quickstart.ja.md)を参照してください。担当者が未installのconsumerを確認後、`candidate/consumer`で以下を実行します。各stepの開始/終了、exit、迷い、補助を記録します。本番secretは使いません。

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

上記の期待exitは0です。`--fail-on never`はFindingを読むdemoのためで、**本番CI gateの設定ではありません**。`openapi inspect`は5 operationを示します。candidateと`.meta.json`は別のreview用成果物で、active `policy/security.yml`と`openapi.yaml`は不変です。`dist/aws/edge`と`dist/aws/infra`はローカル生成物でdeployではありません。Textの`ERROR`/`WARNING`を一つ選び、rule、route、根拠をJSON/SARIFで探してください。Summaryは件数と上位10件を示し、残りはJSON/SARIF artifact参照です。unknown/unsupported/unboundedを安全な許可判定にしません。

計測後、Text diffを`--fail-on never`なしで再実行すると、同fixtureの`--fail-on error`は期待exit1です。これは正常な拒否であり、無条件`set -e` scriptの中へ入れません。migration preview/保存/backupと公開1.4.0の隔離rollbackは[Quickstartの別節](../../docs/quickstart.ja.md)にあり、時間も別欄です。本番rollbackやdeployの承認ではありません。

## 空欄の観察フォーム — 1人・1言語・1候補

| 項目 | 人間による記入欄 |
|---|---|
| 評価者ID（仮名）、日付、言語（JA） | **未実施** |
| 開発・security経験、本ツールの利用経験 | **未実施** |
| Source / harness / tree / main run / attempt / ZIP / tgz / consumer-lock SHA-256; Node/npm; OS/filesystem | **未実施** |
| 担当者のonline依存準備の開始/終了/所要時間 | **未実施** |
| 初回導線の開始/終了、local Summaryまでの総時間 | **未実施** |
| offline install、init/build、inspect、candidate/lint/build、Text Finding、JSON/SARIF/Summaryのstep時間・exit | **未実施** |
| 最初の有用なFindingまでの時間、rule/route/evidence、評価者自身の説明と手動review判断 | **未実施** |
| 詰まったstep、理由、文書の曖昧さ、補助内容と介入時点 | **未実施** |
| 10分の初回導線目標：実測PASS/FAIL、または未計測 | **未計測** |
| migration/rollbackの任意rehearsal時間と結果（初回計測外） | **未実施** |
| 入力Policy/OpenAPIの前後hash、生成物、privacy観察 | **未実施** |

完了した表と、機密を除いた短いcommand/exit記録をMarkdownで担当者へ提出してください。raw Policy/OpenAPI本文、token、Authorization値、userinfo/query/fragment付きURL、個人名、端末の絶対pathを含めません。詰まった箇所は評価者自身の言葉で記録します。空欄は**未実施**のままで、PASSとしません。
