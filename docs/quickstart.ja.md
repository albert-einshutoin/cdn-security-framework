# クイックスタート

## 1. 未公開schema2候補を空のconsumerへ導入

公開済みは1.4.0/schema1です。この文書は未公開mainのschema2候補を対象にします。[Roadmap](ROADMAP.ja.md)で状態を確認してください。候補提供者が`npm run build:ts`後に`npm pack --ignore-scripts`で作ったtarballを受け取り、候補commit SHAとSHA-256を照合します。同梱docsが変わればdigestも変わります。以下の手順は空のconsumerで実行し、repository用npm scriptや開発repo/global install/NODE_PATHを使いません。

```bash
# Set this to the verified tarball supplied with the candidate SHA and SHA-256.
export CANDIDATE_TARBALL=/path/to/verified-candidate.tgz
shasum -a 256 "$CANDIDATE_TARBALL"
mkdir consumer
cd consumer
npm init -y
npm install --save-dev "$CANDIDATE_TARBALL"
./node_modules/.bin/cdn-security --help
```

`--version`の1.4.0表示はrelease GO前の保持値で、公開旧版と候補を区別できません。将来2.0.0が正式公開された後だけ、上のtarball導入を`npm install --save-dev cdn-security-framework@2.0.0`へ置き換えます。今回はその公開後コマンドを検証した扱いにしません。`npm latest`を候補の検証に使いません。

## 2. Profileからinit・lint・AWS build

```bash
./node_modules/.bin/cdn-security init --platform aws --profile balanced
export EDGE_ADMIN_TOKEN=docs-fixture-token-not-for-deploy
node node_modules/cdn-security-framework/scripts/policy-lint.js policy/security.yml
./node_modules/.bin/cdn-security build --policy policy/security.yml --target aws --out-dir dist/aws
```

期待exitはすべて0。balancedはGET/HEAD/POSTを許可し、`/admin`・`/docs`・`/swagger`に`x-edge-token`/`EDGE_ADMIN_TOKEN`のstatic-token gateがあります。上の値は公開synthetic fixture専用で、本番に使いません。既存policyへ`--force`しません。再実行は別の空directoryを使ってください。

`dist/aws/edge/`はruntime、`dist/aws/infra/`はIaC断片です。buildはreview用ファイル生成であり、クラウドへ接続・deployしません。生成JSやCFGを手編集せずPolicyを編集します。

## 3. ローカルHTTP fixture

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

## 4. Guided setupとCloudflare JWT

profileの代わりに`init --guided`でapp形状・認証を選べます。TTYでは対話式です。以下はstdinを閉じ、選択する設定をflagで渡す非TTYの例です。既存AWS policyを上書きせず、別directoryに作ります。

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
