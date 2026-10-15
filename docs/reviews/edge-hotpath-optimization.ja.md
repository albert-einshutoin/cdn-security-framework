# 生成edgeのGraphQL・レスポンス索引・通常パスの最適化

基準は `f0a7cf81ce92ccc961928beb62ef24c8c06ca7ad`（PR #1108マージ後）。中〜高の3件だけを実装した。依存・公開API・CI設定と、低優先度だった生成時GraphQL設定の重複処理は変更していない。

## 変更と維持する契約

- CloudflareのGraphQL識別子判定を1文字ごとのregexからASCIIコード範囲比較へ変更。型・長さの条件、Unicode空白、string/comment、depth/alias/field制限、診断とblock/report、本文転送を維持する。
- responseのprefix索引は真偽値専用の共有 `PATH_MATCH_HELPER` で判定する。候補配列・seen・sortを作らず一致時に返す。`buildPathIndex` が非空ID配列だけを作る契約とown-key確認を使い、root・末尾slash・case・CSP/cache/Varyを維持する。認証側の順序付き `pathCandidates`、AND、signed URL exact、credential検証は変更しない。AWS responseにはbool helperだけ、Cloudflareにはresponse索引がある場合だけ追加helperを注入する。
- Cloudflareのcanonicalizeは、`/`開始かつpercent/matrix parameter/重複slash/exact dot-segmentがない場合だけ元文字列を返す。他は既存の3回decode・不正入力の拒否・option処理を実行する。
- AWS requestのcanonicalizeは変更しない。調査時の案は既存の有効設定を10KiB超過で拒否したため除外した。32/64/80ルートのサイズ・認証テストも維持した。
- goldenは生成コマンドでCloudflare 8件、AWS response 7件を更新。生成物の手編集は行っていない。

## 実装前後の測定

Apple M4 / Node v24.2.0 / workerd 1.20261012.1。beforeは基準commitをgit archiveで隔離し、同じ依存でbuild。実装後の同一driverを両rootに使い、A/B/B/A順に別プロセスで測定した。CloudflareはローカルHTTP client→workerd→別loopback origin、AWSはNode上の生成・minify済みhandler。外部CDNには接続しない。

| 負荷 | before ms | after ms | 差 |
|---|---:|---:|---:|
| workerd GraphQL 64KiB・中央値 | 1.256 | 0.614 | 51.2%短縮 |
| 同・p95 | 2.077 | 1.572 | 24.3%短縮 |
| workerd GraphQL 32KiB・中央値 | 0.717 | 0.367 | 48.8%短縮 |
| workerd GraphQL 2KiB・中央値 | 0.181 | 0.1695 | 6.2%短縮 |
| workerd 深い認証パス・中央値 | 0.248 | 0.205 | 17.4%短縮 |
| workerd 深いpublicパス・中央値 | 0.258 | 0.230 | 11.0%短縮 |
| Node AWS response 深い一致パス・batch平均 | 0.04510 | 0.02199 | 51.2%短縮 |
| Node AWS response 深い不一致パス・batch平均 | 0.04199 | 0.04074 | 3.0%短縮 |

3件を組み合わせた実装全体の比較で、個別効果ではなく短縮幅は加算できない。nativeは各プロセス1,000 warmup＋1,000 samples、前後それぞれ計2,000 samples/負荷。64prefix、`max_uri_length=8192`、GraphQLは2/32/64KiBとも `max_fields=50000,max_body_bytes=1048576`。origin HMAC/body hashは条件に混ぜず、origin到達URI・本文・token・偽装認証markerの除去、response cache/Varyを検証した。8負荷×2,001到達×4プロセスが一致し、runtime/origin/temp cleanupも全成功。

64KiBのprocess中央値はbefore 1.259/1.254ms、after 0.615/0.610ms。深い認証パスはbefore 0.242/0.256ms、after 0.199/0.208ms。短いpublic controlは0.1339→0.1353ms、正規化が必要なcontrolは0.1299→0.1305msと小さな悪化値も観測した。短い認証パスは0.1301→0.1300msで小差だがp95は0.286→0.373msと悪化した。早期return判定自体の追加負担とホスト変動があり、全設定の高速化や性能非退行は主張しない。

AWSは1,000 warmup、5,000回×5batch×2process/側。深い一致パスのafter B2 batch範囲は0.0181〜0.0489msで変動もある。短いパスは0.001892→0.001763msと小差。CloudFrontでの実測とは扱わない。

これらはローカルの経過時間で、本番CDNのCPU時間や実ユーザーのネットワーク遅延ではない。coldの初回1件/負荷/processはrawに分離して保持し、cold-start改善は主張しない。全raw sample、各プロセス集計、driver/input/generated/source hashは[JSON](edge-hotpath-optimization.json)に記録した。

初回native測定はfield literalの幅を40と固定し、実際の41文字に対して本文が2065/33553/67173 bytesになっていた。セルフレビューで式を修正し、正確な2048/32768/65536 bytesでA/B/B/Aを再測定した。表は修正版の結果だけを使い、初回rawと旧driver sourceはJSONのpreliminaryへ分離した。

## テストとレビューの境界

- 追加した契約チェックは実装前19/19成功。振る舞いを変えない最適化なので機能テストの意図的な失敗はない。
- 実装後は対象6ファイル55/55成功。GraphQL ASCII文字分類は全65,536 UTF-16 code unitと非1文字値を確認し、block/report・診断・転送本文を検証した。パスの長さ、大小文字、重複slash、matrix、多重decode、不正入力、CSP/cache/Varyも確認した。
- build:ts、compiler unit、Cloudflare runtime、security baseline、golden drift成功。
- HTTP E2Eは46ケース＋JWKS 50ケース、runtime/origin/両port/tempのcleanup成功。HEAD表記は未commit時のbaseであり、実装とのbindingはcompiler/generated/module/harnessのhashで確認する。
- AWS runtimeの最初の単独実行は既存distの生成時tokenと実行環境が不一致で認証10件が失敗。失敗logを保持し、使い捨てbase-policyを固定synthetic envで生成して同じenvで実行し直し75/75成功。製品コードや期待値を変更して成功させていない。
- Sol mediumによる今回差分のTypeScript/JavaScript・security専門レビューは指摘なし。専門reviewer自身はテストやベンチを実行していない。
- この記録は対象検証・ベンチ段階の固定証拠。Companion Stop Review Gateと、その後のローカル完全検証・最終hosted完全CIは、PR説明と同一headのchecksへ記録する。hosted結果、merge、deployをこの記録から推定しない。

## 再実行

両rootを同じ依存でbuildし、実装後driverを前後両方に使用する。測定中は他の重いテストを並行させない。

```sh
npm run build:ts
npx vitest run test/edge-hotpaths.test.ts test/edge-followup.test.ts test/cloudfront-size-selection.test.ts test/edge-runtime-optimizations.test.ts test/cloudflare-body-inspection.test.ts test/compiler-contract.test.ts --maxWorkers=1
node scripts/compile-unit-tests.js
node scripts/cloudflare-runtime-tests.js
node scripts/security-baseline-check.js
node scripts/check-drift.js
node scripts/cloudflare-http-e2e-tests.js --report <http-report.json>
node scripts/benchmark-edge-http.js --root <built-root> --hot-paths --output <native-result.json>
node scripts/benchmark-edge-runtime.js --root <built-root> --only hotpath-aws-response --fixture <same-synthetic-rsa.json> --output <node-result.json>
EDGE_ADMIN_TOKEN=synthetic-local-runtime ORIGIN_SECRET=synthetic-local-origin node scripts/compile.js --policy policy/base.yml --out-dir <disposable-fixture>
EDGE_ADMIN_TOKEN=synthetic-local-runtime ORIGIN_SECRET=synthetic-local-origin node scripts/runtime-tests.js --dist-dir <disposable-fixture>
VITEST_MAX_WORKERS=2 EDGE_ADMIN_TOKEN=synthetic-local-full-validation ORIGIN_SECRET=synthetic-local-origin npm run test:ci
```
